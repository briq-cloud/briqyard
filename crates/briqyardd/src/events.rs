//! Events (ADR 0019): what happened on this host, in one append-only log. An event is a line
//! of `state/events/<hour>.ndjson`, appended and synced under the log's lock, then sent to the
//! watchers; `seq` is one more per event and never reused.

use anyhow::{Context, Result};
use briqyard_api::{self as api, event};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;
use std::io::{BufRead, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, watch};

/// The most events a host keeps, whatever their age: whole hours go, oldest first.
pub const MAX_EVENTS: u64 = 100_000;
/// The longest message: a console tail is cut here.
const MAX_MESSAGE: usize = 1024;
/// How far a watcher may fall behind the log before it is closed.
const WATCH_BUFFER: usize = 1024;
/// A quiet watch sends `{}` this often, so a proxy does not cut it.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(30);

/// An event about to be logged: what it says, and whom it is about.
#[derive(Clone, Debug)]
pub struct Ev {
    kind: &'static str,
    reason: &'static str,
    message: String,
    machine_id: String,
    tenant: String,
    data: Option<serde_json::Value>,
}

impl Ev {
    pub fn normal(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(event::NORMAL, reason, message.into())
    }

    pub fn warning(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(event::WARNING, reason, message.into())
    }

    fn new(kind: &'static str, reason: &'static str, message: String) -> Self {
        Self {
            kind,
            reason,
            message,
            machine_id: String::new(),
            tenant: String::new(),
            data: None,
        }
    }

    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// About a machine of a tenant.
    pub fn of(mut self, machine_id: &str, tenant: &str) -> Self {
        machine_id.clone_into(&mut self.machine_id);
        tenant.clone_into(&mut self.tenant);
        self
    }
}

/// What a read keeps: every field given must match.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub tenant: Option<String>,
    pub machine: Option<String>,
    pub kind: Option<String>,
}

impl Filter {
    fn matches(&self, e: &api::Event) -> bool {
        let is = |want: &Option<String>, got: &str| want.as_deref().is_none_or(|w| w == got);
        is(&self.tenant, &e.tenant) && is(&self.machine, &e.machine_id) && is(&self.kind, &e.kind)
    }
}

/// Events after a cursor, oldest first, and the cursor to read on from: the last one returned
/// when the page is full, else the log's last seq.
#[derive(Debug, Default, PartialEq)]
pub struct Page {
    pub events: Vec<api::Event>,
    pub next: u64,
}

/// A cursor the log cannot answer from: the events after it are gone, or it is past the
/// log's last seq (the log began again). A read from `oldest - 1` is whole.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Gone {
    pub oldest: u64,
    pub message: String,
}

#[derive(Clone)]
pub struct Events {
    inner: Arc<Shared>,
}

struct Shared {
    log: Mutex<Log>,
    tx: broadcast::Sender<api::Event>,
    /// Set when the daemon goes down: every watch ends.
    closing: watch::Sender<bool>,
}

struct Log {
    dir: PathBuf,
    /// The last seq given.
    seq: u64,
    /// The files, by hour, with the first seq each holds.
    files: BTreeMap<String, u64>,
    /// The newest file, open for appending.
    open: Option<(String, std::fs::File)>,
}

/// An hour's file name without its extension; names sort as their hours do.
fn hour_key(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H").to_string()
}

fn path(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{key}.ndjson"))
}

/// The events of a file, in order, its torn last line (a crash in a write) left out.
fn lines(file: std::fs::File) -> impl Iterator<Item = api::Event> {
    let mut r = std::io::BufReader::new(file);
    std::iter::from_fn(move || loop {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(n) if n > 0 && line.ends_with('\n') => {
                if let Ok(e) = serde_json::from_str(&line) {
                    return Some(e);
                }
            }
            _ => return None,
        }
    })
}

/// Cuts what follows a file's last newline: the line a crash left half written. The next
/// append then starts a line of its own.
fn cut_torn_tail(p: &Path) -> Result<()> {
    let data = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
    let whole = data.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    if whole < data.len() {
        let f = std::fs::OpenOptions::new().write(true).open(p)?;
        f.set_len(whole as u64)?;
        f.sync_data()?;
        tracing::warn!(file = %p.display(), bytes = data.len() - whole, "torn event line cut");
    }
    Ok(())
}

/// A message as kept: at most `MAX_MESSAGE` bytes, cut on a character.
fn bounded(mut s: String) -> String {
    if s.len() > MAX_MESSAGE {
        let mut end = MAX_MESSAGE - '…'.len_utf8();
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}

impl Log {
    /// Appends a line and syncs it. A write that fails is taken back, so the next one starts
    /// a line of its own.
    fn append(&mut self, e: &api::Event) -> Result<()> {
        // Never an hour before the newest file's: a clock that steps back stays in it, so
        // files sort as their seqs do.
        let newest = self.files.keys().next_back().cloned().unwrap_or_default();
        let key = hour_key(e.at).max(newest);
        if self.open.as_ref().is_none_or(|(k, _)| *k != key) {
            let p = path(&self.dir, &key);
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&p)
                .with_context(|| format!("open {}", p.display()))?;
            self.open = Some((key.clone(), f));
        }
        let (_, f) = self.open.as_mut().expect("opened above");
        let mut line = serde_json::to_vec(e)?;
        line.push(b'\n');
        let len = f.seek(std::io::SeekFrom::End(0))?;
        if let Err(err) = f.write_all(&line).and_then(|_| f.sync_data()) {
            let _ = f.set_len(len);
            return Err(err.into());
        }
        self.files.entry(key).or_insert(e.seq);
        Ok(())
    }

    fn oldest(&self) -> u64 {
        self.files.values().next().copied().unwrap_or(self.seq + 1)
    }
}

/// Whether the events after `since` are all still in the log: `0` always is.
fn check_since(since: u64, oldest: u64, last: u64) -> Result<(), Gone> {
    if since > last {
        return Err(Gone {
            oldest,
            message: format!(
                "since {since} is past the last event, {last}: this host's log began again; read from 0"
            ),
        });
    }
    if since > 0 && since + 1 < oldest {
        return Err(Gone {
            oldest,
            message: format!(
                "since {since}: the events after it are gone; the oldest kept is {oldest}"
            ),
        });
    }
    Ok(())
}

impl Events {
    /// Reads back what a previous daemon logged: the files and the last seq, a torn last line
    /// cut and a file left with nothing removed.
    pub fn open(dir: &Path) -> Result<Self> {
        let mut keys: Vec<String> = std::fs::read_dir(dir)
            .with_context(|| format!("read {}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".ndjson").map(String::from)
            })
            .collect();
        keys.sort();
        let mut seq = 0;
        let mut files = BTreeMap::new();
        for (i, key) in keys.iter().enumerate().rev() {
            let p = path(dir, key);
            let newest = files.is_empty() && seq == 0;
            if newest {
                cut_torn_tail(&p)?;
            }
            let file = std::fs::File::open(&p).with_context(|| format!("read {}", p.display()))?;
            let mut events = lines(file);
            let Some(first) = events.next() else {
                std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
                continue;
            };
            if newest {
                seq = events.last().map_or(first.seq, |e| e.seq);
            }
            files.insert(keys[i].clone(), first.seq);
        }
        let (tx, _) = broadcast::channel(WATCH_BUFFER);
        Ok(Self {
            inner: Arc::new(Shared {
                log: Mutex::new(Log {
                    dir: dir.to_path_buf(),
                    seq,
                    files,
                    open: None,
                }),
                tx,
                closing: watch::channel(false).0,
            }),
        })
    }

    /// The seq goes on from at least `seq`: a machine's record carries the seq of its last
    /// event, so a log cut short never hands out a version again.
    pub fn floor(&self, seq: u64) {
        let mut log = self.inner.log.lock().unwrap();
        log.seq = log.seq.max(seq);
    }

    /// Logs an event and sends it to the watchers; its seq. A log that cannot be written is
    /// warned about and the event still goes out: the seq is not taken back.
    pub fn emit(&self, ev: Ev) -> u64 {
        let mut log = self.inner.log.lock().unwrap();
        log.seq += 1;
        let e = api::Event {
            seq: log.seq,
            at: Utc::now(),
            kind: ev.kind.into(),
            reason: ev.reason.into(),
            message: bounded(ev.message),
            machine_id: ev.machine_id,
            tenant: ev.tenant,
            host: String::new(),
            data: ev.data,
        };
        if let Err(err) = log.append(&e) {
            tracing::warn!(seq = e.seq, reason = e.reason, err = %err, "event not written");
        }
        // Under the lock: watchers get the events in seq order.
        let _ = self.inner.tx.send(e.clone());
        e.seq
    }

    /// Up to `limit` events after `since` that the filter keeps (blocking: it reads files).
    pub fn read(&self, since: u64, f: &Filter, limit: usize) -> Result<Page> {
        let (dir, files, last) = {
            let log = self.inner.log.lock().unwrap();
            (log.dir.clone(), log.files.clone(), log.seq)
        };
        let oldest = files.values().next().copied().unwrap_or(last + 1);
        check_since(since, oldest, last)?;
        let files: Vec<(String, u64)> = files.into_iter().collect();
        // From the last file that starts at or before the first event wanted.
        let from = files
            .iter()
            .rposition(|(_, first)| *first <= since + 1)
            .unwrap_or(0);
        let mut events = Vec::new();
        for (key, _) in &files[from..] {
            let file = match std::fs::File::open(path(&dir, key)) {
                Ok(f) => f,
                // Removed by retention since the list was taken.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let oldest = self.inner.log.lock().unwrap().oldest();
                    check_since(since, oldest, last)?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for e in lines(file) {
                if e.seq <= since {
                    continue;
                }
                if e.seq > last {
                    break;
                }
                let seq = e.seq;
                if f.matches(&e) {
                    events.push(e);
                    if events.len() == limit {
                        return Ok(Page { events, next: seq });
                    }
                }
            }
        }
        Ok(Page { events, next: last })
    }

    /// Removes whole hours older than `keep_days`, then the oldest hours while more than `max`
    /// events are kept; the newest file always stays, so the last seq is never lost.
    pub fn prune(&self, now: DateTime<Utc>, keep_days: u32, max: u64) -> Result<usize> {
        let cut = hour_key(now - Duration::days(keep_days as i64));
        let mut log = self.inner.log.lock().unwrap();
        let mut removed = 0;
        while log.files.len() > 1 {
            let (key, first) = log
                .files
                .iter()
                .next()
                .map(|(k, f)| (k.clone(), *f))
                .unwrap();
            if key >= cut && log.seq + 1 - first <= max {
                break;
            }
            let p = path(&log.dir, &key);
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("remove {}", p.display())),
            }
            log.files.remove(&key);
            removed += 1;
        }
        Ok(removed)
    }

    /// Ends every watch: the daemon is going down.
    pub fn close(&self) {
        self.inner.closing.send_replace(true);
    }

    /// A watch from `since`: checked and its first page read now, so a cursor the log cannot
    /// answer is refused before any line goes out; then the lines, one per event (the page,
    /// the pages after it, then each new event), `{}` every `HEARTBEAT`, and a last error
    /// line when the watcher fell behind or the daemon goes down. Ends when `tx` is dropped.
    pub async fn watch(&self, since: u64, f: Filter, tx: mpsc::Sender<String>) -> Result<()> {
        // Subscribed before the first read: an event logged in between is in one or both,
        // and the seq tells which were sent.
        let rx = self.inner.tx.subscribe();
        let page = self.read_blocking(since, f.clone()).await?;
        let me = self.clone();
        tokio::spawn(async move { me.stream(rx, page, f, tx).await });
        Ok(())
    }

    async fn read_blocking(&self, since: u64, f: Filter) -> Result<Page> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.read(since, &f, api::events_limit(None))).await?
    }

    async fn stream(
        &self,
        mut rx: broadcast::Receiver<api::Event>,
        mut page: Page,
        f: Filter,
        tx: mpsc::Sender<String>,
    ) {
        let mut closing = self.inner.closing.subscribe();
        let line = |e: &api::Event| serde_json::to_string(e).unwrap_or_default() + "\n";
        let mut cursor;
        loop {
            let full = page.events.len() == api::events_limit(None);
            for e in &page.events {
                if !send(&tx, &mut closing, line(e)).await {
                    return;
                }
            }
            cursor = page.next;
            if !full {
                break;
            }
            page = match self.read_blocking(cursor, f.clone()).await {
                Ok(p) => p,
                Err(err) => {
                    let _ = tx.try_send(last_line("gone", &format!("{err:#}")));
                    return;
                }
            };
        }
        let start = tokio::time::Instant::now() + HEARTBEAT;
        let mut beat = tokio::time::interval_at(start, HEARTBEAT);
        loop {
            let out = tokio::select! {
                r = rx.recv() => match r {
                    Ok(e) if e.seq <= cursor => continue,
                    Ok(e) => {
                        cursor = e.seq;
                        if !f.matches(&e) {
                            continue;
                        }
                        line(&e)
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let why = format!(
                            "the watch fell {n} events behind the log: watch again from since={cursor}"
                        );
                        let _ = tx.try_send(last_line("lagged", &why));
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = beat.tick() => "{}\n".to_string(),
                _ = closing.wait_for(|c| *c) => {
                    let why = format!("the daemon is going down: watch again from since={cursor}");
                    let _ = tx.try_send(last_line("shutdown", &why));
                    return;
                }
            };
            if !send(&tx, &mut closing, out).await {
                return;
            }
        }
    }
}

/// Sends a line, unless the watcher went away or the daemon is going down.
async fn send(
    tx: &mpsc::Sender<String>,
    closing: &mut watch::Receiver<bool>,
    line: String,
) -> bool {
    tokio::select! {
        r = tx.send(line) => r.is_ok(),
        _ = closing.wait_for(|c| *c) => false,
    }
}

/// The line a watch ends with: an error body, as the API's.
fn last_line(code: &str, why: &str) -> String {
    let e = api::ApiError {
        error: why.into(),
        code: code.into(),
        request_id: String::new(),
        machine: None,
        oldest: None,
    };
    serde_json::to_string(&e).unwrap_or_default() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqyard_api::reason;

    fn open() -> (tempfile::TempDir, Events) {
        let dir = tempfile::tempdir().unwrap();
        let ev = Events::open(dir.path()).unwrap();
        (dir, ev)
    }

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn all(ev: &Events, since: u64) -> Vec<u64> {
        let p = ev.read(since, &Filter::default(), 5000).unwrap();
        p.events.iter().map(|e| e.seq).collect()
    }

    /// An event as a past hour would have logged it, written into that hour's file.
    fn logged_at(ev: &Events, at: &str, n: usize) {
        let mut log = ev.inner.log.lock().unwrap();
        for _ in 0..n {
            log.seq += 1;
            let e = api::Event {
                seq: log.seq,
                at: t(at),
                kind: event::NORMAL.into(),
                reason: reason::CREATED.into(),
                message: String::new(),
                machine_id: String::new(),
                tenant: String::new(),
                host: String::new(),
                data: None,
            };
            log.append(&e).unwrap();
        }
    }

    #[test]
    fn seqs_go_on_across_a_restart_and_from_the_records() {
        let (dir, ev) = open();
        assert_eq!(ev.emit(Ev::normal(reason::HOST_STARTED, "up")), 1);
        let seq = ev.emit(
            Ev::warning(reason::EXITED, "exited with code 7")
                .of("m_1", "t1")
                .data(serde_json::json!({"code": 7})),
        );
        assert_eq!(seq, 2);
        drop(ev);
        // A new daemon goes on from the log.
        let ev = Events::open(dir.path()).unwrap();
        assert_eq!(ev.emit(Ev::normal(reason::HOST_STARTED, "up again")), 3);
        let p = ev.read(0, &Filter::default(), 10).unwrap();
        let e = &p.events[1];
        assert_eq!(
            (e.kind.as_str(), e.reason.as_str(), e.machine_id.as_str()),
            ("warning", "exited", "m_1")
        );
        assert_eq!(e.data, Some(serde_json::json!({"code": 7})));
        // A record that carries a later version than the log (its last lines lost) moves
        // the seq past it: a version is never handed out twice.
        ev.floor(40);
        ev.floor(10);
        assert_eq!(ev.emit(Ev::normal(reason::CREATED, "")), 41);
        // The files are the daemon's alone.
        use std::os::unix::fs::PermissionsExt;
        let f = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn a_torn_last_line_is_cut_and_the_next_one_is_whole() {
        let (dir, ev) = open();
        ev.emit(Ev::normal(reason::CREATED, "a"));
        ev.emit(Ev::normal(reason::STARTED, "b"));
        drop(ev);
        let file = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap();
        f.write_all(br#"{"seq":3,"at":"2026-"#).unwrap();
        let ev = Events::open(dir.path()).unwrap();
        assert_eq!(ev.emit(Ev::normal(reason::STOPPED, "c")), 3);
        assert_eq!(all(&ev, 0), [1, 2, 3]);
        assert!(std::fs::read_to_string(&file).unwrap().ends_with("}\n"));
        // A file a crash left with nothing whole is removed.
        drop(ev);
        std::fs::write(dir.path().join("2999-01-01T00.ndjson"), b"{\"seq\":").unwrap();
        let ev = Events::open(dir.path()).unwrap();
        assert!(!dir.path().join("2999-01-01T00.ndjson").exists());
        assert_eq!(ev.emit(Ev::normal(reason::STOPPED, "d")), 4);
    }

    #[test]
    fn a_read_pages_from_its_cursor_and_filters() {
        let (_dir, ev) = open();
        ev.emit(Ev::normal(reason::HOST_STARTED, "up"));
        ev.emit(Ev::normal(reason::CREATED, "").of("m_a", "t1"));
        ev.emit(Ev::normal(reason::CREATED, "").of("m_b", "t2"));
        ev.emit(Ev::warning(reason::BOOT_FAILED, "").of("m_a", "t1"));
        ev.emit(Ev::normal(reason::DESTROYED, "").of("m_a", "t1"));
        assert_eq!(all(&ev, 0), [1, 2, 3, 4, 5]);
        assert_eq!(all(&ev, 3), [4, 5]);
        // A full page's cursor is its last event; the rest come from there.
        let p = ev.read(0, &Filter::default(), 2).unwrap();
        assert_eq!((p.events.len(), p.next), (2, 2));
        // A page the filter left short reads to the end: its cursor is the last seq, so a
        // poller never reads the same lines again.
        let mine = Filter {
            machine: Some("m_a".into()),
            ..Default::default()
        };
        let p = ev.read(0, &mine, 10).unwrap();
        let seqs: Vec<u64> = p.events.iter().map(|e| e.seq).collect();
        assert_eq!((seqs, p.next), (vec![2, 4, 5], 5));
        let warnings = Filter {
            tenant: Some("t1".into()),
            kind: Some("warning".into()),
            ..Default::default()
        };
        assert_eq!(ev.read(0, &warnings, 10).unwrap().events[0].seq, 4);
        assert_eq!(
            ev.read(5, &mine, 10).unwrap(),
            Page {
                events: vec![],
                next: 5
            }
        );
        // Past the last seq: the log began again, which the reader must learn.
        let err = ev.read(9, &Filter::default(), 10).unwrap_err();
        let gone = err.downcast_ref::<Gone>().expect("gone");
        assert_eq!(gone.oldest, 1);
        assert!(
            gone.message.contains("past the last event, 5"),
            "{}",
            gone.message
        );
    }

    #[test]
    fn retention_removes_old_hours_and_keeps_the_count_but_never_the_newest() {
        let (dir, ev) = open();
        logged_at(&ev, "2026-10-01T10:00:00Z", 3);
        logged_at(&ev, "2026-10-19T10:00:00Z", 3);
        logged_at(&ev, "2026-10-20T10:00:00Z", 3);
        // Seven days: the first hour goes.
        let now = t("2026-10-20T12:00:00Z");
        assert_eq!(ev.prune(now, 7, 100).unwrap(), 1);
        assert_eq!(all(&ev, 0), [4, 5, 6, 7, 8, 9]);
        // A cursor before the oldest kept is gone; one just before it is whole.
        let err = ev.read(2, &Filter::default(), 10).unwrap_err();
        assert_eq!(err.downcast_ref::<Gone>().map(|g| g.oldest), Some(4));
        assert_eq!(all(&ev, 3), [4, 5, 6, 7, 8, 9]);
        // More than the cap: whole hours, oldest first.
        assert_eq!(ev.prune(now, 7, 4).unwrap(), 1);
        assert_eq!(all(&ev, 0), [7, 8, 9]);
        // The newest file stays, however old and however many: the last seq is in it.
        assert_eq!(ev.prune(t("2027-01-01T00:00:00Z"), 7, 1).unwrap(), 0);
        let files = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(files, 1);
        drop(ev);
        let ev = Events::open(dir.path()).unwrap();
        assert_eq!(ev.emit(Ev::normal(reason::CREATED, "")), 10);
    }

    #[test]
    fn a_clock_that_steps_back_stays_in_the_newest_file() {
        let (dir, ev) = open();
        logged_at(&ev, "2026-10-20T15:00:00Z", 1);
        logged_at(&ev, "2026-10-20T14:00:00Z", 1);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["2026-10-20T15.ndjson"]);
        assert_eq!(all(&ev, 0), [1, 2]);
    }

    #[test]
    fn a_message_is_bounded_on_a_character() {
        let (_dir, ev) = open();
        let long = "é".repeat(2000);
        ev.emit(Ev::warning(reason::BOOT_FAILED, long));
        let m = &ev.read(0, &Filter::default(), 1).unwrap().events[0].message;
        assert!(m.len() <= MAX_MESSAGE, "{}", m.len());
        assert!(m.ends_with('…'));
        assert_eq!(bounded("short".into()), "short");
    }

    /// The next line of a watch, within a second.
    async fn next(rx: &mut mpsc::Receiver<String>) -> serde_json::Value {
        let line = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("a line in time")
            .expect("the watch is open");
        assert!(line.ends_with('\n'), "{line:?}");
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn a_watch_sends_what_follows_its_cursor_then_each_new_event() {
        let (_dir, ev) = open();
        for i in 0..3 {
            ev.emit(Ev::normal(reason::CREATED, format!("{i}")).of("m_a", "t1"));
        }
        ev.emit(Ev::normal(reason::CREATED, "").of("m_b", "t2"));
        let (tx, mut rx) = mpsc::channel(16);
        let f = Filter {
            tenant: Some("t1".into()),
            ..Default::default()
        };
        ev.watch(1, f, tx).await.unwrap();
        assert_eq!(next(&mut rx).await["seq"], 2);
        assert_eq!(next(&mut rx).await["seq"], 3);
        // Live: t1's, not t2's.
        ev.emit(Ev::normal(reason::STOPPED, "").of("m_b", "t2"));
        ev.emit(Ev::normal(reason::STOPPED, "").of("m_a", "t1"));
        let e = next(&mut rx).await;
        assert_eq!(
            (e["seq"].as_u64(), e["reason"].as_str()),
            (Some(6), Some("stopped"))
        );
        // A cursor the log cannot answer is refused before any line.
        let (tx, _rx) = mpsc::channel(16);
        let err = ev.watch(99, Filter::default(), tx).await.unwrap_err();
        assert!(err.downcast_ref::<Gone>().is_some(), "{err:#}");
        // The daemon going down ends it with a last line saying so.
        ev.close();
        let e = next(&mut rx).await;
        assert_eq!(e["code"], "shutdown");
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn a_watch_that_falls_behind_is_closed_and_never_blocks_the_log() {
        let (_dir, ev) = open();
        let (tx, mut rx) = mpsc::channel(16);
        ev.watch(0, Filter::default(), tx).await.unwrap();
        // More events than the buffer, faster than the watcher reads: every emit returns.
        for _ in 0..WATCH_BUFFER + 10 {
            ev.emit(Ev::normal(reason::CREATED, ""));
        }
        let mut last = serde_json::Value::Null;
        while let Some(line) = rx.recv().await {
            last = serde_json::from_str(&line).unwrap();
        }
        assert_eq!(last["code"], "lagged");
        assert!(last["error"]
            .as_str()
            .unwrap()
            .contains("watch again from since="));
    }

    #[tokio::test]
    async fn a_quiet_watch_sends_a_heartbeat() {
        let (_dir, ev) = open();
        let (tx, mut rx) = mpsc::channel(16);
        ev.watch(0, Filter::default(), tx).await.unwrap();
        // One event through: the watch is past its backlog and waits on the log.
        ev.emit(Ev::normal(reason::CREATED, ""));
        assert_eq!(next(&mut rx).await["seq"], 1);
        tokio::time::pause();
        tokio::time::advance(HEARTBEAT + std::time::Duration::from_secs(1)).await;
        assert_eq!(next(&mut rx).await, serde_json::json!({}));
    }
}
