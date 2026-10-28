//! Events (ADR 0019): what happened on this host, in one append-only log. An event is a line
//! of `state/events/<hour>.ndjson`, appended and synced under the log's lock, then sent to the
//! watchers; `seq` is one more per event and never reused. Repeats of a use, a refusal or a
//! readiness flip within `FOLD_MINUTES` of its line are folded into one later line.

use anyhow::{Context, Result};
use briqyard_api::{self as api, event, reason};
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
/// A quiet watch sends a bookmark this often, so a proxy does not cut it.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long after its line the repeats of an event are folded rather than logged.
const FOLD_MINUTES: i64 = 10;
/// The reasons whose repeats fold: uses and refusals, which change nothing, and the readiness
/// flips, which a probe can make every second.
const FOLDED: [&str; 4] = [
    reason::SESSION_OPENED,
    reason::QUOTA_EXCEEDED,
    reason::READY,
    reason::NOT_READY,
];
/// Of those, the ones that change the machine: a folded flip still takes a seq, its version,
/// with no line.
const FLIPS: [&str; 2] = [reason::READY, reason::NOT_READY];

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

    /// About a tenant, no machine of it: a create refused before it made one.
    pub fn tenant(mut self, tenant: &str) -> Self {
        tenant.clone_into(&mut self.tenant);
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
    /// The files, by hour, with the first seq and the number of lines each holds.
    files: BTreeMap<String, File>,
    /// The newest file, open for appending.
    open: Option<(String, std::fs::File)>,
    /// Events logged since the daemon started, by type and reason, folded ones included:
    /// `/metrics`.
    emitted: BTreeMap<(&'static str, &'static str), u64>,
    /// The repeats folded since an event's line, by tenant, machine and reason.
    series: BTreeMap<Key, Series>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct File {
    first: u64,
    lines: u64,
}

type Key = (String, String, &'static str);

/// An event's line and the repeats folded since, not logged yet.
struct Series {
    /// When the line was logged: repeats fold until `FOLD_MINUTES` after it.
    opened: DateTime<Utc>,
    folded: Option<Folded>,
}

/// Repeats folded: the last one, when it was, how many, and when the first was.
struct Folded {
    last: Ev,
    at: DateTime<Utc>,
    count: u64,
    first_at: DateTime<Utc>,
}

impl Series {
    fn due(&self, now: DateTime<Utc>) -> bool {
        now >= self.opened + Duration::minutes(FOLD_MINUTES)
    }

    fn fold(&mut self, ev: Ev, now: DateTime<Utc>) {
        let (count, first_at) = match &self.folded {
            Some(f) => (f.count + 1, f.first_at),
            None => (1, now),
        };
        self.folded = Some(Folded {
            last: ev,
            at: now,
            count,
            first_at,
        });
    }
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
        let file = self.files.entry(key).or_insert(File {
            first: e.seq,
            lines: 0,
        });
        file.lines += 1;
        Ok(())
    }

    fn oldest(&self) -> u64 {
        self.files.values().next().map_or(self.seq + 1, |f| f.first)
    }

    /// Logs a line with the next seq and sends it to the watchers; its seq. A log that cannot
    /// be written is warned about and the event still goes out: the seq is not taken back.
    fn line(
        &mut self,
        tx: &broadcast::Sender<api::Event>,
        ev: Ev,
        at: DateTime<Utc>,
        count: u64,
        first_at: Option<DateTime<Utc>>,
    ) -> u64 {
        self.seq += 1;
        let e = api::Event {
            seq: self.seq,
            at,
            kind: ev.kind.into(),
            reason: ev.reason.into(),
            message: bounded(ev.message),
            machine_id: ev.machine_id,
            tenant: ev.tenant,
            host: String::new(),
            data: ev.data,
            count,
            first_at,
        };
        if let Err(err) = self.append(&e) {
            tracing::warn!(seq = e.seq, reason = e.reason, err = %err, "event not written");
        }
        // Under the lock: watchers get the events in seq order.
        let _ = tx.send(e);
        self.seq
    }

    /// Logs the folded repeats of the series `pick` selects, each series' as one line, the
    /// last seen last; the series go on. The last seq given, if any.
    fn flush(
        &mut self,
        tx: &broadcast::Sender<api::Event>,
        pick: impl Fn(&Key) -> bool,
    ) -> Option<u64> {
        let mut folded: Vec<_> = self
            .series
            .iter_mut()
            .filter(|(k, _)| pick(k))
            .filter_map(|(_, s)| s.folded.take())
            .collect();
        folded.sort_by_key(|f| f.at);
        let mut last = None;
        for f in folded {
            last = Some(self.line(tx, f.last, f.at, f.count, Some(f.first_at)));
        }
        last
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
        for key in keys.iter().rev() {
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
            // What retention counts: the lines, not the seqs (a folded flip takes one, no line).
            let data = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
            let lines = data.iter().filter(|b| **b == b'\n').count() as u64;
            files.insert(
                key.clone(),
                File {
                    first: first.seq,
                    lines,
                },
            );
        }
        let (tx, _) = broadcast::channel(WATCH_BUFFER);
        Ok(Self {
            inner: Arc::new(Shared {
                log: Mutex::new(Log {
                    dir: dir.to_path_buf(),
                    seq,
                    files,
                    open: None,
                    emitted: BTreeMap::new(),
                    series: BTreeMap::new(),
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

    /// Logs an event and sends it to the watchers; its seq, the machine's version when it is
    /// about one. A repeat of a `FOLDED` reason within `FOLD_MINUTES` of its line is folded,
    /// no line: a flip still takes a seq (the machine changed), a use or a refusal none. Any
    /// other line about a machine logs the machine's folded repeats first, so the last line
    /// about it says what it is now.
    pub fn emit(&self, ev: Ev) -> Option<u64> {
        self.emit_at(ev, Utc::now())
    }

    fn emit_at(&self, ev: Ev, now: DateTime<Utc>) -> Option<u64> {
        let tx = &self.inner.tx;
        let mut log = self.inner.log.lock().unwrap();
        *log.emitted.entry((ev.kind, ev.reason)).or_default() += 1;
        let key: Key = (ev.tenant.clone(), ev.machine_id.clone(), ev.reason);
        let folds = !(key.0.is_empty() && key.1.is_empty()) && FOLDED.contains(&key.2);
        let flip = FLIPS.contains(&key.2);
        if let Some(s) = log.series.get_mut(&key).filter(|s| !s.due(now)) {
            s.fold(ev, now);
            if !flip {
                return None;
            }
            log.seq += 1;
            return Some(log.seq);
        }
        match folds && !flip {
            true => log.flush(tx, |k| *k == key),
            false if !key.1.is_empty() => log.flush(tx, |k| k.1 == key.1),
            false => None,
        };
        if folds {
            let opened = Series {
                opened: now,
                folded: None,
            };
            log.series.insert(key, opened);
        }
        Some(log.line(tx, ev, now, 1, None))
    }

    /// Ends the series whose window is over, as of `now`, and logs what they folded: a use's
    /// or a refusal's here; the machines whose flips are due are named, for `flush_machine`
    /// under their lock, since those lines move their version.
    pub fn flush_due(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut log = self.inner.log.lock().unwrap();
        log.series
            .retain(|_, s| !(s.due(now) && s.folded.is_none()));
        let uses: Vec<Key> = log
            .series
            .iter()
            .filter(|(k, s)| s.due(now) && !FLIPS.contains(&k.2))
            .map(|(k, _)| k.clone())
            .collect();
        log.flush(&self.inner.tx, |k| uses.contains(k));
        log.series.retain(|k, _| !uses.contains(k));
        let mut machines: Vec<String> = log
            .series
            .iter()
            .filter(|(_, s)| s.due(now))
            .map(|(k, _)| k.1.clone())
            .collect();
        machines.dedup();
        machines
    }

    /// Logs what a machine's series folded, the last seen last, and ends those whose window
    /// is over: the last seq given, its version. The caller holds the machine's record.
    pub fn flush_machine(&self, machine: &str, now: DateTime<Utc>) -> Option<u64> {
        let mut log = self.inner.log.lock().unwrap();
        let last = log.flush(&self.inner.tx, |k| k.1 == machine);
        log.series.retain(|k, s| k.1 != machine || !s.due(now));
        last
    }

    /// How many events were logged since the daemon started, by type and reason.
    pub fn emitted(&self) -> BTreeMap<(&'static str, &'static str), u64> {
        self.inner.log.lock().unwrap().emitted.clone()
    }

    /// Up to `limit` events after `since` that the filter keeps (blocking: it reads files).
    pub fn read(&self, since: u64, f: &Filter, limit: usize) -> Result<Page> {
        let (dir, files, last) = {
            let log = self.inner.log.lock().unwrap();
            (log.dir.clone(), log.files.clone(), log.seq)
        };
        let oldest = files.values().next().map_or(last + 1, |f| f.first);
        check_since(since, oldest, last)?;
        let files: Vec<(String, File)> = files.into_iter().collect();
        // From the last file that starts at or before the first event wanted.
        let from = files
            .iter()
            .rposition(|(_, f)| f.first <= since + 1)
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
    /// lines are kept; the newest file always stays, so the last seq is never lost.
    pub fn prune(&self, now: DateTime<Utc>, keep_days: u32, max: u64) -> Result<usize> {
        let cut = hour_key(now - Duration::days(keep_days as i64));
        let mut log = self.inner.log.lock().unwrap();
        let mut removed = 0;
        while log.files.len() > 1 {
            let key = log.files.keys().next().cloned().unwrap();
            let kept: u64 = log.files.values().map(|f| f.lines).sum();
            if key >= cut && kept <= max {
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

    /// Logs every folded repeat, then ends every watch: the daemon is going down. A machine's
    /// version stays its last flip's seq, which no line carries: a writer that read the
    /// summary gets one 409.
    pub fn close(&self) {
        let mut log = self.inner.log.lock().unwrap();
        log.flush(&self.inner.tx, |_| true);
        log.series.clear();
        drop(log);
        self.inner.closing.send_replace(true);
    }

    /// Each event from now on, as watchers get them, and whether the daemon is going down:
    /// what a stream that is not an event watch (a logs follow) ends on.
    pub fn subscribe(&self) -> (broadcast::Receiver<api::Event>, watch::Receiver<bool>) {
        (self.inner.tx.subscribe(), self.inner.closing.subscribe())
    }

    /// A watch from `since`: checked and its first page read now, so a cursor the log cannot
    /// answer is refused before any line goes out; then the lines, one per event (the page,
    /// the pages after it, then each new event), a bookmark every `HEARTBEAT` of quiet, and a
    /// last error line when the watcher fell behind or the daemon goes down. Ends when `tx` is
    /// dropped.
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
                    send(&tx, &mut closing, last_line("gone", &format!("{err:#}"))).await;
                    return;
                }
            };
        }
        let start = tokio::time::Instant::now() + HEARTBEAT;
        let mut beat = tokio::time::interval_at(start, HEARTBEAT);
        loop {
            // The line to send, and whether it is the last.
            let (out, last) = tokio::select! {
                r = rx.recv() => match r {
                    Ok(e) if e.seq <= cursor => continue,
                    Ok(e) => {
                        cursor = e.seq;
                        if !f.matches(&e) {
                            continue;
                        }
                        (line(&e), false)
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let why = format!(
                            "the watch fell {n} events behind the log: watch again from since={cursor}"
                        );
                        (last_line("lagged", &why), true)
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                // Every event up to `cursor` was looked at: a watch again from it misses nothing.
                _ = beat.tick() => (bookmark(cursor), false),
                _ = closing.wait_for(|c| *c) => {
                    // Only if there is room: a daemon going down waits for no reader.
                    let why = format!("the daemon is going down: watch again from since={cursor}");
                    let _ = tx.try_send(last_line("shutdown", &why));
                    return;
                }
            };
            if !send(&tx, &mut closing, out).await || last {
                return;
            }
        }
    }
}

/// Sends a line, unless the watcher went away or the daemon is going down.
pub async fn send(
    tx: &mpsc::Sender<String>,
    closing: &mut watch::Receiver<bool>,
    line: String,
) -> bool {
    tokio::select! {
        r = tx.send(line) => r.is_ok(),
        _ = closing.wait_for(|c| *c) => false,
    }
}

/// A watch's quiet line: the seq up to which it looked at every event, as a bookmark (no
/// `seq`: it is not an event).
pub fn bookmark(cursor: u64) -> String {
    format!("{{\"bookmark\":{cursor}}}\n")
}

/// The line a watch ends with: an error body, as the API's.
pub fn last_line(code: &str, why: &str) -> String {
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
                count: 1,
                first_at: None,
            };
            log.append(&e).unwrap();
        }
    }

    #[test]
    fn seqs_go_on_across_a_restart_and_from_the_records() {
        let (dir, ev) = open();
        assert_eq!(ev.emit(Ev::normal(reason::HOST_STARTED, "up")), Some(1));
        let seq = ev.emit(
            Ev::warning(reason::EXITED, "exited with code 7")
                .of("m_1", "t1")
                .data(serde_json::json!({"code": 7})),
        );
        assert_eq!(seq, Some(2));
        drop(ev);
        // A new daemon goes on from the log.
        let ev = Events::open(dir.path()).unwrap();
        assert_eq!(
            ev.emit(Ev::normal(reason::HOST_STARTED, "up again")),
            Some(3)
        );
        // Counted from this daemon's start, by type and reason.
        ev.emit(Ev::warning(reason::EXITED, "exited with code 1"));
        ev.emit(Ev::warning(reason::EXITED, "exited with code 2"));
        assert_eq!(
            ev.emitted().into_iter().collect::<Vec<_>>(),
            vec![(("normal", "host_started"), 1), (("warning", "exited"), 2)]
        );
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
        assert_eq!(ev.emit(Ev::normal(reason::CREATED, "")), Some(41));
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
        assert_eq!(ev.emit(Ev::normal(reason::STOPPED, "c")), Some(3));
        assert_eq!(all(&ev, 0), [1, 2, 3]);
        assert!(std::fs::read_to_string(&file).unwrap().ends_with("}\n"));
        // A file a crash left with nothing whole is removed.
        drop(ev);
        std::fs::write(dir.path().join("2999-01-01T00.ndjson"), b"{\"seq\":").unwrap();
        let ev = Events::open(dir.path()).unwrap();
        assert!(!dir.path().join("2999-01-01T00.ndjson").exists());
        assert_eq!(ev.emit(Ev::normal(reason::STOPPED, "d")), Some(4));
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
        assert_eq!(ev.emit(Ev::normal(reason::CREATED, "")), Some(10));
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

    /// What the log holds about a machine: (seq, reason, count).
    fn lines_of(ev: &Events) -> Vec<(u64, String, u64)> {
        let p = ev.read(0, &Filter::default(), 5000).unwrap();
        p.events
            .into_iter()
            .map(|e| (e.seq, e.reason, e.count))
            .collect()
    }

    fn session(n: u32) -> Ev {
        Ev::normal(reason::SESSION_OPENED, format!("sh #{n}")).of("m_a", "t1")
    }

    #[test]
    fn repeats_of_a_use_fold_into_one_line_after_their_window() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        let s = |m: i64| t0 + Duration::seconds(m);
        // The first is logged at once; the next ones within 10 minutes are folded, no seq.
        assert_eq!(ev.emit_at(session(0), s(0)), Some(1));
        for i in 1..=4 {
            assert_eq!(ev.emit_at(session(i), s(i as i64 * 60)), None);
        }
        // Another machine's, and the host's, are their own.
        let other = Ev::normal(reason::SESSION_OPENED, "").of("m_b", "t1");
        assert_eq!(ev.emit_at(other, s(300)), Some(2));
        assert_eq!(lines_of(&ev).len(), 2);
        // Nothing due before the window ends; at its end, one line for the four.
        assert!(ev.flush_due(s(599)).is_empty());
        assert_eq!(lines_of(&ev).len(), 2);
        assert!(
            ev.flush_due(s(600)).is_empty(),
            "no flips to log under a record"
        );
        let p = ev.read(2, &Filter::default(), 10).unwrap();
        let e = &p.events[0];
        assert_eq!((e.seq, e.count, e.message.as_str()), (3, 4, "sh #4"));
        assert_eq!((e.first_at, e.at), (Some(s(60)), s(240)));
        // The series ended: the next one is logged at once and opens another.
        assert_eq!(ev.emit_at(session(5), s(700)), Some(4));
        assert_eq!(ev.emit_at(session(6), s(701)), None);
        // `/metrics` counts every one, folded or not.
        assert_eq!(ev.emitted()[&("normal", "session_opened")], 8);
        // One alone keeps its shape: no count, no first time.
        let line = serde_json::to_value(&ev.read(0, &Filter::default(), 1).unwrap().events[0]);
        let line = line.unwrap();
        assert!(
            line.get("count").is_none() && line.get("first_at").is_none(),
            "{line}"
        );
    }

    #[test]
    fn a_change_logs_what_was_folded_first() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        for i in 0..3 {
            ev.emit_at(session(i), t0 + Duration::seconds(i as i64));
        }
        let stopped = Ev::normal(reason::STOPPED, "stopped (user)").of("m_a", "t1");
        assert_eq!(ev.emit_at(stopped, t0 + Duration::seconds(5)), Some(3));
        assert_eq!(
            lines_of(&ev),
            [
                (1, "session_opened".into(), 1),
                (2, "session_opened".into(), 2),
                (3, "stopped".into(), 1)
            ]
        );
        // The series goes on to its window's end: a session after the stop still folds.
        assert_eq!(ev.emit_at(session(9), t0 + Duration::seconds(6)), None);
    }

    #[test]
    fn folded_flips_take_a_seq_and_the_last_line_says_what_the_machine_is() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        let flip = |ready: bool, sec: i64| {
            let e = match ready {
                true => Ev::normal(reason::READY, format!("ready {sec}")),
                false => Ev::warning(reason::NOT_READY, format!("not ready {sec}")),
            };
            ev.emit_at(e.of("m_a", "t1"), t0 + Duration::seconds(sec))
        };
        assert_eq!(flip(true, 0), Some(1));
        assert_eq!(flip(false, 1), Some(2));
        // Folded: a seq (the machine's version moves), no line.
        assert_eq!(flip(true, 2), Some(3));
        assert_eq!(flip(false, 3), Some(4));
        assert_eq!(flip(true, 4), Some(5));
        assert_eq!(lines_of(&ev).len(), 2);
        // A cursor on a seq no line has reads on from it.
        assert_eq!(all(&ev, 4), Vec::<u64>::new());
        assert_eq!(ev.read(4, &Filter::default(), 10).unwrap().next, 5);
        // Due: the machine is named, its flips logged under its lock, the last seen last.
        let due = t0 + Duration::minutes(10);
        assert_eq!(ev.flush_due(due), ["m_a"]);
        assert_eq!(ev.flush_machine("m_a", due), Some(7));
        let p = ev.read(5, &Filter::default(), 10).unwrap();
        let got: Vec<_> = p
            .events
            .iter()
            .map(|e| (e.seq, e.reason.as_str(), e.count, e.message.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (6, "not_ready", 1, "not ready 3"),
                (7, "ready", 2, "ready 4")
            ]
        );
        assert!(ev.flush_due(due).is_empty());
        // A change of the machine logs its folded flips before itself, whatever their window.
        assert_eq!(flip(false, 700), Some(8));
        assert_eq!(flip(true, 701), Some(9));
        assert_eq!(flip(false, 702), Some(10));
        let stopping = Ev::normal(reason::STOPPING, "").of("m_a", "t1");
        assert_eq!(ev.emit_at(stopping, t0 + Duration::seconds(703)), Some(12));
        let reasons: Vec<String> = lines_of(&ev).into_iter().skip(4).map(|l| l.1).collect();
        assert_eq!(reasons, ["not_ready", "ready", "not_ready", "stopping"]);
    }

    #[test]
    fn a_tenant_refusal_folds_and_the_daemon_going_down_logs_what_was_folded() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        for i in 0..3 {
            let refused = Ev::warning(reason::QUOTA_EXCEEDED, format!("refused {i}")).tenant("t1");
            ev.emit_at(refused, t0 + Duration::seconds(i));
        }
        // The host's own events never fold.
        ev.emit_at(Ev::normal(reason::HOST_STARTED, ""), t0);
        ev.emit_at(Ev::normal(reason::HOST_STARTED, ""), t0);
        assert_eq!(lines_of(&ev).len(), 3);
        ev.close();
        let last = lines_of(&ev).pop().unwrap();
        assert_eq!(last, (4, "quota_exceeded".into(), 2));
    }

    #[test]
    fn retention_counts_lines_not_seqs() {
        let (dir, ev) = open();
        logged_at(&ev, "2026-10-20T10:00:00Z", 3);
        // Seqs a flip took with no line.
        ev.inner.log.lock().unwrap().seq += 1000;
        logged_at(&ev, "2026-10-20T11:00:00Z", 3);
        let now = t("2026-10-20T12:00:00Z");
        assert_eq!(ev.prune(now, 7, 6).unwrap(), 0);
        assert_eq!(ev.prune(now, 7, 5).unwrap(), 1);
        // Counted again at a start.
        drop(ev);
        let ev = Events::open(dir.path()).unwrap();
        let files: Vec<File> = ev
            .inner
            .log
            .lock()
            .unwrap()
            .files
            .values()
            .copied()
            .collect();
        assert_eq!(
            files,
            [File {
                first: 1004,
                lines: 3
            }]
        );
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
        // A bookmark: every event up to it was looked at.
        assert_eq!(next(&mut rx).await, serde_json::json!({"bookmark": 1}));
    }
}
