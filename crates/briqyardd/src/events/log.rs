use super::*;

pub(super) struct Log {
    pub(super) dir: PathBuf,
    /// The last seq given.
    pub(super) seq: u64,
    /// The files, by hour, with the first and last seqs and the number of lines each holds.
    pub(super) files: BTreeMap<String, File>,
    /// The last seq of the newest file retention removed (at start, the seq before the oldest
    /// file kept): a cursor before it misses lines; one at or past it misses none, even on a
    /// seq no line carries.
    pub(super) pruned: u64,
    /// The newest file, open for appending.
    pub(super) open: Option<(String, std::fs::File)>,
    /// Events logged since the daemon started, by type and reason, folded ones included:
    /// `/metrics`.
    pub(super) emitted: BTreeMap<(&'static str, &'static str), u64>,
    /// The repeats folded since an event's line, by namespace, machine and reason.
    pub(super) series: BTreeMap<Key, Series>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct File {
    pub(super) first: u64,
    pub(super) last: u64,
    pub(super) lines: u64,
}

/// An hour's file name without its extension; names sort as their hours do.
pub(super) fn hour_key(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H").to_string()
}

pub(super) fn path(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{key}.ndjson"))
}

/// The events of a file, in order, its torn last line (a crash in a write) left out.
pub(super) fn lines(file: std::fs::File) -> impl Iterator<Item = api::Event> {
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
pub(super) fn cut_torn_tail(p: &Path) -> Result<()> {
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
pub(super) fn bounded(mut s: String) -> String {
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
    pub(super) fn append(&mut self, e: &api::Event) -> Result<()> {
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
            last: e.seq,
            lines: 0,
        });
        file.lines += 1;
        file.last = e.seq;
        Ok(())
    }

    pub(super) fn oldest(&self) -> u64 {
        self.files.values().next().map_or(self.seq + 1, |f| f.first)
    }

    /// Logs a line with the next seq and sends it to the watchers; its seq. A log that cannot
    /// be written is warned about and the event still goes out: the seq is not taken back.
    pub(super) fn line(
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
            namespace: ev.namespace,
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
    pub(super) fn flush(
        &mut self,
        tx: &broadcast::Sender<api::Event>,
        pick: impl Fn(&Key, &Series) -> bool,
    ) -> Option<u64> {
        let mut folded: Vec<_> = self
            .series
            .iter_mut()
            .filter(|(k, s)| pick(k, s))
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

/// Whether the events after `since` are all still in the log: `0` always is; `pruned` is the
/// last seq retention removed, `oldest` the first kept.
pub(super) fn check_since(since: u64, pruned: u64, oldest: u64, last: u64) -> Result<(), Gone> {
    if since > last {
        return Err(Gone {
            oldest,
            message: format!(
                "since {since} is past the last event, {last}: this host's log began again; read from 0"
            ),
        });
    }
    if since > 0 && since < pruned {
        return Err(Gone {
            oldest,
            message: format!(
                "since {since}: the events after it are gone; the oldest kept is {oldest}"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::testutil::*;
    use briqyard_api::reason;

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
}
