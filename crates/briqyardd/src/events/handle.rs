use super::*;

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
            // Retention counts lines, not seqs: a folded flip takes a seq with no line.
            let (mut last, mut lines) = (first.seq, 1);
            for e in events {
                (last, lines) = (e.seq, lines + 1);
            }
            if newest {
                seq = last;
            }
            let file = File {
                first: first.seq,
                last,
                lines,
            };
            files.insert(key.clone(), file);
        }
        let pruned = files.values().next().map_or(0, |f: &File| f.first - 1);
        let (tx, _) = broadcast::channel(WATCH_BUFFER);
        Ok(Self {
            inner: Arc::new(Shared {
                log: Mutex::new(Log {
                    dir: dir.to_path_buf(),
                    seq,
                    files,
                    pruned,
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

    pub(super) fn emit_at(&self, ev: Ev, now: DateTime<Utc>) -> Option<u64> {
        let tx = &self.inner.tx;
        let mut log = self.inner.log.lock().unwrap();
        *log.emitted.entry((ev.kind, ev.reason)).or_default() += 1;
        let key: Key = (ev.namespace.clone(), ev.machine_id.clone(), ev.reason);
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
            true => log.flush(tx, |k, _| *k == key),
            false if !key.1.is_empty() => log.flush(tx, |k, _| k.1 == key.1),
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
        log.flush(&self.inner.tx, |k, _| uses.contains(k));
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

    /// Logs what a machine's flips folded, the last seen last, and its uses whose window is
    /// over, and ends the series whose window is over: the last seq given, its version. The
    /// caller holds the machine's record. Every flip series is logged, due or not, so the last
    /// line says what the machine is.
    pub fn flush_machine(&self, machine: &str, now: DateTime<Utc>) -> Option<u64> {
        let mut log = self.inner.log.lock().unwrap();
        let pick = |k: &Key, s: &Series| k.1 == machine && (FLIPS.contains(&k.2) || s.due(now));
        let last = log.flush(&self.inner.tx, pick);
        log.series.retain(|k, s| k.1 != machine || !s.due(now));
        last
    }

    /// How many events were logged since the daemon started, by type and reason.
    pub fn emitted(&self) -> BTreeMap<(&'static str, &'static str), u64> {
        self.inner.log.lock().unwrap().emitted.clone()
    }

    /// Up to `limit` events after `since` that the filter keeps (blocking: it reads files).
    pub fn read(&self, since: u64, f: &Filter, limit: usize) -> Result<Page> {
        let (dir, files, last, pruned) = {
            let log = self.inner.log.lock().unwrap();
            (log.dir.clone(), log.files.clone(), log.seq, log.pruned)
        };
        let oldest = files.values().next().map_or(last + 1, |f| f.first);
        check_since(since, pruned, oldest, last)?;
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
                    let (pruned, oldest) = {
                        let log = self.inner.log.lock().unwrap();
                        (log.pruned, log.oldest())
                    };
                    check_since(since, pruned, oldest, last)?;
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
            if let Some(f) = log.files.remove(&key) {
                log.pruned = f.last;
            }
            removed += 1;
        }
        Ok(removed)
    }

    /// Logs every folded repeat, then ends every watch: the daemon is going down. A machine's
    /// version stays its last flip's seq, which no line carries: a writer that read the
    /// summary gets one 409.
    pub fn close(&self) {
        let mut log = self.inner.log.lock().unwrap();
        log.flush(&self.inner.tx, |_, _| true);
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

    pub(super) async fn read_blocking(&self, since: u64, f: Filter) -> Result<Page> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.read(since, &f, api::events_limit(None))).await?
    }

    pub(super) async fn stream(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::testutil::*;
    use briqyard_api::reason;

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
            namespace: Some("t1".into()),
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
            namespace: Some("t1".into()),
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
