//! The sleeper: the periodic pass that sleeps idle machines, meters, assesses conditions and watches storage.

use super::*;

impl Manager {
    /// Every 15 s: what machines used since the last tick is measured, the host's conditions
    /// are decided (images removed under disk pressure), idle machines go to sleep, then the
    /// gateways no machine needs, uses since the last tick reach the disk, and a destroy left
    /// `destroying` (a daemon restart, a disk that was busy) is tried again. The first tick is at once: it is where an adopted machine's CPU count starts.
    pub(super) async fn sleeper(self) {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            self.tick().await;
        }
    }

    /// Logs the repeats folded for 10 minutes (ADR 0047): a machine's flips under its record,
    /// since their line is its version. Under the machine's lock and only while the manager
    /// holds it, as `flush_use`: a destroy removes it under that lock, so the write never
    /// brings a destroyed record back. A machine in a transition is skipped: the transition's
    /// own line logs them, and the next tick ends the series.
    pub(super) fn log_folded(&self, now: DateTime<Utc>) {
        for id in self.inner.events.flush_due(now) {
            let e = self.inner.machines.lock().unwrap().get(&id).cloned();
            let Some(e) = e else {
                self.inner.events.flush_machine(&id, now);
                continue;
            };
            let Ok(_turn) = e.lock.try_lock() else {
                continue;
            };
            if !self.holds(&e) {
                self.inner.events.flush_machine(&id, now);
                continue;
            }
            let written = self.save_edit(&e, |r| {
                let seq = self.inner.events.flush_machine(&id, now);
                if let Some(seq) = seq {
                    r.version = seq;
                }
                seq.is_some()
            });
            if let Err(err) = written {
                tracing::warn!(machine = id, err = %err, "record not written");
            }
        }
    }

    pub(super) async fn tick(&self) {
        let now = Utc::now();
        self.measure(now).await;
        self.assess(now).await;
        if let Err(err) =
            self.inner
                .events
                .prune(now, self.inner.cfg.events_keep_days, events::MAX_EVENTS)
        {
            tracing::warn!(err = %err, "old events not removed");
        }
        self.log_folded(now);
        let (due, used, destroying): (Vec<Arc<Entry>>, Vec<Arc<Entry>>, Vec<String>) = {
            let machines = self.inner.machines.lock().unwrap();
            let due = machines
                .values()
                .filter(|e| {
                    let r = e.rec.lock().unwrap();
                    r.state == state::RUNNING
                        && e.in_flight.load(Relaxed) == 0
                        && idle_past(r.last_used_at, r.sleep_window(), now)
                })
                .cloned()
                .collect();
            let used = machines
                .values()
                .filter(|e| e.unsaved_use.load(Relaxed))
                .cloned()
                .collect();
            // One whose lock is held has a destroy under way already.
            let destroying = machines
                .values()
                .filter(|e| {
                    e.rec.lock().unwrap().state == state::DESTROYING && e.lock.try_lock().is_ok()
                })
                .map(|e| e.snapshot().id)
                .collect();
            (due, used, destroying)
        };
        // Idle machines stop together, a few at a time: one stop can take its grace and a
        // kill, and a tick with many must not take minutes.
        let at_once = Arc::new(tokio::sync::Semaphore::new(SLEEPS_AT_ONCE));
        let mut stops = tokio::task::JoinSet::new();
        for e in due {
            let (m, at_once) = (self.clone(), at_once.clone());
            stops.spawn(async move {
                let _turn = at_once.acquire().await;
                tracing::info!(machine = e.snapshot().id, "machine idle, going to sleep");
                let suspend = m.inner.cfg.suspend_on_sleep;
                if let Err(err) = m
                    .stop_entry(&e, stop::IDLE, Duration::from_secs(10), suspend, None)
                    .await
                {
                    tracing::warn!(machine = e.snapshot().id, err = %err, "sleep");
                }
            });
        }
        while stops.join_next().await.is_some() {}
        // Then the gateways nothing needs any more, now that the machines that did may sleep.
        for gw in self.gateways_out_of_step(true) {
            let (m, at_once) = (self.clone(), at_once.clone());
            stops.spawn(async move {
                let _turn = at_once.acquire().await;
                m.sleep_gateway(&gw).await;
            });
        }
        while stops.join_next().await.is_some() {}
        for e in used {
            if let Err(err) = self.flush_use(&e) {
                tracing::warn!(machine = e.snapshot().id, err = %err, "last use not written");
            }
        }
        for id in destroying {
            if let Err(err) = self.destroy_machine(&id, None).await {
                tracing::warn!(machine = id, err = %err, "resume destroy");
            }
        }
        // Detached: they run past this tick.
        drop(self.backup_step(now));
    }

    // --- usage (ADR 0017) ---

    /// Measures every machine up to `now`, then settles the hours: those over are closed, the
    /// open ones written once a minute, the old ones removed.
    pub(super) async fn measure(&self, now: DateTime<Utc>) {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        self.meter(&entries, now).await;
        self.meter_holders(now);
        let keep = self.inner.cfg.usage_keep_days;
        let settled = self
            .inner
            .usage
            .lock()
            .unwrap()
            .settle(&self.inner.store, now, keep);
        if let Err(err) = settled {
            tracing::warn!(err = %err, "usage not written");
        }
    }

    // --- conditions (ADR 0021) ---

    /// Reads the pool and decides the host's conditions, each change an event. Under disk
    /// pressure, unused images go, oldest first, until the pool is back over the threshold.
    /// A pool that cannot be read leaves `disk_pressure` as it was.
    pub(super) async fn assess(&self, now: DateTime<Utc>) {
        let t = self.inner.cfg.conditions;
        let (used, _, _) = self.usage();
        let memory = conditions::memory(used.memory_mb, self.capacity().memory_mb, &t);
        let pool = match self.inner.zfs.pool().await {
            Ok(p) => Some(p),
            Err(err) => {
                tracing::warn!(err = %err, "conditions: pool not read");
                None
            }
        };
        if let Some(p) = pool {
            *self.inner.pool.lock().unwrap() = Some(p);
        }
        let changed: Vec<api::Condition> = {
            let mut c = self.inner.conditions.lock().unwrap();
            let disk = pool.map(|p| conditions::disk(p, &t));
            [
                (api::condition::MEMORY_PRESSURE, Some(memory)),
                (api::condition::DISK_PRESSURE, disk),
            ]
            .into_iter()
            .filter_map(|(kind, found)| c.set(kind, found?, now))
            .collect()
        };
        for c in changed {
            self.note_condition(c);
        }
        let short = pool.map_or(0, |p| conditions::disk_short(p, &t));
        if short > 0 {
            self.free_images(short).await;
        }
    }

    /// A condition that changed: its event and its log line.
    fn note_condition(&self, c: api::Condition) {
        let ev = match c.status {
            true => Ev::warning(reason::HOST_CONDITION, format!("{}: {}", c.kind, c.message)),
            false => Ev::normal(
                reason::HOST_CONDITION,
                format!("{} cleared: {}", c.kind, c.message),
            ),
        };
        if c.status {
            tracing::warn!(
                condition = c.kind,
                message = c.message,
                "host condition true"
            );
        } else {
            tracing::info!(
                condition = c.kind,
                message = c.message,
                "host condition cleared"
            );
        }
        let data = json!({ "condition": c.kind, "status": c.status });
        self.inner.events.emit(ev.data(data));
    }

    /// Every 15 s, apart from the tick, which a stuck `zfs` command holds too:
    /// `storage_stalled` while one has run past `zfs::STALL_AFTER` (ADR 0046).
    pub(super) async fn storage_watch(self) {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            self.assess_storage(crate::zfs::STALL_AFTER, Utc::now());
        }
    }

    pub(super) fn assess_storage(&self, after: Duration, now: DateTime<Utc>) {
        let found = conditions::storage(self.inner.zfs.stalled(after));
        let changed =
            self.inner
                .conditions
                .lock()
                .unwrap()
                .set(api::condition::STORAGE_STALLED, found, now);
        if let Some(c) = changed {
            self.note_condition(c);
        }
    }

    /// Removes unused images until they freed `need` bytes: an image a record names is in
    /// use, even before its machine's disk clones it.
    async fn free_images(&self, need: u64) {
        let named: std::collections::HashSet<String> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .map(|e| e.rec.lock().unwrap().image_key.clone())
            .collect();
        match self.inner.images.free(need, &named).await {
            Ok((0, _)) => {}
            Ok((n, freed)) => tracing::info!(
                removed = n,
                freed_mb = freed >> 20,
                need_mb = need >> 20,
                "images removed under disk pressure"
            ),
            Err(err) => tracing::warn!(err = %err, "images not removed under disk pressure"),
        }
    }

    /// Reads each source once for these machines (the pool's datasets, the internet
    /// counters), then each machine's cgroup and memory snapshot; adds what each used since
    /// its last measure to its meter, and takes that into the ledger. A source that cannot be
    /// read adds nothing this time, and its next reading covers it.
    pub(super) async fn meter(&self, entries: &[Arc<Entry>], now: DateTime<Utc>) {
        let disks = match self.inner.zfs.space_under("m").await {
            Ok(spaces) => Some(disks_by_machine(&spaces)),
            Err(err) => {
                tracing::warn!(err = %err, "usage: disks not read");
                None
            }
        };
        let internet = match self.inner.net.counters().await {
            Ok(c) => Some(c),
            Err(err) => {
                tracing::warn!(err = %err, "usage: internet counters not read");
                None
            }
        };
        for e in entries {
            // Destroyed since it was listed: its destroy measured it a last time.
            if !self.holds(e) {
                continue;
            }
            let r = e.snapshot();
            let jail = self.jail_for(&r).map(|j| j.base);
            let mut files = fc::snapshot_files(
                &self.inner.cfg.run_dir().join(&r.id),
                jail.as_deref(),
                &r.id,
            )
            .to_vec();
            files.extend(self.memory_snapshot_files(&r));
            let memory_snapshot = usage::file_bytes(&files);
            let cgroup = self.inner.vmm.cgroup(&r.id).await;
            let (who, used) = {
                let r = e.rec.lock().unwrap();
                let mut m = e.meter.lock().unwrap();
                if let Some(all) = &disks {
                    let mut d = all.get(&r.id).copied().unwrap_or_default();
                    d.snapshots += memory_snapshot;
                    d.backups = r.backup_bytes;
                    m.disks = d;
                }
                m.advance(now, held(&r));
                let net = internet.as_ref().and_then(|c| c.get(&r.ip)).copied();
                m.counters(now, cgroup.map(|c| c.cpu_usec), net, e.traffic.take());
                m.memory_bytes = cgroup.map_or(0, |c| c.memory_bytes);
                (usage_identity(&r), m.drain())
            };
            self.inner.usage.lock().unwrap().add(&who, used);
        }
    }
}

/// When a running machine goes to sleep: its last use plus its window. None while it was
/// never used or never sleeps, and for a window past every date there is (`"99999999d"`):
/// a time that never comes.
pub(super) fn sleeps_at(
    last_used: Option<DateTime<Utc>>,
    window: Option<Duration>,
) -> Option<DateTime<Utc>> {
    let w = chrono::Duration::from_std(window?).ok()?;
    last_used?.checked_add_signed(w)
}

/// A namespace's machine the host stopped: what the daemon's start boots again.
pub(super) fn stopped_by_host(r: &Record) -> bool {
    r.state == state::STOPPED && r.stopped_reason == stop::HOST && r.is_namespaces()
}

/// Whether the sleep window has run out at `now`. A clock that went backwards (a last use
/// in the future) is not idle.
pub(super) fn idle_past(
    last_used: Option<DateTime<Utc>>,
    window: Option<Duration>,
    now: DateTime<Utc>,
) -> bool {
    match (last_used, window) {
        (Some(t), Some(w)) => now
            .signed_duration_since(t)
            .to_std()
            .map(|d| d > w)
            .unwrap_or(false),
        _ => false,
    }
}
