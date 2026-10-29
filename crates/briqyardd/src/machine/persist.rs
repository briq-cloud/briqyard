//! Writing a machine's record and its use down, closing the manager and handing machines over to the next daemon.

use super::*;

impl Manager {
    /// Writes the record: something about the machine changed.
    pub(super) fn save(&self, e: &Entry) -> Result<()> {
        self.put_record(e, |r| {
            r.updated_at = Utc::now();
            e.unsaved_use.store(false, Relaxed);
            true
        })
    }

    /// Every write of a machine's record: the record as `edit` leaves it (nothing when it says
    /// false), unless the machine is out of the manager. Checked and written under `removed`'s
    /// lock, which [`Self::forget`] holds to delete the record: a write from a task that took
    /// the entry before a destroy (a request waiting on its lock, a backup, the exit watcher)
    /// lands before the deletion or not at all, and never brings the record back.
    fn put_record(&self, e: &Entry, edit: impl FnOnce(&mut Record) -> bool) -> Result<()> {
        let removed = e.removed.lock().unwrap();
        if *removed {
            return Ok(());
        }
        let rec = {
            let mut r = e.rec.lock().unwrap();
            if !edit(&mut r) {
                return Ok(());
            }
            r.clone()
        };
        self.inner.store.put("machines", &rec.id, &rec)
    }

    /// [`Self::save`] of an edit whose result must be on disk before anyone reads it (a
    /// version no line carries, ADR 0047): `edit` runs under the record's lock and the record
    /// is written before that lock is released, all under `removed`'s lock as in
    /// [`Self::put_record`]. Nothing when the record is gone or `edit` says false.
    pub(super) fn save_edit(
        &self,
        e: &Entry,
        edit: impl FnOnce(&mut Record) -> bool,
    ) -> Result<()> {
        let removed = e.removed.lock().unwrap();
        if *removed {
            return Ok(());
        }
        let mut r = e.rec.lock().unwrap();
        if !edit(&mut r) {
            return Ok(());
        }
        r.updated_at = Utc::now();
        e.unsaved_use.store(false, Relaxed);
        self.inner.store.put("machines", &r.id, &*r)
    }

    /// Deletes the record for good, under the lock every write of it checks.
    pub(super) fn forget(&self, e: &Entry) -> Result<()> {
        let mut removed = e.removed.lock().unwrap();
        self.inner.store.delete("machines", &e.snapshot().id)?;
        *removed = true;
        Ok(())
    }

    /// Writes a record whose last use moved since it was last written, as it is: nothing
    /// about the machine changed, so `updated_at` stays. Under the machine's lock, and only
    /// while the manager still holds the machine: a destroy removes it under that lock, so a
    /// late write never brings a destroyed record back. A machine in a transition is skipped;
    /// the transition writes the record itself.
    pub(super) fn flush_use(&self, e: &Arc<Entry>) -> Result<()> {
        let Ok(_turn) = e.lock.try_lock() else {
            return Ok(());
        };
        self.write_use(e)
    }

    /// [`Self::flush_use`]'s write, for a caller that holds the machine's lock.
    fn write_use(&self, e: &Arc<Entry>) -> Result<()> {
        if !self.holds(e) {
            return Ok(());
        }
        self.put_record(e, |_| e.unsaved_use.swap(false, Relaxed))
    }

    /// Whether the manager still holds this entry: a destroy removes it under its lock.
    pub(super) fn holds(&self, e: &Arc<Entry>) -> bool {
        let id = e.snapshot().id;
        self.inner
            .machines
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|m| Arc::ptr_eq(m, e))
    }

    /// Suspends every running machine (a stop when Firecracker refuses): the daemon is going
    /// down, the host perhaps with it (a reboot). Stopped by the host, not idle: the next
    /// daemon starts each one again (ADR 0027), resumed when nothing under it changed. Then
    /// what the next daemon goes on from is written.
    pub async fn close(&self) {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut tasks = Vec::new();
        for e in entries {
            let st = e.snapshot().state;
            if st == state::RUNNING || st == state::STARTING {
                let m = self.clone();
                tasks.push(tokio::spawn(async move {
                    if let Err(err) = m
                        .stop_entry(&e, stop::HOST, Duration::from_secs(10), true, None)
                        .await
                    {
                        tracing::warn!(machine = e.snapshot().id, err = %err, "stop on shutdown");
                    }
                }));
            }
        }
        for t in tasks {
            let _ = t.await;
        }
        self.write_down().await;
    }

    /// Leaves every machine as it is for the next daemon to adopt (ADR 0027: an upgrade).
    /// Takes each machine's lock first, once a stop under way has settled, the namespaces'
    /// machines before the gateways (a start holds its machine's, then its gateway's): a
    /// transition under way ends before, and none begins while the caller holds what this
    /// answers, until the process ends. Then the last
    /// uses the records lack and the usage up to now are written, and nothing else.
    pub async fn hand_over(&self) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
        let mut entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.rec.lock().unwrap().is_gateway());
        let mut held = Vec::with_capacity(entries.len());
        for e in &entries {
            held.push(e.settled_lock().await);
        }
        let running = self.usage().1;
        tracing::info!(running, "handing the machines over to the next daemon");
        self.write_handed_ready(&entries);
        for e in entries.iter().filter(|e| e.unsaved_use.load(Relaxed)) {
            if let Err(err) = self.write_use(e) {
                tracing::warn!(machine = e.snapshot().id, err = %err, "last use not written");
            }
        }
        self.write_usage().await;
        held
    }

    /// Where a hand-over leaves the machines that were ready, for the next daemon's adoption.
    fn handed_ready_path(&self) -> PathBuf {
        self.inner.cfg.run_dir().join("handed-over-ready")
    }

    /// Readiness crosses a hand-over (ADR 0051), as the kubelet keeps it across its restart
    /// (KEP-4781): the machines running and ready now. Their probes start over in the next
    /// daemon, and a machine not ready until its first probe passed would hold the ingress for
    /// up to a probe period. Only a hand-over writes it, so a crash never carries a stale one.
    fn write_handed_ready(&self, entries: &[Arc<Entry>]) {
        let ready: Vec<String> = entries
            .iter()
            .filter(|e| e.snapshot().state == state::RUNNING && e.probe.lock().unwrap().ready)
            .map(|e| e.snapshot().id)
            .collect();
        let path = self.handed_ready_path();
        let written = std::fs::create_dir_all(self.inner.cfg.run_dir())
            .and_then(|()| std::fs::write(&path, ready.join("\n")));
        if let Err(err) = written {
            tracing::warn!(err = %err, "the machines ready at the hand-over not written");
        }
    }

    /// The machines the last hand-over left ready, read once: the file goes with the read.
    pub(super) fn take_handed_ready(&self) -> std::collections::HashSet<String> {
        let path = self.handed_ready_path();
        let read = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        read.lines().map(str::to_string).collect()
    }

    /// What the next daemon goes on from: the last uses not on the records yet, and the
    /// usage measured up to now.
    async fn write_down(&self) {
        let used: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.unsaved_use.load(Relaxed))
            .cloned()
            .collect();
        for e in used {
            if let Err(err) = self.flush_use(&e) {
                tracing::warn!(machine = e.snapshot().id, err = %err, "last use not written");
            }
        }
        self.write_usage().await;
    }

    /// The usage measured up to now, written.
    pub async fn write_usage(&self) {
        let now = Utc::now();
        self.measure(now).await;
        if let Err(err) = self
            .inner
            .usage
            .lock()
            .unwrap()
            .write(&self.inner.store, now)
        {
            tracing::warn!(err = %err, "usage not written");
        }
    }
}
