//! A destroyed machine's holder, the schedule's turns, and receiving disks.

use super::*;

impl Manager {
    /// Keeps a destroyed machine's backups: its holder, made at its destroy, or updated by a
    /// backup that finished after it.
    pub(in super::super) fn hold(&self, rec: &Record, bytes: u64, turn: Turn) -> Result<()> {
        let now = Utc::now();
        let h = self
            .inner
            .backups
            .holders
            .lock()
            .unwrap()
            .entry(rec.id.clone())
            .or_insert_with(|| {
                let r = HolderRec {
                    machine_id: rec.id.clone(),
                    namespace: rec.namespace.clone(),
                    name: rec.name.clone(),
                    metadata: rec.metadata.clone(),
                    size: rec.size,
                    destroyed_at: now,
                    bytes,
                };
                Holder::new(r, turn, now)
            })
            .clone();
        let r = {
            let mut r = h.rec.lock().unwrap();
            r.bytes = bytes;
            h.meter.lock().unwrap().disks.backups = bytes;
            r.clone()
        };
        self.inner.store.put(HOLDERS, &r.machine_id, &r)
    }

    /// A destroy's holder for the backups the record names. A destroy that found no disks
    /// may be a second one: a destroy cut short after its disks went, or a record an older
    /// daemon wrote back after its destroy, whose backups may have been deleted since. Then
    /// what the store lists is held, nothing when it lists none; a store that does not list
    /// them within [`LIST_AT_DESTROY`] fails the destroy.
    pub(in super::super) async fn hold_at_destroy(
        &self,
        rec: &Record,
        had_disks: bool,
        turn: Turn,
    ) -> Result<(), MError> {
        if rec.backup_bytes == 0 && rec.backup.last.is_none() {
            return Ok(());
        }
        let bytes = match (had_disks, self.inner.backups.store.is_some()) {
            (false, true) => {
                let listed = tokio::time::timeout(LIST_AT_DESTROY, self.backups(&rec.id))
                    .await
                    .map_err(|_| {
                        anyhow!(
                            "backups of {} not listed by the store within {} s",
                            rec.id,
                            LIST_AT_DESTROY.as_secs()
                        )
                    })??;
                if listed.is_empty() {
                    return Ok(());
                }
                listed.iter().map(|b| b.bytes).sum()
            }
            _ => rec.backup_bytes,
        };
        Ok(self.hold(rec, bytes, turn)?)
    }

    /// The tick's backup step: each machine whose next backup is due gets one, and each
    /// holder past `keep_destroyed_days` loses its backups, `backup.at_once` at a time.
    /// Detached, since a backup can take minutes: the turn taken here keeps a machine to one
    /// at a time across ticks. The tasks are returned for a test to wait on.
    pub(in super::super) fn backup_step(
        &self,
        now: DateTime<Utc>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        if self.inner.backups.store.is_none() || self.inner.backups.jobs.is_closed() {
            return Vec::new();
        }
        let due: Vec<(Arc<Entry>, OwnedMutexGuard<()>)> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.is_namespaces()
                    && r.state != state::DESTROYING
                    && r.has_disks()
                    && r.backup.policy.is_some()
                    && r.backup.next_at.is_none_or(|t| t <= now)
            })
            .filter_map(|e| Some((e.clone(), e.backup_turn.clone().try_lock_owned().ok()?)))
            .collect();
        let keep = chrono::Duration::days(self.inner.cfg.backup.keep_destroyed_days as i64);
        let expired: Vec<(Arc<Holder>, OwnedMutexGuard<()>)> = self
            .inner
            .backups
            .holders
            .lock()
            .unwrap()
            .values()
            .filter(|h| h.rec.lock().unwrap().destroyed_at + keep <= now)
            .filter_map(|h| Some((h.clone(), h.turn.clone().try_lock_owned().ok()?)))
            .collect();
        let mut tasks = Vec::new();
        for (e, turn) in due {
            let Some(admission) = self.inner.backups.jobs.try_reserve() else {
                break;
            };
            if let Ok(ticket) = self.inner.backups.jobs.start(
                self.clone(),
                jobs::Work::Scheduled(e, now),
                turn,
                admission,
            ) {
                tasks.push(tokio::spawn(ticket.finished()));
            }
        }
        for (h, turn) in expired {
            let Some(admission) = self.inner.backups.jobs.try_reserve() else {
                break;
            };
            if let Ok(ticket) =
                self.inner
                    .backups
                    .jobs
                    .start(self.clone(), jobs::Work::Expire(h), turn, admission)
            {
                tasks.push(tokio::spawn(ticket.finished()));
            }
        }
        tasks
    }

    /// A due machine's backup, its turn held. A machine with no process whose disks wrote
    /// nothing since its last backup is not backed up again: its next time moves on.
    pub(super) async fn scheduled_backup(&self, e: &Arc<Entry>, now: DateTime<Utc>) {
        let r = e.snapshot();
        // Read again under the turn: a PATCH may have moved it while it waited for the gate.
        let Some(every) = r.backup.policy.as_ref().and_then(|p| p.check().ok()) else {
            return;
        };
        if r.backup.next_at.is_some_and(|t| t > now) {
            return;
        }
        if holds_memory(&r.state) || self.written_since_backup(&r).await {
            let _ = self.backup_entry(e, now).await;
            return;
        }
        tracing::debug!(machine = r.id, "unchanged since its last backup");
        let _lock = e.lock.lock().await;
        if self.holds(e) {
            e.rec.lock().unwrap().backup.next_at = Some(after(now, every));
            if let Err(err) = self.save(e) {
                tracing::warn!(machine = r.id, err = %err, "backup schedule not written");
            }
        }
    }

    /// Whether a disk of the machine was written since its last backup's snapshot; true when
    /// it cannot tell (no last backup, the snapshot gone, a `zfs` that does not answer).
    pub(super) async fn written_since_backup(&self, r: &Record) -> bool {
        let Some(last) = &r.backup.last else {
            return true;
        };
        let snap = format!("bk-{last}");
        let z = &self.inner.zfs;
        for ds in [r.root_dataset(), r.data_dataset()] {
            match z.exists(&ds).await {
                Ok(false) => continue,
                Ok(true) => {}
                Err(_) => return true,
            }
            if !matches!(z.written_since(&ds, &snap).await, Ok(0)) {
                return true;
            }
        }
        false
    }

    /// A holder whose time ran out: its backups are deleted, newest first, then the holder.
    pub(super) async fn expire(&self, h: &Arc<Holder>) {
        let (Ok(store), id) = (
            self.backup_store(),
            h.rec.lock().unwrap().machine_id.clone(),
        ) else {
            return;
        };
        let all = match self.backups(&id).await {
            Ok(all) => all,
            Err(err) => {
                tracing::warn!(machine = id, err = %err, "expired backups not listed");
                return;
            }
        };
        let mut deleted = Vec::new();
        for b in all.iter().rev() {
            if let Err(err) = self.delete_backup_objects(store, b).await {
                tracing::warn!(machine = id, backup = b.id, err = %err, "expired backup kept");
                break;
            }
            deleted.push(b.id.clone());
        }
        let left: Vec<api::Backup> = all
            .into_iter()
            .filter(|b| !deleted.contains(&b.id))
            .collect();
        let owner = Owner::Holder(h.clone());
        if let Err(err) = self
            .settle(&owner, &left, deleted_event(&deleted, "expired"))
            .await
        {
            tracing::warn!(machine = id, err = %err, "holder not written");
        }
    }

    /// Adds what the holders' backups took since the last tick to their machines' buckets.
    pub(in super::super) fn meter_holders(&self, now: DateTime<Utc>) {
        let holders: Vec<Arc<Holder>> = self
            .inner
            .backups
            .holders
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for h in holders {
            let (who, used) = {
                let r = h.rec.lock().unwrap();
                let mut m = h.meter.lock().unwrap();
                m.advance(now, usage::Held::default());
                let who = api::UsageBucket {
                    machine_id: r.machine_id.clone(),
                    namespace: r.namespace.clone(),
                    metadata: r.metadata.clone(),
                    size: r.size,
                    ..Default::default()
                };
                (who, m.drain())
            };
            self.inner.usage.lock().unwrap().add(&who, used);
        }
    }

    /// Finds a backup of a machine id, by id or the newest ("latest" or empty).
    pub(in super::super) async fn find_backup(
        &self,
        machine_id: &str,
        which: &str,
    ) -> Result<api::Backup, MError> {
        let store = self.backup_store()?;
        let id = if which.is_empty() || which == "latest" {
            let all = self.backups(machine_id).await?;
            all.last()
                .map(|b| b.id.clone())
                .ok_or_else(|| invalid(format!("no backup of {machine_id} in the store")))?
        } else {
            which.to_string()
        };
        let data = store
            .get_bytes(&format!("backups/{machine_id}/{id}.json"))
            .await
            .map_err(|_| MError::NoBackup(format!("{machine_id}/{id}")))?;
        serde_json::from_slice(&data).map_err(|e| invalid(format!("backup {id}: {e}")))
    }

    /// Makes the machine's disks from a backup: the whole chain of streams, oldest first,
    /// received into the new datasets. Raw streams (ADR 0035) land as their own encryption
    /// root under the key they were sent with: that key, asked by its id, opens them, and they
    /// then take the pool's. A chain in clear (before ADR 0035) is received as it always was.
    /// A chain is one or the other: a raw increment is sent only over a raw backup under the
    /// same key (`in_store`). The key is given to a disk once its whole chain is in: a raw
    /// increment is received only into a dataset that is still its own encryption root.
    pub(in super::super) async fn receive_disks(
        &self,
        e: &Arc<Entry>,
        b: &api::Backup,
        key: Option<&str>,
    ) -> Result<()> {
        let store = self.backup_store()?;
        let rec = e.snapshot();
        let all = self.backups(&b.machine_id).await?;
        for disk in &b.disks {
            let chain = backup_chain(&all, b, &disk.disk);
            let ds = if disk.disk == "data" {
                rec.data_dataset()
            } else {
                rec.root_dataset()
            };
            self.inner.zfs.create_parent(&ds).await?;
            for step in chain {
                let source = store.clone();
                let object_key = step.key.clone();
                self.inner
                    .zfs
                    .receive_with(&ds, move |mut stdin| async move {
                        let mut reader = source.get(&object_key).await?;
                        tokio::io::copy(&mut reader, &mut stdin)
                            .await
                            .with_context(|| format!("restore {object_key}"))?;
                        drop(stdin);
                        Ok(())
                    })
                    .await?;
            }
            if let Some(key) = key {
                self.inner.zfs.inherit_key(&ds, key).await?;
            }
            self.inner.zfs.device(&ds).await?;
        }
        Ok(())
    }
}
