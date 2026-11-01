//! Taking a backup: the object store, the seal, the streams and their record.

use super::*;

impl Manager {
    pub(super) fn backup_store(&self) -> Result<&ObjectStore, MError> {
        self.inner
            .backups
            .store
            .as_ref()
            .ok_or_else(|| invalid("backups are off on this host (backup.store)"))
    }

    /// What a backup is sealed and named with (ADR 0035): the pool key asked of its source,
    /// checked against the pool (a key file replaced, a registry restored to an older key, a
    /// pool re-keyed by hand would otherwise name a key its streams are not under), then
    /// dropped once derived.
    pub(super) async fn seal(&self) -> Result<Seal, MError> {
        let key = crate::poolkey::pool_key(&self.inner.cfg)
            .await
            .context("the pool key, for the backup's seal")?;
        self.inner
            .zfs
            .check_key(&key)
            .await
            .context("the pool key from its source is not the pool's")?;
        Ok(Seal::of(&key)?)
    }

    /// The key a backup is encrypted under, asked by its id for the restore `rs`; none for a
    /// backup in clear.
    pub(in super::super) async fn backup_key(
        &self,
        b: &api::Backup,
        rs: &api::RestoreSpec,
    ) -> Result<Option<String>, MError> {
        let Some(id) = &b.key_id else {
            return Ok(None);
        };
        let key = crate::poolkey::by_id(&self.inner.cfg, id, rs)
            .await
            .with_context(|| format!("the key of backup {}", b.id))?;
        Ok(Some(key))
    }

    pub(super) fn holder(&self, id: &str) -> Option<Arc<Holder>> {
        self.inner.backups.holders.lock().unwrap().get(id).cloned()
    }

    pub(super) fn owner(&self, id: &str) -> Result<Owner, MError> {
        match self.own_entry(id) {
            Ok(e) => Ok(Owner::Machine(e)),
            Err(MError::NotFound) => self.holder(id).map(Owner::Holder).ok_or(MError::NotFound),
            Err(err) => Err(err),
        }
    }

    /// A backup now, on request: after any backup of the machine under way.
    pub async fn backup(&self, id: &str) -> Result<api::Backup, MError> {
        let e = self.own_entry(id)?;
        self.ordinary_operation(&e.snapshot())?;
        self.backup_store()?;
        let turn = e.backup_turn.clone().lock_owned().await;
        let admission = self.inner.backups.jobs.reserve().await?;
        self.inner
            .backups
            .jobs
            .start(
                self.clone(),
                jobs::Work::Requested(e, Utc::now()),
                turn,
                admission,
            )?
            .result()
            .await
    }

    /// One backup of a machine whose turn the caller holds, started `now`: sent, recorded and
    /// pruned to its policy's `keep`; what the store then holds, the next time (`every` after
    /// `now`) and the event go to its record (or, destroyed meanwhile, to its holder). A
    /// failure is `backup_failed`, and a scheduled machine tries again `RETRY_AFTER` later.
    pub(super) async fn backup_entry(
        &self,
        e: &Arc<Entry>,
        now: DateTime<Utc>,
    ) -> Result<api::Backup, MError> {
        let store = self.backup_store()?;
        let rec = e.snapshot();
        if rec.state == state::DESTROYING {
            return Err(MError::BadState(rec.state));
        }
        if !rec.has_disks() {
            return Err(super::made_never(&rec));
        }
        // Its disks are half swapped: what a backup sent now would be neither (ADR 0031).
        if let Some(snap) = &rec.restoring {
            return Err(snapshots::unfinished(snap));
        }
        let (b, mut all) = match self.send_backup(store, &rec).await {
            Ok(made) => made,
            // A destroy took the disks from under it: the destroy is the answer, not a failure.
            Err(_) if !self.holds(e) => return Err(MError::NotFound),
            Err(_) if e.snapshot().state == state::DESTROYING => {
                return Err(MError::BadState(state::DESTROYING.into()))
            }
            Err(err) => {
                self.backup_failed(e, &err, now).await;
                return Err(err);
            }
        };
        let mut pruned = Vec::new();
        if let Some(p) = &rec.backup.policy {
            for old in prune(&all, p.keep as usize).into_iter().rev() {
                match self.delete_backup_objects(store, old).await {
                    Ok(()) => pruned.push(old.id.clone()),
                    Err(err) => {
                        tracing::warn!(machine = rec.id, backup = old.id, err = %err, "old backup kept");
                        break;
                    }
                }
            }
        }
        all.retain(|b| !pruned.contains(&b.id));
        let bytes = all.iter().map(|b| b.bytes).sum();
        let kind = if b.incremental {
            "incremental"
        } else {
            "whole"
        };
        let made = Ev::normal(
            reason::BACKED_UP,
            format!("backup {}: {} bytes, {kind}", b.id, b.bytes),
        )
        .data(json!({ "backup": b.id, "bytes": b.bytes, "incremental": b.incremental }));
        let deleted = deleted_event(&pruned, "retention");
        // Under its lock and only while it is still here: a destroy in between removed the
        // record, which is not written back; its holder takes the backups.
        let _lock = e.lock.lock().await;
        if self.holds(e) {
            {
                let mut r = e.rec.lock().unwrap();
                r.backup_bytes = bytes;
                r.backup.last = Some(b.id.clone());
                r.backup.last_at = Some(b.created_at);
                r.backup.next_at = r
                    .backup
                    .policy
                    .as_ref()
                    .and_then(|p| p.check().ok())
                    .map(|every| after(now, every));
                e.note_locked(&mut r, made);
                if let Some(ev) = deleted {
                    e.note_locked(&mut r, ev);
                }
            }
            self.save(e)?;
        } else {
            self.inner.events.emit(made.of(&rec.id, &rec.namespace));
            if let Some(ev) = deleted {
                self.inner.events.emit(ev.of(&rec.id, &rec.namespace));
            }
            self.hold(&rec, bytes, e.backup_turn.clone())?;
        }
        self.inner.stats.backups.fetch_add(1, Relaxed);
        tracing::info!(
            machine = rec.id,
            backup = b.id,
            bytes = b.bytes,
            incremental = b.incremental,
            pruned = pruned.len(),
            "backup made"
        );
        Ok(b)
    }

    /// Sends each disk, whole or from the last backup's snapshot, then the record; returns
    /// the backup and every backup of the machine with it, oldest first. What a failure made
    /// (snapshots, streams) is taken back: nothing is left that is not a backup.
    pub(super) async fn send_backup(
        &self,
        store: &ObjectStore,
        rec: &Record,
    ) -> Result<(api::Backup, Vec<api::Backup>), MError> {
        let mut all = self.backups(&rec.id).await?;
        let seal = self.seal().await?;
        let key_id = seal.id.clone();
        let whole = rec
            .backup
            .policy
            .as_ref()
            .is_some_and(|p| chain_length(&all) >= p.keep as usize);
        let bid = Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
        let snap = format!("bk-{bid}");
        let z = &self.inner.zfs;
        let (mut snapped, mut sent) = (Vec::new(), Vec::new());
        let disks = async {
            let mut disks = Vec::new();
            for (disk, ds) in [("root", rec.root_dataset()), ("data", rec.data_dataset())] {
                if !z.exists(&ds).await? {
                    continue;
                }
                // The base must be a backup of this machine in the store, sent raw under this
                // pool's key: a restored machine's received snapshots are its source's, and a
                // raw increment applies only over a raw stream (ADR 0035).
                let base = match whole {
                    true => None,
                    false => newest_backup_snapshot(&z.snapshots(&ds).await?)
                        .filter(|s| in_store(&all, s, disk, &key_id)),
                };
                z.snapshot(&ds, &snap).await?;
                snapped.push(ds.clone());
                let key = format!("backups/{}/{disk}/{bid}.zfs", rec.id);
                let target = store.clone();
                let object_key = key.clone();
                sent.push(key.clone());
                let bytes = z
                    .send_with(&ds, &snap, base.as_deref(), move |stdout| async move {
                        target.put(&object_key, stdout).await
                    })
                    .await
                    .with_context(|| format!("backup {disk} of {}", rec.id))?;
                disks.push(api::BackupDisk {
                    disk: disk.into(),
                    key,
                    bytes,
                    from: base.map(|b| b.trim_start_matches("bk-").to_string()),
                });
            }
            anyhow::Ok(disks)
        }
        .await;
        let b = match disks {
            Ok(disks) => api::Backup {
                size: Some(rec.size),
                id: bid.clone(),
                machine_id: rec.id.clone(),
                namespace: rec.namespace.clone(),
                name: rec.name.clone(),
                created_at: Utc::now(),
                bytes: disks.iter().map(|d| d.bytes).sum(),
                incremental: disks.iter().any(|d| d.from.is_some()),
                disks,
                key_id: Some(key_id.clone()),
                machine: None,
                sealed: None,
                deletes_at: None,
            },
            Err(err) => {
                self.take_back(store, &snapped, &snap, &sent).await;
                return Err(err.into());
            }
        };
        let record = api::Backup {
            sealed: Some(seal.seal(
                &format!("{}/{bid}", rec.id),
                &serde_json::to_vec(rec).unwrap_or_default(),
            )?),
            ..b.clone()
        };
        let stored = store
            .put_bytes(
                &format!("backups/{}/{bid}.json", rec.id),
                &serde_json::to_vec_pretty(&record).unwrap_or_default(),
            )
            .await
            .context("backup record");
        if let Err(err) = stored {
            self.take_back(store, &snapped, &snap, &sent).await;
            return Err(err.into());
        }
        // The newest snapshots stay as the base of the next send; the rest go.
        let keep = self.inner.cfg.backup.keep_snapshots.max(1) as usize;
        for ds in &snapped {
            let mut snaps: Vec<String> = z
                .snapshots(ds)
                .await?
                .into_iter()
                .filter(|s| s.starts_with("bk-"))
                .collect();
            snaps.sort();
            while snaps.len() > keep {
                let old = snaps.remove(0);
                if let Err(err) = z.destroy_snapshot(ds, &old).await {
                    tracing::warn!(machine = rec.id, snapshot = old, err = %err, "old backup snapshot kept");
                }
            }
        }
        all.push(b.clone());
        Ok((b, all))
    }

    /// Removes what a failed backup made, as far as it can.
    pub(super) async fn take_back(
        &self,
        store: &ObjectStore,
        snapped: &[String],
        snap: &str,
        sent: &[String],
    ) {
        for key in sent {
            if let Err(err) = store.delete(key).await {
                tracing::warn!(key, err = %err, "stream of a failed backup left in the store");
            }
        }
        for ds in snapped {
            if let Err(err) = self.inner.zfs.destroy_snapshot(ds, snap).await {
                tracing::warn!(dataset = ds, snapshot = snap, err = %err, "snapshot of a failed backup kept");
            }
        }
    }

    /// A backup that did not reach the store: a warning, and a scheduled machine tries again
    /// in `RETRY_AFTER`.
    pub(super) async fn backup_failed(&self, e: &Arc<Entry>, err: &MError, now: DateTime<Utc>) {
        let ev = Ev::warning(reason::BACKUP_FAILED, format!("backup failed: {err:#}"))
            .data(json!({ "error": format!("{err:#}") }));
        tracing::warn!(machine = e.snapshot().id, err = %err, "backup failed");
        let _lock = e.lock.lock().await;
        if !self.holds(e) {
            let r = e.snapshot();
            self.inner.events.emit(ev.of(&r.id, &r.namespace));
            return;
        }
        {
            let mut r = e.rec.lock().unwrap();
            if r.backup.policy.is_some() {
                r.backup.next_at = Some(now + RETRY_AFTER);
            }
            e.note_locked(&mut r, ev);
        }
        if let Err(err) = self.save(e) {
            tracing::warn!(machine = e.snapshot().id, err = %err, "record after a failed backup");
        }
    }
}
