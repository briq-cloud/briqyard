//! Listing, deleting and settling backups.

use super::*;

impl Manager {
    /// A backup's streams, then its record: an interruption leaves a record whose streams
    /// are gone, which the next deletion removes again, never an object no record names.
    pub(super) async fn delete_backup_objects(
        &self,
        store: &ObjectStore,
        b: &api::Backup,
    ) -> Result<()> {
        for d in &b.disks {
            store.delete(&d.key).await?;
        }
        store
            .delete(&format!("backups/{}/{}.json", b.machine_id, b.id))
            .await
    }

    /// The backups of a machine id in the store, oldest first; the machine may be gone, or
    /// on another host. A destroyed machine's holder here says when they go.
    pub async fn backups(&self, machine_id: &str) -> Result<Vec<api::Backup>, MError> {
        if !api::valid_id(machine_id) {
            return Err(invalid("not a machine id"));
        }
        let store = self.backup_store()?;
        let deletes_at = self.holder(machine_id).map(|h| {
            let days = self.inner.cfg.backup.keep_destroyed_days as i64;
            h.rec.lock().unwrap().destroyed_at + chrono::Duration::days(days)
        });
        let keys = {
            let _read = self.inner.backups.reads.acquire().await;
            store.list(&format!("backups/{machine_id}/")).await?
        };
        let mut out = self.read_backups(store, keys).await?;
        for b in &mut out {
            b.deletes_at = deletes_at;
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// The backup records among store keys, read `READS_AT_ONCE` at a time. A record deleted
    /// since it was listed (a deletion under way) is not a backup any more.
    pub(super) async fn read_backups(
        &self,
        store: &ObjectStore,
        keys: Vec<String>,
    ) -> Result<Vec<api::Backup>> {
        let reads = &self.inner.backups.reads;
        let records: Vec<(String, Option<Vec<u8>>)> = futures::stream::iter(keys)
            .filter(|key| std::future::ready(key.ends_with(".json")))
            .map(|key| async move {
                let _read = reads.acquire().await;
                let data = store.get_bytes_if_present(&key).await?;
                anyhow::Ok((key, data))
            })
            .buffered(READS_AT_ONCE)
            .try_collect()
            .await?;
        let mut out = Vec::new();
        for (key, data) in records {
            let Some(data) = data else {
                continue;
            };
            match serde_json::from_slice::<api::Backup>(&data) {
                Ok(mut b) => {
                    if b.size.is_none() {
                        b.size = b
                            .machine
                            .as_ref()
                            .and_then(|r| r.get("size"))
                            .and_then(|size| serde_json::from_value(size.clone()).ok());
                    }
                    b.machine = None;
                    b.sealed = None;
                    out.push(b);
                }
                Err(err) => tracing::warn!(key, err = %err, "unreadable backup record"),
            }
        }
        Ok(out)
    }

    /// Every backup of the host's machines and of its destroyed machines' holders, of one
    /// namespace or all, of one machine or all, by machine then age. A machine that is neither
    /// here nor held here has none, and costs no store read.
    pub async fn all_backups(
        &self,
        namespace: Option<&str>,
        machine: Option<&str>,
    ) -> Result<Vec<api::Backup>, MError> {
        if let Some(t) = namespace {
            check_namespace_id(t)?;
        }
        if machine.is_some_and(|m| !api::valid_id(m)) {
            return Err(invalid("machine: not a machine id"));
        }
        self.backup_store()?;
        let wanted = |t: &str, id: &str| {
            namespace.is_none_or(|want| want == t) && machine.is_none_or(|want| want == id)
        };
        let mut ids: Vec<String> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter_map(|e| {
                let r = e.rec.lock().unwrap();
                (r.is_namespaces() && wanted(&r.namespace, &r.id)).then(|| r.id.clone())
            })
            .collect();
        ids.extend(
            self.inner
                .backups
                .holders
                .lock()
                .unwrap()
                .values()
                .filter_map(|h| {
                    let r = h.rec.lock().unwrap();
                    wanted(&r.namespace, &r.machine_id).then(|| r.machine_id.clone())
                }),
        );
        // A machine destroyed between the two reads is in both.
        ids.sort();
        ids.dedup();
        let lists: Vec<Vec<api::Backup>> = futures::stream::iter(ids)
            .map(|id| async move { self.backups(&id).await })
            .buffered(READS_AT_ONCE)
            .try_collect()
            .await?;
        Ok(lists.into_iter().flatten().collect())
    }

    /// Deletes a backup of a machine of the host or of a destroyed one's holder. Refused
    /// while another backup continues from it, unless `chain`: then those go too, newest
    /// first, so an interruption never leaves a backup whose base is gone.
    pub async fn delete_backup(
        &self,
        machine_id: &str,
        backup_id: &str,
        chain: bool,
    ) -> Result<(), MError> {
        let owner = self.owner(machine_id)?;
        let store = self.backup_store()?;
        let turn = owner.turn();
        let _turn = turn.lock().await;
        let all = self.backups(machine_id).await?;
        let target = all
            .iter()
            .position(|b| b.id == backup_id)
            .ok_or_else(|| MError::NoBackup(format!("{machine_id}/{backup_id}")))?;
        let after = dependents(&all, target);
        if !after.is_empty() && !chain {
            let ids: Vec<&str> = after.iter().map(|&i| all[i].id.as_str()).collect();
            return Err(MError::Conflict(format!(
                "backup {backup_id}: {} continue from it; ?chain=true deletes them too",
                ids.join(", ")
            )));
        }
        let mut gone: Vec<usize> = after;
        gone.push(target);
        gone.sort_unstable();
        let mut deleted = Vec::new();
        let mut failed = None;
        for &i in gone.iter().rev() {
            match self.delete_backup_objects(store, &all[i]).await {
                Ok(()) => deleted.push(all[i].id.clone()),
                Err(err) => {
                    failed = Some(err);
                    break;
                }
            }
        }
        let left: Vec<api::Backup> = all
            .into_iter()
            .filter(|b| !deleted.contains(&b.id))
            .collect();
        self.settle(&owner, &left, deleted_event(&deleted, "request"))
            .await?;
        match failed {
            Some(err) => Err(err.context(format!("delete backup of {machine_id}")).into()),
            None => Ok(()),
        }
    }

    /// Writes what the store holds for an owner after a deletion, with the event: its bytes
    /// and newest backup on a machine's record; for a destroyed machine, on its holder, which
    /// goes once nothing is left.
    pub(super) async fn settle(
        &self,
        owner: &Owner,
        left: &[api::Backup],
        ev: Option<Ev>,
    ) -> Result<()> {
        let bytes = left.iter().map(|b| b.bytes).sum();
        if let Owner::Machine(e) = owner {
            let _lock = e.lock.lock().await;
            if self.holds(e) {
                {
                    let mut r = e.rec.lock().unwrap();
                    r.backup_bytes = bytes;
                    r.backup.last = left.last().map(|b| b.id.clone());
                    r.backup.last_at = left.last().map(|b| b.created_at);
                    if let Some(ev) = ev {
                        e.note_locked(&mut r, ev);
                    }
                }
                return self.save(e);
            }
        }
        // Destroyed, or destroyed meanwhile: its destroy made the holder.
        let (id, namespace) = owner.who();
        if let Some(ev) = ev {
            self.inner.events.emit(ev.of(&id, &namespace));
        }
        let Some(h) = self.holder(&id) else {
            return Ok(());
        };
        if left.is_empty() {
            let mut holders = self.inner.backups.holders.lock().unwrap();
            if holders.get(&id).is_some_and(|x| Arc::ptr_eq(x, &h)) {
                holders.remove(&id);
            }
            return self.inner.store.delete(HOLDERS, &id);
        }
        let rec = {
            let mut r = h.rec.lock().unwrap();
            r.bytes = bytes;
            h.meter.lock().unwrap().disks.backups = bytes;
            r.clone()
        };
        self.inner.store.put(HOLDERS, &id, &rec)
    }
}
