//! Backups (ADR 0008, ADR 0023): a machine's disks streamed to the object store, on request or
//! on the machine's schedule, pruned to its `keep`; a destroyed machine's kept by a holder
//! until `backup.keep_destroyed_days` have passed.

use super::*;
use crate::config;
use crate::objstore::ObjectStore;
use std::collections::HashSet;
use tokio::sync::OwnedMutexGuard;

/// A failed backup is tried again this long after.
const RETRY_AFTER: chrono::Duration = chrono::Duration::minutes(15);

/// The local store's kind for holders.
const HOLDERS: &str = "holders";

/// Held by every backup and deletion of one machine's backups: one at a time per machine.
/// A destroyed machine's holder takes it over.
pub(super) type Turn = Arc<tokio::sync::Mutex<()>>;

/// A machine's backup schedule and where it stands, in its record.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Schedule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<api::BackupPolicy>,
    /// Its newest backup in the store, and when that was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<DateTime<Utc>>,
    /// When the tick backs it up next; none without a policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_at: Option<DateTime<Utc>>,
}

impl Schedule {
    /// Sets the policy at `now` (a create, a PATCH): the next backup is `every` after the last
    /// one, or after now when there is none. The same policy again changes nothing.
    fn set(&mut self, policy: Option<api::BackupPolicy>, now: DateTime<Utc>) -> Result<(), MError> {
        if policy == self.policy {
            return Ok(());
        }
        self.next_at = match &policy {
            Some(p) => Some(after(self.last_at.unwrap_or(now), checked(p)?)),
            None => None,
        };
        self.policy = policy;
        Ok(())
    }
}

/// A policy's `every`, or the refusal naming its field.
fn checked(p: &api::BackupPolicy) -> Result<Duration, MError> {
    p.check().map_err(|e| invalid(format!("backup.{e}")))
}

/// `t` plus `d`, the latest time there is past it.
fn after(t: DateTime<Utc>, d: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(d)
        .ok()
        .and_then(|d| t.checked_add_signed(d))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// The schedule a create gives a machine: the request's (`null`: none), else the host's.
pub(super) fn schedule_of(
    asked: &Option<Option<api::BackupPolicy>>,
    host: &config::Backup,
    now: DateTime<Utc>,
) -> Result<Schedule, MError> {
    let policy = match asked {
        Some(p) => p.clone(),
        None => host.default_policy(),
    };
    let mut s = Schedule::default();
    s.set(policy, now)?;
    Ok(s)
}

/// A PATCH's `backup`, checked before the machine's lock is taken.
pub(super) fn check_update(asked: &Option<Option<api::BackupPolicy>>) -> Result<(), MError> {
    if let Some(Some(p)) = asked {
        checked(p)?;
    }
    Ok(())
}

/// Applies a PATCH's `backup` to a record.
pub(super) fn update(
    r: &mut Record,
    asked: Option<Option<api::BackupPolicy>>,
) -> Result<(), MError> {
    match asked {
        Some(p) => r.backup.set(p, Utc::now()),
        None => Ok(()),
    }
}

/// What keeps a destroyed machine's backups listed, counted and finite (ADR 0023).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct HolderRec {
    pub machine_id: String,
    pub tenant: String,
    pub name: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub size: api::Size,
    pub destroyed_at: DateTime<Utc>,
    /// What its backups take in the store.
    pub bytes: u64,
}

pub(super) struct Holder {
    rec: Mutex<HolderRec>,
    /// Its backups' hours since the tick last took them (ADR 0017).
    meter: Mutex<Meter>,
    turn: Turn,
}

impl Holder {
    fn new(rec: HolderRec, turn: Turn, at: DateTime<Utc>) -> Arc<Self> {
        let mut meter = Meter::new(at);
        meter.disks.backups = rec.bytes;
        Arc::new(Self {
            rec: Mutex::new(rec),
            meter: Mutex::new(meter),
            turn,
        })
    }
}

/// The host's side of backups: the store, the gate the tick's work takes turns at, and the
/// holders of destroyed machines' backups.
pub(super) struct Backups {
    store: Option<ObjectStore>,
    gate: tokio::sync::Semaphore,
    holders: Mutex<HashMap<String, Arc<Holder>>>,
}

impl Backups {
    /// Opens the store `backup.store` names (none when empty) and reads the holders back.
    pub(super) fn open(cfg: &config::Backup, state: &Store) -> Result<Self> {
        let store = if cfg.store.is_empty() {
            None
        } else {
            let st = ObjectStore::open(
                &cfg.store,
                &cfg.endpoint,
                &cfg.region,
                &std::env::var("BRIQYARD_S3_ACCESS_KEY").unwrap_or_default(),
                &std::env::var("BRIQYARD_S3_SECRET_KEY").unwrap_or_default(),
            )
            .context("backup")?;
            tracing::info!(store = st.describe(), "backups on");
            Some(st)
        };
        let now = Utc::now();
        let holders = state
            .list::<HolderRec>(HOLDERS)
            .context("backup holders")?
            .into_iter()
            .map(|r| (r.machine_id.clone(), Holder::new(r, Turn::default(), now)))
            .collect();
        Ok(Self {
            store,
            gate: tokio::sync::Semaphore::new(cfg.at_once.max(1) as usize),
            holders: Mutex::new(holders),
        })
    }
}

/// Whose backups a call acts on: a machine of the host, or a destroyed one's holder.
enum Owner {
    Machine(Arc<Entry>),
    Holder(Arc<Holder>),
}

impl Owner {
    fn turn(&self) -> Turn {
        match self {
            Owner::Machine(e) => e.backup_turn.clone(),
            Owner::Holder(h) => h.turn.clone(),
        }
    }

    /// The machine's id and tenant.
    fn who(&self) -> (String, String) {
        match self {
            Owner::Machine(e) => {
                let r = e.rec.lock().unwrap();
                (r.id.clone(), r.tenant.clone())
            }
            Owner::Holder(h) => {
                let r = h.rec.lock().unwrap();
                (r.machine_id.clone(), r.tenant.clone())
            }
        }
    }
}

impl Manager {
    fn backup_store(&self) -> Result<&ObjectStore, MError> {
        self.inner
            .backups
            .store
            .as_ref()
            .ok_or_else(|| invalid("backups are off on this host (backup.store)"))
    }

    fn holder(&self, id: &str) -> Option<Arc<Holder>> {
        self.inner.backups.holders.lock().unwrap().get(id).cloned()
    }

    fn owner(&self, id: &str) -> Result<Owner, MError> {
        match self.own_entry(id) {
            Ok(e) => Ok(Owner::Machine(e)),
            Err(MError::NotFound) => self.holder(id).map(Owner::Holder).ok_or(MError::NotFound),
            Err(err) => Err(err),
        }
    }

    /// A backup now, on request: after any backup of the machine under way.
    pub async fn backup(&self, id: &str) -> Result<api::Backup, MError> {
        let e = self.own_entry(id)?;
        self.backup_store()?;
        let _turn = e.backup_turn.lock().await;
        self.backup_entry(&e, Utc::now()).await
    }

    /// One backup of a machine whose turn the caller holds, started `now`: sent, recorded and
    /// pruned to its policy's `keep`; what the store then holds, the next time (`every` after
    /// `now`) and the event go to its record (or, destroyed meanwhile, to its holder). A
    /// failure is `backup_failed`, and a scheduled machine tries again `RETRY_AFTER` later.
    async fn backup_entry(
        &self,
        e: &Arc<Entry>,
        now: DateTime<Utc>,
    ) -> Result<api::Backup, MError> {
        let store = self.backup_store()?;
        let rec = e.snapshot();
        if rec.state == state::DESTROYING {
            return Err(MError::BadState(rec.state));
        }
        // Its disks are half swapped: what a backup sent now would be neither (ADR 0031).
        if let Some(snap) = &rec.restoring {
            return Err(snapshots::unfinished(snap));
        }
        let (b, mut all) = match self.send_backup(store, &rec).await {
            Ok(made) => made,
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
            self.inner.events.emit(made.of(&rec.id, &rec.tenant));
            if let Some(ev) = deleted {
                self.inner.events.emit(ev.of(&rec.id, &rec.tenant));
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
    async fn send_backup(
        &self,
        store: &ObjectStore,
        rec: &Record,
    ) -> Result<(api::Backup, Vec<api::Backup>), MError> {
        let mut all = self.backups(&rec.id).await?;
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
                // The base must be a backup of this machine in the store: a restored
                // machine's received snapshots are its source's.
                let base = match whole {
                    true => None,
                    false => newest_backup_snapshot(&z.snapshots(&ds).await?)
                        .filter(|s| in_store(&all, s, disk)),
                };
                z.snapshot(&ds, &snap).await?;
                snapped.push(ds.clone());
                let key = format!("backups/{}/{disk}/{bid}.zfs", rec.id);
                let mut child = z.send(&ds, &snap, base.as_deref())?;
                let stdout = child.stdout.take().expect("piped");
                sent.push(key.clone());
                let bytes = store
                    .put(&key, stdout)
                    .await
                    .with_context(|| format!("backup {disk} of {}", rec.id))?;
                Zfs::finish(child, "zfs send").await?;
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
                id: bid.clone(),
                machine_id: rec.id.clone(),
                tenant: rec.tenant.clone(),
                name: rec.name.clone(),
                created_at: Utc::now(),
                bytes: disks.iter().map(|d| d.bytes).sum(),
                incremental: disks.iter().any(|d| d.from.is_some()),
                disks,
                machine: Some(serde_json::to_value(rec).unwrap_or_default()),
                deletes_at: None,
            },
            Err(err) => {
                self.take_back(store, &snapped, &snap, &sent).await;
                return Err(err.into());
            }
        };
        let stored = store
            .put_bytes(
                &format!("backups/{}/{bid}.json", rec.id),
                &serde_json::to_vec_pretty(&b).unwrap_or_default(),
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
        all.push(api::Backup {
            machine: None,
            ..b.clone()
        });
        Ok((b, all))
    }

    /// Removes what a failed backup made, as far as it can.
    async fn take_back(
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
    async fn backup_failed(&self, e: &Arc<Entry>, err: &MError, now: DateTime<Utc>) {
        let ev = Ev::warning(reason::BACKUP_FAILED, format!("backup failed: {err:#}"))
            .data(json!({ "error": format!("{err:#}") }));
        tracing::warn!(machine = e.snapshot().id, err = %err, "backup failed");
        let _lock = e.lock.lock().await;
        if !self.holds(e) {
            let r = e.snapshot();
            self.inner.events.emit(ev.of(&r.id, &r.tenant));
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

    /// A backup's streams, then its record: an interruption leaves a record whose streams
    /// are gone, which the next deletion removes again, never an object no record names.
    async fn delete_backup_objects(&self, store: &ObjectStore, b: &api::Backup) -> Result<()> {
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
        let mut out = Vec::new();
        for key in store.list(&format!("backups/{machine_id}/")).await? {
            if !key.ends_with(".json") {
                continue;
            }
            let data = store.get_bytes(&key).await?;
            match serde_json::from_slice::<api::Backup>(&data) {
                Ok(mut b) => {
                    b.machine = None;
                    b.deletes_at = deletes_at;
                    out.push(b);
                }
                Err(err) => tracing::warn!(key, err = %err, "unreadable backup record"),
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Every backup of the host's machines and of its destroyed machines' holders, of one
    /// tenant or all, by machine then age.
    pub async fn all_backups(&self, tenant: Option<&str>) -> Result<Vec<api::Backup>, MError> {
        if let Some(t) = tenant {
            check_tenant_id(t)?;
        }
        self.backup_store()?;
        let of_tenant = |t: &str| tenant.is_none_or(|want| want == t);
        let mut ids: Vec<String> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter_map(|e| {
                let r = e.rec.lock().unwrap();
                (r.is_tenants() && of_tenant(&r.tenant)).then(|| r.id.clone())
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
                    of_tenant(&r.tenant).then(|| r.machine_id.clone())
                }),
        );
        // A machine destroyed between the two reads is in both.
        ids.sort();
        ids.dedup();
        let mut out = Vec::new();
        for id in ids {
            out.extend(self.backups(&id).await?);
        }
        Ok(out)
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
    async fn settle(&self, owner: &Owner, left: &[api::Backup], ev: Option<Ev>) -> Result<()> {
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
        let (id, tenant) = owner.who();
        if let Some(ev) = ev {
            self.inner.events.emit(ev.of(&id, &tenant));
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

    /// Keeps a destroyed machine's backups: its holder, made at its destroy, or updated by a
    /// backup that finished after it.
    pub(super) fn hold(&self, rec: &Record, bytes: u64, turn: Turn) -> Result<()> {
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
                    tenant: rec.tenant.clone(),
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

    /// The tick's backup step: each machine whose next backup is due gets one, and each
    /// holder past `keep_destroyed_days` loses its backups, `backup.at_once` at a time.
    /// Detached, since a backup can take minutes: the turn taken here keeps a machine to one
    /// at a time across ticks. The tasks are returned for a test to wait on.
    pub(super) fn backup_step(&self, now: DateTime<Utc>) -> Vec<tokio::task::JoinHandle<()>> {
        if self.inner.backups.store.is_none() {
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
                r.is_tenants()
                    && r.state != state::DESTROYING
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
            let m = self.clone();
            tasks.push(tokio::spawn(async move {
                let _turn = turn;
                let Ok(_slot) = m.inner.backups.gate.acquire().await else {
                    return;
                };
                m.scheduled_backup(&e, now).await;
            }));
        }
        for (h, turn) in expired {
            let m = self.clone();
            tasks.push(tokio::spawn(async move {
                let _turn = turn;
                let Ok(_slot) = m.inner.backups.gate.acquire().await else {
                    return;
                };
                m.expire(&h).await;
            }));
        }
        tasks
    }

    /// A due machine's backup, its turn held. A machine with no process whose disks wrote
    /// nothing since its last backup is not backed up again: its next time moves on.
    async fn scheduled_backup(&self, e: &Arc<Entry>, now: DateTime<Utc>) {
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
    async fn written_since_backup(&self, r: &Record) -> bool {
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
    async fn expire(&self, h: &Arc<Holder>) {
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
    pub(super) fn meter_holders(&self, now: DateTime<Utc>) {
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
                    tenant: r.tenant.clone(),
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
    pub(super) async fn find_backup(
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
    /// received into the new datasets.
    pub(super) async fn receive_disks(&self, e: &Arc<Entry>, b: &api::Backup) -> Result<()> {
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
                let mut child = self.inner.zfs.receive(&ds)?;
                let mut stdin = child.stdin.take().expect("piped");
                let mut reader = store.get(&step.key).await?;
                tokio::io::copy(&mut reader, &mut stdin)
                    .await
                    .with_context(|| format!("restore {}", step.key))?;
                drop(stdin);
                Zfs::finish(child, "zfs receive").await?;
            }
            self.inner.zfs.device(&ds).await?;
        }
        Ok(())
    }
}

/// `backup_deleted` for these ids, when there are any.
fn deleted_event(ids: &[String], why: &str) -> Option<Ev> {
    (!ids.is_empty()).then(|| {
        Ev::normal(
            reason::BACKUP_DELETED,
            format!("backups deleted ({why}): {}", ids.join(", ")),
        )
        .data(json!({ "backups": ids, "reason": why }))
    })
}

/// The newest backup snapshot (`bk-<id>`) among a dataset's snapshots: the base of the next
/// incremental send.
fn newest_backup_snapshot(snaps: &[String]) -> Option<String> {
    snaps.iter().filter(|s| s.starts_with("bk-")).max().cloned()
}

/// Whether a snapshot `bk-<id>` is the snapshot of a backup in `all` holding that disk.
fn in_store(all: &[api::Backup], snap: &str, disk: &str) -> bool {
    let id = snap.trim_start_matches("bk-");
    all.iter()
        .any(|b| b.id == id && b.disks.iter().any(|d| d.disk == disk))
}

fn is_whole(b: &api::Backup) -> bool {
    b.disks.iter().all(|d| d.from.is_none())
}

/// How many backups the newest chain holds: from the newest back to the whole one it starts
/// from (all of them when none is whole).
fn chain_length(all: &[api::Backup]) -> usize {
    match all.iter().rposition(is_whole) {
        Some(i) => all.len() - i,
        None => all.len(),
    }
}

/// What retention deletes from `all` (oldest first): every backup that is neither among the
/// newest `keep` nor a base of one of them. Bases are older, so one pass from the newest
/// finds them all.
fn prune(all: &[api::Backup], keep: usize) -> Vec<&api::Backup> {
    let mut kept: HashSet<&str> = all.iter().rev().take(keep).map(|b| b.id.as_str()).collect();
    for b in all.iter().rev() {
        if kept.contains(b.id.as_str()) {
            kept.extend(b.disks.iter().filter_map(|d| d.from.as_deref()));
        }
    }
    all.iter()
        .filter(|b| !kept.contains(b.id.as_str()))
        .collect()
}

/// The backups (their places in `all`, oldest first) that continue from `all[target]`, at
/// any distance. Each continues from an older one, so one pass in order finds them.
fn dependents(all: &[api::Backup], target: usize) -> Vec<usize> {
    let mut gone: HashSet<&str> = HashSet::from([all[target].id.as_str()]);
    let mut out = Vec::new();
    for (i, b) in all.iter().enumerate().skip(target + 1) {
        if b.disks
            .iter()
            .any(|d| d.from.as_deref().is_some_and(|f| gone.contains(f)))
        {
            gone.insert(&b.id);
            out.push(i);
        }
    }
    out
}

/// The streams to receive, oldest first, to get one disk of a backup: the backup's own stream
/// preceded by the ones it continues from, back to a whole one.
fn backup_chain<'a>(
    all: &'a [api::Backup],
    target: &'a api::Backup,
    disk: &str,
) -> Vec<&'a api::BackupDisk> {
    let mut chain = Vec::new();
    let mut cur = target.disks.iter().find(|d| d.disk == disk);
    let mut guard = 0;
    while let Some(d) = cur {
        chain.push(d);
        guard += 1;
        cur = match &d.from {
            Some(from) if guard < 10_000 => all
                .iter()
                .find(|b| &b.id == from)
                .and_then(|b| b.disks.iter().find(|x| x.disk == disk)),
            _ => None,
        };
    }
    chain.reverse();
    chain
}

#[cfg(test)]
mod tests {
    use super::super::tests::{at, harness_config, Harness};
    use super::*;
    use tokio::task::JoinHandle;

    fn disk(name: &str, id: &str, from: Option<&str>) -> api::BackupDisk {
        api::BackupDisk {
            disk: name.into(),
            key: format!("k-{name}-{id}"),
            bytes: 1,
            from: from.map(String::from),
        }
    }

    /// A backup of the root disk, whole or from another.
    fn b(id: &str, from: Option<&str>) -> api::Backup {
        api::Backup {
            id: id.into(),
            machine_id: "m_1".into(),
            tenant: "t".into(),
            name: "n".into(),
            created_at: Utc::now(),
            bytes: 1,
            incremental: from.is_some(),
            disks: vec![disk("root", id, from)],
            machine: None,
            deletes_at: None,
        }
    }

    fn ids(bs: &[&api::Backup]) -> Vec<String> {
        bs.iter().map(|b| b.id.clone()).collect()
    }

    #[test]
    fn backup_chains() {
        let all = vec![
            b("a", None),
            b("b", Some("a")),
            b("c", Some("b")),
            b("d", None),
        ];
        let keys = |t: &api::Backup| -> Vec<String> {
            backup_chain(&all, t, "root")
                .iter()
                .map(|d| d.key.clone())
                .collect()
        };
        assert_eq!(keys(&all[2]), vec!["k-root-a", "k-root-b", "k-root-c"]);
        assert_eq!(keys(&all[0]), vec!["k-root-a"]);
        assert_eq!(keys(&all[3]), vec!["k-root-d"]);
        assert!(backup_chain(&all, &all[2], "data").is_empty());
        // A base that is not in the store ends the chain where it is.
        let orphan = b("e", Some("zz"));
        assert_eq!(keys(&orphan), vec!["k-root-e"]);
        assert_eq!(
            newest_backup_snapshot(&[
                "fork-x".into(),
                "bk-20260101T000000.000Z".into(),
                "bk-20260102T000000.000Z".into()
            ]),
            Some("bk-20260102T000000.000Z".into())
        );
        assert_eq!(newest_backup_snapshot(&["fork-x".into()]), None);
        // A base is a snapshot of one of the machine's backups that holds that disk.
        assert!(in_store(&all, "bk-b", "root"));
        assert!(!in_store(&all, "bk-b", "data"));
        assert!(!in_store(&all, "bk-zz", "root"));
    }

    #[test]
    fn retention_keeps_the_newest_and_what_they_continue_from() {
        // keep 2: whole every second backup, the store between 2 and 3.
        let mut all = vec![b("1", None)];
        assert!(prune(&all, 2).is_empty());
        assert_eq!(chain_length(&all), 1);
        all.push(b("2", Some("1")));
        assert!(prune(&all, 2).is_empty());
        assert_eq!(chain_length(&all), 2, "the next one is whole");
        all.push(b("3", None));
        assert!(prune(&all, 2).is_empty(), "2 is kept and needs 1");
        assert_eq!(chain_length(&all), 1);
        all.push(b("4", Some("3")));
        assert_eq!(ids(&prune(&all, 2)), vec!["1", "2"]);
        // keep 1: every backup whole, the store holds one.
        let all = vec![b("1", None), b("2", None)];
        assert_eq!(ids(&prune(&all, 1)), vec!["1"]);
        // A base of either disk is kept.
        let mut two = b("2", None);
        two.disks.push(disk("data", "2", Some("1")));
        let all = vec![b("1", None), two, b("3", None)];
        assert!(prune(&all, 2).is_empty());
        assert_eq!(ids(&prune(&all, 1)), vec!["1", "2"]);
        // A chain with no whole backup (before schedules) counts whole.
        let all = vec![b("1", Some("0")), b("2", Some("1"))];
        assert_eq!(chain_length(&all), 2);
        assert_eq!(chain_length(&[]), 0);
    }

    #[test]
    fn what_continues_from_a_backup() {
        let all = vec![
            b("1", None),
            b("2", Some("1")),
            b("3", Some("2")),
            b("4", None),
            b("5", Some("4")),
        ];
        assert_eq!(dependents(&all, 0), vec![1, 2]);
        assert_eq!(dependents(&all, 1), vec![2]);
        assert_eq!(dependents(&all, 3), vec![4]);
        assert!(dependents(&all, 4).is_empty());
    }

    /// A harness whose host backs up to a directory, after `f`; tenant `t1` and the image in
    /// place.
    async fn harness(f: impl FnOnce(&mut config::Backup)) -> Harness {
        let h = harness_config(|cfg| {
            cfg.network.range = "10.64.0.0/22".into();
            cfg.capacity = config::Capacity {
                memory_mb: 4096,
                vcpus: 1000,
                ..Default::default()
            };
            cfg.egress_limits = config::EgressLimits {
                blocked_ports: vec![],
                new_connections_per_minute: 0,
                bandwidth_mbit: 0,
            };
            cfg.backup.store = format!("file://{}", cfg.data_dir.join("store").display());
            f(&mut cfg.backup);
        })
        .await;
        h.ready().await;
        h
    }

    fn every(e: &str, keep: u32) -> Option<Option<api::BackupPolicy>> {
        Some(Some(api::BackupPolicy {
            every: e.into(),
            keep,
        }))
    }

    impl Harness {
        /// A machine of `t1` with this schedule, running or only created.
        async fn machine(
            &self,
            name: &str,
            backup: Option<Option<api::BackupPolicy>>,
            start: bool,
        ) -> api::Machine {
            let mut req = self.request(name);
            req.backup = backup;
            req.start = Some(start);
            self.m.create(req).await.unwrap()
        }

        fn ids(&self, bs: &[api::Backup]) -> Vec<String> {
            bs.iter().map(|b| b.id.clone()).collect()
        }

        async fn listed(&self, id: &str) -> Vec<api::Backup> {
            self.m.backups(id).await.unwrap()
        }

        /// The store's objects of a machine.
        async fn objects(&self, id: &str) -> Vec<String> {
            let store = self.m.backup_store().unwrap();
            store.list(&format!("backups/{id}/")).await.unwrap()
        }

        fn last_of(&self, id: &str, reason: &str) -> api::Event {
            self.events_of(id)
                .into_iter()
                .rev()
                .find(|e| e.reason == reason)
                .unwrap_or_else(|| panic!("{id}: no {reason} in {:?}", self.reasons(id)))
        }

        /// The sends the fake `zfs` started, read without taking the calls, which other
        /// processes are still appending to.
        fn sends(&self) -> usize {
            let calls = self.pool.dev().parent().unwrap().join("calls");
            std::fs::read_to_string(calls)
                .unwrap_or_default()
                .lines()
                .filter(|c| c.starts_with("send "))
                .count()
        }
    }

    /// Waits for the tasks a step started; how many there were.
    async fn run(tasks: Vec<JoinHandle<()>>) -> usize {
        let n = tasks.len();
        for t in tasks {
            t.await.unwrap();
        }
        n
    }

    #[tokio::test]
    async fn a_policy_is_checked_by_field_and_a_patch_sets_or_removes_it() {
        let h = harness(|_| {}).await;
        for (backup, why) in [
            (every("30m", 2), r#"backup.every "30m": at least 1h"#),
            (every("6h", 0), "backup.keep: at least 1"),
        ] {
            let mut req = h.request("bad");
            req.backup = backup;
            match h.m.create(req).await {
                Err(MError::Invalid(e)) => assert_eq!(e, why),
                other => panic!("{other:?}"),
            }
        }
        // None by default on this host.
        let m = h.machine("db", None, false).await;
        assert_eq!((m.backup, m.next_backup_at), (None, None));
        let patch = |backup| api::UpdateMachineRequest {
            backup,
            ..Default::default()
        };
        let before = Utc::now();
        let m =
            h.m.update(&m.id, patch(every("1d", 5)), None)
                .await
                .unwrap();
        assert_eq!(m.backup.as_ref().map(|p| p.keep), Some(5));
        let next = m.next_backup_at.unwrap();
        assert!(
            next >= before + chrono::Duration::days(1)
                && next <= Utc::now() + chrono::Duration::days(1)
        );
        let ev = h.last_of(&m.id, reason::UPDATED);
        assert_eq!(ev.data.unwrap()["fields"], json!(["backup"]));
        // The same policy again is no change: no event, the same next time.
        let again =
            h.m.update(&m.id, patch(every("1d", 5)), None)
                .await
                .unwrap();
        assert_eq!(
            (again.version, again.next_backup_at),
            (m.version, m.next_backup_at)
        );
        let err = h.m.update(&m.id, patch(every("1d", 0)), None).await;
        assert!(matches!(err, Err(MError::Invalid(e)) if e == "backup.keep: at least 1"));
        // null removes it.
        let m = h.m.update(&m.id, patch(Some(None)), None).await.unwrap();
        assert_eq!((m.backup, m.next_backup_at), (None, None));
        assert!(h.stored(&m.id).unwrap().backup.policy.is_none());

        // A host's default is what a create without one gets; null is none.
        let h = harness(|b| {
            b.default_every = "1d".into();
            b.default_keep = 5;
        })
        .await;
        let m = h.machine("db", None, false).await;
        assert_eq!(m.backup.map(|p| (p.every, p.keep)), Some(("1d".into(), 5)));
        assert_eq!(
            m.next_backup_at,
            Some(m.created_at + chrono::Duration::days(1))
        );
        let m = h.machine("scratch", Some(None), false).await;
        assert_eq!(m.backup, None);
    }

    #[tokio::test]
    async fn the_schedule_fires_when_due_and_not_before() {
        let h = harness(|_| {}).await;
        let m = h.machine("db", every("1h", 3), true).await;
        let t = m.next_backup_at.unwrap();
        assert_eq!(t, m.created_at + chrono::Duration::hours(1));
        assert_eq!(m.last_backup_at, None);
        assert_eq!(
            run(h.m.backup_step(t - chrono::Duration::seconds(1))).await,
            0
        );
        assert!(h.listed(&m.id).await.is_empty());
        assert_eq!(run(h.m.backup_step(t)).await, 1);
        let all = h.listed(&m.id).await;
        assert_eq!(all.len(), 1);
        assert!(!all[0].incremental);
        let v = h.m.get(&m.id).unwrap();
        assert_eq!(v.last_backup_at, Some(all[0].created_at));
        assert_eq!(v.next_backup_at, Some(t + chrono::Duration::hours(1)));
        let ev = h.last_of(&m.id, reason::BACKED_UP);
        assert_eq!(ev.data.unwrap()["bytes"], json!(all[0].bytes));
        // Done for this hour: the same tick, or one a minute short of the next, starts none.
        assert_eq!(run(h.m.backup_step(t)).await, 0);
        assert_eq!(
            run(h.m.backup_step(t + chrono::Duration::minutes(59))).await,
            0
        );
        assert_eq!(
            run(h.m.backup_step(t + chrono::Duration::hours(1))).await,
            1
        );
        let all = h.listed(&m.id).await;
        assert_eq!(all.len(), 2);
        assert!(all[1].incremental, "from the first");
        // Written to the record: a daemon that starts again goes on from it.
        assert_eq!(
            h.stored(&m.id).unwrap().backup.next_at,
            Some(t + chrono::Duration::hours(2))
        );
        assert_eq!(
            h.stored(&m.id).unwrap().backup_bytes,
            all.iter().map(|b| b.bytes).sum::<u64>()
        );
    }

    #[tokio::test]
    async fn at_most_at_once_and_never_two_for_one_machine() {
        let h = harness(|b| b.at_once = 2).await;
        let mut ms = Vec::new();
        for name in ["a", "b", "c"] {
            ms.push(h.machine(name, every("1h", 3), true).await);
        }
        let t = ms.iter().filter_map(|m| m.next_backup_at).max().unwrap();
        let hold = h.pool.dev().join("hold.send");
        std::fs::write(&hold, "").unwrap();
        h.pool.calls();
        let tasks = h.m.backup_step(t);
        assert_eq!(tasks.len(), 3);
        tokio::time::timeout(Duration::from_secs(10), async {
            while h.sends() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("two sends start");
        assert_eq!(h.sends(), 2, "the third waits for the gate");
        assert_eq!(h.m.inner.backups.gate.available_permits(), 0);
        // Every turn is held, the waiting one's too: a tick meanwhile starts nothing more.
        assert!(h.m.backup_step(t).is_empty());
        std::fs::remove_file(&hold).unwrap();
        assert_eq!(run(tasks).await, 3);
        assert_eq!(h.sends(), 3);
        for m in &ms {
            assert_eq!(h.listed(&m.id).await.len(), 1, "{}", m.name);
        }
        assert_eq!(h.m.inner.backups.gate.available_permits(), 2);
    }

    #[tokio::test]
    async fn a_machine_with_no_process_is_backed_up_only_when_its_disks_changed() {
        let h = harness(|_| {}).await;
        let m = h.machine("db", every("1h", 3), false).await;
        assert_eq!(m.state, state::CREATED);
        let t = m.next_backup_at.unwrap();
        // Its first backup: there is none to compare with.
        run(h.m.backup_step(t)).await;
        let first = h.listed(&m.id).await;
        assert_eq!(first.len(), 1);
        let version = h.m.get(&m.id).unwrap().version;
        h.pool.answer(&format!("written@bk-{}", first[0].id), "0\n");
        let t = t + chrono::Duration::hours(1);
        assert_eq!(run(h.m.backup_step(t)).await, 1);
        assert_eq!(h.listed(&m.id).await.len(), 1, "unchanged: skipped");
        let v = h.m.get(&m.id).unwrap();
        assert_eq!(v.next_backup_at, Some(t + chrono::Duration::hours(1)));
        assert_eq!(v.version, version, "a skip is no event");
        h.pool
            .answer(&format!("written@bk-{}", first[0].id), "4096\n");
        run(h.m.backup_step(t + chrono::Duration::hours(1))).await;
        let all = h.listed(&m.id).await;
        assert_eq!(all.len(), 2, "written: backed up");
        assert!(all[1].incremental);
    }

    #[tokio::test]
    async fn retention_keeps_keep_restorable_points_and_their_bases() {
        let h = harness(|_| {}).await;
        let m = h.machine("db", every("1h", 2), true).await;
        let mut made = Vec::new();
        for _ in 0..3 {
            made.push(h.m.backup(&m.id).await.unwrap().id);
        }
        // Whole, from it, whole: the second is kept and needs the first.
        let all = h.listed(&m.id).await;
        assert_eq!(h.ids(&all), made);
        assert_eq!(
            all.iter().map(|b| b.incremental).collect::<Vec<_>>(),
            [false, true, false]
        );
        // The oldest kept point restores from its chain.
        let restore = |name: &str, backup: &str| api::CreateMachineRequest {
            tenant: "t1".into(),
            name: name.into(),
            restore: Some(api::RestoreSpec {
                machine_id: m.id.clone(),
                backup: backup.into(),
            }),
            start: Some(false),
            ..Default::default()
        };
        let r = h.m.create(restore("r2", &made[1])).await.unwrap();
        assert_eq!(r.state, state::CREATED);
        // Its own backups start a chain of their own, whole.
        let rb = h.m.backup(&r.id).await.unwrap();
        assert!(!rb.incremental, "{rb:?}");
        // The fourth continues from the third: the first chain goes, streams and records.
        made.push(h.m.backup(&m.id).await.unwrap().id);
        let all = h.listed(&m.id).await;
        assert_eq!(h.ids(&all), made[2..].to_vec());
        assert!(all[1].incremental);
        let mut want: Vec<String> = made[2..]
            .iter()
            .flat_map(|id| {
                [
                    format!("backups/{}/{id}.json", m.id),
                    format!("backups/{}/root/{id}.zfs", m.id),
                ]
            })
            .collect();
        want.sort();
        assert_eq!(h.objects(&m.id).await, want);
        let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
        assert_eq!(ev["reason"], "retention");
        assert_eq!(ev["backups"], json!([made[1], made[0]]), "newest first");
        assert_eq!(
            h.stored(&m.id).unwrap().backup_bytes,
            all.iter().map(|b| b.bytes).sum::<u64>()
        );
        // Both kept points restore.
        h.m.create(restore("r3", &made[2])).await.unwrap();
        h.m.create(restore("r4", &made[3])).await.unwrap();
    }

    #[tokio::test]
    async fn a_promoted_fork_backs_up_whole_from_its_own_snapshots_only() {
        let h = harness(|_| {}).await;
        let src = h.machine("src", Some(None), true).await;
        let sb = h.m.backup(&src.id).await.unwrap();
        let mut req = h.request("fork");
        req.fork = Some(api::ForkSpec {
            machine_id: src.id.clone(),
            copy: String::new(),
        });
        let fork = h.m.create(req).await.unwrap();
        // Destroyed under its fork: the fork's root disk takes the source's older snapshots
        // over, its backup snapshot among them, as ZFS's promote does.
        h.m.destroy(&src.id, None).await.unwrap();
        let taken = h
            .pool
            .dev()
            .join(format!("byard/m/{}/root@bk-{}", fork.id, sb.id));
        assert!(taken.exists(), "{}", taken.display());
        // That snapshot is not a backup of the fork: its first backup is whole.
        let first = h.m.backup(&fork.id).await.unwrap();
        assert!(!first.incremental, "{first:?}");
        assert!(first.disks.iter().all(|d| d.from.is_none()));
        let second = h.m.backup(&fork.id).await.unwrap();
        assert_eq!(second.disks[0].from.as_deref(), Some(first.id.as_str()));
        // And its chain restores.
        let r =
            h.m.create(api::CreateMachineRequest {
                tenant: "t1".into(),
                name: "back".into(),
                restore: Some(api::RestoreSpec {
                    machine_id: fork.id.clone(),
                    backup: second.id.clone(),
                }),
                start: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(r.state, state::CREATED);
    }

    #[tokio::test]
    async fn a_base_is_deleted_only_with_what_continues_from_it() {
        let h = harness(|_| {}).await;
        let m = h.machine("db", Some(None), true).await;
        let mut made = Vec::new();
        for _ in 0..3 {
            made.push(h.m.backup(&m.id).await.unwrap().id);
        }
        match h.m.delete_backup(&m.id, &made[0], false).await {
            Err(MError::Conflict(e)) => {
                assert!(e.contains(&made[1]) && e.contains(&made[2]), "{e}");
                assert!(e.contains("?chain=true"), "{e}");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            h.m.delete_backup(&m.id, "20990101T000000.000Z", false)
                .await,
            Err(MError::NoBackup(_))
        ));
        assert!(matches!(
            h.m.delete_backup("m_none", &made[0], false).await,
            Err(MError::NotFound)
        ));
        // The newest goes alone; the record's newest is the one before.
        h.m.delete_backup(&m.id, &made[2], false).await.unwrap();
        assert_eq!(h.ids(&h.listed(&m.id).await), made[..2].to_vec());
        assert_eq!(
            h.stored(&m.id).unwrap().backup.last.as_ref(),
            Some(&made[1])
        );
        let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
        assert_eq!(
            (ev["reason"].clone(), ev["backups"].clone()),
            (json!("request"), json!([made[2]]))
        );
        // Its snapshot was the base on the host, and it is gone from the store: whole.
        let next = h.m.backup(&m.id).await.unwrap();
        assert!(!next.incremental);
        h.m.delete_backup(&m.id, &made[0], true).await.unwrap();
        assert_eq!(h.ids(&h.listed(&m.id).await), vec![next.id.clone()]);
        let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
        assert_eq!(ev["backups"], json!([made[1], made[0]]));
        assert_eq!(h.stored(&m.id).unwrap().backup_bytes, next.bytes);
    }

    #[tokio::test]
    async fn a_failed_backup_is_a_warning_and_is_tried_again_after_the_backoff() {
        let h = harness(|_| {}).await;
        // The fake's `zfs` refuses any name with "boom" in it.
        let e = h.add("m_boom", state::STOPPED, 256);
        let t = at("2026-10-21T10:00:00Z");
        {
            let mut r = e.rec.lock().unwrap();
            r.backup.policy = every("1h", 3).flatten();
            r.backup.next_at = Some(t);
        }
        assert_eq!(run(h.m.backup_step(t)).await, 1);
        let ev = h.last_of("m_boom", reason::BACKUP_FAILED);
        assert_eq!(ev.kind, api::event::WARNING);
        assert!(ev.message.contains("permission denied"), "{}", ev.message);
        assert!(ev.data.unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("permission denied"));
        assert_eq!(
            h.m.get("m_boom").unwrap().next_backup_at,
            Some(t + RETRY_AFTER)
        );
        assert_eq!(
            run(h.m.backup_step(t + chrono::Duration::minutes(14))).await,
            0
        );
        assert_eq!(run(h.m.backup_step(t + RETRY_AFTER)).await, 1);
        let failed = h
            .reasons("m_boom")
            .iter()
            .filter(|r| *r == reason::BACKUP_FAILED)
            .count();
        assert_eq!(failed, 2);
        assert!(h.listed("m_boom").await.is_empty());
    }

    #[tokio::test]
    async fn a_backup_the_store_refuses_leaves_nothing_behind() {
        let h = harness(|_| {}).await;
        let m = h.machine("db", Some(None), false).await;
        // A file where the root disk's streams go: the store cannot write there.
        let store = h.m.inner.cfg.data_dir.join("store");
        std::fs::create_dir_all(store.join(format!("backups/{}", m.id))).unwrap();
        std::fs::write(store.join(format!("backups/{}/root", m.id)), "").unwrap();
        assert!(h.m.backup(&m.id).await.is_err());
        assert_eq!(
            h.last_of(&m.id, reason::BACKUP_FAILED).kind,
            api::event::WARNING
        );
        let root = h.m.get(&m.id).map(|_| format!("m/{}/root", m.id)).unwrap();
        let snaps = h.pool.zfs.snapshots(&root).await.unwrap();
        assert!(!snaps.iter().any(|s| s.starts_with("bk-")), "{snaps:?}");
        assert!(h.listed(&m.id).await.is_empty());
    }

    #[tokio::test]
    async fn a_destroyed_machine_s_backups_are_listed_counted_then_deleted() {
        let h = harness(|_| {}).await;
        let mut req = h.request("db");
        req.backup = every("1h", 3);
        req.metadata = BTreeMap::from([("briq".to_string(), "bq_1".to_string())]);
        let m = h.m.create(req).await.unwrap();
        let first = h.m.backup(&m.id).await.unwrap();
        let second = h.m.backup(&m.id).await.unwrap();
        let bytes = first.bytes + second.bytes;
        let gone = Utc::now();
        h.m.destroy(&m.id, None).await.unwrap();
        assert!(matches!(h.m.get(&m.id), Err(MError::NotFound)));
        // Listed with the tenant's, each saying when it goes.
        let all = h.m.all_backups(Some("t1")).await.unwrap();
        assert_eq!(h.ids(&all), vec![first.id.clone(), second.id.clone()]);
        let deletes_at = all[0].deletes_at.unwrap();
        assert!(deletes_at >= gone + chrono::Duration::days(30));
        assert!(deletes_at <= Utc::now() + chrono::Duration::days(30));
        assert_eq!(
            h.m.backups(&m.id).await.unwrap()[1].deletes_at,
            Some(deletes_at)
        );
        assert!(h.m.all_backups(Some("t2")).await.unwrap().is_empty());
        assert_eq!(h.m.all_backups(None).await.unwrap().len(), 2);
        // Counted in its own buckets, as it was: what its backups take, nothing else.
        let now = Utc::now();
        h.m.measure(now + chrono::Duration::hours(1)).await;
        let from = usage::hour_of(gone).to_rfc3339();
        let to = (usage::hour_of(now) + chrono::Duration::hours(2)).to_rfc3339();
        let mine: Vec<api::UsageBucket> = h
            .buckets(&from, &to)
            .await
            .into_iter()
            .filter(|b| b.machine_id == m.id)
            .collect();
        let gb_hours: f64 = mine.iter().map(|b| b.usage.backup_gb_hours).sum();
        let hour = bytes as f64 / (1u64 << 30) as f64;
        assert!(
            gb_hours >= hour && gb_hours < hour * 1.01,
            "{gb_hours} {hour}"
        );
        let last = mine.last().unwrap();
        assert_eq!(
            (
                last.role.as_deref(),
                last.metadata.get("briq").map(String::as_str)
            ),
            (None, Some("bq_1"))
        );
        assert_eq!(last.usage.root_gb_hours, 0.0);
        // Deleted by request too, and held across a restart of the daemon.
        h.m.delete_backup(&m.id, &second.id, false).await.unwrap();
        assert_eq!(
            h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap()["reason"],
            "request"
        );
        let again = Backups::open(&h.m.inner.cfg.backup, &h.m.inner.store).unwrap();
        let held = again
            .holders
            .lock()
            .unwrap()
            .get(&m.id)
            .map(|x| x.rec.lock().unwrap().bytes);
        assert_eq!(held, Some(first.bytes));
        // `keep_destroyed_days` later, the rest goes, then the holder.
        let days = |n| gone + chrono::Duration::days(n);
        assert_eq!(run(h.m.backup_step(days(29))).await, 0);
        assert_eq!(run(h.m.backup_step(days(31))).await, 1);
        assert!(h.m.all_backups(Some("t1")).await.unwrap().is_empty());
        assert!(h.objects(&m.id).await.is_empty());
        assert!(h.m.holder(&m.id).is_none());
        assert!(h
            .m
            .inner
            .store
            .get::<HolderRec>(HOLDERS, &m.id)
            .unwrap()
            .is_none());
        let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
        assert_eq!(
            (ev["reason"].clone(), ev["backups"].clone()),
            (json!("expired"), json!([first.id]))
        );
        assert!(matches!(
            h.m.delete_backup(&m.id, &first.id, false).await,
            Err(MError::NotFound)
        ));
    }

    #[tokio::test]
    async fn the_routes_delete_and_list() {
        let h = harness(|_| {}).await;
        let m = h.machine("db", Some(None), true).await;
        let first = h.m.backup(&m.id).await.unwrap();
        let second = h.m.backup(&m.id).await.unwrap();
        let st = Arc::new(crate::api::AppState {
            mgr: h.m.clone(),
            token: String::new(),
            metrics_token: String::new(),
            loopback: true,
            openapi: "",
            tls_fingerprint: String::new(),
        });
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", ln.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
        let http = reqwest::Client::new();
        let list: Vec<api::Backup> = http
            .get(format!("{url}/backups?tenant=t1"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list.len(), 2);
        let delete = |q: &str| {
            http.delete(format!("{url}/machines/{}/backups/{q}", m.id))
                .send()
        };
        let r = delete(&first.id).await.unwrap();
        assert_eq!(r.status(), 409);
        assert_eq!(r.json::<api::ApiError>().await.unwrap().code, "conflict");
        let r = delete("20990101T000000.000Z").await.unwrap();
        assert_eq!(r.status(), 404);
        assert!(r
            .json::<api::ApiError>()
            .await
            .unwrap()
            .error
            .contains("20990101T000000.000Z"));
        assert_eq!(
            delete(&format!("{}?chain=true", first.id))
                .await
                .unwrap()
                .status(),
            204
        );
        assert!(
            h.listed(&m.id).await.is_empty(),
            "{second:?} went with its base"
        );
        let r = http
            .get(format!("{url}/backups?tenant=../x"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }
}
