//! Backups (ADR 0008, ADR 0023): a machine's disks streamed to the object store, on request or
//! on the machine's schedule, pruned to its `keep`; a destroyed machine's kept by a holder
//! until `backup.keep_destroyed_days` have passed.

use super::*;
use crate::config;
use crate::objstore::ObjectStore;
use futures::{StreamExt, TryStreamExt};
use std::collections::HashSet;
use tokio::sync::OwnedMutexGuard;

/// A failed backup is tried again this long after.
const RETRY_AFTER: chrono::Duration = chrono::Duration::minutes(15);

/// The local store's kind for holders.
const HOLDERS: &str = "holders";
/// How long a destroy without disks waits for the store's list of its backups. Past it the
/// store counts as unreachable, and the machine stays `destroying` for the tick to try again.
/// The tick resumes destroys one by one, each under its machine's lock, so the store's own
/// retry budget (minutes) must not hold them.
const LIST_AT_DESTROY: std::time::Duration = std::time::Duration::from_secs(30);

/// Store reads that listings make at once, host-wide: a listing of every machine's backups,
/// and listings asked together, take turns at this many.
const READS_AT_ONCE: usize = 16;

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
    #[serde(alias = "tenant")]
    pub namespace: String,
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
    /// Listings' store reads (`READS_AT_ONCE`).
    reads: tokio::sync::Semaphore,
    holders: Mutex<HashMap<String, Arc<Holder>>>,
}

/// A pool key's id and what a backup's record is sealed with: a key per record, derived from
/// the pool key by HKDF-SHA256 with the record's place in its info, for AES-256-GCM. The pool
/// key itself is not kept (ADR 0035).
pub(super) struct Seal {
    id: String,
    prk: ring::hkdf::Prk,
}

impl Seal {
    pub(super) fn of(pool_key: &str) -> Result<Seal> {
        use ring::hkdf;
        let id = api::poolkey::id(pool_key).ok_or_else(|| anyhow!("not a pool key"))?;
        let bytes = hex::decode(pool_key.trim())?;
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"briqyard backup record").extract(&bytes);
        Ok(Seal { id, prk })
    }

    /// The key of the record at `place` (`<machine>/<backup>`): a sealed spec opens in no
    /// other record.
    fn key(&self, place: &str) -> Result<ring::aead::LessSafeKey> {
        use ring::aead;
        let info: [&[u8]; 2] = [b"aes-256-gcm ", place.as_bytes()];
        let okm = self
            .prk
            .expand(&info, &aead::AES_256_GCM)
            .map_err(|_| anyhow!("derive the key of record {place}"))?;
        Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
    }

    /// `plain` sealed for the record at `place`: a random nonce, then the ciphertext and its
    /// tag, in base64; the place is the associated data too.
    fn seal(&self, place: &str, plain: &[u8]) -> Result<String> {
        use base64::Engine;
        use ring::aead::{Aad, Nonce};
        use ring::rand::SecureRandom;
        let mut nonce = [0u8; 12];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow!("the OS gave no random bytes for a record's nonce"))?;
        let mut out = plain.to_vec();
        self.key(place)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(place.as_bytes()),
                &mut out,
            )
            .map_err(|_| anyhow!("seal record {place}"))?;
        Ok(base64::engine::general_purpose::STANDARD.encode([&nonce[..], &out].concat()))
    }

    fn open(&self, place: &str, sealed: &str) -> Result<Vec<u8>> {
        use base64::Engine;
        use ring::aead::{Aad, Nonce};
        let data = base64::engine::general_purpose::STANDARD.decode(sealed)?;
        if data.len() < 12 + 16 {
            return Err(anyhow!("sealed record of {place}: too short"));
        }
        let (nonce, rest) = data.split_at(12);
        let mut buf = rest.to_vec();
        let plain = self
            .key(place)?
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).expect("12 bytes"),
                Aad::from(place.as_bytes()),
                &mut buf,
            )
            .map_err(|_| anyhow!("sealed record of {place}: does not open under its key"))?;
        Ok(plain.to_vec())
    }
}

/// The machine a backup holds: opened with the backup's key when sealed (ADR 0035), as it is
/// in a backup made before.
pub(super) fn spec_of(b: &api::Backup, key: Option<&str>) -> Result<serde_json::Value> {
    let Some(sealed) = &b.sealed else {
        return Ok(b.machine.clone().unwrap_or_default());
    };
    let key = key.ok_or_else(|| anyhow!("backup {}: sealed, and no key", b.id))?;
    let plain = Seal::of(key)?.open(&format!("{}/{}", b.machine_id, b.id), sealed)?;
    Ok(serde_json::from_slice(&plain)?)
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
            reads: tokio::sync::Semaphore::new(READS_AT_ONCE),
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

    /// The machine's id and namespace.
    fn who(&self) -> (String, String) {
        match self {
            Owner::Machine(e) => {
                let r = e.rec.lock().unwrap();
                (r.id.clone(), r.namespace.clone())
            }
            Owner::Holder(h) => {
                let r = h.rec.lock().unwrap();
                (r.machine_id.clone(), r.namespace.clone())
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

    /// What a backup is sealed and named with (ADR 0035): the pool key asked of its source,
    /// checked against the pool (a key file replaced, a registry restored to an older key, a
    /// pool re-keyed by hand would otherwise name a key its streams are not under), then
    /// dropped once derived.
    async fn seal(&self) -> Result<Seal, MError> {
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
    pub(super) async fn backup_key(
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
    async fn send_backup(
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
    async fn read_backups(
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
    pub(super) async fn hold_at_destroy(
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
    /// received into the new datasets. Raw streams (ADR 0035) land as their own encryption
    /// root under the key they were sent with: that key, asked by its id, opens them, and they
    /// then take the pool's. A chain in clear (before ADR 0035) is received as it always was.
    /// A chain is one or the other: a raw increment is sent only over a raw backup under the
    /// same key (`in_store`). The key is given to a disk once its whole chain is in: a raw
    /// increment is received only into a dataset that is still its own encryption root.
    pub(super) async fn receive_disks(
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
                let mut child = self.inner.zfs.receive(&ds)?;
                let mut stdin = child.stdin.take().expect("piped");
                let mut reader = store.get(&step.key).await?;
                tokio::io::copy(&mut reader, &mut stdin)
                    .await
                    .with_context(|| format!("restore {}", step.key))?;
                drop(stdin);
                Zfs::finish(child, "zfs receive").await?;
            }
            if let Some(key) = key {
                self.inner.zfs.inherit_key(&ds, key).await?;
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

/// Whether a snapshot `bk-<id>` is the snapshot of a backup in `all` holding that disk, sent
/// raw under the key `key_id`.
fn in_store(all: &[api::Backup], snap: &str, disk: &str, key_id: &str) -> bool {
    let id = snap.trim_start_matches("bk-");
    all.iter().any(|b| {
        b.id == id && b.key_id.as_deref() == Some(key_id) && b.disks.iter().any(|d| d.disk == disk)
    })
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
mod tests;
