//! Backups (ADR 0008, ADR 0023): a machine's disks streamed to the object store, on request or
//! on the machine's schedule, pruned to its `keep`; a destroyed machine's kept by a holder
//! until `backup.keep_destroyed_days` have passed.

use super::*;
use crate::config;
use crate::objstore::ObjectStore;
use futures::{StreamExt, TryStreamExt};
use std::collections::HashSet;
use tokio::sync::OwnedMutexGuard;

mod chain;
mod holders;
mod jobs;
mod list;
mod take;
#[cfg(test)]
mod tests;

use chain::*;

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
    gate: Arc<tokio::sync::Semaphore>,
    jobs: Arc<jobs::Jobs>,
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
            gate: Arc::new(tokio::sync::Semaphore::new(cfg.at_once.max(1) as usize)),
            jobs: jobs::Jobs::new(cfg.at_once.max(1) as usize),
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
    /// Stop new backup/expiry admission while already owned jobs continue to settlement.
    pub fn close_backup_admission(&self) {
        self.inner.backups.jobs.close();
        self.inner.zfs.close_io_admission();
    }
    /// Await actual whole jobs, not their request waiters. The process shutdown budget
    /// bounds this await; timeout does not assert publication absence or undo effects.
    pub async fn drain_backups(&self) {
        self.inner.backups.jobs.drain().await;
        self.inner.zfs.drain_io().await;
    }
}
