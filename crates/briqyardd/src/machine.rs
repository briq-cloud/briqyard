//! Machines: their records, disks, network and Firecracker processes, and every lifecycle
//! transition. One `Manager` per daemon.

use crate::conditions::{self, Conditions};
use crate::config::Config;
use crate::console;
use crate::events::{self, Ev, Events};
use crate::fc;
use crate::guestc;
use crate::image::{self, Builder, ImageConfig, Removal};
use crate::metrics;
use crate::netw::{self, dns::Resolver, host, nft, nft::Ruleset, Range, Subnet};
use crate::store::Store;
use crate::usage::{self, Ledger, Meter, Traffic};
use crate::zfs::Zfs;
use anyhow::{anyhow, bail, Context, Result};
use briqyard_api::guest;
use briqyard_api::{self as api, reason, state, stop};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, Notify};

mod backups;
use backups::{Backups, Schedule, Turn};
mod probes;
mod snapshots;
use snapshots::SnapshotRec;

/// What the API maps to statuses.
#[derive(Debug, thiserror::Error)]
pub enum MError {
    #[error("machine not found")]
    NotFound,
    #[error("backup {0} not found")]
    NoBackup(String),
    #[error("snapshot {0} not found")]
    NoSnapshot(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("machine is not running: {0}")]
    NotRunning(String),
    #[error("machine is busy: {0}")]
    BadState(String),
    #[error("the host is full: {0}")]
    Capacity(String),
    /// Past a limit of the tenant's quota (ADR 0025).
    #[error("{0}")]
    Quota(String),
    #[error("the tenant still has machines")]
    TenantInUse,
    #[error("a machine of the tenant runs through its gateway")]
    GatewayInUse,
    /// A call that would change or run something in a tenant's gateway through the machine
    /// routes: the tenant's route owns it.
    #[error("the tenant's gateway: use /v1/tenants/{0}/gateway")]
    Gateway(String),
    /// The guest never came up or exited while booting: the image's fault, not the host's.
    /// The machine stays, in state `error`, with the console tail in its `error`.
    #[error("boot failed: {}", .0.error)]
    BootFailed(Box<api::Machine>),
    /// A `/wait` for `ready` ran out while the machine runs and its probes say it does not
    /// serve yet (ADR 0022): the machine, its probes' last results in it.
    #[error("machine {} is running, not ready: {}", .0.id, not_ready_why(.0))]
    NotReady(Box<api::Machine>),
    /// `If-Match` named a version the machine has moved past (ADR 0019): the machine as it is.
    #[error("machine {} is at version {}: read it again", .0.id, .0.version)]
    Moved(Box<api::Machine>),
    /// An event cursor the log cannot answer from, with the oldest seq it keeps.
    #[error("{message}")]
    Gone { oldest: u64, message: String },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn invalid(msg: impl Into<String>) -> MError {
    MError::Invalid(msg.into())
}

/// A tenant id is checked before it names a file.
fn check_tenant_id(id: &str) -> Result<(), MError> {
    match api::valid_id(id) {
        true => Ok(()),
        false => Err(invalid(
            "tenant must be a-z, 0-9, _ or -, at most 64 characters",
        )),
    }
}

/// `via: "gateway"` in a tenant that has none.
fn no_gateway(tenant: &str) -> MError {
    invalid(format!(
        "tenant has no gateway: PUT /v1/tenants/{tenant}/gateway first"
    ))
}

/// What a machine is to its tenant when it is not one of the tenant's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The tenant's gateway (ADR 0016): run by the daemon, absent from the tenant's machines.
    Gateway,
}

/// A machine as the daemon keeps it: the API view plus what running it needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub tenant: String,
    /// None for the tenant's own machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    pub name: String,
    pub image: String,
    pub image_key: String,
    pub image_digest: String,
    pub image_config: ImageConfig,
    /// The image the root disk was made from: when it is not `image_key`, the next start
    /// makes the root disk again (ADR 0024).
    #[serde(default)]
    pub root_key: String,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub files: Vec<api::File>,
    pub size: api::Size,
    #[serde(default)]
    pub volume: Option<api::VolumeSpec>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub sleep: String,
    pub restart: api::RestartPolicy,
    /// Its startup, readiness and liveness probes (ADR 0022).
    #[serde(default)]
    pub probes: api::Probes,
    /// Where its traffic may go (ADR 0015); a record from before has none: open.
    #[serde(default)]
    pub egress: api::Egress,
    /// Its own limits on its internet traffic, over the host's (ADR 0018).
    #[serde(default)]
    pub limits: api::EgressLimits,
    /// Its own limits on each of its disks, over the host's for its size (ADR 0030).
    #[serde(default)]
    pub disk_limits: api::DiskLimits,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub state: String,
    #[serde(default)]
    pub stopped_reason: String,
    #[serde(default)]
    pub exit: Option<api::Exit>,
    #[serde(default)]
    pub error: String,
    pub subnet_index: u32,
    pub host_num: u8,
    pub ip: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub restarts: u32,
    /// Restarts since the last run that lasted `RESET_AFTER`: the backoff's step (ADR 0022).
    #[serde(default)]
    pub recent_restarts: u32,
    /// When the restart policy starts it again, while it waits to.
    #[serde(default)]
    pub restarting_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub boots: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When `state` last changed; written only by `Entry::set_state`.
    #[serde(default)]
    pub state_changed_at: DateTime<Utc>,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub stopped_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Where the current boot's console output starts.
    #[serde(default)]
    pub console_offset: u64,
    /// Stopped with a memory snapshot: the next start resumes where it was.
    #[serde(default)]
    pub suspended: bool,
    /// What this machine's backups take in the store.
    #[serde(default)]
    pub backup_bytes: u64,
    /// Its backup schedule (ADR 0023).
    #[serde(default)]
    pub backup: Schedule,
    /// The seq of the last event about it (ADR 0019); written only by `Entry::note_locked`.
    #[serde(default)]
    pub version: u64,
    /// What a PATCH changes at the next start, and since when (ADR 0024).
    #[serde(default)]
    pub pending: Option<api::SpecChange>,
    #[serde(default)]
    pub pending_since: Option<DateTime<Utc>>,
    /// Its snapshots, oldest first (ADR 0031).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshots: Vec<SnapshotRec>,
    /// The snapshot its disks are going back to, until the restore is done (ADR 0031).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restoring: Option<String>,
    /// What the init said at the last boot (ADR 0027).
    #[serde(default)]
    pub init_version: String,
    /// What ran the last boot (`Vmm::version`): a memory snapshot resumes only under it.
    #[serde(default)]
    pub vmm_version: String,
    /// What a newer daemon wrote and this one does not know: kept as it is, so a rollback that
    /// rewrites the record does not drop it (ADR 0027).
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

impl Record {
    /// One of the tenant's own machines: what the tenant's listing, counts and removal see.
    fn is_tenants(&self) -> bool {
        self.role.is_none()
    }
    fn is_gateway(&self) -> bool {
        self.role == Some(Role::Gateway)
    }
    pub fn hostname(&self) -> String {
        format!("{}.internal", self.name)
    }
    pub fn machine_host(&self) -> String {
        format!("{}.vm.internal", self.id)
    }
    pub fn dataset(&self) -> String {
        format!("m/{}", self.id)
    }
    pub fn root_dataset(&self) -> String {
        format!("m/{}/root", self.id)
    }
    pub fn data_dataset(&self) -> String {
        format!("m/{}/data", self.id)
    }
    /// The dataset of a disk in use: `root` or `data`.
    pub fn disk_dataset(&self, disk: &str) -> String {
        format!("m/{}/{disk}", self.id)
    }
    /// Whether its next start makes the root disk again: a new image pending, or one applied
    /// whose root disk is not made yet (ADR 0024).
    fn remakes_root(&self) -> bool {
        self.root_key != self.image_key || self.pending.as_ref().is_some_and(|p| p.image.is_some())
    }
    pub fn sleep_window(&self) -> Option<Duration> {
        api::parse_sleep(&self.sleep).ok().flatten()
    }

    /// Brings a record written by an earlier daemon to the current shape: `sleep` was `""`
    /// for never, `state_changed_at` did not exist (its best stand-in is `updated_at`), nor
    /// `root_key` (the root disk was always made from the record's image).
    fn migrate(&mut self) {
        self.sleep = sleep_setting(&self.sleep);
        if self.state_changed_at == DateTime::<Utc>::default() {
            self.state_changed_at = self.updated_at;
        }
        if self.root_key.is_empty() {
            self.root_key = self.image_key.clone();
        }
    }
}

/// The one way a sleep window is stored: what the API said, with "" (never) as "never".
fn sleep_setting(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        "never".into()
    } else {
        s.into()
    }
}

/// Whether a machine in this state holds the memory it was given: from the reservation at
/// `starting` until its process is gone.
fn holds_memory(state: &str) -> bool {
    matches!(state, state::STARTING | state::RUNNING | state::STOPPING)
}

/// What a machine in this record's state holds, for its usage.
fn held(r: &Record) -> usage::Held {
    usage::Held {
        running: holds_memory(&r.state),
        suspended: r.state == state::STOPPED && r.suspended,
        memory_mb: r.size.memory_mb,
    }
}

/// A role as the API names it.
fn role_name(role: Option<Role>) -> Option<String> {
    role.map(|role| match role {
        Role::Gateway => "gateway".to_string(),
    })
}

/// Who a usage bucket is about, as the record says now.
fn usage_identity(r: &Record) -> api::UsageBucket {
    api::UsageBucket {
        machine_id: r.id.clone(),
        tenant: r.tenant.clone(),
        role: role_name(r.role),
        metadata: r.metadata.clone(),
        size: r.size,
        ..Default::default()
    }
}

/// What each machine's datasets take, from the pool's listing under `m`: the allocated sizes
/// of its root and data volumes, and what `m/<id>` and everything under it hold.
fn disks_by_machine(spaces: &[crate::zfs::Space]) -> HashMap<String, usage::Disks> {
    let mut out: HashMap<String, usage::Disks> = HashMap::new();
    for s in spaces {
        let mut parts = s.name.split('/');
        let (Some("m"), Some(id)) = (parts.next(), parts.next()) else {
            continue;
        };
        let d = out.entry(id.to_string()).or_default();
        match parts.next() {
            Some("root") => d.root = s.volsize,
            Some("data") => d.volume = s.volsize,
            _ => {}
        }
        d.used += s.data;
        d.snapshots += s.snapshots;
    }
    out
}

/// Whether `need` MB more fit next to `used` on a host of `cap`.
fn admit(used: u32, cap: u32, need: u32) -> Result<(), MError> {
    match used.checked_add(need) {
        Some(total) if total <= cap => Ok(()),
        _ => Err(MError::Capacity(format!("{used} MB used of {cap}"))),
    }
}

/// A limit of a tenant's quota that a create or a start would pass (ADR 0025).
#[derive(Debug, PartialEq)]
struct Exceeded {
    tenant: String,
    resource: &'static str,
    limit: u32,
    used: u32,
    need: u32,
}

impl std::fmt::Display for Exceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tenant {}'s quota: {} {} of {} used, {} more asked",
            self.tenant, self.resource, self.used, self.limit, self.need
        )
    }
}

impl Exceeded {
    fn event(&self, message: String) -> Ev {
        Ev::warning(reason::QUOTA_EXCEEDED, message).data(json!({
            "resource": self.resource, "limit": self.limit, "used": self.used, "need": self.need,
        }))
    }
}

/// The first limit of `quota` that `need` more would pass next to `used`; a resource the
/// request does not ask for is never refused, even past a limit lowered under the use.
fn over_quota(
    tenant: &str,
    quota: &api::Quota,
    used: &api::QuotaUse,
    need: &api::QuotaUse,
) -> Option<Exceeded> {
    [
        ("machines", quota.machines, used.machines, need.machines),
        ("disk_gb", quota.disk_gb, used.disk_gb, need.disk_gb),
        ("memory_mb", quota.memory_mb, used.memory_mb, need.memory_mb),
        ("vcpus", quota.vcpus, used.vcpus, need.vcpus),
    ]
    .into_iter()
    .find_map(|(resource, limit, used, need)| {
        let limit = limit?;
        (need > 0 && used.saturating_add(need) > limit).then(|| Exceeded {
            tenant: tenant.into(),
            resource,
            limit,
            used,
            need,
        })
    })
}

/// What a machine of this record counts toward its tenant's quota: itself, its volume, and
/// its size while it holds memory, or when `starting` it is about to.
fn quota_need(r: &Record, starting: bool) -> api::QuotaUse {
    let runs = starting || holds_memory(&r.state);
    api::QuotaUse {
        machines: 1,
        memory_mb: if runs { r.size.memory_mb } else { 0 },
        vcpus: if runs { r.size.vcpus } else { 0 },
        disk_gb: r.volume.as_ref().map_or(0, |v| v.size_gb),
    }
}

/// What a tenant's machines hold, its gateway included: its quota's use.
fn tenant_use(machines: &HashMap<String, Arc<Entry>>, tenant: &str) -> api::QuotaUse {
    let mut u = api::QuotaUse::default();
    for e in machines.values() {
        let r = e.rec.lock().unwrap();
        if r.tenant == tenant {
            let n = quota_need(&r, false);
            u.machines += n.machines;
            u.memory_mb += n.memory_mb;
            u.vcpus += n.vcpus;
            u.disk_gb += n.disk_gb;
        }
    }
    u
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantRec {
    pub id: String,
    pub subnet_index: u32,
    pub created_at: DateTime<Utc>,
    /// What the tenant may hold (ADR 0025); none set: no limit.
    #[serde(default)]
    pub quota: api::Quota,
}

/// A tenant as the manager holds it: its record and the subnet its index names, checked
/// against `network.range` when the record was loaded or made.
#[derive(Clone)]
struct Tenant {
    rec: TenantRec,
    subnet: Subnet,
    /// The tenant's lock: held while its gateway is started, put, removed or put to sleep,
    /// and by a machine that needs the gateway until that machine is `starting`, so the
    /// sleeper never stops a gateway a start is about to use.
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl Tenant {
    fn new(rec: TenantRec, subnet: Subnet) -> Self {
        Self {
            rec,
            subnet,
            lock: Default::default(),
        }
    }
}

/// The gateway's name in its tenant: `gateway.internal`.
const GATEWAY_NAME: &str = "gateway";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointRec {
    pub id: String,
    pub machine_id: String,
    pub tenant: String,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub host_port: Option<u16>,
    #[serde(default)]
    pub host: String,
    pub created_at: DateTime<Utc>,
}

/// Idle machines the sleeper stops at once.
const SLEEPS_AT_ONCE: usize = 8;

/// Makes an id: a prefix and 12 hex characters.
pub fn new_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{prefix}_{}", hex::encode(b))
}

struct Entry {
    /// Serializes lifecycle operations on one machine; owned by a hand-over (ADR 0027).
    lock: Arc<tokio::sync::Mutex<()>>,
    rec: Mutex<Record>,
    live: Mutex<Option<fc::Vm>>,
    /// The reason set before asking the guest to stop; `None` when it ends on its own.
    stop_req: Mutex<Option<String>>,
    /// Signalled on every state change: what `wait` and a stop wait on.
    changed: Notify,
    /// A use since the record was last written; read and written under `rec`'s lock.
    unsaved_use: AtomicBool,
    /// Commands running in it for a caller, exec sessions included (ADR 0029): in use, it does
    /// not go to sleep.
    in_flight: AtomicUsize,
    /// Its usage since the tick last took it (ADR 0017); locked after `rec`, never before.
    meter: Mutex<Meter>,
    /// Bytes through its endpoints, added by the ingress as they pass.
    traffic: Arc<Traffic>,
    /// What its disks did, added from Firecracker's metrics (ADR 0030).
    disk_io: Arc<fc::DiskIo>,
    /// The host's event log: what an event about it goes to.
    events: Events,
    /// Held by each backup and deletion of its backups.
    backup_turn: Turn,
    /// While a stop that released the lock is under way: by when it has settled (ADR 0031).
    stop_deadline: Mutex<Option<tokio::time::Instant>>,
    /// What its probes found in the current run (ADR 0022); locked before `rec`, never after.
    probe: Mutex<probes::Run>,
    /// The task running its probes, while one runs.
    prober: Mutex<Option<tokio::task::AbortHandle>>,
}

impl Entry {
    fn new(rec: Record, events: Events) -> Arc<Self> {
        Arc::new(Self {
            lock: Default::default(),
            rec: Mutex::new(rec),
            live: Mutex::new(None),
            stop_req: Mutex::new(None),
            changed: Notify::new(),
            unsaved_use: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            meter: Mutex::new(Meter::new(Utc::now())),
            traffic: Arc::default(),
            disk_io: Arc::default(),
            events,
            backup_turn: Turn::default(),
            stop_deadline: Mutex::new(None),
            probe: Mutex::default(),
            prober: Mutex::new(None),
        })
    }

    fn snapshot(&self) -> Record {
        self.rec.lock().unwrap().clone()
    }

    /// Its backup turn, then its lock: what anything that replaces a disk holds, in the
    /// order a backup takes them, so no backup sends a disk while it is replaced.
    async fn lock_with_turn(
        &self,
    ) -> (
        tokio::sync::OwnedMutexGuard<()>,
        tokio::sync::MutexGuard<'_, ()>,
    ) {
        let turn = self.backup_turn.clone().lock_owned().await;
        (turn, self.lock.lock().await)
    }

    /// Its lock for a start, with its backup turn when that start replaces a disk: a new
    /// image's root disk (ADR 0024), or a restore to finish (ADR 0031). Whether it will is
    /// read again under the lock: a change in between takes the turn on the next round.
    async fn lock_for_start(
        &self,
    ) -> (
        Option<tokio::sync::OwnedMutexGuard<()>>,
        tokio::sync::MutexGuard<'_, ()>,
    ) {
        let swaps = |r: Record| r.remakes_root() || r.restoring.is_some();
        loop {
            if swaps(self.snapshot()) {
                let (turn, guard) = self.lock_with_turn().await;
                return (Some(turn), guard);
            }
            let guard = self.lock.lock().await;
            if !swaps(self.snapshot()) {
                return (None, guard);
            }
        }
    }

    /// `lock_for_start` (with the turn always when `turn`, as a restore takes it), once a
    /// stop under way (the sleeper's, a caller's) has settled: a start, a wake or a restore
    /// arriving meanwhile goes on after it rather than failing on `stopping`. A stop that has
    /// not settled by the deadline it set is the caller's to refuse.
    async fn lock_once_stopped(
        &self,
        turn: bool,
    ) -> (
        Option<tokio::sync::OwnedMutexGuard<()>>,
        tokio::sync::MutexGuard<'_, ()>,
    ) {
        loop {
            let turns = match turn {
                true => {
                    let (t, g) = self.lock_with_turn().await;
                    (Some(t), g)
                }
                false => self.lock_for_start().await,
            };
            let deadline = *self.stop_deadline.lock().unwrap();
            let deadline = match deadline {
                Some(d) if self.snapshot().state == state::STOPPING => d,
                _ => return turns,
            };
            if tokio::time::Instant::now() > deadline {
                return turns;
            }
            // Registered before the lock goes: the settle that follows wakes it.
            let settled = self.changed.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            drop(turns);
            let _ = tokio::time::timeout_at(deadline, settled).await;
        }
    }

    /// Its lock, once no stop is under way: a stop holds the lock to begin, then leaves it to
    /// the watcher, which settles the state under it once the guest has ended (ADR 0027's
    /// hand-over waits for that).
    async fn settled_lock(&self) -> tokio::sync::OwnedMutexGuard<()> {
        loop {
            let guard = self.lock.clone().lock_owned().await;
            if self.snapshot().state != state::STOPPING {
                return guard;
            }
            let settled = self.changed.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            drop(guard);
            settled.await;
        }
    }

    /// Marks a use now. In memory only: the sleeper reads it here, and the record on disk
    /// catches up with the next write or the sleeper's tick, so a busy machine does not
    /// rewrite its record on every connection.
    fn touch(&self) {
        let mut r = self.rec.lock().unwrap();
        r.last_used_at = Some(Utc::now());
        self.unsaved_use.store(true, Relaxed);
    }

    /// The one place `state` is written: the time in the old state is accrued to the meter,
    /// `state_changed_at` follows it and whoever waits on the machine is woken. `f` edits the
    /// rest of the record under the same lock and says what happened: that event is logged
    /// and becomes the machine's version (ADR 0019).
    fn set_state(&self, state: &str, f: impl FnOnce(&mut Record) -> Option<Ev>) {
        {
            let mut r = self.rec.lock().unwrap();
            if r.state != state {
                let now = Utc::now();
                let mut m = self.meter.lock().unwrap();
                m.advance(now, held(&r));
                if r.state == state::STARTING && state == state::RUNNING {
                    let took = now - r.state_changed_at;
                    m.boot_seconds = Some(took.num_microseconds().unwrap_or(0) as f64 / 1e6);
                }
                drop(m);
                r.state = state.into();
                r.state_changed_at = now;
            }
            if let Some(ev) = f(&mut r) {
                self.note_locked(&mut r, ev);
            }
        }
        self.changed.notify_waiters();
    }

    /// Logs an event about the machine, which becomes its version. The caller writes the record.
    fn note(&self, ev: Ev) {
        let mut r = self.rec.lock().unwrap();
        self.note_locked(&mut r, ev);
    }

    fn note_locked(&self, r: &mut Record, ev: Ev) {
        r.version = self.events.emit(ev.of(&r.id, &r.tenant));
    }
}

/// An open exec session (ADR 0029): the command's connection to the init, which ends the
/// command when it closes, and the machine held in use.
pub struct Session {
    pub conn: Box<dyn guestc::Conn>,
    pub machine: String,
    pub in_use: InUse,
}

/// A machine in use while this lives: it does not go to sleep, and its last use is when this
/// began and when it ended.
pub struct InUse(Arc<Entry>);

impl InUse {
    fn new(e: Arc<Entry>) -> Self {
        e.in_flight.fetch_add(1, Relaxed);
        e.touch();
        Self(e)
    }
}

impl Drop for InUse {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Relaxed);
    }
}

/// Counters since the daemon started, for /metrics.
#[derive(Default)]
pub struct Stats {
    pub boots: std::sync::atomic::AtomicU64,
    pub resumes: std::sync::atomic::AtomicU64,
    pub suspends: std::sync::atomic::AtomicU64,
    pub execs: std::sync::atomic::AtomicU64,
    pub starts_failed: std::sync::atomic::AtomicU64,
    pub backups: std::sync::atomic::AtomicU64,
}

struct Inner {
    stats: Stats,
    cfg: Config,
    store: Store,
    zfs: Zfs,
    images: Builder,
    dns: Resolver,
    /// The host behind the manager: its VMM, the guests, its network. Mocks in tests.
    vmm: Arc<dyn fc::Vmm>,
    guest: Arc<dyn guestc::Guest>,
    net: Arc<dyn host::Net>,
    range: Range,
    egress: String,
    host_id: String,
    /// The address TCP endpoints are reported at, resolved once.
    advertise: String,
    machines: Mutex<HashMap<String, Arc<Entry>>>,
    tenants: Mutex<HashMap<String, Tenant>>,
    endpoints: Mutex<HashMap<String, EndpointRec>>,
    endpoint_events: broadcast::Sender<(EndpointRec, bool)>,
    /// The egress policy the tables hold for each machine, with its tenant's gateway: what a
    /// stop takes out, even once the gateway machine it names is gone.
    policies: Mutex<HashMap<String, (Ipv4Addr, nft::Policy)>>,
    /// Held while a tenant is made (its subnet index, bridge and record), see `ensure_tenant`.
    tenant_create: tokio::sync::Mutex<()>,
    /// The backup store, the gate of scheduled backups, the holders (ADR 0023).
    backups: Backups,
    /// Boots run at once; see `boots_at_once`.
    boot_gate: tokio::sync::Semaphore,
    /// Probe executions run at once (ADR 0022).
    probe_gate: tokio::sync::Semaphore,
    /// The hours of usage not closed yet.
    usage: Mutex<Ledger>,
    /// What happened on the host (ADR 0019).
    events: Events,
    /// The pool's space as the tick last read it, and the conditions it decided (ADR 0021).
    pool: Mutex<Option<crate::zfs::Pool>>,
    conditions: Mutex<Conditions>,
    /// This daemon's start and what it did with what the previous one left (ADR 0027).
    started: Mutex<api::DaemonStart>,
}

#[derive(Clone)]
pub struct Manager {
    inner: Arc<Inner>,
}

impl Manager {
    /// Loads the state and prepares the host: forwarding, nftables, the tenants' bridges and
    /// DNS, and reaps machines left over from a previous daemon.
    pub async fn new(
        cfg: Config,
        store: Store,
        zfs: Zfs,
        mut images: Builder,
        dns: Resolver,
    ) -> Result<Self> {
        let range = Range::parse(&cfg.network.range).context("network.range")?;
        let host_id = match store.get_meta("host_id")? {
            Some(id) => id,
            None => {
                let id = new_id("h");
                store.put_meta("host_id", &id)?;
                id
            }
        };
        let egress = if cfg.network.egress.is_empty() {
            host::default_egress_interface()
                .await
                .context("network.egress")?
        } else {
            cfg.network.egress.clone()
        };
        tokio::fs::create_dir_all(cfg.run_dir()).await?;
        let boots_at_once = if cfg.boots_at_once > 0 {
            cfg.boots_at_once
        } else {
            (std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4)
                / 2)
            .max(2)
        };
        let backups = Backups::open(&cfg.backup, &store)?;
        let (endpoint_events, _) = broadcast::channel(64);
        let ledger = Ledger::load(&store, Utc::now()).context("usage")?;
        let events = Events::open(&store.dir("events")).context("events")?;
        images.events = Some(events.clone());
        let advertise = advertise_address(
            &cfg.ingress.advertise,
            &cfg.ingress.bind,
            host_ip(&egress).await,
        );
        let inner = Arc::new(Inner {
            stats: Stats::default(),
            vmm: Arc::new(fc::Firecracker {
                binary: cfg.firecracker.clone(),
                pci: cfg.pci,
                console_max: (cfg.console_max_mb as u64) << 20,
                version: fc::vmm_version(&cfg.firecracker)?,
            }),
            guest: Arc::new(guestc::Vsock),
            net: Arc::new(host::HostNet),
            cfg,
            store,
            zfs,
            images,
            dns,
            range,
            egress,
            host_id,
            advertise,
            machines: Mutex::new(HashMap::new()),
            tenants: Mutex::new(HashMap::new()),
            endpoints: Mutex::new(HashMap::new()),
            endpoint_events,
            policies: Mutex::new(HashMap::new()),
            tenant_create: tokio::sync::Mutex::new(()),
            backups,
            boot_gate: tokio::sync::Semaphore::new(boots_at_once as usize),
            probe_gate: tokio::sync::Semaphore::new(probes::PROBES_AT_ONCE),
            usage: Mutex::new(ledger),
            events,
            pool: Mutex::new(None),
            conditions: Mutex::new(Conditions::new(Utc::now())),
            started: Mutex::new(api::DaemonStart::default()),
        });
        let m = Self { inner };
        m.load()?;
        host::enable_forwarding()?;
        let tenants: Vec<Tenant> = m.inner.tenants.lock().unwrap().values().cloned().collect();
        for t in &tenants {
            m.plumb_tenant(t).await?;
            m.refresh_dns(t);
        }
        m.apply_rules().await?;
        let (adopted, stopped, gone) = m.recover().await;
        let swept = m.sweep_orphans().await;
        let machines = m.inner.machines.lock().unwrap().len();
        *m.inner.started.lock().unwrap() = api::DaemonStart {
            at: Utc::now(),
            adopted,
            stopped,
            gone,
        };
        m.inner.events.emit(
            Ev::normal(
                reason::HOST_STARTED,
                format!("daemon started: {adopted} machines adopted, {stopped} not handed over and {gone} gone marked stopped, {swept} leftovers swept"),
            )
            .data(json!({
                "version": api::VERSION, "vmm_version": m.inner.vmm.version(),
                "machines": machines, "adopted": adopted, "stopped": stopped, "gone": gone,
                "swept": swept,
            })),
        );
        m.start_stopped_by_host();
        let sleeper = m.clone();
        tokio::spawn(async move { sleeper.sleeper().await });
        Ok(m)
    }

    pub fn host_id(&self) -> &str {
        &self.inner.host_id
    }

    /// Reads the records. A tenant whose subnet index is outside `network.range`, or an
    /// endpoint whose port is outside `ingress.tcp_ports`, is refused here, with the fix, rather than found by the first request that needs its subnet. The
    /// event log goes on past every machine's version.
    fn load(&self) -> Result<()> {
        let st = &self.inner.store;
        for rec in st.list::<TenantRec>("tenants")? {
            let subnet = self.inner.range.subnet(rec.subnet_index).with_context(|| {
                format!(
                    "tenant {}: widen network.range back, or remove the tenant",
                    rec.id
                )
            })?;
            self.inner
                .tenants
                .lock()
                .unwrap()
                .insert(rec.id.clone(), Tenant::new(rec, subnet));
        }
        for mut r in st.list::<Record>("machines")? {
            r.migrate();
            self.inner.events.floor(r.version);
            let id = r.id.clone();
            self.inner
                .machines
                .lock()
                .unwrap()
                .insert(id, Entry::new(r, self.inner.events.clone()));
        }
        // An endpoint port outside the range would listen where the daemon's table does not
        // hold it for `allowed_clients`: refused, like a tenant outside `network.range`.
        let spec = &self.inner.cfg.ingress.tcp_ports;
        let (lo, hi) = port_range(spec).map_err(|e| anyhow!("{e}"))?;
        for ep in st.list::<EndpointRec>("endpoints")? {
            if let Some(p) = ep.host_port.filter(|p| !(lo..=hi).contains(p)) {
                bail!(
                    "endpoint {} (machine {}) holds host port {p}, outside ingress.tcp_ports \
                     {spec}: put the range back, or remove the endpoint",
                    ep.id,
                    ep.machine_id
                );
            }
            self.inner
                .endpoints
                .lock()
                .unwrap()
                .insert(ep.id.clone(), ep);
        }
        Ok(())
    }

    /// Machines a previous daemon left running: adopted when their Firecracker is still up
    /// and answering, else ended (only a process that still carries the machine's id is
    /// killed: after a reboot the pid is someone else's) and marked stopped by the host, so
    /// the next use wakes them. Destroys cut short are resumed by the sleeper's tick. How many
    /// were adopted, and how many marked stopped.
    async fn recover(&self) -> (usize, usize, usize) {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let (mut adopted, mut stopped, mut gone) = (0, 0, 0);
        for e in entries {
            let rec = e.snapshot();
            if !matches!(
                rec.state.as_str(),
                state::RUNNING | state::STARTING | state::STOPPING
            ) {
                continue;
            }
            if rec.state == state::RUNNING && rec.pid > 0 && self.adopt(&e, rec.pid).await {
                adopted += 1;
                continue;
            }
            // Its process still there but not answering for it (not handed over), or gone: it
            // exited while no daemon ran.
            let alive =
                rec.pid > 0 && self.inner.vmm.machine_of(rec.pid).as_deref() == Some(&rec.id);
            let why = match alive {
                true => {
                    stopped += 1;
                    self.inner.vmm.kill(rec.pid);
                    "left running by a previous daemon that could not hand it over: stopped"
                }
                false => {
                    gone += 1;
                    "its process ended while no daemon ran: stopped"
                }
            };
            self.unplug(&rec.id, &rec.ip).await;
            e.set_state(state::STOPPED, |r| {
                r.stopped_reason = stop::HOST.into();
                r.pid = 0;
                r.stopped_at = Some(Utc::now());
                Some(Ev::warning(reason::STOPPED, why).data(json!({"reason": stop::HOST})))
            });
            tracing::warn!(
                machine = rec.id,
                "machine left running by a previous daemon, marked stopped"
            );
            let _ = self.save(&e);
        }
        // An adopted machine that sends through its tenant's gateway needs it, and the
        // gateway's own process may not have survived: it starts as a start would start it.
        for gw in self.gateways_out_of_step(false) {
            let (m, tenant) = (self.clone(), gw.snapshot().tenant);
            tokio::spawn(async move {
                if let Err(err) = m.ensure_gateway(&tenant).await {
                    tracing::warn!(tenant, err = %err, "gateway an adopted machine needs");
                }
            });
        }
        (adopted, stopped, gone)
    }

    /// Resources a previous daemon left with no record to own them: a crash between a resource
    /// and its record, or a destroy cut short. A Firecracker nobody knows is ended; its run
    /// directory, jail, TAP and disks go. Done once at start, so nothing leaks for good. How
    /// many it found.
    async fn sweep_orphans(&self) -> usize {
        let known: std::collections::HashSet<String> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut swept = 0;
        for (pid, id) in self.inner.vmm.processes() {
            if !known.contains(&id) {
                self.inner.vmm.kill(pid);
                tracing::warn!(machine = id, pid, "firecracker with no record, ended");
                swept += 1;
            }
        }
        if let Ok(mut rd) = tokio::fs::read_dir(self.inner.cfg.run_dir()).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("m_") && !known.contains(&name) {
                    let _ = tokio::fs::remove_dir_all(e.path()).await;
                    tracing::warn!(machine = name, "run directory with no record, removed");
                    swept += 1;
                }
            }
        }
        let jails = self.inner.cfg.jail_base().join("firecracker");
        if let Ok(mut rd) = tokio::fs::read_dir(&jails).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.replacen("m-", "m_", 1);
                if name.starts_with("m-") && !known.contains(&id) {
                    let _ = tokio::fs::remove_dir_all(e.path()).await;
                    tracing::warn!(machine = id, "jail with no record, removed");
                    swept += 1;
                }
            }
        }
        if let Ok(taps) = self.inner.net.list_taps().await {
            let owned: std::collections::HashSet<String> =
                known.iter().map(|id| netw::tap_name(id)).collect();
            for t in taps {
                if !owned.contains(&t) {
                    let _ = self.inner.net.delete_link(&t).await;
                    tracing::warn!(tap = t, "tap with no record, removed");
                    swept += 1;
                }
            }
        }
        if let Ok(vols) = self.inner.zfs.volumes_under("m").await {
            let mut ids: Vec<String> = vols
                .iter()
                .filter_map(|v| v.strip_prefix("m/"))
                .filter_map(|v| v.split('/').next())
                .map(String::from)
                .collect();
            ids.sort();
            ids.dedup();
            for id in ids {
                if !known.contains(&id) {
                    match self.inner.zfs.destroy(&format!("m/{id}")).await {
                        Ok(()) => {
                            tracing::warn!(machine = id, "disks with no record, destroyed");
                            swept += 1;
                        }
                        Err(err) => {
                            tracing::warn!(machine = id, err = %err, "disks with no record")
                        }
                    }
                }
            }
        }
        // A restore cut short goes on; a snapshot or a retired disk nothing needs goes: a
        // fork's that outlived the fork, one taken when the daemon died before its record.
        swept += self.tidy_at_start().await;
        if swept > 0 {
            tracing::info!(swept, "orphans swept at start");
        }
        swept
    }

    /// Takes over a VMM a previous daemon left running (it crashed; a shutdown suspends
    /// them instead), when the VMM still answers for the machine.
    async fn adopt(&self, e: &Arc<Entry>, pid: u32) -> bool {
        let rec = e.snapshot();
        let dir = self.inner.cfg.run_dir().join(&rec.id);
        let jail = self.jail_for(&rec);
        let Some(vm) = self
            .inner
            .vmm
            .adopt(&rec.id, &dir, jail.as_ref(), pid, e.disk_io.clone())
            .await
        else {
            return false;
        };
        *e.live.lock().unwrap() = Some(vm.clone());
        *e.stop_req.lock().unwrap() = None;
        self.watch(e, &vm);
        // Its probes run again from the top; nobody waits on this run, so a startup that
        // fails is a crash for the restart policy, not a failed boot.
        let (_, _, generation) = self.reset_probes(e);
        self.spawn_probes(e, &vm, generation, false);
        e.note(
            Ev::normal(
                reason::ADOPTED,
                format!("pid {pid}, left running by a previous daemon, taken over"),
            )
            .data(json!({"pid": pid})),
        );
        let _ = self.save(e);
        tracing::info!(
            machine = rec.id,
            pid,
            "adopted a machine left running by a previous daemon"
        );
        true
    }

    /// Settles the machine's state once its process is gone.
    fn watch(&self, e: &Arc<Entry>, vm: &fc::Vm) {
        let (m, e, pid, mut exited) = (self.clone(), e.clone(), vm.pid, vm.exited.clone());
        tokio::spawn(async move {
            let _ = exited.wait_for(|gone| *gone).await;
            m.settle_exit(&e, pid).await;
        });
    }

    /// Writes the record: something about the machine changed.
    fn save(&self, e: &Entry) -> Result<()> {
        let rec = {
            let mut r = e.rec.lock().unwrap();
            r.updated_at = Utc::now();
            e.unsaved_use.store(false, Relaxed);
            r.clone()
        };
        self.inner.store.put("machines", &rec.id, &rec)
    }

    /// Writes a record whose last use moved since it was last written, as it is: nothing
    /// about the machine changed, so `updated_at` stays. Under the machine's lock, and only
    /// while the manager still holds the machine: a destroy removes it under that lock, so a
    /// late write never brings a destroyed record back. A machine in a transition is skipped;
    /// the transition writes the record itself.
    fn flush_use(&self, e: &Arc<Entry>) -> Result<()> {
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
        let rec = {
            let r = e.rec.lock().unwrap();
            if !e.unsaved_use.swap(false, Relaxed) {
                return Ok(());
            }
            r.clone()
        };
        self.inner.store.put("machines", &rec.id, &rec)
    }

    /// Whether the manager still holds this entry: a destroy removes it under its lock.
    fn holds(&self, e: &Arc<Entry>) -> bool {
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
    /// Takes each machine's lock first, once a stop under way has settled, the tenants'
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
        for e in entries.iter().filter(|e| e.unsaved_use.load(Relaxed)) {
            if let Err(err) = self.write_use(e) {
                tracing::warn!(machine = e.snapshot().id, err = %err, "last use not written");
            }
        }
        self.write_usage().await;
        held
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
    async fn write_usage(&self) {
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

    /// Starts again the machines the host stopped (the last shutdown suspended them, or a
    /// previous daemon could not hand them over) whose sleep window has not run out: what ran
    /// before the daemon went down runs once it is back, used or not (ADR 0027). Detached,
    /// through the boot gate; a gateway is started by what needs it.
    fn start_stopped_by_host(&self) {
        let now = Utc::now();
        let left: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                stopped_by_host(&r) && !idle_past(r.last_used_at, r.sleep_window(), now)
            })
            .cloned()
            .collect();
        for e in left {
            let m = self.clone();
            tokio::spawn(async move {
                let _turns = e.lock_for_start().await;
                // A call may have moved it meanwhile (a wake, a stop, a destroy).
                if !stopped_by_host(&e.snapshot()) {
                    return;
                }
                if let Err(err) = m.start_entry(&e, false).await {
                    tracing::warn!(machine = e.snapshot().id, err = %err, "start again after the daemon's start");
                }
            });
        }
    }

    // --- tenants ---

    async fn plumb_tenant(&self, t: &Tenant) -> Result<()> {
        self.inner.net.ensure_bridge(&t.subnet).await?;
        self.inner.dns.listen(t.subnet.gateway()).await?;
        Ok(())
    }

    async fn ensure_tenant(&self, id: &str) -> Result<Tenant> {
        if let Some(t) = self.inner.tenants.lock().unwrap().get(id) {
            return Ok(t.clone());
        }
        // One tenant is made at a time: two made together would read the same free subnet
        // index before either had taken it, and share a bridge.
        let _creating = self.inner.tenant_create.lock().await;
        if let Some(t) = self.inner.tenants.lock().unwrap().get(id) {
            return Ok(t.clone());
        }
        let t = {
            let tenants = self.inner.tenants.lock().unwrap();
            let used: Vec<u32> = tenants.values().map(|t| t.rec.subnet_index).collect();
            let idx = netw::first_free(used, 0, self.inner.range.count() - 1)
                .ok_or_else(|| anyhow!("no tenant subnet left"))?;
            Tenant::new(
                TenantRec {
                    id: id.to_string(),
                    subnet_index: idx,
                    created_at: Utc::now(),
                    quota: api::Quota::default(),
                },
                self.inner.range.subnet(idx)?,
            )
        };
        self.plumb_tenant(&t).await?;
        self.inner.store.put("tenants", id, &t.rec)?;
        self.inner
            .tenants
            .lock()
            .unwrap()
            .insert(id.to_string(), t.clone());
        Ok(t)
    }

    /// Installs the host's nftables tables, once at start.
    async fn apply_rules(&self) -> Result<()> {
        self.rules()?.apply().await
    }

    /// The tables as the daemon starts. A running record may be adopted with its TAP, so it
    /// is pinned here with its egress policy, which `policies` and the resolver then hold;
    /// everything else pins and sets its policy as it goes. A `via` machine whose gateway
    /// machine is gone (destroyed while it ran, then the daemon crashed) gets no pin: nothing
    /// it sends leaves its TAP. Every machine's internet traffic is counted, from zero.
    fn rules(&self) -> Result<Ruleset> {
        let cfg = &self.inner.cfg;
        let all: Vec<Record> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .map(|e| e.snapshot())
            .collect();
        let mut counted: Vec<String> = all.iter().map(|r| r.ip.clone()).collect();
        counted.sort();
        let running = all.into_iter().filter(|r| r.state == state::RUNNING);
        let mut pins = Vec::new();
        for r in running {
            let Ok(policy) = self.policy_for(&r) else {
                continue;
            };
            pins.push((netw::tap_name(&r.id), r.ip.clone()));
            if let Some((gateway, p)) = policy {
                self.hold_policy(&r.id, gateway, p);
            }
        }
        pins.sort();
        let mut policies: Vec<nft::Policy> = self
            .inner
            .policies
            .lock()
            .unwrap()
            .values()
            .map(|(_, p)| p.clone())
            .collect();
        policies.sort_by(|a, b| a.ip().cmp(b.ip()));
        Ok(Ruleset {
            egress: self.inner.egress.clone(),
            range: self.inner.range.to_string(),
            allowed_clients: cfg
                .ingress
                .allowed_clients
                .iter()
                .map(|c| netw::cidr(c))
                .collect::<Result<_>>()?,
            ports: netw::nft::daemon_ports(&cfg.listen, &cfg.ingress.http, &cfg.ingress.tcp_ports)?,
            host_ports: cfg.network.host_ports.clone(),
            pins,
            policies,
            counted,
        })
    }

    // --- egress (ADR 0015) ---

    /// An egress policy a machine of `tenant` may take: one of the modes, and for `via` a
    /// machine of the same tenant other than `me`, or the tenant's gateway.
    fn check_egress(&self, e: &api::Egress, tenant: &str, me: &str) -> Result<(), MError> {
        e.check().map_err(invalid)?;
        if e.mode == api::egress::VIA {
            self.via_target(e, tenant, me)?;
        }
        Ok(())
    }

    /// The address of the machine a `via` policy names: fixed for that machine's life.
    fn via_target(&self, e: &api::Egress, tenant: &str, me: &str) -> Result<String, MError> {
        let id = if e.via_gateway() {
            self.gateway_of(tenant)
                .ok_or_else(|| no_gateway(tenant))?
                .snapshot()
                .id
        } else {
            e.via.clone().unwrap_or_default()
        };
        if id == me {
            return Err(invalid("egress.via names the machine itself"));
        }
        let target = self
            .inner
            .machines
            .lock()
            .unwrap()
            .get(&id)
            .map(|e| e.snapshot())
            .filter(|r| r.state != state::DESTROYING)
            .ok_or_else(|| invalid(format!("egress.via {id}: no such machine")))?;
        if target.tenant != tenant {
            return Err(invalid(format!(
                "egress.via {id}: a machine of another tenant"
            )));
        }
        Ok(target.ip)
    }

    /// The policy a record asks for, resolved against its tenant, with the tenant's gateway:
    /// `None` for open with nothing to limit. An open machine's limits are its own over the
    /// host's (ADR 0018); `via` and `none` never reach the NAT, so they carry none.
    fn policy_for(&self, r: &Record) -> Result<Option<(Ipv4Addr, nft::Policy)>, MError> {
        let limits = self.inner.cfg.egress_limits.with(&r.limits);
        if r.egress.mode == api::egress::OPEN && limits.is_none() {
            return Ok(None);
        }
        let t = self
            .tenant_of(&r.tenant)
            .ok_or_else(|| anyhow!("tenant network is gone"))?;
        let gateway = t.subnet.gateway();
        let ip = r.ip.clone();
        let p = match r.egress.mode.as_str() {
            api::egress::OPEN => nft::Policy::Open { ip, limits },
            api::egress::VIA => nft::Policy::Via {
                ip,
                to: self.via_target(&r.egress, &r.tenant, &r.id)?,
                host: gateway.to_string(),
            },
            _ => nft::Policy::None { ip },
        };
        Ok(Some((gateway, p)))
    }

    /// Tells the resolver to answer a machine internal names only, or no longer, when its
    /// policy says so.
    fn internal_dns(&self, gateway: Ipv4Addr, p: &nft::Policy, on: bool) {
        if !p.internal_only() {
            return;
        }
        if let Ok(ip) = p.ip().parse() {
            self.inner.dns.internal_only(gateway, ip, on);
        }
    }

    /// Puts a machine's policy in the tables and the resolver, in place of what they held
    /// for it; open with no limits leaves nothing. The resolver keeps the machine in from
    /// before the tables do until after they stop.
    async fn set_policy(&self, id: &str, policy: Option<(Ipv4Addr, nft::Policy)>) -> Result<()> {
        self.unset_policy(id).await?;
        let Some((gateway, p)) = policy else {
            return Ok(());
        };
        self.internal_dns(gateway, &p, true);
        if let Err(err) = self.inner.net.set_policy(&p).await {
            self.internal_dns(gateway, &p, false);
            return Err(err);
        }
        self.inner
            .policies
            .lock()
            .unwrap()
            .insert(id.into(), (gateway, p));
        Ok(())
    }

    /// Records a policy the tables hold already (rendered at start).
    fn hold_policy(&self, id: &str, gateway: Ipv4Addr, p: nft::Policy) {
        self.internal_dns(gateway, &p, true);
        self.inner
            .policies
            .lock()
            .unwrap()
            .insert(id.into(), (gateway, p));
    }

    /// Takes a machine's policy out of the tables, then out of the resolver. None held is
    /// success.
    async fn unset_policy(&self, id: &str) -> Result<()> {
        let held = self.inner.policies.lock().unwrap().get(id).cloned();
        let Some((gateway, p)) = held else {
            return Ok(());
        };
        self.inner.net.unset_policy(&p).await?;
        self.internal_dns(gateway, &p, false);
        self.inner.policies.lock().unwrap().remove(id);
        Ok(())
    }

    /// Changes a running machine's policy. From one policy to another is one transaction,
    /// so there is no moment with neither, and a refusal leaves the old one; the resolver
    /// takes the machine in before the tables change and lets it go after.
    async fn replace_policy(&self, id: &str, new: Option<(Ipv4Addr, nft::Policy)>) -> Result<()> {
        let held = self.inner.policies.lock().unwrap().get(id).cloned();
        match (held, new) {
            (Some((_, old)), Some((gateway, p))) => {
                if old != p {
                    let (taken, let_go) = (
                        p.internal_only() && !old.internal_only(),
                        old.internal_only() && !p.internal_only(),
                    );
                    if taken {
                        self.internal_dns(gateway, &p, true);
                    }
                    if let Err(err) = self.inner.net.swap_policy(&old, &p).await {
                        if taken {
                            self.internal_dns(gateway, &p, false);
                        }
                        return Err(err);
                    }
                    if let_go {
                        self.internal_dns(gateway, &old, false);
                    }
                }
                self.inner
                    .policies
                    .lock()
                    .unwrap()
                    .insert(id.into(), (gateway, p));
                Ok(())
            }
            (None, new) => self.set_policy(id, new).await,
            (Some(_), None) => self.unset_policy(id).await,
        }
    }

    /// Withdraws what a machine's TAP carries on the host: the TAP, its pin and its egress
    /// policy. A policy left behind is replaced by the next start, and gone with the tables
    /// the next daemon renders.
    async fn unplug(&self, id: &str, ip: &str) {
        let _ = self.inner.net.delete_tap(id, ip).await;
        if let Err(err) = self.unset_policy(id).await {
            tracing::warn!(machine = id, err = %err, "egress policy left in the tables");
        }
    }

    /// Republishes a tenant's names on its gateway.
    fn refresh_dns(&self, t: &Tenant) {
        let mut names: HashMap<String, Ipv4Addr> = HashMap::new();
        for e in self.inner.machines.lock().unwrap().values() {
            let r = e.rec.lock().unwrap();
            if r.tenant != t.rec.id {
                continue;
            }
            if let Ok(ip) = r.ip.parse::<Ipv4Addr>() {
                names.insert(r.hostname(), ip);
                names.insert(r.machine_host(), ip);
            }
        }
        self.inner.dns.set(t.subnet.gateway(), names);
    }

    fn tenant_of(&self, id: &str) -> Option<Tenant> {
        self.inner.tenants.lock().unwrap().get(id).cloned()
    }

    pub fn tenants(&self) -> Vec<api::Tenant> {
        let tenants: Vec<Tenant> = self
            .inner
            .tenants
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::Tenant> = tenants.iter().map(|t| self.tenant_view(t)).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn tenant(&self, id: &str) -> Result<api::Tenant, MError> {
        let t = self.tenant_of(id).ok_or(MError::NotFound)?;
        Ok(self.tenant_view(&t))
    }

    fn tenant_view(&self, t: &Tenant) -> api::Tenant {
        let machines = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.tenant == t.rec.id && r.is_tenants()
            })
            .count();
        let gateway = self.gateway_of(&t.rec.id).map(|e| {
            let r = e.snapshot();
            api::GatewayView {
                state: r.state,
                ip: r.ip,
                port: r.ports.first().copied().unwrap_or(0),
                machine_id: r.id,
                error: r.error,
            }
        });
        api::Tenant {
            id: t.rec.id.clone(),
            subnet: t.subnet.cidr(),
            router: t.subnet.gateway().to_string(),
            machines,
            created_at: t.rec.created_at,
            host: String::new(),
            region: String::new(),
            gateway,
        }
    }

    /// Removes the network of a tenant with no machine left, and its gateway first. Missing
    /// is success.
    pub async fn delete_tenant(&self, id: &str) -> Result<(), MError> {
        check_tenant_id(id)?;
        let t = match self.tenant_of(id) {
            Some(t) => t,
            None => return Ok(()),
        };
        let in_use = self.inner.machines.lock().unwrap().values().any(|e| {
            let r = e.rec.lock().unwrap();
            r.tenant == id && r.is_tenants()
        });
        if in_use {
            return Err(MError::TenantInUse);
        }
        {
            let _turn = t.lock.lock().await;
            if let Some(gw) = self.gateway_of(id) {
                self.destroy_machine(&gw.snapshot().id, None).await?;
            }
        }
        self.inner.dns.unset(t.subnet.gateway());
        self.inner.net.delete_bridge(t.rec.subnet_index).await?;
        self.inner.tenants.lock().unwrap().remove(id);
        self.inner.store.delete("tenants", id)?;
        Ok(())
    }

    // --- quotas (ADR 0025) ---

    /// The tenant's quota and what it holds.
    pub fn quota(&self, tenant: &str) -> Result<api::TenantQuota, MError> {
        let quota = self.tenant_of(tenant).ok_or(MError::NotFound)?.rec.quota;
        let used = tenant_use(&self.inner.machines.lock().unwrap(), tenant);
        Ok(api::TenantQuota {
            tenant: tenant.into(),
            quota,
            used,
        })
    }

    /// Puts the tenant's quota, the tenant made when it has nothing yet (as a gateway is), so
    /// its first create is held to it. A quota under the use stops nothing: what comes next
    /// is refused.
    pub async fn set_quota(
        &self,
        tenant: &str,
        quota: api::Quota,
    ) -> Result<api::TenantQuota, MError> {
        check_tenant_id(tenant)?;
        let mut t = self.ensure_tenant(tenant).await?;
        t.rec.quota = quota;
        self.inner.store.put("tenants", tenant, &t.rec)?;
        if let Some(kept) = self.inner.tenants.lock().unwrap().get_mut(tenant) {
            kept.rec.quota = quota;
        }
        self.quota(tenant)
    }

    // --- the tenant's gateway (ADR 0016) ---

    /// Puts the tenant's gateway: made, not started, when the tenant has none (the tenant
    /// too, when it has nothing yet); else given the new spec, a running one restarted. With
    /// `start`, it then runs as a start that needs it would run it.
    pub async fn set_gateway(
        &self,
        tenant: &str,
        spec: api::GatewaySpec,
    ) -> Result<api::Tenant, MError> {
        check_tenant_id(tenant)?;
        if spec.image.is_empty() || spec.port == 0 {
            return Err(invalid("a gateway needs an image and a port (1..65535)"));
        }
        spec.probes.check().map_err(invalid)?;
        // A machine of the daemon: no window of its own, it runs while something needs it,
        // and comes back whenever its program ends on its own.
        let req = api::CreateMachineRequest {
            tenant: tenant.into(),
            name: GATEWAY_NAME.into(),
            size: spec.size(),
            image: spec.image,
            cmd: spec.cmd,
            env: spec.env,
            volume: spec.volume_gb.map(|size_gb| api::VolumeSpec {
                size_gb,
                mount: "/data".into(),
            }),
            ports: vec![spec.port],
            probes: Some(spec.probes),
            sleep: "never".into(),
            restart: Some(api::RestartPolicy {
                policy: "always".into(),
                max_retries: 0,
            }),
            start: Some(false),
            ..Default::default()
        };
        check_size(&req.size)?;
        // Pulled before the tenant's lock: a pull may take minutes.
        let im = self.inner.images.ensure(&req.image).await?;
        let t = self.ensure_tenant(tenant).await?;
        let _turn = t.lock.lock().await;
        match self.gateway_of(tenant) {
            None => {
                self.create_as(req, Some(Role::Gateway)).await?;
            }
            Some(gw) => self.replace_gateway(&gw, req, im).await?,
        }
        if spec.start {
            let gw = self.gateway_of(tenant).ok_or_else(|| no_gateway(tenant))?;
            self.run_gateway(&gw).await?;
        }
        self.tenant(tenant)
    }

    /// A new spec on the same machine, address and volume: stopped if it runs, started again
    /// (a new image's root disk is made by the next start, ADR 0024). The spec it has already
    /// changes nothing, so a control plane may put it again. Under the tenant's lock.
    async fn replace_gateway(
        &self,
        gw: &Arc<Entry>,
        req: api::CreateMachineRequest,
        im: image::Image,
    ) -> Result<(), MError> {
        let was = gw.snapshot();
        let size_gb = |v: &Option<api::VolumeSpec>| v.as_ref().map(|v| v.size_gb);
        if size_gb(&req.volume) != size_gb(&was.volume) {
            return Err(invalid(
                "volume_gb is fixed for the gateway's life: DELETE the gateway to change it",
            ));
        }
        let probes = req.probes.clone().unwrap_or_default();
        if im.key == was.image_key
            && req.cmd == was.cmd
            && req.env == was.env
            && req.size == was.size
            && req.ports == was.ports
            && probes == was.probes
        {
            return Ok(());
        }
        let running = was.state == state::RUNNING;
        if running {
            self.stop_entry(gw, stop::HOST, Duration::from_secs(10), false, None)
                .await?;
        }
        {
            let _turn = gw.lock.lock().await;
            let r = gw.snapshot();
            if !matches!(
                r.state.as_str(),
                state::CREATED | state::STOPPED | state::ERROR
            ) {
                return Err(MError::BadState(r.state));
            }
            {
                let mut r = gw.rec.lock().unwrap();
                let fields: Vec<&str> = [
                    ("image", im.key != r.image_key),
                    ("cmd", req.cmd != r.cmd),
                    ("env", req.env != r.env),
                    ("size", req.size != r.size),
                    ("ports", req.ports != r.ports),
                    ("probes", probes != r.probes),
                ]
                .into_iter()
                .filter_map(|(f, changed)| changed.then_some(f))
                .collect();
                r.image = req.image;
                r.image_key = im.key;
                r.image_digest = im.digest;
                r.image_config = im.config;
                r.cmd = req.cmd;
                r.env = req.env;
                r.size = req.size;
                r.ports = req.ports;
                r.probes = probes;
                // A memory snapshot is of the old program on the old disk: boot cold.
                r.suspended = false;
                let ev = Ev::normal(
                    reason::UPDATED,
                    format!("the gateway's {} replaced", fields.join(", ")),
                );
                gw.note_locked(&mut r, ev.data(json!({ "fields": fields })));
            }
            self.save(gw)?;
        }
        if running {
            self.run_gateway(gw).await?;
        }
        Ok(())
    }

    /// Stops and destroys the tenant's gateway; refused while a machine runs through it.
    /// None is success.
    pub async fn delete_gateway(&self, tenant: &str) -> Result<(), MError> {
        check_tenant_id(tenant)?;
        let Some(t) = self.tenant_of(tenant) else {
            return Ok(());
        };
        let _turn = t.lock.lock().await;
        let Some(gw) = self.gateway_of(tenant) else {
            return Ok(());
        };
        if gateway_needed(&self.inner.machines.lock().unwrap(), tenant) {
            return Err(MError::GatewayInUse);
        }
        self.destroy_machine(&gw.snapshot().id, None).await
    }

    /// The tenant's gateway machine, unless it is being destroyed.
    fn gateway_of(&self, tenant: &str) -> Option<Arc<Entry>> {
        self.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .find(|e| {
                let r = e.rec.lock().unwrap();
                r.tenant == tenant && r.is_gateway() && r.state != state::DESTROYING
            })
            .cloned()
    }

    /// Makes sure the tenant's gateway runs and its port answers, and returns the tenant's
    /// lock held: two starts that need the gateway boot it once.
    async fn ensure_gateway(
        &self,
        tenant: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, MError> {
        let t = self
            .tenant_of(tenant)
            .ok_or_else(|| anyhow!("tenant network is gone"))?;
        let turn = t.lock.clone().lock_owned().await;
        let gw = self.gateway_of(tenant).ok_or_else(|| no_gateway(tenant))?;
        self.run_gateway(&gw).await?;
        Ok(turn)
    }

    /// Starts the gateway unless it runs, then waits for it to serve within the boot timeout:
    /// its `ready` when it has a startup or readiness probe (ADR 0022), else its port. A
    /// gateway that does not serve in time is ended and left in `error` with its console's
    /// last lines, as a boot that fails is. Under the tenant's lock; the gateway's own lock is
    /// let go while it is waited for, since its probes take it to end a failed boot.
    async fn run_gateway(&self, gw: &Arc<Entry>) -> Result<(), MError> {
        let (started, live) = {
            let _turns = gw.lock_for_start().await;
            let started = gw.snapshot().state != state::RUNNING;
            if started {
                self.start_boxed(gw, true).await?;
            }
            (started, gw.live.lock().unwrap().clone())
        };
        let Some(live) = live else {
            return Err(MError::NotRunning("the gateway has no process".into()));
        };
        let r = gw.snapshot();
        let port = r.ports.first().copied().unwrap_or(0);
        let ip: Ipv4Addr = r.ip.parse().map_err(anyhow::Error::from)?;
        let timeout = Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10));
        let mut exited = live.exited.clone();
        let answered = match probes::ready_at_boot(&r.probes) {
            true => tokio::select! {
                r = self.inner.net.wait_port(ip, port, timeout) => {
                    r.map_err(|err| format!("port {port} did not answer: {err:#}"))
                }
                _ = exited.wait_for(|gone| *gone) => Err("the gateway exited".to_string()),
            },
            false => match self.wait(&r.id, Until::Ready, timeout).await {
                Ok(_) => Ok(()),
                // Its startup probe failed it already: the machine says why.
                Err(MError::BootFailed(m)) => return Err(MError::BootFailed(m)),
                Err(err) => Err(format!("not ready: {err}")),
            },
        };
        let _turn = gw.lock.lock().await;
        let Err(why) = answered else {
            if started {
                gw.note(
                    Ev::normal(
                        reason::GATEWAY_STARTED,
                        format!("the tenant's gateway answers on {ip}:{port}"),
                    )
                    .data(json!({ "port": port })),
                );
                let _ = self.save(gw);
            }
            return Ok(());
        };
        if gw.live.lock().unwrap().as_ref().map(|l| l.pid) == Some(live.pid) {
            self.end_process(gw, &live, Duration::ZERO).await;
        }
        let tail = self.last_console_lines(&r, 5);
        Err(self.boot_failed(gw, format!("{why}: {tail}")))
    }

    /// What a machine that needs the gateway answers when the gateway did not come up:
    /// `boot_failed` with the machine as it is (not moved), the gateway's reason in `error`.
    fn gateway_failed(&self, e: &Entry, err: MError) -> MError {
        match err {
            MError::BootFailed(gw) => {
                let mut m = self.view(e);
                m.error = format!("the tenant's gateway did not come up: {}", gw.error);
                MError::BootFailed(Box::new(m))
            }
            other => other,
        }
    }

    /// The gateways whose state is not what their tenant needs: running while no machine
    /// needs them (`running`), or not running while one does (not `running`).
    fn gateways_out_of_step(&self, running: bool) -> Vec<Arc<Entry>> {
        let machines = self.inner.machines.lock().unwrap();
        machines
            .values()
            .filter(|e| {
                let tenant = {
                    let r = e.rec.lock().unwrap();
                    if !r.is_gateway() || (r.state == state::RUNNING) != running {
                        return false;
                    }
                    r.tenant.clone()
                };
                gateway_needed(&machines, &tenant) != running
            })
            .cloned()
            .collect()
    }

    /// Stops a gateway nothing needs, under its tenant's lock. A lock someone holds is a start
    /// or a change of the gateway under way: the next tick looks again.
    async fn sleep_gateway(&self, gw: &Arc<Entry>) {
        let r = gw.snapshot();
        let Some(t) = self.tenant_of(&r.tenant) else {
            return;
        };
        let Ok(_turn) = t.lock.try_lock() else {
            return;
        };
        if gateway_needed(&self.inner.machines.lock().unwrap(), &r.tenant) {
            return;
        }
        tracing::info!(
            machine = r.id,
            tenant = r.tenant,
            "gateway unused, going to sleep"
        );
        let suspend = self.inner.cfg.suspend_on_sleep;
        if let Err(err) = self
            .stop_entry(gw, stop::IDLE, Duration::from_secs(10), suspend, None)
            .await
        {
            tracing::warn!(machine = r.id, err = %err, "gateway sleep");
            return;
        }
        let _turn = gw.lock.lock().await;
        if self.holds(gw) && gw.snapshot().state == state::STOPPED {
            gw.note(Ev::normal(
                reason::GATEWAY_STOPPED,
                "nothing sends through the tenant's gateway: stopped",
            ));
            let _ = self.save(gw);
        }
    }

    // --- lookup and views ---

    fn entry(&self, id: &str) -> Result<Arc<Entry>, MError> {
        self.inner
            .machines
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(MError::NotFound)
    }

    /// The machine a call that changes or runs something in it acts on: every such call of
    /// the API resolves its machine here. A tenant's gateway is read through the machine
    /// routes (get, logs, stats) and changed only through its tenant's.
    fn own_entry(&self, id: &str) -> Result<Arc<Entry>, MError> {
        let e = self.entry(id)?;
        let r = e.rec.lock().unwrap();
        if r.is_gateway() {
            return Err(MError::Gateway(r.tenant.clone()));
        }
        drop(r);
        Ok(e)
    }

    fn view(&self, e: &Entry) -> api::Machine {
        let r = e.snapshot();
        let running = r.state == state::RUNNING;
        let sleeps_at = if running && e.in_flight.load(Relaxed) == 0 {
            sleeps_at(r.last_used_at, r.sleep_window())
        } else {
            None
        };
        let (ready, probes_status) = {
            let run = e.probe.lock().unwrap();
            (running && run.ready, run.status.clone())
        };
        let waiting_restart = r.state == state::STOPPED && r.stopped_reason == stop::EXIT;
        api::Machine {
            id: r.id.clone(),
            tenant: r.tenant.clone(),
            name: r.name.clone(),
            image: r.image.clone(),
            image_digest: r.image_digest.clone(),
            state: r.state.clone(),
            stopped_reason: r.stopped_reason.clone(),
            exit: r.exit.clone(),
            error: r.error.clone(),
            ip: r.ip.clone(),
            hostname: r.hostname(),
            machine_host: r.machine_host(),
            size: r.size,
            volume: r.volume.clone(),
            ports: r.ports.clone(),
            sleep: r.sleep.clone(),
            restart: r.restart.clone(),
            restarts: r.restarts,
            restarting_at: r.restarting_at.filter(|_| waiting_restart),
            ready,
            probes: r.probes.clone(),
            probes_status,
            egress: r.egress.clone(),
            limits: self.inner.cfg.egress_limits.with(&r.limits).view(),
            egress_drops: e.meter.lock().unwrap().drops(),
            disk_limits: self.disk_rate(&r).view(),
            metadata: r.metadata.clone(),
            endpoints: self.endpoints_of(&r.id),
            created_at: r.created_at,
            updated_at: r.updated_at,
            state_changed_at: r.state_changed_at,
            started_at: r.started_at,
            stopped_at: r.stopped_at,
            last_used_at: r.last_used_at,
            sleeps_at,
            suspended: r.suspended,
            backup: r.backup.policy.clone(),
            last_backup_at: r.backup.last_at,
            next_backup_at: r.backup.next_at,
            version: r.version,
            pending: r.pending.as_ref().map(|p| p.view()),
            pending_since: r.pending_since,
            init_version: r.init_version.clone(),
            vmm_version: r.vmm_version.clone(),
            host: String::new(),
        }
    }

    pub fn get(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        Ok(self.view(&e))
    }

    /// The tenant's machines, or every tenant's, those whose labels (`metadata`) match every
    /// selector (ADR 0025).
    pub fn list(&self, tenant: Option<&str>, labels: &[api::Label]) -> Vec<api::Machine> {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::Machine> = entries
            .iter()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.is_tenants()
                    && tenant.map(|t| r.tenant == t).unwrap_or(true)
                    && labels.iter().all(|l| l.matches(&r.metadata))
            })
            .map(|e| self.view(e))
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    /// What running machines take (gateways included), how many run, and how many machines
    /// tenants have (gateways not counted).
    pub fn usage(&self) -> (api::Capacity, usize, usize) {
        let machines = self.inner.machines.lock().unwrap();
        let (used, running) = committed(&machines);
        let total = machines
            .values()
            .filter(|e| e.rec.lock().unwrap().is_tenants())
            .count();
        (used, running, total)
    }

    /// Takes the machine's memory from the host and moves it to `starting`, as one step
    /// under the map's lock: two starts that read the same free memory cannot both take it,
    /// nor pass their tenant's quota together (ADR 0025). A pending change goes onto the record
    /// in that step (ADR 0024), its size the one reserved and counted, with `image` its new
    /// image, resolved. Its events are logged once that lock is let go: the log syncs to disk,
    /// and the map is every request's. Nothing else moves the machine meanwhile: its own lock
    /// is held.
    fn reserve(&self, e: &Entry, image: Option<image::Image>) -> Result<(), MError> {
        let tenant = e.rec.lock().unwrap().tenant.clone();
        let quota = self
            .tenant_of(&tenant)
            .map(|t| t.rec.quota)
            .unwrap_or_default();
        let mut applied = None;
        // A memory snapshot taken under another Firecracker or host kernel is not loaded
        // (ADR 0027): this start is cold.
        let vmm = self.inner.vmm.version();
        let mut dropped = None;
        let over = {
            let machines = self.inner.machines.lock().unwrap();
            let size = {
                let r = e.rec.lock().unwrap();
                r.pending.as_ref().and_then(|p| p.size).unwrap_or(r.size)
            };
            let need = api::QuotaUse {
                memory_mb: size.memory_mb,
                vcpus: size.vcpus,
                ..Default::default()
            };
            match over_quota(&tenant, &quota, &tenant_use(&machines, &tenant), &need) {
                Some(x) => Some(x),
                None => {
                    let (used, _) = committed(&machines);
                    admit(used.memory_mb, self.capacity().memory_mb, size.memory_mb)?;
                    e.set_state(state::STARTING, |r| {
                        r.error.clear();
                        r.pid = 0;
                        r.restarting_at = None;
                        applied = apply_pending(r, image);
                        if r.suspended && r.vmm_version != vmm {
                            r.suspended = false;
                            dropped = Some(r.vmm_version.clone());
                        }
                        None
                    });
                    None
                }
            }
        };
        if let Some(x) = over {
            e.note(x.event(format!("start refused: {x}")));
            let _ = self.save(e);
            return Err(MError::Quota(x.to_string()));
        }
        if let Some(fields) = applied {
            e.note(
                Ev::normal(reason::APPLIED, format!("{} applied", fields.join(", ")))
                    .data(json!({ "fields": fields })),
            );
        }
        let resume = e.snapshot().suspended;
        let ev = match (resume, dropped) {
            (true, _) => Ev::normal(reason::STARTING, "resuming from its memory snapshot")
                .data(json!({ "resume": true })),
            (false, None) => {
                Ev::normal(reason::STARTING, "booting").data(json!({ "resume": false }))
            }
            (false, Some(was)) => Ev::normal(
                reason::STARTING,
                format!("booting: its memory snapshot was taken under {was}, the host runs {vmm}"),
            )
            .data(json!({ "resume": false, "snapshot_vmm": was })),
        };
        e.note(ev);
        Ok(())
    }

    /// The images on the host.
    pub async fn images(&self) -> Result<Vec<api::Image>, MError> {
        Ok(self
            .inner
            .images
            .list()
            .await?
            .into_iter()
            .map(|(im, machines)| api::Image {
                key: im.key,
                reference: im.r#ref,
                digest: im.digest,
                size_gb: im.size_gb,
                built_at: im.built_at,
                machines,
            })
            .collect())
    }

    /// Removes an image no machine clones.
    pub async fn delete_image(&self, key: &str) -> Result<(), MError> {
        if !key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(MError::NotFound);
        }
        match self.inner.images.remove(key, Removal::Request).await? {
            true => Ok(()),
            false => Err(MError::Conflict("machines still use this image".into())),
        }
    }

    /// Removes images unused for `keep`; runs hourly from the daemon.
    pub async fn gc_images(&self, keep: chrono::Duration) -> usize {
        self.inner.images.gc(keep).await.unwrap_or_else(|e| {
            tracing::warn!(err = %e, "image gc");
            0
        })
    }

    /// What the machine uses now: CPU and memory from its cgroup when jailed, disk from ZFS.
    pub async fn stats(&self, id: &str) -> Result<api::MachineStats, MError> {
        let e = self.entry(id)?;
        let r = e.snapshot();
        let mut st = api::MachineStats {
            state: r.state.clone(),
            ..Default::default()
        };
        if r.state == state::RUNNING {
            if let Some(t) = r.started_at {
                st.uptime_sec = (Utc::now() - t).num_seconds().max(0) as u64;
            }
            if let Some(cg) = self.inner.vmm.cgroup(&r.id).await {
                st.cpu_usec = cg.cpu_usec;
                st.memory_bytes = cg.memory_bytes;
            }
        }
        st.disk_bytes = self.inner.zfs.used(&r.dataset()).await.unwrap_or(0);
        Ok(st)
    }

    /// `/metrics` (ADR 0021): the host's figures and each machine's from the tick's last
    /// measure. Nothing is probed here: a scrape costs the same however often it comes.
    pub fn metrics(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        let mut entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.snapshot().id);
        let mut host = metrics::Host::default();
        let machines: Vec<metrics::Machine> = entries
            .iter()
            .map(|e| {
                let r = e.rec.lock().unwrap();
                let m = e.meter.lock().unwrap();
                *host.by_state.entry(r.state.clone()).or_default() += 1;
                host.suspended += r.suspended as usize;
                metrics::Machine {
                    id: r.id.clone(),
                    tenant: r.tenant.clone(),
                    name: r.name.clone(),
                    role: role_name(r.role),
                    state: r.state.clone(),
                    counted: m.counted(),
                    memory_bytes: m.memory_bytes,
                    memory_limit_bytes: (r.size.memory_mb as u64) << 20,
                    disk_used_bytes: m.disks.used + m.disks.snapshots,
                    restarts: m.restarts,
                    boot_seconds: m.boot_seconds,
                    disk_read_bytes: e.disk_io.read_bytes.load(Relaxed),
                    disk_write_bytes: e.disk_io.write_bytes.load(Relaxed),
                    disk_throttled: e.disk_io.throttled.load(Relaxed),
                }
            })
            .collect();
        let (used, _, _) = self.usage();
        let cap = self.capacity();
        let st = &self.inner.stats;
        host.tenants = self.inner.tenants.lock().unwrap().len();
        host.endpoints = self.inner.endpoints.lock().unwrap().len();
        host.memory_mb = (used.memory_mb, cap.memory_mb);
        host.vcpus = (used.vcpus, cap.vcpus);
        host.pool = *self.inner.pool.lock().unwrap();
        host.conditions = self.conditions();
        host.events = self.inner.events.emitted();
        host.counters = vec![
            (
                "briqyard_boots_total",
                "Cold boots since the daemon started.",
                st.boots.load(Relaxed),
            ),
            (
                "briqyard_resumes_total",
                "Resumes from a memory snapshot.",
                st.resumes.load(Relaxed),
            ),
            (
                "briqyard_suspends_total",
                "Stops with a memory snapshot.",
                st.suspends.load(Relaxed),
            ),
            (
                "briqyard_execs_total",
                "Commands run in machines.",
                st.execs.load(Relaxed),
            ),
            (
                "briqyard_starts_failed_total",
                "Starts that failed.",
                st.starts_failed.load(Relaxed),
            ),
            (
                "briqyard_backups_total",
                "Backups sent to the store.",
                st.backups.load(Relaxed),
            ),
        ];
        metrics::render(&host, &machines)
    }

    /// The host's conditions as the tick last decided them.
    pub fn conditions(&self) -> Vec<api::Condition> {
        self.inner.conditions.lock().unwrap().list()
    }

    /// This daemon's start (ADR 0027).
    pub fn started(&self) -> api::DaemonStart {
        *self.inner.started.lock().unwrap()
    }

    /// What a machine booted now runs under (ADR 0027).
    pub fn vmm_version(&self) -> String {
        self.inner.vmm.version()
    }

    /// The running machines' use over the tick's last window (ADR 0021), of one tenant or
    /// all, gateways included, by tenant then name.
    pub fn top(&self, tenant: Option<&str>) -> Vec<api::TopMachine> {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::TopMachine> = entries
            .iter()
            .filter_map(|e| {
                let r = e.rec.lock().unwrap();
                if r.state != state::RUNNING || tenant.is_some_and(|t| r.tenant != t) {
                    return None;
                }
                let m = e.meter.lock().unwrap();
                let rates = m.rates();
                Some(api::TopMachine {
                    machine_id: r.id.clone(),
                    tenant: r.tenant.clone(),
                    name: r.name.clone(),
                    role: role_name(r.role),
                    cpu_percent: rates.cpu_percent,
                    memory_bytes: m.memory_bytes,
                    memory_limit_bytes: (r.size.memory_mb as u64) << 20,
                    disk_used_bytes: m.disks.used + m.disks.snapshots,
                    internet_in_bytes_per_sec: rates.internet_in,
                    internet_out_bytes_per_sec: rates.internet_out,
                    ingress_in_bytes_per_sec: rates.ingress_in,
                    ingress_out_bytes_per_sec: rates.ingress_out,
                    window_sec: rates.window_sec,
                    host: String::new(),
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.tenant, &a.name).cmp(&(&b.tenant, &b.name)));
        out
    }

    /// Free space in the pool, in MB.
    pub async fn disk_free_mb(&self) -> u64 {
        self.inner.zfs.free().await.unwrap_or(0) >> 20
    }

    pub fn capacity(&self) -> api::Capacity {
        let c = self.inner.cfg.capacity;
        api::Capacity {
            memory_mb: if c.memory_mb > 0 {
                c.memory_mb
            } else {
                default_memory_mb(host_memory_mb(), c.reserved_memory_mb, arc_max_mb())
            },
            vcpus: if c.vcpus > 0 {
                c.vcpus
            } else {
                let threads = std::thread::available_parallelism().map_or(2, |n| n.get());
                default_vcpus(threads as u32, c.reserved_threads)
            },
        }
    }

    // --- create ---

    pub async fn create(&self, req: api::CreateMachineRequest) -> Result<api::Machine, MError> {
        self.create_as(req, None).await
    }

    /// A create, of one of the tenant's machines or of a machine with a role.
    async fn create_as(
        &self,
        req: api::CreateMachineRequest,
        role: Option<Role>,
    ) -> Result<api::Machine, MError> {
        check_tenant_id(&req.tenant)?;
        if let Some(rs) = &req.restore {
            if !api::valid_id(&rs.machine_id) {
                return Err(invalid("restore.machine_id is not a machine id"));
            }
        }
        if !api::valid_name(&req.name) {
            return Err(invalid("name must be a DNS label (a-z, 0-9, -)"));
        }
        if req.image.is_empty() && req.fork.is_none() && req.restore.is_none() {
            return Err(invalid("image is required"));
        }
        if req.fork.is_some() && req.restore.is_some() {
            return Err(invalid("fork and restore are one or the other"));
        }
        // A restore with no size takes the backup's; everything else says its size.
        let size_from_backup = req.restore.is_some() && req.size == api::Size::default();
        // What it runs, checked as a PATCH of it is (ADR 0024).
        let mut spec = req.spec();
        if size_from_backup {
            spec.size = None;
        }
        spec.check().map_err(invalid)?;
        if let Some(v) = &req.volume {
            if v.size_gb < 1 || !v.mount.starts_with('/') {
                return Err(invalid("volume needs size_gb >= 1 and an absolute mount"));
            }
        }
        api::parse_sleep(&req.sleep).map_err(invalid)?;
        check_limits(req.limits.as_ref())?;
        check_disk_limits(req.disk_limits.as_ref())?;
        if let Some(p) = &req.probes {
            p.check().map_err(invalid)?;
        }
        let restart = req.restart.clone().unwrap_or_default();
        if self.name_taken(&req.tenant, &req.name) {
            return Err(MError::Conflict(
                "a machine with that name exists in the tenant".into(),
            ));
        }
        let now = Utc::now();
        let mut rec = Record {
            id: new_id("m"),
            tenant: req.tenant.clone(),
            role,
            name: req.name.clone(),
            image: String::new(),
            image_key: String::new(),
            image_digest: String::new(),
            image_config: ImageConfig::default(),
            root_key: String::new(),
            entrypoint: req.entrypoint.clone(),
            cmd: req.cmd.clone(),
            env: req.env.clone(),
            files: req.files.clone(),
            size: req.size,
            volume: req.volume.clone(),
            ports: req.ports.clone(),
            sleep: sleep_setting(&req.sleep),
            restart,
            probes: req.probes.clone().unwrap_or_default(),
            egress: req.egress.clone().unwrap_or_default(),
            limits: req.limits.clone().unwrap_or_default(),
            disk_limits: req.disk_limits.clone().unwrap_or_default(),
            metadata: req.metadata.clone(),
            state: state::CREATED.into(),
            stopped_reason: String::new(),
            exit: None,
            error: String::new(),
            subnet_index: 0,
            host_num: 0,
            ip: String::new(),
            pid: 0,
            restarts: 0,
            recent_restarts: 0,
            restarting_at: None,
            boots: 0,
            created_at: now,
            updated_at: now,
            state_changed_at: now,
            started_at: None,
            stopped_at: None,
            last_used_at: None,
            console_offset: 0,
            suspended: false,
            backup_bytes: 0,
            backup: backups::schedule_of(&req.backup, &self.inner.cfg.backup, now)?,
            version: 0,
            pending: None,
            pending_since: None,
            init_version: String::new(),
            vmm_version: String::new(),
            rest: Default::default(),
            snapshots: Vec::new(),
            restoring: None,
        };
        self.check_egress(&rec.egress, &rec.tenant, &rec.id)?;
        let mut src: Option<Arc<Entry>> = None;
        let mut restore_from: Option<api::Backup> = None;
        if let Some(rs) = &req.restore {
            let b = self.find_backup(&rs.machine_id, &rs.backup).await?;
            let was: Record = serde_json::from_value(b.machine.clone().unwrap_or_default())
                .map_err(|e| invalid(format!("backup {}: machine record: {e}", b.id)))?;
            // The request says what it says; the backup fills the rest.
            rec.image = was.image;
            rec.image_key = was.image_key;
            rec.image_digest = was.image_digest;
            rec.image_config = was.image_config;
            // The root disk comes from the backup: made from what it was made from.
            rec.root_key = was.root_key;
            if rec.entrypoint.is_none() {
                rec.entrypoint = was.entrypoint;
            }
            if rec.cmd.is_none() {
                rec.cmd = was.cmd;
            }
            let mut env = was.env;
            env.extend(rec.env.clone());
            rec.env = env;
            if rec.files.is_empty() {
                rec.files = was.files;
            }
            if req.ports.is_empty() {
                rec.ports = was.ports;
            }
            if req.egress.is_none() {
                rec.egress = was.egress;
                self.check_egress(&rec.egress, &rec.tenant, &rec.id)?;
            }
            if req.limits.is_none() {
                rec.limits = was.limits;
            }
            if req.disk_limits.is_none() {
                rec.disk_limits = was.disk_limits;
            }
            if req.probes.is_none() {
                rec.probes = was.probes;
            }
            if rec.size == api::Size::default() {
                rec.size = was.size;
            }
            match (&rec.volume, &was.volume) {
                (None, Some(v)) => rec.volume = Some(v.clone()),
                (Some(a), Some(b)) if a.mount != b.mount => {
                    return Err(invalid("a restore keeps the backup's volume mount"))
                }
                (Some(_), None) => return Err(invalid("the backup has no volume to restore")),
                _ => {}
            }
            if b.disks.iter().any(|d| d.disk == "data") != rec.volume.is_some() {
                return Err(invalid("the backup's disks and the volume do not match"));
            }
            check_size(&rec.size)?;
            restore_from = Some(b);
        } else if let Some(fork) = &req.fork {
            let s = self.own_entry(&fork.machine_id).map_err(|e| match e {
                MError::NotFound => invalid("fork source not found"),
                other => other,
            })?;
            let sr = s.snapshot();
            if sr.tenant != req.tenant {
                return Err(invalid("fork source belongs to another tenant"));
            }
            if !req.image.is_empty() && req.image != sr.image {
                return Err(invalid("a fork keeps its source's image"));
            }
            rec.image = sr.image.clone();
            rec.image_key = sr.image_key.clone();
            rec.image_digest = sr.image_digest.clone();
            rec.image_config = sr.image_config.clone();
            match (&req.volume, &sr.volume) {
                (None, v) => rec.volume = v.clone(),
                (Some(a), Some(b)) if a.mount != b.mount => {
                    return Err(invalid("a fork keeps its source's volume mount"))
                }
                _ => {}
            }
            src = Some(s);
        } else {
            let im = self.inner.images.ensure(&req.image).await?;
            rec.image = req.image.clone();
            rec.image_key = im.key;
            rec.image_digest = im.digest;
            rec.image_config = im.config;
        }
        if rec.root_key.is_empty() {
            rec.root_key = rec.image_key.clone();
        }
        let t = self.ensure_tenant(&req.tenant).await?;
        let e = self.add_machine(rec, &t, req.start.unwrap_or(true))?;
        let _guard = e.lock.lock().await;
        let ip = e.snapshot().ip;
        let made = match self.inner.net.count(&ip).await.context("usage counters") {
            Err(err) => Err(err),
            Ok(()) => match &restore_from {
                Some(b) => self.receive_disks(&e, b).await,
                None => self.make_disks(&e, src.as_deref(), req.fork.as_ref()).await,
            },
        };
        if let Err(err) = made {
            let rec = e.snapshot();
            self.remove_machine(&e);
            let _ = self.inner.net.uncount(&ip).await;
            let _ = self.inner.zfs.destroy(&rec.dataset()).await;
            return Err(err.into());
        }
        e.note(match (&restore_from, &req.fork) {
            (Some(b), _) => Ev::normal(
                reason::RESTORED,
                format!("restored from backup {} of {}", b.id, b.machine_id),
            )
            .data(json!({ "from": b.machine_id, "backup": b.id })),
            (None, Some(f)) => Ev::normal(reason::FORKED, format!("forked from {}", f.machine_id))
                .data(json!({ "from": f.machine_id })),
            (None, None) => {
                let r = e.snapshot();
                Ev::normal(reason::CREATED, format!("created from {}", r.image))
                    .data(json!({ "image": r.image, "digest": r.image_digest }))
            }
        });
        self.save(&e)?;
        if req.start.unwrap_or(true) {
            // Created but did not start: the same answer a start would give; the machine
            // stays, for the caller to read and destroy.
            self.start_entry(&e, true).await?;
        }
        Ok(self.view(&e))
    }

    fn name_taken(&self, tenant: &str, name: &str) -> bool {
        self.inner.machines.lock().unwrap().values().any(|e| {
            let r = e.rec.lock().unwrap();
            r.tenant == tenant && r.name == name && r.state != state::DESTROYING
        })
    }

    /// Gives the machine an address and registers it, within its tenant's quota (ADR 0025):
    /// a machine and its volume, and its size when it is `starting` at once. Nothing on disk
    /// yet.
    fn add_machine(
        &self,
        mut rec: Record,
        t: &Tenant,
        starting: bool,
    ) -> Result<Arc<Entry>, MError> {
        let mut machines = self.inner.machines.lock().unwrap();
        let mut used = Vec::new();
        for e in machines.values() {
            let r = e.rec.lock().unwrap();
            if r.tenant == rec.tenant && r.name == rec.name && r.state != state::DESTROYING {
                return Err(MError::Conflict(
                    "a machine with that name exists in the tenant".into(),
                ));
            }
            if r.tenant == t.rec.id {
                used.push(r.host_num as u32);
            }
        }
        let held = tenant_use(&machines, &rec.tenant);
        if let Some(x) = over_quota(
            &rec.tenant,
            &t.rec.quota,
            &held,
            &quota_need(&rec, starting),
        ) {
            drop(machines);
            let ev = x.event(format!("create of {} refused: {x}", rec.name));
            self.inner.events.emit(ev.tenant(&rec.tenant));
            return Err(MError::Quota(x.to_string()));
        }
        // The address a `via` policy in the tables names stays its gateway's, even once that
        // machine is gone: given to a new machine, it would be reachable through the policy.
        for (_, p) in self.inner.policies.lock().unwrap().values() {
            if let nft::Policy::Via { to, .. } = p {
                if let Ok(to) = to.parse::<Ipv4Addr>() {
                    if to.octets()[..3] == t.subnet.network.octets()[..3] {
                        used.push(to.octets()[3] as u32);
                    }
                }
            }
        }
        let n = netw::first_free(used, 2, 254)
            .ok_or_else(|| MError::Capacity(format!("tenant {} has no address left", t.rec.id)))?;
        rec.subnet_index = t.rec.subnet_index;
        rec.host_num = n as u8;
        rec.ip = t.subnet.host(n as u8)?.to_string();
        let id = rec.id.clone();
        let e = Entry::new(rec, self.inner.events.clone());
        machines.insert(id, e.clone());
        drop(machines);
        self.refresh_dns(t);
        Ok(e)
    }

    fn remove_machine(&self, e: &Entry) {
        let rec = e.snapshot();
        self.inner.machines.lock().unwrap().remove(&rec.id);
        if let Some(t) = self.tenant_of(&rec.tenant) {
            self.refresh_dns(&t);
        }
    }

    /// Clones the root disk and makes the data volume; for a fork, both from snapshots of the
    /// source taken now.
    async fn make_disks(
        &self,
        e: &Entry,
        src: Option<&Entry>,
        fork: Option<&api::ForkSpec>,
    ) -> Result<()> {
        let r = e.snapshot();
        let z = &self.inner.zfs;
        let copy_disks = src.is_some()
            && fork
                .map(|f| f.copy.is_empty() || f.copy == "disk")
                .unwrap_or(false);
        if copy_disks {
            // Under the source's lock: a restore swaps its disks under that lock (ADR 0031),
            // and a tidy removes a fork snapshot nothing clones yet.
            let src = src.unwrap();
            let _src_lock = src.lock.lock().await;
            let s = src.snapshot();
            if s.state == state::DESTROYING {
                return Err(anyhow!("fork source {} is being destroyed", s.id));
            }
            if let Some(snap) = &s.restoring {
                return Err(anyhow!(
                    "fork source {}: a restore to {snap} is unfinished",
                    s.id
                ));
            }
            let snap = format!("fork-{}", r.id);
            z.snapshot(&s.root_dataset(), &snap).await?;
            z.clone_snapshot(&s.root_dataset(), &snap, &r.root_dataset())
                .await?;
            if r.volume.is_some() && z.exists(&s.data_dataset()).await? {
                z.snapshot(&s.data_dataset(), &snap).await?;
                z.clone_snapshot(&s.data_dataset(), &snap, &r.data_dataset())
                    .await?;
                return Ok(());
            }
        } else {
            z.clone_snapshot(
                &format!("images/{}", r.image_key),
                image::SNAP,
                &r.root_dataset(),
            )
            .await?;
        }
        if let Some(v) = &r.volume {
            let dev = z
                .create(&r.data_dataset(), (v.size_gb as u64) << 30)
                .await?;
            let out = tokio::process::Command::new("mkfs.ext4")
                .args([
                    "-q",
                    "-F",
                    "-L",
                    "data",
                    "-E",
                    "lazy_itable_init=0,lazy_journal_init=0",
                ])
                .arg(&dev)
                .output()
                .await
                .context("run mkfs.ext4")?;
            if !out.status.success() {
                return Err(anyhow!(
                    "mkfs.ext4 {}: {}",
                    dev.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        Ok(())
    }

    // --- start ---

    /// `If-Match` (ADR 0019): the version the caller read, compared under the machine's lock,
    /// so nothing moves it between the check and the change. None: no condition.
    fn check_version(&self, e: &Entry, at: Option<u64>) -> Result<(), MError> {
        match at {
            Some(v) if v != e.snapshot().version => Err(MError::Moved(Box::new(self.view(e)))),
            _ => Ok(()),
        }
    }

    pub async fn start(&self, id: &str, at: Option<u64>) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        let _turns = e.lock_once_stopped(false).await;
        self.check_version(&e, at)?;
        if e.snapshot().state != state::RUNNING {
            self.start_entry(&e, true).await?;
        }
        Ok(self.view(&e))
    }

    /// Starts a machine that went to sleep, that the host stopped or whose process ended;
    /// one stopped on purpose stays stopped.
    pub async fn wake(&self, id: &str, at: Option<u64>) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        let _turns = e.lock_once_stopped(false).await;
        self.check_version(&e, at)?;
        let r = e.snapshot();
        match r.state.as_str() {
            state::RUNNING => {
                e.touch();
                return Ok(self.view(&e));
            }
            state::STOPPED if r.stopped_reason == stop::USER => {
                return Err(MError::NotRunning("stopped on request".into()))
            }
            state::ERROR => return Err(MError::BadState(r.state)),
            _ => {}
        }
        self.start_entry(&e, true).await?;
        Ok(self.view(&e))
    }

    /// `start_entry` behind a boxed future: the restart path recurses through a spawned task,
    /// and the compiler needs the cycle broken somewhere.
    fn start_boxed<'a>(
        &'a self,
        e: &'a Arc<Entry>,
        asked: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), MError>> + Send + 'a>> {
        Box::pin(self.start_entry(e, asked))
    }

    /// Boots the machine. Called with the entry's lock held, on a machine that is not up:
    /// one being destroyed is refused here, whoever asks (a start, a wake, a restart).
    /// `asked`: a caller asked for this run (a create, a start, a wake), not the restart
    /// policy; its startup probe failing is a failed boot (ADR 0022).
    async fn start_entry(&self, e: &Arc<Entry>, asked: bool) -> Result<(), MError> {
        let cfg = &self.inner.cfg;
        let rec = e.snapshot();
        match rec.state.as_str() {
            state::CREATED | state::STOPPED | state::ERROR => {}
            other => return Err(MError::BadState(other.into())),
        }
        // A pending change's image is pulled and built before anything moves (ADR 0024): a
        // failure is the boot's, and the change waits for the next start.
        let image = match rec.pending.as_ref().and_then(|p| p.image.clone()) {
            Some(reference) => match self.inner.images.ensure(&reference).await {
                Ok(im) => Some(im),
                Err(err) => {
                    self.inner.stats.starts_failed.fetch_add(1, Relaxed);
                    return Err(self.boot_failed(e, format!("image {reference}: {err:#}")));
                }
            },
            None => None,
        };
        // Resolved before anything moves: a `via` whose machine is gone refuses the start.
        let policy = self.policy_for(&rec)?;
        // Through the tenant's gateway: it runs first, and the tenant's lock is kept until
        // this machine is `starting`, which is what the sleeper looks for.
        let gateway_turn = match rec.egress.via_gateway() {
            true => Some(
                self.ensure_gateway(&rec.tenant)
                    .await
                    .map_err(|err| self.gateway_failed(e, err))?,
            ),
            false => None,
        };
        self.reserve(e, image)?;
        drop(gateway_turn);
        let _ = self.save(e);
        // The host's fault (a network, disk or Firecracker error): the machine ends in
        // `error` and the caller gets a 500.
        let fail = |err: anyhow::Error| -> MError {
            self.inner
                .stats
                .starts_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            e.set_state(state::ERROR, |r| {
                r.error = format!("{err:#}");
                r.stopped_at = Some(Utc::now());
                r.pid = 0;
                Some(Ev::warning(reason::START_FAILED, r.error.clone()))
            });
            let _ = self.save(e);
            MError::Other(err)
        };
        // A restore cut short first (ADR 0031), then a new image's root disk (ADR 0024).
        let rec = e.snapshot();
        // The machines they free a snapshot of are tidied apart, once the caller's lock
        // is released (ADR 0031): never another machine's lock under this one's.
        if rec.restoring.is_some() {
            let parents = self
                .finish_restore(e)
                .await
                .map_err(|err| fail(anyhow!("{err:#}")))?;
            self.tidy_later(parents);
        }
        let rec = e.snapshot();
        if rec.root_key != rec.image_key {
            let parents = self.remake_root(e).await.map_err(fail)?;
            self.tidy_later(parents);
        }
        // What this boot runs: the record, the change it applied on it.
        let rec = e.snapshot();
        let t = match self.tenant_of(&rec.tenant) {
            Some(t) => t,
            None => return Err(fail(anyhow!("tenant network is gone"))),
        };
        let tap = self
            .inner
            .net
            .ensure_tap(&rec.id, &netw::bridge_name(t.rec.subnet_index), &rec.ip)
            .await
            .map_err(fail)?;
        self.set_policy(&rec.id, policy).await.map_err(fail)?;
        let dir = cfg.run_dir().join(&rec.id);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| fail(e.into()))?;
        let config_drive = dir.join("config.tar");
        self.write_config_drive(&config_drive, &rec, &t)
            .map_err(fail)?;
        let root_dev = self
            .inner
            .zfs
            .device(&rec.root_dataset())
            .await
            .context("root disk")
            .map_err(fail)?;
        let data_dev = match &rec.volume {
            Some(_) => Some(
                self.inner
                    .zfs
                    .device(&rec.data_dataset())
                    .await
                    .context("data volume")
                    .map_err(fail)?,
            ),
            None => None,
        };
        // Where this boot's lines start in the console (the writer rotates it by size).
        let console_offset = console::end(&dir).unwrap_or(0);
        e.rec.lock().unwrap().console_offset = console_offset;
        let ip: Ipv4Addr = rec.ip.parse().unwrap();
        let boot = fc::Boot {
            id: rec.id.clone(),
            dir,
            jail: self.jail_for(&rec),
            vcpus: rec.size.vcpus,
            memory_mb: rec.size.memory_mb,
            kernel: cfg.kernel.clone(),
            boot_args: self.boot_args(),
            config_drive,
            root: root_dev,
            data: data_dev,
            tap,
            mac: netw::mac_for(ip),
            resume: rec.suspended,
            disk: self.disk_rate(&rec),
            disk_io: e.disk_io.clone(),
        };
        // Boots take their turn: a host asked for many at once boots a few at a time, each
        // with the whole timeout, instead of all of them crawling past it together.
        let _boot_turn = self
            .inner
            .boot_gate
            .acquire()
            .await
            .map_err(|e| fail(anyhow!(e)))?;
        // CPU time counts from what the machine's cgroup holds before this boot.
        let cpu = self
            .inner
            .vmm
            .cgroup(&rec.id)
            .await
            .map_or(0, |c| c.cpu_usec);
        e.meter.lock().unwrap().boot(cpu);
        let live = self.inner.vmm.boot(&boot).await.map_err(fail)?;
        {
            *e.live.lock().unwrap() = Some(live.clone());
            *e.stop_req.lock().unwrap() = None;
            let mut r = e.rec.lock().unwrap();
            r.pid = live.pid;
            r.suspended = false;
            if !live.resumed {
                r.boots += 1;
                r.vmm_version = self.inner.vmm.version();
            }
        }
        let _ = self.save(e);
        self.watch(e, &live);

        let ready = self.inner.guest.wait_ready(
            &live.vsock,
            Duration::from_secs(cfg.boot_timeout_sec.max(10)),
        );
        let mut exited = live.exited.clone();
        let outcome = tokio::select! {
            r = ready => r.map_err(|err| format!("the guest did not come up: {err}")),
            // `exited` is sent once the console is fully written, so the tail is complete.
            _ = exited.changed() => Err("the machine exited during boot".to_string()),
        };
        if let Ok(init) = &outcome {
            e.rec.lock().unwrap().init_version = init.clone();
        }
        if let Err(why) = outcome {
            // The image's fault: the process is ended here, under the lock, so the watcher
            // finds nothing to settle and no restart policy applies. The machine stays in
            // `error`, with the console's last lines, for the caller to read and destroy.
            self.end_process(e, &live, Duration::ZERO).await;
            self.inner.stats.starts_failed.fetch_add(1, Relaxed);
            let tail = self.last_console_lines(&rec, 5);
            return Err(self.boot_failed(e, format!("{why}: {tail}")));
        }
        let (_, _, generation) = self.reset_probes(e);
        e.set_state(state::RUNNING, |r| {
            let now = Utc::now();
            r.started_at = Some(now);
            r.last_used_at = Some(now);
            r.stopped_reason.clear();
            let pid = live.pid;
            let ev = match live.resumed {
                true => Ev::normal(
                    reason::RESUMED,
                    format!("resumed from its memory snapshot, pid {pid}"),
                ),
                false => Ev::normal(reason::STARTED, format!("running, pid {pid}")),
            };
            Some(ev.data(json!({ "pid": pid })))
        });
        self.spawn_probes(e, &live, generation, asked);
        let _ = self.save(e);
        tracing::info!(
            machine = rec.id,
            tenant = rec.tenant,
            name = rec.name,
            ip = rec.ip,
            pid = live.pid,
            resumed = live.resumed,
            "machine running"
        );
        use std::sync::atomic::Ordering::Relaxed;
        if live.resumed {
            self.inner.stats.resumes.fetch_add(1, Relaxed);
        } else {
            self.inner.stats.boots.fetch_add(1, Relaxed);
        }
        Ok(())
    }

    /// A boot the machine's spec fails (ADR 0011): the machine left in `error` with why, a
    /// `boot_failed` event, and the 409 that carries the machine. Its process is already gone.
    fn boot_failed(&self, e: &Entry, why: String) -> MError {
        e.set_state(state::ERROR, |r| {
            r.error = why;
            r.stopped_at = Some(Utc::now());
            r.pid = 0;
            Some(Ev::warning(reason::BOOT_FAILED, r.error.clone()))
        });
        let _ = self.save(e);
        MError::BootFailed(Box::new(self.view(e)))
    }

    /// Makes the root disk again from the record's image, before a boot (ADR 0024): the root
    /// disk is swapped for a clone of the image (ADR 0031), the old one retired and kept only
    /// while forks clone it; the snapshots' root halves and memory go, since the root disk
    /// follows the image; the data volume is not touched. The image comes from the cache,
    /// pulled again when the host removed it since the start resolved it. Returns the
    /// machines whose snapshots the old root disk was cloned from, to tidy.
    async fn remake_root(&self, e: &Entry) -> Result<Vec<String>> {
        let im = self.inner.images.ensure(&e.snapshot().image).await?;
        let base = im.dataset();
        {
            let mut r = e.rec.lock().unwrap();
            r.image_key = im.key;
            r.image_digest = im.digest;
            r.image_config = im.config;
        }
        let r = e.snapshot();
        self.finish_swap(&r, "root")
            .await
            .context("the root disk")?;
        self.swap(&r, "root", &base, image::SNAP)
            .await
            .context("the root disk")?;
        let dropped = {
            let mut rec = e.rec.lock().unwrap();
            rec.root_key = rec.image_key.clone();
            let dropped: Vec<String> = rec
                .snapshots
                .iter()
                .filter(|s| s.memory.is_some())
                .map(|s| s.id.clone())
                .collect();
            for s in rec.snapshots.iter_mut() {
                s.disks.retain(|d| d != "root");
                s.memory = None;
            }
            rec.snapshots.retain(|s| !s.disks.is_empty());
            dropped
        };
        for snap in dropped {
            self.remove_memory(&r, &snap);
        }
        self.save(e)?;
        Ok(self.tidy_or_warn(e).await)
    }

    /// The jail of a machine, when the daemon runs Firecracker under the jailer: one uid per
    /// machine, from its place in the tenant's network.
    fn jail_for(&self, rec: &Record) -> Option<fc::Jail> {
        let cfg = &self.inner.cfg;
        if cfg.jailer.as_os_str().is_empty() {
            return None;
        }
        let uid = jail_uid(cfg.jail_uid_base, rec.subnet_index, rec.host_num);
        Some(fc::Jail {
            jailer: cfg.jailer.clone(),
            base: cfg.jail_base(),
            uid,
            gid: uid,
            cpus: rec.size.vcpus,
            // Guest memory, plus what Firecracker itself needs around it.
            memory_mb: rec.size.memory_mb + 256,
        })
    }

    /// The limits on each of its disks: its own over the host's for its size (ADR 0030).
    fn disk_rate(&self, rec: &Record) -> fc::DiskRate {
        self.inner
            .cfg
            .disk_limits
            .with(rec.size.vcpus, &rec.disk_limits)
    }

    fn boot_args(&self) -> String {
        boot_args(self.inner.cfg.pci, &self.inner.cfg.kernel_args)
    }

    /// Settles the state after the Firecracker process exited.
    async fn settle_exit(&self, e: &Arc<Entry>, pid: u32) {
        let _guard = e.lock.lock().await;
        let mut exit = {
            let live = e.live.lock().unwrap();
            match live.as_ref() {
                Some(l) if l.pid == pid => l.exit.clone(),
                _ => return,
            }
        };
        let rec = e.snapshot();
        self.unplug(&rec.id, &rec.ip).await;
        *e.live.lock().unwrap() = None;
        // The init's report, or none: the process is gone, so the wait ends either way. A
        // process that ended without the init's word (killed, a kernel panic) reads as 255;
        // nothing the guest prints on its console can set its exit.
        let _ = exit.wait_for(|r| r.is_some()).await;
        let report = exit.borrow().clone().unwrap_or(guest::ExitReport {
            code: 255,
            ..Default::default()
        });
        let (code, oom, requested) = (report.code, report.oom, report.requested);
        let stop_req = e.stop_req.lock().unwrap().take();
        if stop_req.is_none() && !requested {
            self.exited(e, code, oom, code != 0);
            return;
        }
        let Some(why) = stop_req else {
            e.set_state(state::STOPPED, |r| {
                r.pid = 0;
                r.stopped_at = Some(Utc::now());
                r.stopped_reason = stop::USER.into();
                Some(
                    Ev::normal(reason::STOPPED, "stopped on request")
                        .data(json!({ "reason": stop::USER })),
                )
            });
            let _ = self.save(e);
            return;
        };
        self.settle_stopped(e, &why);
    }

    /// A stop asked for `why` is done, its process gone: `stopped` with that reason, or
    /// `suspended` when it kept a memory snapshot.
    fn settle_stopped(&self, e: &Entry, why: &str) {
        *e.stop_deadline.lock().unwrap() = None;
        e.set_state(state::STOPPED, |r| {
            r.pid = 0;
            r.stopped_at = Some(Utc::now());
            r.stopped_reason = why.into();
            tracing::info!(machine = r.id, reason = why, "machine stopped");
            let ev = match r.suspended {
                true => Ev::normal(
                    reason::SUSPENDED,
                    format!("suspended ({why}): its memory snapshot kept"),
                ),
                false => Ev::normal(reason::STOPPED, format!("stopped ({why})")),
            };
            Some(ev.data(json!({ "reason": why })))
        });
        let _ = self.save(e);
    }

    /// A process that ended on its own, or that a probe ended (`failed` whatever its code):
    /// the exit recorded and the restart policy's decision. A restart waits the backoff (ADR
    /// 0022): 10 s doubling to 5 minutes by `recent_restarts`, which a run of `RESET_AFTER`
    /// clears; from the third in a row it is a crash loop. Under the machine's lock.
    fn exited(&self, e: &Arc<Entry>, code: i32, oom: bool, failed: bool) {
        let now = Utc::now();
        let mut restart = None;
        e.set_state(state::STOPPED, |r| {
            r.pid = 0;
            r.stopped_at = Some(now);
            if r.started_at.is_some_and(|t| now - t >= RESET_AFTER) {
                r.recent_restarts = 0;
            }
            let again = restarts_after_exit(&r.restart, failed, r.restarts);
            r.exit = Some(api::Exit {
                code,
                oom_killed: oom,
                at: now,
                restarting: again,
            });
            r.stopped_reason = stop::EXIT.into();
            if again {
                r.restarts += 1;
                r.recent_restarts += 1;
                e.meter.lock().unwrap().restarts += 1;
                let delay = restart_delay(r.recent_restarts);
                r.restarting_at = Some(now + delay);
                restart = Some((r.restarts, r.recent_restarts, delay, r.restart.clone()));
                tracing::warn!(
                    machine = r.id,
                    code,
                    oom,
                    restart = r.restarts,
                    delay_sec = delay.as_secs(),
                    "machine exited, restarting"
                );
            } else {
                r.restarts = 0;
                r.recent_restarts = 0;
                r.restarting_at = None;
                tracing::info!(machine = r.id, code, oom, "machine exited");
            }
            let ev = match (oom, code) {
                (true, _) => Ev::warning(reason::EXITED, "killed: out of memory"),
                (false, 0) if !failed => Ev::normal(reason::EXITED, "exited with code 0"),
                (false, _) => Ev::warning(reason::EXITED, format!("exited with code {code}")),
            };
            Some(ev.data(json!({ "code": code, "oom": oom, "restarting": again })))
        });
        if let Some((attempt, recent, delay, policy)) = &restart {
            let secs = delay.as_secs();
            let bound = match policy.policy.as_str() {
                "always" => "always".to_string(),
                _ => format!("at most {}", policy.max_retries),
            };
            e.note(
                Ev::warning(
                    reason::RESTARTING,
                    format!("restart {attempt} in {secs} s ({bound})"),
                )
                .data(json!({ "attempt": attempt, "policy": policy.policy, "delay_sec": secs })),
            );
            if *recent >= CRASH_LOOP_AT {
                e.note(
                    Ev::warning(
                        reason::CRASH_LOOP,
                        format!(
                            "restarted {recent} times in a row, no run of 10 minutes between: next in {secs} s"
                        ),
                    )
                    .data(json!({ "restarts": recent, "delay_sec": secs })),
                );
            }
        }
        let _ = self.save(e);
        let Some((_, _, delay, _)) = restart else {
            return;
        };
        let (m, e) = (self.clone(), e.clone());
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _turns = e.lock_for_start().await;
            let r = e.snapshot();
            if r.state != state::STOPPED || r.stopped_reason != stop::EXIT {
                return;
            }
            match m.start_boxed(&e, false).await {
                Ok(()) => {}
                Err(err @ MError::BootFailed(_)) => {
                    tracing::warn!(machine = r.id, err = %err, "restart")
                }
                Err(err) => tracing::error!(machine = r.id, err = %err, "restart"),
            }
        });
    }

    /// The last `max` bytes of the console since the current boot began.
    fn console_since(&self, r: &Record, max: u64) -> String {
        let dir = self.inner.cfg.run_dir().join(&r.id);
        let end = console::end(&dir).unwrap_or(0);
        let from = r.console_offset.max(end.saturating_sub(max));
        let Ok(Some((_, bytes))) = console::read_from(&dir, from) else {
            return String::new();
        };
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = bytes.take(max).read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn last_console_lines(&self, r: &Record, n: usize) -> String {
        let text = self.console_since(r, 64 << 10);
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(n);
        lines[start..].join(" | ")
    }

    // --- stop ---

    /// Ends the process of a machine whose entry lock is held: asks the guest to stop and
    /// kills after `grace` (at once when zero), waits for Firecracker to be gone, then clears
    /// the entry itself, since the watcher cannot take the lock to settle it, and wakes whoever
    /// waited for that.
    async fn end_process(&self, e: &Arc<Entry>, live: &fc::Vm, grace: Duration) {
        let mut exited = live.exited.clone();
        if !*exited.borrow() {
            let asked = !grace.is_zero()
                && tokio::time::timeout(
                    Duration::from_secs(5),
                    self.inner.guest.shutdown(&live.vsock, grace),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            let gone = asked
                && tokio::time::timeout(grace + Duration::from_secs(5), exited.wait_for(|x| *x))
                    .await
                    .is_ok();
            if !gone {
                self.inner.vmm.kill(live.pid);
                let _ = exited.wait_for(|x| *x).await;
            }
        }
        *e.live.lock().unwrap() = None;
        *e.stop_req.lock().unwrap() = None;
        let r = e.snapshot();
        self.unplug(&r.id, &r.ip).await;
        e.changed.notify_waiters();
    }

    pub async fn stop(
        &self,
        id: &str,
        timeout: Duration,
        suspend: bool,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        self.stop_entry(&e, stop::USER, timeout, suspend, at)
            .await?;
        Ok(self.view(&e))
    }

    /// Asks the guest to end its process, then waits for Firecracker to exit; after the grace,
    /// kills. Takes the entry's lock only briefly so the watcher can settle the state. `at` is
    /// the caller's `If-Match`, checked under that lock.
    async fn stop_entry(
        &self,
        e: &Arc<Entry>,
        why: &str,
        timeout: Duration,
        suspend: bool,
        at: Option<u64>,
    ) -> Result<(), MError> {
        let timeout = if timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            timeout
        };
        let live = {
            let _guard = e.lock.lock().await;
            self.check_version(e, at)?;
            let r = e.snapshot();
            match r.state.as_str() {
                state::STOPPED | state::CREATED | state::ERROR => {
                    if r.state == state::STOPPED
                        && why == stop::USER
                        && r.stopped_reason != stop::USER
                    {
                        let mut rec = e.rec.lock().unwrap();
                        rec.stopped_reason = stop::USER.into();
                        let ev = Ev::normal(
                            reason::STOPPED,
                            format!("stopped on request (it was {})", r.stopped_reason),
                        );
                        e.note_locked(&mut rec, ev.data(json!({ "reason": stop::USER })));
                        drop(rec);
                        let _ = self.save(e);
                    }
                    return Ok(());
                }
                state::RUNNING => {}
                state::STOPPING => {
                    // Another stop is in flight: wait for the watcher to settle it. The wait
                    // is registered before the lock goes, or a settle in between is missed.
                    let settled = e.changed.notified();
                    tokio::pin!(settled);
                    settled.as_mut().enable();
                    drop(_guard);
                    let _ = tokio::time::timeout(timeout + Duration::from_secs(15), settled).await;
                    return Ok(());
                }
                other => return Err(MError::BadState(other.into())),
            }
            let live = e.live.lock().unwrap().clone();
            let live = match live {
                Some(l) => l,
                None => return Err(MError::NotRunning("no process".into())),
            };
            *e.stop_req.lock().unwrap() = Some(why.to_string());
            // What this call waits at most below, the lock released: a start waits as long.
            *e.stop_deadline.lock().unwrap() =
                Some(tokio::time::Instant::now() + timeout + Duration::from_secs(20));
            e.set_state(state::STOPPING, |_| {
                Some(
                    Ev::normal(reason::STOPPING, format!("stopping ({why})"))
                        .data(json!({ "reason": why, "suspend": suspend })),
                )
            });
            let _ = self.save(e);
            // A suspend keeps a memory snapshot: the next start resumes in well under a
            // second. Refused, the machine is stopped the plain way.
            let suspended = suspend
                && match self.inner.vmm.snapshot(&live, true).await {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::warn!(machine = r.id, err = %err, "suspend refused, stopping");
                        false
                    }
                };
            if suspended {
                self.inner
                    .stats
                    .suspends
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // The guest is paused and saved: end the process; the watcher settles the
                // state with the reason set above. The watcher takes the entry's lock to do
                // it, so the lock is released before waiting, or the wait only ends when it
                // times out.
                e.rec.lock().unwrap().suspended = true;
                let _ = self.save(e);
                let settled = e.changed.notified();
                tokio::pin!(settled);
                settled.as_mut().enable();
                self.inner.vmm.kill(live.pid);
                drop(_guard);
                let _ = tokio::time::timeout(Duration::from_secs(15), settled).await;
                return Ok(());
            }
            live
        };
        let settled = e.changed.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        if let Err(err) = tokio::time::timeout(
            Duration::from_secs(5),
            self.inner.guest.shutdown(&live.vsock, timeout),
        )
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r)
        {
            tracing::warn!(machine = e.snapshot().id, err = %err, "guest shutdown request failed, killing");
            self.inner.vmm.kill(live.pid);
        }
        let mut exited = live.exited.clone();
        if !*exited.borrow()
            && tokio::time::timeout(timeout + Duration::from_secs(5), exited.changed())
                .await
                .is_err()
        {
            tracing::warn!(
                machine = e.snapshot().id,
                "guest did not stop in time, killing"
            );
            self.inner.vmm.kill(live.pid);
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), settled).await;
        Ok(())
    }

    // --- destroy ---

    /// A destroy through the API: missing is success.
    pub async fn destroy(&self, id: &str, at: Option<u64>) -> Result<(), MError> {
        match self.own_entry(id) {
            Err(MError::NotFound) => Ok(()),
            Err(err) => Err(err),
            Ok(_) => self.destroy_machine(id, at).await,
        }
    }

    /// One critical section under the entry's lock, from the state to the record's removal:
    /// nothing starts the machine in between, and a destroy that fails leaves it
    /// `destroying` for the sleeper's tick to try again. `at` is the caller's `If-Match`.
    async fn destroy_machine(&self, id: &str, at: Option<u64>) -> Result<(), MError> {
        let e = match self.entry(id) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        let others = {
            let _guard = e.lock.lock().await;
            if !self.inner.machines.lock().unwrap().contains_key(id) {
                // A destroy that held the lock before this one finished the job.
                return Ok(());
            }
            self.destroy_locked(&e, id, at).await?
        };
        // Its lock released, it is gone: the machines its disks touched are tidied, each
        // under its own lock (ADR 0031).
        self.tidy_machines(others).await;
        Ok(())
    }

    /// The destroy's critical section. Returns the machines to tidy after it: those its disks
    /// were cloned from, whose snapshot may be free now, and the forks promoted over it,
    /// which hold its snapshots now.
    async fn destroy_locked(
        &self,
        e: &Arc<Entry>,
        id: &str,
        at: Option<u64>,
    ) -> Result<Vec<String>, MError> {
        let e = e.clone();
        self.check_version(&e, at)?;
        // No event: the destroy is one step, and `destroyed` ends it.
        e.set_state(state::DESTROYING, |_| None);
        let _ = self.save(&e);
        let live = e.live.lock().unwrap().clone();
        if let Some(live) = live {
            self.end_process(&e, &live, Duration::from_secs(5)).await;
        }
        for ep in self.endpoints_of(id) {
            let _ = self.delete_endpoint(&ep.id);
        }
        let rec = e.snapshot();
        self.unplug(id, &rec.ip).await;
        // Its last use, measured while its disks and counters are still there; the bucket
        // stays after it (ADR 0017).
        self.meter(std::slice::from_ref(&e), Utc::now()).await;
        self.inner
            .net
            .uncount(&rec.ip)
            .await
            .context("usage counters")?;
        // A fork is a clone of this machine's disks: it takes the snapshots over and lives on.
        // What this machine's disks were cloned from is read after that, since a promotion
        // moves it: the snapshot it leaves behind goes once nothing clones it.
        let z = &self.inner.zfs;
        let mut others = Vec::new();
        if z.exists(&rec.dataset()).await.context("disks")? {
            let promoted = z
                .release_clones(&rec.dataset())
                .await
                .context("forks of the disks")?;
            others.extend(
                promoted
                    .iter()
                    .filter_map(|c| snapshots::machine_of(c))
                    .map(String::from),
            );
            for ds in z.volumes_under(&rec.dataset()).await.context("disks")? {
                if let Some((origin, _)) = z.origin(&ds).await.context("origin of the disks")? {
                    others.extend(
                        snapshots::machine_of(&origin)
                            .filter(|m| *m != id)
                            .map(String::from),
                    );
                }
            }
            z.destroy(&rec.dataset()).await.context("disks")?;
        }
        let _ = tokio::fs::remove_dir_all(self.inner.cfg.run_dir().join(id)).await;
        if let Some(j) = self.jail_for(&rec) {
            let _ =
                tokio::fs::remove_dir_all(fc::jail_root(&j.base, id).parent().unwrap_or(&j.base))
                    .await;
        }
        // Its backups stay, for a restore: a holder keeps them listed, counted and finite.
        if rec.backup_bytes > 0 || rec.backup.last.is_some() {
            self.hold(&rec, rec.backup_bytes, e.backup_turn.clone())?;
        }
        self.inner.store.delete("machines", id)?;
        self.remove_machine(&e);
        self.inner
            .events
            .emit(Ev::normal(reason::DESTROYED, "destroyed").of(id, &rec.tenant));
        tracing::info!(machine = id, "machine destroyed");
        others.sort();
        others.dedup();
        Ok(others)
    }

    // --- use and sleep ---

    /// Changes the sleep window, the metadata, the egress policy, the limits or the probes of a
    /// machine, in any state; a running machine's policy changes in the tables at once, and its
    /// probes start over. What it runs (`spec`) changes at its next start (ADR 0024): kept as
    /// `pending` meanwhile, a running machine running on as it was. A change is an event
    /// (`egress_changed` for the policy or the limits, `updated` for the rest, one with
    /// `pending` for the spec); a request that changes nothing is none.
    pub async fn update(
        &self,
        id: &str,
        req: api::UpdateMachineRequest,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        if let Some(sl) = &req.sleep {
            api::parse_sleep(sl).map_err(invalid)?;
        }
        check_limits(req.limits.as_ref())?;
        check_disk_limits(req.disk_limits.as_ref())?;
        backups::check_update(&req.backup)?;
        if let Some(p) = &req.probes {
            p.check().map_err(invalid)?;
        }
        req.spec.check().map_err(invalid)?;
        // Under the entry's lock, like every transition: no start or stop runs in between,
        // and a destroy that ran first has removed the machine, whose record is not written
        // back.
        let _guard = e.lock.lock().await;
        if !self.inner.machines.lock().unwrap().contains_key(id) {
            return Err(MError::NotFound);
        }
        self.check_version(&e, at)?;
        // Held until the record says `via: gateway`, as a start holds it.
        let mut gateway_turn = None;
        let reprobe;
        if req.egress.is_some() || req.limits.is_some() {
            let mut r = e.snapshot();
            if let Some(eg) = &req.egress {
                self.check_egress(eg, &r.tenant, &r.id)?;
                r.egress = eg.clone();
            }
            if let Some(l) = &req.limits {
                r.limits = l.over(&r.limits);
            }
            // The tables first: refused, the old policy stays and so does the record.
            if r.state == state::RUNNING {
                let policy = self.policy_for(&r)?;
                if req.egress.as_ref().is_some_and(|eg| eg.via_gateway()) {
                    gateway_turn = Some(
                        self.ensure_gateway(&r.tenant)
                            .await
                            .map_err(|err| self.gateway_failed(&e, err))?,
                    );
                }
                self.replace_policy(&r.id, policy).await?;
            }
        }
        if let Some(l) = &req.disk_limits {
            // Firecracker first: refused, the disks keep their limits and the record its own.
            let mut r = e.snapshot();
            let was = self.disk_rate(&r);
            r.disk_limits = l.over(&r.disk_limits);
            let now = self.disk_rate(&r);
            let live = e.live.lock().unwrap().clone();
            if let (Some(vm), true) = (live, now != was && r.state == state::RUNNING) {
                self.inner
                    .vmm
                    .disk_rate(&vm, &now, r.volume.is_some())
                    .await
                    .context("disk limits")?;
            }
        }
        {
            let mut r = e.rec.lock().unwrap();
            let was = r.clone();
            if let Some(sl) = req.sleep {
                r.sleep = sleep_setting(&sl);
            }
            if let Some(m) = req.metadata {
                r.metadata = m;
            }
            if let Some(eg) = req.egress {
                r.egress = eg;
            }
            if let Some(l) = req.limits {
                r.limits = l.over(&r.limits);
            }
            if let Some(l) = req.disk_limits {
                r.disk_limits = l.over(&r.disk_limits);
            }
            backups::update(&mut r, req.backup)?;
            if let Some(p) = req.probes {
                r.probes = p;
            }
            if let Some(ev) = change_event(&was, &r) {
                e.note_locked(&mut r, ev);
            }
            let pending = pending_after(&r, req.spec);
            if pending != r.pending {
                r.pending_since = match pending {
                    Some(_) => r.pending_since.or(Some(Utc::now())),
                    None => None,
                };
                let fields = pending
                    .clone()
                    .unwrap_or_default()
                    .changed_from(&r.pending.take().unwrap_or_default());
                r.pending = pending;
                let ev = Ev::normal(
                    reason::UPDATED,
                    format!("{} change at the next start", fields.join(", ")),
                );
                e.note_locked(
                    &mut r,
                    ev.data(json!({ "fields": fields, "pending": true })),
                );
            }
            reprobe = r.probes != was.probes && r.state == state::RUNNING;
        }
        self.save(&e)?;
        drop(gateway_turn);
        if reprobe {
            self.restart_probes(&e);
        }
        Ok(self.view(&e))
    }

    /// Stops the machine and starts it again: what a PATCH left pending applies now (ADR 0024).
    /// One that is not running is started. `at` is the caller's `If-Match`, checked by the
    /// stop, whose events move the version.
    pub async fn restart(&self, id: &str, at: Option<u64>) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        self.stop_entry(&e, stop::USER, Duration::ZERO, false, at)
            .await?;
        let _turns = e.lock_for_start().await;
        if e.snapshot().state != state::RUNNING {
            self.start_entry(&e, true).await?;
        }
        Ok(self.view(&e))
    }

    pub fn touch(&self, id: &str) -> Result<(), MError> {
        self.own_entry(id)?.touch();
        Ok(())
    }

    /// Every 15 s: what machines used since the last tick is measured, the host's conditions
    /// are decided (images removed under disk pressure), idle machines go to sleep, then the
    /// gateways no machine needs, uses since the last tick reach the disk, and a destroy left
    /// `destroying` (a daemon restart, a disk that was busy) is tried again. The first tick is at once: it is where an adopted machine's CPU count starts.
    async fn sleeper(self) {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            self.tick().await;
        }
    }

    async fn tick(&self) {
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
    async fn measure(&self, now: DateTime<Utc>) {
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
    async fn assess(&self, now: DateTime<Utc>) {
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
        let short = pool.map_or(0, |p| conditions::disk_short(p, &t));
        if short > 0 {
            self.free_images(short).await;
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
    async fn meter(&self, entries: &[Arc<Entry>], now: DateTime<Utc>) {
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

    /// Where the ingress adds the bytes it passes to and from a machine's endpoints.
    pub fn traffic(&self, id: &str) -> Option<Arc<Traffic>> {
        self.entry(id).ok().map(|e| e.traffic.clone())
    }

    /// The buckets of the hours in `[from, to)`, of one tenant or all, by hour then machine:
    /// the open hours from memory, the others from their files.
    pub async fn usage_buckets(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        tenant: Option<String>,
    ) -> Result<Vec<api::UsageBucket>, MError> {
        let (mut out, open) =
            self.inner
                .usage
                .lock()
                .unwrap()
                .open_buckets(from, to, tenant.as_deref());
        let store = self.inner.store.clone();
        let stored = tokio::task::spawn_blocking(move || {
            usage::stored(&store, from, to, tenant.as_deref(), &open)
        })
        .await
        .map_err(|e| anyhow!(e))??;
        out.extend(stored);
        out.sort_by(|a, b| (a.hour, &a.machine_id).cmp(&(b.hour, &b.machine_id)));
        Ok(out)
    }

    // --- events (ADR 0019) ---

    pub fn events(&self) -> &Events {
        &self.inner.events
    }

    /// A page of events after `since`, oldest first.
    pub async fn events_page(
        &self,
        since: u64,
        f: events::Filter,
        limit: usize,
    ) -> Result<api::EventsPage, MError> {
        let log = self.inner.events.clone();
        let page = tokio::task::spawn_blocking(move || log.read(since, &f, limit))
            .await
            .map_err(|e| anyhow!(e))?
            .map_err(gone)?;
        Ok(api::EventsPage {
            events: page.events,
            next: page.next.to_string(),
        })
    }

    /// Blocks until the machine runs (`Until::Running`) or is ready (`Until::Ready`, ADR 0022),
    /// or until it is clear it will not, within `timeout`.
    pub async fn wait(
        &self,
        id: &str,
        until: Until,
        timeout: Duration,
    ) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Registered before the state is read, so a change in between is not missed.
            let changed = e.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let m = self.view(&e);
            if let Some(answer) = wait_verdict(&m, until) {
                return answer.map(|()| m);
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                let m = self.view(&e);
                return Err(match until == Until::Ready && m.state == state::RUNNING {
                    true => MError::NotReady(Box::new(m)),
                    false => MError::NotRunning(format!("still {} after {timeout:?}", m.state)),
                });
            }
        }
    }

    /// The address a proxy connects to once the machine is ready, woken when it sleeps:
    /// readiness gates traffic (ADR 0022).
    pub async fn ready_addr(&self, id: &str, timeout: Duration) -> Result<Ipv4Addr, MError> {
        let ip = self.machine_addr(id, true).await?;
        self.wait(id, Until::Ready, timeout).await?;
        Ok(ip)
    }

    // --- config drive ---

    fn write_config_drive(&self, path: &Path, r: &Record, t: &Tenant) -> Result<()> {
        write_drive(path, &config_drive(r, t.subnet.gateway())?)
    }

    // --- exec and files ---

    async fn running_vsock(&self, id: &str, wake: bool) -> Result<PathBuf, MError> {
        let e = self.own_entry(id)?;
        let (st, reason, live) = {
            let r = e.rec.lock().unwrap();
            (
                r.state.clone(),
                r.stopped_reason.clone(),
                e.live.lock().unwrap().clone(),
            )
        };
        if st == state::RUNNING {
            if let Some(l) = live {
                return Ok(l.vsock);
            }
        }
        if !wake {
            let s = if reason.is_empty() {
                st
            } else {
                format!("{st} ({reason})")
            };
            return Err(MError::NotRunning(s));
        }
        // A command that woke the machine runs once it is ready, as traffic does (ADR 0022):
        // a database woken by `psql` must be accepting by then. A machine already running
        // and not ready still takes commands at once, as a pod does.
        self.wake_detached(id).await?;
        let boot = Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10));
        self.wait(id, Until::Ready, boot).await?;
        let live = e.live.lock().unwrap().clone();
        live.map(|l| l.vsock)
            .ok_or_else(|| MError::NotRunning("no process".into()))
    }

    /// A wake on behalf of something else (an exec, an ingress connection), which may give
    /// up before the boot is done: the boot goes on without it.
    async fn wake_detached(&self, id: &str) -> Result<api::Machine, MError> {
        let m = self.clone();
        let id = id.to_string();
        detached(async move { m.wake(&id, None).await }).await
    }

    /// Runs a command to its end (the JSON exec): a session whose stdin is the request's,
    /// read to its exit (ADR 0029). The machine is in use while it runs.
    pub async fn exec(&self, id: &str, req: api::ExecRequest) -> Result<api::ExecResult, MError> {
        let timeout_ms = if req.timeout_ms == 0 {
            300_000
        } else {
            req.timeout_ms
        };
        let greq = guest::Request {
            op: "exec".into(),
            cmd: req.cmd,
            env: req.env,
            cwd: req.cwd,
            stdin: req.stdin.into_bytes(),
            timeout_ms,
            ..Default::default()
        };
        let (mut conn, _in_use) = self.start_command(id, req.wake, greq).await?;
        let out = tokio::time::timeout(
            Duration::from_millis(timeout_ms + 10_000),
            guestc::collect(&mut conn),
        )
        .await
        .map_err(|_| MError::NotRunning("the command did not finish".into()))?
        .map_err(|err| {
            if err.downcast_ref::<guestc::Closed>().is_some() {
                MError::NotRunning("the machine went down during the command".into())
            } else {
                MError::Other(self.init_named(id, err))
            }
        })?;
        Ok(api::ExecResult {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.code,
            timed_out: out.timed_out,
        })
    }

    /// A guest call's error with the machine's init named when it did not know the op (ADR
    /// 0027): what an exec, a put, a get, and any op added later go through.
    fn init_named(&self, id: &str, err: anyhow::Error) -> anyhow::Error {
        let init = self
            .entry(id)
            .map(|e| e.snapshot().init_version)
            .unwrap_or_default();
        guestc::with_init(err, &init)
    }

    /// Starts an exec session (ADR 0029): the command runs once the guest takes it, and the
    /// machine is in use until the session is dropped. Wakes the machine as an exec does.
    pub async fn open_session(
        &self,
        id: &str,
        req: api::session::ExecSession,
    ) -> Result<Session, MError> {
        if req.cmd.is_empty() {
            return Err(invalid("cmd is required"));
        }
        let program = req.cmd[0].clone();
        let greq = guest::Request {
            op: "exec".into(),
            cmd: req.cmd,
            env: req.env,
            cwd: req.cwd,
            timeout_ms: req.timeout_ms,
            interactive: true,
            tty: req.tty,
            cols: req.cols,
            rows: req.rows,
            ..Default::default()
        };
        let (conn, in_use) = self.start_command(id, req.wake, greq).await?;
        let (machine, tenant) = {
            let r = in_use.0.rec.lock().unwrap();
            (r.id.clone(), r.tenant.clone())
        };
        // A use, not a change: the machine's version does not move (ADR 0019).
        let tty = if req.tty { " on a terminal" } else { "" };
        self.inner.events.emit(
            Ev::normal(reason::SESSION_OPENED, format!("{program}{tty}"))
                .of(&machine, &tenant)
                .data(json!({ "command": program, "tty": req.tty })),
        );
        Ok(Session {
            conn,
            machine,
            in_use,
        })
    }

    /// The one way a command starts in a machine for a caller: woken when asked, the guest's
    /// connection once it took the command, and the machine in use while `InUse` lives.
    async fn start_command(
        &self,
        id: &str,
        wake: bool,
        req: guest::Request,
    ) -> Result<(Box<dyn guestc::Conn>, InUse), MError> {
        self.inner
            .stats
            .execs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let e = self.own_entry(id)?;
        let sock = self.running_vsock(id, wake).await?;
        // An init older than sessions takes the request as a plain exec, its input and terminal
        // ignored (ADR 0027): refused, the init named, before the guest is asked.
        let init = e.snapshot().init_version;
        if req.interactive && api::version::before(&init, api::version::SESSIONS) {
            let old = guestc::UnknownOp {
                op: "session".into(),
                init,
            };
            return Err(MError::Conflict(old.to_string()));
        }
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.guest.session(&sock, req),
        )
        .await
        .map_err(|_| MError::NotRunning("the guest did not take the command".into()))?
        .map_err(MError::Other)?;
        Ok((conn, InUse::new(e)))
    }

    pub async fn put_file(&self, id: &str, req: api::PutFileRequest) -> Result<(), MError> {
        let sock = self.running_vsock(id, false).await?;
        let data =
            guest::base64_decode(&req.base64).map_err(|e| invalid(format!("base64: {e}")))?;
        let mode = match &req.mode {
            Some(m) if !m.is_empty() => {
                u32::from_str_radix(m, 8).map_err(|_| invalid(format!("mode {m:?}")))?
            }
            _ => 0o644,
        };
        tokio::time::timeout(
            Duration::from_secs(60),
            self.inner.guest.put(&sock, &req.path, mode, data),
        )
        .await
        .map_err(|_| MError::NotRunning("timeout".into()))?
        .map_err(|err| self.init_named(id, err))?;
        let _ = self.touch(id);
        Ok(())
    }

    pub async fn get_file(&self, id: &str, path: &str) -> Result<Vec<u8>, MError> {
        let sock = self.running_vsock(id, false).await?;
        let data = tokio::time::timeout(Duration::from_secs(60), self.inner.guest.get(&sock, path))
            .await
            .map_err(|_| MError::NotRunning("timeout".into()))?
            .map_err(|err| self.init_named(id, err))?;
        let _ = self.touch(id);
        Ok(data)
    }

    // --- logs ---

    /// Pages the console. `since` is an offset in the whole console, the rotated file
    /// included (ADR 0021); `limit` caps lines.
    pub fn logs(&self, id: &str, since: &str, limit: usize) -> Result<api::LogsResponse, MError> {
        self.entry(id)?;
        let limit = if limit == 0 || limit > 5000 {
            500
        } else {
            limit
        };
        let dir = self.inner.cfg.run_dir().join(id);
        match console_page(&dir, log_cursor(since)?, limit).map_err(|e| MError::Other(e.into()))? {
            None => Ok(api::LogsResponse::default()),
            Some((lines, next)) => Ok(api::LogsResponse {
                lines,
                next: next.to_string(),
            }),
        }
    }

    /// Follows the console from `since` (ADR 0025): the lines after it, then each new one,
    /// one JSON line each (`api::LogLine`), `{}` every `events::HEARTBEAT`, and a last error
    /// line when the machine is destroyed or the daemon goes down. Checked before any line
    /// goes out; ends when `tx` is dropped.
    pub fn follow_logs(
        &self,
        id: &str,
        since: &str,
        tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<(), MError> {
        // Subscribed before the machine is looked up: a destroy in between is seen.
        let (logged, closing) = self.inner.events.subscribe();
        self.entry(id)?;
        let cursor = log_cursor(since)?;
        let me = self.clone();
        let id = id.to_string();
        tokio::spawn(async move { me.follow(id, cursor, logged, closing, tx).await });
        Ok(())
    }

    async fn follow(
        &self,
        id: String,
        mut cursor: u64,
        mut logged: broadcast::Receiver<api::Event>,
        mut closing: tokio::sync::watch::Receiver<bool>,
        tx: tokio::sync::mpsc::Sender<String>,
    ) {
        let dir = self.inner.cfg.run_dir().join(&id);
        let grown = console::grown(&dir);
        let start = tokio::time::Instant::now() + events::HEARTBEAT;
        let mut beat = tokio::time::interval_at(start, events::HEARTBEAT);
        loop {
            // Enabled before the read: a line written after it wakes this one.
            let woken = grown.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            loop {
                let (lines, next) = match console_page(&dir, cursor, FOLLOW_PAGE) {
                    Ok(Some(page)) => page,
                    Ok(None) => break,
                    Err(err) => {
                        let why = format!("read the console: {err}");
                        events::send(&tx, &mut closing, events::last_line("internal", &why)).await;
                        return;
                    }
                };
                cursor = next;
                let full = lines.len() == FOLLOW_PAGE;
                for l in lines {
                    let line = serde_json::to_string(&l).unwrap_or_default() + "\n";
                    if !events::send(&tx, &mut closing, line).await {
                        return;
                    }
                }
                if !full {
                    break;
                }
            }
            let destroyed = loop {
                let beat_now = tokio::select! {
                    _ = &mut woken => break false,
                    e = logged.recv() => match e {
                        Ok(e) if e.machine_id == id && e.reason == reason::DESTROYED => break true,
                        Ok(_) => false,
                        // Behind the host's log: the records say whether it is gone.
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            if !self.inner.machines.lock().unwrap().contains_key(&id) {
                                break true;
                            }
                            false
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    _ = beat.tick() => true,
                    _ = closing.wait_for(|c| *c) => {
                        // Only if there is room: a daemon going down waits for no reader.
                        let why = format!("the daemon is going down: follow again from since={cursor}");
                        let _ = tx.try_send(events::last_line("shutdown", &why));
                        return;
                    }
                    _ = tx.closed() => return,
                };
                if beat_now && !events::send(&tx, &mut closing, "{}\n".into()).await {
                    return;
                }
            };
            if destroyed {
                let why = format!("machine {id} was destroyed; its console went with it");
                events::send(&tx, &mut closing, events::last_line("destroyed", &why)).await;
                return;
            }
        }
    }

    // --- endpoints ---

    pub fn endpoint_events(&self) -> broadcast::Receiver<(EndpointRec, bool)> {
        self.inner.endpoint_events.subscribe()
    }

    pub fn all_endpoints(&self) -> Vec<EndpointRec> {
        let mut out: Vec<EndpointRec> = self
            .inner
            .endpoints
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    pub fn endpoint(&self, id: &str) -> Option<EndpointRec> {
        self.inner.endpoints.lock().unwrap().get(id).cloned()
    }

    pub fn endpoints_of(&self, machine_id: &str) -> Vec<api::Endpoint> {
        let mut out: Vec<api::Endpoint> = self
            .inner
            .endpoints
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.machine_id == machine_id)
            .map(|e| self.endpoint_view(e))
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    pub fn endpoint_view(&self, e: &EndpointRec) -> api::Endpoint {
        let address = match e.protocol.as_str() {
            "http" => format!("http://{}", e.host),
            _ => format!("{}:{}", self.inner.advertise, e.host_port.unwrap_or(0)),
        };
        api::Endpoint {
            id: e.id.clone(),
            machine_id: e.machine_id.clone(),
            port: e.port,
            protocol: e.protocol.clone(),
            host_port: e.host_port,
            host: e.host.clone(),
            address,
            created_at: e.created_at,
        }
    }

    pub fn create_endpoint(
        &self,
        machine_id: &str,
        req: api::CreateEndpointRequest,
    ) -> Result<api::Endpoint, MError> {
        let e = self.own_entry(machine_id)?;
        if req.port == 0 {
            return Err(invalid("port must be 1..65535"));
        }
        let proto = if req.protocol.is_empty() {
            "tcp".to_string()
        } else {
            req.protocol.clone()
        };
        if proto != "tcp" && proto != "http" {
            return Err(invalid("protocol must be tcp or http"));
        }
        let tenant = e.snapshot().tenant;
        let name = e.snapshot().name;
        let mut endpoints = self.inner.endpoints.lock().unwrap();
        if let Some(ex) = endpoints
            .values()
            .find(|ex| ex.machine_id == machine_id && ex.port == req.port && ex.protocol == proto)
        {
            return Ok(self.endpoint_view(ex));
        }
        let mut ep = EndpointRec {
            id: new_id("ep"),
            machine_id: machine_id.to_string(),
            tenant,
            port: req.port,
            protocol: proto.clone(),
            host_port: None,
            host: String::new(),
            created_at: Utc::now(),
        };
        if proto == "tcp" {
            let used: Vec<u16> = endpoints.values().filter_map(|x| x.host_port).collect();
            ep.host_port = Some(free_tcp_port(&self.inner.cfg.ingress.tcp_ports, used)?);
        } else {
            if self.inner.cfg.ingress.http.is_empty() {
                return Err(invalid(
                    "http endpoints are not enabled on this host (ingress.http)",
                ));
            }
            let label = if req.host.is_empty() {
                format!("{name}-{}", &new_id("")[1..5])
            } else {
                req.host.clone()
            };
            if !api::valid_name(&label) {
                return Err(invalid("host must be a DNS label"));
            }
            ep.host = format!("{label}.{}", self.inner.cfg.ingress.domain);
            if endpoints.values().any(|x| x.host == ep.host) {
                return Err(invalid(format!("host {} is taken", ep.host)));
            }
        }
        self.inner.store.put("endpoints", &ep.id, &ep)?;
        endpoints.insert(ep.id.clone(), ep.clone());
        drop(endpoints);
        let _ = self.inner.endpoint_events.send((ep.clone(), true));
        Ok(self.endpoint_view(&ep))
    }

    pub fn delete_endpoint(&self, id: &str) -> Result<(), MError> {
        let ep = self.inner.endpoints.lock().unwrap().remove(id);
        if let Some(ep) = ep {
            self.inner.store.delete("endpoints", id)?;
            let _ = self.inner.endpoint_events.send((ep, false));
        }
        Ok(())
    }

    /// The address a proxy connects to, waking the machine when asked.
    pub async fn machine_addr(&self, id: &str, wake: bool) -> Result<Ipv4Addr, MError> {
        let e = self.entry(id)?;
        let (st, ip) = {
            let r = e.rec.lock().unwrap();
            (r.state.clone(), r.ip.clone())
        };
        if st == state::RUNNING {
            e.touch();
            return Ok(ip.parse().unwrap());
        }
        if !wake {
            return Err(MError::NotRunning(st));
        }
        self.wake_detached(id).await?;
        Ok(ip.parse().unwrap())
    }
}

/// A read the log refused as `gone` (ADR 0019), or what else went wrong.
pub fn gone(err: anyhow::Error) -> MError {
    match err.downcast::<events::Gone>() {
        Ok(g) => MError::Gone {
            oldest: g.oldest,
            message: g.message,
        },
        Err(err) => MError::Other(err),
    }
}

/// Runs a transition in a task of its own and waits for it: a client that hangs up drops
/// the wait, never the transition, so no machine is left half-moved.
pub async fn detached<T, F>(fut: F) -> Result<T, MError>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, MError>> + Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(r) => r,
        Err(err) => Err(MError::Other(anyhow!("transition task: {err}"))),
    }
}

/// What the machines in the map hold now: memory and vCPUs committed, and how many are up.
fn committed(machines: &HashMap<String, Arc<Entry>>) -> (api::Capacity, usize) {
    let mut used = api::Capacity::default();
    let mut up = 0;
    for e in machines.values() {
        let r = e.rec.lock().unwrap();
        if holds_memory(&r.state) {
            up += 1;
            used.memory_mb += r.size.memory_mb;
            used.vcpus += r.size.vcpus;
        }
    }
    (used, up)
}

/// Whether a machine of `tenant` that sends through its gateway is running or starting: what
/// keeps the gateway up.
fn gateway_needed(machines: &HashMap<String, Arc<Entry>>, tenant: &str) -> bool {
    machines.values().any(|e| {
        let r = e.rec.lock().unwrap();
        r.tenant == tenant
            && r.egress.via_gateway()
            && matches!(r.state.as_str(), state::STARTING | state::RUNNING)
    })
}

/// The event of a PATCH: `egress_changed` when the policy or the limits moved (both are what
/// the tables hold for its internet traffic), else `updated`; each with the fields that did.
/// None when nothing changed.
fn change_event(was: &Record, now: &Record) -> Option<Ev> {
    let changed = |pairs: &[(&'static str, bool)]| -> Vec<&'static str> {
        pairs.iter().filter(|(_, c)| *c).map(|(f, _)| *f).collect()
    };
    let egress = changed(&[
        ("egress", was.egress != now.egress),
        ("limits", was.limits != now.limits),
    ]);
    if !egress.is_empty() {
        let label = |e: &api::Egress| match &e.via {
            Some(via) => format!("{}:{via}", e.mode),
            None => e.mode.clone(),
        };
        let (from, to) = (label(&was.egress), label(&now.egress));
        let message = match was.egress != now.egress {
            true => format!("egress {from} -> {to}"),
            false => "egress limits changed".to_string(),
        };
        return Some(Ev::normal(reason::EGRESS_CHANGED, message).data(json!({
            "fields": egress, "from": from, "to": to, "limits": now.limits,
        })));
    }
    let fields = changed(&[
        ("sleep", was.sleep != now.sleep),
        ("metadata", was.metadata != now.metadata),
        ("backup", was.backup.policy != now.backup.policy),
        ("probes", was.probes != now.probes),
        ("disk_limits", was.disk_limits != now.disk_limits),
    ]);
    if fields.is_empty() {
        return None;
    }
    let ev = Ev::normal(reason::UPDATED, format!("{} changed", fields.join(", ")));
    Some(ev.data(json!({ "fields": fields })))
}

/// What the next start applies after a PATCH of `change` (ADR 0024): the pending change with
/// `change` over it, less what the record already has; None when nothing is left.
fn pending_after(r: &Record, change: api::SpecChange) -> Option<api::SpecChange> {
    let p = r.pending.clone().unwrap_or_default();
    let next = api::SpecChange {
        image: change.image.or(p.image).filter(|v| *v != r.image),
        entrypoint: (change.entrypoint.or(p.entrypoint))
            .filter(|v| Some(v) != r.entrypoint.as_ref()),
        cmd: change.cmd.or(p.cmd).filter(|v| Some(v) != r.cmd.as_ref()),
        env: change.env.or(p.env).filter(|v| *v != r.env),
        files: change.files.or(p.files).filter(|v| *v != r.files),
        size: change.size.or(p.size).filter(|v| *v != r.size),
        ports: change.ports.or(p.ports).filter(|v| *v != r.ports),
        restart: change.restart.or(p.restart).filter(|v| *v != r.restart),
    };
    (!next.is_empty()).then_some(next)
}

/// Puts the pending change on the record, in the step that starts the machine (ADR 0024);
/// `image` is its new image, resolved. A change to what a memory snapshot holds drops the
/// snapshot: that start is cold. The fields applied; None when nothing was pending.
fn apply_pending(r: &mut Record, image: Option<image::Image>) -> Option<Vec<&'static str>> {
    let p = r.pending.take()?;
    r.pending_since = None;
    let fields = p.fields();
    if p.touches_snapshot() {
        r.suspended = false;
    }
    if let (Some(reference), Some(im)) = (p.image, image) {
        r.image = reference;
        r.image_key = im.key;
        r.image_digest = im.digest;
        r.image_config = im.config;
    }
    if let Some(v) = p.entrypoint {
        r.entrypoint = Some(v);
    }
    if let Some(v) = p.cmd {
        r.cmd = Some(v);
    }
    if let Some(v) = p.env {
        r.env = v;
    }
    if let Some(v) = p.files {
        r.files = v;
    }
    if let Some(v) = p.size {
        r.size = v;
    }
    if let Some(v) = p.ports {
        r.ports = v;
    }
    if let Some(v) = p.restart {
        r.restart = v;
    }
    Some(fields)
}

/// What `/wait` waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Until {
    Running,
    Ready,
}

/// What a `/wait` answers now, or None to keep waiting. For `Ready`, a machine in `error`
/// failed its boot (the guest or its startup probe): `boot_failed`, as its start would answer.
fn wait_verdict(m: &api::Machine, until: Until) -> Option<Result<(), MError>> {
    match (will_run(m), until) {
        (Some(Ok(())), Until::Ready) if !m.ready => None,
        (Some(Err(_)), Until::Ready) if m.state == state::ERROR => {
            Some(Err(MError::BootFailed(Box::new(m.clone()))))
        }
        (verdict, _) => verdict.map(|v| v.map_err(MError::NotRunning)),
    }
}

/// Why a running machine is not ready: its probes' last results.
fn not_ready_why(m: &api::Machine) -> String {
    let s = &m.probes_status;
    let said: Vec<String> = [("startup", &s.startup), ("readiness", &s.readiness)]
        .into_iter()
        .filter_map(|(name, st)| st.as_ref().map(|st| (name, st)))
        .filter(|(_, st)| !st.passed)
        .map(|(name, st)| format!("{name}: {}", st.message))
        .collect();
    match said.is_empty() {
        true => "its probes have not passed yet".into(),
        false => said.join("; "),
    }
}

/// What `/wait` answers: running, will not run (why), or still moving.
fn will_run(m: &api::Machine) -> Option<Result<(), String>> {
    match m.state.as_str() {
        state::RUNNING => Some(Ok(())),
        state::ERROR => Some(Err(m.error.clone())),
        state::DESTROYING => Some(Err("destroying".into())),
        state::STOPPED
            if !(m.stopped_reason == stop::EXIT
                && m.exit.as_ref().map(|e| e.restarting).unwrap_or(false)) =>
        {
            Some(Err(format!("stopped ({})", m.stopped_reason)))
        }
        _ => None,
    }
}

/// The address TCP endpoints are reported at: `ingress.advertise`, else a bind address that
/// names one, else the egress interface's.
fn advertise_address(advertise: &str, bind: &str, host_ip: Option<Ipv4Addr>) -> String {
    if !advertise.is_empty() {
        return advertise.into();
    }
    if !bind.is_empty() && bind != "0.0.0.0" {
        return bind.into();
    }
    host_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| bind.into())
}

/// The first IPv4 address of an interface.
async fn host_ip(interface: &str) -> Option<Ipv4Addr> {
    let out = tokio::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", interface])
        .output()
        .await
        .ok()?;
    inet_of(&String::from_utf8_lossy(&out.stdout))
}

fn check_size(size: &api::Size) -> Result<(), MError> {
    size.check().map_err(invalid)
}

/// Limits a request may set (ADR 0018); none is fine.
fn check_limits(l: Option<&api::EgressLimits>) -> Result<(), MError> {
    match l.map(|l| l.check()) {
        Some(Err(e)) => Err(invalid(format!("limits.{e}"))),
        _ => Ok(()),
    }
}

/// Disk limits a request may set (ADR 0030); none is fine.
fn check_disk_limits(l: Option<&api::DiskLimits>) -> Result<(), MError> {
    match l.map(|l| l.check()) {
        Some(Err(e)) => Err(invalid(format!("disk_limits.{e}"))),
        _ => Ok(()),
    }
}

/// Lines a follow reads at a time.
const FOLLOW_PAGE: usize = 500;

/// A `/logs` cursor: an offset in the whole console; empty is its start.
fn log_cursor(since: &str) -> Result<u64, MError> {
    match since {
        "" => Ok(0),
        s => s
            .parse()
            .map_err(|_| invalid("since must be a cursor from a previous page")),
    }
}

/// Up to `limit` whole lines of the console in `dir` from `from`, and the cursor after the
/// last; `None` when the machine has no console yet.
fn console_page(
    dir: &Path,
    from: u64,
    limit: usize,
) -> std::io::Result<Option<(Vec<api::LogLine>, u64)>> {
    use std::io::BufRead;
    let Some((mut pos, mut r)) = console::read_from(dir, from)? else {
        return Ok(None);
    };
    let mut lines = Vec::new();
    while lines.len() < limit {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 || !line.ends_with('\n') {
            break;
        }
        pos += n as u64;
        lines.push(parse_log_line(&line));
    }
    Ok(Some((lines, pos)))
}

fn parse_log_line(line: &str) -> api::LogLine {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some((ts, rest)) = line.split_once(' ') {
        if let Ok(t) = DateTime::parse_from_rfc3339(ts) {
            return api::LogLine {
                ts: t.with_timezone(&Utc),
                line: rest.to_string(),
            };
        }
    }
    api::LogLine {
        ts: Utc::now(),
        line: line.to_string(),
    }
}

fn port_range(s: &str) -> Result<(u16, u16), MError> {
    let bad = || invalid(format!("ingress.tcp_ports {s:?}: want \"lo-hi\""));
    let (lo, hi) = s.split_once('-').ok_or_else(bad)?;
    let lo: u16 = lo.trim().parse().map_err(|_| bad())?;
    let hi: u16 = hi.trim().parse().map_err(|_| bad())?;
    if lo == 0 || lo > hi {
        return Err(bad());
    }
    Ok((lo, hi))
}

fn host_memory_mb() -> u32 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| meminfo_total_mb(&s))
        .unwrap_or(4096)
}

/// MemTotal from `/proc/meminfo`, in MB.
fn meminfo_total_mb(text: &str) -> Option<u32> {
    text.lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| (kb / 1024) as u32)
}

/// What the host hands out when the configuration does not say: its memory less what it
/// keeps for itself and its other services (`capacity.reserved_memory_mb`, 2 GB) and less the
/// ZFS cache's ceiling when one is set (ADR 0028), at least 1 GB.
fn default_memory_mb(host_mb: u32, reserved_mb: u32, arc_max_mb: u32) -> u32 {
    host_mb
        .saturating_sub(reserved_mb)
        .saturating_sub(arc_max_mb)
        .max(1024)
}

/// Four shared vCPUs a hardware thread, less the threads kept for the host's other services
/// (`capacity.reserved_threads`), at least one thread's.
fn default_vcpus(threads: u32, reserved: u32) -> u32 {
    threads.saturating_sub(reserved).max(1) * 4
}

/// The ZFS cache's ceiling (`zfs_arc_max`, the bootstrap sets it), in MB; 0 when it is the
/// module's default, which the cache gives back under pressure.
fn arc_max_mb() -> u32 {
    std::fs::read_to_string("/sys/module/zfs/parameters/zfs_arc_max")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|b| (b >> 20) as u32)
        .unwrap_or(0)
}

/// The first IPv4 address in `ip -4 -o addr show` output.
fn inet_of(text: &str) -> Option<Ipv4Addr> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let i = f.iter().position(|w| *w == "inet")?;
    f.get(i + 1)?.split('/').next()?.parse().ok()
}

/// Whether a machine whose process ended on its own (a failure: an exit code other than 0, or
/// a probe that ended it; after `restarts` restarts in a row) is started again.
fn restarts_after_exit(policy: &api::RestartPolicy, failed: bool, restarts: u32) -> bool {
    match policy.policy.as_str() {
        "always" => true,
        "on-failure" => failed && restarts < policy.max_retries,
        _ => false,
    }
}

/// A run this long ends a crash loop: the backoff starts over at its exit (ADR 0022).
const RESET_AFTER: chrono::Duration = chrono::Duration::minutes(10);

/// The restart in a crash loop from which each one is a `crash_loop` event.
const CRASH_LOOP_AT: u32 = 3;

/// How long the `n`th restart since a run of `RESET_AFTER` waits: 10 s, doubling, at most
/// 5 minutes, as Kubernetes's CrashLoopBackOff.
fn restart_delay(n: u32) -> Duration {
    let doubled = 10u64 << n.saturating_sub(1).min(5);
    Duration::from_secs(doubled.min(300))
}

/// When a running machine goes to sleep: its last use plus its window. None while it was
/// never used or never sleeps, and for a window past every date there is (`"99999999d"`):
/// a time that never comes.
fn sleeps_at(last_used: Option<DateTime<Utc>>, window: Option<Duration>) -> Option<DateTime<Utc>> {
    let w = chrono::Duration::from_std(window?).ok()?;
    last_used?.checked_add_signed(w)
}

/// A tenant's machine the host stopped: what the daemon's start boots again.
fn stopped_by_host(r: &Record) -> bool {
    r.state == state::STOPPED && r.stopped_reason == stop::HOST && r.is_tenants()
}

/// Whether the sleep window has run out at `now`. A clock that went backwards (a last use
/// in the future) is not idle.
fn idle_past(
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

/// The uid (and gid) a jailed machine runs as: one per machine, from its place in the
/// tenant's network, so no two machines on the host share one.
fn jail_uid(base: u32, subnet_index: u32, host_num: u8) -> u32 {
    base + subnet_index * 256 + host_num as u32
}

/// The guest kernel's command line. The root disk is mounted with `discard`: what the guest
/// deletes goes back to the pool (ADR 0037).
fn boot_args(pci: bool, extra: &str) -> String {
    let mut args = format!(
        "console=ttyS0 reboot=k panic=1 root=/dev/vda rw rootfstype=ext4 rootflags=discard i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on init={}",
        image::INIT_PATH
    );
    if !pci {
        args.push_str(" pci=off");
    }
    if !extra.is_empty() {
        args.push(' ');
        args.push_str(extra);
    }
    args
}

/// The lowest host port in the ingress range no endpoint holds.
fn free_tcp_port(spec: &str, used: Vec<u16>) -> Result<u16, MError> {
    let (lo, hi) = port_range(spec)?;
    let used = used.into_iter().map(u32::from).collect();
    netw::first_free(used, lo as u32, hi as u32)
        .map(|p| p as u16)
        .ok_or_else(|| MError::Capacity("no tcp endpoint port left".into()))
}

/// The config drive: a tar archive the init reads raw, `config.json` first and the boot
/// files under `files/`, padded to a multiple of 512 bytes since Firecracker wants a drive
/// that size.
fn config_drive(r: &Record, gateway: Ipv4Addr) -> Result<Vec<u8>> {
    let mut env = r.image_config.env.clone();
    env.extend(r.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    // Docker semantics: an entrypoint given replaces the image's and drops its cmd.
    let (entrypoint, cmd) = match (&r.entrypoint, &r.cmd) {
        (Some(ep), Some(c)) => (ep.clone(), c.clone()),
        (Some(ep), None) => (ep.clone(), vec![]),
        (None, Some(c)) => (r.image_config.entrypoint.clone(), c.clone()),
        (None, None) => (
            r.image_config.entrypoint.clone(),
            r.image_config.cmd.clone(),
        ),
    };
    let mut hosts = BTreeMap::new();
    hosts.insert(r.hostname(), r.ip.clone());
    hosts.insert(r.machine_host(), r.ip.clone());
    let mut cfg = guest::Config {
        hostname: r.name.clone(),
        ip: format!("{}/24", r.ip),
        gateway: gateway.to_string(),
        dns: vec![gateway.to_string()],
        hosts,
        entrypoint,
        cmd,
        env,
        workdir: r.image_config.workdir.clone(),
        user: r.image_config.user.clone(),
        mounts: vec![],
        files: vec![],
        stop_timeout_sec: 10,
    };
    if let Some(v) = &r.volume {
        cfg.mounts.push(guest::Mount {
            device: "/dev/vdc".into(),
            path: v.mount.clone(),
            fstype: "ext4".into(),
        });
    }
    let mut files: Vec<(String, u32, Vec<u8>)> = Vec::new();
    for f in &r.files {
        let data = guest::base64_decode(&f.base64).map_err(|e| anyhow!("file {}: {e}", f.path))?;
        let mode = match &f.mode {
            Some(m) if !m.is_empty() => {
                u32::from_str_radix(m, 8).map_err(|_| anyhow!("file {}: mode {m:?}", f.path))?
            }
            _ => 0o644,
        };
        cfg.files.push(guest::FileMeta {
            path: f.path.clone(),
            mode,
        });
        files.push((f.path.clone(), mode, data));
    }
    let mut b = tar::Builder::new(Vec::new());
    let cfg_json = serde_json::to_vec(&cfg)?;
    let mut h = tar::Header::new_gnu();
    h.set_mode(0o600);
    h.set_size(cfg_json.len() as u64);
    h.set_mtime(Utc::now().timestamp() as u64);
    b.append_data(&mut h, guest::CONFIG_NAME, &cfg_json[..])?;
    for (p, mode, data) in &files {
        let mut h = tar::Header::new_gnu();
        h.set_mode(*mode);
        h.set_size(data.len() as u64);
        h.set_mtime(Utc::now().timestamp() as u64);
        b.append_data(
            &mut h,
            format!("{}{}", guest::FILES_PREFIX, p.trim_start_matches('/')),
            &data[..],
        )?;
    }
    let mut out = b.into_inner()?;
    let pad = (512 - out.len() % 512) % 512;
    out.resize(out.len() + pad, 0);
    Ok(out)
}

/// Writes a drive whole and for the daemon alone (it holds the machine's secrets): through a
/// temp file next to it, so a crash leaves the previous drive or none, never half of one.
fn write_drive(path: &Path, data: &[u8]) -> Result<()> {
    crate::store::write_private(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn log_lines() {
        let l = parse_log_line("2026-10-18T22:00:00.123456Z hello world\n");
        assert_eq!(l.line, "hello world");
        assert_eq!(l.ts.timestamp(), 1_792_360_800);
        assert_eq!(parse_log_line("no timestamp\n").line, "no timestamp");
    }

    #[test]
    fn port_ranges() {
        assert_eq!(port_range("20000-29999").unwrap(), (20000, 29999));
        assert!(port_range("29999-20000").is_err());
        assert!(port_range("x").is_err());
        assert!(port_range("0-10").is_err());
    }

    #[test]
    fn endpoint_ports() {
        assert_eq!(free_tcp_port("20000-29999", vec![]).unwrap(), 20000);
        assert_eq!(
            free_tcp_port("20000-29999", vec![20001, 20000, 20003]).unwrap(),
            20002
        );
        // A port outside the range (a stale record) does not get in the way.
        assert_eq!(
            free_tcp_port("20000-29999", vec![80, 30000]).unwrap(),
            20000
        );
        match free_tcp_port("20000-20001", vec![20000, 20001]) {
            Err(MError::Capacity(msg)) => assert_eq!(msg, "no tcp endpoint port left"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            free_tcp_port("nonsense", vec![]),
            Err(MError::Invalid(_))
        ));
    }

    fn policy(policy: &str, max_retries: u32) -> api::RestartPolicy {
        api::RestartPolicy {
            policy: policy.into(),
            max_retries,
        }
    }

    #[test]
    fn restart_decisions() {
        // on-failure: a failure restarts until the retries run out; a clean exit never.
        let p = policy("on-failure", 3);
        assert!(restarts_after_exit(&p, true, 0));
        assert!(restarts_after_exit(&p, true, 2));
        assert!(!restarts_after_exit(&p, true, 3));
        assert!(!restarts_after_exit(&p, false, 0));
        assert!(!restarts_after_exit(&policy("on-failure", 0), true, 0));
        // always: every time, whatever the code and however many times before.
        let p = policy("always", 0);
        assert!(restarts_after_exit(&p, false, 0));
        assert!(restarts_after_exit(&p, true, 1000));
        // no: never.
        assert!(!restarts_after_exit(&policy("no", 3), true, 0));
        // The default policy is on-failure with three retries.
        let d = api::RestartPolicy::default();
        assert!(restarts_after_exit(&d, true, 2));
        assert!(!restarts_after_exit(&d, true, 3));
    }

    #[test]
    fn the_backoff_doubles_to_five_minutes() {
        let secs: Vec<u64> = (1..=9).map(|n| restart_delay(n).as_secs()).collect();
        assert_eq!(secs, [10, 20, 40, 80, 160, 300, 300, 300, 300]);
        // Past any count: the cap, never an overflow.
        assert_eq!(restart_delay(u32::MAX), Duration::from_secs(300));
        assert_eq!(restart_delay(0), Duration::from_secs(10));
    }

    #[test]
    fn sleep_deadlines() {
        let t = Utc.with_ymd_and_hms(2026, 10, 18, 22, 0, 0).unwrap();
        let w = Some(Duration::from_secs(30 * 60));
        assert_eq!(
            sleeps_at(Some(t), w),
            Some(t + chrono::Duration::minutes(30))
        );
        // Never used, or never sleeps: no deadline.
        assert_eq!(sleeps_at(None, w), None);
        assert_eq!(sleeps_at(Some(t), None), None);
        // A window past every date never comes, and does not panic the view.
        let huge = api::parse_sleep("99999999d").unwrap();
        assert_eq!(sleeps_at(Some(t), huge), None);
        assert!(!idle_past(
            Some(t),
            huge,
            t + chrono::Duration::days(365 * 1000)
        ));

        let secs = |n: i64| t + chrono::Duration::seconds(n);
        assert!(!idle_past(Some(t), w, secs(0)));
        assert!(!idle_past(Some(t), w, secs(30 * 60)));
        assert!(idle_past(Some(t), w, secs(30 * 60 + 1)));
        assert!(!idle_past(None, w, secs(3600)));
        assert!(!idle_past(Some(t), None, secs(3600)));
        // A last use in the future (the clock went backwards) is not idle.
        assert!(!idle_past(Some(t), w, secs(-3600)));
    }

    #[test]
    fn a_record_knows_its_sleep_window() {
        let mut r = record();
        assert_eq!(r.sleep_window(), Some(Duration::from_secs(1800)));
        r.sleep = String::new();
        assert_eq!(r.sleep_window(), None);
        r.sleep = "never".into();
        assert_eq!(r.sleep_window(), None);
        r.sleep = "3h".into();
        assert_eq!(r.sleep_window(), Some(Duration::from_secs(3 * 3600)));
        // A value that does not parse reads as never: the API refused it at the edge.
        r.sleep = "soon".into();
        assert_eq!(r.sleep_window(), None);
    }

    #[test]
    fn jail_uids() {
        assert_eq!(jail_uid(100_000, 0, 2), 100_002);
        assert_eq!(jail_uid(100_000, 3, 254), 100_000 + 3 * 256 + 254);
        // Two machines differ in subnet or host number, never share a uid.
        assert_ne!(jail_uid(100_000, 0, 255), jail_uid(100_000, 1, 0));
    }

    #[test]
    fn kernel_command_line() {
        let a = boot_args(false, "");
        assert!(
            a.starts_with("console=ttyS0 reboot=k panic=1 root=/dev/vda rw"),
            "{a}"
        );
        assert!(a.contains(&format!("init={}", image::INIT_PATH)), "{a}");
        assert!(a.contains(" rootfstype=ext4 rootflags=discard "), "{a}");
        assert!(a.ends_with(" pci=off"), "{a}");
        let b = boot_args(true, "loglevel=3 quiet");
        assert!(!b.contains("pci=off"), "{b}");
        assert!(b.ends_with(" loglevel=3 quiet"), "{b}");
    }

    #[test]
    fn host_facts() {
        let meminfo = "MemTotal:       16318192 kB\nMemFree:         1234 kB\n";
        assert_eq!(meminfo_total_mb(meminfo), Some(15935));
        assert_eq!(meminfo_total_mb("MemFree: 1 kB\n"), None);
        assert_eq!(meminfo_total_mb(""), None);
        // 64 GB, the ARC capped at 6 GB: 56 GB for machines; no cap, 2 GB kept only.
        assert_eq!(default_memory_mb(65536, 2048, 6144), 57344);
        assert_eq!(default_memory_mb(65536, 2048, 0), 63488);
        assert_eq!(
            default_memory_mb(65536, 3072, 6144),
            56320,
            "an edge beside it"
        );
        assert_eq!(default_memory_mb(3072, 2048, 1024), 1024, "at least 1 GB");
        assert_eq!(default_vcpus(16, 0), 64);
        assert_eq!(default_vcpus(16, 2), 56);
        assert_eq!(default_vcpus(2, 4), 4, "at least one thread's");

        let addr = "2: eth0    inet 192.168.64.3/24 brd 192.168.64.255 scope global dynamic eth0\\       valid_lft 86000sec preferred_lft 86000sec\n";
        assert_eq!(inet_of(addr), Some(Ipv4Addr::new(192, 168, 64, 3)));
        assert_eq!(inet_of(""), None);
        assert_eq!(inet_of("2: eth0 inet6 fe80::1/64 scope link\n"), None);
    }

    /// A machine as the manager would have made it, in the second tenant subnet.
    fn record() -> Record {
        let now = Utc.with_ymd_and_hms(2026, 10, 18, 22, 0, 0).unwrap();
        Record {
            id: "m_abc123".into(),
            tenant: "t1".into(),
            role: None,
            name: "db".into(),
            image: "postgres:17".into(),
            image_key: "deadbeef".into(),
            image_digest: "sha256:abc".into(),
            root_key: "deadbeef".into(),
            image_config: ImageConfig {
                entrypoint: vec!["docker-entrypoint.sh".into()],
                cmd: vec!["postgres".into()],
                env: BTreeMap::from([
                    ("PATH".to_string(), "/usr/bin".to_string()),
                    ("PGDATA".to_string(), "/var/lib/postgresql/data".to_string()),
                ]),
                workdir: "/".into(),
                user: "postgres".into(),
                volumes: vec![],
                exposed_ports: vec![5432],
            },
            entrypoint: None,
            cmd: None,
            env: BTreeMap::from([("PGDATA".to_string(), "/data/pg".to_string())]),
            files: vec![],
            size: api::Size {
                vcpus: 1,
                memory_mb: 512,
            },
            volume: Some(api::VolumeSpec {
                size_gb: 2,
                mount: "/data".into(),
            }),
            ports: vec![5432],
            sleep: "30m".into(),
            restart: api::RestartPolicy::default(),
            probes: api::Probes::default(),
            egress: api::Egress::default(),
            limits: api::EgressLimits::default(),
            disk_limits: api::DiskLimits::default(),
            metadata: BTreeMap::new(),
            state: state::CREATED.into(),
            stopped_reason: String::new(),
            exit: None,
            error: String::new(),
            subnet_index: 1,
            host_num: 2,
            ip: "10.64.1.2".into(),
            pid: 0,
            restarts: 0,
            recent_restarts: 0,
            restarting_at: None,
            boots: 0,
            created_at: now,
            updated_at: now,
            state_changed_at: now,
            started_at: None,
            stopped_at: None,
            last_used_at: None,
            console_offset: 0,
            suspended: false,
            backup_bytes: 0,
            backup: Schedule::default(),
            version: 0,
            pending: None,
            pending_since: None,
            init_version: String::new(),
            vmm_version: String::new(),
            rest: Default::default(),
            snapshots: Vec::new(),
            restoring: None,
        }
    }

    /// How the next boots go: what the guest does once its process is up.
    #[derive(Clone, Debug)]
    enum Boots {
        /// The init answers ping after the delay.
        Ready(Duration),
        /// The init never answers.
        Silent,
        /// The process exits before the init answers, with the init's exit report.
        Exits(i32),
        /// The VMM panics: a bug in a transition.
        Panics,
    }

    /// A process the mock host runs: a pid, the console the manager reads, how its guest
    /// answers, and the `exited` watch the manager waits on.
    struct Proc {
        pid: u32,
        id: String,
        vsock: PathBuf,
        console: PathBuf,
        boots: Boots,
        exited: tokio::sync::watch::Sender<bool>,
        /// The init's report, sent by `exit`; dropped when the process is `gone`, so the
        /// manager's wait on it ends.
        exit: Option<tokio::sync::watch::Sender<Option<guest::ExitReport>>>,
    }

    /// The host behind the manager, running nothing: a boot makes a `Proc` under a fresh
    /// pid, the guest answers as `boots` says, TAPs are a set of names, and every call is
    /// recorded, one line each, the way the fake `zfs` records its own. Cgroups and the
    /// internet counters are values a test sets.
    struct Mock {
        boots: Mutex<Boots>,
        /// How long a guest takes to stop once asked.
        stops: Mutex<Duration>,
        next_pid: std::sync::atomic::AtomicU32,
        procs: Mutex<Vec<Proc>>,
        taps: Mutex<std::collections::BTreeSet<String>>,
        calls: Mutex<Vec<String>>,
        /// Policy calls fail, as an `nft` that refuses its input.
        refuse_policies: AtomicBool,
        /// No guest port accepts: `wait_port` answers only at its deadline.
        silent_ports: AtomicBool,
        /// Each machine's cgroup; none without an entry.
        cgroups: Mutex<HashMap<String, fc::CgroupUse>>,
        /// The counted addresses and their counters.
        counted: Mutex<BTreeMap<String, nft::Counters>>,
        /// `uncount` fails, as an `nft` that refuses its input.
        refuse_uncount: AtomicBool,
        /// What an exec of a command (its argv joined by spaces) exits with; 0 when absent.
        exec_codes: Mutex<HashMap<String, i32>>,
        /// How long an exec takes, and how many run at once now and at most.
        exec_takes: Mutex<Duration>,
        execs_now: Arc<std::sync::atomic::AtomicUsize>,
        execs_most: std::sync::atomic::AtomicUsize,
        /// The ports of an address a TCP probe finds closed; every other one accepts.
        closed: Mutex<std::collections::HashSet<(Ipv4Addr, u16)>>,
        /// What an HTTP probe of an address and port answers; 200 when absent.
        http_codes: Mutex<HashMap<(Ipv4Addr, u16), u16>>,
        /// The size each machine last booted with, as Firecracker is given it.
        booted: Mutex<HashMap<String, api::Size>>,
        /// What the VMM says it is (ADR 0027): another value is an upgraded Firecracker.
        vmm_version: Mutex<String>,
        /// The version the guests' inits answer with.
        init_version: Mutex<String>,
        /// The limits each machine's disks have now: given at boot, changed live, and
        /// whether the volume was given them too.
        disks: Mutex<HashMap<String, (fc::DiskRate, bool)>>,
        /// A live change of disk limits fails, as a Firecracker that refuses the PATCH.
        refuse_disk_rate: AtomicBool,
    }

    impl Mock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                boots: Mutex::new(Boots::Ready(Duration::ZERO)),
                stops: Mutex::new(Duration::ZERO),
                next_pid: std::sync::atomic::AtomicU32::new(1000),
                procs: Mutex::new(Vec::new()),
                taps: Mutex::new(Default::default()),
                calls: Mutex::new(Vec::new()),
                refuse_policies: AtomicBool::new(false),
                silent_ports: AtomicBool::new(false),
                cgroups: Mutex::new(HashMap::new()),
                counted: Mutex::new(BTreeMap::new()),
                refuse_uncount: AtomicBool::new(false),
                exec_codes: Mutex::new(HashMap::new()),
                exec_takes: Mutex::new(Duration::ZERO),
                execs_now: Default::default(),
                execs_most: Default::default(),
                closed: Mutex::new(Default::default()),
                http_codes: Mutex::new(HashMap::new()),
                booted: Mutex::new(HashMap::new()),
                vmm_version: Mutex::new("v1.17.0/test".into()),
                init_version: Mutex::new("0.1.0+init".into()),
                disks: Mutex::new(HashMap::new()),
                refuse_disk_rate: AtomicBool::new(false),
            })
        }

        /// An exec of `cmd` exits with `code` from now on.
        fn answers(&self, cmd: &str, code: i32) {
            self.exec_codes.lock().unwrap().insert(cmd.into(), code);
        }

        /// An HTTP probe of `ip:port` answers `code` from now on.
        fn http(&self, ip: &str, port: u16, code: u16) {
            let ip = ip.parse().unwrap();
            self.http_codes.lock().unwrap().insert((ip, port), code);
        }

        fn cpu(&self, id: &str, usec: u64) {
            self.cgroups
                .lock()
                .unwrap()
                .entry(id.into())
                .or_default()
                .cpu_usec = usec;
        }

        fn memory(&self, id: &str, bytes: u64) {
            self.cgroups
                .lock()
                .unwrap()
                .entry(id.into())
                .or_default()
                .memory_bytes = bytes;
        }

        /// Traffic of a counted address, as the forward chain would count it.
        fn internet(&self, ip: &str, inb: u64, out: u64) {
            let mut c = self.counted.lock().unwrap();
            let n = c.get_mut(ip).expect("a counted address");
            n.internet_in += inb;
            n.internet_out += out;
        }

        /// Packets the limits dropped for a counted address, as the forward chain would count
        /// them.
        fn dropped(&self, ip: &str, port: u64, rate: u64, bandwidth: u64) {
            let mut c = self.counted.lock().unwrap();
            let d = &mut c.get_mut(ip).expect("a counted address").dropped;
            d.blocked_port += port;
            d.rate += rate;
            d.bandwidth += bandwidth;
        }

        fn boots(&self, b: Boots) {
            *self.boots.lock().unwrap() = b;
        }

        fn stops_take(&self, d: Duration) {
            *self.stops.lock().unwrap() = d;
        }

        fn record(&self, line: String) {
            self.calls.lock().unwrap().push(line);
        }

        /// The calls so far, then forgets them.
        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }

        /// The pids whose process has not exited.
        fn alive(&self) -> Vec<u32> {
            self.procs
                .lock()
                .unwrap()
                .iter()
                .filter(|p| !*p.exited.borrow())
                .map(|p| p.pid)
                .collect()
        }

        /// Makes a process as a previous daemon would have left it: up, nobody's child.
        fn left_running(&self, id: &str, dir: &Path) -> u32 {
            let (_, vsock, console, _) = fc::paths(dir);
            let pid = self
                .next_pid
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.procs.lock().unwrap().push(Proc {
                pid,
                id: id.into(),
                vsock,
                console,
                boots: Boots::Ready(Duration::ZERO),
                exited: tokio::sync::watch::channel(false).0,
                exit: Some(tokio::sync::watch::channel(None).0),
            });
            pid
        }

        /// A line on the process's console, stamped as the daemon stamps them.
        fn say(&self, pid: u32, line: &str) {
            let procs = self.procs.lock().unwrap();
            let p = procs.iter().find(|p| p.pid == pid).expect("a process");
            let _ = std::fs::create_dir_all(p.console.parent().unwrap());
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p.console)
                .unwrap();
            use std::io::Write;
            let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            writeln!(f, "{ts} {line}").unwrap();
        }

        /// The process ends as the init would end it: the trace on its console, its report
        /// to the host, then gone.
        fn exit(&self, pid: u32, code: i32, requested: bool) {
            self.say(
                pid,
                &format!("[briqyard] exit code={code} oom=false requested={requested}"),
            );
            let procs = self.procs.lock().unwrap();
            if let Some(tx) = procs
                .iter()
                .find(|p| p.pid == pid)
                .and_then(|p| p.exit.as_ref())
            {
                let _ = tx.send(Some(guest::ExitReport {
                    code,
                    oom: false,
                    requested,
                }));
            }
            drop(procs);
            self.gone(pid);
        }

        /// The process is gone: no report can come after this.
        fn gone(&self, pid: u32) {
            let mut procs = self.procs.lock().unwrap();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.exit = None;
                let _ = p.exited.send(true);
            }
        }

        /// A live process's report channel.
        fn exit_of(p: &Proc) -> tokio::sync::watch::Receiver<Option<guest::ExitReport>> {
            p.exit.as_ref().expect("a live process").subscribe()
        }

        /// The live process behind a vsock path.
        fn proc_at(
            &self,
            vsock: &Path,
        ) -> Result<(u32, Boots, tokio::sync::watch::Receiver<bool>)> {
            let procs = self.procs.lock().unwrap();
            procs
                .iter()
                .rev()
                .find(|p| p.vsock == vsock)
                .map(|p| (p.pid, p.boots.clone(), p.exited.subscribe()))
                .ok_or_else(|| anyhow!("vsock {}: no process", vsock.display()))
        }
    }

    #[async_trait::async_trait]
    impl fc::Vmm for Mock {
        async fn boot(&self, b: &fc::Boot) -> Result<fc::Vm> {
            let boots = self.boots.lock().unwrap().clone();
            self.record(format!("boot {} tap={} resume={}", b.id, b.tap, b.resume));
            let size = api::Size {
                vcpus: b.vcpus,
                memory_mb: b.memory_mb,
            };
            self.booted.lock().unwrap().insert(b.id.clone(), size);
            self.disks
                .lock()
                .unwrap()
                .insert(b.id.clone(), (b.disk, b.data.is_some()));
            if let Boots::Panics = boots {
                panic!("the VMM panicked");
            }
            tokio::fs::create_dir_all(&b.dir).await?;
            let (api, vsock, console, _) = fc::paths(&b.dir);
            let snapshot = b.dir.join("snap.mem");
            let resumed = b.resume && snapshot.exists();
            let _ = std::fs::remove_file(&snapshot);
            let _ = std::fs::remove_file(b.dir.join("snap.state"));
            let pid = self
                .next_pid
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (exited, rx) = tokio::sync::watch::channel(false);
            let (exit_tx, exit) = tokio::sync::watch::channel(None);
            self.procs.lock().unwrap().push(Proc {
                pid,
                id: b.id.clone(),
                vsock: vsock.clone(),
                console,
                boots: boots.clone(),
                exited,
                exit: Some(exit_tx),
            });
            if let Boots::Exits(code) = boots {
                self.exit(pid, code, false);
            }
            Ok(fc::Vm {
                pid,
                api,
                vsock,
                dir: b.dir.clone(),
                chroot: None,
                resumed,
                exited: rx,
                exit,
            })
        }

        async fn adopt(
            &self,
            id: &str,
            dir: &Path,
            _jail: Option<&fc::Jail>,
            pid: u32,
            _disk_io: Arc<fc::DiskIo>,
        ) -> Option<fc::Vm> {
            self.record(format!("adopt {id} {pid}"));
            let procs = self.procs.lock().unwrap();
            let p = procs
                .iter()
                .find(|p| p.pid == pid && p.id == id && !*p.exited.borrow())?;
            let (api, _, _, _) = fc::paths(dir);
            Some(fc::Vm {
                pid,
                api,
                vsock: p.vsock.clone(),
                dir: dir.to_path_buf(),
                chroot: None,
                resumed: false,
                exited: p.exited.subscribe(),
                exit: Self::exit_of(p),
            })
        }

        async fn disk_rate(&self, vm: &fc::Vm, rate: &fc::DiskRate, volume: bool) -> Result<()> {
            self.record(format!(
                "disk-rate {} {}mb {}iops",
                vm.pid, rate.bandwidth_mb, rate.iops
            ));
            if self.refuse_disk_rate.load(Relaxed) {
                anyhow::bail!("firecracker: 400 drive update refused");
            }
            let id = self.machine_of(vm.pid).unwrap();
            self.disks.lock().unwrap().insert(id, (*rate, volume));
            Ok(())
        }

        async fn snapshot(&self, vm: &fc::Vm, durable: bool) -> Result<()> {
            let how = if durable { "synced" } else { "unsynced" };
            self.record(format!("snapshot {} {how}", vm.pid));
            std::fs::write(vm.dir.join("snap.state"), b"state")?;
            std::fs::write(vm.dir.join("snap.mem"), b"memory")?;
            Ok(())
        }

        async fn resume(&self, vm: &fc::Vm) -> Result<()> {
            self.record(format!("resume {}", vm.pid));
            Ok(())
        }

        fn kill(&self, pid: u32) {
            self.record(format!("kill {pid}"));
            self.gone(pid);
        }

        fn machine_of(&self, pid: u32) -> Option<String> {
            self.processes()
                .into_iter()
                .find(|(p, _)| *p == pid)
                .map(|(_, id)| id)
        }

        fn processes(&self) -> Vec<(u32, String)> {
            self.procs
                .lock()
                .unwrap()
                .iter()
                .filter(|p| !*p.exited.borrow())
                .map(|p| (p.pid, p.id.clone()))
                .collect()
        }

        async fn cgroup(&self, id: &str) -> Option<fc::CgroupUse> {
            self.cgroups.lock().unwrap().get(id).copied()
        }

        fn version(&self) -> String {
            self.vmm_version.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl guestc::Guest for Mock {
        /// Answers as the real wait does: only at the deadline when the init is silent.
        async fn wait_ready(&self, vsock: &Path, timeout: Duration) -> Result<String> {
            let (pid, boots, exited) = self.proc_at(vsock)?;
            self.record(format!("wait_ready {pid}"));
            let answers = async {
                if let Boots::Ready(after) = boots {
                    tokio::time::sleep(after).await;
                    if !*exited.borrow() {
                        return;
                    }
                }
                std::future::pending::<()>().await
            };
            tokio::time::timeout(timeout, answers)
                .await
                .map_err(|_| anyhow!("guest init did not answer within {timeout:?}"))?;
            Ok(self.init_version.lock().unwrap().clone())
        }

        async fn shutdown(&self, vsock: &Path, grace: Duration) -> Result<()> {
            let (pid, _, _) = self.proc_at(vsock)?;
            self.record(format!("shutdown {pid} {}s", grace.as_secs()));
            let takes = *self.stops.lock().unwrap();
            tokio::time::sleep(takes).await;
            self.exit(pid, 0, true);
            Ok(())
        }

        /// The init, reduced. A command (not `interactive`): `ok` on stdout (`no` on stderr too
        /// when it fails) after `exec_takes`, its code from `exec_codes`. A session: each
        /// `stdin` frame back as stdout, a `resize` as a `COLSxROWS` line, its code at
        /// `close_stdin`.
        async fn session(
            &self,
            vsock: &Path,
            req: guest::Request,
        ) -> Result<Box<dyn guestc::Conn>> {
            use std::sync::atomic::Ordering::SeqCst;
            use tokio::io::AsyncWriteExt;
            let (pid, _, _) = self.proc_at(vsock)?;
            let cmd = req.cmd.join(" ");
            let code = self.exec_codes.lock().unwrap().get(&cmd).copied();
            let (ours, theirs) = tokio::io::duplex(1 << 16);
            if !req.interactive {
                self.record(format!("exec {pid} {cmd}"));
                let now = self.execs_now.fetch_add(1, SeqCst) + 1;
                self.execs_most.fetch_max(now, SeqCst);
                let takes = *self.exec_takes.lock().unwrap();
                let running = self.execs_now.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(takes).await;
                    running.fetch_sub(1, SeqCst);
                    let code = code.unwrap_or(0);
                    let mut out = vec![guest::Response::chunk("stdout", b"ok\n".to_vec())];
                    if code != 0 {
                        out.push(guest::Response::chunk("stderr", b"no\n".to_vec()));
                    }
                    out.push(guest::Response::exit(code, false));
                    let mut theirs = theirs;
                    for r in out {
                        let _ = theirs.write_all(&guest::encode_frame(&r).unwrap()).await;
                    }
                });
                return Ok(Box::new(ours));
            }
            self.record(format!("session {pid} {cmd} tty={}", req.tty));
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(theirs);
                while let Ok(f) = guestc::read_frame::<_, guest::Request>(&mut rd).await {
                    let out = match f.op.as_str() {
                        "stdin" => guest::Response::chunk("stdout", f.data),
                        "resize" => guest::Response::chunk(
                            "stdout",
                            format!("{}x{}\n", f.cols, f.rows).into_bytes(),
                        ),
                        "close_stdin" => guest::Response::exit(code.unwrap_or(0), false),
                        _ => continue,
                    };
                    let last = out.kind == "exit";
                    let frame = guest::encode_frame(&out).unwrap();
                    if wr.write_all(&frame).await.is_err() || last {
                        break;
                    }
                }
            });
            Ok(Box::new(ours))
        }

        async fn put(&self, vsock: &Path, path: &str, mode: u32, data: Vec<u8>) -> Result<()> {
            let (pid, _, _) = self.proc_at(vsock)?;
            self.record(format!("put {pid} {path} {mode:o} {}b", data.len()));
            Ok(())
        }

        async fn get(&self, vsock: &Path, path: &str) -> Result<Vec<u8>> {
            let (pid, _, _) = self.proc_at(vsock)?;
            self.record(format!("get {pid} {path}"));
            Ok(b"content".to_vec())
        }
    }

    #[async_trait::async_trait]
    impl host::Net for Mock {
        async fn ensure_bridge(&self, s: &Subnet) -> Result<String> {
            let name = netw::bridge_name(s.index);
            self.record(format!("ensure_bridge {name} {}", s.cidr()));
            Ok(name)
        }

        async fn delete_bridge(&self, index: u32) -> Result<()> {
            self.record(format!("delete_bridge {}", netw::bridge_name(index)));
            Ok(())
        }

        async fn ensure_tap(&self, machine_id: &str, bridge: &str, ip: &str) -> Result<String> {
            let name = netw::tap_name(machine_id);
            self.record(format!("ensure_tap {name} {bridge} {ip}"));
            self.taps.lock().unwrap().insert(name.clone());
            Ok(name)
        }

        async fn delete_tap(&self, machine_id: &str, ip: &str) -> Result<()> {
            let name = netw::tap_name(machine_id);
            self.record(format!("delete_tap {name} {ip}"));
            self.taps.lock().unwrap().remove(&name);
            Ok(())
        }

        async fn delete_link(&self, name: &str) -> Result<()> {
            self.record(format!("delete_link {name}"));
            self.taps.lock().unwrap().remove(name);
            Ok(())
        }

        async fn list_taps(&self) -> Result<Vec<String>> {
            Ok(self.taps.lock().unwrap().iter().cloned().collect())
        }

        async fn set_policy(&self, p: &nft::Policy) -> Result<()> {
            self.policy_call(format!("set_policy {}", policy_line(p)))
        }

        async fn unset_policy(&self, p: &nft::Policy) -> Result<()> {
            self.policy_call(format!("unset_policy {}", policy_line(p)))
        }

        async fn swap_policy(&self, old: &nft::Policy, new: &nft::Policy) -> Result<()> {
            let (old, new) = (policy_line(old), policy_line(new));
            self.policy_call(format!("swap_policy {old} -> {new}"))
        }

        /// Like nft: again keeps the counts.
        async fn count(&self, ip: &str) -> Result<()> {
            self.counted.lock().unwrap().entry(ip.into()).or_default();
            Ok(())
        }

        async fn uncount(&self, ip: &str) -> Result<()> {
            if self.refuse_uncount.load(Relaxed) {
                return Err(anyhow!("nft: refused"));
            }
            self.counted.lock().unwrap().remove(ip);
            Ok(())
        }

        async fn counters(&self) -> Result<HashMap<String, nft::Counters>> {
            Ok(self.counted.lock().unwrap().clone().into_iter().collect())
        }

        async fn wait_port(&self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<()> {
            self.record(format!("wait_port {ip}:{port}"));
            if self.silent_ports.load(Relaxed) {
                tokio::time::sleep(timeout).await;
                return Err(anyhow!("{ip}:{port} did not accept within {timeout:?}"));
            }
            Ok(())
        }

        async fn probe_tcp(&self, ip: Ipv4Addr, port: u16, _timeout: Duration) -> Result<()> {
            self.record(format!("probe_tcp {ip}:{port}"));
            match self.closed.lock().unwrap().contains(&(ip, port)) {
                true => Err(anyhow!("{ip}:{port}: Connection refused")),
                false => Ok(()),
            }
        }

        async fn probe_http(
            &self,
            ip: Ipv4Addr,
            port: u16,
            path: &str,
            _timeout: Duration,
        ) -> Result<u16> {
            self.record(format!("probe_http {ip}:{port}{path}"));
            Ok(*self
                .http_codes
                .lock()
                .unwrap()
                .get(&(ip, port))
                .unwrap_or(&200))
        }
    }

    impl Mock {
        fn policy_call(&self, line: String) -> Result<()> {
            self.record(line);
            if self.refuse_policies.load(Relaxed) {
                return Err(anyhow!("nft: refused"));
            }
            Ok(())
        }
    }

    /// A policy as the mock records it.
    fn policy_line(p: &nft::Policy) -> String {
        match p {
            nft::Policy::Via { ip, to, host } => format!("via {ip} to {to} host {host}"),
            nft::Policy::None { ip } => format!("none {ip}"),
            nft::Policy::Open { ip, limits: l } => format!(
                "open {ip} ports {:?} conn {} mbit {}",
                l.blocked_ports, l.new_connections_per_minute, l.bandwidth_mbit
            ),
        }
    }

    /// A manager over a temp directory, the fake `zfs` and the mock host: every transition
    /// runs, and what it did to the disks, the processes and the network is on record.
    pub(super) struct Harness {
        pub(super) pool: crate::zfs::fake::Fake,
        host: Arc<Mock>,
        _dir: tempfile::TempDir,
        pub(super) m: Manager,
    }

    async fn harness(range: &str, memory_mb: u32) -> Harness {
        // No host limits: an open machine puts nothing in the tables, and the calls the tests
        // read are the pin's and the policy's alone. The limits' tests set theirs.
        harness_with(range, memory_mb, no_limits()).await
    }

    /// No limit at all.
    fn no_limits() -> crate::config::EgressLimits {
        crate::config::EgressLimits {
            blocked_ports: vec![],
            new_connections_per_minute: 0,
            bandwidth_mbit: 0,
        }
    }

    /// A harness whose host limits every open machine's internet traffic with these.
    async fn harness_with(
        range: &str,
        memory_mb: u32,
        egress_limits: crate::config::EgressLimits,
    ) -> Harness {
        harness_config(|cfg| {
            cfg.network.range = range.into();
            cfg.capacity = crate::config::Capacity {
                memory_mb,
                vcpus: 1000,
                ..Default::default()
            };
            cfg.egress_limits = egress_limits;
        })
        .await
    }

    /// A harness on a configuration `f` changes; its data directory is the harness's.
    pub(super) async fn harness_config(f: impl FnOnce(&mut Config)) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let fake = crate::zfs::fake::Fake::open("byard").await.unwrap();
        let init = dir.path().join("init");
        std::fs::write(&init, b"init").unwrap();
        let mut cfg = Config {
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        f(&mut cfg);
        let zfs = fake.zfs.clone();
        let mut images = Builder::new(zfs.clone(), cfg.image_dir(), init, 8, vec![]).unwrap();
        let store = Store::open(&cfg.state_dir()).unwrap();
        let events = Events::open(&store.dir("events")).unwrap();
        images.events = Some(events.clone());
        let (endpoint_events, _) = broadcast::channel(64);
        let host = Mock::new();
        let backups = Backups::open(&cfg.backup, &store).unwrap();
        let m = Manager {
            inner: Arc::new(Inner {
                stats: Stats::default(),
                range: Range::parse(&cfg.network.range).unwrap(),
                cfg,
                store,
                zfs,
                images,
                dns: Resolver::new(&["127.0.0.1".into()]),
                vmm: host.clone(),
                guest: host.clone(),
                net: host.clone(),
                egress: "lo".into(),
                host_id: "h_test".into(),
                advertise: "127.0.0.1".into(),
                machines: Mutex::new(HashMap::new()),
                tenants: Mutex::new(HashMap::new()),
                endpoints: Mutex::new(HashMap::new()),
                endpoint_events,
                policies: Mutex::new(HashMap::new()),
                tenant_create: tokio::sync::Mutex::new(()),
                backups,
                boot_gate: tokio::sync::Semaphore::new(2),
                probe_gate: tokio::sync::Semaphore::new(probes::PROBES_AT_ONCE),
                usage: Mutex::new(Ledger::default()),
                events,
                pool: Mutex::new(None),
                conditions: Mutex::new(Conditions::new(Utc::now())),
                started: Mutex::new(api::DaemonStart::default()),
            }),
        };
        fake.calls();
        Harness {
            pool: fake,
            host,
            _dir: dir,
            m,
        }
    }

    /// An image reference that pins a digest: `ensure` asks no registry for it.
    const IMAGE: &str =
        "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000001";

    impl Harness {
        /// Registers a machine in `state`, as if loaded, and returns its entry.
        pub(super) fn add(&self, id: &str, state: &str, memory_mb: u32) -> Arc<Entry> {
            let mut r = record();
            r.id = id.into();
            r.state = state.into();
            r.size.memory_mb = memory_mb;
            let e = Entry::new(r, self.m.inner.events.clone());
            self.m
                .inner
                .machines
                .lock()
                .unwrap()
                .insert(id.into(), e.clone());
            e
        }

        /// A tenant with its network known, as `load` would have it; the first takes subnet
        /// index 1, where `record()` puts its machine. Nothing is plumbed: the bridge and the
        /// gateway's DNS listener need the host.
        fn tenant(&self, id: &str) -> Tenant {
            let mut tenants = self.m.inner.tenants.lock().unwrap();
            let idx = tenants.len() as u32 + 1;
            let t = Tenant::new(
                TenantRec {
                    id: id.into(),
                    subnet_index: idx,
                    created_at: Utc::now(),
                    quota: api::Quota::default(),
                },
                self.m.inner.range.subnet(idx).unwrap(),
            );
            tenants.insert(id.into(), t.clone());
            t
        }

        /// The disks of an added machine, on the fake pool.
        pub(super) async fn disks(&self, e: &Entry) {
            let r = e.snapshot();
            let z = &self.pool.zfs;
            z.create(&r.root_dataset(), 1 << 20).await.unwrap();
            if r.volume.is_some() {
                z.create(&r.data_dataset(), 1 << 20).await.unwrap();
            }
        }

        /// A create request in tenant `t1` from the seeded image, started unless told
        /// otherwise; no volume, since a volume is formatted with the host's `mkfs.ext4`.
        pub(super) fn request(&self, name: &str) -> api::CreateMachineRequest {
            api::CreateMachineRequest {
                tenant: "t1".into(),
                name: name.into(),
                image: IMAGE.into(),
                size: api::Size {
                    vcpus: 1,
                    memory_mb: 256,
                },
                sleep: "30m".into(),
                ..Default::default()
            }
        }

        /// Tenant `t1` and the image in place, so a `request` can be created.
        pub(super) async fn ready(&self) {
            self.tenant("t1");
            self.m
                .inner
                .images
                .seed(IMAGE, ImageConfig::default())
                .await
                .unwrap();
            self.pool.calls();
        }

        /// Each stop takes this long on the host from now on.
        pub(super) fn stops_take(&self, d: Duration) {
            self.host.stops_take(d);
        }

        /// The host's Firecracker and kernel from now on (ADR 0027): another one is an upgrade.
        pub(super) fn set_vmm_version(&self, v: &str) {
            *self.host.vmm_version.lock().unwrap() = v.into();
        }

        /// The host's calls so far (boots, snapshots, kills), then forgets them.
        pub(super) fn host_calls(&self) -> Vec<String> {
            self.host.calls()
        }

        /// The machine's record as the store has it.
        pub(super) fn stored(&self, id: &str) -> Option<Record> {
            self.m.inner.store.get("machines", id).unwrap()
        }
    }

    #[tokio::test]
    async fn a_reservation_is_one_step() {
        // Eight starts race for the memory of two: never more than two may take it,
        // however they interleave.
        for _ in 0..20 {
            let h = harness("10.64.0.0/22", 1024).await;
            let entries: Vec<Arc<Entry>> = (0..8)
                .map(|i| h.add(&format!("m_{i}"), state::STOPPED, 512))
                .collect();
            let admitted = std::thread::scope(|s| {
                let handles: Vec<_> = entries
                    .iter()
                    .map(|e| s.spawn(|| h.m.reserve(e, None).is_ok()))
                    .collect();
                handles
                    .into_iter()
                    .map(|j| j.join().unwrap())
                    .filter(|ok| *ok)
                    .count()
            });
            assert_eq!(admitted, 2);
            let (used, up, _) = h.m.usage();
            assert_eq!((used.memory_mb, up), (1024, 2));
        }
        // What was admitted is `starting`; what was not is untouched.
        let h = harness("10.64.0.0/22", 512).await;
        let a = h.add("m_a", state::STOPPED, 512);
        let b = h.add("m_b", state::STOPPED, 512);
        assert!(h.m.reserve(&a, None).is_ok());
        assert!(matches!(h.m.reserve(&b, None), Err(MError::Capacity(_))));
        assert_eq!(a.snapshot().state, state::STARTING);
        assert_eq!(b.snapshot().state, state::STOPPED);
        // A machine on its way down still holds its memory.
        a.set_state(state::STOPPING, |_| None);
        assert!(matches!(h.m.reserve(&b, None), Err(MError::Capacity(_))));
        assert!(admit(0, 100, 100).is_ok());
        assert!(admit(1, 100, 100).is_err());
        assert!(admit(u32::MAX, u32::MAX, 1).is_err());
    }

    #[tokio::test]
    async fn a_machine_being_destroyed_is_not_started() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_d", state::DESTROYING, 512);
        for r in [
            h.m.start("m_d", None).await,
            h.m.wake("m_d", None).await,
            h.m.start_entry(&e, true)
                .await
                .map(|_| h.m.get("m_d").unwrap()),
        ] {
            match r {
                Err(MError::BadState(s)) => assert_eq!(s, state::DESTROYING),
                other => panic!("{other:?}"),
            }
        }
        // Refused before anything was touched: still destroying, no error recorded.
        let r = e.snapshot();
        assert_eq!(
            (r.state.as_str(), r.error.as_str()),
            (state::DESTROYING, "")
        );
    }

    #[tokio::test]
    async fn wait_for_running_follows_the_state() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_w", state::STARTING, 512);
        let m = h.m.clone();
        let waiting =
            tokio::spawn(
                async move { m.wait("m_w", Until::Running, Duration::from_secs(30)).await },
            );
        e.set_state(state::RUNNING, |_| None);
        assert_eq!(waiting.await.unwrap().unwrap().state, state::RUNNING);

        let e = h.add("m_e", state::STARTING, 512);
        let m = h.m.clone();
        let waiting =
            tokio::spawn(
                async move { m.wait("m_e", Until::Running, Duration::from_secs(30)).await },
            );
        e.set_state(state::ERROR, |r| {
            r.error = "no init".into();
            None
        });
        match waiting.await.unwrap() {
            Err(MError::NotRunning(why)) => assert_eq!(why, "no init"),
            other => panic!("{other:?}"),
        }
        // Already settled: answered at once, without a change to wait for.
        assert_eq!(
            h.m.wait("m_w", Until::Running, Duration::from_secs(30))
                .await
                .unwrap()
                .state,
            state::RUNNING
        );
        assert!(matches!(
            h.m.wait("m_x", Until::Running, Duration::from_secs(1))
                .await,
            Err(MError::NotFound)
        ));
    }

    #[test]
    fn wait_decisions() {
        let m = |state: &str, reason: &str, restarting: bool| api::Machine {
            state: state.into(),
            stopped_reason: reason.into(),
            error: "why".into(),
            exit: Some(api::Exit {
                code: 1,
                oom_killed: false,
                at: Utc::now(),
                restarting,
            }),
            ..Default::default()
        };
        assert_eq!(will_run(&m(state::RUNNING, "", false)), Some(Ok(())));
        assert_eq!(
            will_run(&m(state::ERROR, "", false)),
            Some(Err("why".into()))
        );
        assert_eq!(
            will_run(&m(state::DESTROYING, "", false)),
            Some(Err("destroying".into()))
        );
        assert_eq!(
            will_run(&m(state::STOPPED, stop::USER, false)),
            Some(Err("stopped (user)".into()))
        );
        assert_eq!(
            will_run(&m(state::STOPPED, stop::EXIT, false)),
            Some(Err("stopped (exit)".into()))
        );
        // A process that exited and is being restarted will run: keep waiting.
        assert_eq!(will_run(&m(state::STOPPED, stop::EXIT, true)), None);
        assert_eq!(will_run(&m(state::STARTING, "", false)), None);
        assert_eq!(will_run(&m(state::STOPPING, "", false)), None);
    }

    #[test]
    fn wait_for_ready_decisions() {
        let m = |state: &str, ready: bool| api::Machine {
            id: "m_1".into(),
            state: state.into(),
            ready,
            error: "why".into(),
            ..Default::default()
        };
        let verdict = |m: &api::Machine, until| match wait_verdict(m, until) {
            None => "wait".to_string(),
            Some(Ok(())) => "ok".to_string(),
            Some(Err(MError::BootFailed(_))) => "boot_failed".to_string(),
            Some(Err(MError::NotRunning(why))) => format!("not_running: {why}"),
            Some(Err(other)) => format!("{other:?}"),
        };
        // Running is enough for `running`; `ready` waits for the probes.
        assert_eq!(verdict(&m(state::RUNNING, false), Until::Running), "ok");
        assert_eq!(verdict(&m(state::RUNNING, false), Until::Ready), "wait");
        assert_eq!(verdict(&m(state::RUNNING, true), Until::Ready), "ok");
        // In `error`, a wait for ready answers as the boot did; for running, as before.
        assert_eq!(
            verdict(&m(state::ERROR, false), Until::Ready),
            "boot_failed"
        );
        assert_eq!(
            verdict(&m(state::ERROR, false), Until::Running),
            "not_running: why"
        );
        assert_eq!(verdict(&m(state::STARTING, false), Until::Ready), "wait");
        assert_eq!(
            verdict(&m(state::DESTROYING, false), Until::Ready),
            "not_running: destroying"
        );
        // Why it is not ready: the probes that have not passed, else that none has run.
        let mut r = m(state::RUNNING, false);
        assert_eq!(not_ready_why(&r), "its probes have not passed yet");
        let st = |passed, message: &str| api::ProbeStatus {
            passed,
            message: message.into(),
            failures: 1,
            at: Utc::now(),
        };
        r.probes_status.startup = Some(st(true, "exit 0"));
        r.probes_status.readiness = Some(st(false, "HTTP 503"));
        assert_eq!(not_ready_why(&r), "readiness: HTTP 503");
    }

    #[tokio::test]
    async fn state_changed_at_moves_only_with_the_state() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_s", state::STOPPED, 512);
        let t0 = e.snapshot().state_changed_at;
        e.set_state(state::STOPPED, |r| {
            r.stopped_reason = stop::USER.into();
            None
        });
        e.touch();
        let r = e.snapshot();
        assert_eq!(r.state_changed_at, t0);
        // A use is not a change to the machine; a write of one is.
        assert_eq!(r.updated_at, t0);
        h.m.save(&e).unwrap();
        assert!(e.snapshot().updated_at > t0);
        e.set_state(state::STARTING, |_| None);
        let r = e.snapshot();
        assert!(r.state_changed_at > t0);
        assert_eq!(h.m.get("m_s").unwrap().state_changed_at, r.state_changed_at);
    }

    #[test]
    fn records_from_before_are_migrated() {
        let mut r = record();
        r.sleep = String::new();
        r.state_changed_at = DateTime::<Utc>::default();
        r.root_key.clear();
        r.migrate();
        assert_eq!(r.sleep, "never");
        assert_eq!(r.state_changed_at, r.updated_at);
        assert_eq!(
            r.root_key, r.image_key,
            "the root disk was made from its image"
        );
        // A current record is left alone.
        let mut r = record();
        r.state_changed_at = r.updated_at + chrono::Duration::seconds(5);
        r.root_key = "older".into();
        let before = r.clone();
        r.migrate();
        assert_eq!(r.sleep, before.sleep);
        assert_eq!(r.state_changed_at, before.state_changed_at);
        assert_eq!(r.root_key, "older");
        // One representation of "never", whatever the API was sent.
        assert_eq!(sleep_setting(""), "never");
        assert_eq!(sleep_setting("  "), "never");
        assert_eq!(sleep_setting("never"), "never");
        assert_eq!(sleep_setting(" 30m "), "30m");
    }

    #[tokio::test]
    async fn sleep_is_stored_as_the_api_says_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.add("m_n", state::STOPPED, 512);
        let set = |sleep: &str| api::UpdateMachineRequest {
            sleep: Some(sleep.into()),
            ..Default::default()
        };
        assert_eq!(
            h.m.update("m_n", set("never"), None).await.unwrap().sleep,
            "never"
        );
        assert_eq!(
            h.m.update("m_n", set(""), None).await.unwrap().sleep,
            "never"
        );
        assert_eq!(
            h.m.update("m_n", set("3h"), None).await.unwrap().sleep,
            "3h"
        );
        assert!(matches!(
            h.m.update("m_n", set("soon"), None).await,
            Err(MError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn a_tenant_outside_the_range_is_refused_at_load() {
        let h = harness("10.64.0.0/22", 4096).await;
        let t = TenantRec {
            id: "t1".into(),
            subnet_index: 4,
            created_at: Utc::now(),
            quota: api::Quota::default(),
        };
        h.m.inner.store.put("tenants", "t1", &t).unwrap();
        let err = h.m.load().unwrap_err();
        assert!(format!("{err:#}").contains("tenant t1"), "{err:#}");
        assert!(h.m.inner.tenants.lock().unwrap().is_empty());
        // In range: loaded with its subnet.
        let t = TenantRec {
            subnet_index: 3,
            ..t
        };
        h.m.inner.store.put("tenants", "t1", &t).unwrap();
        h.m.load().unwrap();
        assert_eq!(h.m.tenants()[0].router, "10.64.3.1");
    }

    #[tokio::test]
    async fn an_endpoint_port_outside_the_range_is_refused_at_load() {
        // A port the daemon's table does not keep for allowed_clients: refused, not opened.
        let h = harness_config(|c| c.ingress.tcp_ports = "30000-32767".into()).await;
        let ep = EndpointRec {
            id: "ep_1".into(),
            machine_id: "m_1".into(),
            tenant: "t1".into(),
            port: 5432,
            protocol: "tcp".into(),
            host_port: Some(20001),
            host: String::new(),
            created_at: Utc::now(),
        };
        h.m.inner.store.put("endpoints", "ep_1", &ep).unwrap();
        let err = format!("{:#}", h.m.load().unwrap_err());
        assert_eq!(
            err,
            "endpoint ep_1 (machine m_1) holds host port 20001, outside ingress.tcp_ports \
             30000-32767: put the range back, or remove the endpoint"
        );
        assert!(h.m.inner.endpoints.lock().unwrap().is_empty());
        let ep = EndpointRec {
            host_port: Some(30001),
            ..ep
        };
        h.m.inner.store.put("endpoints", "ep_1", &ep).unwrap();
        h.m.load().unwrap();
        assert_eq!(h.m.all_endpoints().len(), 1);
    }

    #[tokio::test]
    async fn a_tenant_id_is_checked_before_it_names_a_file() {
        let h = harness("10.64.0.0/22", 4096).await;
        for bad in ["", "../x", "a/b", "A"] {
            let req = api::CreateMachineRequest {
                tenant: bad.into(),
                name: "db".into(),
                image: "alpine".into(),
                size: api::Size {
                    vcpus: 1,
                    memory_mb: 256,
                },
                ..Default::default()
            };
            assert!(
                matches!(h.m.create(req).await, Err(MError::Invalid(_))),
                "{bad}"
            );
            assert!(
                matches!(h.m.delete_tenant(bad).await, Err(MError::Invalid(_))),
                "{bad}"
            );
            assert!(
                matches!(h.m.backups(bad).await, Err(MError::Invalid(_))),
                "{bad}"
            );
        }
        // A tenant that does not exist is simply gone.
        assert!(h.m.delete_tenant("t-none").await.is_ok());
    }

    #[tokio::test]
    async fn a_detached_transition_outlives_its_caller() {
        let go = Arc::new(Notify::new());
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (g, d) = (go.clone(), done.clone());
        let caller = tokio::spawn(async move {
            detached(async move {
                g.notified().await;
                d.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<(), MError>(())
            })
            .await
        });
        tokio::task::yield_now().await;
        // The client hangs up: the wait goes, the work does not.
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        go.notify_one();
        tokio::task::yield_now().await;
        assert!(done.load(std::sync::atomic::Ordering::SeqCst));
        // The task's own result comes back as is; a panic in it is an internal error.
        assert!(matches!(
            detached(async { Err::<(), MError>(MError::NotFound) }).await,
            Err(MError::NotFound)
        ));
        assert!(matches!(
            detached::<(), _>(async { panic!("boom") }).await,
            Err(MError::Other(_))
        ));
    }

    #[test]
    fn the_advertised_address() {
        let ip = Some(Ipv4Addr::new(192, 168, 64, 3));
        assert_eq!(advertise_address("10.0.0.5", "0.0.0.0", ip), "10.0.0.5");
        assert_eq!(advertise_address("", "10.0.0.5", ip), "10.0.0.5");
        assert_eq!(advertise_address("", "0.0.0.0", ip), "192.168.64.3");
        assert_eq!(advertise_address("", "", ip), "192.168.64.3");
        assert_eq!(advertise_address("", "0.0.0.0", None), "0.0.0.0");
    }

    /// Reads the drive back: every entry's path, mode and content.
    fn entries(drive: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
        use std::io::Read;
        let mut a = tar::Archive::new(drive);
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().into_owned();
                let mode = e.header().mode().unwrap();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                (path, mode, data)
            })
            .collect()
    }

    #[test]
    fn config_drive_carries_the_guest_config() {
        let r = record();
        let gw = Ipv4Addr::new(10, 64, 1, 1);
        let drive = config_drive(&r, gw).unwrap();
        assert_eq!(drive.len() % 512, 0, "{}", drive.len());
        let es = entries(&drive);
        assert_eq!(es.len(), 1);
        let (path, mode, data) = &es[0];
        assert_eq!(path, guest::CONFIG_NAME);
        assert_eq!(*mode, 0o600);
        let cfg: guest::Config = serde_json::from_slice(data).unwrap();
        assert_eq!(cfg.hostname, "db");
        assert_eq!(cfg.ip, "10.64.1.2/24");
        assert_eq!(cfg.gateway, "10.64.1.1");
        assert_eq!(cfg.dns, vec!["10.64.1.1"]);
        assert_eq!(cfg.hosts["db.internal"], "10.64.1.2");
        assert_eq!(cfg.hosts["m_abc123.vm.internal"], "10.64.1.2");
        // The image's entrypoint and cmd, since the machine gives neither.
        assert_eq!(cfg.entrypoint, vec!["docker-entrypoint.sh"]);
        assert_eq!(cfg.cmd, vec!["postgres"]);
        // The machine's env over the image's.
        assert_eq!(cfg.env["PATH"], "/usr/bin");
        assert_eq!(cfg.env["PGDATA"], "/data/pg");
        assert_eq!(cfg.workdir, "/");
        assert_eq!(cfg.user, "postgres");
        assert_eq!(cfg.mounts.len(), 1);
        assert_eq!(cfg.mounts[0].device, "/dev/vdc");
        assert_eq!(cfg.mounts[0].path, "/data");
        assert_eq!(cfg.mounts[0].fstype, "ext4");
        assert!(cfg.files.is_empty());
        assert_eq!(cfg.stop_timeout_sec, 10);

        // No volume: no mount.
        let mut r = record();
        r.volume = None;
        let cfg: guest::Config =
            serde_json::from_slice(&entries(&config_drive(&r, gw).unwrap())[0].2).unwrap();
        assert!(cfg.mounts.is_empty());
    }

    #[test]
    fn config_drive_follows_docker_for_entrypoint_and_cmd() {
        let gw = Ipv4Addr::new(10, 64, 1, 1);
        let cfg_of = |r: &Record| -> guest::Config {
            serde_json::from_slice(&entries(&config_drive(r, gw).unwrap())[0].2).unwrap()
        };
        // A cmd alone keeps the image's entrypoint.
        let mut r = record();
        r.cmd = Some(vec![
            "postgres".into(),
            "-c".into(),
            "log_min_messages=debug".into(),
        ]);
        let c = cfg_of(&r);
        assert_eq!(c.entrypoint, vec!["docker-entrypoint.sh"]);
        assert_eq!(c.cmd, vec!["postgres", "-c", "log_min_messages=debug"]);
        // An entrypoint alone replaces the image's and drops its cmd.
        let mut r = record();
        r.entrypoint = Some(vec!["/bin/sh".into()]);
        let c = cfg_of(&r);
        assert_eq!(c.entrypoint, vec!["/bin/sh"]);
        assert!(c.cmd.is_empty());
        // Both given: both used.
        let mut r = record();
        r.entrypoint = Some(vec!["/bin/sh".into()]);
        r.cmd = Some(vec!["-c".into(), "true".into()]);
        let c = cfg_of(&r);
        assert_eq!(c.entrypoint, vec!["/bin/sh"]);
        assert_eq!(c.cmd, vec!["-c", "true"]);
    }

    #[test]
    fn config_drive_carries_the_boot_files() {
        let gw = Ipv4Addr::new(10, 64, 1, 1);
        let mut r = record();
        r.files = vec![
            api::File {
                path: "/etc/app/app.conf".into(),
                base64: guest::base64_encode(b"k=v\n"),
                mode: None,
            },
            api::File {
                path: "/usr/local/bin/run".into(),
                base64: guest::base64_encode(b"#!/bin/sh\n"),
                mode: Some("0755".into()),
            },
            api::File {
                path: "/empty".into(),
                base64: String::new(),
                mode: Some(String::new()),
            },
        ];
        let drive = config_drive(&r, gw).unwrap();
        assert_eq!(drive.len() % 512, 0);
        let es = entries(&drive);
        assert_eq!(es.len(), 4);
        let cfg: guest::Config = serde_json::from_slice(&es[0].2).unwrap();
        assert_eq!(cfg.files.len(), 3);
        assert_eq!(
            (cfg.files[0].path.as_str(), cfg.files[0].mode),
            ("/etc/app/app.conf", 0o644)
        );
        assert_eq!(
            (cfg.files[1].path.as_str(), cfg.files[1].mode),
            ("/usr/local/bin/run", 0o755)
        );
        assert_eq!(
            (cfg.files[2].path.as_str(), cfg.files[2].mode),
            ("/empty", 0o644)
        );
        // Under files/, by guest path without the leading slash.
        assert_eq!(es[1].0, "files/etc/app/app.conf");
        assert_eq!(es[1].1, 0o644);
        assert_eq!(es[1].2, b"k=v\n");
        assert_eq!(es[2].0, "files/usr/local/bin/run");
        assert_eq!(es[2].1, 0o755);
        assert_eq!(es[2].2, b"#!/bin/sh\n");
        assert_eq!(es[3].0, "files/empty");
        assert!(es[3].2.is_empty());
    }

    #[test]
    fn config_drive_refuses_a_bad_file() {
        let gw = Ipv4Addr::new(10, 64, 1, 1);
        let mut r = record();
        r.files = vec![api::File {
            path: "/x".into(),
            base64: "not base64!".into(),
            mode: None,
        }];
        let err = config_drive(&r, gw).unwrap_err();
        assert!(err.to_string().starts_with("file /x: "), "{err}");

        r.files = vec![api::File {
            path: "/x".into(),
            base64: guest::base64_encode(b"ok"),
            mode: Some("rw-r--r--".into()),
        }];
        let err = config_drive(&r, gw).unwrap_err();
        assert_eq!(err.to_string(), "file /x: mode \"rw-r--r--\"");
    }

    #[test]
    fn a_drive_is_written_whole_then_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.tar");
        let data = config_drive(&record(), Ipv4Addr::new(10, 64, 1, 1)).unwrap();
        write_drive(&path, &data).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(!path.with_extension("tar.tmp").exists());
        // A second write replaces the first.
        write_drive(&path, b"x").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        // A directory that does not exist is an error, not a panic.
        assert!(write_drive(&dir.path().join("nope/config.tar"), b"x").is_err());
    }

    #[test]
    fn record_names() {
        let r = record();
        assert_eq!(r.hostname(), "db.internal");
        assert_eq!(r.machine_host(), "m_abc123.vm.internal");
        assert_eq!(r.dataset(), "m/m_abc123");
        assert_eq!(r.root_dataset(), "m/m_abc123/root");
        assert_eq!(r.data_dataset(), "m/m_abc123/data");
    }

    #[test]
    fn ids_have_a_prefix_and_twelve_hex_digits() {
        let id = new_id("m");
        let (p, hex) = id.split_once('_').unwrap();
        assert_eq!(p, "m");
        assert_eq!(hex.len(), 12);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        assert_ne!(new_id("m"), new_id("m"));
    }

    // --- transitions against the mock host ---

    #[tokio::test]
    async fn a_create_boots_the_machine_to_running() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let t0 = Utc::now();
        let m = h.m.create(h.request("web")).await.unwrap();
        assert_eq!(m.state, state::RUNNING);
        assert!(m.state_changed_at >= t0);
        assert!(m.started_at.is_some() && m.last_used_at.is_some());
        assert_eq!(
            m.sleeps_at,
            m.last_used_at.map(|t| t + chrono::Duration::minutes(30))
        );
        assert_eq!(
            (m.ip.as_str(), m.hostname.as_str()),
            ("10.64.1.2", "web.internal")
        );
        // The record on disk is the one in memory, running, with its pid.
        let stored = h.stored(&m.id).unwrap();
        assert_eq!(stored.state, state::RUNNING);
        assert_eq!(stored.pid, 1000);
        assert_eq!(stored.boots, 1);
        // The root disk is a clone of the image's snapshot; no volume, no data disk.
        let image = h.m.images().await.unwrap().remove(0);
        let zfs = h.pool.calls();
        assert!(
            zfs.contains(&format!(
                "clone byard/images/{}@base byard/m/{}/root",
                image.key, m.id
            )),
            "{zfs:?}"
        );
        assert!(!zfs.iter().any(|c| c.contains("/data")), "{zfs:?}");
        // The TAP was made on the tenant's bridge, pinned to the address, before the boot;
        // then the guest was waited for.
        let tap = netw::tap_name(&m.id);
        assert_eq!(
            h.host.calls(),
            vec![
                format!("ensure_tap {tap} by1 10.64.1.2"),
                format!("boot {} tap={tap} resume=false", m.id),
                "wait_ready 1000".to_string(),
            ]
        );
        assert_eq!(h.host.alive(), vec![1000]);
        let (used, up, total) = h.m.usage();
        assert_eq!((used.memory_mb, up, total), (256, 1, 1));
        assert_eq!(h.m.list(Some("t1"), &[])[0].id, m.id);
        // A second machine of that name is refused before anything is made.
        assert!(matches!(
            h.m.create(h.request("web")).await,
            Err(MError::Conflict(_))
        ));
        assert!(h.pool.calls().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_guest_that_never_answers_is_boot_failed() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.host.boots(Boots::Silent);
        let err = h.m.create(h.request("web")).await.unwrap_err();
        let m = match err {
            MError::BootFailed(m) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(m.state, state::ERROR);
        assert!(
            m.error.starts_with("the guest did not come up: "),
            "{}",
            m.error
        );
        // The process was ended, the TAP removed; the machine stays for the caller.
        assert!(h.host.alive().is_empty());
        let calls = h.host.calls();
        assert!(calls.contains(&"kill 1000".to_string()), "{calls:?}");
        assert_eq!(
            calls.last().unwrap(),
            &format!("delete_tap {} 10.64.1.2", netw::tap_name(&m.id))
        );
        assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
        assert_eq!(h.stored(&m.id).unwrap().state, state::ERROR);
        // The watcher found nothing to settle: no restart, one boot.
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
        assert!(!h.host.calls().iter().any(|c| c.starts_with("boot ")));
        // An errored machine holds no memory, and `/wait` answers at once with the reason.
        assert_eq!(h.m.usage().0.memory_mb, 0);
        match h
            .m
            .wait(&m.id, Until::Running, Duration::from_secs(1))
            .await
        {
            Err(MError::NotRunning(why)) => assert_eq!(why, m.error),
            other => panic!("{other:?}"),
        }
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(h.m.inner.stats.starts_failed.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn a_machine_that_exits_during_boot_is_boot_failed_with_its_console() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.host.boots(Boots::Exits(137));
        let err = h.m.create(h.request("web")).await.unwrap_err();
        let m = match err {
            MError::BootFailed(m) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(m.state, state::ERROR);
        assert!(
            m.error.starts_with("the machine exited during boot: "),
            "{}",
            m.error
        );
        assert!(m.error.contains("[briqyard] exit code=137"), "{}", m.error);
        // Not an exit the restart policy sees: the watcher had nothing to settle.
        assert!(m.exit.is_none());
        tokio::task::yield_now().await;
        assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
        assert_eq!(
            h.host
                .calls()
                .iter()
                .filter(|c| c.starts_with("boot "))
                .count(),
            1
        );
        // `create` with `start: false` leaves it `created`, and a `start` fails the same way.
        h.host.boots(Boots::Exits(1));
        let mut req = h.request("db");
        req.start = Some(false);
        let created = h.m.create(req).await.unwrap();
        assert_eq!(created.state, state::CREATED);
        assert!(matches!(
            h.m.start(&created.id, None).await,
            Err(MError::BootFailed(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_start_and_a_destroy_racing_leave_nothing_behind() {
        for round in 0..6 {
            let h = harness("10.64.0.0/22", 4096).await;
            h.tenant("t1");
            let e = h.add("m_race", state::STOPPED, 512);
            h.disks(&e).await;
            let (a, b) = (h.m.clone(), h.m.clone());
            let start = async move { a.start("m_race", None).await.map(|m| m.state) };
            let destroy = async move { b.destroy("m_race", None).await };
            let (started, destroyed) = if round % 2 == 0 {
                let s = tokio::spawn(start);
                let d = tokio::spawn(destroy);
                (s.await.unwrap(), d.await.unwrap())
            } else {
                let d = tokio::spawn(destroy);
                let s = tokio::spawn(start);
                (s.await.unwrap(), d.await.unwrap())
            };
            destroyed.unwrap();
            // The start ran first and was undone, or found the machine on its way out.
            match started {
                Ok(st) => assert_eq!(st, state::RUNNING, "round {round}"),
                Err(MError::BadState(st)) => assert_eq!(st, state::DESTROYING, "round {round}"),
                Err(MError::NotFound) => {}
                other => panic!("round {round}: {other:?}"),
            }
            // One outcome either way: no record, no process, no disks, no TAP.
            assert!(matches!(h.m.get("m_race"), Err(MError::NotFound)));
            assert!(h.stored("m_race").is_none());
            assert!(h.host.alive().is_empty(), "round {round}");
            assert!(!h.pool.dev().join("byard/m/m_race").exists());
            assert!(h.m.inner.net.list_taps().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn two_starts_past_capacity_admit_one() {
        let h = harness("10.64.0.0/22", 512).await;
        h.tenant("t1");
        for id in ["m_a", "m_b"] {
            let e = h.add(id, state::STOPPED, 512);
            h.disks(&e).await;
        }
        let (a, b) = (h.m.clone(), h.m.clone());
        let (ra, rb) = tokio::join!(a.start("m_a", None), b.start("m_b", None));
        let mut outcomes = [ra, rb];
        outcomes.sort_by_key(|r| r.is_err());
        assert_eq!(outcomes[0].as_ref().unwrap().state, state::RUNNING);
        match &outcomes[1] {
            Err(MError::Capacity(why)) => assert_eq!(why, "512 MB used of 512"),
            other => panic!("{other:?}"),
        }
        let (used, up, _) = h.m.usage();
        assert_eq!((used.memory_mb, up), (512, 1));
        // The refused one was not touched: still stopped, nothing booted for it.
        assert_eq!(
            h.host
                .calls()
                .iter()
                .filter(|c| c.starts_with("boot "))
                .count(),
            1
        );
        let states: Vec<String> = h.m.list(None, &[]).into_iter().map(|m| m.state).collect();
        assert!(states.contains(&state::STOPPED.to_string()), "{states:?}");
    }

    #[tokio::test]
    async fn a_stop_ends_the_guest_and_the_watcher_settles_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.host.calls();
        let stopped =
            h.m.stop(&m.id, Duration::from_secs(3), false, None)
                .await
                .unwrap();
        assert_eq!(
            (stopped.state.as_str(), stopped.stopped_reason.as_str()),
            (state::STOPPED, stop::USER)
        );
        assert!(stopped.stopped_at.is_some());
        assert_eq!(h.stored(&m.id).unwrap().pid, 0);
        // The guest was asked, not killed; its TAP went with it.
        let calls = h.host.calls();
        assert_eq!(calls[0], "shutdown 1000 3s");
        assert!(!calls.iter().any(|c| c.starts_with("kill ")), "{calls:?}");
        assert!(calls.contains(&format!("delete_tap {} 10.64.1.2", netw::tap_name(&m.id))));
        assert_eq!(h.m.usage().0.memory_mb, 0);
        // Stopped on request: a wake refuses, a start boots it again.
        assert!(matches!(
            h.m.wake(&m.id, None).await,
            Err(MError::NotRunning(_))
        ));
        let again = h.m.start(&m.id, None).await.unwrap();
        assert_eq!(
            (again.state.as_str(), again.stopped_reason.as_str()),
            (state::RUNNING, "")
        );
        assert_eq!(h.stored(&m.id).unwrap().boots, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stop_of_a_stopping_machine_returns_when_it_settles() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        // A stop is in flight: the state says so, and whoever asked still holds the lock.
        let held = e.lock.lock().await;
        e.set_state(state::STOPPING, |_| None);
        let (m2, id) = (h.m.clone(), m.id.clone());
        let second = tokio::spawn(async move {
            let t0 = std::time::Instant::now();
            m2.stop(&id, Duration::from_secs(1), false, None)
                .await
                .unwrap();
            t0.elapsed()
        });
        drop(held);
        // The watcher settles the machine as soon as it can take the lock.
        let _settling = e.lock.lock().await;
        e.set_state(state::STOPPED, |r| {
            r.stopped_reason = stop::USER.into();
            None
        });
        drop(_settling);
        let waited = second.await.unwrap();
        assert!(waited < Duration::from_secs(1), "{waited:?}");
    }

    #[tokio::test]
    async fn a_wake_during_a_sleep_waits_for_the_stop_then_starts() {
        // Found by the e2e suite: an exec waking a machine the sleeper was stopping got
        // `bad_state: stopping`.
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("db")).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.host.stops_take(Duration::from_millis(300));
        let (m2, e2) = (h.m.clone(), e.clone());
        let sleep = tokio::spawn(async move {
            m2.stop_entry(&e2, stop::IDLE, Duration::from_secs(1), false, None)
                .await
                .unwrap()
        });
        while e.snapshot().state != state::STOPPING {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let woken = h.m.wake(&m.id, None).await.unwrap();
        assert_eq!(woken.state, state::RUNNING);
        sleep.await.unwrap();
        assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
    }

    #[tokio::test]
    async fn a_create_whose_caller_hangs_up_still_runs() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.host.boots(Boots::Ready(Duration::from_millis(50)));
        let (m, req) = (h.m.clone(), h.request("web"));
        let caller =
            tokio::spawn(async move { detached(async move { m.create(req).await }).await });
        // The client hangs up once the machine is registered: its disks and its boot are
        // still to come.
        let id = loop {
            match h.m.list(Some("t1"), &[]).pop() {
                Some(m) => break m.id,
                None => tokio::task::yield_now().await,
            }
        };
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let running =
            h.m.wait(&id, Until::Running, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(running.state, state::RUNNING);
        assert_eq!(h.stored(&id).unwrap().state, state::RUNNING);
        assert_eq!(h.host.alive().len(), 1);
    }

    #[tokio::test]
    async fn a_transition_that_panics_is_internal_and_frees_the_machine() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let e = h.add("m_p", state::STOPPED, 512);
        h.disks(&e).await;
        h.host.boots(Boots::Panics);
        let m = h.m.clone();
        let err = detached(async move { m.start("m_p", None).await })
            .await
            .unwrap_err();
        match err {
            MError::Other(err) => {
                assert!(err.to_string().starts_with("transition task: "), "{err}")
            }
            other => panic!("{other:?}"),
        }
        // The lock went with the task: the next call on the machine is served.
        h.host.boots(Boots::Ready(Duration::ZERO));
        tokio::time::timeout(Duration::from_secs(5), h.m.destroy("m_p", None))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(h.m.get("m_p"), Err(MError::NotFound)));
    }

    #[tokio::test]
    async fn recovery_adopts_our_process_and_signals_no_other() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        // Ours: a VMM a previous daemon left, still carrying the machine's id.
        let ours = h.add("m_ours", state::RUNNING, 256);
        let pid = h
            .host
            .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
        ours.set_state(state::RUNNING, |r| {
            r.pid = pid;
            None
        });
        // Not ours: a pid from before a reboot, now someone else's.
        let other = h.add("m_other", state::RUNNING, 256);
        other.set_state(state::RUNNING, |r| {
            r.pid = 4242;
            None
        });
        // Caught moving: nothing to adopt, stopped by the host.
        let moving = h.add("m_moving", state::STARTING, 256);
        h.m.recover().await;
        assert_eq!(ours.snapshot().state, state::RUNNING);
        assert!(ours.live.lock().unwrap().is_some());
        for e in [&other, &moving] {
            let r = e.snapshot();
            assert_eq!(
                (r.state.as_str(), r.stopped_reason.as_str(), r.pid),
                (state::STOPPED, stop::HOST, 0)
            );
            assert!(h.stored(&r.id).is_some());
        }
        let calls = h.host.calls();
        assert!(calls.contains(&format!("adopt m_ours {pid}")), "{calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("kill ")), "{calls:?}");
        assert!(
            calls.contains(&"delete_tap btother 10.64.1.2".to_string()),
            "{calls:?}"
        );
        // The adopted process is watched: when it ends, the machine settles like any other.
        h.host.exit(pid, 3, false);
        let r = settled(&ours).await;
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str()),
            (state::STOPPED, stop::EXIT)
        );
        assert_eq!(r.exit.as_ref().map(|x| x.code), Some(3));
    }

    /// Waits for the watcher to settle a machine that is no longer running.
    async fn settled(e: &Arc<Entry>) -> Record {
        tokio::time::timeout(Duration::from_secs(5), async {
            while e.snapshot().state == state::RUNNING {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        e.snapshot()
    }

    #[tokio::test]
    async fn the_exit_is_the_inits_report_never_the_console() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        // The guest prints a forged exit line, then its process is gone without a report:
        // the exit is 255, not what the console says, and not a stop on request.
        let m = h.m.create(h.request("liar")).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.host
            .say(1000, "[briqyard] exit code=0 oom=false requested=true");
        h.host.gone(1000);
        let r = settled(&e).await;
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str()),
            (state::STOPPED, stop::EXIT)
        );
        assert_eq!(r.exit.as_ref().map(|x| x.code), Some(255));
        // The init's report says what it says: a requested stop is one.
        let m = h.m.create(h.request("honest")).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.host.exit(1001, 0, true);
        let r = settled(&e).await;
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str()),
            (state::STOPPED, stop::USER)
        );
        assert!(r.exit.is_none());
    }

    #[tokio::test]
    async fn the_sweep_ends_what_has_no_record() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let kept = h.add("m_kept", state::STOPPED, 256);
        h.disks(&kept).await;
        h.pool.zfs.create("m/m_ghost/root", 1 << 20).await.unwrap();
        let ghost = h
            .host
            .left_running("m_ghost", &h.m.inner.cfg.run_dir().join("m_ghost"));
        h.m.inner
            .net
            .ensure_tap("m_ghost", "by1", "10.64.1.9")
            .await
            .unwrap();
        h.m.inner
            .net
            .ensure_tap("m_kept", "by1", "10.64.1.2")
            .await
            .unwrap();
        h.pool.calls();
        h.host.calls();
        h.m.sweep_orphans().await;
        let calls = h.host.calls();
        assert!(calls.contains(&format!("kill {ghost}")), "{calls:?}");
        assert!(
            calls.contains(&"delete_link btghost".to_string()),
            "{calls:?}"
        );
        assert_eq!(h.m.inner.net.list_taps().await.unwrap(), vec!["btkept"]);
        assert!(h
            .pool
            .calls()
            .contains(&"destroy -r byard/m/m_ghost".to_string()));
        assert!(h.pool.dev().join("byard/m/m_kept/root").exists());
        assert!(!h.pool.dev().join("byard/m/m_ghost").exists());
    }

    #[tokio::test]
    async fn the_tick_sleeps_idle_machines_and_resumes_destroys() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let idle = h.m.create(h.request("idle")).await.unwrap();
        let mut forever = h.request("forever");
        forever.sleep = "never".into();
        let forever = h.m.create(forever).await.unwrap();
        let fresh = h.m.create(h.request("fresh")).await.unwrap();
        let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
        for id in [&idle.id, &forever.id] {
            h.m.entry(id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
        }
        let gone = h.add("m_gone", state::DESTROYING, 256);
        h.disks(&gone).await;
        h.host.calls();
        h.m.tick().await;
        let idle = h.m.get(&idle.id).unwrap();
        assert_eq!(
            (idle.state.as_str(), idle.stopped_reason.as_str()),
            (state::STOPPED, stop::IDLE)
        );
        assert_eq!(h.m.get(&forever.id).unwrap().state, state::RUNNING);
        assert_eq!(h.m.get(&fresh.id).unwrap().state, state::RUNNING);
        assert!(matches!(h.m.get("m_gone"), Err(MError::NotFound)));
        assert!(!h.pool.dev().join("byard/m/m_gone").exists());
        let calls = h.host.calls();
        assert_eq!(
            calls.iter().filter(|c| c.starts_with("shutdown ")).count(),
            1
        );
        // Asleep, not stopped on request: use wakes it.
        let woken =
            h.m.exec(
                &idle.id,
                api::ExecRequest {
                    cmd: vec!["true".into()],
                    wake: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(woken.exit_code, 0);
        let idle = h.m.get(&idle.id).unwrap();
        assert_eq!(idle.state, state::RUNNING);
        assert!(idle.last_used_at > long_ago);
    }

    #[tokio::test]
    async fn a_suspend_resumes_on_the_next_start() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.host.calls();
        let slept =
            h.m.stop(&m.id, Duration::from_secs(1), true, None)
                .await
                .unwrap();
        assert!(slept.suspended);
        assert_eq!(slept.state, state::STOPPED);
        let calls = h.host.calls();
        assert_eq!(&calls[..2], ["snapshot 1000 synced", "kill 1000"]);
        let back = h.m.start(&m.id, None).await.unwrap();
        assert!(!back.suspended);
        assert_eq!(back.state, state::RUNNING);
        let calls = h.host.calls();
        assert!(
            calls.iter().any(|c| c.ends_with(" resume=true")),
            "{calls:?}"
        );
        // A resume is not a boot.
        assert_eq!(h.stored(&m.id).unwrap().boots, 1);
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(h.m.inner.stats.resumes.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn touches_are_written_once_by_the_tick() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_t", state::STOPPED, 256);
        h.m.save(&e).unwrap();
        // A write is told by content, not by the file's time (Linux stamps files with a coarse
        // clock): a mark put in the stored record only, which any write from memory removes.
        let mark = || {
            let mut r = h.stored("m_t").unwrap();
            r.metadata.insert("unwritten".into(), "yes".into());
            h.m.inner.store.put("machines", "m_t", &r).unwrap();
        };
        let unwritten = || h.stored("m_t").unwrap().metadata.contains_key("unwritten");
        let before = h.stored("m_t").unwrap();
        mark();
        for _ in 0..10 {
            h.m.touch("m_t").unwrap();
        }
        let used = e.snapshot().last_used_at;
        assert!(used.is_some());
        // Memory has the use, the API reads it there, and the disk was not written.
        assert_eq!(h.m.get("m_t").unwrap().last_used_at, used);
        assert!(unwritten());
        // The tick writes it once, as the machine is: `updated_at` stays.
        h.m.tick().await;
        let stored = h.stored("m_t").unwrap();
        assert!(!unwritten());
        assert_eq!(stored.last_used_at, used);
        assert_eq!(stored.updated_at, before.updated_at);
        // Nothing moved since: the next tick writes nothing.
        mark();
        h.m.tick().await;
        assert!(unwritten());
        // A change to the machine carries the use with it, and the tick has nothing left.
        h.m.touch("m_t").unwrap();
        e.set_state(state::STARTING, |_| None);
        h.m.save(&e).unwrap();
        assert_eq!(
            h.stored("m_t").unwrap().last_used_at,
            e.snapshot().last_used_at
        );
        mark();
        h.m.tick().await;
        assert!(unwritten());
    }

    #[tokio::test]
    async fn a_use_never_writes_back_a_machine_that_is_gone_or_busy() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_u", state::STOPPED, 256);
        h.m.save(&e).unwrap();
        h.m.touch("m_u").unwrap();
        // A transition holds the machine: the flush leaves it to the transition.
        let turn = e.lock.try_lock().unwrap();
        h.m.flush_use(&e).unwrap();
        assert_eq!(h.stored("m_u").unwrap().last_used_at, None);
        assert!(e.unsaved_use.load(Relaxed));
        // The destroy that held it removed it: the flush writes nothing back.
        h.m.inner.machines.lock().unwrap().remove("m_u");
        h.m.inner.store.delete("machines", "m_u").unwrap();
        drop(turn);
        h.m.flush_use(&e).unwrap();
        assert!(h.stored("m_u").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_machines_go_to_sleep_together() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
        for name in ["a", "b", "c"] {
            let m = h.m.create(h.request(name)).await.unwrap();
            h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
        }
        // Each guest takes 3 s to stop: one after another, the tick would take 9.
        h.host.stops_take(Duration::from_secs(3));
        let t0 = tokio::time::Instant::now();
        h.m.tick().await;
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_secs(3) && took < Duration::from_secs(6),
            "{took:?}"
        );
        for m in h.m.list(None, &[]) {
            assert_eq!(
                (m.state.as_str(), m.stopped_reason.as_str()),
                (state::STOPPED, stop::IDLE),
                "{}",
                m.name
            );
        }
    }

    // --- fork snapshots ---

    impl Harness {
        /// A fork of `src`, both disks, started.
        pub(super) async fn fork(&self, src: &str, name: &str) -> api::Machine {
            let mut req = self.request(name);
            req.image = String::new();
            req.fork = Some(api::ForkSpec {
                machine_id: src.into(),
                copy: String::new(),
            });
            self.m.create(req).await.unwrap()
        }

        pub(super) fn snapshot_exists(&self, ds: &str, snap: &str) -> bool {
            self.pool.dev().join(format!("byard/{ds}@{snap}")).exists()
        }
    }

    #[tokio::test]
    async fn a_destroyed_fork_frees_its_snapshot_on_the_source() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let src = h.m.create(h.request("src")).await.unwrap();
        let fork = h.fork(&src.id, "fork").await;
        let (root, snap) = (format!("m/{}/root", src.id), format!("fork-{}", fork.id));
        assert!(h.snapshot_exists(&root, &snap));
        h.pool.calls();
        h.m.destroy(&fork.id, None).await.unwrap();
        // Nothing clones the snapshot once the fork is gone: it goes with the fork.
        let calls = h.pool.calls();
        assert!(
            calls.contains(&format!("destroy byard/{root}@{snap}")),
            "{calls:?}"
        );
        assert!(!h.snapshot_exists(&root, &snap));
        assert!(h.pool.dev().join(format!("byard/{root}")).exists());
        // Two forks of one snapshot: the snapshot stays until the last one goes.
        let a = h.fork(&src.id, "a").await;
        let snap_a = format!("fork-{}", a.id);
        h.pool
            .zfs
            .clone_snapshot(&root, &snap_a, "m/other/root")
            .await
            .unwrap();
        h.m.destroy(&a.id, None).await.unwrap();
        assert!(h.snapshot_exists(&root, &snap_a));
        // A snapshot that is not a fork's (the image's base) is never touched.
        h.pool.calls();
        h.m.destroy(&src.id, None).await.unwrap();
        assert!(!h
            .pool
            .calls()
            .iter()
            .any(|c| c.starts_with("destroy byard/images/")));
    }

    #[tokio::test]
    async fn a_destroyed_source_leaves_its_fork_whole_and_frees_what_it_took_over() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let src = h.m.create(h.request("src")).await.unwrap();
        let fork = h.fork(&src.id, "fork").await;
        let fork_root = format!("m/{}/root", fork.id);
        let snap = format!("fork-{}", fork.id);
        h.m.destroy(&src.id, None).await.unwrap();
        // The fork was promoted and owns the snapshot it was made from; with the source gone
        // nothing clones that snapshot, so it goes too.
        assert!(h.pool.dev().join(format!("byard/{fork_root}")).exists());
        assert!(!h.pool.dev().join(format!("byard/m/{}", src.id)).exists());
        assert!(!h.snapshot_exists(&fork_root, &snap));
        // It took its source's origin over, as ZFS's promote does: the image's.
        let origin = h.pool.zfs.origin(&fork_root).await.unwrap().unwrap();
        assert!(origin.0.starts_with("images/"), "{origin:?}");
        assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
        h.m.destroy(&fork.id, None).await.unwrap();
    }

    #[tokio::test]
    async fn the_sweep_frees_fork_snapshots_with_no_clone() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let kept = h.add("m_kept", state::STOPPED, 256);
        h.disks(&kept).await;
        let child = h.add("m_child", state::STOPPED, 256);
        let z = &h.pool.zfs;
        // One snapshot a destroy failed to free, one whose clone is a machine of ours.
        z.snapshot("m/m_kept/root", "fork-gone").await.unwrap();
        z.snapshot("m/m_kept/root", "fork-m_child").await.unwrap();
        z.clone_snapshot(
            "m/m_kept/root",
            "fork-m_child",
            &child.snapshot().root_dataset(),
        )
        .await
        .unwrap();
        // One the record names, one a daemon that died before the record left (ADR 0031).
        z.snapshot("m/m_kept/root", "s_mine").await.unwrap();
        z.snapshot("m/m_kept/root", "s_lost").await.unwrap();
        kept.rec.lock().unwrap().snapshots.push(SnapshotRec {
            id: "s_mine".into(),
            name: None,
            created_at: Utc::now(),
            disks: vec!["root".into()],
            memory: None,
            vmm_version: String::new(),
        });
        h.m.sweep_orphans().await;
        assert!(!h.snapshot_exists("m/m_kept/root", "fork-gone"));
        assert!(h.snapshot_exists("m/m_kept/root", "fork-m_child"));
        assert!(h.snapshot_exists("m/m_kept/root", "s_mine"));
        assert!(!h.snapshot_exists("m/m_kept/root", "s_lost"));
    }

    // --- egress (ADR 0015) ---

    fn egress(mode: &str, via: Option<&str>) -> api::Egress {
        api::Egress {
            mode: mode.into(),
            via: via.map(String::from),
        }
    }

    fn set_egress(mode: &str, via: Option<&str>) -> api::UpdateMachineRequest {
        api::UpdateMachineRequest {
            egress: Some(egress(mode, via)),
            ..Default::default()
        }
    }

    /// The message of an `invalid` refusal.
    fn refused<T: std::fmt::Debug>(r: Result<T, MError>) -> String {
        match r {
            Err(MError::Invalid(msg)) => msg,
            other => panic!("not refused: {other:?}"),
        }
    }

    impl Harness {
        fn request_egress(
            &self,
            name: &str,
            mode: &str,
            via: Option<&str>,
        ) -> api::CreateMachineRequest {
            api::CreateMachineRequest {
                egress: Some(egress(mode, via)),
                ..self.request(name)
            }
        }

        /// Whether tenant `t1`'s resolver answers `ip` from the tenant's names alone.
        fn dns_kept(&self, ip: &str) -> bool {
            let gateway = Ipv4Addr::new(10, 64, 1, 1);
            self.m
                .inner
                .dns
                .is_internal_only(gateway, ip.parse().unwrap())
        }
    }

    const VIA: &str = "via 10.64.1.3 to 10.64.1.2 host 10.64.1.1";

    #[tokio::test]
    async fn a_via_machine_is_kept_to_its_gateway_while_it_runs() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let gw = h.m.create(h.request("gw")).await.unwrap();
        h.host.calls();
        let m =
            h.m.create(h.request_egress("sbx", "via", Some(&gw.id)))
                .await
                .unwrap();
        assert_eq!(m.egress, egress("via", Some(&gw.id)));
        assert_eq!(h.stored(&m.id).unwrap().egress, m.egress);
        // The TAP and its pin, then the policy, then the boot.
        let tap = netw::tap_name(&m.id);
        assert_eq!(
            h.host.calls(),
            vec![
                format!("ensure_tap {tap} by1 10.64.1.3"),
                format!("set_policy {VIA}"),
                format!("boot {} tap={tap} resume=false", m.id),
                "wait_ready 1001".to_string(),
            ]
        );
        assert!(h.dns_kept("10.64.1.3"));
        assert!(!h.dns_kept("10.64.1.2"), "the gateway machine is open");
        // A stop takes it out right after the pin.
        h.m.stop(&m.id, Duration::from_secs(3), false, None)
            .await
            .unwrap();
        let calls = h.host.calls();
        let at = |line: String| calls.iter().position(|c| *c == line);
        let unpinned = at(format!("delete_tap {tap} 10.64.1.3")).expect("unpinned");
        assert_eq!(
            at(format!("unset_policy {VIA}")),
            Some(unpinned + 1),
            "{calls:?}"
        );
        assert!(!h.dns_kept("10.64.1.3"));
        assert!(h.m.inner.policies.lock().unwrap().is_empty());
        // Every start sets it again.
        h.m.start(&m.id, None).await.unwrap();
        assert!(h.host.calls().contains(&format!("set_policy {VIA}")));
    }

    #[tokio::test]
    async fn a_policy_changes_at_once_on_a_running_machine() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let gw = h.m.create(h.request("gw")).await.unwrap();
        let m =
            h.m.create(h.request_egress("sbx", "via", Some(&gw.id)))
                .await
                .unwrap();
        h.host.calls();
        let changed =
            h.m.update(&m.id, set_egress("none", None), None)
                .await
                .unwrap();
        assert_eq!(changed.egress, egress("none", None));
        assert_eq!(
            h.host.calls(),
            [format!("swap_policy {VIA} -> none 10.64.1.3")],
            "one call, one transaction"
        );
        assert!(h.dns_kept("10.64.1.3"));
        // The same policy again: nothing to change.
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap();
        assert!(h.host.calls().is_empty());
        // Open: nothing in the tables, outside names forwarded again.
        h.m.update(&m.id, set_egress("open", None), None)
            .await
            .unwrap();
        assert_eq!(h.host.calls(), ["unset_policy none 10.64.1.3"]);
        assert!(!h.dns_kept("10.64.1.3"));
        // Stopped: the record changes, the next start applies it.
        h.m.stop(&m.id, Duration::from_secs(3), false, None)
            .await
            .unwrap();
        h.host.calls();
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap();
        assert!(h.host.calls().is_empty());
        assert_eq!(h.stored(&m.id).unwrap().egress, egress("none", None));
        h.m.start(&m.id, None).await.unwrap();
        assert!(h
            .host
            .calls()
            .contains(&"set_policy none 10.64.1.3".to_string()));
    }

    #[tokio::test]
    async fn a_via_names_another_machine_of_the_tenant() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.tenant("t2");
        let gw = h.m.create(h.request("gw")).await.unwrap();
        let other =
            h.m.create(api::CreateMachineRequest {
                tenant: "t2".into(),
                ..h.request("other")
            })
            .await
            .unwrap();
        let m = h.m.create(h.request("sbx")).await.unwrap();
        h.host.calls();
        h.pool.calls();
        let missing = "m_000000000000";
        for (via, want) in [
            (
                other.id.as_str(),
                format!("egress.via {}: a machine of another tenant", other.id),
            ),
            (missing, format!("egress.via {missing}: no such machine")),
        ] {
            let create = h.m.create(h.request_egress("sbx2", "via", Some(via))).await;
            assert_eq!(refused(create), want);
            let update = h.m.update(&m.id, set_egress("via", Some(via)), None).await;
            assert_eq!(refused(update), want);
        }
        assert_eq!(
            refused(
                h.m.update(&m.id, set_egress("via", Some(&m.id)), None)
                    .await
            ),
            "egress.via names the machine itself"
        );
        assert_eq!(
            refused(h.m.create(h.request_egress("sbx2", "via", None)).await),
            "egress.via must name a machine of the tenant"
        );
        // Nothing applied, made or changed.
        assert!(h.host.calls().is_empty());
        let zfs = h.pool.calls();
        assert!(zfs.is_empty(), "{zfs:?}");
        assert!(h.m.list(None, &[]).iter().all(|x| x.name != "sbx2"));
        assert_eq!(h.stored(&m.id).unwrap().egress, api::Egress::default());
        // Its own tenant's machine is a gateway.
        h.m.update(&m.id, set_egress("via", Some(&gw.id)), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_gateway_destroyed_under_a_via_machine_leaves_it_reaching_nothing() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let gw = h.m.create(h.request("gw")).await.unwrap();
        let m =
            h.m.create(h.request_egress("sbx", "via", Some(&gw.id)))
                .await
                .unwrap();
        h.m.destroy(&gw.id, None).await.unwrap();
        // The policy stays, and so does the address it names: a new machine gets another.
        assert_eq!(h.m.create(h.request("next")).await.unwrap().ip, "10.64.1.4");
        h.host.calls();
        // A stop takes out what was set, gateway or not.
        h.m.stop(&m.id, Duration::from_secs(3), false, None)
            .await
            .unwrap();
        assert!(h.host.calls().contains(&format!("unset_policy {VIA}")));
        // A start is refused until the policy names a machine that is there; nothing moves.
        assert_eq!(
            refused(h.m.start(&m.id, None).await),
            format!("egress.via {}: no such machine", gw.id)
        );
        assert!(h.host.calls().is_empty());
        assert_eq!(h.stored(&m.id).unwrap().state, state::STOPPED);
        // Named by no policy, the address is free again.
        assert_eq!(h.m.create(h.request("last")).await.unwrap().ip, "10.64.1.2");
    }

    #[tokio::test]
    async fn the_tables_at_start_hold_the_running_policies() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let add = |id: &str, st: &str, n: u8, eg: api::Egress| {
            let e = h.add(id, st, 256);
            let mut r = e.rec.lock().unwrap();
            r.name = id.trim_start_matches("m_").into();
            (r.host_num, r.ip, r.egress) = (n, format!("10.64.1.{n}"), eg);
        };
        add("m_gw", state::RUNNING, 2, api::Egress::default());
        add("m_via", state::RUNNING, 3, egress("via", Some("m_gw")));
        add("m_none", state::RUNNING, 4, egress("none", None));
        // Its gateway is gone: no pin, so nothing it sends leaves its TAP.
        add("m_lost", state::RUNNING, 5, egress("via", Some("m_gone")));
        add("m_off", state::STOPPED, 6, egress("none", None));
        let r = h.m.rules().unwrap();
        let pin = |tap: &str, ip: &str| (tap.to_string(), ip.to_string());
        assert_eq!(
            r.pins,
            [
                pin("btgw", "10.64.1.2"),
                pin("btnone", "10.64.1.4"),
                pin("btvia", "10.64.1.3")
            ]
        );
        assert_eq!(
            r.policies,
            [
                nft::Policy::Via {
                    ip: "10.64.1.3".into(),
                    to: "10.64.1.2".into(),
                    host: "10.64.1.1".into()
                },
                nft::Policy::None {
                    ip: "10.64.1.4".into()
                }
            ]
        );
        assert!(r
            .render()
            .contains("elements = { 10.64.1.3 . 10.64.1.2, 10.64.1.3 . 10.64.1.1 }"));
        // Every machine's internet traffic is counted, a stopped one's too: its element lives
        // as long as it does.
        assert_eq!(
            r.counted,
            [
                "10.64.1.2",
                "10.64.1.3",
                "10.64.1.4",
                "10.64.1.5",
                "10.64.1.6"
            ]
        );
        // Held as if set: the resolver keeps them in, and a stop takes them out.
        assert!(h.dns_kept("10.64.1.3") && h.dns_kept("10.64.1.4"));
        assert!(!h.dns_kept("10.64.1.5") && !h.dns_kept("10.64.1.6"));
        assert_eq!(h.m.inner.policies.lock().unwrap().len(), 2);
        // None of them is adopted (no process): each is unplugged, policy included.
        h.host.calls();
        h.m.recover().await;
        let calls = h.host.calls();
        assert!(calls.contains(&format!("unset_policy {VIA}")), "{calls:?}");
        assert!(calls.contains(&"unset_policy none 10.64.1.4".to_string()));
        assert!(h.m.inner.policies.lock().unwrap().is_empty());
        assert!(!h.dns_kept("10.64.1.3") && !h.dns_kept("10.64.1.4"));
    }

    #[tokio::test]
    async fn a_refused_swap_keeps_the_old_policy_and_the_record() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let gw = h.m.create(h.request("gw")).await.unwrap();
        let m =
            h.m.create(h.request_egress("sbx", "via", Some(&gw.id)))
                .await
                .unwrap();
        h.host.calls();
        h.host.refuse_policies.store(true, Relaxed);
        let err =
            h.m.update(&m.id, set_egress("none", None), None)
                .await
                .unwrap_err();
        assert!(matches!(err, MError::Other(_)), "{err:?}");
        // One transaction tried, nothing taken out before it.
        assert_eq!(
            h.host.calls(),
            [format!("swap_policy {VIA} -> none 10.64.1.3")]
        );
        let via = egress("via", Some(&gw.id));
        assert_eq!(h.m.get(&m.id).unwrap().egress, via);
        assert_eq!(h.stored(&m.id).unwrap().egress, via);
        let held = h.m.inner.policies.lock().unwrap().get(&m.id).cloned();
        assert!(
            matches!(held, Some((_, nft::Policy::Via { .. }))),
            "{held:?}"
        );
        assert!(h.dns_kept("10.64.1.3"));
        // Accepted, it lands.
        h.host.refuse_policies.store(false, Relaxed);
        let changed =
            h.m.update(&m.id, set_egress("none", None), None)
                .await
                .unwrap();
        assert_eq!(changed.egress, egress("none", None));
    }

    // --- disk limits (ADR 0030) ---

    fn disk(bandwidth_mb: u32, iops: u32, burst_sec: u32) -> fc::DiskRate {
        fc::DiskRate {
            bandwidth_mb,
            iops,
            burst_sec,
        }
    }

    fn set_disk(l: api::DiskLimits) -> api::UpdateMachineRequest {
        api::UpdateMachineRequest {
            disk_limits: Some(l),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn disks_boot_with_the_host_s_limits_for_the_size_under_the_machine_s_own() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        // The host's default for 1 vCPU, on the root disk only: it has no volume.
        assert_eq!(m.disk_limits, disk(32, 4000, 10).view());
        let disks = |id: &str| h.host.disks.lock().unwrap().get(id).copied();
        assert_eq!(disks(&m.id), Some((disk(32, 4000, 10), false)));
        let mut req = h.request("db");
        req.size.vcpus = 2;
        req.disk_limits = Some(api::DiskLimits {
            iops: Some(500),
            ..Default::default()
        });
        let db = h.m.create(req).await.unwrap();
        // Its own value over the host's; the rest scale with its 2 vCPUs.
        assert_eq!(db.disk_limits, disk(64, 500, 10).view());
        assert_eq!(disks(&db.id), Some((disk(64, 500, 10), false)));
        assert_eq!(
            h.stored(&db.id).unwrap().disk_limits,
            api::DiskLimits {
                iops: Some(500),
                ..Default::default()
            },
            "the record keeps its own values, not the host's"
        );
        // A new size is the next boot's, and so are the limits it brings.
        let grown = api::Size {
            vcpus: 4,
            memory_mb: 256,
        };
        let patched =
            h.m.update(&m.id, spec(|s| s.size = Some(grown)), None)
                .await
                .unwrap();
        assert_eq!(patched.disk_limits, disk(32, 4000, 10).view());
        let up = h.m.restart(&m.id, None).await.unwrap();
        assert_eq!(up.disk_limits, disk(128, 16000, 10).view());
        assert_eq!(disks(&m.id), Some((disk(128, 16000, 10), false)));
        // Refused before anything is made, with the field named.
        let mut bad = h.request("bad");
        bad.disk_limits = Some(api::DiskLimits {
            burst_sec: Some(4000),
            ..Default::default()
        });
        assert_eq!(
            refused(h.m.create(bad).await),
            "disk_limits.burst_sec: at most 3600"
        );
    }

    #[tokio::test]
    async fn disk_limits_change_at_once_on_a_running_machine_and_at_the_boot_otherwise() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.host.calls();
        let disks = |id: &str| h.host.disks.lock().unwrap().get(id).copied();
        let slow = api::DiskLimits {
            bandwidth_mb: Some(2),
            ..Default::default()
        };
        let changed =
            h.m.update(&m.id, set_disk(slow.clone()), None)
                .await
                .unwrap();
        assert_eq!(changed.disk_limits, disk(2, 4000, 10).view());
        assert_eq!(disks(&m.id), Some((disk(2, 4000, 10), false)));
        let pid = h.stored(&m.id).unwrap().pid;
        assert_eq!(h.host.calls(), [format!("disk-rate {pid} 2mb 4000iops")]);
        // A machine with a volume: both disks take it (a unit test has no `mkfs.ext4` to
        // make one, so the record says it has one).
        h.m.entry(&m.id).unwrap().rec.lock().unwrap().volume = Some(api::VolumeSpec {
            size_gb: 1,
            mount: "/data".into(),
        });
        let iops = api::DiskLimits {
            iops: Some(100),
            ..Default::default()
        };
        h.m.update(&m.id, set_disk(iops), None).await.unwrap();
        assert_eq!(disks(&m.id), Some((disk(2, 100, 10), true)));
        h.m.entry(&m.id).unwrap().rec.lock().unwrap().volume = None;
        let back = api::DiskLimits {
            iops: Some(4000),
            ..Default::default()
        };
        let changed = h.m.update(&m.id, set_disk(back), None).await.unwrap();
        h.host.calls();
        let ev = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (ev.reason.as_str(), ev.message.as_str()),
            ("updated", "disk_limits changed")
        );
        // The same again changes nothing: no call, no event.
        let version = changed.version;
        let same = h.m.update(&m.id, set_disk(slow), None).await.unwrap();
        assert!(h.host.calls().is_empty());
        assert_eq!(same.version, version);
        // Refused by Firecracker: the disks and the record keep what they had.
        h.host.refuse_disk_rate.store(true, Relaxed);
        let lift = api::DiskLimits {
            bandwidth_mb: Some(0),
            ..Default::default()
        };
        let err = h.m.update(&m.id, set_disk(lift.clone()), None).await;
        assert!(matches!(err, Err(MError::Other(_))), "{err:?}");
        assert_eq!(
            h.m.get(&m.id).unwrap().disk_limits,
            disk(2, 4000, 10).view()
        );
        assert_eq!(h.stored(&m.id).unwrap().disk_limits.bandwidth_mb, Some(2));
        h.host.refuse_disk_rate.store(false, Relaxed);
        // Stopped: only the record, and the next boot is given it.
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.host.calls();
        h.m.update(&m.id, set_disk(lift), None).await.unwrap();
        assert!(!h.host.calls().iter().any(|c| c.starts_with("disk-rate")));
        h.m.start(&m.id, None).await.unwrap();
        assert_eq!(disks(&m.id), Some((disk(0, 4000, 10), false)));
        // Out of bounds: refused, named.
        let bad = api::DiskLimits {
            bandwidth_mb: Some(100_001),
            ..Default::default()
        };
        assert_eq!(
            refused(h.m.update(&m.id, set_disk(bad), None).await),
            "disk_limits.bandwidth_mb: at most 100000"
        );
    }

    #[tokio::test]
    async fn disk_metrics_add_up_per_machine_across_its_boots() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let io = h.m.entry(&m.id).unwrap().disk_io.clone();
        let line = |w: u64, t: u64| {
            json!({"block": {"write_bytes": w, "rate_limiter_throttled_events": t}}).to_string()
        };
        io.add(&line(1 << 20, 3));
        h.m.restart(&m.id, None).await.unwrap();
        // A new process starts its counters at zero; the machine's go on.
        io.add(&line(1 << 20, 4));
        let text = h.m.metrics();
        crate::metrics::check_exposition(&text);
        let l = format!(r#"machine="{}",tenant="t1",name="web""#, m.id);
        for want in [
            format!("briqyard_machine_disk_write_bytes_total{{{l}}} 2097152"),
            format!("briqyard_machine_disk_throttled_total{{{l}}} 7"),
            format!("briqyard_machine_disk_read_bytes_total{{{l}}} 0"),
        ] {
            assert!(text.lines().any(|x| x == want), "{want}\n{text}");
        }
    }

    // --- egress limits (ADR 0018) ---

    /// The host's limits in these tests: port 25, 600 connections a minute, no cap.
    fn host_limits() -> crate::config::EgressLimits {
        crate::config::EgressLimits {
            blocked_ports: vec![25],
            new_connections_per_minute: 600,
            bandwidth_mbit: 0,
        }
    }

    fn set_limits(l: api::EgressLimits) -> api::UpdateMachineRequest {
        api::UpdateMachineRequest {
            limits: Some(l),
            ..Default::default()
        }
    }

    fn view_limits(ports: &[u16], conn: u32, mbit: u32) -> api::EgressLimits {
        api::EgressLimits {
            blocked_ports: Some(ports.to_vec()),
            new_connections_per_minute: Some(conn),
            bandwidth_mbit: Some(mbit),
        }
    }

    #[tokio::test]
    async fn an_open_machine_runs_with_the_host_s_limits_under_its_own() {
        let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
        h.ready().await;
        let m =
            h.m.create(api::CreateMachineRequest {
                limits: Some(api::EgressLimits {
                    bandwidth_mbit: Some(100),
                    ..Default::default()
                }),
                ..h.request("web")
            })
            .await
            .unwrap();
        // Its own field over the host's two; shown whole, stored as it was asked.
        assert_eq!(m.limits, view_limits(&[25], 600, 100));
        assert_eq!(h.stored(&m.id).unwrap().limits.bandwidth_mbit, Some(100));
        assert_eq!(h.stored(&m.id).unwrap().limits.blocked_ports, None);
        // Set where the policy is: after the pin, before the boot. The resolver forwards
        // outside names as for any open machine.
        let (tap, open) = (
            netw::tap_name(&m.id),
            "open 10.64.1.2 ports [25] conn 600 mbit 100",
        );
        assert_eq!(
            h.host.calls(),
            vec![
                format!("ensure_tap {tap} by1 10.64.1.2"),
                format!("set_policy {open}"),
                format!("boot {} tap={tap} resume=false", m.id),
                "wait_ready 1000".to_string(),
            ]
        );
        assert!(!h.dns_kept("10.64.1.2"));
        // A stop withdraws them right after the pin, a start sets them again.
        h.m.stop(&m.id, Duration::from_secs(3), false, None)
            .await
            .unwrap();
        let calls = h.host.calls();
        let at = |line: String| calls.iter().position(|c| *c == line);
        let unpinned = at(format!("delete_tap {tap} 10.64.1.2")).expect("unpinned");
        assert_eq!(
            at(format!("unset_policy {open}")),
            Some(unpinned + 1),
            "{calls:?}"
        );
        assert!(h.m.inner.policies.lock().unwrap().is_empty());
        h.m.start(&m.id, None).await.unwrap();
        assert!(h.host.calls().contains(&format!("set_policy {open}")));
        // A destroy withdraws them too, and the drop counters with the others.
        h.m.destroy(&m.id, None).await.unwrap();
        assert!(h.host.calls().contains(&format!("unset_policy {open}")));
        assert!(h.m.inner.policies.lock().unwrap().is_empty());
        assert!(!h.host.counted.lock().unwrap().contains_key("10.64.1.2"));
    }

    #[tokio::test]
    async fn limits_change_at_once_on_a_running_machine() {
        let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        assert_eq!(m.limits, view_limits(&[25], 600, 0));
        h.host.calls();
        // The fields it names, in one transaction; the others stay.
        let lift = api::EgressLimits {
            new_connections_per_minute: Some(0),
            ..Default::default()
        };
        let changed = h.m.update(&m.id, set_limits(lift), None).await.unwrap();
        assert_eq!(changed.limits, view_limits(&[25], 0, 0));
        assert_eq!(
            h.host.calls(),
            ["swap_policy open 10.64.1.2 ports [25] conn 600 mbit 0 -> open 10.64.1.2 ports [25] conn 0 mbit 0"]
        );
        let ports = api::EgressLimits {
            blocked_ports: Some(vec![465, 25]),
            bandwidth_mbit: Some(2),
            ..Default::default()
        };
        let changed = h.m.update(&m.id, set_limits(ports), None).await.unwrap();
        assert_eq!(changed.limits, view_limits(&[25, 465], 0, 2));
        assert_eq!(
            h.stored(&m.id).unwrap().limits,
            api::EgressLimits {
                blocked_ports: Some(vec![465, 25]),
                new_connections_per_minute: Some(0),
                bandwidth_mbit: Some(2),
            }
        );
        h.host.calls();
        // The same again: nothing to change.
        let same = api::EgressLimits {
            bandwidth_mbit: Some(2),
            ..Default::default()
        };
        h.m.update(&m.id, set_limits(same), None).await.unwrap();
        assert!(h.host.calls().is_empty());
        // Nothing left to limit: nothing in the tables.
        let none = view_limits(&[], 0, 0);
        h.m.update(&m.id, set_limits(none), None).await.unwrap();
        assert_eq!(
            h.host.calls(),
            ["unset_policy open 10.64.1.2 ports [25, 465] conn 0 mbit 2"]
        );
        assert!(h.m.inner.policies.lock().unwrap().is_empty());
        // Refused: named, nothing applied or stored.
        let bad = api::EgressLimits {
            blocked_ports: Some(vec![0]),
            ..Default::default()
        };
        assert_eq!(
            refused(h.m.update(&m.id, set_limits(bad.clone()), None).await),
            "limits.blocked_ports: 0 is not a port"
        );
        assert_eq!(
            refused(
                h.m.create(api::CreateMachineRequest {
                    limits: Some(bad),
                    ..h.request("web2")
                })
                .await
            ),
            "limits.blocked_ports: 0 is not a port"
        );
        assert!(h.host.calls().is_empty());
        assert_eq!(h.stored(&m.id).unwrap().limits.blocked_ports, Some(vec![]));
        // Stopped: the record changes, the next start applies it.
        h.m.stop(&m.id, Duration::from_secs(3), false, None)
            .await
            .unwrap();
        h.host.calls();
        let conn = api::EgressLimits {
            new_connections_per_minute: Some(6),
            ..Default::default()
        };
        assert_eq!(
            h.m.update(&m.id, set_limits(conn), None)
                .await
                .unwrap()
                .limits,
            view_limits(&[], 6, 0)
        );
        assert!(h.host.calls().is_empty());
        h.m.start(&m.id, None).await.unwrap();
        assert!(h
            .host
            .calls()
            .contains(&"set_policy open 10.64.1.2 ports [] conn 6 mbit 0".to_string()));
    }

    #[tokio::test]
    async fn via_and_none_machines_get_no_limits() {
        let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
        h.ready().await;
        let gw = h.m.create(h.request("gw")).await.unwrap();
        h.host.calls();
        // They never reach the NAT: their policy is the one they would have without limits.
        let m =
            h.m.create(h.request_egress("sbx", "via", Some(&gw.id)))
                .await
                .unwrap();
        assert!(h.host.calls().contains(&format!("set_policy {VIA}")));
        let n =
            h.m.create(h.request_egress("off", "none", None))
                .await
                .unwrap();
        assert!(h
            .host
            .calls()
            .contains(&"set_policy none 10.64.1.4".to_string()));
        // The limits are shown and stored all the same, ready for an open policy.
        assert_eq!(n.limits, view_limits(&[25], 600, 0));
        let own = api::EgressLimits {
            bandwidth_mbit: Some(10),
            ..Default::default()
        };
        h.m.update(&m.id, set_limits(own), None).await.unwrap();
        assert!(h.host.calls().is_empty(), "nothing to change in the tables");
        // Open: the policy becomes its limits, in one transaction, and the resolver lets
        // it go once the tables have changed.
        assert!(h.dns_kept("10.64.1.3"));
        h.m.update(&m.id, set_egress("open", None), None)
            .await
            .unwrap();
        assert_eq!(
            h.host.calls(),
            [format!(
                "swap_policy {VIA} -> open 10.64.1.3 ports [25] conn 600 mbit 10"
            )]
        );
        assert!(!h.dns_kept("10.64.1.3"));
        // And back: the resolver takes it in before.
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap();
        assert_eq!(
            h.host.calls(),
            ["swap_policy open 10.64.1.3 ports [25] conn 600 mbit 10 -> none 10.64.1.3"]
        );
        assert!(h.dns_kept("10.64.1.3"));
        // Refused, a swap to open keeps the machine in the resolver with its old policy.
        h.host.refuse_policies.store(true, Relaxed);
        assert!(h
            .m
            .update(&m.id, set_egress("open", None), None)
            .await
            .is_err());
        assert!(h.dns_kept("10.64.1.3"));
        // Refused, a swap from open takes nothing into the resolver.
        h.host.refuse_policies.store(false, Relaxed);
        h.m.update(&gw.id, set_limits(view_limits(&[25], 600, 1)), None)
            .await
            .unwrap();
        h.host.refuse_policies.store(true, Relaxed);
        assert!(h
            .m
            .update(&gw.id, set_egress("none", None), None)
            .await
            .is_err());
        assert!(!h.dns_kept("10.64.1.2"));
    }

    #[tokio::test]
    async fn the_tables_at_start_hold_the_running_machines_limits() {
        let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
        h.tenant("t1");
        let add = |id: &str, st: &str, n: u8, eg: api::Egress, own: api::EgressLimits| {
            let e = h.add(id, st, 256);
            let mut r = e.rec.lock().unwrap();
            r.name = id.trim_start_matches("m_").into();
            (r.host_num, r.ip, r.egress, r.limits) = (n, format!("10.64.1.{n}"), eg, own);
        };
        let own = api::EgressLimits {
            new_connections_per_minute: Some(6),
            ..Default::default()
        };
        add(
            "m_web",
            state::RUNNING,
            2,
            api::Egress::default(),
            own.clone(),
        );
        add(
            "m_free",
            state::RUNNING,
            3,
            api::Egress::default(),
            view_limits(&[], 0, 0),
        );
        add(
            "m_none",
            state::RUNNING,
            4,
            egress("none", None),
            own.clone(),
        );
        add("m_off", state::STOPPED, 5, api::Egress::default(), own);
        let r = h.m.rules().unwrap();
        // The running open machine with something to limit, merged; the one with nothing
        // has no policy; `none` has its own; a stopped machine has nothing.
        assert_eq!(
            r.policies,
            [
                nft::Policy::Open {
                    ip: "10.64.1.2".into(),
                    limits: crate::config::EgressLimits {
                        new_connections_per_minute: 6,
                        ..host_limits()
                    }
                },
                nft::Policy::None {
                    ip: "10.64.1.4".into()
                }
            ]
        );
        assert!(r
            .render()
            .contains("\tlimit conn_10_64_1_2 {\n\t\trate over 6/minute burst 6 packets\n\t}\n"));
        // Held as if set, and only `none` in the resolver.
        assert_eq!(h.m.inner.policies.lock().unwrap().len(), 2);
        assert!(!h.dns_kept("10.64.1.2") && h.dns_kept("10.64.1.4"));
    }

    #[tokio::test]
    async fn drops_land_in_the_view_and_the_usage() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
        h.m.inner.net.count("10.64.1.2").await.unwrap();
        h.host.dropped("10.64.1.2", 2, 5, 0);
        h.m.measure(at("2026-10-20T14:00:15Z")).await;
        h.host.dropped("10.64.1.2", 1, 0, 10);
        h.m.measure(at("2026-10-20T14:00:30Z")).await;
        let u = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
        assert_eq!(u.usage.egress_dropped_packets, 18);
        assert_eq!(
            h.m.get("m_a").unwrap().egress_drops,
            api::EgressDrops {
                blocked_port: 3,
                rate: 5,
                bandwidth: 10
            }
        );
        // Since the machine started: a boot counts the view from none, not the usage.
        e.meter.lock().unwrap().boot(0);
        h.host.dropped("10.64.1.2", 1, 0, 0);
        h.m.measure(at("2026-10-20T14:00:45Z")).await;
        assert_eq!(h.m.get("m_a").unwrap().egress_drops.total(), 1);
        let u = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
        assert_eq!(u.usage.egress_dropped_packets, 19);
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_waiting_on_a_destroy_finds_nothing() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        // The guest takes a while to stop: the destroy holds the lock meanwhile.
        h.host.stops_take(Duration::from_secs(3));
        let d = h.m.clone();
        let id = m.id.clone();
        let destroy = tokio::spawn(async move { d.destroy(&id, None).await });
        while h.m.get(&m.id).unwrap().state != state::DESTROYING {
            tokio::task::yield_now().await;
        }
        let set = api::UpdateMachineRequest {
            sleep: Some("3h".into()),
            ..Default::default()
        };
        let patched = h.m.update(&m.id, set, None).await;
        destroy.await.unwrap().unwrap();
        assert!(matches!(patched, Err(MError::NotFound)), "{patched:?}");
        assert!(h.stored(&m.id).is_none(), "the record is not written back");
        assert!(matches!(h.m.get(&m.id), Err(MError::NotFound)));
    }

    // --- the tenant's gateway (ADR 0016) ---

    const IMAGE2: &str =
        "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000002";

    fn gateway_spec(port: u16) -> api::GatewaySpec {
        api::GatewaySpec {
            image: IMAGE.into(),
            env: BTreeMap::from([("TOKEN".to_string(), "t0k".to_string())]),
            port,
            ..Default::default()
        }
    }

    impl Harness {
        /// Tenant `t1` with a gateway on port 3128, not started; its machine id.
        async fn with_gateway(&self) -> String {
            self.ready().await;
            let t = self.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
            self.host.calls();
            self.pool.calls();
            t.gateway.unwrap().machine_id
        }

        /// A machine of `t1` that sends through the tenant's gateway.
        fn consumer(&self, name: &str) -> api::CreateMachineRequest {
            self.request_egress(name, "via", Some("gateway"))
        }

        fn gateway_view(&self) -> api::GatewayView {
            self.m.tenant("t1").unwrap().gateway.expect("a gateway")
        }

        fn boots_of(calls: &[String], id: &str) -> usize {
            let boot = format!("boot {id} ");
            calls.iter().filter(|c| c.starts_with(&boot)).count()
        }
    }

    const VIA_GATEWAY: &str = "via 10.64.1.3 to 10.64.1.2 host 10.64.1.1";

    #[tokio::test]
    async fn a_gateway_is_a_machine_of_the_daemon_not_of_the_tenant() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let t = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
        let gw = t.gateway.clone().unwrap();
        assert_eq!(
            (gw.state.as_str(), gw.ip.as_str(), gw.port),
            (state::CREATED, "10.64.1.2", 3128)
        );
        assert_eq!(t.machines, 0);
        // Made, not started: disks, no process, no TAP.
        assert!(!h.host.calls().iter().any(|c| c.starts_with("boot ")));
        assert!(h
            .pool
            .dev()
            .join(format!("byard/m/{}/root", gw.machine_id))
            .exists());
        // Its record says what it is; its name in the tenant is `gateway.internal`.
        let r = h.stored(&gw.machine_id).unwrap();
        assert_eq!(r.role, Some(Role::Gateway));
        assert_eq!(r.env["TOKEN"], "t0k");
        let m = h.m.get(&gw.machine_id).unwrap();
        assert_eq!(m.hostname, "gateway.internal");
        assert_eq!(
            (
                m.sleep.as_str(),
                m.egress.clone(),
                m.restart.policy.as_str()
            ),
            ("never", api::Egress::default(), "always")
        );
        // Not one of the tenant's machines: not listed, not counted, its console readable.
        assert!(h.m.list(None, &[]).is_empty() && h.m.list(Some("t1"), &[]).is_empty());
        assert_eq!(h.m.usage().2, 0);
        assert!(h.m.logs(&gw.machine_id, "", 10).is_ok());
        // The name is taken in the tenant, like any machine's.
        assert!(matches!(
            h.m.create(h.request("gateway")).await,
            Err(MError::Conflict(_))
        ));
        assert!(matches!(h.m.tenant("t9"), Err(MError::NotFound)));
        // A spec the gateway cannot run is refused before anything is made.
        for bad in [
            gateway_spec(0),
            api::GatewaySpec {
                image: String::new(),
                ..gateway_spec(3128)
            },
            api::GatewaySpec {
                size: Some(api::Size {
                    vcpus: 0,
                    memory_mb: 256,
                }),
                ..gateway_spec(3128)
            },
        ] {
            assert!(matches!(
                h.m.set_gateway("t1", bad).await,
                Err(MError::Invalid(_))
            ));
        }
        assert_eq!(h.gateway_view().machine_id, gw.machine_id);
    }

    #[tokio::test]
    async fn a_start_through_the_gateway_boots_it_first() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let m = h.m.create(h.consumer("sbx")).await.unwrap();
        assert_eq!(m.state, state::RUNNING);
        // The gateway's boot and its port, then the machine's pin, its policy naming the
        // gateway's address, and its boot.
        let (gtap, tap) = (netw::tap_name(&gw), netw::tap_name(&m.id));
        assert_eq!(
            h.host.calls(),
            vec![
                format!("ensure_tap {gtap} by1 10.64.1.2"),
                format!("boot {gw} tap={gtap} resume=false"),
                "wait_ready 1000".to_string(),
                "wait_port 10.64.1.2:3128".to_string(),
                format!("ensure_tap {tap} by1 10.64.1.3"),
                format!("set_policy {VIA_GATEWAY}"),
                format!("boot {} tap={tap} resume=false", m.id),
                "wait_ready 1001".to_string(),
            ]
        );
        assert_eq!(h.gateway_view().state, state::RUNNING);
        // The tenant has one machine; the host runs two and commits both.
        assert_eq!(h.m.tenant("t1").unwrap().machines, 1);
        let (used, running, total) = h.m.usage();
        assert_eq!((used.memory_mb, running, total), (512, 2, 1));
        // The tables a daemon start renders name the gateway too.
        let rules = h.m.rules().unwrap();
        assert!(rules.policies.iter().any(|p| matches!(p,
            nft::Policy::Via { to, .. } if to == "10.64.1.2")));
        // Running already: the next start probes its port and boots nothing for it.
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.host.calls();
        h.m.start(&m.id, None).await.unwrap();
        let calls = h.host.calls();
        assert_eq!(Harness::boots_of(&calls, &gw), 0, "{calls:?}");
        assert_eq!(calls[0], "wait_port 10.64.1.2:3128");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_starts_through_the_gateway_boot_it_once() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let mut ids = Vec::new();
        for name in ["a", "b"] {
            let mut req = h.consumer(name);
            req.start = Some(false);
            ids.push(h.m.create(req).await.unwrap().id);
        }
        h.host.boots(Boots::Ready(Duration::from_millis(50)));
        let (ma, mb) = (h.m.clone(), h.m.clone());
        let (a, b) = (ids[0].clone(), ids[1].clone());
        let (ra, rb) = tokio::join!(
            tokio::spawn(async move { ma.start(&a, None).await }),
            tokio::spawn(async move { mb.start(&b, None).await })
        );
        assert_eq!(ra.unwrap().unwrap().state, state::RUNNING);
        assert_eq!(rb.unwrap().unwrap().state, state::RUNNING);
        let calls = h.host.calls();
        assert_eq!(Harness::boots_of(&calls, &gw), 1, "{calls:?}");
        assert_eq!(h.gateway_view().state, state::RUNNING);
    }

    #[tokio::test(start_paused = true)]
    async fn a_gateway_that_does_not_come_up_fails_the_start_and_says_so() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let mut req = h.consumer("sbx");
        req.start = Some(false);
        let m = h.m.create(req).await.unwrap();
        h.host.calls();
        // Its program never listens: the gateway is ended, in error, with the port named.
        h.host.silent_ports.store(true, Relaxed);
        let failed = |r: Result<api::Machine, MError>| match r {
            Err(MError::BootFailed(b)) => *b,
            other => panic!("{other:?}"),
        };
        let b = failed(h.m.start(&m.id, None).await);
        // The answer is the machine asked for, not moved, the gateway's reason in it.
        assert_eq!(
            (b.id.as_str(), b.state.as_str()),
            (m.id.as_str(), state::CREATED)
        );
        assert!(
            b.error
                .starts_with("the tenant's gateway did not come up: port 3128 did not answer"),
            "{}",
            b.error
        );
        let g = h.gateway_view();
        assert_eq!(g.state, state::ERROR);
        assert!(
            g.error.starts_with("port 3128 did not answer"),
            "{}",
            g.error
        );
        let calls = h.host.calls();
        assert_eq!(Harness::boots_of(&calls, &m.id), 0, "{calls:?}");
        assert!(!calls.iter().any(|c| c.contains("10.64.1.3")), "{calls:?}");
        assert!(h.host.alive().is_empty());
        assert_eq!(h.stored(&m.id).unwrap().state, state::CREATED);
        // Its guest never comes up: the same answer, with the boot's reason.
        h.host.silent_ports.store(false, Relaxed);
        h.host.boots(Boots::Silent);
        let b = failed(h.m.start(&m.id, None).await);
        assert!(
            b.error
                .starts_with("the tenant's gateway did not come up: the guest did not come up: "),
            "{}",
            b.error
        );
        assert_eq!(h.m.get(&m.id).unwrap().state, state::CREATED);
        // Fixed: the next start brings the gateway back from `error`, then the machine.
        h.host.boots(Boots::Ready(Duration::ZERO));
        assert_eq!(h.m.start(&m.id, None).await.unwrap().state, state::RUNNING);
        assert_eq!(h.gateway_view().state, state::RUNNING);
        assert_eq!(h.m.get(&gw).unwrap().error, "");
    }

    #[tokio::test]
    async fn the_sleeper_stops_the_gateway_once_nothing_needs_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let a = h.m.create(h.consumer("a")).await.unwrap();
        let b = h.m.create(h.consumer("b")).await.unwrap();
        let mut open = h.request("open");
        open.sleep = "never".into();
        h.m.create(open).await.unwrap();
        let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
        let idle = |id: &str| h.m.entry(id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
        // Nothing idle: the gateway stays.
        h.m.tick().await;
        assert_eq!(h.gateway_view().state, state::RUNNING);
        // One consumer asleep, the other running: it stays.
        idle(&a.id);
        h.m.tick().await;
        assert_eq!(h.m.get(&a.id).unwrap().stopped_reason, stop::IDLE);
        assert_eq!(h.gateway_view().state, state::RUNNING);
        // The last one asleep: the gateway goes in the same tick; a machine that does not
        // send through it does not keep it.
        idle(&b.id);
        h.m.tick().await;
        assert_eq!(h.m.get(&b.id).unwrap().stopped_reason, stop::IDLE);
        let g = h.m.get(&gw).unwrap();
        assert_eq!(
            (g.state.as_str(), g.stopped_reason.as_str()),
            (state::STOPPED, stop::IDLE)
        );
        // A wake of a consumer (an exec here, a connection alike) goes through the start.
        h.host.calls();
        let woken =
            h.m.exec(
                &a.id,
                api::ExecRequest {
                    cmd: vec!["true".into()],
                    wake: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(woken.exit_code, 0);
        assert_eq!(Harness::boots_of(&h.host.calls(), &gw), 1);
        assert_eq!(h.gateway_view().state, state::RUNNING);
    }

    #[tokio::test]
    async fn the_sleeper_leaves_a_gateway_whose_tenant_is_busy() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let m = h.m.create(h.consumer("sbx")).await.unwrap();
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        // A start that needs the gateway holds the tenant's lock until it is `starting`:
        // nothing runs through the gateway yet, and still it is not stopped under that start.
        let t = h.m.tenant_of("t1").unwrap();
        let held = t.lock.lock().await;
        h.m.tick().await;
        assert_eq!(h.m.get(&gw).unwrap().state, state::RUNNING);
        drop(held);
        h.m.tick().await;
        assert_eq!(h.m.get(&gw).unwrap().state, state::STOPPED);
    }

    #[tokio::test]
    async fn a_gateway_in_use_is_kept_and_one_unused_removed() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let m = h.m.create(h.consumer("sbx")).await.unwrap();
        assert!(matches!(
            h.m.delete_gateway("t1").await,
            Err(MError::GatewayInUse)
        ));
        assert_eq!(h.gateway_view().state, state::RUNNING);
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.m.delete_gateway("t1").await.unwrap();
        // Stopped and destroyed: no record, no process, no disks.
        assert!(h.m.tenant("t1").unwrap().gateway.is_none());
        assert!(matches!(h.m.get(&gw), Err(MError::NotFound)));
        assert!(h.stored(&gw).is_none());
        assert!(h.host.alive().is_empty());
        assert!(!h.pool.dev().join(format!("byard/m/{gw}")).exists());
        // Its consumer's next start is refused, with what to do; none is success.
        assert_eq!(
            refused(h.m.start(&m.id, None).await),
            "tenant has no gateway: PUT /v1/tenants/t1/gateway first"
        );
        assert_eq!(h.stored(&m.id).unwrap().state, state::STOPPED);
        h.m.delete_gateway("t1").await.unwrap();
        h.m.delete_gateway("t-none").await.unwrap();
    }

    #[tokio::test]
    async fn the_tenants_removal_destroys_its_gateway() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        // The tenant's own machine keeps the tenant, and the gateway with it.
        assert!(matches!(
            h.m.delete_tenant("t1").await,
            Err(MError::TenantInUse)
        ));
        assert!(h.m.get(&gw).is_ok());
        h.m.destroy(&m.id, None).await.unwrap();
        h.m.delete_tenant("t1").await.unwrap();
        assert!(matches!(h.m.get(&gw), Err(MError::NotFound)));
        assert!(!h.pool.dev().join(format!("byard/m/{gw}")).exists());
        assert!(h.m.tenants().is_empty());
    }

    #[tokio::test]
    async fn via_gateway_needs_the_tenant_to_have_one() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let want = "tenant has no gateway: PUT /v1/tenants/t1/gateway first";
        assert_eq!(refused(h.m.create(h.consumer("sbx")).await), want);
        let m = h.m.create(h.request("web")).await.unwrap();
        let patch =
            h.m.update(&m.id, set_egress("via", Some("gateway")), None)
                .await;
        assert_eq!(refused(patch), want);
        assert_eq!(h.stored(&m.id).unwrap().egress, api::Egress::default());
        // The gateway itself cannot send through itself: a start of it refuses.
        let t = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
        let gw = h.m.entry(&t.gateway.unwrap().machine_id).unwrap();
        gw.rec.lock().unwrap().egress = egress("via", Some("gateway"));
        assert_eq!(
            refused(h.m.start_entry(&gw, true).await),
            "egress.via names the machine itself"
        );
    }

    #[tokio::test]
    async fn a_patch_to_via_gateway_runs_the_gateway_before_the_policy() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        let mut req = h.request("sbx");
        req.sleep = "never".into();
        let m = h.m.create(req).await.unwrap();
        h.host.calls();
        let patched =
            h.m.update(&m.id, set_egress("via", Some("gateway")), None)
                .await
                .unwrap();
        assert!(patched.egress.via_gateway());
        let calls = h.host.calls();
        let at = |line: &str| calls.iter().position(|c| c == line).unwrap_or(usize::MAX);
        assert!(
            at("wait_port 10.64.1.2:3128") < at(&format!("set_policy {VIA_GATEWAY}")),
            "{calls:?}"
        );
        assert_eq!(Harness::boots_of(&calls, &gw), 1);
        // From now on it needs the gateway: the sleeper keeps it.
        h.m.tick().await;
        assert_eq!(h.gateway_view().state, state::RUNNING);
    }

    #[tokio::test]
    async fn a_put_on_a_running_gateway_restarts_it_with_the_new_spec() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        h.m.inner
            .images
            .seed(IMAGE2, ImageConfig::default())
            .await
            .unwrap();
        h.m.create(h.consumer("sbx")).await.unwrap();
        h.host.calls();
        h.pool.calls();
        let spec = api::GatewaySpec {
            image: IMAGE2.into(),
            ..gateway_spec(8080)
        };
        let t = h.m.set_gateway("t1", spec).await.unwrap();
        // Same machine, same address; the new port and image, running again.
        let g = t.gateway.unwrap();
        assert_eq!(
            (
                g.machine_id.as_str(),
                g.ip.as_str(),
                g.port,
                g.state.as_str()
            ),
            (gw.as_str(), "10.64.1.2", 8080, state::RUNNING)
        );
        let calls = h.host.calls();
        assert!(calls[0].starts_with("shutdown "), "{calls:?}");
        assert_eq!(Harness::boots_of(&calls, &gw), 1);
        assert_eq!(calls.last().unwrap(), "wait_port 10.64.1.2:8080");
        let key2 = h.stored(&gw).unwrap().image_key;
        // The old root disk swapped out (ADR 0031), then gone: no fork holds it.
        let zfs = h.pool.calls();
        let retired = format!("byard/m/{gw}/root.r_");
        assert!(
            zfs.iter()
                .any(|c| c.starts_with(&format!("rename byard/m/{gw}/root {retired}"))),
            "{zfs:?}"
        );
        assert!(
            zfs.iter()
                .any(|c| c.starts_with(&format!("destroy -r {retired}"))),
            "{zfs:?}"
        );
        assert!(
            zfs.contains(&format!(
                "clone byard/images/{key2}@base byard/m/{gw}/root.next"
            )),
            "{zfs:?}"
        );
        assert_eq!(h.m.get(&gw).unwrap().image, IMAGE2);
        // Asleep with a memory snapshot, then replaced: the next start boots it cold.
        let sbx = h.m.list(None, &[])[0].id.clone();
        h.m.stop(&sbx, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        let e = h.m.entry(&gw).unwrap();
        h.m.stop_entry(&e, stop::USER, Duration::from_secs(1), true, None)
            .await
            .unwrap();
        assert!(h.m.get(&gw).unwrap().suspended);
        h.m.set_gateway("t1", gateway_spec(8080)).await.unwrap();
        assert!(!h.m.get(&gw).unwrap().suspended);
        h.host.calls();
        h.m.start(&sbx, None).await.unwrap();
        let calls = h.host.calls();
        assert!(
            calls.contains(&format!(
                "boot {gw} tap={} resume=false",
                netw::tap_name(&gw)
            )),
            "{calls:?}"
        );
        // The volume is the gateway's for its life.
        let spec = api::GatewaySpec {
            volume_gb: Some(1),
            ..gateway_spec(8080)
        };
        assert!(refused(h.m.set_gateway("t1", spec).await).starts_with("volume_gb is fixed"));
    }

    #[tokio::test]
    async fn the_gateways_address_stays_reserved_while_a_policy_names_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        h.m.create(h.consumer("sbx")).await.unwrap();
        // Destroyed under a running consumer (by its machine id): a new gateway gets another
        // address, so the consumer's policy reaches nothing rather than a stranger.
        h.m.destroy_machine(&gw, None).await.unwrap();
        let t = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
        assert_eq!(t.gateway.unwrap().ip, "10.64.1.4");
    }

    #[tokio::test]
    async fn the_gateway_is_read_only_through_the_machine_routes() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        // Read: the machine, its console, its use.
        assert_eq!(h.m.get(&gw).unwrap().name, "gateway");
        assert!(h.m.logs(&gw, "", 10).is_ok());
        assert!(h.m.stats(&gw).await.is_ok());
        h.pool.calls();
        // Everything that changes or runs something in it is the tenant route's.
        let gateway = |r: Result<(), MError>| match r {
            Err(MError::Gateway(t)) => t,
            other => panic!("{other:?}"),
        };
        let exec = api::ExecRequest {
            cmd: vec!["true".into()],
            wake: true,
            ..Default::default()
        };
        let put = api::PutFileRequest {
            path: "/x".into(),
            base64: String::new(),
            mode: None,
        };
        let mut fork = h.request("fork");
        fork.image = String::new();
        fork.fork = Some(api::ForkSpec {
            machine_id: gw.clone(),
            copy: String::new(),
        });
        let refused = [
            gateway(h.m.destroy(&gw, None).await),
            gateway(
                h.m.stop(&gw, Duration::from_secs(1), false, None)
                    .await
                    .map(|_| ()),
            ),
            gateway(h.m.start(&gw, None).await.map(|_| ())),
            gateway(h.m.wake(&gw, None).await.map(|_| ())),
            gateway(h.m.touch(&gw)),
            gateway(
                h.m.update(&gw, set_egress("none", None), None)
                    .await
                    .map(|_| ()),
            ),
            gateway(h.m.create(fork).await.map(|_| ())),
            gateway(h.m.exec(&gw, exec).await.map(|_| ())),
            gateway(h.m.put_file(&gw, put).await),
            gateway(h.m.get_file(&gw, "/etc/hostname").await.map(|_| ())),
            gateway(
                h.m.snapshot(&gw, api::SnapshotRequest::default())
                    .await
                    .map(|_| ()),
            ),
            gateway(h.m.snapshots(&gw).await.map(|_| ())),
            gateway(h.m.delete_snapshot(&gw, "s_1").await),
            gateway(h.m.restore_snapshot(&gw, "s_1", None).await.map(|_| ())),
            gateway(h.m.backup(&gw).await.map(|_| ())),
            gateway(
                h.m.create_endpoint(
                    &gw,
                    api::CreateEndpointRequest {
                        port: 3128,
                        ..Default::default()
                    },
                )
                .map(|_| ()),
            ),
        ];
        assert!(refused.iter().all(|t| t == "t1"), "{refused:?}");
        assert_eq!(
            MError::Gateway("t1".into()).to_string(),
            "the tenant's gateway: use /v1/tenants/t1/gateway"
        );
        // Untouched: not started, not destroyed, no other machine made, no snapshot taken.
        assert_eq!(h.gateway_view().state, state::CREATED);
        assert!(h.host.calls().is_empty());
        assert!(h.m.list(None, &[]).is_empty());
        assert!(h.pool.calls().is_empty());
    }

    #[tokio::test]
    async fn recovery_starts_the_gateway_an_adopted_machine_needs() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        h.tenant("t2");
        let gateway = |id: &str, tenant: &str| {
            // Found running, its process gone with the daemon: nothing to adopt.
            let e = h.add(id, state::RUNNING, 256);
            e.set_state(state::RUNNING, |r| {
                (r.role, r.tenant, r.name) = (Some(Role::Gateway), tenant.into(), "gateway".into());
                (r.ports, r.pid) = (vec![3128], 4242);
                None
            });
            e
        };
        let adopted = |id: &str, tenant: &str, n: u8, eg: api::Egress| {
            let e = h.add(id, state::RUNNING, 256);
            let pid = h.host.left_running(id, &h.m.inner.cfg.run_dir().join(id));
            e.set_state(state::RUNNING, |r| {
                (r.tenant, r.name, r.egress, r.pid) = (tenant.into(), id.into(), eg, pid);
                (r.host_num, r.ip) = (n, format!("10.64.1.{n}"));
                None
            });
            e
        };
        let needed = gateway("m_gw", "t1");
        h.disks(&needed).await;
        let sbx = adopted("m_sbx", "t1", 3, egress("via", Some("gateway")));
        // A tenant whose adopted machine does not send through its gateway.
        let unneeded = gateway("m_gw2", "t2");
        adopted("m_open", "t2", 4, api::Egress::default());
        h.m.recover().await;
        // Started detached, as a start that needs it would: boot, then its port.
        tokio::time::timeout(Duration::from_secs(5), async {
            while needed.snapshot().state != state::RUNNING {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the gateway runs");
        let calls = h.host.calls();
        assert!(
            calls.contains(&"wait_port 10.64.1.2:3128".to_string()),
            "{calls:?}"
        );
        assert!(
            sbx.live.lock().unwrap().is_some(),
            "the machine was adopted"
        );
        assert_eq!(sbx.snapshot().state, state::RUNNING);
        let r = unneeded.snapshot();
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str()),
            (state::STOPPED, stop::HOST)
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("boot m_gw2 ")),
            "{calls:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_put_with_start_runs_the_gateway_before_any_machine_needs_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let start = api::GatewaySpec {
            start: true,
            ..gateway_spec(3128)
        };
        let t = h.m.set_gateway("t1", start.clone()).await.unwrap();
        let gw = t.gateway.unwrap();
        assert_eq!(gw.state, state::RUNNING);
        let tap = netw::tap_name(&gw.machine_id);
        assert_eq!(
            h.host.calls(),
            [
                format!("ensure_tap {tap} by1 10.64.1.2"),
                format!("boot {} tap={tap} resume=false", gw.machine_id),
                "wait_ready 1000".to_string(),
                "wait_port 10.64.1.2:3128".to_string(),
            ]
        );
        // Running with the spec it has: left as is, its port asked again.
        h.m.set_gateway("t1", start.clone()).await.unwrap();
        assert_eq!(h.host.calls(), ["wait_port 10.64.1.2:3128"]);
        // Nothing needs it: the sleeper may stop it, and a machine's start brings it back.
        h.m.tick().await;
        assert_eq!(h.gateway_view().state, state::STOPPED);
        // A program that never listens: boot_failed names the gateway, with its console.
        h.m.inner.store.delete("machines", &gw.machine_id).unwrap();
        h.host.silent_ports.store(true, Relaxed);
        let b = match h.m.set_gateway("t1", start).await {
            Err(MError::BootFailed(b)) => b,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            (b.id.as_str(), b.state.as_str()),
            (gw.machine_id.as_str(), state::ERROR)
        );
        assert!(
            b.error.starts_with("port 3128 did not answer"),
            "{}",
            b.error
        );
        assert_eq!(h.gateway_view().state, state::ERROR);
    }

    // --- usage (ADR 0017) ---

    pub(super) fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    const GB: f64 = (1u64 << 30) as f64;

    impl Harness {
        /// A machine as `add` makes it (512 MB), its usage accrued up to `since`.
        fn metered(&self, id: &str, state: &str, since: &str) -> Arc<Entry> {
            let e = self.add(id, state, 512);
            e.meter.lock().unwrap().at = at(since);
            e
        }

        /// The buckets of `[from, to)`.
        pub(super) async fn buckets(&self, from: &str, to: &str) -> Vec<api::UsageBucket> {
            self.m.usage_buckets(at(from), at(to), None).await.unwrap()
        }

        /// The bucket of a machine in an hour.
        async fn bucket(&self, id: &str, hour: &str) -> api::UsageBucket {
            let next = (at(hour) + chrono::Duration::hours(1)).to_rfc3339();
            let all = self.buckets(hour, &next).await;
            all.into_iter()
                .find(|b| b.machine_id == id)
                .unwrap_or_else(|| panic!("no bucket of {id} at {hour}"))
        }
    }

    #[tokio::test]
    async fn a_machine_running_across_an_hour_has_two_buckets_that_split_its_seconds() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.metered("m_a", state::RUNNING, "2026-10-20T13:59:50Z");
        h.m.measure(at("2026-10-20T14:00:20Z")).await;
        let bs = h
            .buckets("2026-10-20T13:00:00Z", "2026-10-20T15:00:00Z")
            .await;
        let got: Vec<(DateTime<Utc>, f64, bool)> = bs
            .iter()
            .map(|b| (b.hour, b.usage.running_seconds, b.closed))
            .collect();
        assert_eq!(
            got,
            [
                (at("2026-10-20T13:00:00Z"), 10.0, true),
                (at("2026-10-20T14:00:00Z"), 20.0, false)
            ]
        );
        assert_eq!(bs[1].usage.memory_mb_seconds, 512.0 * 20.0);
        let b = &bs[0];
        assert_eq!(
            (
                b.machine_id.as_str(),
                b.tenant.as_str(),
                &b.role,
                b.size.memory_mb
            ),
            ("m_a", "t1", &None, 512)
        );
        // The hour that is over is on disk, closed; the open one is written too.
        let closed: Vec<api::UsageBucket> =
            h.m.inner
                .store
                .get("usage", "2026-10-20T13")
                .unwrap()
                .unwrap();
        assert!(closed[0].closed);
        let open: Vec<api::UsageBucket> =
            h.m.inner
                .store
                .get("usage", "2026-10-20T14")
                .unwrap()
                .unwrap();
        assert!(!open[0].closed);
    }

    #[tokio::test]
    async fn a_state_change_accrues_the_time_in_the_old_state() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_a", state::RUNNING, 512);
        let t0 = Utc::now() - chrono::Duration::seconds(30);
        e.meter.lock().unwrap().at = t0;
        e.set_state(state::STOPPED, |_| None);
        // A minute later, the tick finds it stopped: the 30 s before the stop ran, the
        // minute after did not.
        h.m.measure(Utc::now() + chrono::Duration::seconds(60))
            .await;
        let (from, to) = (
            usage::hour_of(t0),
            usage::hour_of(Utc::now()) + chrono::Duration::hours(2),
        );
        let ran: f64 =
            h.m.usage_buckets(from, to, None)
                .await
                .unwrap()
                .iter()
                .map(|b| b.usage.running_seconds)
                .sum();
        assert!((30.0..31.0).contains(&ran), "{ran}");
    }

    #[tokio::test]
    async fn cpu_counts_what_the_cgroup_grew_by_and_a_reset_adds_all() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
        // Running before this daemon: its first reading is where the count starts.
        h.host.cpu("m_a", 50_000_000);
        h.m.measure(at("2026-10-20T14:00:15Z")).await;
        h.host.cpu("m_a", 52_500_000);
        h.m.measure(at("2026-10-20T14:00:30Z")).await;
        // A new cgroup reads smaller: all of it is new.
        h.host.cpu("m_a", 1_000_000);
        h.m.measure(at("2026-10-20T14:00:45Z")).await;
        let b = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
        assert_eq!(b.usage.cpu_seconds, 3.5);
    }

    #[tokio::test]
    async fn a_suspended_machine_counts_suspended_seconds_and_its_memory_snapshot() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.metered("m_s", state::STOPPED, "2026-10-20T14:00:00Z");
        e.rec.lock().unwrap().suspended = true;
        let dir = h.m.inner.cfg.run_dir().join("m_s");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("snap.mem"), vec![1u8; 1 << 20]).unwrap();
        h.m.measure(at("2026-10-20T14:10:00Z")).await;
        let u = h.bucket("m_s", "2026-10-20T14:00:00Z").await.usage;
        assert_eq!(
            (u.suspended_seconds, u.running_seconds, u.memory_mb_seconds),
            (600.0, 0.0, 0.0)
        );
        let bytes = usage::file_bytes(&[dir.join("snap.mem")]);
        assert!(bytes >= 1 << 20, "{bytes}");
        assert_eq!(u.snapshot_gb_hours, bytes as f64 / GB * 600.0 / 3600.0);
        // Resumed, the snapshot is gone: running, and nothing suspended any more.
        std::fs::remove_file(dir.join("snap.mem")).unwrap();
        {
            let mut r = e.rec.lock().unwrap();
            (r.state, r.suspended) = (state::RUNNING.into(), false);
        }
        h.m.measure(at("2026-10-20T14:11:00Z")).await;
        let u = h.bucket("m_s", "2026-10-20T14:00:00Z").await.usage;
        assert_eq!((u.suspended_seconds, u.running_seconds), (600.0, 60.0));
    }

    #[tokio::test]
    async fn a_stopped_machine_counts_its_disks_and_no_compute() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.metered("m_d", state::STOPPED, "2026-10-20T14:00:00Z");
        e.rec.lock().unwrap().backup_bytes = 3 << 30;
        h.host.cpu("m_d", 9_000_000);
        // The pool's listing: the machine's datasets, and another machine's that is not its.
        h.pool.answer(
            "space",
            "byard/m\t-\t24576\t0\n\
             byard/m/m_d\t-\t0\t0\n\
             byard/m/m_d/root\t8589934592\t1073741824\t536870912\n\
             byard/m/m_d/data\t2147483648\t1073741824\t0\n\
             byard/m/m_x/root\t8589934592\t5\t5\n",
        );
        h.m.measure(at("2026-10-20T15:00:00Z")).await;
        let u = h.bucket("m_d", "2026-10-20T14:00:00Z").await.usage;
        assert_eq!(
            (u.root_gb_hours, u.volume_gb_hours, u.disk_used_gb_hours),
            (8.0, 2.0, 2.0)
        );
        assert_eq!((u.snapshot_gb_hours, u.backup_gb_hours), (0.5, 3.0));
        assert_eq!(
            (u.running_seconds, u.memory_mb_seconds, u.cpu_seconds),
            (0.0, 0.0, 0.0)
        );
        // One call for the whole pool, whatever the number of machines.
        let calls = h.pool.calls();
        assert_eq!(
            calls.iter().filter(|c| c.starts_with("list -H -p")).count(),
            1,
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn internet_and_ingress_bytes_land_on_their_machine() {
        let h = harness("10.64.0.0/22", 4096).await;
        let a = h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
        let b = h.metered("m_b", state::RUNNING, "2026-10-20T14:00:00Z");
        b.rec.lock().unwrap().ip = "10.64.1.3".into();
        b.rec.lock().unwrap().role = Some(Role::Gateway);
        for ip in ["10.64.1.2", "10.64.1.3"] {
            h.m.inner.net.count(ip).await.unwrap();
        }
        h.host.internet("10.64.1.2", 1000, 100);
        let tr = h.m.traffic("m_b").unwrap();
        tr.received(7);
        tr.sent(70);
        h.m.measure(at("2026-10-20T14:00:15Z")).await;
        // Only what grew since: the counters are read again, not added again.
        h.host.internet("10.64.1.2", 1, 0);
        h.m.measure(at("2026-10-20T14:00:30Z")).await;
        let (ua, ub) = (
            h.bucket("m_a", "2026-10-20T14:00:00Z").await,
            h.bucket("m_b", "2026-10-20T14:00:00Z").await,
        );
        let net = |u: &api::Usage| {
            (
                u.internet_in_bytes,
                u.internet_out_bytes,
                u.ingress_in_bytes,
                u.ingress_out_bytes,
            )
        };
        assert_eq!(net(&ua.usage), (1001, 100, 0, 0));
        assert_eq!(net(&ub.usage), (0, 0, 7, 70));
        // The tenant's gateway is a machine of the daemon: its bucket says so.
        assert_eq!(ub.role.as_deref(), Some("gateway"));
        assert_eq!(ua.role, None);
        drop(a);
    }

    #[tokio::test]
    async fn a_closed_hour_is_never_written_again() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.metered("m_a", state::RUNNING, "2026-10-20T14:59:50Z");
        h.m.measure(at("2026-10-20T15:00:10Z")).await;
        let file = h.m.inner.cfg.state_dir().join("usage/2026-10-20T14.json");
        let before = std::fs::read(&file).unwrap();
        // A meter behind the closed hour (its last 5 s) adds them to the open one.
        h.metered("m_late", state::RUNNING, "2026-10-20T14:59:55Z");
        h.m.measure(at("2026-10-20T15:00:20Z")).await;
        assert_eq!(std::fs::read(&file).unwrap(), before);
        let in14 = h
            .buckets("2026-10-20T14:00:00Z", "2026-10-20T15:00:00Z")
            .await;
        assert_eq!(in14.len(), 1);
        assert_eq!(
            (in14[0].machine_id.as_str(), in14[0].usage.running_seconds),
            ("m_a", 10.0)
        );
        let late = h.bucket("m_late", "2026-10-20T15:00:00Z").await;
        assert_eq!(late.usage.running_seconds, 25.0);
        assert_eq!(
            h.bucket("m_a", "2026-10-20T15:00:00Z")
                .await
                .usage
                .running_seconds,
            20.0
        );
    }

    #[tokio::test]
    async fn a_restart_reads_the_open_hour_back_and_closes_one_left_open() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
        h.m.measure(at("2026-10-20T14:10:00Z")).await;
        // An hour a crashed daemon left open, before it.
        let left = api::UsageBucket {
            hour: at("2026-10-20T12:00:00Z"),
            machine_id: "m_old".into(),
            tenant: "t1".into(),
            ..Default::default()
        };
        h.m.inner
            .store
            .put("usage", "2026-10-20T12", &vec![left])
            .unwrap();
        // The daemon starts again at 14:20; what it measures goes on from 14:20.
        let loaded = Ledger::load(&h.m.inner.store, at("2026-10-20T14:20:00Z")).unwrap();
        *h.m.inner.usage.lock().unwrap() = loaded;
        e.meter.lock().unwrap().at = at("2026-10-20T14:20:00Z");
        h.m.measure(at("2026-10-20T14:30:00Z")).await;
        let b = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
        assert_eq!((b.usage.running_seconds, b.closed), (1200.0, false));
        let old: Vec<api::UsageBucket> =
            h.m.inner
                .store
                .get("usage", "2026-10-20T12")
                .unwrap()
                .unwrap();
        assert!(old[0].closed, "closed at the start");
    }

    #[tokio::test]
    async fn retention_removes_hours_past_usage_keep_days_once_an_hour() {
        let h = harness("10.64.0.0/22", 4096).await;
        let put = |key: &str| {
            let b = api::UsageBucket {
                hour: at(&format!("{key}:00:00Z")),
                closed: true,
                ..Default::default()
            };
            h.m.inner.store.put("usage", key, &vec![b]).unwrap();
        };
        put("2026-07-01T00");
        put("2026-10-10T00");
        h.m.measure(at("2026-10-20T14:00:00Z")).await;
        assert_eq!(h.m.inner.store.keys("usage").unwrap(), ["2026-10-10T00"]);
        // Once an hour: an old file found later in the same hour waits for the next one.
        put("2026-07-02T00");
        h.m.measure(at("2026-10-20T14:30:00Z")).await;
        assert!(h
            .m
            .inner
            .store
            .get::<Vec<api::UsageBucket>>("usage", "2026-07-02T00")
            .unwrap()
            .is_some());
        h.m.measure(at("2026-10-20T15:00:00Z")).await;
        assert_eq!(h.m.inner.store.keys("usage").unwrap(), ["2026-10-10T00"]);
    }

    #[tokio::test]
    async fn a_destroyed_machine_keeps_its_buckets_and_its_counters_go() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let t0 = Utc::now();
        let m = h.m.create(h.request("web")).await.unwrap();
        assert!(
            h.host.counted.lock().unwrap().contains_key(&m.ip),
            "counted from its create"
        );
        // Booted by this daemon: its CPU counts from the boot, so the first reading counts.
        h.host.cpu(&m.id, 3_000_000);
        h.host.internet(&m.ip, 500, 50);
        h.m.destroy(&m.id, None).await.unwrap();
        assert!(!h.host.counted.lock().unwrap().contains_key(&m.ip));
        // Measured by the destroy itself: no tick ran.
        let mine: Vec<api::UsageBucket> =
            h.m.usage_buckets(
                usage::hour_of(t0),
                usage::hour_of(Utc::now()) + chrono::Duration::hours(1),
                None,
            )
            .await
            .unwrap()
            .into_iter()
            .filter(|b| b.machine_id == m.id)
            .collect();
        let sum = |f: fn(&api::Usage) -> f64| mine.iter().map(|b| f(&b.usage)).sum::<f64>();
        assert!(sum(|u| u.running_seconds) > 0.0, "{mine:?}");
        assert_eq!(sum(|u| u.cpu_seconds), 3.0);
        assert_eq!(sum(|u| u.internet_in_bytes as f64), 500.0);
        // Counters that cannot be removed keep the destroy from finishing: the address would
        // be handed out again with the old count. The tick tries again.
        let m = h.m.create(h.request("web2")).await.unwrap();
        h.host.refuse_uncount.store(true, Relaxed);
        let err = h.m.destroy(&m.id, None).await.unwrap_err();
        assert!(format!("{err:#}").contains("usage counters"), "{err:#}");
        assert_eq!(h.m.get(&m.id).unwrap().state, state::DESTROYING);
        h.host.refuse_uncount.store(false, Relaxed);
        h.m.tick().await;
        assert!(matches!(h.m.get(&m.id), Err(MError::NotFound)));
        assert!(!h.host.counted.lock().unwrap().contains_key(&m.ip));
        // A create that fails once counted (a fork of a source whose disks are gone) takes
        // its counters back.
        h.add("m_src", state::STOPPED, 256);
        let mut fork = h.request("fork");
        fork.image.clear();
        fork.fork = Some(api::ForkSpec {
            machine_id: "m_src".into(),
            copy: String::new(),
        });
        let err = h.m.create(fork).await.unwrap_err();
        assert!(format!("{err:#}").contains("zfs"), "{err:#}");
        assert!(h.host.counted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_usage_route_checks_its_range() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
        h.m.measure(at("2026-10-20T14:10:00Z")).await;
        let st = Arc::new(crate::api::AppState {
            mgr: h.m.clone(),
            token: String::new(),
            metrics_token: String::new(),
            loopback: true,
            openapi: "",
            tls_fingerprint: String::new(),
        });
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/usage", ln.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
        let get = |q: &str| reqwest::get(format!("{url}{q}"));
        let r = get("?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z")
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let bs: Vec<api::UsageBucket> = r.json().await.unwrap();
        assert_eq!(bs.len(), 1);
        assert_eq!(bs[0].usage.running_seconds, 600.0);
        let r = get("?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z&tenant=t2")
            .await
            .unwrap();
        assert_eq!(r.json::<Vec<api::UsageBucket>>().await.unwrap().len(), 0);
        for (q, why) in [
            ("", "from is required"),
            ("?from=2026-10-20T14:00:00Z", "to is required"),
            (
                "?from=2026-10-20T14:30:00Z&to=2026-10-20T15:00:00Z",
                "not on the hour",
            ),
            (
                "?from=2026-10-20T15:00:00Z&to=2026-10-20T14:00:00Z",
                "to must be after from",
            ),
            (
                "?from=2026-10-20T14:00:00Z&to=2026-12-20T14:00:00Z",
                "at most 31 days",
            ),
        ] {
            let r = get(q).await.unwrap();
            assert_eq!(r.status(), 400, "{q}");
            let e: api::ApiError = r.json().await.unwrap();
            assert_eq!(e.code, "invalid", "{q}");
            assert!(e.error.contains(why), "{q}: {}", e.error);
        }
    }

    // --- events and versions (ADR 0019) ---

    impl Harness {
        /// The events about a machine, oldest first.
        pub(super) fn events_of(&self, id: &str) -> Vec<api::Event> {
            let f = events::Filter {
                machine: Some(id.into()),
                ..Default::default()
            };
            self.m.inner.events.read(0, &f, 5000).unwrap().events
        }

        pub(super) fn reasons(&self, id: &str) -> Vec<String> {
            self.events_of(id).into_iter().map(|e| e.reason).collect()
        }

        /// Waits until the machine's events hold `n` of `reason`, within ten minutes: on a
        /// paused clock, which a restart's backoff needs.
        async fn events_reach(&self, id: &str, reason: &str, n: usize) {
            let count = || self.reasons(id).iter().filter(|r| *r == reason).count();
            tokio::time::timeout(Duration::from_secs(600), async {
                while count() < n {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{id}: {:?}", self.reasons(id)));
        }
    }

    #[tokio::test]
    async fn each_transition_is_an_event_and_moves_the_version() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        let running = h.m.start(&m.id, None).await.unwrap();
        // The version is the seq of the last event, in memory and on disk.
        let evs = h.events_of(&m.id);
        assert_eq!(running.version, evs.last().unwrap().seq);
        assert_eq!(h.stored(&m.id).unwrap().version, running.version);
        h.m.destroy(&m.id, None).await.unwrap();
        assert_eq!(
            h.reasons(&m.id),
            [
                "created",
                "starting",
                "started",
                "stopping",
                "stopped",
                "starting",
                "started",
                "destroyed"
            ]
        );
        let evs = h.events_of(&m.id);
        assert!(evs.windows(2).all(|w| w[0].seq < w[1].seq));
        assert!(evs
            .iter()
            .all(|e| e.tenant == "t1" && e.kind == api::event::NORMAL));
        let data = |i: usize| evs[i].data.clone().unwrap_or_default();
        assert_eq!(data(0)["image"], IMAGE);
        assert_eq!(data(1)["resume"], false);
        assert_eq!(data(2)["pid"], 1000);
        assert_eq!(
            (data(3)["reason"].clone(), data(4)["reason"].clone()),
            ("user".into(), "user".into())
        );
        assert_eq!(evs[4].message, "stopped (user)");
    }

    #[tokio::test]
    async fn a_failed_start_is_a_warning_that_says_whose_fault() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        // The image's: the guest exited booting; its console's tail is in the message.
        h.host.boots(Boots::Exits(1));
        let m = match h.m.create(h.request("bad")).await {
            Err(MError::BootFailed(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(h.reasons(&m.id), ["created", "starting", "boot_failed"]);
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(e.kind, api::event::WARNING);
        assert!(
            e.message.starts_with("the machine exited during boot"),
            "{}",
            e.message
        );
        assert!(
            e.message.contains("[briqyard] exit code=1"),
            "{}",
            e.message
        );
        assert_eq!(m.version, e.seq);
        // The host's: a policy the tables refuse.
        h.host.boots(Boots::Ready(Duration::ZERO));
        h.host.refuse_policies.store(true, Relaxed);
        let err =
            h.m.create(h.request_egress("walled", "none", None))
                .await
                .unwrap_err();
        assert!(matches!(err, MError::Other(_)), "{err:?}");
        let id =
            h.m.list(Some("t1"), &[])
                .into_iter()
                .find(|x| x.name == "walled")
                .unwrap()
                .id;
        assert_eq!(h.reasons(&id), ["created", "starting", "start_failed"]);
        let e = h.events_of(&id).pop().unwrap();
        assert_eq!(e.kind, api::event::WARNING);
        assert!(e.message.contains("nft: refused"), "{}", e.message);
    }

    #[tokio::test(start_paused = true)]
    async fn an_exit_and_its_restart_are_events() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("job")).await.unwrap();
        h.host.exit(1000, 7, false);
        // The default policy, on-failure with 3 retries: the first comes after 10 s.
        h.events_reach(&m.id, reason::STARTED, 2).await;
        assert_eq!(
            h.reasons(&m.id),
            [
                "created",
                "starting",
                "started",
                "exited",
                "restarting",
                "starting",
                "started"
            ]
        );
        let evs = h.events_of(&m.id);
        let (exited, restarting) = (&evs[3], &evs[4]);
        assert_eq!(
            (exited.kind.as_str(), exited.message.as_str()),
            ("warning", "exited with code 7")
        );
        assert_eq!(
            exited.data,
            Some(json!({"code": 7, "oom": false, "restarting": true}))
        );
        assert_eq!(restarting.message, "restart 1 in 10 s (at most 3)");
        assert_eq!(restarting.data.as_ref().unwrap()["delay_sec"], 10);
        assert_eq!(restarting.data.as_ref().unwrap()["attempt"], 1);
        // Counted for `/metrics`, and a start's time measured.
        let e = h.m.entry(&m.id).unwrap();
        assert_eq!(e.meter.lock().unwrap().restarts, 1);
        assert!(e.meter.lock().unwrap().boot_seconds.is_some());
        // An exit with nothing to restart says so, and a clean exit is no warning.
        let mut req = h.request("once");
        req.restart = Some(api::RestartPolicy {
            policy: "no".into(),
            max_retries: 0,
        });
        let m = h.m.create(req).await.unwrap();
        h.host.exit(1002, 0, false);
        h.events_reach(&m.id, reason::EXITED, 1).await;
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (e.kind.as_str(), e.message.as_str()),
            ("normal", "exited with code 0")
        );
        assert_eq!(e.data.unwrap()["restarting"], false);
    }

    #[tokio::test]
    async fn a_suspend_and_its_resume_are_events() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.m.stop(&m.id, Duration::from_secs(1), true, None)
            .await
            .unwrap();
        h.m.start(&m.id, None).await.unwrap();
        let evs = h.events_of(&m.id);
        let got: Vec<(&str, &str)> = evs[3..]
            .iter()
            .map(|e| (e.reason.as_str(), e.message.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("stopping", "stopping (user)"),
                ("suspended", "suspended (user): its memory snapshot kept"),
                ("starting", "resuming from its memory snapshot"),
                ("resumed", "resumed from its memory snapshot, pid 1001"),
            ]
        );
        assert_eq!(evs[3].data.as_ref().unwrap()["suspend"], true);
        // A sleeping machine stopped on request: that changes it, so it is an event.
        let m = h.m.create(h.request("nap")).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        let last = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (last.reason.as_str(), last.message.as_str()),
            ("stopped", "stopped on request (it was idle)")
        );
    }

    #[tokio::test]
    async fn the_gateway_says_when_it_serves_and_when_it_sleeps() {
        let h = harness("10.64.0.0/22", 4096).await;
        let gw = h.with_gateway().await;
        assert_eq!(h.reasons(&gw), ["created"]);
        let c = h.m.create(h.consumer("c")).await.unwrap();
        assert_eq!(
            h.reasons(&gw),
            ["created", "starting", "started", "gateway_started"]
        );
        let started = h.events_of(&gw).pop().unwrap();
        assert_eq!(
            started.message,
            "the tenant's gateway answers on 10.64.1.2:3128"
        );
        // Its consumer's start came after the gateway answered.
        let consumer = h.events_of(&c.id);
        assert!(consumer[1].seq > started.seq);
        // A start that finds it running says nothing more.
        h.m.create(h.consumer("d")).await.unwrap();
        assert_eq!(h.reasons(&gw).len(), 4);
        for id in [
            c.id.clone(),
            h.m.list(Some("t1"), &[])
                .into_iter()
                .find(|m| m.name == "d")
                .unwrap()
                .id,
        ] {
            h.m.stop(&id, Duration::from_secs(1), false, None)
                .await
                .unwrap();
        }
        h.m.tick().await;
        assert_eq!(
            h.reasons(&gw)[4..],
            ["stopping", "stopped", "gateway_stopped"]
        );
        assert_eq!(
            h.m.get(&gw).unwrap().version,
            h.events_of(&gw).pop().unwrap().seq
        );
        // A new spec is an update of the gateway.
        let mut spec = gateway_spec(3128);
        spec.env.insert("MORE".into(), "1".into());
        h.m.set_gateway("t1", spec).await.unwrap();
        let e = h.events_of(&gw).pop().unwrap();
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("updated", "the gateway's env replaced")
        );
    }

    #[tokio::test]
    async fn a_patch_is_an_event_only_when_it_changes_something() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let changed =
            h.m.update(&m.id, set_egress("none", None), None)
                .await
                .unwrap();
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("egress_changed", "egress open -> none")
        );
        let data = e.data.unwrap();
        assert_eq!(
            (&data["fields"], &data["from"], &data["to"]),
            (&json!(["egress"]), &json!("open"), &json!("none"))
        );
        assert_eq!(changed.version, e.seq);
        // The limits are what the tables hold for its internet traffic too: an egress change.
        let limits = api::UpdateMachineRequest {
            limits: Some(api::EgressLimits {
                bandwidth_mbit: Some(5),
                ..Default::default()
            }),
            ..Default::default()
        };
        let limited = h.m.update(&m.id, limits.clone(), None).await.unwrap();
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("egress_changed", "egress limits changed")
        );
        let data = e.data.unwrap();
        assert_eq!(data["fields"], json!(["limits"]));
        assert_eq!(data["limits"]["bandwidth_mbit"], 5);
        assert_eq!(limited.version, e.seq);
        // The same limits again change nothing.
        let same = h.m.update(&m.id, limits, None).await.unwrap();
        assert_eq!(same.version, limited.version);
        let sleep = |s: &str| api::UpdateMachineRequest {
            sleep: Some(s.into()),
            ..Default::default()
        };
        let three = h.m.update(&m.id, sleep("3h"), None).await.unwrap();
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("updated", "sleep changed")
        );
        assert_eq!(three.version, e.seq);
        // The same value again: no event, the version stays.
        let same = h.m.update(&m.id, sleep("3h"), None).await.unwrap();
        assert_eq!(same.version, three.version);
        let both = api::UpdateMachineRequest {
            sleep: Some("never".into()),
            metadata: Some(BTreeMap::from([(
                "briq_id".to_string(),
                "bq_1".to_string(),
            )])),
            ..Default::default()
        };
        h.m.update(&m.id, both, None).await.unwrap();
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(e.data, Some(json!({"fields": ["sleep", "metadata"]})));
    }

    #[tokio::test]
    async fn a_stale_if_match_is_refused_with_the_machine_as_it_is() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let stale = m.version - 1;
        let moved = |r: Result<api::Machine, MError>| match r {
            Err(MError::Moved(now)) => now.version,
            other => panic!("{other:?}"),
        };
        let sleep = api::UpdateMachineRequest {
            sleep: Some("3h".into()),
            ..Default::default()
        };
        assert_eq!(
            moved(h.m.update(&m.id, sleep.clone(), Some(stale)).await),
            m.version
        );
        assert_eq!(h.m.get(&m.id).unwrap().sleep, "30m", "nothing changed");
        assert_eq!(
            moved(
                h.m.stop(&m.id, Duration::from_secs(1), false, Some(stale))
                    .await
            ),
            m.version
        );
        assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
        assert_eq!(moved(h.m.start(&m.id, Some(stale)).await), m.version);
        assert_eq!(moved(h.m.wake(&m.id, Some(stale)).await), m.version);
        assert!(matches!(
            h.m.destroy(&m.id, Some(stale)).await,
            Err(MError::Moved(_))
        ));
        assert!(h.m.get(&m.id).is_ok());
        // The version read passes, once: the change moves it.
        let patched =
            h.m.update(&m.id, sleep.clone(), Some(m.version))
                .await
                .unwrap();
        assert_eq!(patched.sleep, "3h");
        assert_eq!(
            moved(h.m.update(&m.id, sleep, Some(m.version)).await),
            patched.version
        );
        let stopped =
            h.m.stop(&m.id, Duration::from_secs(1), false, Some(patched.version))
                .await
                .unwrap();
        h.m.destroy(&m.id, Some(stopped.version)).await.unwrap();
        assert!(h.m.get(&m.id).is_err());
    }

    #[tokio::test]
    async fn the_seq_goes_on_past_every_records_version_at_load() {
        let h = harness("10.64.0.0/22", 4096).await;
        // A record written at version 500 by a daemon whose log was lost after it.
        let mut r = record();
        r.version = 500;
        h.m.inner.store.put("machines", &r.id, &r).unwrap();
        h.m.load().unwrap();
        assert_eq!(h.m.get(&r.id).unwrap().version, 500);
        assert_eq!(
            h.m.inner.events.emit(Ev::normal(reason::HOST_STARTED, "")),
            501
        );
    }

    #[tokio::test]
    async fn recovery_says_what_it_adopted_and_what_it_stopped() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let ours = h.add("m_ours", state::RUNNING, 256);
        let pid = h
            .host
            .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
        ours.set_state(state::RUNNING, |r| {
            r.pid = pid;
            None
        });
        // Its process gone: it exited while no daemon ran.
        h.add("m_lost", state::STARTING, 256);
        // Its process there, but mid-start: not one to take over, ended (what fails an upgrade).
        let cut = h.add("m_cut", state::STARTING, 256);
        let cut_pid = h
            .host
            .left_running("m_cut", &h.m.inner.cfg.run_dir().join("m_cut"));
        cut.set_state(state::STARTING, |r| {
            r.pid = cut_pid;
            None
        });
        h.host.calls();
        assert_eq!(h.m.recover().await, (1, 1, 1));
        assert!(h.host.calls().contains(&format!("kill {cut_pid}")));
        let cut = h.events_of("m_cut").pop().unwrap();
        assert_eq!(
            cut.message,
            "left running by a previous daemon that could not hand it over: stopped"
        );
        let adopted = h.events_of("m_ours").pop().unwrap();
        assert_eq!(adopted.reason, "adopted");
        assert_eq!(adopted.data, Some(json!({"pid": pid})));
        assert_eq!(h.stored("m_ours").unwrap().version, adopted.seq);
        let lost = h.events_of("m_lost").pop().unwrap();
        assert_eq!(
            (lost.reason.as_str(), lost.kind.as_str()),
            ("stopped", "warning")
        );
        assert_eq!(lost.data, Some(json!({"reason": "host"})));
        assert_eq!(
            lost.message,
            "its process ended while no daemon ran: stopped"
        );
    }

    /// The next line of a streamed answer, as JSON, within five seconds.
    async fn next_line(w: &mut reqwest::Response, buf: &mut String) -> serde_json::Value {
        loop {
            if let Some(i) = buf.find('\n') {
                let l = serde_json::from_str(&buf[..i]).unwrap();
                buf.drain(..=i);
                return l;
            }
            let chunk = tokio::time::timeout(Duration::from_secs(5), w.chunk())
                .await
                .expect("a line in time")
                .unwrap()
                .expect("the stream is open");
            buf.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }

    #[tokio::test]
    async fn the_events_route_pages_watches_and_checks_if_match() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let st = Arc::new(crate::api::AppState {
            mgr: h.m.clone(),
            token: String::new(),
            metrics_token: String::new(),
            loopback: true,
            openapi: "",
            tls_fingerprint: String::new(),
        });
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", ln.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
        let m = h.m.create(h.request("web")).await.unwrap();
        let http = reqwest::Client::new();
        let get = |q: String| http.get(format!("{base}/v1/events{q}")).send();
        let r = get(format!("?machine={}", m.id)).await.unwrap();
        assert_eq!(r.status(), 200);
        let page: api::EventsPage = r.json().await.unwrap();
        let reasons: Vec<&str> = page.events.iter().map(|e| e.reason.as_str()).collect();
        assert_eq!(reasons, ["created", "starting", "started"]);
        assert_eq!(page.next, m.version.to_string());
        // A cursor the log cannot answer, and queries that make no sense.
        let r = get("?since=99".into()).await.unwrap();
        assert_eq!(r.status(), 410);
        let e: api::ApiError = r.json().await.unwrap();
        assert_eq!((e.code.as_str(), e.oldest), ("gone", Some(1)));
        for q in ["?since=x", "?type=fatal", "?machine=../x", "?watch=yes"] {
            let r = get(q.into()).await.unwrap();
            assert_eq!(r.status(), 400, "{q}");
        }
        // A watch from the first event: the rest of the log, then what happens next.
        let mut w = get(format!("?watch=true&since=1&machine={}", m.id))
            .await
            .unwrap();
        assert_eq!(w.headers()["content-type"], "application/x-ndjson");
        let mut buf = String::new();
        assert_eq!(next_line(&mut w, &mut buf).await["reason"], "starting");
        assert_eq!(next_line(&mut w, &mut buf).await["reason"], "started");
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        assert_eq!(next_line(&mut w, &mut buf).await["reason"], "stopping");
        assert_eq!(next_line(&mut w, &mut buf).await["reason"], "stopped");
        // If-Match on a PATCH: stale is 409 with the machine, current passes, garbage is 400.
        let now = h.m.get(&m.id).unwrap().version;
        let patch = |v: String| {
            http.patch(format!("{base}/v1/machines/{}", m.id))
                .header("if-match", v)
                .json(&json!({"sleep": "3h"}))
                .send()
        };
        let r = patch((now - 1).to_string()).await.unwrap();
        assert_eq!(r.status(), 409);
        let e: api::ApiError = r.json().await.unwrap();
        assert_eq!(e.code, "conflict");
        assert_eq!(e.machine.map(|m| m.version), Some(now));
        let r = patch(format!("\"{now}\"")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.json::<api::Machine>().await.unwrap().version > now);
        let r = patch("soon".into()).await.unwrap();
        assert_eq!(r.status(), 400);
        // A lifecycle POST takes it too.
        let r = http
            .post(format!("{base}/v1/machines/{}/start", m.id))
            .header("if-match", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 409);
    }

    // --- probes (ADR 0022) ---

    fn http_probe(port: u16) -> api::Probe {
        api::Probe {
            http: Some(api::HttpProbe {
                port,
                path: "/".into(),
            }),
            period_sec: 1,
            ..Default::default()
        }
    }

    fn exec_probe(cmd: &str) -> api::Probe {
        api::Probe {
            exec: Some(cmd.split(' ').map(String::from).collect()),
            period_sec: 1,
            ..Default::default()
        }
    }

    fn readiness(p: api::Probe) -> api::Probes {
        api::Probes {
            readiness: Some(p),
            ..Default::default()
        }
    }

    impl Harness {
        fn probed(&self, name: &str, probes: api::Probes) -> api::CreateMachineRequest {
            let mut r = self.request(name);
            r.probes = Some(probes);
            r
        }

        fn last_event(&self, id: &str) -> api::Event {
            self.events_of(id).pop().expect("an event")
        }
    }

    /// Waits until `f` holds, a tenth of a second at a time, within ten minutes: on a paused
    /// clock, a probe's periods pass at once.
    async fn eventually(what: &str, f: impl Fn() -> bool) {
        for _ in 0..6000 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("never: {what}");
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_sets_ready_and_says_when_it_changes() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        // Without probes: ready once running, as Kubernetes; never while stopped.
        let plain = h.m.create(h.request("plain")).await.unwrap();
        assert!(plain.ready);
        assert!(plain.probes.is_empty() && plain.probes_status.is_empty());
        let stopped =
            h.m.stop(&plain.id, Duration::from_secs(1), false, None)
                .await
                .unwrap();
        assert!(!stopped.ready);
        // A readiness probe: not ready while it fails, and never was, so no `not_ready`.
        let m =
            h.m.create(h.probed("web", readiness(http_probe(8080))))
                .await
                .unwrap();
        h.host.http(&m.ip, 8080, 503);
        assert_eq!((m.state.as_str(), m.ready), (state::RUNNING, false));
        let status = || h.m.get(&m.id).unwrap().probes_status.readiness;
        eventually("two failures", || status().is_some_and(|s| s.failures >= 2)).await;
        let st = status().unwrap();
        assert_eq!((st.passed, st.message.as_str()), (false, "HTTP 503"));
        assert!(!h.reasons(&m.id).contains(&"not_ready".to_string()));
        // It passes: ready, an event that moves the version.
        h.host.http(&m.ip, 8080, 200);
        eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
        let ev = h.last_event(&m.id);
        assert_eq!(
            (ev.reason.as_str(), ev.kind.as_str(), ev.message.as_str()),
            ("ready", "normal", "ready: readiness passed")
        );
        assert_eq!(ev.data, Some(json!({"probe": "readiness"})));
        assert_eq!(h.m.get(&m.id).unwrap().version, ev.seq);
        assert_eq!(h.stored(&m.id).unwrap().version, ev.seq);
        // Three failures in a row: not ready, a warning that says why.
        h.host.http(&m.ip, 8080, 500);
        eventually("not ready", || !h.m.get(&m.id).unwrap().ready).await;
        let ev = h.last_event(&m.id);
        assert_eq!(
            (ev.reason.as_str(), ev.kind.as_str(), ev.message.as_str()),
            (
                "not_ready",
                "warning",
                "not ready: readiness failed 3 times in a row: HTTP 500"
            )
        );
        assert_eq!(ev.data, Some(json!({"probe": "readiness", "failures": 3})));
        // A probe is not a use: the sleep window never moved.
        let now = h.m.get(&m.id).unwrap();
        assert_eq!(now.last_used_at, m.last_used_at);
        assert!(h
            .host
            .calls()
            .contains(&format!("probe_http {}:8080/", m.ip)));
        // Stopped: not ready, and the probes stop with the process.
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.host.calls();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!h.host.calls().iter().any(|c| c.starts_with("probe_")));
        assert!(!h.m.get(&m.id).unwrap().ready);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_follows_ready_and_says_why_it_is_not() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m =
            h.m.create(h.probed("web", readiness(http_probe(8080))))
                .await
                .unwrap();
        h.host.http(&m.ip, 8080, 503);
        // For running: at once, as before.
        let up = h.m.wait(&m.id, Until::Running, Duration::from_secs(30));
        assert_eq!(up.await.unwrap().state, state::RUNNING);
        // For ready: not by the timeout, answered with the machine and its probe's word.
        match h.m.wait(&m.id, Until::Ready, Duration::from_secs(5)).await {
            Err(MError::NotReady(now)) => {
                assert!(!now.ready);
                assert_eq!(now.probes_status.readiness.unwrap().message, "HTTP 503");
            }
            other => panic!("{other:?}"),
        }
        // A wait under way answers once the probe passes.
        let (mgr, id) = (h.m.clone(), m.id.clone());
        let waiting =
            tokio::spawn(async move { mgr.wait(&id, Until::Ready, Duration::from_secs(60)).await });
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!waiting.is_finished());
        h.host.http(&m.ip, 8080, 200);
        assert!(waiting.await.unwrap().unwrap().ready);
        // A machine without probes is ready with `running`.
        let plain = h.m.create(h.request("plain")).await.unwrap();
        let ready = h.m.wait(&plain.id, Until::Ready, Duration::from_secs(1));
        assert!(ready.await.unwrap().ready);
    }

    #[tokio::test(start_paused = true)]
    async fn a_startup_probe_that_fails_fails_the_boot_a_caller_waits_on() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.host.answers("pg_isready", 1);
        let probes = api::Probes {
            startup: Some(exec_probe("pg_isready")),
            liveness: Some(exec_probe("true")),
            ..Default::default()
        };
        let m = h.m.create(h.probed("pg", probes)).await.unwrap();
        // The create answers at `running`; the caller waits for `ready`.
        assert_eq!((m.state.as_str(), m.ready), (state::RUNNING, false));
        let failed = match h.m.wait(&m.id, Until::Ready, Duration::from_secs(60)).await {
            Err(MError::BootFailed(failed)) => failed,
            other => panic!("{other:?}"),
        };
        assert_eq!(failed.state, state::ERROR);
        assert!(
            failed
                .error
                .starts_with("the startup probe failed 3 times in a row: exit 1: no: "),
            "{}",
            failed.error
        );
        assert_eq!(
            h.reasons(&m.id),
            ["created", "starting", "started", "startup_failed"]
        );
        let ev = h.last_event(&m.id);
        assert_eq!(ev.kind, "warning");
        assert_eq!(ev.data, Some(json!({"failures": 3, "boot": true})));
        assert_eq!(
            ev.message,
            "startup failed 3 times in a row: exit 1: no: the boot failed"
        );
        // The guest was asked to stop; nothing restarts a boot that failed (ADR 0011), and
        // liveness never ran before startup passed.
        let calls = h.host.calls();
        assert!(
            calls.contains(&"shutdown 1000 10s".to_string()),
            "{calls:?}"
        );
        assert!(!calls.iter().any(|c| c.ends_with(" true")), "{calls:?}");
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
        assert_eq!(h.stored(&m.id).unwrap().boots, 1);
        assert!(h.host.alive().is_empty());
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(h.m.inner.stats.starts_failed.load(Relaxed), 1);
        // For running, it will not run: the reason, as before.
        match h
            .m
            .wait(&m.id, Until::Running, Duration::from_secs(1))
            .await
        {
            Err(MError::NotRunning(why)) => assert_eq!(why, failed.error),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_startup_probe_failing_a_restart_is_a_crash_for_the_policy() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let probes = api::Probes {
            startup: Some(exec_probe("check")),
            ..Default::default()
        };
        let m = h.m.create(h.probed("app", probes)).await.unwrap();
        // Startup passed and there is no readiness probe: ready, through the startup probe.
        eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
        assert_eq!(h.last_event(&m.id).message, "ready: startup passed");
        // It crashes; the restart's startup fails: a crash too, restarted by the policy.
        h.host.answers("check", 1);
        h.host.exit(h.stored(&m.id).unwrap().pid, 1, false);
        h.events_reach(&m.id, reason::STARTUP_FAILED, 1).await;
        h.events_reach(&m.id, reason::RESTARTING, 2).await;
        let evs = h.events_of(&m.id);
        let failed = evs.iter().find(|e| e.reason == "startup_failed").unwrap();
        assert_eq!(failed.data, Some(json!({"failures": 3, "boot": false})));
        assert!(
            failed.message.ends_with(": ending it"),
            "{}",
            failed.message
        );
        let exited: Vec<_> = evs.iter().filter(|e| e.reason == "exited").collect();
        assert_eq!(exited[1].data.as_ref().unwrap()["restarting"], true);
        let now = h.m.get(&m.id).unwrap();
        assert_eq!((now.state.as_str(), now.restarts), (state::STOPPED, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn liveness_restarts_under_the_policy_and_not_under_no() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let alive = "test -f /tmp/alive";
        let probes = api::Probes {
            liveness: Some(exec_probe(alive)),
            ..Default::default()
        };
        let m = h.m.create(h.probed("live", probes.clone())).await.unwrap();
        // Liveness does not gate `ready`.
        assert!(m.ready);
        h.host.answers(alive, 1);
        h.events_reach(&m.id, reason::LIVENESS_FAILED, 1).await;
        let after: Vec<String> = h.reasons(&m.id)[3..].to_vec();
        assert_eq!(after, ["liveness_failed", "exited", "restarting"]);
        let ev = h.events_of(&m.id)[3].clone();
        assert_eq!(
            (ev.kind.as_str(), ev.message.as_str()),
            (
                "warning",
                "liveness failed 3 times in a row: exit 1: no: ending it"
            )
        );
        assert_eq!(ev.data, Some(json!({"failures": 3})));
        // Ended as a stop is (asked, then killed after 10 s), and a failure for the policy
        // whatever the code the process gave.
        assert!(h.host.calls().contains(&"shutdown 1000 10s".to_string()));
        let now = h.m.get(&m.id).unwrap();
        assert_eq!(
            (
                now.state.as_str(),
                now.stopped_reason.as_str(),
                now.restarts
            ),
            (state::STOPPED, stop::EXIT, 1)
        );
        let exit = now.exit.unwrap();
        assert!(exit.restarting);
        let at = now.restarting_at.expect("when it starts again");
        assert_eq!((at - exit.at).num_seconds(), 10);
        // It comes back, and its probes run again.
        h.host.answers(alive, 0);
        h.events_reach(&m.id, reason::STARTED, 2).await;
        let again = h.m.get(&m.id).unwrap();
        assert_eq!(again.state, state::RUNNING);
        assert_eq!(again.restarting_at, None);
        eventually("probed again", || {
            h.m.get(&m.id)
                .unwrap()
                .probes_status
                .liveness
                .is_some_and(|s| s.passed)
        })
        .await;
        // Under `restart: no` it is ended and stays stopped.
        let mut req = h.probed("once", probes);
        req.restart = Some(api::RestartPolicy {
            policy: "no".into(),
            max_retries: 0,
        });
        let once = h.m.create(req).await.unwrap();
        h.host.answers(alive, 1);
        h.events_reach(&once.id, reason::LIVENESS_FAILED, 1).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        let now = h.m.get(&once.id).unwrap();
        assert_eq!(
            (now.state.as_str(), now.stopped_reason.as_str()),
            (state::STOPPED, stop::EXIT)
        );
        assert!(!now.exit.unwrap().restarting);
        assert_eq!(now.restarting_at, None);
        assert!(!h.reasons(&once.id).contains(&"restarting".to_string()));
        assert_eq!(h.stored(&once.id).unwrap().boots, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn restarts_back_off_and_a_third_in_a_row_is_a_crash_loop() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let mut req = h.request("crash");
        req.restart = Some(api::RestartPolicy {
            policy: "always".into(),
            max_retries: 0,
        });
        let m = h.m.create(req).await.unwrap();
        for n in 1..=4 {
            h.host.exit(h.stored(&m.id).unwrap().pid, 1, false);
            h.events_reach(&m.id, reason::STARTED, n + 1).await;
        }
        let evs = h.events_of(&m.id);
        let delays: Vec<u64> = evs
            .iter()
            .filter(|e| e.reason == "restarting")
            .map(|e| e.data.as_ref().unwrap()["delay_sec"].as_u64().unwrap())
            .collect();
        assert_eq!(delays, [10, 20, 40, 80]);
        // From the third restart in a row, each is a crash loop, right after its `restarting`.
        let loops: Vec<&api::Event> = evs.iter().filter(|e| e.reason == "crash_loop").collect();
        assert_eq!(loops.len(), 2);
        assert_eq!(loops[0].data, Some(json!({"restarts": 3, "delay_sec": 40})));
        assert_eq!(
            loops[0].message,
            "restarted 3 times in a row, no run of 10 minutes between: next in 40 s"
        );
        let i = evs.iter().position(|e| e.reason == "crash_loop").unwrap();
        assert_eq!(evs[i - 1].data.as_ref().unwrap()["attempt"], 3);
        // A run of 10 minutes ends the loop: the next restart waits 10 s again. The count
        // `max_retries` reads is not reset by it.
        e_started_minutes_ago(&h, &m.id, 11);
        h.host.exit(h.stored(&m.id).unwrap().pid, 1, false);
        h.events_reach(&m.id, reason::RESTARTING, 5).await;
        let last = h.events_of(&m.id);
        let last = last
            .iter()
            .rev()
            .find(|e| e.reason == "restarting")
            .unwrap();
        assert_eq!(last.data.as_ref().unwrap()["delay_sec"], 10);
        assert_eq!(last.data.as_ref().unwrap()["attempt"], 5);
        assert_eq!(
            h.reasons(&m.id)
                .iter()
                .filter(|r| *r == "crash_loop")
                .count(),
            2
        );
        let r = h.stored(&m.id).unwrap();
        assert_eq!((r.restarts, r.recent_restarts), (5, 1));
    }

    // --- exec sessions (ADR 0029) ---

    fn session_req(cmd: &[&str], tty: bool) -> api::session::ExecSession {
        api::session::ExecSession {
            cmd: cmd.iter().map(|c| c.to_string()).collect(),
            tty,
            cols: 100,
            rows: 30,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_session_streams_both_ways_and_is_an_event_not_a_version() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("sbx")).await.unwrap();
        h.host.answers("sh", 3);
        let mut s =
            h.m.open_session(&m.id, session_req(&["sh"], true))
                .await
                .unwrap();
        assert_eq!(s.machine, m.id);
        let pid = h
            .host
            .calls()
            .into_iter()
            .find(|c| c.starts_with("session "))
            .unwrap();
        assert!(pid.ends_with(" sh tty=true"), "{pid}");
        // Input goes in, the command's answer comes back, the code ends it.
        for f in [
            guest::Request {
                op: "stdin".into(),
                data: b"ls\n".to_vec(),
                ..Default::default()
            },
            guest::Request {
                op: "resize".into(),
                cols: 120,
                rows: 40,
                ..Default::default()
            },
            guest::Request {
                op: "close_stdin".into(),
                ..Default::default()
            },
        ] {
            guestc::write_request(&mut s.conn, &f).await.unwrap();
        }
        let out = guestc::collect(&mut s.conn).await.unwrap();
        assert_eq!(out.stdout, b"ls\n120x40\n");
        assert_eq!(out.code, 3);
        // An event says someone came in; the machine's version did not move.
        let ev =
            h.m.inner
                .events
                .read(0, &events::Filter::default(), 1000)
                .unwrap();
        let opened = ev
            .events
            .iter()
            .find(|e| e.reason == reason::SESSION_OPENED)
            .unwrap();
        assert_eq!(
            (opened.machine_id.as_str(), opened.message.as_str()),
            (m.id.as_str(), "sh on a terminal")
        );
        assert_eq!(opened.data, Some(json!({"command": "sh", "tty": true})));
        assert_eq!(h.m.get(&m.id).unwrap().version, m.version);
    }

    #[tokio::test]
    async fn an_open_session_keeps_the_machine_awake() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("sbx")).await.unwrap();
        let s =
            h.m.open_session(&m.id, session_req(&["sh"], true))
                .await
                .unwrap();
        let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
        let idle = || h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
        idle();
        assert_eq!(
            h.m.get(&m.id).unwrap().sleeps_at,
            None,
            "no sleep while in use"
        );
        h.m.tick().await;
        assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
        // The session's end is a use: the window starts again from it.
        drop(s);
        let after = h.m.get(&m.id).unwrap();
        assert!(after.last_used_at > long_ago);
        assert!(after.sleeps_at.is_some());
        h.m.tick().await;
        assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
        idle();
        h.m.tick().await;
        let slept = h.m.get(&m.id).unwrap();
        assert_eq!(
            (slept.state.as_str(), slept.stopped_reason.as_str()),
            (state::STOPPED, stop::IDLE)
        );
    }

    #[tokio::test]
    async fn a_command_in_flight_keeps_the_machine_awake() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("job")).await.unwrap();
        *h.host.exec_takes.lock().unwrap() = Duration::from_secs(3);
        let mgr = h.m.clone();
        let id = m.id.clone();
        let job = tokio::spawn(async move {
            mgr.exec(
                &id,
                api::ExecRequest {
                    cmd: vec!["migrate".into()],
                    ..Default::default()
                },
            )
            .await
        });
        eventually("the command runs", || {
            h.host.execs_now.load(std::sync::atomic::Ordering::SeqCst) == 1
        })
        .await;
        // Its window ran out while it runs: it is in use, it does not sleep under it.
        h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at =
            Some(Utc::now() - chrono::Duration::hours(1));
        h.m.tick().await;
        assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
        let out = job.await.unwrap().unwrap();
        assert_eq!((out.exit_code, out.stdout.as_str()), (0, "ok\n"));
        assert!(
            h.m.get(&m.id).unwrap().last_used_at > Some(Utc::now() - chrono::Duration::minutes(1))
        );
    }

    #[tokio::test]
    async fn a_session_wakes_a_sleeping_machine_or_says_why_not() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("sbx")).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        let mut asleep = session_req(&["sh"], false);
        asleep.wake = false;
        match h.m.open_session(&m.id, asleep).await {
            Err(MError::NotRunning(why)) => assert_eq!(why, "stopped (idle)"),
            other => panic!("{:?}", other.err()),
        }
        assert!(matches!(
            h.m.open_session(&m.id, session_req(&[], false)).await.err(),
            Some(MError::Invalid(_))
        ));
        let s =
            h.m.open_session(&m.id, session_req(&["sh"], false))
                .await
                .unwrap();
        assert_eq!(h.m.get(&s.machine).unwrap().state, state::RUNNING);
        assert!(matches!(
            h.m.open_session("m_none", session_req(&["sh"], false))
                .await
                .err(),
            Some(MError::NotFound)
        ));
    }

    #[tokio::test]
    async fn a_session_on_an_init_older_than_sessions_is_refused_naming_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        // An init older than the version report: it would run the command as a plain exec,
        // no input, no terminal.
        *h.host.init_version.lock().unwrap() = String::new();
        let m = h.m.create(h.request("old")).await.unwrap();
        h.host.calls();
        match h.m.open_session(&m.id, session_req(&["sh"], true)).await {
            Err(MError::Conflict(why)) => assert_eq!(
                why,
                "the machine's init (older than the version report) does not know `session`: it is older than this daemon; the machine gets this daemon's init when its root disk is made again (an image change)"
            ),
            other => panic!("{:?}", other.err()),
        }
        assert!(
            !h.host.calls().iter().any(|c| c.starts_with("session ")),
            "nothing reached the guest"
        );
        // An exec is the old way in: it runs.
        let exec = api::ExecRequest {
            cmd: vec!["true".into()],
            wake: true,
            ..Default::default()
        };
        let out = h.m.exec(&m.id, exec).await.unwrap();
        assert_eq!(out.exit_code, 0);
        // One of a release before sessions, named.
        *h.host.init_version.lock().unwrap() = "0.0.9+a".into();
        let m = h.m.create(h.request("older")).await.unwrap();
        match h.m.open_session(&m.id, session_req(&["sh"], false)).await {
            Err(MError::Conflict(why)) => assert!(
                why.starts_with("the machine's init (0.0.9+a) does not know `session`"),
                "{why}"
            ),
            other => panic!("{:?}", other.err()),
        }
        // This release's: a session.
        *h.host.init_version.lock().unwrap() = api::VERSION.into();
        let m = h.m.create(h.request("new")).await.unwrap();
        assert!(h
            .m
            .open_session(&m.id, session_req(&["sh"], false))
            .await
            .is_ok());
    }

    /// Moves the current run's start back, as if it had run that long.
    fn e_started_minutes_ago(h: &Harness, id: &str, minutes: i64) {
        let e = h.m.entry(id).unwrap();
        e.rec.lock().unwrap().started_at = Some(Utc::now() - chrono::Duration::minutes(minutes));
    }

    #[tokio::test(start_paused = true)]
    async fn the_ingress_waits_for_a_woken_machine_to_be_ready() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m =
            h.m.create(h.probed("web", readiness(http_probe(8080))))
                .await
                .unwrap();
        eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
        let e = h.m.entry(&m.id).unwrap();
        h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        // A connection wakes it; its program is not serving yet: the proxy waits.
        h.host.http(&m.ip, 8080, 503);
        let mgr = h.m.clone();
        let id = m.id.clone();
        let dial = tokio::spawn(async move { mgr.ready_addr(&id, Duration::from_secs(120)).await });
        eventually("woken", || h.m.get(&m.id).unwrap().state == state::RUNNING).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!dial.is_finished());
        h.host.http(&m.ip, 8080, 200);
        let ip = dial.await.unwrap().unwrap();
        assert_eq!(ip.to_string(), m.ip);
        assert!(h.m.get(&m.id).unwrap().ready);
        // Running and not ready: readiness gates every connection, not only a wake's.
        h.host.http(&m.ip, 8080, 500);
        eventually("not ready", || !h.m.get(&m.id).unwrap().ready).await;
        match h.m.ready_addr(&m.id, Duration::from_secs(5)).await {
            Err(MError::NotReady(_)) => {}
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_exec_that_wakes_a_machine_runs_once_it_is_ready() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m =
            h.m.create(h.probed("db", readiness(http_probe(8080))))
                .await
                .unwrap();
        eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
        let e = h.m.entry(&m.id).unwrap();
        h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        // The command wakes it; its program is not serving yet: the command waits.
        h.host.http(&m.ip, 8080, 503);
        let mgr = h.m.clone();
        let id = m.id.clone();
        let run = tokio::spawn(async move { mgr.running_vsock(&id, true).await });
        eventually("woken", || h.m.get(&m.id).unwrap().state == state::RUNNING).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!run.is_finished());
        h.host.http(&m.ip, 8080, 200);
        run.await.unwrap().unwrap();
        assert!(h.m.get(&m.id).unwrap().ready);
        // Running and not ready, no wake: the command runs at once, as in a pod.
        h.host.http(&m.ip, 8080, 500);
        eventually("not ready", || !h.m.get(&m.id).unwrap().ready).await;
        h.m.running_vsock(&m.id, true).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn probe_executions_take_turns_across_the_host() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.m.inner
            .probe_gate
            .forget_permits(probes::PROBES_AT_ONCE - 2);
        *h.host.exec_takes.lock().unwrap() = Duration::from_secs(2);
        let mut ids = Vec::new();
        for i in 0..5 {
            let req = h.probed(&format!("m{i}"), readiness(exec_probe("ready-check")));
            ids.push(h.m.create(req).await.unwrap().id);
        }
        // Each one gets its turn: all ready in the end, never more than two at once.
        eventually("all ready", || {
            ids.iter().all(|id| h.m.get(id).unwrap().ready)
        })
        .await;
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(h.host.execs_most.load(SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_of_the_probes_applies_at_once_to_a_running_machine() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        assert!(m.ready);
        h.host.http(&m.ip, 8080, 503);
        let set = |p: api::Probes| api::UpdateMachineRequest {
            probes: Some(p),
            ..Default::default()
        };
        let patched =
            h.m.update(&m.id, set(readiness(http_probe(8080))), None)
                .await
                .unwrap();
        assert_eq!(patched.probes, readiness(http_probe(8080)));
        assert!(!patched.ready);
        let evs = h.events_of(&m.id);
        let got: Vec<(&str, &str)> = evs[3..]
            .iter()
            .map(|e| (e.reason.as_str(), e.message.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("updated", "probes changed"),
                ("not_ready", "not ready: its probes changed")
            ]
        );
        assert_eq!(h.stored(&m.id).unwrap().probes, readiness(http_probe(8080)));
        eventually("probed", || {
            h.m.get(&m.id)
                .unwrap()
                .probes_status
                .readiness
                .is_some_and(|s| s.failures >= 1)
        })
        .await;
        // The probes taken off: ready at once, the results gone, no probe runs any more.
        let cleared =
            h.m.update(&m.id, set(api::Probes::default()), None)
                .await
                .unwrap();
        assert!(cleared.ready && cleared.probes_status.is_empty());
        assert_eq!(h.last_event(&m.id).message, "ready: its probes changed");
        h.host.calls();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!h.host.calls().iter().any(|c| c.starts_with("probe_")));
        // The same probes again change nothing.
        let v = h.m.get(&m.id).unwrap().version;
        let same =
            h.m.update(&m.id, set(api::Probes::default()), None)
                .await
                .unwrap();
        assert_eq!(same.version, v);
        // Refused with the field named, on a PATCH as on a create.
        let bad = readiness(api::Probe::default());
        let want = "probes.readiness: exactly one of exec, tcp and http";
        assert_eq!(
            refused(h.m.update(&m.id, set(bad.clone()), None).await),
            want
        );
        assert_eq!(refused(h.m.create(h.probed("bad", bad)).await), want);
    }

    #[tokio::test(start_paused = true)]
    async fn a_gateway_with_a_readiness_probe_is_waited_for_ready_not_its_port() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let mut spec = gateway_spec(3128);
        spec.probes = readiness(api::Probe {
            tcp: Some(3128),
            period_sec: 1,
            ..Default::default()
        });
        let gw = h.m.set_gateway("t1", spec).await.unwrap().gateway.unwrap();
        let ip: Ipv4Addr = gw.ip.parse().unwrap();
        h.host.closed.lock().unwrap().insert((ip, 3128));
        h.host.calls();
        // Not ready within the boot timeout: the consumer's start fails, the gateway errs.
        let err = h.m.create(h.consumer("c")).await.unwrap_err();
        let m = match err {
            MError::BootFailed(m) => m,
            other => panic!("{other:?}"),
        };
        assert!(
            m.error
                .starts_with("the tenant's gateway did not come up: not ready: "),
            "{}",
            m.error
        );
        assert_eq!(h.gateway_view().state, state::ERROR);
        let calls = h.host.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("wait_port")),
            "{calls:?}"
        );
        assert!(calls.contains(&format!("probe_tcp {ip}:3128")), "{calls:?}");
        // Its port answers: the next start runs it, ready, then the consumer.
        h.host.closed.lock().unwrap().clear();
        let c = h.m.start(&m.id, None).await.unwrap();
        assert_eq!(c.state, state::RUNNING);
        let gw = h.m.get(&gw.machine_id).unwrap();
        assert!(gw.ready);
        assert_eq!(h.last_event(&gw.id).reason, "gateway_started");
    }

    #[tokio::test]
    async fn an_adopted_machine_runs_its_probes_again() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let e = h.add("m_ours", state::RUNNING, 256);
        let pid = h
            .host
            .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
        e.set_state(state::RUNNING, |r| {
            r.pid = pid;
            r.probes = readiness(http_probe(8080));
            None
        });
        h.host.http("10.64.1.2", 8080, 503);
        assert_eq!(h.m.recover().await, (1, 0, 0));
        // Not ready until its readiness probe passes again: results are not kept.
        let m = h.m.get("m_ours").unwrap();
        assert_eq!((m.state.as_str(), m.ready), (state::RUNNING, false));
        h.host.http("10.64.1.2", 8080, 200);
        tokio::time::timeout(Duration::from_secs(10), async {
            while !h.m.get("m_ours").unwrap().ready {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    // --- metrics, conditions, top (ADR 0021) ---

    #[tokio::test]
    async fn metrics_hold_every_machine_by_its_labels_from_the_last_measure() {
        let h = harness("10.64.0.0/22", 4096).await;
        let run = h.metered("m_run", state::RUNNING, "2026-10-21T10:00:00Z");
        let gw = h.metered("m_gw", state::RUNNING, "2026-10-21T10:00:00Z");
        let _stopped = h.metered("m_stop", state::STOPPED, "2026-10-21T10:00:00Z");
        let _broken = h.metered("m_err", state::ERROR, "2026-10-21T10:00:00Z");
        for (e, name, ip) in [(&run, "db", "10.64.1.2"), (&gw, "gateway", "10.64.1.3")] {
            let mut r = e.rec.lock().unwrap();
            r.name = name.into();
            r.ip = ip.into();
        }
        gw.rec.lock().unwrap().role = Some(Role::Gateway);
        h.m.inner.net.count("10.64.1.2").await.unwrap();
        h.pool.answer(
            "space",
            "byard/m/m_run\t-\t4096\t0\nbyard/m/m_run/root\t8589934592\t52428800\t1048576\n",
        );
        h.pool.answer("used,available", "950\n50\n");
        h.host.cpu("m_run", 2_000_000);
        h.m.measure(at("2026-10-21T10:00:15Z")).await;
        h.host.cpu("m_run", 4_500_000);
        h.host.memory("m_run", 100 << 20);
        h.host.internet("10.64.1.2", 1000, 10);
        h.m.traffic("m_run").unwrap().sent(300);
        h.m.measure(at("2026-10-21T10:00:30Z")).await;
        h.m.assess(at("2026-10-21T10:00:30Z")).await;
        // A start's time is measured from `starting` to `running`.
        run.set_state(state::STARTING, |_| None);
        run.set_state(state::RUNNING, |_| None);
        let text = h.m.metrics();
        crate::metrics::check_exposition(&text);
        let lines: Vec<&str> = text.lines().collect();
        let db = r#"machine="m_run",tenant="t1",name="db""#;
        for want in [
            format!("briqyard_machine_cpu_seconds_total{{{db}}} 2.5"),
            format!("briqyard_machine_memory_bytes{{{db}}} 104857600"),
            format!("briqyard_machine_memory_limit_bytes{{{db}}} 536870912"),
            format!("briqyard_machine_disk_used_bytes{{{db}}} 53481472"),
            format!("briqyard_machine_internet_in_bytes_total{{{db}}} 1000"),
            format!("briqyard_machine_internet_out_bytes_total{{{db}}} 10"),
            format!("briqyard_machine_ingress_out_bytes_total{{{db}}} 300"),
            format!("briqyard_machine_egress_dropped_packets_total{{{db}}} 0"),
            format!("briqyard_machine_restarts_total{{{db}}} 0"),
            format!("briqyard_machine_state{{{db},state=\"running\"}} 1"),
            r#"briqyard_machine_state{machine="m_gw",tenant="t1",name="gateway",role="gateway",state="running"} 1"#.into(),
            r#"briqyard_machine_state{machine="m_err",tenant="t1",name="db",state="error"} 1"#.into(),
            r#"briqyard_machine_state{machine="m_stop",tenant="t1",name="db",state="stopped"} 1"#.into(),
            // The host's, the names from before included.
            r#"briqyard_machines{state="running"} 2"#.into(),
            "briqyard_machines_total 4".into(),
            r#"briqyard_memory_mb{kind="used"} 1024"#.into(),
            r#"briqyard_pool_bytes{kind="size"} 1000"#.into(),
            r#"briqyard_pool_bytes{kind="free"} 50"#.into(),
            r#"briqyard_host_condition{condition="memory_pressure"} 0"#.into(),
            r#"briqyard_host_condition{condition="disk_pressure"} 1"#.into(),
            r#"briqyard_events_total{type="warning",reason="host_condition"} 1"#.into(),
            "briqyard_boots_total 0".into(),
        ] {
            assert!(lines.contains(&want.as_str()), "{want}\n{text}");
        }
        // One state series per machine; a boot time only once a start was measured.
        let states = lines
            .iter()
            .filter(|l| l.starts_with(r#"briqyard_machine_state{machine="m_run""#))
            .count();
        assert_eq!(states, 1);
        let boots: Vec<&&str> = lines
            .iter()
            .filter(|l| l.starts_with("briqyard_machine_boot_seconds{"))
            .collect();
        assert_eq!(boots.len(), 1, "{boots:?}");
        assert!(boots[0].starts_with(&format!("briqyard_machine_boot_seconds{{{db}}} ")));
        // A scrape asks nothing of the host: no zfs call, no cgroup read.
        h.pool.calls();
        h.host.cgroups.lock().unwrap().clear();
        let again = h.m.metrics();
        assert!(h.pool.calls().is_empty());
        assert!(again.contains(&format!("briqyard_machine_memory_bytes{{{db}}} 104857600")));
    }

    impl Harness {
        /// The host's events of a reason, oldest first.
        fn host_events(&self, reason: &str) -> Vec<api::Event> {
            let all = self.m.inner.events.read(0, &Default::default(), 5000);
            all.unwrap()
                .events
                .into_iter()
                .filter(|e| e.reason == reason)
                .collect()
        }
    }

    #[tokio::test]
    async fn conditions_turn_true_and_clear_with_their_events() {
        let h = harness("10.64.0.0/22", 1000).await;
        h.pool.answer("used,available", "100\n900\n");
        let e = h.add("m_a", state::RUNNING, 960);
        let t0 = at("2026-10-21T10:00:00Z");
        h.m.assess(t0).await;
        let c = h.m.conditions();
        assert_eq!(
            (c[0].kind.as_str(), c[0].status, c[0].since),
            ("memory_pressure", true, t0)
        );
        assert_eq!(c[0].message, "960 MB of 1000 committed (96%), over 95%");
        assert!(!c[1].status, "{:?}", c[1]);
        let evs = h.host_events(reason::HOST_CONDITION);
        assert_eq!(evs.len(), 1, "only a change is an event: {evs:?}");
        assert_eq!(
            (evs[0].kind.as_str(), evs[0].message.as_str()),
            (
                "warning",
                "memory_pressure: 960 MB of 1000 committed (96%), over 95%"
            )
        );
        assert_eq!(
            evs[0].data,
            Some(json!({"condition": "memory_pressure", "status": true}))
        );
        // Still true at the next tick: no event, the time it turned kept.
        h.m.assess(t0 + chrono::Duration::seconds(15)).await;
        assert_eq!(h.host_events(reason::HOST_CONDITION).len(), 1);
        assert_eq!(h.m.conditions()[0].since, t0);
        // The machine stops: cleared, a normal event.
        e.set_state(state::STOPPED, |_| None);
        let t1 = t0 + chrono::Duration::seconds(30);
        h.m.assess(t1).await;
        let evs = h.host_events(reason::HOST_CONDITION);
        assert_eq!(
            (evs[1].kind.as_str(), evs[1].message.as_str()),
            (
                "normal",
                "memory_pressure cleared: 0 MB of 1000 committed (0%)"
            )
        );
        assert_eq!(h.m.conditions()[0].since, t1);
        // The pool fills: disk pressure; a pool that cannot be read leaves it as it was.
        h.pool.answer("used,available", "950\n50\n");
        h.m.assess(t1).await;
        assert!(h.m.conditions()[1].status);
        assert_eq!(
            h.host_events(reason::HOST_CONDITION)[2].message,
            "disk_pressure: pool 0.0 GB free of 0.0 (5%), under 10%"
        );
        h.pool.answer("used,available", "-\n");
        h.m.assess(t1).await;
        assert!(h.m.conditions()[1].status, "kept");
        assert_eq!(h.host_events(reason::HOST_CONDITION).len(), 3);
    }

    #[tokio::test]
    async fn under_disk_pressure_the_oldest_unused_images_go_until_the_pool_is_back() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        // The seeded image is cloned by a machine; then four more, oldest first.
        h.m.create(h.request("web")).await.unwrap();
        let mut keys = vec![];
        for n in 2..=5 {
            let r = format!("alpine@sha256:{n:064}");
            let im =
                h.m.inner
                    .images
                    .seed(&r, ImageConfig::default())
                    .await
                    .unwrap();
            keys.push(im.key);
        }
        // The oldest of them is named by a record whose disk is not made yet.
        h.add("m_new", state::CREATED, 256)
            .rec
            .lock()
            .unwrap()
            .image_key = keys[0].clone();
        // 8 GB free of 100: 2 GB short of 10%; each image takes 1 GB.
        let gb = 1u64 << 30;
        h.pool
            .answer("used,available", &format!("{}\n{}\n", 92 * gb, 8 * gb));
        h.pool.answer("used", &format!("{gb}\n"));
        h.m.assess(Utc::now()).await;
        let left: Vec<String> =
            h.m.images()
                .await
                .unwrap()
                .into_iter()
                .map(|i| i.key)
                .collect();
        assert_eq!(left.len(), 3, "{left:?}");
        assert!(
            left.contains(&keys[0]) && left.contains(&keys[3]),
            "{left:?}"
        );
        assert!(
            !left.contains(&keys[1]) && !left.contains(&keys[2]),
            "{left:?}"
        );
        let gone: Vec<(String, String)> = h
            .host_events(reason::IMAGE_REMOVED)
            .into_iter()
            .map(|e| {
                let d = e.data.unwrap();
                (
                    d["key"].as_str().unwrap().into(),
                    d["reason"].as_str().unwrap().into(),
                )
            })
            .collect();
        assert_eq!(
            gone,
            [
                (keys[1].clone(), "disk_pressure".into()),
                (keys[2].clone(), "disk_pressure".into())
            ]
        );
        // Back over the threshold: nothing more goes.
        h.pool
            .answer("used,available", &format!("{}\n{}\n", 80 * gb, 20 * gb));
        h.m.assess(Utc::now()).await;
        assert_eq!(h.m.images().await.unwrap().len(), 3);
        // The age rule says so too, and a removal on request.
        assert_eq!(h.m.gc_images(chrono::Duration::zero()).await, 2);
        let reasons: Vec<String> = h
            .host_events(reason::IMAGE_REMOVED)
            .into_iter()
            .map(|e| e.data.unwrap()["reason"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(reasons[2..], ["unused", "unused"]);
    }

    #[tokio::test]
    async fn top_takes_its_rates_from_the_last_two_ticks() {
        let h = harness("10.64.0.0/22", 4096).await;
        let a = h.metered("m_a", state::RUNNING, "2026-10-21T10:00:00Z");
        let b = h.metered("m_b", state::STOPPED, "2026-10-21T10:00:00Z");
        b.rec.lock().unwrap().ip = "10.64.1.3".into();
        h.m.inner.net.count("10.64.1.2").await.unwrap();
        h.host.cpu("m_a", 1_000_000);
        h.host.memory("m_a", 64 << 20);
        h.host.internet("10.64.1.2", 100, 10);
        h.m.measure(at("2026-10-21T10:00:00Z")).await;
        // One measure: no window yet.
        let t = h.m.top(None);
        assert_eq!((t.len(), t[0].window_sec, t[0].cpu_percent), (1, 0.0, 0.0));
        h.host.cpu("m_a", 4_000_000);
        h.host.internet("10.64.1.2", 1500, 30);
        let tr = h.m.traffic("m_a").unwrap();
        tr.received(30);
        tr.sent(300);
        h.m.measure(at("2026-10-21T10:00:15Z")).await;
        let t = h.m.top(None);
        assert_eq!(
            t,
            vec![api::TopMachine {
                machine_id: "m_a".into(),
                tenant: "t1".into(),
                name: "db".into(),
                role: None,
                cpu_percent: 20.0,
                memory_bytes: 64 << 20,
                memory_limit_bytes: 512 << 20,
                disk_used_bytes: 0,
                internet_in_bytes_per_sec: 100.0,
                internet_out_bytes_per_sec: 2.0,
                ingress_in_bytes_per_sec: 2.0,
                ingress_out_bytes_per_sec: 20.0,
                window_sec: 15.0,
                host: String::new(),
            }],
            "running machines only"
        );
        assert!(h.m.top(Some("t2")).is_empty());
        assert_eq!(h.m.top(Some("t1")).len(), 1);
        drop(a);
    }

    #[tokio::test]
    async fn logs_read_across_the_rotated_console() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.add("m_a", state::RUNNING, 256);
        let dir = h.m.inner.cfg.run_dir().join("m_a");
        std::fs::create_dir_all(&dir).unwrap();
        let line = |s: &str| format!("2026-10-21T10:00:00.000000Z {s}\n");
        let (one, two) = (line("one"), line("two"));
        // `two` rotated away once: the previous file starts at 1000 in the console.
        std::fs::write(dir.join("console.1000.log"), &one).unwrap();
        std::fs::write(dir.join("console.log"), &two).unwrap();
        let page = h.m.logs("m_a", "", 10).unwrap();
        let got: Vec<&str> = page.lines.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(got, ["one", "two"]);
        let end = 1000 + (one.len() + two.len()) as u64;
        assert_eq!(page.next, end.to_string());
        // A cursor in the current file, and one past the end.
        let mid = (1000 + one.len()).to_string();
        assert_eq!(h.m.logs("m_a", &mid, 10).unwrap().lines.len(), 1);
        let after = h.m.logs("m_a", &end.to_string(), 10).unwrap();
        assert_eq!((after.lines.len(), after.next), (0, end.to_string()));
    }

    // --- labels, quotas and logs follow (ADR 0025) ---

    #[tokio::test]
    async fn a_listing_selects_by_labels_all_of_them() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let labelled = |name: &str, labels: &[(&str, &str)]| {
            let mut req = h.request(name);
            req.start = Some(false);
            req.metadata = labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            req
        };
        let web =
            h.m.create(labelled("web", &[("app", "web"), ("tier", "front")]))
                .await
                .unwrap();
        let db = h.m.create(labelled("db", &[("app", "db")])).await.unwrap();
        h.m.create(labelled("bare", &[])).await.unwrap();
        let ids = |tenant: Option<&str>, sel: &[&str]| -> Vec<String> {
            let sel: Vec<api::Label> = sel.iter().map(|s| api::Label::parse(s).unwrap()).collect();
            h.m.list(tenant, &sel).into_iter().map(|m| m.id).collect()
        };
        assert_eq!(ids(None, &["app=web"]), [web.id.as_str()]);
        assert_eq!(ids(Some("t1"), &["app"]), [web.id.clone(), db.id.clone()]);
        assert_eq!(ids(None, &["app=web", "tier=front"]), [web.id.as_str()]);
        assert!(
            ids(None, &["app=db", "tier"]).is_empty(),
            "every one must match"
        );
        assert!(ids(Some("t2"), &["app"]).is_empty());
        assert_eq!(ids(None, &[]).len(), 3);
    }

    #[test]
    fn a_quota_refuses_the_first_limit_a_request_passes() {
        let q = api::Quota {
            machines: Some(2),
            memory_mb: Some(512),
            disk_gb: Some(10),
            vcpus: None,
        };
        let used = api::QuotaUse {
            machines: 1,
            memory_mb: 256,
            vcpus: 1,
            disk_gb: 10,
        };
        let need = |machines, memory_mb, disk_gb| api::QuotaUse {
            machines,
            memory_mb,
            vcpus: 64,
            disk_gb,
        };
        assert_eq!(
            over_quota("t1", &q, &used, &need(1, 256, 0)),
            None,
            "up to the limit"
        );
        let x = over_quota("t1", &q, &used, &need(1, 512, 0)).unwrap();
        assert_eq!(
            x.to_string(),
            "tenant t1's quota: memory_mb 256 of 512 used, 512 more asked"
        );
        // Disk is used up: a machine with no volume still fits, one with a volume does not.
        assert_eq!(over_quota("t1", &q, &used, &need(1, 0, 0)), None);
        let x = over_quota("t1", &q, &used, &need(1, 0, 1)).unwrap();
        assert_eq!(
            (x.resource, x.limit, x.used, x.need),
            ("disk_gb", 10, 10, 1)
        );
        // Machines are checked first; no limit is none.
        let x = over_quota("t1", &q, &used, &need(2, 9999, 9)).unwrap();
        assert_eq!(x.resource, "machines");
        assert_eq!(
            over_quota("t1", &api::Quota::default(), &used, &need(99, 99_999, 999)),
            None
        );
        let none = api::Quota {
            machines: Some(0),
            ..Default::default()
        };
        assert!(over_quota("t1", &none, &api::QuotaUse::default(), &need(1, 0, 0)).is_some());
    }

    #[tokio::test]
    async fn quotas_hold_a_tenant_at_create_fork_and_start() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        assert!(matches!(h.m.quota("t9"), Err(MError::NotFound)));
        let set = |machines, memory_mb| api::Quota {
            machines: Some(machines),
            memory_mb: Some(memory_mb),
            disk_gb: Some(5),
            vcpus: None,
        };
        // Put before any machine (the tenant is made, as `ensure_tenant` makes one; the
        // network needs the host, so known here).
        h.tenant("t2");
        let q = h.m.set_quota("t2", set(1, 384)).await.unwrap();
        assert_eq!((q.quota, q.used), (set(1, 384), api::QuotaUse::default()));
        assert_eq!(h.m.tenant("t2").unwrap().machines, 0);
        let stored: TenantRec = h.m.inner.store.get("tenants", "t2").unwrap().unwrap();
        assert_eq!(stored.quota, set(1, 384), "kept across a restart");
        h.m.set_quota("t1", set(2, 384)).await.unwrap();
        let a = h.m.create(h.request("a")).await.unwrap();
        let mut b = h.request("b");
        b.start = Some(false);
        let b = h.m.create(b).await.unwrap();
        // The use, as the quota counts it: two machines, one of them running.
        let used = |t| h.m.quota(t).unwrap().used;
        assert_eq!(
            used("t1"),
            api::QuotaUse {
                machines: 2,
                memory_mb: 256,
                vcpus: 1,
                disk_gb: 0
            }
        );
        // A start past memory: refused, the machine as it was, an event about it.
        let err = h.m.start(&b.id, None).await.unwrap_err();
        assert!(matches!(err, MError::Quota(_)), "{err}");
        assert_eq!(
            err.to_string(),
            "tenant t1's quota: memory_mb 256 of 384 used, 256 more asked"
        );
        assert_eq!(h.m.get(&b.id).unwrap().state, state::CREATED);
        let ev = h.events_of(&b.id).pop().unwrap();
        assert_eq!(
            (ev.reason.as_str(), ev.kind.as_str()),
            ("quota_exceeded", "warning")
        );
        assert_eq!(ev.message, format!("start refused: {err}"));
        assert_eq!(
            ev.data.unwrap(),
            json!({"resource": "memory_mb", "limit": 384, "used": 256, "need": 256})
        );
        assert_eq!(h.m.get(&b.id).unwrap().version, ev.seq, "an event about it");
        // A fork past the machines: refused before anything is made, an event of the tenant.
        let mut fork = h.request("f");
        fork.image.clear();
        fork.fork = Some(api::ForkSpec {
            machine_id: a.id.clone(),
            copy: String::new(),
        });
        let err = h.m.create(fork).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "tenant t1's quota: machines 2 of 2 used, 1 more asked"
        );
        assert_eq!(h.m.list(Some("t1"), &[]).len(), 2);
        let f = events::Filter {
            tenant: Some("t1".into()),
            ..Default::default()
        };
        let last =
            h.m.inner
                .events
                .read(0, &f, 5000)
                .unwrap()
                .events
                .pop()
                .unwrap();
        assert_eq!(
            (
                last.reason.as_str(),
                last.machine_id.as_str(),
                last.tenant.as_str()
            ),
            ("quota_exceeded", "", "t1")
        );
        assert_eq!(last.message, format!("create of f refused: {err}"));
        // The gateway counts as a machine.
        let err = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap_err();
        assert!(err.to_string().contains("machines 2 of 2"), "{err}");
        // With room for machines: a create that starts is held to memory before it is made,
        // and one with a volume to disk.
        h.m.set_quota("t1", set(5, 384)).await.unwrap();
        let err = h.m.create(h.request("c")).await.unwrap_err();
        assert!(err.to_string().contains("memory_mb 256 of 384"), "{err}");
        let mut v = h.request("v");
        v.volume = Some(api::VolumeSpec {
            size_gb: 6,
            mount: "/data".into(),
        });
        let err = h.m.create(v).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "tenant t1's quota: disk_gb 0 of 5 used, 6 more asked"
        );
        assert_eq!(h.m.list(Some("t1"), &[]).len(), 2, "nothing made");
        // Once a stops, b starts: memory is what runs.
        h.m.stop(&a.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        assert_eq!(used("t1").memory_mb, 0);
        assert_eq!(h.m.start(&b.id, None).await.unwrap().state, state::RUNNING);
        // A quota lowered under the use stops nothing.
        h.m.set_quota("t1", set(1, 0)).await.unwrap();
        assert_eq!(h.m.get(&b.id).unwrap().state, state::RUNNING);
        assert_eq!(used("t1").machines, 2);
    }

    /// The next line of a follow, as JSON, within five seconds.
    async fn followed(rx: &mut tokio::sync::mpsc::Receiver<String>) -> serde_json::Value {
        let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a line in time")
            .expect("the follow is open");
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn logs_follow_sends_what_is_there_then_each_line_across_a_rotation_until_destroyed() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let dir = h.m.inner.cfg.run_dir().join(&m.id);
        // The daemon's writer of the console, rotating every two lines.
        let mut w = console::Writer::open(&dir, 64).await.unwrap();
        let ts = "2026-10-21T10:00:00.000000Z";
        w.line(ts, b"before").await.unwrap();
        let from = h.m.logs(&m.id, "", 500).unwrap();
        assert!(matches!(
            h.m.follow_logs("m_nope", "", tokio::sync::mpsc::channel(1).0),
            Err(MError::NotFound)
        ));
        assert!(matches!(
            h.m.follow_logs(&m.id, "x", tokio::sync::mpsc::channel(1).0),
            Err(MError::Invalid(_))
        ));
        // From the start: the lines there, the last one written before the follow.
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        h.m.follow_logs(&m.id, "", tx).unwrap();
        let mut got = vec![];
        for _ in 0..from.lines.len() {
            got.push(
                followed(&mut rx).await["line"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(got.last().map(String::as_str), Some("before"));
        // From a cursor: only what comes after it, each line as the writer writes it, in the
        // paged answer's shape, across the rotations.
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        h.m.follow_logs(&m.id, &from.next, tx).unwrap();
        for i in 0..5 {
            w.line(ts, format!("line {i}").as_bytes()).await.unwrap();
            let l = followed(&mut rx).await;
            assert_eq!(
                l,
                json!({"ts": "2026-10-21T10:00:00Z", "line": format!("line {i}")})
            );
        }
        let rotated = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name().to_string_lossy().starts_with("console.")
                    && e.file_name() != "console.log"
            });
        assert!(rotated, "the console rotated under the follow");
        // Destroyed: a last line says so, and the stream ends.
        drop(w);
        h.m.destroy(&m.id, None).await.unwrap();
        let last = followed(&mut rx).await;
        assert_eq!(last["code"], "destroyed");
        assert_eq!(
            last["error"],
            format!("machine {} was destroyed; its console went with it", m.id)
        );
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn a_quiet_follow_sends_a_heartbeat_and_ends_with_the_daemon() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.add("m_a", state::CREATED, 256);
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        // No console yet: nothing to send until a line is written.
        h.m.follow_logs("m_a", "", tx).unwrap();
        tokio::task::yield_now().await;
        tokio::time::pause();
        tokio::time::advance(events::HEARTBEAT + Duration::from_secs(1)).await;
        assert_eq!(followed(&mut rx).await, json!({}));
        h.m.inner.events.close();
        let last = followed(&mut rx).await;
        assert_eq!(last["code"], "shutdown");
        assert!(last["error"]
            .as_str()
            .unwrap()
            .ends_with("follow again from since=0"));
        assert!(rx.recv().await.is_none());
    }

    // --- changes at the next boot (ADR 0024) ---

    /// A PATCH of what the machine runs.
    fn spec(f: impl FnOnce(&mut api::SpecChange)) -> api::UpdateMachineRequest {
        let mut req = api::UpdateMachineRequest::default();
        f(&mut req.spec);
        req
    }

    fn env(k: &str, v: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(k.to_string(), v.to_string())])
    }

    impl Harness {
        /// The guest config and the boot files on the config drive the machine's last start
        /// wrote.
        fn drive(&self, id: &str) -> (guest::Config, Vec<(String, u32, Vec<u8>)>) {
            let path = self.m.inner.cfg.run_dir().join(id).join("config.tar");
            let mut all = entries(&std::fs::read(path).unwrap());
            let cfg = serde_json::from_slice(&all.remove(0).2).unwrap();
            (cfg, all)
        }
    }

    #[tokio::test]
    async fn a_change_of_what_it_runs_waits_for_the_next_start() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.m.inner
            .images
            .seed(IMAGE2, ImageConfig::default())
            .await
            .unwrap();
        let mut req = h.request("web");
        req.env = env("V", "1");
        let m = h.m.create(req).await.unwrap();
        h.host.calls();
        let change = spec(|s| {
            s.image = Some(IMAGE2.into());
            s.env = Some(env("V", "2"));
            s.files = Some(vec![api::File {
                path: "/srv/index.html".into(),
                base64: guest::base64_encode(b"v2"),
                mode: None,
            }]);
        });
        // A stale If-Match is refused and leaves nothing pending.
        let stale = h.m.update(&m.id, change.clone(), Some(m.version - 1)).await;
        assert!(matches!(stale, Err(MError::Moved(_))), "{stale:?}");
        assert!(h.m.get(&m.id).unwrap().pending.is_none());
        let patched =
            h.m.update(&m.id, change.clone(), Some(m.version))
                .await
                .unwrap();
        // It runs on as it was: the same process, the same image; the change is pending.
        assert_eq!(
            (patched.state.as_str(), patched.image.as_str()),
            (state::RUNNING, IMAGE)
        );
        let calls = h.host.calls();
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("boot") || c.starts_with("kill")),
            "{calls:?}"
        );
        let pending = patched.pending.clone().unwrap();
        assert_eq!(pending.fields, ["image", "env", "files"]);
        assert_eq!(pending.image.as_deref(), Some(IMAGE2));
        assert!(patched.pending_since.is_some());
        let e = h.events_of(&m.id).pop().unwrap();
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("updated", "image, env, files change at the next start")
        );
        assert_eq!(
            e.data,
            Some(json!({"fields": ["image", "env", "files"], "pending": true}))
        );
        assert_eq!(patched.version, e.seq);
        // The same change again is none: no event, the version stays.
        let same = h.m.update(&m.id, change, None).await.unwrap();
        assert_eq!(same.version, patched.version);
        // A second PATCH goes over the first; its event names what it moved.
        let cmd = vec!["sh".to_string(), "-c".into(), "echo $V".into()];
        let more =
            h.m.update(&m.id, spec(|s| s.cmd = Some(cmd.clone())), None)
                .await
                .unwrap();
        assert_eq!(
            more.pending.unwrap().fields,
            ["image", "cmd", "env", "files"]
        );
        assert_eq!(
            more.pending_since, patched.pending_since,
            "the oldest change"
        );
        assert_eq!(
            h.events_of(&m.id).pop().unwrap().data,
            Some(json!({"fields": ["cmd"], "pending": true}))
        );
        // A restart applies it, after its If-Match.
        let stale = h.m.restart(&m.id, Some(patched.version)).await;
        assert!(matches!(stale, Err(MError::Moved(_))), "{stale:?}");
        let applied = h.m.restart(&m.id, Some(more.version)).await.unwrap();
        assert_eq!(
            (applied.state.as_str(), applied.image.as_str()),
            (state::RUNNING, IMAGE2)
        );
        assert!(applied.pending.is_none() && applied.pending_since.is_none());
        let reasons = h.reasons(&m.id);
        assert_eq!(
            reasons[reasons.len() - 5..],
            ["stopping", "stopped", "applied", "starting", "started"]
        );
        let ev = h
            .events_of(&m.id)
            .into_iter()
            .find(|e| e.reason == "applied");
        assert_eq!(
            ev.map(|e| (e.message, e.data)),
            Some((
                "image, cmd, env, files applied".to_string(),
                Some(json!({"fields": ["image", "cmd", "env", "files"]}))
            ))
        );
        // The boot read the new spec: its config drive carries it.
        let (cfg, files) = h.drive(&m.id);
        assert_eq!(cfg.env.get("V").map(String::as_str), Some("2"));
        assert_eq!(cfg.cmd, cmd);
        assert_eq!(
            files,
            [("files/srv/index.html".to_string(), 0o644, b"v2".to_vec())]
        );
        assert_eq!(h.stored(&m.id).unwrap().boots, 2);
    }

    #[tokio::test]
    async fn a_new_image_makes_the_root_disk_again_and_keeps_the_volume() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let im =
            h.m.inner
                .images
                .seed(IMAGE2, ImageConfig::default())
                .await
                .unwrap();
        let e = h.add("m_x", state::STOPPED, 256);
        h.disks(&e).await;
        let dev = h.pool.dev();
        std::fs::write(dev.join("byard/m/m_x/data"), b"the database").unwrap();
        // A fork of its root disk, as a create with `fork` makes one.
        let z = &h.pool.zfs;
        z.snapshot("m/m_x/root", "fork-m_child").await.unwrap();
        z.clone_snapshot("m/m_x/root", "fork-m_child", "m/m_child/root")
            .await
            .unwrap();
        h.m.update("m_x", spec(|s| s.image = Some(IMAGE2.into())), None)
            .await
            .unwrap();
        h.pool.calls();
        h.m.start("m_x", None).await.unwrap();
        let r = h.stored("m_x").unwrap();
        assert_eq!(
            (r.image.as_str(), r.image_key.as_str(), r.root_key.as_str()),
            (IMAGE2, im.key.as_str(), im.key.as_str())
        );
        // The root disk is a clone of the new image; the volume was never touched.
        let origin = std::fs::read_to_string(dev.join("byard/m/m_x/root.origin")).unwrap();
        assert_eq!(origin.trim(), format!("byard/images/{}@base", im.key));
        assert_eq!(
            std::fs::read(dev.join("byard/m/m_x/data")).unwrap(),
            b"the database"
        );
        // Swapped (ADR 0031): the old root disk renamed aside, a clone of the image in its
        // place.
        let calls = h.pool.calls();
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("rename byard/m/m_x/root byard/m/m_x/root.r_")),
            "{calls:?}"
        );
        assert!(
            !calls
                .iter()
                .any(|c| c.contains("m_x/data") && !c.starts_with("list ")),
            "{calls:?}"
        );
        // The fork lives on, whole, a clone of the old root disk, retired and kept for it.
        let fork_origin = std::fs::read_to_string(dev.join("byard/m/m_child/root.origin")).unwrap();
        assert!(
            fork_origin.starts_with("byard/m/m_x/root.r_")
                && fork_origin.trim().ends_with("@fork-m_child"),
            "{fork_origin}"
        );
        // The next start has nothing to make.
        h.m.stop("m_x", Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.pool.calls();
        h.m.start("m_x", None).await.unwrap();
        let calls = h.pool.calls();
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("clone ") || c.starts_with("destroy ")),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn a_root_disk_is_made_from_the_image_the_cache_has_for_it_now() {
        // The build its record names is gone from the host (removed since the start resolved
        // it): the root disk comes from the image as the cache answers for its reference.
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let im = h.m.inner.images.ensure(IMAGE).await.unwrap();
        let e = h.add("m_y", state::STOPPED, 256);
        h.disks(&e).await;
        {
            let mut r = e.rec.lock().unwrap();
            r.image = IMAGE.into();
            r.root_key = "older".into();
        }
        h.m.start("m_y", None).await.unwrap();
        let r = h.stored("m_y").unwrap();
        assert_eq!((r.image_key, r.root_key), (im.key.clone(), im.key));
    }

    #[tokio::test]
    async fn a_root_disk_is_made_again_only_once_no_backup_runs() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.m.inner
            .images
            .seed(IMAGE2, ImageConfig::default())
            .await
            .unwrap();
        let e = h.add("m_x", state::STOPPED, 256);
        h.disks(&e).await;
        // A backup under way holds the turn, as `backup_entry`'s callers do.
        let backup = e.backup_turn.clone().lock_owned().await;
        // A start with no root disk to make does not wait for it.
        h.m.start("m_x", None).await.unwrap();
        h.m.stop("m_x", Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.m.update("m_x", spec(|s| s.image = Some(IMAGE2.into())), None)
            .await
            .unwrap();
        h.pool.calls();
        let m = h.m.clone();
        let mut start = tokio::spawn(async move { m.start("m_x", None).await });
        let waited = tokio::time::timeout(Duration::from_millis(300), &mut start).await;
        assert!(waited.is_err(), "the start waits for the backup");
        let calls = h.pool.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("destroy ")),
            "{calls:?}"
        );
        assert_eq!(h.m.get("m_x").unwrap().state, state::STOPPED);
        drop(backup);
        let up = start.await.unwrap().unwrap();
        assert_eq!(
            (up.state.as_str(), up.image.as_str()),
            (state::RUNNING, IMAGE2)
        );
        let key = h.m.inner.images.ensure(IMAGE2).await.unwrap().key;
        assert_eq!(h.stored("m_x").unwrap().root_key, key);
    }

    #[tokio::test]
    async fn a_new_size_is_reserved_at_the_start_and_refused_past_the_host() {
        let h = harness("10.64.0.0/22", 1024).await;
        h.ready().await;
        let a = h.m.create(h.request("a")).await.unwrap();
        let mut big = h.request("b");
        big.size.memory_mb = 512;
        let b = h.m.create(big).await.unwrap();
        let grown = api::Size {
            vcpus: 2,
            memory_mb: 768,
        };
        let patched =
            h.m.update(&a.id, spec(|s| s.size = Some(grown)), None)
                .await
                .unwrap();
        // It runs on at its size: the host holds 256 for it.
        assert_eq!(patched.size.memory_mb, 256);
        assert_eq!(h.m.usage().0.memory_mb, 768);
        h.m.stop(&a.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        // b holds 512: 768 more do not fit, and the change waits for a start that fits.
        let full = h.m.start(&a.id, None).await;
        assert!(matches!(full, Err(MError::Capacity(_))), "{full:?}");
        let still = h.m.get(&a.id).unwrap();
        assert_eq!(
            (still.state.as_str(), still.size.memory_mb),
            (state::STOPPED, 256)
        );
        assert_eq!(still.pending.and_then(|p| p.size), Some(grown));
        h.m.stop(&b.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        // A restart of a stopped machine is a start.
        let up = h.m.restart(&a.id, None).await.unwrap();
        assert_eq!((up.state.as_str(), up.size), (state::RUNNING, grown));
        assert_eq!(
            h.m.usage().0,
            api::Capacity {
                memory_mb: 768,
                vcpus: 2
            }
        );
        assert_eq!(h.host.booted.lock().unwrap().get(&a.id), Some(&grown));
    }

    #[tokio::test]
    async fn a_change_to_what_a_memory_snapshot_holds_makes_the_next_start_cold() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let suspend = || h.m.stop(&m.id, Duration::from_secs(1), true, None);
        assert!(suspend().await.unwrap().suspended);
        // The ports are the daemon's: a resume applies them.
        h.m.update(&m.id, spec(|s| s.ports = Some(vec![8080])), None)
            .await
            .unwrap();
        h.host.calls();
        let back = h.m.start(&m.id, None).await.unwrap();
        assert_eq!(back.ports, [8080]);
        let calls = h.host.calls();
        assert!(
            calls.iter().any(|c| c.ends_with(" resume=true")),
            "{calls:?}"
        );
        // The env is in the guest's memory: the snapshot is dropped, the boot is cold.
        assert!(suspend().await.unwrap().suspended);
        h.m.update(&m.id, spec(|s| s.env = Some(env("V", "2"))), None)
            .await
            .unwrap();
        h.host.calls();
        let cold = h.m.start(&m.id, None).await.unwrap();
        assert!(!cold.suspended);
        let calls = h.host.calls();
        assert!(
            calls.iter().any(|c| c.ends_with(" resume=false")),
            "{calls:?}"
        );
        let evs = h.events_of(&m.id);
        let starting = evs.iter().rev().find(|e| e.reason == "starting").unwrap();
        assert_eq!(starting.data, Some(json!({"resume": false})));
        assert_eq!(evs.last().map(|e| e.reason.as_str()), Some("started"));
        assert_eq!(h.drive(&m.id).0.env.get("V").map(String::as_str), Some("2"));
    }

    #[tokio::test]
    async fn an_image_that_cannot_be_pulled_fails_the_boot_and_stays_pending() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        h.host.calls();
        // No registry answers there.
        let nowhere =
            "127.0.0.1:1/nothing@sha256:0000000000000000000000000000000000000000000000000000000000000009";
        h.m.update(&m.id, spec(|s| s.image = Some(nowhere.into())), None)
            .await
            .unwrap();
        let failed = match h.m.start(&m.id, None).await {
            Err(MError::BootFailed(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            (failed.state.as_str(), failed.image.as_str()),
            (state::ERROR, IMAGE)
        );
        assert!(
            failed.error.starts_with(&format!("image {nowhere}: ")),
            "{}",
            failed.error
        );
        assert_eq!(failed.pending.map(|p| p.fields), Some(vec!["image".into()]));
        assert_eq!(
            h.reasons(&m.id).last().map(String::as_str),
            Some("boot_failed")
        );
        assert!(!h.host.calls().iter().any(|c| c.starts_with("boot ")));
        // A PATCH back to the image it has leaves nothing pending; the start boots that.
        let fixed =
            h.m.update(&m.id, spec(|s| s.image = Some(IMAGE.into())), None)
                .await
                .unwrap();
        assert!(fixed.pending.is_none() && fixed.pending_since.is_none());
        assert_eq!(h.m.start(&m.id, None).await.unwrap().state, state::RUNNING);
    }

    #[tokio::test]
    async fn create_and_patch_refuse_a_bad_spec_in_the_same_words() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let file = |path: &str, base64: &str, mode: Option<&str>| api::File {
            path: path.into(),
            base64: base64.into(),
            mode: mode.map(String::from),
        };
        let bad = [
            (
                spec(|s| {
                    s.size = Some(api::Size {
                        vcpus: 0,
                        memory_mb: 256,
                    })
                }),
                "size.vcpus must be 1..32",
            ),
            (
                spec(|s| s.files = Some(vec![file("etc/x", "", None)])),
                "file \"etc/x\": path must be absolute",
            ),
            (
                spec(|s| s.files = Some(vec![file("/x", "!!", None)])),
                "file \"/x\": ",
            ),
            (
                spec(|s| s.files = Some(vec![file("/x", "", Some("9"))])),
                "file \"/x\": mode \"9\": want octal digits",
            ),
            (
                spec(|s| s.env = Some(env("A=B", "1"))),
                "env \"A=B\": a name is not empty and holds no \"=\"",
            ),
            (spec(|s| s.ports = Some(vec![0])), "ports: 0 is not a port"),
            (
                spec(|s| {
                    s.restart = Some(api::RestartPolicy {
                        policy: "sometimes".into(),
                        max_retries: 0,
                    })
                }),
                "restart.policy must be no, on-failure or always",
            ),
        ];
        for (patch, want) in bad {
            let s = patch.spec.clone();
            let mut req = h.request("bad");
            req.size = s.size.unwrap_or(req.size);
            req.files = s.files.unwrap_or_default();
            req.env = s.env.unwrap_or_default();
            req.ports = s.ports.unwrap_or_default();
            req.restart = s.restart;
            let at_create = refused(h.m.create(req).await);
            let at_patch = refused(h.m.update(&m.id, patch, None).await);
            assert!(at_create.starts_with(want), "{at_create:?}, want {want:?}");
            assert_eq!(at_create, at_patch);
        }
        assert!(h.m.get(&m.id).unwrap().pending.is_none());
        let empty = refused(
            h.m.update(&m.id, spec(|s| s.image = Some("".into())), None)
                .await,
        );
        assert_eq!(empty, "image must not be empty");
    }

    // --- upgrades (ADR 0027) ---

    #[tokio::test]
    async fn a_boot_records_what_the_init_says_and_what_ran_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        assert_eq!(
            (m.init_version.as_str(), m.vmm_version.as_str()),
            ("0.1.0+init", "v1.17.0/test")
        );
        let r = h.stored(&m.id).unwrap();
        assert_eq!(
            (r.init_version.as_str(), r.vmm_version.as_str()),
            ("0.1.0+init", "v1.17.0/test")
        );
        // A cold boot under another init and Firecracker records them.
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        *h.host.init_version.lock().unwrap() = "0.2.0+b".into();
        *h.host.vmm_version.lock().unwrap() = "v1.18.0/test".into();
        let m = h.m.start(&m.id, None).await.unwrap();
        assert_eq!(
            (m.init_version.as_str(), m.vmm_version.as_str()),
            ("0.2.0+b", "v1.18.0/test")
        );
    }

    #[tokio::test]
    async fn a_snapshot_taken_under_another_vmm_is_not_resumed() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        let suspend = || h.m.stop(&m.id, Duration::from_secs(1), true, None);
        assert!(suspend().await.unwrap().suspended);
        // Firecracker (or the host kernel) changed under the suspended machine: a cold boot.
        *h.host.vmm_version.lock().unwrap() = "v1.18.0/test".into();
        h.host.calls();
        let back = h.m.start(&m.id, None).await.unwrap();
        assert!(!back.suspended);
        assert!(h.host.calls().iter().any(|c| c.ends_with(" resume=false")));
        let starting = h
            .events_of(&m.id)
            .into_iter()
            .rev()
            .find(|e| e.reason == "starting")
            .unwrap();
        assert_eq!(
            starting.message,
            "booting: its memory snapshot was taken under v1.17.0/test, the host runs v1.18.0/test"
        );
        assert_eq!(
            starting.data,
            Some(json!({"resume": false, "snapshot_vmm": "v1.17.0/test"}))
        );
        assert_eq!(back.vmm_version, "v1.18.0/test");
        // Taken and resumed under the same one: a resume.
        assert!(suspend().await.unwrap().suspended);
        h.host.calls();
        h.m.start(&m.id, None).await.unwrap();
        assert!(h.host.calls().iter().any(|c| c.ends_with(" resume=true")));
        // A snapshot from before the versions were recorded says none: cold, once.
        assert!(suspend().await.unwrap().suspended);
        h.m.entry(&m.id)
            .unwrap()
            .rec
            .lock()
            .unwrap()
            .vmm_version
            .clear();
        h.host.calls();
        h.m.start(&m.id, None).await.unwrap();
        assert!(h.host.calls().iter().any(|c| c.ends_with(" resume=false")));
    }

    #[tokio::test]
    async fn a_hand_over_leaves_every_machine_running_for_the_next_daemon() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.m.touch(&m.id).unwrap();
        h.host.calls();
        let _held = h.m.hand_over().await;
        assert_eq!(
            h.host.calls(),
            Vec::<String>::new(),
            "nothing stopped, suspended or killed"
        );
        let r = h.stored(&m.id).unwrap();
        assert_eq!(
            (r.state.as_str(), r.pid),
            (state::RUNNING, m_pid(&h, &m.id))
        );
        assert!(
            r.last_used_at >= m.last_used_at,
            "the last use is on the record"
        );
        // What the next daemon's start finds: the machine, still running, adopted.
        assert_eq!(h.m.recover().await, (1, 0, 0));
    }

    #[test]
    fn a_record_keeps_what_a_newer_daemon_wrote() {
        // A record with a field this daemon does not know (a newer one's, before a rollback).
        let mut v = serde_json::to_value(record()).unwrap();
        v["checkpoint"] = json!({"name": "before-migration", "vmm": "v1.18.0/x"});
        let r: Record = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(r.rest.keys().collect::<Vec<_>>(), ["checkpoint"]);
        // Rewritten as it came: the field is kept, nothing else moves.
        assert_eq!(serde_json::to_value(&r).unwrap(), v);
        // A record of this daemon's carries nothing more.
        let mine = serde_json::to_value(record()).unwrap();
        let back: Record = serde_json::from_value(mine.clone()).unwrap();
        assert!(back.rest.is_empty());
        assert_eq!(serde_json::to_value(&back).unwrap(), mine);
    }

    #[tokio::test]
    async fn a_hand_over_waits_for_a_transition_and_lets_none_begin() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let a = h.m.create(h.request("a")).await.unwrap();
        let b = h.m.create(h.request("b")).await.unwrap();
        // A stop under way when the hand-over is asked: its guest takes a while to end.
        *h.host.stops.lock().unwrap() = Duration::from_millis(300);
        let m = h.m.clone();
        let id = a.id.clone();
        let stop =
            tokio::spawn(async move { m.stop(&id, Duration::from_secs(5), false, None).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let held = h.m.hand_over().await;
        // The stop finished before the hand-over wrote anything: its record says so.
        assert_eq!(h.stored(&a.id).unwrap().state, state::STOPPED);
        assert!(stop.await.unwrap().is_ok());
        // While the hand-over's locks are held, a stop asked now does not begin.
        let m = h.m.clone();
        let id = b.id.clone();
        let late =
            tokio::spawn(async move { m.stop(&id, Duration::from_secs(5), false, None).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!late.is_finished());
        assert_eq!(h.stored(&b.id).unwrap().state, state::RUNNING);
        drop(held);
        late.await.unwrap().unwrap();
    }

    /// The machine's process as the manager holds it.
    fn m_pid(h: &Harness, id: &str) -> u32 {
        h.m.entry(id).unwrap().snapshot().pid
    }

    #[tokio::test]
    async fn a_daemons_start_boots_again_what_the_host_stopped() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let a = h.m.create(h.request("a")).await.unwrap();
        let b = h.m.create(h.request("b")).await.unwrap();
        let c = h.m.create(h.request("c")).await.unwrap();
        let mut never = h.request("d");
        never.sleep = "never".into();
        let d = h.m.create(never).await.unwrap();
        h.m.stop(&c.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        // The daemon's stop: every running machine suspended, stopped by the host.
        h.m.close().await;
        for id in [&a.id, &b.id, &d.id] {
            let r = h.stored(id).unwrap();
            assert_eq!(
                (r.state.as_str(), r.stopped_reason.as_str(), r.suspended),
                ("stopped", "host", true)
            );
        }
        // b's window ran out while the host was down; d never sleeps.
        let long_ago = Utc::now() - chrono::Duration::hours(2);
        h.m.entry(&b.id).unwrap().rec.lock().unwrap().last_used_at = Some(long_ago);
        h.m.entry(&d.id).unwrap().rec.lock().unwrap().last_used_at = Some(long_ago);
        h.host.calls();
        h.m.start_stopped_by_host();
        let running = |id: &str| h.m.get(id).unwrap().state == state::RUNNING;
        eventually("a and d running again", || running(&a.id) && running(&d.id)).await;
        let calls = h.host.calls();
        let boots: Vec<&String> = calls.iter().filter(|c| c.starts_with("boot ")).collect();
        assert_eq!(boots.len(), 2, "{calls:?}");
        assert!(
            boots.iter().all(|c| c.ends_with(" resume=true")),
            "{boots:?}"
        );
        // b sleeps on, wakeable; c was stopped on purpose.
        let b = h.m.get(&b.id).unwrap();
        assert_eq!(
            (b.state.as_str(), b.stopped_reason.as_str()),
            ("stopped", "host")
        );
        let c = h.m.get(&c.id).unwrap();
        assert_eq!(
            (c.state.as_str(), c.stopped_reason.as_str()),
            ("stopped", "user")
        );
        assert!(h.m.wake(&b.id, None).await.unwrap().state == state::RUNNING);
    }
}
