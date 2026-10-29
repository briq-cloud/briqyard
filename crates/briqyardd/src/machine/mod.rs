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
mod create;
mod endpoints;
mod exec;
mod gateway;
mod moves;
mod namespaces;
mod network;
mod observe;
mod persist;
mod probes;
mod quotas;
mod shutdown;
mod snapshots;
mod start;
mod startup;
#[cfg(test)]
mod tests;
mod tick;
mod update;
mod views;

use backups::{Backups, Schedule, Turn};
use create::*;
use endpoints::*;
pub use observe::Until;
use observe::*;
use quotas::*;
use snapshots::SnapshotRec;
use startup::*;
use tick::*;
use update::*;

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
    /// A create of a name the namespace has: the machine of that name, for a caller sending the
    /// same create again to find the one it made (ADR 0048).
    #[error("a machine with that name exists in the namespace: {}", .0.id)]
    NameTaken(Box<api::Machine>),
    #[error("machine is not running: {0}")]
    NotRunning(String),
    #[error("machine is busy: {0}")]
    BadState(String),
    #[error("the host is full: {0}")]
    Capacity(String),
    /// Past a limit of the namespace's quota (ADR 0025).
    #[error("{0}")]
    Quota(String),
    #[error("the namespace still has machines")]
    NamespaceInUse,
    #[error("a machine of the namespace runs through its gateway")]
    GatewayInUse,
    /// A call that would change or run something in a namespace's gateway through the machine
    /// routes: the namespace's route owns it.
    #[error("the namespace's gateway: use /v1/namespaces/{0}/gateway")]
    Gateway(String),
    /// The guest never came up or exited while booting: the image's fault, not the host's.
    /// The machine stays, in state `error`, with the console tail in its `error`.
    #[error("boot failed: {}", .0.error)]
    BootFailed(Box<api::Machine>),
    /// Its create could not pull its image (ADR 0048): the machine, in `error`, no disks.
    #[error("pull failed: {}", .0.error)]
    PullFailed(Box<api::Machine>),
    /// Its create could not make its disks or start it (ADR 0048): the machine, in `error`.
    #[error("create failed: {}", .0.error)]
    CreateFailed(Box<api::Machine>),
    /// A `/wait` ran out while the machine is on its way: creating, starting, a restart
    /// waiting, or running while its probes say it does not serve yet (ADR 0022, 0048). The
    /// machine, its probes' last results in it.
    #[error("machine {} is {}", .0.id, not_ready_state(.0))]
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

/// A volume asked smaller than the one it has or comes from (ADR 0040).
fn never_shrinks(asked: u32, held: u32) -> MError {
    invalid(format!(
        "volume: {asked} GB asked, {held} GB held: a volume never shrinks"
    ))
}

/// A namespace id is checked before it names a file.
fn check_namespace_id(id: &str) -> Result<(), MError> {
    match api::valid_id(id) {
        true => Ok(()),
        false => Err(invalid(
            "namespace must be a-z, 0-9, _ or -, at most 64 characters",
        )),
    }
}

/// `via: "gateway"` in a namespace that has none.
fn no_gateway(namespace: &str) -> MError {
    invalid(format!(
        "namespace has no gateway: PUT /v1/namespaces/{namespace}/gateway first"
    ))
}

/// What a machine is to its namespace when it is not one of the namespace's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The namespace's gateway (ADR 0016): run by the daemon, absent from the namespace's machines.
    Gateway,
}

/// A machine as the daemon keeps it: the API view plus what running it needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(alias = "tenant")]
    pub namespace: String,
    /// None for the namespace's own machines.
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
    /// The event that put it in `error` (`api::Machine::error_reason`).
    #[serde(default)]
    pub error_reason: String,
    /// While `creating`: its create starts it once its disks are made, and its memory is
    /// taken from the record on (ADR 0048).
    #[serde(default)]
    pub start: bool,
    /// While `creating`: its disks come from a fork's source or a backup, which the record does
    /// not name, so a restart of the daemon cannot take its create up again (ADR 0048).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_source: bool,
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
    /// One of the namespace's own machines: what the namespace's listing, counts and removal see.
    fn is_namespaces(&self) -> bool {
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
    /// Its disks exist: not while its create runs, nor after one that failed (ADR 0048).
    fn has_disks(&self) -> bool {
        match self.state.as_str() {
            state::CREATING => false,
            state::ERROR => !matches!(
                self.error_reason.as_str(),
                reason::PULL_FAILED | reason::CREATE_FAILED
            ),
            _ => true,
        }
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
/// What a call that needs its disks answers on a machine whose create has not made them, or
/// failed (ADR 0048).
fn made_never(r: &Record) -> MError {
    MError::BadState(match r.state.as_str() {
        state::CREATING => "creating".into(),
        _ => format!(
            "{} ({}): its create failed; destroy it and create it again",
            r.state, r.error_reason
        ),
    })
}

/// A guest call's error: `not_running` when the guest cannot be reached (a machine whose guest
/// exits as the call comes), else as it is.
fn not_running_if_unreachable(err: anyhow::Error) -> MError {
    match err.downcast::<guestc::Unreachable>() {
        Ok(u) => MError::NotRunning(u.to_string()),
        Err(err) => MError::Other(err),
    }
}

fn holds_memory(state: &str) -> bool {
    matches!(state, state::STARTING | state::RUNNING | state::STOPPING)
}

/// Whether the host counts this machine's memory as taken: it holds it, or its create will
/// start it (ADR 0048: room is taken when the machine is recorded, not when it boots).
fn commits_memory(r: &Record) -> bool {
    holds_memory(&r.state) || (r.state == state::CREATING && r.start)
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
        namespace: r.namespace.clone(),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamespaceRec {
    pub id: String,
    pub subnet_index: u32,
    pub created_at: DateTime<Utc>,
    /// What the namespace may hold (ADR 0025); none set: no limit.
    #[serde(default)]
    pub quota: api::Quota,
}

/// A namespace as the manager holds it: its record and the subnet its index names, checked
/// against `network.range` when the record was loaded or made.
#[derive(Clone)]
struct Namespace {
    rec: NamespaceRec,
    subnet: Subnet,
    /// The namespace's lock: held while its gateway is started, put, removed or put to sleep,
    /// and by a machine that needs the gateway until that machine is `starting`, so the
    /// sleeper never stops a gateway a start is about to use.
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl Namespace {
    fn new(rec: NamespaceRec, subnet: Subnet) -> Self {
        Self {
            rec,
            subnet,
            lock: Default::default(),
        }
    }
}

/// The gateway's name in its namespace: `gateway.internal`.
const GATEWAY_NAME: &str = "gateway";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointRec {
    pub id: String,
    pub machine_id: String,
    #[serde(alias = "tenant")]
    pub namespace: String,
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
    /// Out of the manager: its record deleted by its destroy, or never written (a create that
    /// failed). Every write of the record checks it under this lock, which the deletion holds.
    removed: Mutex<bool>,
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
            removed: Mutex::new(false),
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

    /// A repeat folded with no seq (a use, a refusal: nothing changed) keeps the version.
    fn note_locked(&self, r: &mut Record, ev: Ev) {
        if let Some(seq) = self.events.emit(ev.of(&r.id, &r.namespace)) {
            r.version = seq;
        }
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
    namespaces: Mutex<HashMap<String, Namespace>>,
    endpoints: Mutex<HashMap<String, EndpointRec>>,
    endpoint_events: broadcast::Sender<(EndpointRec, bool)>,
    /// The egress policy the tables hold for each machine, with its namespace's gateway: what a
    /// stop takes out, even once the gateway machine it names is gone.
    policies: Mutex<HashMap<String, (Ipv4Addr, nft::Policy)>>,
    /// Held while a namespace is made (its subnet index, bridge and record), see `ensure_namespace`.
    namespace_create: tokio::sync::Mutex<()>,
    /// The backup store, the gate of scheduled backups, the holders (ADR 0023).
    backups: Backups,
    /// Boots run at once; see `boots_at_once`.
    boot_gate: tokio::sync::Semaphore,
    /// Probe executions run at once (ADR 0022).
    probe_gate: tokio::sync::Semaphore,
    /// When this daemon started: a probe that starts within its period of it spreads its
    /// first run (`probes::first_run`).
    began: tokio::time::Instant,
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

/// What a create makes the machine's disks from (ADR 0048).
enum Make {
    /// Its image, pulled when the host has not seen it.
    Image,
    /// Snapshots of another machine's disks, taken now.
    Fork(Arc<Entry>, api::ForkSpec),
    /// A backup, and the key its streams are under.
    Restore(Box<api::Backup>, Option<String>),
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
