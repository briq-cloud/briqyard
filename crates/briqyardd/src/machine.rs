//! Machines: their records, disks, network and Firecracker processes, and every lifecycle
//! transition. One `Manager` per daemon.

use crate::config::Config;
use crate::fc;
use crate::guestc;
use crate::image::{self, Builder, ImageConfig};
use crate::netw::{self, dns::Resolver, host, nft, nft::Ruleset, Range, Subnet};
use crate::objstore::ObjectStore;
use crate::store::Store;
use crate::zfs::Zfs;
use anyhow::{anyhow, Context, Result};
use briqyard_api::guest;
use briqyard_api::{self as api, state, stop};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, Notify};

/// What the API maps to statuses.
#[derive(Debug, thiserror::Error)]
pub enum MError {
    #[error("machine not found")]
    NotFound,
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
    #[error("the tenant still has machines")]
    TenantInUse,
    /// The guest never came up or exited while booting: the image's fault, not the host's.
    /// The machine stays, in state `error`, with the console tail in its `error`.
    #[error("boot failed: {}", .0.error)]
    BootFailed(Box<api::Machine>),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn invalid(msg: impl Into<String>) -> MError {
    MError::Invalid(msg.into())
}

/// A machine as the daemon keeps it: the API view plus what running it needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub tenant: String,
    pub name: String,
    pub image: String,
    pub image_key: String,
    pub image_digest: String,
    pub image_config: ImageConfig,
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
    /// Where its traffic may go (ADR 0015); a record from before has none: open.
    #[serde(default)]
    pub egress: api::Egress,
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
}

impl Record {
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
    pub fn sleep_window(&self) -> Option<Duration> {
        api::parse_sleep(&self.sleep).ok().flatten()
    }

    /// Brings a record written by an earlier daemon to the current shape: `sleep` was `""`
    /// for never, and `state_changed_at` did not exist (its best stand-in is `updated_at`).
    fn migrate(&mut self) {
        self.sleep = sleep_setting(&self.sleep);
        if self.state_changed_at == DateTime::<Utc>::default() {
            self.state_changed_at = self.updated_at;
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

/// Whether `need` MB more fit next to `used` on a host of `cap`.
fn admit(used: u32, cap: u32, need: u32) -> Result<(), MError> {
    match used.checked_add(need) {
        Some(total) if total <= cap => Ok(()),
        _ => Err(MError::Capacity(format!("{used} MB used of {cap}"))),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantRec {
    pub id: String,
    pub subnet_index: u32,
    pub created_at: DateTime<Utc>,
}

/// A tenant as the manager holds it: its record and the subnet its index names, checked
/// against `network.range` when the record was loaded or made.
#[derive(Clone)]
struct Tenant {
    rec: TenantRec,
    subnet: Subnet,
}

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

/// A console log past this size is rotated at the next cold boot.
const CONSOLE_ROTATE_BYTES: u64 = 32 << 20;

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
    /// Serializes lifecycle operations on one machine.
    lock: tokio::sync::Mutex<()>,
    rec: Mutex<Record>,
    live: Mutex<Option<fc::Vm>>,
    /// The reason set before asking the guest to stop; `None` when it ends on its own.
    stop_req: Mutex<Option<String>>,
    /// Signalled on every state change: what `wait_running` and a stop wait on.
    changed: Notify,
    /// A use since the record was last written; read and written under `rec`'s lock.
    unsaved_use: AtomicBool,
}

impl Entry {
    fn new(rec: Record) -> Arc<Self> {
        Arc::new(Self {
            lock: tokio::sync::Mutex::new(()),
            rec: Mutex::new(rec),
            live: Mutex::new(None),
            stop_req: Mutex::new(None),
            changed: Notify::new(),
            unsaved_use: AtomicBool::new(false),
        })
    }

    fn snapshot(&self) -> Record {
        self.rec.lock().unwrap().clone()
    }

    /// Marks a use now. In memory only: the sleeper reads it here, and the record on disk
    /// catches up with the next write or the sleeper's tick, so a busy machine does not
    /// rewrite its record on every connection.
    fn touch(&self) {
        let mut r = self.rec.lock().unwrap();
        r.last_used_at = Some(Utc::now());
        self.unsaved_use.store(true, Relaxed);
    }

    /// The one place `state` is written: `state_changed_at` follows it and whoever waits on
    /// the machine is woken. `f` edits the rest of the record under the same lock.
    fn set_state(&self, state: &str, f: impl FnOnce(&mut Record)) {
        {
            let mut r = self.rec.lock().unwrap();
            if r.state != state {
                r.state = state.into();
                r.state_changed_at = Utc::now();
            }
            f(&mut r);
        }
        self.changed.notify_waiters();
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
    /// Where backups go; none when `backup.store` is empty.
    backups: Option<ObjectStore>,
    /// Boots run at once; see `boots_at_once`.
    boot_gate: tokio::sync::Semaphore,
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
        images: Builder,
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
        let backups = if cfg.backup.store.is_empty() {
            None
        } else {
            let st = ObjectStore::open(
                &cfg.backup.store,
                &cfg.backup.endpoint,
                &cfg.backup.region,
                &std::env::var("BRIQYARD_S3_ACCESS_KEY").unwrap_or_default(),
                &std::env::var("BRIQYARD_S3_SECRET_KEY").unwrap_or_default(),
            )
            .context("backup")?;
            tracing::info!(store = st.describe(), "backups on");
            Some(st)
        };
        let (endpoint_events, _) = broadcast::channel(64);
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
        m.recover().await;
        m.sweep_orphans().await;
        let sleeper = m.clone();
        tokio::spawn(async move { sleeper.sleeper().await });
        Ok(m)
    }

    pub fn host_id(&self) -> &str {
        &self.inner.host_id
    }

    /// Reads the records. A tenant whose subnet index is outside `network.range` is refused
    /// here, with the fix, rather than found by the first request that needs its subnet.
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
                .insert(rec.id.clone(), Tenant { rec, subnet });
        }
        for mut r in st.list::<Record>("machines")? {
            r.migrate();
            let id = r.id.clone();
            self.inner
                .machines
                .lock()
                .unwrap()
                .insert(id, Entry::new(r));
        }
        for ep in st.list::<EndpointRec>("endpoints")? {
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
    /// the next use wakes them. Destroys cut short are resumed by the sleeper's tick.
    async fn recover(&self) {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for e in entries {
            let rec = e.snapshot();
            if !matches!(
                rec.state.as_str(),
                state::RUNNING | state::STARTING | state::STOPPING
            ) {
                continue;
            }
            if rec.state == state::RUNNING && rec.pid > 0 && self.adopt(&e, rec.pid).await {
                continue;
            }
            if rec.pid > 0 && self.inner.vmm.machine_of(rec.pid).as_deref() == Some(&rec.id) {
                self.inner.vmm.kill(rec.pid);
            }
            self.unplug(&rec.id, &rec.ip).await;
            e.set_state(state::STOPPED, |r| {
                r.stopped_reason = stop::HOST.into();
                r.pid = 0;
                r.stopped_at = Some(Utc::now());
            });
            tracing::warn!(
                machine = rec.id,
                "machine left running by a previous daemon, marked stopped"
            );
            let _ = self.save(&e);
        }
    }

    /// Resources a previous daemon left with no record to own them: a crash between a resource
    /// and its record, or a destroy cut short. A Firecracker nobody knows is ended; its run
    /// directory, jail, TAP and disks go. Done once at start, so nothing leaks for good.
    async fn sweep_orphans(&self) {
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
        // A fork's snapshot on its source outlives a destroy that failed to free it.
        if let Ok(snaps) = self.inner.zfs.snapshots_under("m").await {
            for s in snaps {
                if let Some((ds, snap)) = s.split_once('@') {
                    if self.free_fork_snapshot(ds, snap).await {
                        tracing::warn!(snapshot = s, "fork snapshot with no clone, destroyed");
                        swept += 1;
                    }
                }
            }
        }
        if swept > 0 {
            tracing::info!(swept, "orphans swept at start");
        }
    }

    /// Removes a `fork-*` snapshot nothing clones any more: `true` when it did. Kept, with a
    /// warning, when ZFS cannot say or refuses; the sweep at start tries again.
    async fn free_fork_snapshot(&self, ds: &str, snap: &str) -> bool {
        if !snap.starts_with("fork-") {
            return false;
        }
        let z = &self.inner.zfs;
        let freed = match z.clones(ds, snap).await {
            Ok(clones) if clones.is_empty() => z.destroy_snapshot(ds, snap).await.map(|_| true),
            Ok(_) => Ok(false),
            Err(err) => Err(err),
        };
        freed.unwrap_or_else(|err| {
            tracing::warn!(dataset = ds, snapshot = snap, err = %err, "fork snapshot kept");
            false
        })
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
            .adopt(&rec.id, &dir, jail.as_ref(), pid)
            .await
        else {
            return false;
        };
        *e.live.lock().unwrap() = Some(vm.clone());
        *e.stop_req.lock().unwrap() = None;
        self.watch(e, &vm);
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
    /// about the machine changed, so `updated_at` stays.
    fn flush_use(&self, e: &Entry) -> Result<()> {
        let rec = {
            let r = e.rec.lock().unwrap();
            if !e.unsaved_use.swap(false, Relaxed) {
                return Ok(());
            }
            r.clone()
        };
        self.inner.store.put("machines", &rec.id, &rec)
    }

    /// Suspends every running machine (a stop when Firecracker refuses); the daemon is going
    /// down, and after its restart each one resumes on first use in well under a second.
    /// Stopped by the host, not idle: the next use wakes it whatever its sleep window says.
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
                        .stop_entry(&e, stop::HOST, Duration::from_secs(10), true)
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
            Tenant {
                rec: TenantRec {
                    id: id.to_string(),
                    subnet_index: idx,
                    created_at: Utc::now(),
                },
                subnet: self.inner.range.subnet(idx)?,
            }
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
    /// it sends leaves its TAP.
    fn rules(&self) -> Result<Ruleset> {
        let cfg = &self.inner.cfg;
        let running: Vec<Record> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .map(|e| e.snapshot())
            .filter(|r| r.state == state::RUNNING)
            .collect();
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
            pins,
            policies,
        })
    }

    // --- egress (ADR 0015) ---

    /// An egress policy a machine of `tenant` may take: one of the modes, and for `via` a
    /// machine of the same tenant other than `me`.
    fn check_egress(&self, e: &api::Egress, tenant: &str, me: &str) -> Result<(), MError> {
        e.check().map_err(invalid)?;
        if e.mode == api::egress::VIA {
            self.via_target(e, tenant, me)?;
        }
        Ok(())
    }

    /// The address of the machine a `via` policy names: fixed for that machine's life.
    fn via_target(&self, e: &api::Egress, tenant: &str, me: &str) -> Result<String, MError> {
        let id = e.via.as_deref().unwrap_or_default();
        if id == me {
            return Err(invalid("egress.via names the machine itself"));
        }
        let target = self
            .inner
            .machines
            .lock()
            .unwrap()
            .get(id)
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
    /// `None` for open.
    fn policy_for(&self, r: &Record) -> Result<Option<(Ipv4Addr, nft::Policy)>, MError> {
        if r.egress.mode == api::egress::OPEN {
            return Ok(None);
        }
        let t = self
            .tenant_of(&r.tenant)
            .ok_or_else(|| anyhow!("tenant network is gone"))?;
        let gateway = t.subnet.gateway();
        let p = if r.egress.mode == api::egress::VIA {
            nft::Policy::Via {
                ip: r.ip.clone(),
                to: self.via_target(&r.egress, &r.tenant, &r.id)?,
                host: gateway.to_string(),
            }
        } else {
            nft::Policy::None { ip: r.ip.clone() }
        };
        Ok(Some((gateway, p)))
    }

    /// Puts a machine's policy in the tables and the resolver, in place of what they held
    /// for it; open leaves nothing. The resolver keeps the machine in from before the
    /// tables do until after they stop.
    async fn set_policy(&self, id: &str, policy: Option<(Ipv4Addr, nft::Policy)>) -> Result<()> {
        self.unset_policy(id).await?;
        let Some((gateway, p)) = policy else {
            return Ok(());
        };
        let ip: Ipv4Addr = p.ip().parse()?;
        self.inner.dns.internal_only(gateway, ip, true);
        if let Err(err) = self.inner.net.set_policy(&p).await {
            self.inner.dns.internal_only(gateway, ip, false);
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
        if let Ok(ip) = p.ip().parse() {
            self.inner.dns.internal_only(gateway, ip, true);
        }
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
        if let Ok(ip) = p.ip().parse() {
            self.inner.dns.internal_only(gateway, ip, false);
        }
        self.inner.policies.lock().unwrap().remove(id);
        Ok(())
    }

    /// Changes a running machine's policy. From one policy to another is one transaction,
    /// so there is no moment with neither, and a refusal leaves the old one; the resolver
    /// keeps the machine in throughout (same address, same gateway).
    async fn replace_policy(&self, id: &str, new: Option<(Ipv4Addr, nft::Policy)>) -> Result<()> {
        let held = self.inner.policies.lock().unwrap().get(id).cloned();
        match (held, new) {
            (Some((_, old)), Some((gateway, p))) => {
                if old != p {
                    self.inner.net.swap_policy(&old, &p).await?;
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
        let machines = self.inner.machines.lock().unwrap();
        let mut out: Vec<api::Tenant> = self
            .inner
            .tenants
            .lock()
            .unwrap()
            .values()
            .map(|t| api::Tenant {
                id: t.rec.id.clone(),
                subnet: t.subnet.cidr(),
                gateway: t.subnet.gateway().to_string(),
                machines: machines
                    .values()
                    .filter(|e| e.rec.lock().unwrap().tenant == t.rec.id)
                    .count(),
                created_at: t.rec.created_at,
                host: String::new(),
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Removes an empty tenant's network. Missing is success.
    pub async fn delete_tenant(&self, id: &str) -> Result<(), MError> {
        if !api::valid_id(id) {
            return Err(invalid(
                "tenant must be a-z, 0-9, _ or -, at most 64 characters",
            ));
        }
        let t = match self.tenant_of(id) {
            Some(t) => t,
            None => return Ok(()),
        };
        let in_use = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .any(|e| e.rec.lock().unwrap().tenant == id);
        if in_use {
            return Err(MError::TenantInUse);
        }
        self.inner.dns.unset(t.subnet.gateway());
        self.inner.net.delete_bridge(t.rec.subnet_index).await?;
        self.inner.tenants.lock().unwrap().remove(id);
        self.inner.store.delete("tenants", id)?;
        Ok(())
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

    fn view(&self, e: &Entry) -> api::Machine {
        let r = e.snapshot();
        let sleeps_at = if r.state == state::RUNNING {
            sleeps_at(r.last_used_at, r.sleep_window())
        } else {
            None
        };
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
            egress: r.egress.clone(),
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
            host: String::new(),
        }
    }

    pub fn get(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        Ok(self.view(&e))
    }

    pub fn list(&self, tenant: Option<&str>) -> Vec<api::Machine> {
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
                tenant
                    .map(|t| e.rec.lock().unwrap().tenant == t)
                    .unwrap_or(true)
            })
            .map(|e| self.view(e))
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    /// What running machines take, how many run, how many exist.
    pub fn usage(&self) -> (api::Capacity, usize, usize) {
        let machines = self.inner.machines.lock().unwrap();
        let (used, running) = committed(&machines);
        (used, running, machines.len())
    }

    /// Takes the machine's memory from the host and moves it to `starting`, as one step
    /// under the map's lock: two starts that read the same free memory cannot both take it.
    fn reserve(&self, e: &Entry) -> Result<(), MError> {
        let machines = self.inner.machines.lock().unwrap();
        let (used, _) = committed(&machines);
        let need = e.rec.lock().unwrap().size.memory_mb;
        admit(used.memory_mb, self.capacity().memory_mb, need)?;
        e.set_state(state::STARTING, |r| {
            r.error.clear();
            r.pid = 0;
        });
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
        match self.inner.images.remove(key).await? {
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
            if self.jail_for(&r).is_some() {
                let cg = fc::cgroup_dir(&r.id);
                if let Ok(text) = tokio::fs::read_to_string(cg.join("cpu.stat")).await {
                    for line in text.lines() {
                        if let Some(v) = line.strip_prefix("usage_usec ") {
                            st.cpu_usec = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if let Ok(text) = tokio::fs::read_to_string(cg.join("memory.current")).await {
                    st.memory_bytes = text.trim().parse().unwrap_or(0);
                }
            }
        }
        st.disk_bytes = self.inner.zfs.used(&r.dataset()).await.unwrap_or(0);
        Ok(st)
    }

    /// The Prometheus exposition of what the host does.
    pub async fn metrics(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        let mut by_state: std::collections::BTreeMap<String, usize> = Default::default();
        let mut suspended = 0;
        {
            let machines = self.inner.machines.lock().unwrap();
            for e in machines.values() {
                let r = e.rec.lock().unwrap();
                *by_state.entry(r.state.clone()).or_default() += 1;
                if r.suspended {
                    suspended += 1;
                }
            }
        }
        let (used, _, total) = self.usage();
        let cap = self.capacity();
        let tenants = self.inner.tenants.lock().unwrap().len();
        let endpoints = self.inner.endpoints.lock().unwrap().len();
        let disk_free = self.disk_free_mb().await;
        let st = &self.inner.stats;
        let mut out = String::new();
        out.push_str("# HELP briqyard_machines Machines on this host, by state.\n# TYPE briqyard_machines gauge\n");
        for (state, n) in &by_state {
            out.push_str(&format!("briqyard_machines{{state=\"{state}\"}} {n}\n"));
        }
        out.push_str(&format!(
            "briqyard_machines_total {total}\nbriqyard_machines_suspended {suspended}\n"
        ));
        out.push_str(&format!("# TYPE briqyard_tenants gauge\nbriqyard_tenants {tenants}\n# TYPE briqyard_endpoints gauge\nbriqyard_endpoints {endpoints}\n"));
        out.push_str(&format!("# TYPE briqyard_memory_mb gauge\nbriqyard_memory_mb{{kind=\"used\"}} {}\nbriqyard_memory_mb{{kind=\"capacity\"}} {}\n", used.memory_mb, cap.memory_mb));
        out.push_str(&format!("# TYPE briqyard_vcpus gauge\nbriqyard_vcpus{{kind=\"used\"}} {}\nbriqyard_vcpus{{kind=\"capacity\"}} {}\n", used.vcpus, cap.vcpus));
        out.push_str(&format!(
            "# TYPE briqyard_disk_free_mb gauge\nbriqyard_disk_free_mb {disk_free}\n"
        ));
        out.push_str(&format!(
            "# TYPE briqyard_boots_total counter\nbriqyard_boots_total {}\n# TYPE briqyard_resumes_total counter\nbriqyard_resumes_total {}\n# TYPE briqyard_suspends_total counter\nbriqyard_suspends_total {}\n# TYPE briqyard_execs_total counter\nbriqyard_execs_total {}\n# TYPE briqyard_starts_failed_total counter\nbriqyard_starts_failed_total {}\n# TYPE briqyard_backups_total counter\nbriqyard_backups_total {}\n",
            st.boots.load(Relaxed),
            st.resumes.load(Relaxed),
            st.suspends.load(Relaxed),
            st.execs.load(Relaxed),
            st.starts_failed.load(Relaxed),
            st.backups.load(Relaxed)
        ));
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
                host_memory_mb().saturating_sub(2048).max(1024)
            },
            vcpus: if c.vcpus > 0 {
                c.vcpus
            } else {
                (std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    * 4) as u32
            },
        }
    }

    // --- create ---

    pub async fn create(&self, req: api::CreateMachineRequest) -> Result<api::Machine, MError> {
        if !api::valid_id(&req.tenant) {
            return Err(invalid(
                "tenant must be a-z, 0-9, _ or -, at most 64 characters",
            ));
        }
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
        if !size_from_backup {
            check_size(&req.size)?;
        }
        if let Some(v) = &req.volume {
            if v.size_gb < 1 || !v.mount.starts_with('/') {
                return Err(invalid("volume needs size_gb >= 1 and an absolute mount"));
            }
        }
        api::parse_sleep(&req.sleep).map_err(invalid)?;
        for f in &req.files {
            if !f.path.starts_with('/') {
                return Err(invalid(format!("file {:?}: path must be absolute", f.path)));
            }
        }
        let restart = match &req.restart {
            None => api::RestartPolicy::default(),
            Some(r) if ["no", "on-failure", "always"].contains(&r.policy.as_str()) => r.clone(),
            Some(_) => return Err(invalid("restart.policy must be no, on-failure or always")),
        };
        if self.name_taken(&req.tenant, &req.name) {
            return Err(MError::Conflict(
                "a machine with that name exists in the tenant".into(),
            ));
        }
        let now = Utc::now();
        let mut rec = Record {
            id: new_id("m"),
            tenant: req.tenant.clone(),
            name: req.name.clone(),
            image: String::new(),
            image_key: String::new(),
            image_digest: String::new(),
            image_config: ImageConfig::default(),
            entrypoint: req.entrypoint.clone(),
            cmd: req.cmd.clone(),
            env: req.env.clone(),
            files: req.files.clone(),
            size: req.size,
            volume: req.volume.clone(),
            ports: req.ports.clone(),
            sleep: sleep_setting(&req.sleep),
            restart,
            egress: req.egress.clone().unwrap_or_default(),
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
            boots: 0,
            created_at: now,
            updated_at: now,
            state_changed_at: now,
            started_at: None,
            stopped_at: None,
            last_used_at: None,
            console_offset: 0,
            suspended: false,
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
            let s = self
                .entry(&fork.machine_id)
                .map_err(|_| invalid("fork source not found"))?;
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
        let t = self.ensure_tenant(&req.tenant).await?;
        let e = self.add_machine(rec, &t)?;
        let _guard = e.lock.lock().await;
        let made = match &restore_from {
            Some(b) => self.receive_disks(&e, b).await,
            None => self.make_disks(&e, src.as_deref(), req.fork.as_ref()).await,
        };
        if let Err(err) = made {
            let rec = e.snapshot();
            self.remove_machine(&e);
            let _ = self.inner.zfs.destroy(&rec.dataset()).await;
            return Err(err.into());
        }
        self.save(&e)?;
        if req.start.unwrap_or(true) {
            // Created but did not start: the same answer a start would give; the machine
            // stays, for the caller to read and destroy.
            self.start_entry(&e).await?;
        }
        Ok(self.view(&e))
    }

    fn name_taken(&self, tenant: &str, name: &str) -> bool {
        self.inner.machines.lock().unwrap().values().any(|e| {
            let r = e.rec.lock().unwrap();
            r.tenant == tenant && r.name == name && r.state != state::DESTROYING
        })
    }

    /// Gives the machine an address and registers it. Nothing on disk yet.
    fn add_machine(&self, mut rec: Record, t: &Tenant) -> Result<Arc<Entry>, MError> {
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
        let e = Entry::new(rec);
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
            let s = src.unwrap().snapshot();
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

    // --- backups ---

    fn backup_store(&self) -> Result<&ObjectStore, MError> {
        self.inner
            .backups
            .as_ref()
            .ok_or_else(|| invalid("backups are off on this host (backup.store)"))
    }

    /// Sends the machine's disks to the store: whole the first time, then what changed since
    /// the last backup whose snapshot is still on the host. A running machine's backup is
    /// crash-consistent (what a power cut would leave); a stopped one's is clean.
    pub async fn backup(&self, id: &str) -> Result<api::Backup, MError> {
        let store = self.backup_store()?;
        let e = self.entry(id)?;
        let rec = e.snapshot();
        if rec.state == state::DESTROYING {
            return Err(MError::BadState(rec.state));
        }
        let bid = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let snap = format!("bk-{bid}");
        let z = &self.inner.zfs;
        let mut disks = Vec::new();
        let mut total = 0u64;
        let mut incremental = false;
        for (disk, ds) in [("root", rec.root_dataset()), ("data", rec.data_dataset())] {
            if !z.exists(&ds).await? {
                continue;
            }
            let base = newest_backup_snapshot(&z.snapshots(&ds).await?);
            z.snapshot(&ds, &snap).await?;
            let key = format!("backups/{}/{disk}/{bid}.zfs", rec.id);
            let mut child = z.send(&ds, &snap, base.as_deref())?;
            let stdout = child.stdout.take().expect("piped");
            let sent = store
                .put(&key, stdout)
                .await
                .with_context(|| format!("backup {disk} of {}", rec.id))?;
            Zfs::finish(child, "zfs send").await?;
            if base.is_some() {
                incremental = true;
            }
            total += sent;
            disks.push(api::BackupDisk {
                disk: disk.into(),
                key,
                bytes: sent,
                from: base.map(|b| b.trim_start_matches("bk-").to_string()),
            });
            // The newest snapshots stay as the base of the next send; the rest go.
            let keep = self.inner.cfg.backup.keep_snapshots.max(1) as usize;
            let mut snaps: Vec<String> = z
                .snapshots(&ds)
                .await?
                .into_iter()
                .filter(|s| s.starts_with("bk-"))
                .collect();
            snaps.sort();
            while snaps.len() > keep {
                let old = snaps.remove(0);
                if let Err(err) = z.destroy_snapshot(&ds, &old).await {
                    tracing::warn!(machine = rec.id, snapshot = old, err = %err, "old backup snapshot kept");
                }
            }
        }
        let b = api::Backup {
            id: bid.clone(),
            machine_id: rec.id.clone(),
            tenant: rec.tenant.clone(),
            name: rec.name.clone(),
            created_at: Utc::now(),
            bytes: total,
            incremental,
            disks,
            machine: Some(serde_json::to_value(&rec).unwrap_or_default()),
        };
        store
            .put_bytes(
                &format!("backups/{}/{bid}.json", rec.id),
                &serde_json::to_vec_pretty(&b).unwrap_or_default(),
            )
            .await
            .context("backup record")?;
        self.inner
            .stats
            .backups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            machine = rec.id,
            backup = bid,
            bytes = total,
            incremental,
            "backup made"
        );
        Ok(b)
    }

    /// The backups of a machine in the store, oldest first; the machine may be gone.
    pub async fn backups(&self, machine_id: &str) -> Result<Vec<api::Backup>, MError> {
        if !api::valid_id(machine_id) {
            return Err(invalid("not a machine id"));
        }
        let store = self.backup_store()?;
        let mut out = Vec::new();
        for key in store.list(&format!("backups/{machine_id}/")).await? {
            if !key.ends_with(".json") {
                continue;
            }
            let data = store.get_bytes(&key).await?;
            match serde_json::from_slice::<api::Backup>(&data) {
                Ok(mut b) => {
                    b.machine = None;
                    out.push(b);
                }
                Err(err) => tracing::warn!(key, err = %err, "unreadable backup record"),
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn find_backup(&self, machine_id: &str, which: &str) -> Result<api::Backup, MError> {
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
            .map_err(|_| MError::NotFound)?;
        serde_json::from_slice(&data).map_err(|e| invalid(format!("backup {id}: {e}")))
    }

    /// Makes the machine's disks from a backup: the whole chain of streams, oldest first,
    /// received into the new datasets.
    async fn receive_disks(&self, e: &Arc<Entry>, b: &api::Backup) -> Result<()> {
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

    // --- start ---

    pub async fn start(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let _guard = e.lock.lock().await;
        if e.snapshot().state != state::RUNNING {
            self.start_entry(&e).await?;
        }
        Ok(self.view(&e))
    }

    /// Starts a machine that went to sleep, that the host stopped or whose process ended;
    /// one stopped on purpose stays stopped.
    pub async fn wake(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let _guard = e.lock.lock().await;
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
        self.start_entry(&e).await?;
        Ok(self.view(&e))
    }

    /// `start_entry` behind a boxed future: the restart path recurses through a spawned task,
    /// and the compiler needs the cycle broken somewhere.
    fn start_boxed<'a>(
        &'a self,
        e: &'a Arc<Entry>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), MError>> + Send + 'a>> {
        Box::pin(self.start_entry(e))
    }

    /// Boots the machine. Called with the entry's lock held, on a machine that is not up:
    /// one being destroyed is refused here, whoever asks (a start, a wake, a restart).
    async fn start_entry(&self, e: &Arc<Entry>) -> Result<(), MError> {
        let cfg = &self.inner.cfg;
        let rec = e.snapshot();
        match rec.state.as_str() {
            state::CREATED | state::STOPPED | state::ERROR => {}
            other => return Err(MError::BadState(other.into())),
        }
        // Resolved before anything moves: a `via` whose machine is gone refuses the start.
        let policy = self.policy_for(&rec)?;
        self.reserve(e)?;
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
            });
            let _ = self.save(e);
            MError::Other(err)
        };
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
        // A console that grew past the cap is set aside: logs page the current file only, and
        // the previous one stays for an operator.
        let console = dir.join("console.log");
        if tokio::fs::metadata(&console)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
            > CONSOLE_ROTATE_BYTES
        {
            let _ = tokio::fs::rename(&console, dir.join("console.log.1")).await;
        }
        let console_offset = tokio::fs::metadata(&console)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
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
        };
        // Boots take their turn: a host asked for many at once boots a few at a time, each
        // with the whole timeout, instead of all of them crawling past it together.
        let _boot_turn = self
            .inner
            .boot_gate
            .acquire()
            .await
            .map_err(|e| fail(anyhow!(e)))?;
        let live = self.inner.vmm.boot(&boot).await.map_err(fail)?;
        {
            *e.live.lock().unwrap() = Some(live.clone());
            *e.stop_req.lock().unwrap() = None;
            let mut r = e.rec.lock().unwrap();
            r.pid = live.pid;
            r.suspended = false;
            if !live.resumed {
                r.boots += 1;
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
        if let Err(why) = outcome {
            // The image's fault: the process is ended here, under the lock, so the watcher
            // finds nothing to settle and no restart policy applies. The machine stays in
            // `error`, with the console's last lines, for the caller to read and destroy.
            self.end_process(e, &live, Duration::ZERO).await;
            self.inner
                .stats
                .starts_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tail = self.last_console_lines(&rec, 5);
            e.set_state(state::ERROR, |r| {
                r.error = format!("{why}: {tail}");
                r.stopped_at = Some(Utc::now());
                r.pid = 0;
            });
            let _ = self.save(e);
            return Err(MError::BootFailed(Box::new(self.view(e))));
        }
        e.set_state(state::RUNNING, |r| {
            let now = Utc::now();
            r.started_at = Some(now);
            r.last_used_at = Some(now);
            r.stopped_reason.clear();
        });
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
        let now = Utc::now();
        let mut restart_again = false;
        e.set_state(state::STOPPED, |r| {
            r.pid = 0;
            r.stopped_at = Some(now);
            if let Some(reason) = stop_req {
                r.stopped_reason = reason.clone();
                tracing::info!(machine = r.id, reason, "machine stopped");
            } else if requested {
                r.stopped_reason = stop::USER.into();
            } else {
                let again = restarts_after_exit(&r.restart, code, r.restarts);
                r.exit = Some(api::Exit {
                    code,
                    oom_killed: oom,
                    at: now,
                    restarting: again,
                });
                r.stopped_reason = stop::EXIT.into();
                if again {
                    r.restarts += 1;
                    restart_again = true;
                    tracing::warn!(
                        machine = r.id,
                        code,
                        oom,
                        restart = r.restarts,
                        "machine exited, restarting"
                    );
                } else {
                    r.restarts = 0;
                    tracing::info!(machine = r.id, code, oom, "machine exited");
                }
            }
        });
        let _ = self.save(e);
        if restart_again {
            let m = self.clone();
            let e = e.clone();
            let delay = Duration::from_secs(e.snapshot().restarts as u64);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _guard = e.lock.lock().await;
                let r = e.snapshot();
                if r.state != state::STOPPED || r.stopped_reason != stop::EXIT {
                    return;
                }
                match m.start_boxed(&e).await {
                    Ok(()) => {}
                    Err(err @ MError::BootFailed(_)) => {
                        tracing::warn!(machine = r.id, err = %err, "restart")
                    }
                    Err(err) => tracing::error!(machine = r.id, err = %err, "restart"),
                }
            });
        }
    }

    fn console_since(&self, r: &Record, max: u64) -> String {
        let path = self.inner.cfg.run_dir().join(&r.id).join("console.log");
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return String::new(),
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let start = r.console_offset.max(len.saturating_sub(max));
        use std::io::{Read, Seek};
        let mut f = f;
        if f.seek(std::io::SeekFrom::Start(start)).is_err() {
            return String::new();
        }
        let mut buf = Vec::new();
        let _ = f.take(max).read_to_end(&mut buf);
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
    ) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        self.stop_entry(&e, stop::USER, timeout, suspend).await?;
        Ok(self.view(&e))
    }

    /// Asks the guest to end its process, then waits for Firecracker to exit; after the grace,
    /// kills. Takes the entry's lock only briefly so the watcher can settle the state.
    async fn stop_entry(
        &self,
        e: &Arc<Entry>,
        reason: &str,
        timeout: Duration,
        suspend: bool,
    ) -> Result<(), MError> {
        let timeout = if timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            timeout
        };
        let live = {
            let _guard = e.lock.lock().await;
            let r = e.snapshot();
            match r.state.as_str() {
                state::STOPPED | state::CREATED | state::ERROR => {
                    if r.state == state::STOPPED
                        && reason == stop::USER
                        && r.stopped_reason != stop::USER
                    {
                        e.rec.lock().unwrap().stopped_reason = stop::USER.into();
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
            *e.stop_req.lock().unwrap() = Some(reason.to_string());
            e.set_state(state::STOPPING, |_| {});
            let _ = self.save(e);
            // A suspend keeps a memory snapshot: the next start resumes in well under a
            // second. Refused, the machine is stopped the plain way.
            let suspended = suspend
                && match self.inner.vmm.snapshot(&live).await {
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

    /// One critical section under the entry's lock, from the state to the record's removal:
    /// nothing starts the machine in between, and a destroy that fails leaves it
    /// `destroying` for the sleeper's tick to try again.
    pub async fn destroy(&self, id: &str) -> Result<(), MError> {
        let e = match self.entry(id) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        let _guard = e.lock.lock().await;
        if !self.inner.machines.lock().unwrap().contains_key(id) {
            // A destroy that held the lock before this one finished the job.
            return Ok(());
        }
        e.set_state(state::DESTROYING, |_| {});
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
        // A fork is a clone of this machine's disks: it takes the snapshots over and lives on.
        // What this machine was cloned from is read after that, since a promotion moves it:
        // the fork snapshot it leaves behind goes once nothing clones it.
        let mut origins = Vec::new();
        for ds in [rec.root_dataset(), rec.data_dataset()] {
            if self.inner.zfs.exists(&ds).await.context("disks")? {
                self.inner
                    .zfs
                    .release_clones(&ds)
                    .await
                    .context("forks of the disks")?;
                origins.extend(
                    self.inner
                        .zfs
                        .origin(&ds)
                        .await
                        .context("origin of the disks")?,
                );
            }
        }
        self.inner
            .zfs
            .destroy(&rec.dataset())
            .await
            .context("disks")?;
        for (ds, snap) in origins {
            self.free_fork_snapshot(&ds, &snap).await;
        }
        let _ = tokio::fs::remove_dir_all(self.inner.cfg.run_dir().join(id)).await;
        if let Some(j) = self.jail_for(&rec) {
            let _ =
                tokio::fs::remove_dir_all(fc::jail_root(&j.base, id).parent().unwrap_or(&j.base))
                    .await;
        }
        self.inner.store.delete("machines", id)?;
        self.remove_machine(&e);
        tracing::info!(machine = id, "machine destroyed");
        Ok(())
    }

    // --- use and sleep ---

    /// Changes the sleep window, the metadata or the egress policy of a machine, in any
    /// state; a running machine's policy changes in the tables at once.
    pub async fn update(
        &self,
        id: &str,
        req: api::UpdateMachineRequest,
    ) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        if let Some(sl) = &req.sleep {
            api::parse_sleep(sl).map_err(invalid)?;
        }
        // A new policy is written under the entry's lock: no start or stop runs in between.
        let _guard = match &req.egress {
            Some(_) => Some(e.lock.lock().await),
            None => None,
        };
        if req.egress.is_some() && !self.inner.machines.lock().unwrap().contains_key(id) {
            // Destroyed while this waited for the lock.
            return Err(MError::NotFound);
        }
        if let Some(eg) = &req.egress {
            let mut r = e.snapshot();
            self.check_egress(eg, &r.tenant, &r.id)?;
            // The tables first: refused, the old policy stays and so does the record.
            if r.state == state::RUNNING {
                r.egress = eg.clone();
                let policy = self.policy_for(&r)?;
                self.replace_policy(&r.id, policy).await?;
            }
        }
        {
            let mut r = e.rec.lock().unwrap();
            if let Some(sl) = req.sleep {
                r.sleep = sleep_setting(&sl);
            }
            if let Some(m) = req.metadata {
                r.metadata = m;
            }
            if let Some(eg) = req.egress {
                r.egress = eg;
            }
        }
        self.save(&e)?;
        Ok(self.view(&e))
    }

    pub fn touch(&self, id: &str) -> Result<(), MError> {
        self.entry(id)?.touch();
        Ok(())
    }

    /// Every 15 s: idle machines go to sleep, uses since the last tick reach the disk, and a
    /// destroy left `destroying` (a daemon restart, a disk that was busy) is tried again.
    async fn sleeper(self) {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            self.tick().await;
        }
    }

    async fn tick(&self) {
        let now = Utc::now();
        let (due, used, destroying): (Vec<Arc<Entry>>, Vec<Arc<Entry>>, Vec<String>) = {
            let machines = self.inner.machines.lock().unwrap();
            let due = machines
                .values()
                .filter(|e| {
                    let r = e.rec.lock().unwrap();
                    r.state == state::RUNNING && idle_past(r.last_used_at, r.sleep_window(), now)
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
                    .stop_entry(&e, stop::IDLE, Duration::from_secs(10), suspend)
                    .await
                {
                    tracing::warn!(machine = e.snapshot().id, err = %err, "sleep");
                }
            });
        }
        while stops.join_next().await.is_some() {}
        for e in used {
            if let Err(err) = self.flush_use(&e) {
                tracing::warn!(machine = e.snapshot().id, err = %err, "last use not written");
            }
        }
        for id in destroying {
            if let Err(err) = self.destroy(&id).await {
                tracing::warn!(machine = id, err = %err, "resume destroy");
            }
        }
    }

    /// Blocks until the machine runs, or until it is clear it will not (within `timeout`).
    pub async fn wait_running(&self, id: &str, timeout: Duration) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Registered before the state is read, so a change in between is not missed.
            let changed = e.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let m = self.view(&e);
            match will_run(&m) {
                Some(Ok(())) => return Ok(m),
                Some(Err(why)) => return Err(MError::NotRunning(why)),
                None => {}
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return Err(MError::NotRunning(format!(
                    "still {} after {timeout:?}",
                    m.state
                )));
            }
        }
    }

    // --- config drive ---

    fn write_config_drive(&self, path: &Path, r: &Record, t: &Tenant) -> Result<()> {
        write_drive(path, &config_drive(r, t.subnet.gateway())?)
    }

    // --- exec and files ---

    async fn running_vsock(&self, id: &str, wake: bool) -> Result<PathBuf, MError> {
        let e = self.entry(id)?;
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
        self.wake_detached(id).await?;
        let live = e.live.lock().unwrap().clone();
        live.map(|l| l.vsock)
            .ok_or_else(|| MError::NotRunning("no process".into()))
    }

    /// A wake on behalf of something else (an exec, an ingress connection), which may give
    /// up before the boot is done: the boot goes on without it.
    async fn wake_detached(&self, id: &str) -> Result<api::Machine, MError> {
        let m = self.clone();
        let id = id.to_string();
        detached(async move { m.wake(&id).await }).await
    }

    pub async fn exec(&self, id: &str, req: api::ExecRequest) -> Result<api::ExecResult, MError> {
        self.inner
            .stats
            .execs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sock = self.running_vsock(id, req.wake).await?;
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
        let out = tokio::time::timeout(
            Duration::from_millis(timeout_ms + 10_000),
            self.inner.guest.exec(&sock, greq),
        )
        .await
        .map_err(|_| MError::NotRunning("the command did not finish".into()))?
        .map_err(|err| {
            if err.downcast_ref::<guestc::Closed>().is_some() {
                MError::NotRunning("the machine went down during the command".into())
            } else {
                MError::Other(err)
            }
        })?;
        let _ = self.touch(id);
        Ok(api::ExecResult {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.code,
            timed_out: out.timed_out,
        })
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
        .map_err(|_| MError::NotRunning("timeout".into()))??;
        let _ = self.touch(id);
        Ok(())
    }

    pub async fn get_file(&self, id: &str, path: &str) -> Result<Vec<u8>, MError> {
        let sock = self.running_vsock(id, false).await?;
        let data = tokio::time::timeout(Duration::from_secs(60), self.inner.guest.get(&sock, path))
            .await
            .map_err(|_| MError::NotRunning("timeout".into()))??;
        let _ = self.touch(id);
        Ok(data)
    }

    // --- logs ---

    /// Pages the console. `since` is the byte offset to continue from; `limit` caps lines.
    pub fn logs(&self, id: &str, since: &str, limit: usize) -> Result<api::LogsResponse, MError> {
        self.entry(id)?;
        let limit = if limit == 0 || limit > 5000 {
            500
        } else {
            limit
        };
        let path = self.inner.cfg.run_dir().join(id).join("console.log");
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(api::LogsResponse::default())
            }
            Err(e) => return Err(MError::Other(e.into())),
        };
        let offset: u64 = if since.is_empty() {
            0
        } else {
            since
                .parse()
                .map_err(|_| invalid("since must be a cursor from a previous page"))?
        };
        use std::io::{BufRead, Seek};
        let mut f = f;
        f.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| MError::Other(e.into()))?;
        let mut r = std::io::BufReader::with_capacity(64 << 10, f);
        let mut resp = api::LogsResponse::default();
        let mut pos = offset;
        while resp.lines.len() < limit {
            let mut line = String::new();
            let n = r
                .read_line(&mut line)
                .map_err(|e| MError::Other(e.into()))?;
            if n == 0 || !line.ends_with('\n') {
                break;
            }
            pos += n as u64;
            resp.lines.push(parse_log_line(&line));
        }
        resp.next = pos.to_string();
        Ok(resp)
    }

    // --- snapshots ---

    /// Removes a snapshot `snapshot` made, from both disks. Missing is success; a snapshot
    /// of the daemon's own (a fork's, a backup's) is not the caller's to remove.
    pub async fn delete_snapshot(&self, id: &str, snap: &str) -> Result<(), MError> {
        let e = self.entry(id)?;
        let r = e.snapshot();
        if !snap.starts_with("s_") || !api::valid_id(snap) {
            return Err(MError::NotFound);
        }
        self.inner
            .zfs
            .destroy_snapshot(&r.root_dataset(), snap)
            .await?;
        if r.volume.is_some() {
            self.inner
                .zfs
                .destroy_snapshot(&r.data_dataset(), snap)
                .await?;
        }
        Ok(())
    }

    pub async fn snapshot(&self, id: &str) -> Result<api::Snapshot, MError> {
        let e = self.entry(id)?;
        let r = e.snapshot();
        let snap = new_id("s");
        self.inner.zfs.snapshot(&r.root_dataset(), &snap).await?;
        if r.volume.is_some() {
            self.inner.zfs.snapshot(&r.data_dataset(), &snap).await?;
        }
        Ok(api::Snapshot {
            id: snap,
            machine_id: id.to_string(),
            created_at: Utc::now(),
        })
    }

    pub async fn snapshots(&self, id: &str) -> Result<Vec<api::Snapshot>, MError> {
        let e = self.entry(id)?;
        let r = e.snapshot();
        let names = self.inner.zfs.snapshots(&r.root_dataset()).await?;
        Ok(names
            .into_iter()
            .filter(|n| n.starts_with("s_"))
            .map(|n| api::Snapshot {
                id: n,
                machine_id: id.to_string(),
                created_at: r.created_at,
            })
            .collect())
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
        let e = self.entry(machine_id)?;
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
    if !(1..=32).contains(&size.vcpus) {
        return Err(invalid("size.vcpus must be 1..32"));
    }
    if !(128..=262144).contains(&size.memory_mb) {
        return Err(invalid("size.memory_mb must be 128..262144"));
    }
    Ok(())
}

/// The newest backup snapshot (`bk-<id>`) among a dataset's snapshots: the base of the next
/// incremental send.
fn newest_backup_snapshot(snaps: &[String]) -> Option<String> {
    snaps.iter().filter(|s| s.starts_with("bk-")).max().cloned()
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

/// The first IPv4 address in `ip -4 -o addr show` output.
fn inet_of(text: &str) -> Option<Ipv4Addr> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let i = f.iter().position(|w| *w == "inet")?;
    f.get(i + 1)?.split('/').next()?.parse().ok()
}

/// Whether a machine whose process ended on its own (exit `code`, after `restarts` restarts
/// in a row) is started again.
fn restarts_after_exit(policy: &api::RestartPolicy, code: i32, restarts: u32) -> bool {
    match policy.policy.as_str() {
        "always" => true,
        "on-failure" => code != 0 && restarts < policy.max_retries,
        _ => false,
    }
}

/// When a running machine goes to sleep: its last use plus its window. None while it was
/// never used or never sleeps.
fn sleeps_at(last_used: Option<DateTime<Utc>>, window: Option<Duration>) -> Option<DateTime<Utc>> {
    match (last_used, window) {
        (Some(t), Some(w)) => Some(t + chrono::Duration::from_std(w).unwrap_or_default()),
        _ => None,
    }
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

/// The guest kernel's command line.
fn boot_args(pci: bool, extra: &str) -> String {
    let mut args = format!(
        "console=ttyS0 reboot=k panic=1 root=/dev/vda rw rootfstype=ext4 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on init={}",
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
    fn backup_chains() {
        let disk = |key: &str, from: Option<&str>| api::BackupDisk {
            disk: "root".into(),
            key: key.into(),
            bytes: 1,
            from: from.map(String::from),
        };
        let b = |id: &str, from: Option<&str>| api::Backup {
            id: id.into(),
            machine_id: "m_1".into(),
            tenant: "t".into(),
            name: "n".into(),
            created_at: Utc::now(),
            bytes: 1,
            incremental: from.is_some(),
            disks: vec![disk(&format!("k-{id}"), from)],
            machine: None,
        };
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
        assert_eq!(keys(&all[2]), vec!["k-a", "k-b", "k-c"]);
        assert_eq!(keys(&all[0]), vec!["k-a"]);
        assert_eq!(keys(&all[3]), vec!["k-d"]);
        assert!(backup_chain(&all, &all[2], "data").is_empty());
        // A base that is not in the store ends the chain where it is.
        let orphan = b("e", Some("zz"));
        assert_eq!(keys(&orphan), vec!["k-e"]);
        assert_eq!(
            newest_backup_snapshot(&[
                "fork-x".into(),
                "bk-20260101T000000Z".into(),
                "bk-20260102T000000Z".into()
            ]),
            Some("bk-20260102T000000Z".into())
        );
        assert_eq!(newest_backup_snapshot(&["fork-x".into()]), None);
    }

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
        // on-failure: a non-zero exit restarts until the retries run out; a clean exit never.
        let p = policy("on-failure", 3);
        assert!(restarts_after_exit(&p, 1, 0));
        assert!(restarts_after_exit(&p, 137, 2));
        assert!(!restarts_after_exit(&p, 1, 3));
        assert!(!restarts_after_exit(&p, 0, 0));
        assert!(!restarts_after_exit(&policy("on-failure", 0), 1, 0));
        // always: every time, whatever the code and however many times before.
        let p = policy("always", 0);
        assert!(restarts_after_exit(&p, 0, 0));
        assert!(restarts_after_exit(&p, 1, 1000));
        // no: never.
        assert!(!restarts_after_exit(&policy("no", 3), 1, 0));
        // The default policy is on-failure with three retries.
        let d = api::RestartPolicy::default();
        assert!(restarts_after_exit(&d, 1, 2));
        assert!(!restarts_after_exit(&d, 1, 3));
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
            name: "db".into(),
            image: "postgres:17".into(),
            image_key: "deadbeef".into(),
            image_digest: "sha256:abc".into(),
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
            egress: api::Egress::default(),
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
            boots: 0,
            created_at: now,
            updated_at: now,
            state_changed_at: now,
            started_at: None,
            stopped_at: None,
            last_used_at: None,
            console_offset: 0,
            suspended: false,
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
    /// recorded, one line each, the way the fake `zfs` records its own.
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
            })
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
            if let Boots::Panics = boots {
                panic!("the VMM panicked");
            }
            tokio::fs::create_dir_all(&b.dir).await?;
            let (api, vsock, console, _) = fc::paths(&b.dir);
            let snapshot = b.dir.join("snap.mem");
            let resumed = b.resume && snapshot.exists();
            let _ = std::fs::remove_file(&snapshot);
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

        async fn snapshot(&self, vm: &fc::Vm) -> Result<()> {
            self.record(format!("snapshot {}", vm.pid));
            std::fs::write(vm.dir.join("snap.mem"), b"memory")?;
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
    }

    #[async_trait::async_trait]
    impl guestc::Guest for Mock {
        /// Answers as the real wait does: only at the deadline when the init is silent.
        async fn wait_ready(&self, vsock: &Path, timeout: Duration) -> Result<()> {
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
                .map_err(|_| anyhow!("guest init did not answer within {timeout:?}"))
        }

        async fn shutdown(&self, vsock: &Path, grace: Duration) -> Result<()> {
            let (pid, _, _) = self.proc_at(vsock)?;
            self.record(format!("shutdown {pid} {}s", grace.as_secs()));
            let takes = *self.stops.lock().unwrap();
            tokio::time::sleep(takes).await;
            self.exit(pid, 0, true);
            Ok(())
        }

        async fn exec(&self, vsock: &Path, req: guest::Request) -> Result<guestc::ExecOutput> {
            let (pid, _, _) = self.proc_at(vsock)?;
            self.record(format!("exec {pid} {}", req.cmd.join(" ")));
            Ok(guestc::ExecOutput {
                stdout: b"ok\n".to_vec(),
                stderr: Vec::new(),
                code: 0,
                timed_out: false,
            })
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
        }
    }

    /// A manager over a temp directory, the fake `zfs` and the mock host: every transition
    /// runs, and what it did to the disks, the processes and the network is on record.
    struct Harness {
        pool: crate::zfs::fake::Fake,
        host: Arc<Mock>,
        _dir: tempfile::TempDir,
        m: Manager,
    }

    async fn harness(range: &str, memory_mb: u32) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let fake = crate::zfs::fake::Fake::open("byard").await.unwrap();
        let init = dir.path().join("init");
        std::fs::write(&init, b"init").unwrap();
        let cfg = Config {
            data_dir: dir.path().join("data"),
            network: crate::config::Network {
                range: range.into(),
                ..Default::default()
            },
            capacity: crate::config::Capacity {
                memory_mb,
                vcpus: 1000,
            },
            ..Default::default()
        };
        let zfs = fake.zfs.clone();
        let images = Builder::new(zfs.clone(), cfg.image_dir(), init, 8).unwrap();
        let store = Store::open(&cfg.state_dir()).unwrap();
        let (endpoint_events, _) = broadcast::channel(64);
        let host = Mock::new();
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
                backups: None,
                boot_gate: tokio::sync::Semaphore::new(2),
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
        fn add(&self, id: &str, state: &str, memory_mb: u32) -> Arc<Entry> {
            let mut r = record();
            r.id = id.into();
            r.state = state.into();
            r.size.memory_mb = memory_mb;
            let e = Entry::new(r);
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
            let t = Tenant {
                rec: TenantRec {
                    id: id.into(),
                    subnet_index: idx,
                    created_at: Utc::now(),
                },
                subnet: self.m.inner.range.subnet(idx).unwrap(),
            };
            tenants.insert(id.into(), t.clone());
            t
        }

        /// The disks of an added machine, on the fake pool.
        async fn disks(&self, e: &Entry) {
            let r = e.snapshot();
            let z = &self.pool.zfs;
            z.create(&r.root_dataset(), 1 << 20).await.unwrap();
            if r.volume.is_some() {
                z.create(&r.data_dataset(), 1 << 20).await.unwrap();
            }
        }

        /// A create request in tenant `t1` from the seeded image, started unless told
        /// otherwise; no volume, since a volume is formatted with the host's `mkfs.ext4`.
        fn request(&self, name: &str) -> api::CreateMachineRequest {
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
        async fn ready(&self) {
            self.tenant("t1");
            self.m
                .inner
                .images
                .seed(IMAGE, ImageConfig::default())
                .await
                .unwrap();
            self.pool.calls();
        }

        /// The machine's record as the store has it.
        fn stored(&self, id: &str) -> Option<Record> {
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
                    .map(|e| s.spawn(|| h.m.reserve(e).is_ok()))
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
        assert!(h.m.reserve(&a).is_ok());
        assert!(matches!(h.m.reserve(&b), Err(MError::Capacity(_))));
        assert_eq!(a.snapshot().state, state::STARTING);
        assert_eq!(b.snapshot().state, state::STOPPED);
        // A machine on its way down still holds its memory.
        a.set_state(state::STOPPING, |_| {});
        assert!(matches!(h.m.reserve(&b), Err(MError::Capacity(_))));
        assert!(admit(0, 100, 100).is_ok());
        assert!(admit(1, 100, 100).is_err());
        assert!(admit(u32::MAX, u32::MAX, 1).is_err());
    }

    #[tokio::test]
    async fn a_machine_being_destroyed_is_not_started() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_d", state::DESTROYING, 512);
        for r in [
            h.m.start("m_d").await,
            h.m.wake("m_d").await,
            h.m.start_entry(&e).await.map(|_| h.m.get("m_d").unwrap()),
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
    async fn wait_running_follows_the_state() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_w", state::STARTING, 512);
        let m = h.m.clone();
        let waiting =
            tokio::spawn(async move { m.wait_running("m_w", Duration::from_secs(30)).await });
        e.set_state(state::RUNNING, |_| {});
        assert_eq!(waiting.await.unwrap().unwrap().state, state::RUNNING);

        let e = h.add("m_e", state::STARTING, 512);
        let m = h.m.clone();
        let waiting =
            tokio::spawn(async move { m.wait_running("m_e", Duration::from_secs(30)).await });
        e.set_state(state::ERROR, |r| r.error = "no init".into());
        match waiting.await.unwrap() {
            Err(MError::NotRunning(why)) => assert_eq!(why, "no init"),
            other => panic!("{other:?}"),
        }
        // Already settled: answered at once, without a change to wait for.
        assert_eq!(
            h.m.wait_running("m_w", Duration::from_secs(30))
                .await
                .unwrap()
                .state,
            state::RUNNING
        );
        assert!(matches!(
            h.m.wait_running("m_x", Duration::from_secs(1)).await,
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

    #[tokio::test]
    async fn state_changed_at_moves_only_with_the_state() {
        let h = harness("10.64.0.0/22", 4096).await;
        let e = h.add("m_s", state::STOPPED, 512);
        let t0 = e.snapshot().state_changed_at;
        e.set_state(state::STOPPED, |r| r.stopped_reason = stop::USER.into());
        e.touch();
        let r = e.snapshot();
        assert_eq!(r.state_changed_at, t0);
        // A use is not a change to the machine; a write of one is.
        assert_eq!(r.updated_at, t0);
        h.m.save(&e).unwrap();
        assert!(e.snapshot().updated_at > t0);
        e.set_state(state::STARTING, |_| {});
        let r = e.snapshot();
        assert!(r.state_changed_at > t0);
        assert_eq!(h.m.get("m_s").unwrap().state_changed_at, r.state_changed_at);
    }

    #[test]
    fn records_from_before_are_migrated() {
        let mut r = record();
        r.sleep = String::new();
        r.state_changed_at = DateTime::<Utc>::default();
        r.migrate();
        assert_eq!(r.sleep, "never");
        assert_eq!(r.state_changed_at, r.updated_at);
        // A current record is left alone.
        let mut r = record();
        r.state_changed_at = r.updated_at + chrono::Duration::seconds(5);
        let before = r.clone();
        r.migrate();
        assert_eq!(r.sleep, before.sleep);
        assert_eq!(r.state_changed_at, before.state_changed_at);
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
            h.m.update("m_n", set("never")).await.unwrap().sleep,
            "never"
        );
        assert_eq!(h.m.update("m_n", set("")).await.unwrap().sleep, "never");
        assert_eq!(h.m.update("m_n", set("3h")).await.unwrap().sleep, "3h");
        assert!(matches!(
            h.m.update("m_n", set("soon")).await,
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
        assert_eq!(h.m.tenants()[0].gateway, "10.64.3.1");
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
        assert_eq!(h.m.list(Some("t1"))[0].id, m.id);
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
        match h.m.wait_running(&m.id, Duration::from_secs(1)).await {
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
            h.m.start(&created.id).await,
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
            let start = async move { a.start("m_race").await.map(|m| m.state) };
            let destroy = async move { b.destroy("m_race").await };
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
        let (ra, rb) = tokio::join!(a.start("m_a"), b.start("m_b"));
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
        let states: Vec<String> = h.m.list(None).into_iter().map(|m| m.state).collect();
        assert!(states.contains(&state::STOPPED.to_string()), "{states:?}");
    }

    #[tokio::test]
    async fn a_stop_ends_the_guest_and_the_watcher_settles_it() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let m = h.m.create(h.request("web")).await.unwrap();
        h.host.calls();
        let stopped =
            h.m.stop(&m.id, Duration::from_secs(3), false)
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
        assert!(matches!(h.m.wake(&m.id).await, Err(MError::NotRunning(_))));
        let again = h.m.start(&m.id).await.unwrap();
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
        e.set_state(state::STOPPING, |_| {});
        let (m2, id) = (h.m.clone(), m.id.clone());
        let second = tokio::spawn(async move {
            let t0 = std::time::Instant::now();
            m2.stop(&id, Duration::from_secs(1), false).await.unwrap();
            t0.elapsed()
        });
        drop(held);
        // The watcher settles the machine as soon as it can take the lock.
        let _settling = e.lock.lock().await;
        e.set_state(state::STOPPED, |r| r.stopped_reason = stop::USER.into());
        drop(_settling);
        let waited = second.await.unwrap();
        assert!(waited < Duration::from_secs(1), "{waited:?}");
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
            match h.m.list(Some("t1")).pop() {
                Some(m) => break m.id,
                None => tokio::task::yield_now().await,
            }
        };
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let running = h.m.wait_running(&id, Duration::from_secs(5)).await.unwrap();
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
        let err = detached(async move { m.start("m_p").await })
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
        tokio::time::timeout(Duration::from_secs(5), h.m.destroy("m_p"))
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
        ours.set_state(state::RUNNING, |r| r.pid = pid);
        // Not ours: a pid from before a reboot, now someone else's.
        let other = h.add("m_other", state::RUNNING, 256);
        other.set_state(state::RUNNING, |r| r.pid = 4242);
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
        let slept = h.m.stop(&m.id, Duration::from_secs(1), true).await.unwrap();
        assert!(slept.suspended);
        assert_eq!(slept.state, state::STOPPED);
        let calls = h.host.calls();
        assert_eq!(&calls[..2], ["snapshot 1000", "kill 1000"]);
        let back = h.m.start(&m.id).await.unwrap();
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
        let path = h.m.inner.cfg.state_dir().join("machines/m_t.json");
        let written = || std::fs::metadata(&path).unwrap().modified().unwrap();
        let before = h.stored("m_t").unwrap();
        let t0 = written();
        for _ in 0..10 {
            h.m.touch("m_t").unwrap();
        }
        let used = e.snapshot().last_used_at;
        assert!(used.is_some());
        // Memory has the use, the API reads it there, and the disk was not written.
        assert_eq!(h.m.get("m_t").unwrap().last_used_at, used);
        assert_eq!(h.stored("m_t").unwrap().last_used_at, None);
        assert_eq!(written(), t0);
        // The tick writes it once, as the machine is: `updated_at` stays.
        h.m.tick().await;
        let stored = h.stored("m_t").unwrap();
        assert_eq!(stored.last_used_at, used);
        assert_eq!(stored.updated_at, before.updated_at);
        let t1 = written();
        assert!(t1 > t0);
        // Nothing moved since: the next tick writes nothing.
        h.m.tick().await;
        assert_eq!(written(), t1);
        // A change to the machine carries the use with it, and the tick has nothing left.
        h.m.touch("m_t").unwrap();
        e.set_state(state::STARTING, |_| {});
        h.m.save(&e).unwrap();
        let t2 = written();
        assert_eq!(
            h.stored("m_t").unwrap().last_used_at,
            e.snapshot().last_used_at
        );
        h.m.tick().await;
        assert_eq!(written(), t2);
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
        for m in h.m.list(None) {
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
        async fn fork(&self, src: &str, name: &str) -> api::Machine {
            let mut req = self.request(name);
            req.image = String::new();
            req.fork = Some(api::ForkSpec {
                machine_id: src.into(),
                copy: String::new(),
            });
            self.m.create(req).await.unwrap()
        }

        fn snapshot_exists(&self, ds: &str, snap: &str) -> bool {
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
        h.m.destroy(&fork.id).await.unwrap();
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
        h.m.destroy(&a.id).await.unwrap();
        assert!(h.snapshot_exists(&root, &snap_a));
        // A snapshot that is not a fork's (the image's base) is never touched.
        h.pool.calls();
        h.m.destroy(&src.id).await.unwrap();
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
        h.m.destroy(&src.id).await.unwrap();
        // The fork was promoted and owns the snapshot it was made from; with the source gone
        // nothing clones that snapshot, so it goes too.
        assert!(h.pool.dev().join(format!("byard/{fork_root}")).exists());
        assert!(!h.pool.dev().join(format!("byard/m/{}", src.id)).exists());
        assert!(!h.snapshot_exists(&fork_root, &snap));
        assert_eq!(h.pool.zfs.origin(&fork_root).await.unwrap(), None);
        assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
        h.m.destroy(&fork.id).await.unwrap();
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
        z.snapshot("m/m_kept/root", "s_mine").await.unwrap();
        h.m.sweep_orphans().await;
        assert!(!h.snapshot_exists("m/m_kept/root", "fork-gone"));
        assert!(h.snapshot_exists("m/m_kept/root", "fork-m_child"));
        assert!(h.snapshot_exists("m/m_kept/root", "s_mine"));
    }

    #[tokio::test]
    async fn a_snapshot_is_removed_on_request() {
        let h = harness("10.64.0.0/22", 4096).await;
        h.tenant("t1");
        let e = h.add("m_s", state::STOPPED, 256);
        h.disks(&e).await;
        let s = h.m.snapshot("m_s").await.unwrap();
        assert!(h.snapshot_exists("m/m_s/root", &s.id));
        assert!(h.snapshot_exists("m/m_s/data", &s.id));
        assert_eq!(h.m.snapshots("m_s").await.unwrap()[0].id, s.id);
        h.m.delete_snapshot("m_s", &s.id).await.unwrap();
        assert!(!h.snapshot_exists("m/m_s/root", &s.id));
        assert!(!h.snapshot_exists("m/m_s/data", &s.id));
        assert!(h.m.snapshots("m_s").await.unwrap().is_empty());
        // Gone already: success. The daemon's own snapshots are not the caller's.
        h.m.delete_snapshot("m_s", &s.id).await.unwrap();
        h.pool.zfs.snapshot("m/m_s/root", "fork-x").await.unwrap();
        for bad in ["fork-x", "bk-20260101T000000Z", "s_../x", ""] {
            assert!(
                matches!(h.m.delete_snapshot("m_s", bad).await, Err(MError::NotFound)),
                "{bad}"
            );
        }
        assert!(h.snapshot_exists("m/m_s/root", "fork-x"));
        assert!(matches!(
            h.m.delete_snapshot("m_none", "s_1").await,
            Err(MError::NotFound)
        ));
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
        h.m.stop(&m.id, Duration::from_secs(3), false)
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
        h.m.start(&m.id).await.unwrap();
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
        let changed = h.m.update(&m.id, set_egress("none", None)).await.unwrap();
        assert_eq!(changed.egress, egress("none", None));
        assert_eq!(
            h.host.calls(),
            [format!("swap_policy {VIA} -> none 10.64.1.3")],
            "one call, one transaction"
        );
        assert!(h.dns_kept("10.64.1.3"));
        // The same policy again: nothing to change.
        h.m.update(&m.id, set_egress("none", None)).await.unwrap();
        assert!(h.host.calls().is_empty());
        // Open: nothing in the tables, outside names forwarded again.
        h.m.update(&m.id, set_egress("open", None)).await.unwrap();
        assert_eq!(h.host.calls(), ["unset_policy none 10.64.1.3"]);
        assert!(!h.dns_kept("10.64.1.3"));
        // Stopped: the record changes, the next start applies it.
        h.m.stop(&m.id, Duration::from_secs(3), false)
            .await
            .unwrap();
        h.host.calls();
        h.m.update(&m.id, set_egress("none", None)).await.unwrap();
        assert!(h.host.calls().is_empty());
        assert_eq!(h.stored(&m.id).unwrap().egress, egress("none", None));
        h.m.start(&m.id).await.unwrap();
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
            let update = h.m.update(&m.id, set_egress("via", Some(via))).await;
            assert_eq!(refused(update), want);
        }
        assert_eq!(
            refused(h.m.update(&m.id, set_egress("via", Some(&m.id))).await),
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
        assert!(h.m.list(None).iter().all(|x| x.name != "sbx2"));
        assert_eq!(h.stored(&m.id).unwrap().egress, api::Egress::default());
        // Its own tenant's machine is a gateway.
        h.m.update(&m.id, set_egress("via", Some(&gw.id)))
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
        h.m.destroy(&gw.id).await.unwrap();
        // The policy stays, and so does the address it names: a new machine gets another.
        assert_eq!(h.m.create(h.request("next")).await.unwrap().ip, "10.64.1.4");
        h.host.calls();
        // A stop takes out what was set, gateway or not.
        h.m.stop(&m.id, Duration::from_secs(3), false)
            .await
            .unwrap();
        assert!(h.host.calls().contains(&format!("unset_policy {VIA}")));
        // A start is refused until the policy names a machine that is there; nothing moves.
        assert_eq!(
            refused(h.m.start(&m.id).await),
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
            h.m.update(&m.id, set_egress("none", None))
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
        let changed = h.m.update(&m.id, set_egress("none", None)).await.unwrap();
        assert_eq!(changed.egress, egress("none", None));
    }
}
