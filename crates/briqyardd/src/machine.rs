//! Machines: their records, disks, network and Firecracker processes, and every lifecycle
//! transition. One `Manager` per daemon.

use crate::config::Config;
use crate::fc;
use crate::guestc;
use crate::image::{self, Builder, ImageConfig};
use crate::netw::{self, dns::Resolver, host, nft::Ruleset, Range, Subnet};
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
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub stopped_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Where the current boot's console output starts.
    #[serde(default)]
    pub console_offset: u64,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantRec {
    pub id: String,
    pub subnet_index: u32,
    pub created_at: DateTime<Utc>,
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

/// Makes an id: a prefix and 12 hex characters.
pub fn new_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{prefix}_{}", hex::encode(b))
}

/// The running process, as the entry keeps it.
#[derive(Clone)]
struct Live {
    pid: u32,
    vsock: PathBuf,
    exited: tokio::sync::watch::Receiver<bool>,
}

struct Entry {
    /// Serializes lifecycle operations on one machine.
    lock: tokio::sync::Mutex<()>,
    rec: Mutex<Record>,
    live: Mutex<Option<Live>>,
    /// The reason set before asking the guest to stop; `None` when it ends on its own.
    stop_req: Mutex<Option<String>>,
    /// Signalled when the watcher settled the state after an exit.
    settled: Notify,
}

impl Entry {
    fn snapshot(&self) -> Record {
        self.rec.lock().unwrap().clone()
    }
}

struct Inner {
    cfg: Config,
    store: Store,
    zfs: Zfs,
    images: Builder,
    dns: Resolver,
    range: Range,
    egress: String,
    host_id: String,
    machines: Mutex<HashMap<String, Arc<Entry>>>,
    tenants: Mutex<HashMap<String, TenantRec>>,
    endpoints: Mutex<HashMap<String, EndpointRec>>,
    endpoint_events: broadcast::Sender<(EndpointRec, bool)>,
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
        let (endpoint_events, _) = broadcast::channel(64);
        let inner = Arc::new(Inner {
            cfg,
            store,
            zfs,
            images,
            dns,
            range,
            egress,
            host_id,
            machines: Mutex::new(HashMap::new()),
            tenants: Mutex::new(HashMap::new()),
            endpoints: Mutex::new(HashMap::new()),
            endpoint_events,
        });
        let m = Self { inner };
        m.load()?;
        host::enable_forwarding()?;
        let tenants: Vec<TenantRec> = m.inner.tenants.lock().unwrap().values().cloned().collect();
        for t in &tenants {
            m.plumb_tenant(t).await?;
            m.refresh_dns(t);
        }
        m.apply_rules().await?;
        m.recover().await;
        let sleeper = m.clone();
        tokio::spawn(async move { sleeper.sleeper().await });
        Ok(m)
    }

    pub fn host_id(&self) -> &str {
        &self.inner.host_id
    }

    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    fn load(&self) -> Result<()> {
        let st = &self.inner.store;
        for t in st.list::<TenantRec>("tenants")? {
            self.inner.tenants.lock().unwrap().insert(t.id.clone(), t);
        }
        for r in st.list::<Record>("machines")? {
            let e = Arc::new(Entry {
                lock: tokio::sync::Mutex::new(()),
                rec: Mutex::new(r.clone()),
                live: Mutex::new(None),
                stop_req: Mutex::new(None),
                settled: Notify::new(),
            });
            self.inner.machines.lock().unwrap().insert(r.id, e);
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

    /// Machines a previous daemon left: their Firecracker processes are ended and they are
    /// marked stopped (idle, so the next use wakes them).
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
            match rec.state.as_str() {
                state::RUNNING | state::STARTING | state::STOPPING => {
                    if rec.pid > 0 {
                        unsafe {
                            libc::kill(-(rec.pid as i32), libc::SIGKILL);
                            libc::kill(rec.pid as i32, libc::SIGKILL);
                        }
                    }
                    let _ = host::delete_tap(&rec.id).await;
                    {
                        let mut r = e.rec.lock().unwrap();
                        r.state = state::STOPPED.into();
                        r.stopped_reason = stop::IDLE.into();
                        r.pid = 0;
                        r.stopped_at = Some(Utc::now());
                    }
                    tracing::warn!(
                        machine = rec.id,
                        "machine left running by a previous daemon, marked stopped"
                    );
                    let _ = self.save(&e);
                }
                state::DESTROYING => {
                    let m = self.clone();
                    let id = rec.id.clone();
                    tokio::spawn(async move {
                        if let Err(err) = m.destroy(&id).await {
                            tracing::error!(machine = id, err = %err, "resume destroy");
                        }
                    });
                }
                _ => {}
            }
        }
    }

    fn save(&self, e: &Entry) -> Result<()> {
        let rec = {
            let mut r = e.rec.lock().unwrap();
            r.updated_at = Utc::now();
            r.clone()
        };
        self.inner.store.put("machines", &rec.id, &rec)
    }

    /// Stops every running machine; the daemon is going down.
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
                    if let Err(err) = m.stop_entry(&e, stop::IDLE, Duration::from_secs(10)).await {
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

    fn subnet(&self, t: &TenantRec) -> Subnet {
        self.inner
            .range
            .subnet(t.subnet_index)
            .expect("subnet index in range")
    }

    async fn plumb_tenant(&self, t: &TenantRec) -> Result<()> {
        let s = self.subnet(t);
        host::ensure_bridge(&s).await?;
        self.inner.dns.listen(s.gateway()).await?;
        Ok(())
    }

    async fn ensure_tenant(&self, id: &str) -> Result<TenantRec> {
        if let Some(t) = self.inner.tenants.lock().unwrap().get(id) {
            return Ok(t.clone());
        }
        let t = {
            let tenants = self.inner.tenants.lock().unwrap();
            let used: Vec<u32> = tenants.values().map(|t| t.subnet_index).collect();
            let idx = netw::first_free(used, 0, self.inner.range.count() - 1)
                .ok_or_else(|| anyhow!("no tenant subnet left"))?;
            TenantRec {
                id: id.to_string(),
                subnet_index: idx,
                created_at: Utc::now(),
            }
        };
        self.plumb_tenant(&t).await?;
        self.inner.store.put("tenants", id, &t)?;
        self.inner
            .tenants
            .lock()
            .unwrap()
            .insert(id.to_string(), t.clone());
        self.apply_rules().await?;
        Ok(t)
    }

    async fn apply_rules(&self) -> Result<()> {
        let mut bridges: Vec<String> = self
            .inner
            .tenants
            .lock()
            .unwrap()
            .values()
            .map(|t| netw::bridge_name(t.subnet_index))
            .collect();
        bridges.sort();
        Ruleset {
            egress: self.inner.egress.clone(),
            range: self.inner.range.to_string(),
            bridges,
        }
        .apply()
        .await
    }

    /// Republishes a tenant's names on its gateway.
    fn refresh_dns(&self, t: &TenantRec) {
        let mut names: HashMap<String, Ipv4Addr> = HashMap::new();
        for e in self.inner.machines.lock().unwrap().values() {
            let r = e.rec.lock().unwrap();
            if r.tenant != t.id {
                continue;
            }
            if let Ok(ip) = r.ip.parse::<Ipv4Addr>() {
                names.insert(r.hostname(), ip);
                names.insert(r.machine_host(), ip);
            }
        }
        self.inner.dns.set(self.subnet(t).gateway(), names);
    }

    fn tenant_of(&self, id: &str) -> Option<TenantRec> {
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
            .map(|t| {
                let s = self.subnet(t);
                api::Tenant {
                    id: t.id.clone(),
                    subnet: s.cidr(),
                    gateway: s.gateway().to_string(),
                    machines: machines
                        .values()
                        .filter(|e| e.rec.lock().unwrap().tenant == t.id)
                        .count(),
                    created_at: t.created_at,
                }
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Removes an empty tenant's network. Missing is success.
    pub async fn delete_tenant(&self, id: &str) -> Result<(), MError> {
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
        self.inner.dns.unset(self.subnet(&t).gateway());
        host::delete_bridge(t.subnet_index).await?;
        self.inner.tenants.lock().unwrap().remove(id);
        self.inner.store.delete("tenants", id)?;
        self.apply_rules().await?;
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
            match (r.last_used_at, r.sleep_window()) {
                (Some(t), Some(w)) => Some(t + chrono::Duration::from_std(w).unwrap_or_default()),
                _ => None,
            }
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
            sleep: if r.sleep.is_empty() {
                "never".into()
            } else {
                r.sleep.clone()
            },
            restart: r.restart.clone(),
            metadata: r.metadata.clone(),
            endpoints: self.endpoints_of(&r.id),
            created_at: r.created_at,
            updated_at: r.updated_at,
            started_at: r.started_at,
            stopped_at: r.stopped_at,
            last_used_at: r.last_used_at,
            sleeps_at,
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
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        out
    }

    /// What running machines take, how many run, how many exist.
    pub fn usage(&self) -> (api::Capacity, usize, usize) {
        let mut used = api::Capacity::default();
        let (mut running, mut total) = (0, 0);
        for e in self.inner.machines.lock().unwrap().values() {
            let r = e.rec.lock().unwrap();
            total += 1;
            if r.state == state::RUNNING || r.state == state::STARTING {
                running += 1;
                used.memory_mb += r.size.memory_mb;
                used.vcpus += r.size.vcpus;
            }
        }
        (used, running, total)
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
        if req.tenant.is_empty() || req.tenant.len() > 64 {
            return Err(invalid("tenant is required (at most 64 characters)"));
        }
        if !api::valid_name(&req.name) {
            return Err(invalid("name must be a DNS label (a-z, 0-9, -)"));
        }
        if req.image.is_empty() && req.fork.is_none() {
            return Err(invalid("image is required"));
        }
        if !(1..=32).contains(&req.size.vcpus) {
            return Err(invalid("size.vcpus must be 1..32"));
        }
        if !(128..=262144).contains(&req.size.memory_mb) {
            return Err(invalid("size.memory_mb must be 128..262144"));
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
            sleep: if req.sleep == "never" {
                String::new()
            } else {
                req.sleep.clone()
            },
            restart,
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
            started_at: None,
            stopped_at: None,
            last_used_at: None,
            console_offset: 0,
        };
        let mut src: Option<Arc<Entry>> = None;
        if let Some(fork) = &req.fork {
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
        if let Err(err) = self.make_disks(&e, src.as_deref(), req.fork.as_ref()).await {
            let rec = e.snapshot();
            self.remove_machine(&e);
            let _ = self.inner.zfs.destroy(&rec.dataset()).await;
            return Err(err.into());
        }
        self.save(&e)?;
        if req.start.unwrap_or(true) {
            if let Err(err) = self.start_entry(&e).await {
                // Created but did not start: the caller gets the machine with its error.
                tracing::warn!(machine = e.snapshot().id, err = %err, "start after create");
            }
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
    fn add_machine(&self, mut rec: Record, t: &TenantRec) -> Result<Arc<Entry>, MError> {
        let mut machines = self.inner.machines.lock().unwrap();
        let mut used = Vec::new();
        for e in machines.values() {
            let r = e.rec.lock().unwrap();
            if r.tenant == rec.tenant && r.name == rec.name && r.state != state::DESTROYING {
                return Err(MError::Conflict(
                    "a machine with that name exists in the tenant".into(),
                ));
            }
            if r.tenant == t.id {
                used.push(r.host_num as u32);
            }
        }
        let n = netw::first_free(used, 2, 254)
            .ok_or_else(|| MError::Capacity(format!("tenant {} has no address left", t.id)))?;
        let s = self.subnet(t);
        rec.subnet_index = t.subnet_index;
        rec.host_num = n as u8;
        rec.ip = s.host(n as u8)?.to_string();
        let e = Arc::new(Entry {
            lock: tokio::sync::Mutex::new(()),
            rec: Mutex::new(rec.clone()),
            live: Mutex::new(None),
            stop_req: Mutex::new(None),
            settled: Notify::new(),
        });
        machines.insert(rec.id.clone(), e.clone());
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

    // --- start ---

    pub async fn start(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let _guard = e.lock.lock().await;
        let st = e.snapshot().state;
        match st.as_str() {
            state::RUNNING => return Ok(self.view(&e)),
            state::CREATED | state::STOPPED | state::ERROR => {}
            other => return Err(MError::BadState(other.into())),
        }
        self.start_entry(&e).await?;
        Ok(self.view(&e))
    }

    /// Starts a machine that went to sleep or whose process ended; one stopped on purpose
    /// stays stopped.
    pub async fn wake(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let _guard = e.lock.lock().await;
        let r = e.snapshot();
        match r.state.as_str() {
            state::RUNNING => {
                self.touch_entry(&e);
                return Ok(self.view(&e));
            }
            state::STOPPED if r.stopped_reason == stop::USER => {
                return Err(MError::NotRunning("stopped on request".into()))
            }
            state::STOPPED | state::CREATED => {}
            other => return Err(MError::BadState(other.into())),
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

    /// Boots the machine. Called with the entry's lock held.
    async fn start_entry(&self, e: &Arc<Entry>) -> Result<(), MError> {
        let cfg = &self.inner.cfg;
        let rec = e.snapshot();
        let cap = self.capacity();
        let (used, _, _) = self.usage();
        if used.memory_mb + rec.size.memory_mb > cap.memory_mb {
            return Err(MError::Capacity(format!(
                "{} MB used of {}",
                used.memory_mb, cap.memory_mb
            )));
        }
        {
            let mut r = e.rec.lock().unwrap();
            r.state = state::STARTING.into();
            r.error.clear();
            r.pid = 0;
        }
        let _ = self.save(e);
        let fail = |err: anyhow::Error| -> MError {
            {
                let mut r = e.rec.lock().unwrap();
                r.state = state::ERROR.into();
                r.error = format!("{err:#}");
                r.stopped_at = Some(Utc::now());
                r.pid = 0;
            }
            let _ = self.save(e);
            MError::Other(err)
        };
        let t = match self.tenant_of(&rec.tenant) {
            Some(t) => t,
            None => return Err(fail(anyhow!("tenant network is gone"))),
        };
        let tap = host::ensure_tap(&rec.id, &netw::bridge_name(t.subnet_index))
            .await
            .map_err(fail)?;
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
        let console_offset = tokio::fs::metadata(dir.join("console.log"))
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        e.rec.lock().unwrap().console_offset = console_offset;
        let mut proc = fc::Process::start(&cfg.firecracker, &rec.id, &dir, cfg.pci)
            .await
            .map_err(fail)?;
        let c = proc.client.clone();
        let ip: Ipv4Addr = rec.ip.parse().unwrap();
        let configure = async {
            c.machine_config(rec.size.vcpus, rec.size.memory_mb).await?;
            c.boot_source(&cfg.kernel, &self.boot_args()).await?;
            c.drive("rootfs", &root_dev, true, false, "Writeback")
                .await?;
            c.drive("config", &config_drive, false, true, "Unsafe")
                .await?;
            if let Some(d) = &data_dev {
                c.drive("data", d, false, false, "Writeback").await?;
            }
            c.network_interface("eth0", &tap, &netw::mac_for(ip))
                .await?;
            c.vsock(3, &proc.vsock).await?;
            c.start().await?;
            Ok::<(), anyhow::Error>(())
        };
        if let Err(err) = configure.await {
            proc.kill();
            return Err(fail(anyhow!("configure firecracker: {err}")));
        }
        let (exit_tx, exit_rx) = tokio::sync::watch::channel(false);
        let live = Live {
            pid: proc.pid(),
            vsock: proc.vsock.clone(),
            exited: exit_rx,
        };
        {
            *e.live.lock().unwrap() = Some(live.clone());
            *e.stop_req.lock().unwrap() = None;
            let mut r = e.rec.lock().unwrap();
            r.pid = proc.pid();
            r.boots += 1;
        }
        let _ = self.save(e);
        let watcher = self.clone();
        let we = e.clone();
        tokio::spawn(async move {
            proc.wait().await;
            let _ = exit_tx.send(true);
            watcher.settle_exit(&we, live.pid).await;
        });

        let ready = guestc::wait_ready(&live.vsock, Duration::from_secs(60));
        let mut exited = live.exited.clone();
        tokio::select! {
            r = ready => {
                if let Err(err) = r {
                    if *exited.borrow() {
                        return Err(MError::Other(anyhow!("the machine exited during boot: {}", self.last_console_lines(&rec, 5))));
                    }
                    unsafe { libc::kill(live.pid as i32, libc::SIGKILL); }
                    return Err(fail(anyhow!("the guest did not come up: {err}")));
                }
            }
            _ = exited.changed() => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Err(MError::Other(anyhow!("the machine exited during boot: {}", self.last_console_lines(&rec, 5))));
            }
        }
        {
            let now = Utc::now();
            let mut r = e.rec.lock().unwrap();
            r.state = state::RUNNING.into();
            r.started_at = Some(now);
            r.last_used_at = Some(now);
            r.stopped_reason.clear();
        }
        let _ = self.save(e);
        tracing::info!(
            machine = rec.id,
            tenant = rec.tenant,
            name = rec.name,
            ip = rec.ip,
            pid = live.pid,
            "machine running"
        );
        Ok(())
    }

    fn boot_args(&self) -> String {
        let mut args = format!(
            "console=ttyS0 reboot=k panic=1 root=/dev/vda rw rootfstype=ext4 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on init={}",
            image::INIT_PATH
        );
        if !self.inner.cfg.pci {
            args.push_str(" pci=off");
        }
        if !self.inner.cfg.kernel_args.is_empty() {
            args.push(' ');
            args.push_str(&self.inner.cfg.kernel_args);
        }
        args
    }

    /// Settles the state after the Firecracker process exited.
    async fn settle_exit(&self, e: &Arc<Entry>, pid: u32) {
        let _guard = e.lock.lock().await;
        {
            let live = e.live.lock().unwrap();
            if live.as_ref().map(|l| l.pid) != Some(pid) {
                return;
            }
        }
        let rec = e.snapshot();
        let _ = host::delete_tap(&rec.id).await;
        *e.live.lock().unwrap() = None;
        let (code, oom, requested) = self.exit_from_console(&rec);
        let stop_req = e.stop_req.lock().unwrap().take();
        let now = Utc::now();
        let mut restart_again = false;
        {
            let mut r = e.rec.lock().unwrap();
            r.pid = 0;
            r.stopped_at = Some(now);
            if let Some(reason) = stop_req {
                r.state = state::STOPPED.into();
                r.stopped_reason = reason.clone();
                tracing::info!(machine = r.id, reason, "machine stopped");
            } else if requested {
                r.state = state::STOPPED.into();
                r.stopped_reason = stop::USER.into();
            } else {
                let again = match r.restart.policy.as_str() {
                    "always" => true,
                    "on-failure" => code != 0 && r.restarts < r.restart.max_retries,
                    _ => false,
                };
                r.exit = Some(api::Exit {
                    code,
                    oom_killed: oom,
                    at: now,
                    restarting: again,
                });
                r.state = state::STOPPED.into();
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
        }
        let _ = self.save(e);
        e.settled.notify_waiters();
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
                if let Err(err) = m.start_boxed(&e).await {
                    tracing::error!(machine = r.id, err = %err, "restart");
                }
            });
        }
    }

    /// Reads the init's exit line for this boot: `[briqyard] exit code=N oom=B requested=R`.
    fn exit_from_console(&self, r: &Record) -> (i32, bool, bool) {
        let text = self.console_since(r, 8 << 20);
        let mut found = (255, false, false);
        for line in text.lines() {
            if let Some(rest) = line.split("[briqyard] exit ").nth(1) {
                let mut code = 255;
                let (mut oom, mut requested) = (false, false);
                for kv in rest.split_whitespace() {
                    match kv.split_once('=') {
                        Some(("code", v)) => code = v.parse().unwrap_or(255),
                        Some(("oom", v)) => oom = v == "true",
                        Some(("requested", v)) => requested = v == "true",
                        _ => {}
                    }
                }
                found = (code, oom, requested);
            }
        }
        found
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

    pub async fn stop(&self, id: &str, timeout: Duration) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        self.stop_entry(&e, stop::USER, timeout).await?;
        Ok(self.view(&e))
    }

    /// Asks the guest to end its process, then waits for Firecracker to exit; after the grace,
    /// kills. Takes the entry's lock only briefly so the watcher can settle the state.
    async fn stop_entry(
        &self,
        e: &Arc<Entry>,
        reason: &str,
        timeout: Duration,
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
                    drop(_guard);
                    let _ = tokio::time::timeout(
                        timeout + Duration::from_secs(15),
                        e.settled.notified(),
                    )
                    .await;
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
            e.rec.lock().unwrap().state = state::STOPPING.into();
            let _ = self.save(e);
            live
        };
        let settled = e.settled.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        if let Err(err) = tokio::time::timeout(
            Duration::from_secs(5),
            guestc::shutdown(&live.vsock, timeout),
        )
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r)
        {
            tracing::warn!(machine = e.snapshot().id, err = %err, "guest shutdown request failed, killing");
            unsafe {
                libc::kill(live.pid as i32, libc::SIGKILL);
            }
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
            unsafe {
                libc::kill(live.pid as i32, libc::SIGKILL);
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), settled).await;
        Ok(())
    }

    // --- destroy ---

    pub async fn destroy(&self, id: &str) -> Result<(), MError> {
        let e = match self.entry(id) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        let st = e.snapshot().state;
        if st == state::RUNNING || st == state::STOPPING || st == state::STARTING {
            self.stop_entry(&e, stop::USER, Duration::from_secs(5))
                .await?;
        }
        {
            let _guard = e.lock.lock().await;
            e.rec.lock().unwrap().state = state::DESTROYING.into();
            let _ = self.save(&e);
        }
        for ep in self.endpoints_of(id) {
            let _ = self.delete_endpoint(&ep.id);
        }
        let _ = host::delete_tap(id).await;
        let rec = e.snapshot();
        self.inner
            .zfs
            .destroy(&rec.dataset())
            .await
            .context("disks")?;
        let _ = tokio::fs::remove_dir_all(self.inner.cfg.run_dir().join(id)).await;
        self.inner.store.delete("machines", id)?;
        self.remove_machine(&e);
        tracing::info!(machine = id, "machine destroyed");
        Ok(())
    }

    // --- use and sleep ---

    pub fn touch(&self, id: &str) -> Result<(), MError> {
        let e = self.entry(id)?;
        self.touch_entry(&e);
        Ok(())
    }

    fn touch_entry(&self, e: &Entry) {
        e.rec.lock().unwrap().last_used_at = Some(Utc::now());
        let _ = self.save(e);
    }

    async fn sleeper(self) {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let due: Vec<Arc<Entry>> = self
                .inner
                .machines
                .lock()
                .unwrap()
                .values()
                .filter(|e| {
                    let r = e.rec.lock().unwrap();
                    r.state == state::RUNNING
                        && match (r.last_used_at, r.sleep_window()) {
                            (Some(t), Some(w)) => Utc::now()
                                .signed_duration_since(t)
                                .to_std()
                                .map(|d| d > w)
                                .unwrap_or(false),
                            _ => false,
                        }
                })
                .cloned()
                .collect();
            for e in due {
                tracing::info!(machine = e.snapshot().id, "machine idle, going to sleep");
                if let Err(err) = self
                    .stop_entry(&e, stop::IDLE, Duration::from_secs(10))
                    .await
                {
                    tracing::warn!(machine = e.snapshot().id, err = %err, "sleep");
                }
            }
        }
    }

    pub async fn wait_running(&self, id: &str, timeout: Duration) -> Result<api::Machine, MError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let m = self.get(id)?;
            match m.state.as_str() {
                state::RUNNING => return Ok(m),
                state::ERROR => return Err(MError::NotRunning(m.error)),
                state::STOPPED
                    if !(m.stopped_reason == stop::EXIT
                        && m.exit.as_ref().map(|e| e.restarting).unwrap_or(false)) =>
                {
                    return Err(MError::NotRunning(format!(
                        "stopped ({})",
                        m.stopped_reason
                    )))
                }
                _ => {}
            }
            if tokio::time::Instant::now() > deadline {
                return Err(MError::NotRunning(format!(
                    "still {} after {timeout:?}",
                    m.state
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // --- config drive ---

    fn write_config_drive(&self, path: &Path, r: &Record, t: &TenantRec) -> Result<()> {
        let s = self.subnet(t);
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
            gateway: s.gateway().to_string(),
            dns: vec![s.gateway().to_string()],
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
            let data =
                guest::base64_decode(&f.base64).map_err(|e| anyhow!("file {}: {e}", f.path))?;
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
        let tmp = path.with_extension("tar.tmp");
        let mut b = tar::Builder::new(std::fs::File::create(&tmp)?);
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
        let mut f = b.into_inner()?;
        // Firecracker wants a drive's size to be a multiple of 512 bytes.
        use std::io::Write;
        let len = f.metadata()?.len();
        let pad = (512 - len % 512) % 512;
        if pad > 0 {
            f.write_all(&vec![0u8; pad as usize])?;
        }
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        Ok(())
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
        self.wake(id).await?;
        let live = e.live.lock().unwrap().clone();
        live.map(|l| l.vsock)
            .ok_or_else(|| MError::NotRunning("no process".into()))
    }

    pub async fn exec(&self, id: &str, req: api::ExecRequest) -> Result<api::ExecResult, MError> {
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
            guestc::exec(&sock, greq),
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
            guestc::put(&sock, &req.path, mode, data),
        )
        .await
        .map_err(|_| MError::NotRunning("timeout".into()))??;
        let _ = self.touch(id);
        Ok(())
    }

    pub async fn get_file(&self, id: &str, path: &str) -> Result<Vec<u8>, MError> {
        let sock = self.running_vsock(id, false).await?;
        let data = tokio::time::timeout(Duration::from_secs(60), guestc::get(&sock, path))
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
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
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
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        out
    }

    pub fn endpoint_view(&self, e: &EndpointRec) -> api::Endpoint {
        let address = match e.protocol.as_str() {
            "http" => format!("http://{}", e.host),
            _ => {
                let bind = &self.inner.cfg.ingress.bind;
                let addr = if bind.is_empty() || bind == "0.0.0.0" {
                    self.host_ip()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| bind.clone())
                } else {
                    bind.clone()
                };
                format!("{addr}:{}", e.host_port.unwrap_or(0))
            }
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

    fn host_ip(&self) -> Option<Ipv4Addr> {
        // Read once per call: cheap and always current.
        let out = std::process::Command::new("ip")
            .args(["-4", "-o", "addr", "show", "dev", &self.inner.egress])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let f: Vec<&str> = text.split_whitespace().collect();
        let i = f.iter().position(|w| *w == "inet")?;
        f.get(i + 1)?.split('/').next()?.parse().ok()
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
            let (lo, hi) = port_range(&self.inner.cfg.ingress.tcp_ports)?;
            let used: Vec<u32> = endpoints
                .values()
                .filter_map(|x| x.host_port.map(|p| p as u32))
                .collect();
            let port = netw::first_free(used, lo as u32, hi as u32)
                .ok_or_else(|| MError::Capacity("no tcp endpoint port left".into()))?;
            ep.host_port = Some(port as u16);
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
            self.touch_entry(&e);
            return Ok(ip.parse().unwrap());
        }
        if !wake {
            return Err(MError::NotRunning(st));
        }
        self.wake(id).await?;
        Ok(ip.parse().unwrap())
    }
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
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|kb| kb.parse::<u64>().ok())
                })
        })
        .map(|kb| (kb / 1024) as u32)
        .unwrap_or(4096)
}
