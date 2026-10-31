//! The manager's tests: the shared harness (a manager over a temp directory, the fake `zfs`
//! and a mock host) here, the tests by area in the modules beside it.

use super::*;
use chrono::TimeZone;

mod balloon;
mod event_log;
mod gateway;
mod lifecycle;
mod metering;
mod mock;
mod move_addresses;
mod moves;
mod namespace_lifecycle;
mod network;
mod observe;
mod probing;
mod quotas;
mod recovery;
mod sessions;
mod siblings;
mod tick;
mod units;
mod update;

use gateway::*;
use mock::*;
use network::*;
use probing::*;
use recovery::*;
use sessions::*;
use units::*;
use update::*;

/// A machine as the manager would have made it, in the second namespace subnet.
pub(in crate::machine) fn record() -> Record {
    let now = Utc.with_ymd_and_hms(2026, 10, 18, 22, 0, 0).unwrap();
    Record {
        id: "m_abc123".into(),
        namespace: "t1".into(),
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
            cpu_millis: None,
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
        error_reason: String::new(),
        start: false,
        from_source: false,
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
        boot_identity: None,
        boot_incarnation: None,
        rest: Default::default(),
        snapshots: Vec::new(),
        restoring: None,
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

impl Manager {
    /// A create that answers once the machine is made, and started unless `start` is
    /// false: what most tests start from.
    pub(super) async fn create_made(
        &self,
        req: api::CreateMachineRequest,
    ) -> Result<api::Machine, MError> {
        let scope = self.inner.zfs.io_scope()?;
        let (e, how, child_scope) = scope
            .run(async {
                let (e, how) = self.record(req, None).await?;
                let child_scope = self.inner.zfs.io_scope()?;
                Ok::<_, MError>((e, how, child_scope))
            })
            .await?;
        self.make_admitted(child_scope, &e, how).await?;
        Ok(self.view(&e))
    }
}

pub(in crate::machine) async fn harness(range: &str, memory_mb: u32) -> Harness {
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
pub(super) async fn harness_with(
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
    // The pool's key, in a file as on a host alone: the one the fake's `load-key` takes.
    let key = "0123456789abcdef".repeat(4);
    std::fs::write(dir.path().join("pool.key"), &key).unwrap();
    std::fs::write(fake.dev().join("key"), &key).unwrap();
    fake.answer("encryptionroot", "byard\n");
    // A pool with room: 1 TiB free, what a volume's create or growth is admitted on.
    fake.answer("used,available", &format!("0\n{}\n", 1u64 << 40));
    let mut cfg = Config {
        data_dir: dir.path().join("data"),
        ..Default::default()
    };
    cfg.storage.key = format!("file:{}", dir.path().join("pool.key").display());
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
            verified_templates: Mutex::new(std::collections::HashSet::new()),
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
            address_holds: Mutex::new(std::collections::HashSet::new()),
            namespaces: Mutex::new(HashMap::new()),
            endpoints: Mutex::new(HashMap::new()),
            endpoint_events,
            policies: Mutex::new(HashMap::new()),
            namespace_create: tokio::sync::Mutex::new(()),
            namespace_lifecycle: tokio::sync::RwLock::new(()),
            backups,
            boot_gate: tokio::sync::Semaphore::new(2),
            probe_gate: tokio::sync::Semaphore::new(probes::PROBES_AT_ONCE),
            began: tokio::time::Instant::now(),
            probe_spread: Box::new(golden_spread()),
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

/// A fixed, evenly spread sequence in [0, 1) (the golden ratio's multiples), where production
/// draws at random: sixteen random points can all land in half a period, so a test that
/// checks how far apart first runs fall needs points that do not depend on chance.
fn golden_spread() -> impl Fn() -> f64 + Send + Sync {
    let n = std::sync::atomic::AtomicU32::new(0);
    move || {
        let i = n.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        (f64::from(i) * 0.618_033_988_749_894_9).fract()
    }
}

/// An image reference that pins a digest: `ensure` asks no registry for it.
pub(super) const IMAGE: &str =
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

    /// A namespace with its network known, as `load` would have it; the first takes subnet
    /// index 1, where `record()` puts its machine. Nothing is plumbed: the bridge and the
    /// gateway's DNS listener need the host.
    pub(in crate::machine) fn namespace(&self, id: &str) -> Namespace {
        let mut namespaces = self.m.inner.namespaces.lock().unwrap();
        let idx = namespaces.len() as u32 + 1;
        let t = Namespace::new(
            NamespaceRec {
                id: id.into(),
                subnet_index: idx,
                created_at: Utc::now(),
                quota: api::Quota::default(),
            },
            self.m.inner.range.subnet(idx).unwrap(),
        );
        namespaces.insert(id.into(), t.clone());
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

    /// A create request in namespace `t1` from the seeded image, started unless told
    /// otherwise; no volume, since a volume is formatted with the host's `mkfs.ext4`.
    pub(super) fn request(&self, name: &str) -> api::CreateMachineRequest {
        api::CreateMachineRequest {
            namespace: "t1".into(),
            name: name.into(),
            image: IMAGE.into(),
            size: api::Size {
                vcpus: 1,
                memory_mb: 256,
                cpu_millis: None,
            },
            sleep: "30m".into(),
            ..Default::default()
        }
    }

    /// Namespace `t1` and the image in place, so a `request` can be created.
    pub(super) async fn ready(&self) {
        self.namespace("t1");
        self.m
            .inner
            .images
            .seed(IMAGE, ImageConfig::default())
            .await
            .unwrap();
        self.pool.calls();
    }

    /// Whether the log has an event of this reason about the machine.
    pub(super) async fn said(&self, id: &str, reason: &str) -> bool {
        let page = self.m.events_page(0, events::Filter::default(), 5000).await;
        page.unwrap()
            .events
            .iter()
            .any(|e| e.machine_id == id && e.reason == reason)
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
    /// The root disk's device the machine last booted on.
    pub(super) fn booted_root(&self, id: &str) -> PathBuf {
        self.host.roots.lock().unwrap()[id].0.clone()
    }

    /// The volume's device the machine last booted on.
    pub(super) fn booted_data(&self, id: &str) -> PathBuf {
        self.host.roots.lock().unwrap()[id].1.clone().unwrap()
    }

    pub(super) fn host_calls(&self) -> Vec<String> {
        self.host.calls()
    }

    /// The machine's record as the store has it.
    pub(super) fn stored(&self, id: &str) -> Option<Record> {
        self.m.inner.store.get("machines", id).unwrap()
    }
}

/// Whether something listens on the host's port.
pub(super) async fn listening(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

// --- usage (ADR 0017) ---

pub(super) fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

/// A machine of `record()` in `state` with its volume at `gb` GB, its disks made.
pub(super) async fn with_volume(h: &Harness, id: &str, state: &str, gb: u32) -> Arc<Entry> {
    let e = h.add(id, state, 256);
    e.rec.lock().unwrap().volume.as_mut().unwrap().size_gb = gb;
    let r = e.snapshot();
    let z = &h.pool.zfs;
    z.create(&r.root_dataset(), 1 << 20).await.unwrap();
    z.create(&r.data_dataset(), (gb as u64) << 30)
        .await
        .unwrap();
    h.pool.calls();
    e
}

pub(super) fn grow_to(size_gb: u32) -> api::UpdateMachineRequest {
    spec(|s| s.volume = Some(api::VolumeSize { size_gb }))
}
