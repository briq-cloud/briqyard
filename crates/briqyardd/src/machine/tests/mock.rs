//! The mock host: a stand-in VMM, guest and network, with its processes on record.

use super::*;
mod clone_recovery;
mod guest_protocol;
mod warm;

/// How the next boots go: what the guest does once its process is up.
#[derive(Clone, Debug)]
pub(super) enum Boots {
    /// The init answers ping after the delay.
    Ready(Duration),
    /// The init never answers.
    Silent,
    /// The init fails before the main process starts (a missing program), with its report
    /// and its reason ("" as from an init older than the field).
    Exits(i32, &'static str),
    /// The main process starts and exits at once, the machine gone before the init answers.
    Runs(i32),
    /// The VMM panics: a bug in a transition.
    Panics,
}

/// A process the mock host runs: a pid, the console the manager reads, how its guest
/// answers, and the `exited` watch the manager waits on.
pub(super) struct Proc {
    pub(super) pid: u32,
    pub(super) id: String,
    pub(super) vsock: PathBuf,
    pub(super) console: PathBuf,
    pub(super) boots: Boots,
    pub(super) boot_identity: Option<fc::BootIdentity>,
    pub(super) exited: tokio::sync::watch::Sender<bool>,
    /// The init's report, sent by `exit`; dropped when the process is `gone`, so the
    /// manager's wait on it ends.
    pub(super) exit: Option<tokio::sync::watch::Sender<Option<guest::ExitReport>>>,
}

type Attachment = (String, String, Option<nft::Policy>);

/// The host behind the manager, running nothing: a boot makes a `Proc` under a fresh
/// pid, the guest answers as `boots` says, TAPs are a set of names, and every call is
/// recorded, one line each, the way the fake `zfs` records its own. Cgroups and the
/// internet counters are values a test sets.
pub(super) struct Mock {
    pub(super) boots: Mutex<Boots>,
    pub(super) host_boot_id: Mutex<Option<String>>,
    pub(super) refuse_clone_exit: AtomicBool,
    /// How long a guest takes to stop once asked.
    pub(super) stops: Mutex<Duration>,
    pub(super) next_pid: std::sync::atomic::AtomicU32,
    pub(super) procs: Mutex<Vec<Proc>>,
    pub(super) taps: Mutex<std::collections::BTreeSet<String>>,
    pub(super) calls: Mutex<Vec<String>>,
    /// Policy calls fail, as an `nft` that refuses its input.
    pub(super) refuse_policies: AtomicBool,
    pub(super) refuse_clear: AtomicBool,
    pub(super) refuse_clear_ip: Mutex<Option<String>>,
    pub(super) refuse_count_ip: Mutex<Option<String>>,
    pub(super) pause_network: Mutex<Option<(&'static str, String)>>,
    pub(super) network_started: tokio::sync::Notify,
    pub(super) network_release: tokio::sync::Notify,
    pub(super) cleared_ips: Mutex<Vec<String>>,
    pub(super) attachments: Mutex<HashMap<String, Attachment>>,
    /// No guest port accepts: `wait_port` answers only at its deadline.
    pub(super) silent_ports: AtomicBool,
    /// Each machine's cgroup; none without an entry.
    pub(super) cgroups: Mutex<HashMap<String, fc::CgroupUse>>,
    /// The counted addresses and their counters.
    pub(super) counted: Mutex<BTreeMap<String, nft::Counters>>,
    /// `uncount` fails, as an `nft` that refuses its input.
    pub(super) refuse_uncount: AtomicBool,
    pub(super) refuse_count: AtomicBool,
    /// What an exec of a command (its argv joined by spaces) exits with; 0 when absent.
    pub(super) exec_codes: Mutex<HashMap<String, i32>>,
    /// How long an exec takes, and how many run at once now and at most.
    pub(super) exec_takes: Mutex<Duration>,
    pub(super) execs_now: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) execs_most: std::sync::atomic::AtomicUsize,
    /// The ports of an address a TCP probe finds closed; every other one accepts.
    pub(super) closed: Mutex<std::collections::HashSet<(Ipv4Addr, u16)>>,
    /// When each TCP probe and exec began, on the runtime's clock.
    pub(super) probed: Mutex<Vec<(String, tokio::time::Instant)>>,
    /// What an HTTP probe of an address and port answers; 200 when absent.
    pub(super) http_codes: Mutex<HashMap<(Ipv4Addr, u16), u16>>,
    /// The size each machine last booted with, as Firecracker is given it.
    pub(super) booted: Mutex<HashMap<String, api::Size>>,
    /// What the VMM says it is (ADR 0027): another value is an upgraded Firecracker.
    pub(super) vmm_version: Mutex<String>,
    /// The version the guests' inits answer with.
    pub(super) init_version: Mutex<String>,
    pub(super) file_stream_v1: AtomicBool,
    pub(super) paused: Mutex<std::collections::HashSet<u32>>,
    clone_status: Mutex<HashMap<PathBuf, guest::CloneStatus>>,
    pub(in crate::machine) destination_requests: Mutex<HashMap<PathBuf, guest::DestinationBind>>,
    pub(in crate::machine) destination_bad_ack: AtomicBool,
    pub(in crate::machine) destination_refuse: AtomicBool,
    pub(super) init_digests: Mutex<HashMap<PathBuf, String>>,
    /// The limits each machine's disks have now: given at boot, changed live, and
    /// whether the volume was given them too.
    pub(super) disks: Mutex<HashMap<String, (fc::DiskRate, bool)>>,
    /// The devices each machine last booted on: its root disk, its volume.
    pub(super) roots: Mutex<HashMap<String, (PathBuf, Option<PathBuf>)>>,
    /// A live change of disk limits fails, as a Firecracker that refuses the PATCH.
    pub(super) refuse_disk_rate: AtomicBool,
    pub(super) refuse_balloon_stats: AtomicBool,
    pub(super) pause_bridge_delete: AtomicBool,
    pub(super) bridge_delete_started: tokio::sync::Notify,
    pub(super) bridge_delete_release: tokio::sync::Notify,
}

impl Mock {
    async fn wait_network(&self, operation: &str, ip: &str) {
        let paused = self
            .pause_network
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(op, address)| *op == operation && (address == "*" || address == ip));
        if paused {
            self.network_started.notify_one();
            self.network_release.notified().await;
        }
    }

    pub(in crate::machine) fn new() -> Arc<Self> {
        Arc::new(Self {
            boots: Mutex::new(Boots::Ready(Duration::ZERO)),
            host_boot_id: Mutex::new(Some("11111111-1111-4111-8111-111111111111".into())),
            refuse_clone_exit: AtomicBool::new(false),
            stops: Mutex::new(Duration::ZERO),
            next_pid: std::sync::atomic::AtomicU32::new(1000),
            procs: Mutex::new(Vec::new()),
            taps: Mutex::new(Default::default()),
            calls: Mutex::new(Vec::new()),
            refuse_policies: AtomicBool::new(false),
            refuse_clear: AtomicBool::new(false),
            refuse_clear_ip: Mutex::new(None),
            refuse_count_ip: Mutex::new(None),
            pause_network: Mutex::new(None),
            network_started: tokio::sync::Notify::new(),
            network_release: tokio::sync::Notify::new(),
            cleared_ips: Mutex::new(Vec::new()),
            attachments: Mutex::new(HashMap::new()),
            silent_ports: AtomicBool::new(false),
            cgroups: Mutex::new(HashMap::new()),
            counted: Mutex::new(BTreeMap::new()),
            refuse_uncount: AtomicBool::new(false),
            refuse_count: AtomicBool::new(false),
            exec_codes: Mutex::new(HashMap::new()),
            exec_takes: Mutex::new(Duration::ZERO),
            execs_now: Default::default(),
            execs_most: Default::default(),
            closed: Mutex::new(Default::default()),
            probed: Mutex::new(Vec::new()),
            http_codes: Mutex::new(HashMap::new()),
            booted: Mutex::new(HashMap::new()),
            vmm_version: Mutex::new("v1.17.0/test".into()),
            init_version: Mutex::new("0.1.0+init".into()),
            file_stream_v1: AtomicBool::new(false),
            paused: Mutex::new(std::collections::HashSet::new()),
            clone_status: Mutex::new(HashMap::new()),
            destination_requests: Mutex::new(HashMap::new()),
            destination_bad_ack: AtomicBool::new(false),
            destination_refuse: AtomicBool::new(false),
            init_digests: Mutex::new(HashMap::new()),
            disks: Mutex::new(HashMap::new()),
            roots: Mutex::new(HashMap::new()),
            refuse_disk_rate: AtomicBool::new(false),
            refuse_balloon_stats: AtomicBool::new(false),
            pause_bridge_delete: AtomicBool::new(false),
            bridge_delete_started: tokio::sync::Notify::new(),
            bridge_delete_release: tokio::sync::Notify::new(),
        })
    }

    /// An exec of `cmd` exits with `code` from now on.
    pub(in crate::machine) fn answers(&self, cmd: &str, code: i32) {
        self.exec_codes.lock().unwrap().insert(cmd.into(), code);
    }

    /// An HTTP probe of `ip:port` answers `code` from now on.
    pub(in crate::machine) fn http(&self, ip: &str, port: u16, code: u16) {
        let ip = ip.parse().unwrap();
        self.http_codes.lock().unwrap().insert((ip, port), code);
    }

    pub(super) fn cpu(&self, id: &str, usec: u64) {
        self.cgroups
            .lock()
            .unwrap()
            .entry(id.into())
            .or_default()
            .cpu_usec = usec;
    }

    pub(in crate::machine) fn memory(&self, id: &str, bytes: u64) {
        self.cgroups
            .lock()
            .unwrap()
            .entry(id.into())
            .or_default()
            .memory_bytes = bytes;
    }

    /// Traffic of a counted address, as the forward chain would count it.
    pub(super) fn internet(&self, ip: &str, inb: u64, out: u64) {
        let mut c = self.counted.lock().unwrap();
        let n = c.get_mut(ip).expect("a counted address");
        n.internet_in += inb;
        n.internet_out += out;
    }

    /// Packets the limits dropped for a counted address, as the forward chain would count
    /// them.
    pub(in crate::machine) fn dropped(&self, ip: &str, port: u64, rate: u64, bandwidth: u64) {
        let mut c = self.counted.lock().unwrap();
        let d = &mut c.get_mut(ip).expect("a counted address").dropped;
        d.blocked_port += port;
        d.rate += rate;
        d.bandwidth += bandwidth;
    }

    pub(in crate::machine) fn boots(&self, b: Boots) {
        *self.boots.lock().unwrap() = b;
    }

    pub(in crate::machine) fn stops_take(&self, d: Duration) {
        *self.stops.lock().unwrap() = d;
    }

    pub(in crate::machine) fn record(&self, line: String) {
        self.calls.lock().unwrap().push(line);
    }

    /// The calls so far, then forgets them.
    pub(in crate::machine) fn calls(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    /// The pids whose process has not exited.
    pub(super) fn alive(&self) -> Vec<u32> {
        self.procs
            .lock()
            .unwrap()
            .iter()
            .filter(|p| !*p.exited.borrow())
            .map(|p| p.pid)
            .collect()
    }

    /// Makes a process as a previous daemon would have left it: up, nobody's child.
    pub(super) fn left_running(&self, id: &str, dir: &Path) -> u32 {
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
            boot_identity: None,
            exited: tokio::sync::watch::channel(false).0,
            exit: Some(tokio::sync::watch::channel(None).0),
        });
        pid
    }

    /// A line on the process's console, stamped as the daemon stamps them.
    pub(super) fn say(&self, pid: u32, line: &str) {
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
    pub(in crate::machine) fn exit(&self, pid: u32, code: i32, requested: bool) {
        self.report(pid, code, requested, true, "");
    }

    /// The init's report and the end of the process; `started` false for a main process
    /// the init could not start, and `error` why.
    pub(in crate::machine) fn report(
        &self,
        pid: u32,
        code: i32,
        requested: bool,
        started: bool,
        error: &str,
    ) {
        if !error.is_empty() {
            self.say(pid, &format!("[briqyard] {error}"));
        }
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
                started,
                version: self.init_version.lock().unwrap().clone(),
                error: error.to_string(),
            }));
        }
        drop(procs);
        self.gone(pid);
    }

    /// The process is gone: no report can come after this.
    pub(in crate::machine) fn gone(&self, pid: u32) {
        let mut procs = self.procs.lock().unwrap();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.exit = None;
            let _ = p.exited.send(true);
        }
    }

    /// A live process's report channel.
    pub(super) fn exit_of(p: &Proc) -> tokio::sync::watch::Receiver<Option<guest::ExitReport>> {
        p.exit.as_ref().expect("a live process").subscribe()
    }

    /// The live process behind a vsock path.
    pub(super) fn proc_at(
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
    async fn warm_test_barrier(&self, phase: &str, id: &str) {
        self.wait_network(phase, id).await;
    }

    fn paused_slots_supported(&self) -> bool {
        true
    }
    async fn boot(&self, b: &fc::Boot) -> Result<fc::Vm> {
        let boots = self.boots.lock().unwrap().clone();
        // The manager must durably publish the selected identity before any VMM launches.
        if !b.resume {
            let path = b
                .dir
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("state/machines")
                .join(format!("{}.json", b.id));
            let persisted: Record = serde_json::from_slice(&std::fs::read(path)?)?;
            assert_eq!(persisted.boot_identity, b.boot_identity);
            assert!(!persisted.suspended);
        }
        self.record(format!("boot {} tap={} resume={}", b.id, b.tap, b.resume));
        let size = api::Size {
            vcpus: b.vcpus,
            memory_mb: b.memory_mb,
            cpu_millis: None,
        };
        self.booted.lock().unwrap().insert(b.id.clone(), size);
        self.disks
            .lock()
            .unwrap()
            .insert(b.id.clone(), (b.disk, b.data.is_some()));
        self.roots
            .lock()
            .unwrap()
            .insert(b.id.clone(), (b.root.clone(), b.data.clone()));
        if let Boots::Panics = boots {
            panic!("the VMM panicked");
        }
        tokio::fs::create_dir_all(&b.dir).await?;
        let (api, vsock, console, _) = fc::paths(&b.dir);
        let snapshot = b.dir.join("snap.mem");
        if b.resume && !snapshot.exists() {
            return Err(fc::ResumeFailed("memory file missing".into()).into());
        }
        let resumed = b.resume || b.memory_clone.is_some();
        let mut tar = tar::Archive::new(std::fs::File::open(&b.config_drive)?);
        for entry in tar.entries()? {
            let mut entry = entry?;
            if entry.path()?.as_ref() == Path::new(guest::CONFIG_NAME) {
                let cfg: guest::Config = serde_json::from_reader(&mut entry)?;
                if cfg.template_profile.is_some() {
                    self.clone_status.lock().unwrap().insert(
                        vsock.clone(),
                        guest::CloneStatus {
                            protocol: 1,
                            profile: cfg.template_profile.clone().unwrap(),
                            ram_marker: "0123456789abcdef0123456789abcdef".into(),
                            stage: "builder".into(),
                            identity: None,
                        },
                    );
                    use sha2::{Digest, Sha256};
                    self.init_digests
                        .lock()
                        .unwrap()
                        .insert(vsock.clone(), hex::encode(Sha256::digest(b"init")));
                }
            }
        }
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
            boot_identity: b.boot_identity.clone(),
            exited,
            exit: Some(exit_tx),
        });
        match boots {
            Boots::Exits(code, error) => self.report(pid, code, false, false, error),
            Boots::Runs(code) => self.exit(pid, code, false),
            _ => {}
        }
        let chroot = b.jail.as_ref().map(|j| fc::jail_root(&j.base, &b.id));
        if let Some(root) = &chroot {
            std::fs::create_dir_all(root)?;
        }
        Ok(fc::Vm {
            pid,
            api,
            vsock,
            dir: b.dir.clone(),
            chroot,
            resumed,
            boot_identity: b.boot_identity.clone(),
            incarnation: Some(mock_incarnation(pid)),
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
            boot_identity: p
                .boot_identity
                .as_ref()
                .map(|i| fc::BootIdentity::ambiguous(&i.device_profile)),
            incarnation: Some(mock_incarnation(pid)),
            exited: p.exited.subscribe(),
            exit: Self::exit_of(p),
        })
    }

    fn host_boot_id(&self) -> Option<String> {
        self.host_boot_id.lock().unwrap().clone()
    }
    async fn settle_clone_process(&self, id: &str, saved: &fc::Incarnation) -> Result<bool> {
        self.settle_clone(id, saved)
    }

    async fn pause(&self, vm: &fc::Vm) -> Result<()> {
        self.park_slot(vm.pid)
    }
    async fn resume_paused(&self, vm: &fc::Vm) -> Result<()> {
        self.resume_slot(vm.pid)
    }
    async fn adopt_paused(
        &self,
        id: &str,
        dir: &Path,
        jail: Option<&fc::Jail>,
        pid: u32,
        disk_io: Arc<fc::DiskIo>,
    ) -> Option<fc::Vm> {
        self.adopt_pool_slot(id, dir, jail, pid, disk_io).await
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
        self.write_snapshot(vm, durable)
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

    fn cpu_fingerprint(&self) -> Option<String> {
        Some("test_cpu".into())
    }

    fn boot_identity(&self, reporting: bool) -> Option<fc::BootIdentity> {
        Some(
            fc::BootIdentity {
                schema: 1,
                device_profile: fc::LEGACY_PROFILE.into(),
                kernel_sha256: "kernel-digest".into(),
                vmm_sha256: self.version(),
                host_kernel: "test".into(),
                transport: "mmio".into(),
            }
            .with_reporting(reporting),
        )
    }

    async fn balloon_statistics(&self, _vm: &fc::Vm) -> Result<Option<fc::BalloonStatistics>> {
        self.record("balloon-statistics".into());
        if self.refuse_balloon_stats.load(Relaxed) {
            bail!("statistics unavailable");
        }
        Ok(Some(fc::BalloonStatistics {
            target_pages: 0,
            actual_pages: 3,
            free_memory: Some(123),
            available_memory: None,
            disk_caches: Some(456),
        }))
    }
}

impl Mock {
    pub(super) async fn ensure_tap(
        &self,
        machine_id: &str,
        bridge: &str,
        ip: &str,
    ) -> Result<String> {
        let name = netw::tap_name(machine_id);
        self.record(format!("ensure_tap {name} {bridge} {ip}"));
        self.taps.lock().unwrap().insert(name.clone());
        Ok(name)
    }

    pub(super) async fn delete_tap(&self, machine_id: &str, ip: &str) -> Result<()> {
        let name = netw::tap_name(machine_id);
        self.record(format!("delete_tap {name} {ip}"));
        self.taps.lock().unwrap().remove(&name);
        Ok(())
    }
}

#[async_trait::async_trait]
impl host::Net for Mock {
    async fn quarantine(&self, machine: &str) -> Result<String> {
        self.record(format!("quarantine {machine}"));
        Ok(netw::tap_name(machine))
    }
    async fn activate_quarantined(
        &self,
        machine: &str,
        bridge: &str,
        ip: &str,
        _policy: Option<&nft::Policy>,
    ) -> Result<()> {
        self.record(format!("activate_quarantined {machine} {bridge} {ip}"));
        Ok(())
    }
    async fn ensure_bridge(&self, s: &Subnet) -> Result<String> {
        let name = netw::bridge_name(s.index);
        self.record(format!("ensure_bridge {name} {}", s.cidr()));
        Ok(name)
    }

    async fn delete_bridge(&self, index: u32) -> Result<()> {
        if self
            .pause_bridge_delete
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.bridge_delete_started.notify_one();
            self.bridge_delete_release.notified().await;
        }
        self.record(format!("delete_bridge {}", netw::bridge_name(index)));
        Ok(())
    }

    async fn attach(
        &self,
        machine: &str,
        bridge: &str,
        ip: &str,
        old: Option<&nft::Policy>,
        new: Option<&nft::Policy>,
        new_owner: bool,
    ) -> Result<String> {
        let tap = self.ensure_tap(machine, bridge, ip).await?;
        self.attachments.lock().unwrap().remove(machine);
        if let Some(old) = old {
            self.unset_policy(old).await?;
        }
        if new_owner {
            self.clear_connections(ip).await?;
        }
        if let Some(new) = new {
            self.set_policy(new).await?;
        }
        self.attachments
            .lock()
            .unwrap()
            .insert(machine.into(), (bridge.into(), ip.into(), new.cloned()));
        Ok(tap)
    }
    async fn detach(
        &self,
        machine: &str,
        _bridge: &str,
        ip: &str,
        policy: Option<&nft::Policy>,
    ) -> Result<()> {
        self.delete_tap(machine, ip).await?;
        if let Some(policy) = policy {
            self.unset_policy(policy).await?;
        }
        self.attachments.lock().unwrap().remove(machine);
        Ok(())
    }
    async fn clear_connections(&self, ip: &str) -> Result<()> {
        self.wait_network("clear", ip).await;
        if self.refuse_clear.load(Relaxed)
            || self.refuse_clear_ip.lock().unwrap().as_deref() == Some(ip)
        {
            anyhow::bail!("conntrack refused");
        }
        self.cleared_ips.lock().unwrap().push(ip.into());
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
        self.wait_network("count", ip).await;
        if self.refuse_count.load(Relaxed)
            || self.refuse_count_ip.lock().unwrap().as_deref() == Some(ip)
        {
            return Err(anyhow!("nft: refused"));
        }
        self.counted.lock().unwrap().entry(ip.into()).or_default();
        Ok(())
    }

    async fn uncount(&self, ip: &str) -> Result<()> {
        self.wait_network("uncount", ip).await;
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
        let at = tokio::time::Instant::now();
        self.probed.lock().unwrap().push((format!("{ip}"), at));
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
    pub(super) fn policy_call(&self, line: String) -> Result<()> {
        self.record(line);
        if self.refuse_policies.load(Relaxed) {
            return Err(anyhow!("nft: refused"));
        }
        Ok(())
    }
}

/// A policy as the mock records it.
pub(super) fn policy_line(p: &nft::Policy) -> String {
    match p {
        nft::Policy::Via {
            ip,
            to,
            host,
            siblings,
            ..
        } => format!(
            "via {ip} to {to} host {host}{}",
            if *siblings { " siblings" } else { "" }
        ),
        nft::Policy::None { ip } => format!("none {ip}"),
        nft::Policy::Open { ip, limits: l } => format!(
            "open {ip} ports {:?} conn {} mbit {}",
            l.blocked_ports, l.new_connections_per_minute, l.bandwidth_mbit
        ),
    }
}

fn mock_incarnation(pid: u32) -> fc::Incarnation {
    fc::Incarnation {
        pid,
        start_ticks: u64::from(pid),
        host_boot_id: "11111111-1111-4111-8111-111111111111".into(),
    }
}
