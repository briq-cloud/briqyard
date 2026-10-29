//! The manager's tests: the shared harness (a manager over a temp directory, the fake `zfs`
//! and a mock host) here, the tests by area in the modules beside it.

use super::*;
use chrono::TimeZone;

mod event_log;
mod gateway;
mod lifecycle;
mod metering;
mod moves;
mod network;
mod observe;
mod probing;
mod quotas;
mod recovery;
mod sessions;
mod tick;
mod units;
mod update;

use gateway::*;
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
        rest: Default::default(),
        snapshots: Vec::new(),
        restoring: None,
    }
}

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
    refuse_count: AtomicBool,
    /// What an exec of a command (its argv joined by spaces) exits with; 0 when absent.
    exec_codes: Mutex<HashMap<String, i32>>,
    /// How long an exec takes, and how many run at once now and at most.
    exec_takes: Mutex<Duration>,
    execs_now: Arc<std::sync::atomic::AtomicUsize>,
    execs_most: std::sync::atomic::AtomicUsize,
    /// The ports of an address a TCP probe finds closed; every other one accepts.
    closed: Mutex<std::collections::HashSet<(Ipv4Addr, u16)>>,
    /// When each TCP probe and exec began, on the runtime's clock.
    probed: Mutex<Vec<(String, tokio::time::Instant)>>,
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
    /// The devices each machine last booted on: its root disk, its volume.
    roots: Mutex<HashMap<String, (PathBuf, Option<PathBuf>)>>,
    /// A live change of disk limits fails, as a Firecracker that refuses the PATCH.
    refuse_disk_rate: AtomicBool,
}

impl Mock {
    pub(in crate::machine) fn new() -> Arc<Self> {
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
            disks: Mutex::new(HashMap::new()),
            roots: Mutex::new(HashMap::new()),
            refuse_disk_rate: AtomicBool::new(false),
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
    fn exit_of(p: &Proc) -> tokio::sync::watch::Receiver<Option<guest::ExitReport>> {
        p.exit.as_ref().expect("a live process").subscribe()
    }

    /// The live process behind a vsock path.
    fn proc_at(&self, vsock: &Path) -> Result<(u32, Boots, tokio::sync::watch::Receiver<bool>)> {
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
        match boots {
            Boots::Exits(code, error) => self.report(pid, code, false, false, error),
            Boots::Runs(code) => self.exit(pid, code, false),
            _ => {}
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
    async fn session(&self, vsock: &Path, req: guest::Request) -> Result<Box<dyn guestc::Conn>> {
        use std::sync::atomic::Ordering::SeqCst;
        use tokio::io::AsyncWriteExt;
        let (pid, _, _) = self.proc_at(vsock)?;
        let cmd = req.cmd.join(" ");
        let code = self.exec_codes.lock().unwrap().get(&cmd).copied();
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        if !req.interactive {
            self.record(format!("exec {pid} {cmd}"));
            let at = tokio::time::Instant::now();
            self.probed.lock().unwrap().push((cmd.clone(), at));
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
        if self.refuse_count.load(Relaxed) {
            return Err(anyhow!("nft: refused"));
        }
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

impl Manager {
    /// A create that answers once the machine is made, and started unless `start` is
    /// false: what most tests start from.
    pub(super) async fn create_made(
        &self,
        req: api::CreateMachineRequest,
    ) -> Result<api::Machine, MError> {
        let (e, how) = self.record(req, None).await?;
        self.make(&e, how).await?;
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
            namespaces: Mutex::new(HashMap::new()),
            endpoints: Mutex::new(HashMap::new()),
            endpoint_events,
            policies: Mutex::new(HashMap::new()),
            namespace_create: tokio::sync::Mutex::new(()),
            backups,
            boot_gate: tokio::sync::Semaphore::new(2),
            probe_gate: tokio::sync::Semaphore::new(probes::PROBES_AT_ONCE),
            began: tokio::time::Instant::now(),
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
