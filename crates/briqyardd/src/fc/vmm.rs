//! The `Vmm` trait and Firecracker's implementation of it.

use super::*;

/// What a machine boots with: its files and devices as host paths, its network, its size.
#[derive(Clone, Debug)]
pub struct Boot {
    pub id: String,
    /// The machine's run dir: its sockets when not jailed, its console always.
    pub dir: PathBuf,
    pub jail: Option<Jail>,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub kernel: PathBuf,
    pub boot_args: String,
    pub config_drive: PathBuf,
    pub root: PathBuf,
    pub data: Option<PathBuf>,
    pub tap: String,
    pub mac: String,
    /// Resume from the snapshot next to the sockets when there is one.
    pub resume: bool,
    /// The limits on the root disk and the volume.
    pub disk: DiskRate,
    /// Where its disks' metrics add up.
    pub disk_io: Arc<DiskIo>,
}

/// A machine's VMM as the manager keeps it: the process, its sockets, and when it is gone.
#[derive(Clone)]
pub struct Vm {
    pub pid: u32,
    /// The VMM's API socket.
    pub api: PathBuf,
    /// The vsock Unix socket on the host: where the guest is reached.
    pub vsock: PathBuf,
    /// The machine's run dir.
    pub dir: PathBuf,
    /// The chroot root when jailed.
    pub chroot: Option<PathBuf>,
    /// Resumed from a snapshot rather than booted.
    pub resumed: bool,
    /// `true` once the process is gone and its console fully written.
    pub exited: watch::Receiver<bool>,
    /// What the init reported when the main process ended; `None` until then, and the
    /// channel closes with the process, so a wait on it ends either way.
    pub exit: watch::Receiver<Option<guest::ExitReport>>,
}

impl Vm {
    pub(super) fn inside(&self, name: &str) -> PathBuf {
        inside_path(self.chroot.as_deref(), &self.dir, name)
    }

    pub(super) fn outside(&self, name: &str) -> PathBuf {
        outside_path(self.chroot.as_deref(), &self.dir, name)
    }
}

/// How machines are run: Firecracker on the host, a mock in the manager's tests.
#[async_trait]
pub trait Vmm: Send + Sync {
    /// Starts a VMM for the machine and boots it, or resumes it when asked and a snapshot
    /// is there (a resume that fails boots cold). Returns once the machine runs on the
    /// VMM's side; the guest answering is the caller's wait.
    async fn boot(&self, b: &Boot) -> Result<Vm>;

    /// Takes over a VMM a previous daemon left: `Some` when `pid` runs machine `id` and its
    /// API says the machine runs. Its disks' metrics add up in `disk_io` again.
    async fn adopt(
        &self,
        id: &str,
        dir: &Path,
        jail: Option<&Jail>,
        pid: u32,
        disk_io: Arc<DiskIo>,
    ) -> Option<Vm>;

    /// Gives a running machine's disks these limits now: the root disk, and the volume when
    /// it has one.
    async fn disk_rate(&self, vm: &Vm, rate: &DiskRate, volume: bool) -> Result<()>;

    /// Pauses the machine and writes its memory and state next to its sockets, for the
    /// next boot to resume. `durable`: the files are on disk when it returns (a suspend);
    /// otherwise the caller syncs them, after resuming the machine. An error means the VMM
    /// refused and the machine runs on.
    async fn snapshot(&self, vm: &Vm, durable: bool) -> Result<()>;

    /// Lets a machine `snapshot` paused run on.
    async fn resume(&self, vm: &Vm) -> Result<()>;

    /// SIGKILL to the process and to its group.
    fn kill(&self, pid: u32);

    /// The machine id the process carries, when it is a VMM of ours.
    fn machine_of(&self, pid: u32) -> Option<String>;

    /// Every VMM on the host with the machine id it carries.
    fn processes(&self) -> Vec<(u32, String)>;

    /// What the machine's cgroup says; none without one (not jailed, or never booted).
    async fn cgroup(&self, id: &str) -> Option<CgroupUse>;

    /// What a machine booted now runs under: the VMM's version and the host kernel's release
    /// (ADR 0027). A memory snapshot resumes only under the one it was taken under.
    fn version(&self) -> String;
}

/// The Firecracker on this host.
pub struct Firecracker {
    pub binary: PathBuf,
    /// Firecracker's PCI transport.
    pub pci: bool,
    /// A console past this size is rotated while the machine runs (ADR 0021).
    pub console_max: u64,
    /// [`vmm_version`] of `binary`, read once at the daemon's start.
    pub version: String,
}

/// `<Firecracker's version>/<the host kernel's release>`, `v1.17.0/6.8.0-45-generic`: what a
/// memory snapshot is tied to. Firecracker promises no snapshot across its versions, and
/// calls one across host kernels unstable (ADR 0027).
pub fn vmm_version(binary: &Path) -> Result<String> {
    let out = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .with_context(|| format!("{} --version", binary.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    version_of(&text, &kernel)
        .ok_or_else(|| anyhow!("{} --version said {text:?}", binary.display()))
}

/// The version on `firecracker --version`'s first line (`Firecracker v1.17.0`), and the
/// kernel's release.
pub(super) fn version_of(firecracker: &str, kernel: &str) -> Option<String> {
    let v = firecracker
        .lines()
        .next()?
        .trim()
        .strip_prefix("Firecracker ")?;
    (!v.is_empty()).then(|| format!("{v}/{}", kernel.trim()))
}

#[async_trait]
impl Vmm for Firecracker {
    async fn boot(&self, b: &Boot) -> Result<Vm> {
        let mut resume = b.resume;
        let (proc, exit) = loop {
            let mut proc = Process::start(
                &self.binary,
                &b.id,
                &b.dir,
                self.pci,
                b.jail.as_ref(),
                self.console_max,
            )
            .await?;
            let exit = match listen_exit(&proc.vsock, proc.uid, proc.gid, proc.done()) {
                Ok(rx) => rx,
                Err(err) => {
                    proc.kill();
                    proc.wait().await;
                    return Err(err);
                }
            };
            let c = proc.client.clone();
            if let Err(err) = proc.metrics_to(b.disk_io.clone()).await {
                proc.kill();
                proc.wait().await;
                return Err(err.context("firecracker metrics"));
            }
            let (snap_state, snap_mem) = (proc.outside("snap.state"), proc.outside("snap.mem"));
            resume = resume && snap_state.exists() && snap_mem.exists();
            if resume {
                // Memory and state come back; the disks are where they were; the TAP has the
                // same name. Nothing boots: the guest carries on where it was paused.
                let load = async {
                    // What the snapshot's devices open again: the drives, by the names given at boot.
                    proc.expose_file(&b.config_drive, "config.tar")?;
                    proc.expose_block(&b.root, "root")?;
                    if let Some(d) = &b.data {
                        proc.expose_block(d, "data")?;
                    }
                    c.snapshot_load(
                        &proc.inside("snap.state"),
                        &proc.inside("snap.mem"),
                        "eth0",
                        &b.tap,
                    )
                    .await?;
                    // The snapshot holds the limits of the run it paused: today's go on.
                    c.drive_rate("rootfs", &b.disk).await?;
                    if b.data.is_some() {
                        c.drive_rate("data", &b.disk).await?;
                    }
                    Ok::<(), anyhow::Error>(())
                };
                match load.await {
                    Ok(()) => break (proc, exit),
                    Err(err) => {
                        tracing::warn!(machine = b.id, err = %err, "resume from snapshot failed, booting cold");
                        proc.kill();
                        proc.wait().await;
                        resume = false;
                        continue;
                    }
                }
            }
            let configure = async {
                let kernel = proc.expose_file(&b.kernel, "vmlinux")?;
                let config = proc.expose_file(&b.config_drive, "config.tar")?;
                let root = proc.expose_block(&b.root, "root")?;
                c.machine_config(b.vcpus, b.memory_mb).await?;
                c.boot_source(&kernel, &b.boot_args).await?;
                c.drive("rootfs", &root, true, false, "Writeback", Some(&b.disk))
                    .await?;
                c.drive("config", &config, false, true, "Unsafe", None)
                    .await?;
                if let Some(d) = &b.data {
                    let data = proc.expose_block(d, "data")?;
                    c.drive("data", &data, false, false, "Writeback", Some(&b.disk))
                        .await?;
                }
                c.network_interface("eth0", &b.tap, &b.mac).await?;
                c.vsock(3, &proc.inside("vsock.sock")).await?;
                c.start().await?;
                Ok::<(), anyhow::Error>(())
            };
            if let Err(err) = configure.await {
                proc.kill();
                proc.wait().await;
                return Err(anyhow!("configure firecracker: {err}"));
            }
            break (proc, exit);
        };
        // A snapshot is for one resume: stale files would be loaded into a different boot.
        let _ = tokio::fs::remove_file(proc.outside("snap.state")).await;
        let _ = tokio::fs::remove_file(proc.outside("snap.mem")).await;
        let (exited_tx, exited) = watch::channel(false);
        let vm = Vm {
            pid: proc.pid(),
            api: proc.api.clone(),
            vsock: proc.vsock.clone(),
            dir: proc.dir.clone(),
            chroot: proc.chroot.clone(),
            resumed: resume,
            exited,
            exit,
        };
        tokio::spawn(async move {
            let mut proc = proc;
            proc.wait().await;
            let _ = exited_tx.send(true);
        });
        Ok(vm)
    }

    /// The process must be alive, be Firecracker, and answer on the machine's API socket as
    /// running. It is nobody's child, so its pid is polled for `exited`.
    async fn adopt(
        &self,
        id: &str,
        dir: &Path,
        jail: Option<&Jail>,
        pid: u32,
        disk_io: Arc<DiskIo>,
    ) -> Option<Vm> {
        if self.machine_of(pid).as_deref() != Some(id) {
            return None;
        }
        let (api, vsock, _, _) = paths_for(dir, jail, id);
        let client = Client::new(&api);
        let running = match tokio::time::timeout(Duration::from_secs(3), client.info()).await {
            Ok(Ok(info)) => api_running(&info),
            _ => false,
        };
        if !running {
            return None;
        }
        let (exited_tx, exited) = watch::channel(false);
        // The previous daemon's listener died with it; the guest connects at its exit, so
        // a new one on the same path takes the report.
        let (uid, gid) = jail.map(|j| (j.uid, j.gid)).unwrap_or((0, 0));
        let exit = listen_exit(&vsock, uid, gid, exited.clone()).ok()?;
        // The pipe Firecracker was told at its boot; without one, no disk metrics this run.
        let chroot = jail.map(|j| jail_root(&j.base, id));
        let pipe = outside_path(chroot.as_deref(), dir, METRICS_FIFO);
        if let Err(err) = read_metrics(&pipe, disk_io, exited.clone()) {
            tracing::warn!(machine = id, err = %err, "disk metrics not read");
        }
        let machine = id.to_string();
        tokio::spawn(async move {
            while machine_of(pid).as_deref() == Some(machine.as_str()) {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let _ = exited_tx.send(true);
        });
        Some(Vm {
            pid,
            api,
            vsock,
            dir: dir.to_path_buf(),
            chroot,
            resumed: false,
            exited,
            exit,
        })
    }

    async fn disk_rate(&self, vm: &Vm, rate: &DiskRate, volume: bool) -> Result<()> {
        let c = Client::new(&vm.api);
        c.drive_rate("rootfs", rate).await.context("root disk")?;
        if volume {
            c.drive_rate("data", rate).await.context("volume")?;
        }
        Ok(())
    }

    async fn snapshot(&self, vm: &Vm, durable: bool) -> Result<()> {
        use crate::profile::stage;
        use std::time::Instant;
        let c = Client::new(&vm.api);
        let machine = vm.dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let operation = if durable {
            "snapshot_durable"
        } else {
            "snapshot_unsynced"
        };
        let started = Instant::now();
        let paused = c.pause().await;
        stage(operation, "pause", machine, vm.pid, started, paused.is_ok());
        paused.context("pause")?;
        let started = Instant::now();
        let snapshot = c
            .snapshot_create(&vm.inside("snap.state"), &vm.inside("snap.mem"), durable)
            .await;
        // Firecracker's request includes disk flushes and, when durable, file fsyncs.
        // This boundary cannot separate writing from syncing inside Firecracker.
        stage(
            operation,
            "create",
            machine,
            vm.pid,
            started,
            snapshot.is_ok(),
        );
        if let Err(err) = snapshot {
            let started = Instant::now();
            let resumed = c.resume().await;
            stage(
                operation,
                "resume_after_error",
                machine,
                vm.pid,
                started,
                resumed.is_ok(),
            );
            let _ = tokio::fs::remove_file(vm.outside("snap.state")).await;
            let _ = tokio::fs::remove_file(vm.outside("snap.mem")).await;
            return Err(err.context("snapshot (resumed)"));
        }
        Ok(())
    }

    async fn resume(&self, vm: &Vm) -> Result<()> {
        Client::new(&vm.api).resume().await.context("resume")
    }

    fn kill(&self, pid: u32) {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }

    fn machine_of(&self, pid: u32) -> Option<String> {
        machine_of(pid)
    }

    fn version(&self) -> String {
        self.version.clone()
    }

    /// Read from `/proc`: what a sweep compares to the records.
    fn processes(&self) -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else {
                continue;
            };
            if let Some(id) = firecracker_id(&cmd) {
                out.push((pid, id));
            }
        }
        out
    }

    /// The cgroup the jailer made for the machine, while it exists.
    async fn cgroup(&self, id: &str) -> Option<CgroupUse> {
        let cg = cgroup_dir(id);
        let stat = tokio::fs::read_to_string(cg.join("cpu.stat")).await.ok()?;
        let memory = tokio::fs::read_to_string(cg.join("memory.current"))
            .await
            .unwrap_or_default();
        Some(CgroupUse {
            cpu_usec: cpu_usec(&stat)?,
            memory_bytes: memory.trim().parse().unwrap_or(0),
        })
    }
}

/// The machine id a Firecracker command line carries (`firecracker --id m-… …`), as the
/// daemon spells it; `None` for any other process.
pub(super) fn firecracker_id(cmdline: &[u8]) -> Option<String> {
    let args: Vec<&str> = cmdline
        .split(|b| *b == 0)
        .filter_map(|a| std::str::from_utf8(a).ok())
        .collect();
    if !args.first()?.ends_with("firecracker") {
        return None;
    }
    let i = args.iter().position(|a| *a == "--id")?;
    Some(args.get(i + 1)?.replacen("m-", "m_", 1))
}

/// The machine a pid runs, by its command line: the only check before the daemon signals a
/// pid it did not spawn (a record's pid after a reboot is someone else's).
pub(super) fn machine_of(pid: u32) -> Option<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|c| firecracker_id(&c))
}

/// Whether Firecracker's `GET /` says the microVM runs.
pub(super) fn api_running(info: &serde_json::Value) -> bool {
    info["state"].as_str() == Some("Running")
}

/// Where Firecracker brings a guest connection to host port [`guest::EXIT_PORT`]: the vsock
/// socket's path with `_<port>` appended (Firecracker's convention for guest-initiated
/// connections), next to the socket, inside the chroot when jailed.
pub fn exit_socket(vsock: &Path) -> PathBuf {
    let mut name = vsock.as_os_str().to_owned();
    name.push(format!("_{}", guest::EXIT_PORT));
    PathBuf::from(name)
}

/// Listens for the init's exit report at [`exit_socket`]: the first connection's one frame
/// is the report. The socket belongs to the jail's user, since Firecracker connects to it
/// as that user. The listener ends with the process (`done`), and the channel closes with
/// it, so whoever waits for the report stops waiting when none can come. The socket file
/// stays until the next bind replaces it: the next boot may have bound it already.
pub(super) fn listen_exit(
    vsock: &Path,
    uid: u32,
    gid: u32,
    mut done: watch::Receiver<bool>,
) -> Result<watch::Receiver<Option<guest::ExitReport>>> {
    let path = exit_socket(vsock);
    let _ = std::fs::remove_file(&path);
    let ln = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("listen {}", path.display()))?;
    let _ = std::os::unix::fs::chown(&path, Some(uid), Some(gid));
    let (tx, rx) = watch::channel(None);
    tokio::spawn(async move {
        // A connection made before the process ended is ready before `done` is: taken first.
        let accepted = tokio::select! {
            biased;
            r = ln.accept() => r.ok(),
            _ = done.wait_for(|d| *d) => None,
        };
        if let Some((mut s, _)) = accepted {
            if let Ok(report) = crate::guestc::read_frame::<_, guest::ExitReport>(&mut s).await {
                let _ = tx.send(Some(report));
            }
        }
    });
    Ok(rx)
}

/// A file name next to Firecracker's sockets, as Firecracker sees it: at the root of the
/// chroot when jailed, in the run dir otherwise.
pub(super) fn inside_path(chroot: Option<&Path>, dir: &Path, name: &str) -> PathBuf {
    match chroot {
        Some(_) => PathBuf::from("/").join(name),
        None => dir.join(name),
    }
}

/// The same file as the host sees it.
pub(super) fn outside_path(chroot: Option<&Path>, dir: &Path, name: &str) -> PathBuf {
    match chroot {
        Some(r) => r.join(name),
        None => dir.join(name),
    }
}

/// Puts `host` at the jail root as `name` (a hard link, or a copy across filesystems), owned
/// by the jail's user and read-only for it (Firecracker only reads what it is given: a config
/// drive written 0600 is 0400 in the jail), and returns the path inside the chroot. An
/// earlier file of that name is replaced.
pub(super) fn place_file(
    root: &Path,
    host: &Path,
    name: &str,
    uid: u32,
    gid: u32,
) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let inside = root.join(name);
    let _ = std::fs::remove_file(&inside);
    if std::fs::hard_link(host, &inside).is_err() {
        std::fs::copy(host, &inside)
            .with_context(|| format!("copy {} into the jail", host.display()))?;
    }
    let _ = std::os::unix::fs::chown(&inside, Some(uid), Some(gid));
    let mode = std::fs::metadata(&inside)?.permissions().mode() & 0o444;
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(mode))?;
    Ok(PathBuf::from("/").join(name))
}

/// Copies console lines with a timestamp in front of each.
pub(super) async fn stamp<R: tokio::io::AsyncRead + Unpin>(
    r: R,
    out: std::sync::Arc<tokio::sync::Mutex<crate::console::Writer>>,
) {
    let mut lines = BufReader::new(r);
    let mut line = Vec::new();
    loop {
        line.clear();
        match lines.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let _ = out.lock().await.line(&ts, &line).await;
    }
    let _ = out.lock().await.flush().await;
}
