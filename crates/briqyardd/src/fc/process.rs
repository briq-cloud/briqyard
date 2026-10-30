//! A Firecracker process: its jail, cgroup, disk rates and paths.

use super::*;

/// How to run Firecracker under its jailer: a chroot per machine under `base`, as `uid`.
#[derive(Clone, Debug)]
pub struct Jail {
    pub jailer: PathBuf,
    pub base: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// CPU time the machine may use, in millicores; 0 for no limit.
    pub cpu_millis: u32,
    /// Memory the Firecracker process may use, in MB (the guest's memory plus Firecracker's
    /// own); 0 for no limit.
    pub memory_mb: u32,
}

/// Firecracker's rate limiter on one disk (ADR 0030): bytes and requests a second, each a
/// token bucket one second deep, plus a burst given once; 0 is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiskRate {
    pub bandwidth_mb: u32,
    pub iops: u32,
    pub burst_sec: u32,
}

impl DiskRate {
    /// A drive's `rate_limiter`. A bucket of size 0 is none, so a PATCH with one lifts it.
    pub fn rate_limiter(&self) -> serde_json::Value {
        let bucket = |per_sec: u64| json!({"size": per_sec, "one_time_burst": per_sec * self.burst_sec as u64, "refill_time": 1000});
        json!({
            "bandwidth": bucket((self.bandwidth_mb as u64) << 20),
            "ops": bucket(self.iops as u64),
        })
    }

    /// As the API shows it: every field there.
    pub fn view(&self) -> api::DiskLimits {
        api::DiskLimits {
            bandwidth_mb: Some(self.bandwidth_mb),
            iops: Some(self.iops),
            burst_sec: Some(self.burst_sec),
        }
    }
}

/// What a machine's disks did, from Firecracker's metrics: totals since the daemon started,
/// across its boots (ADR 0030).
#[derive(Debug, Default)]
pub struct DiskIo {
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    /// Requests the rate limiter held back.
    pub throttled: AtomicU64,
}

impl DiskIo {
    /// Adds one of Firecracker's metrics lines: each counter there is what it grew by since the
    /// line before; `block` is every drive's together. A line that does not parse adds nothing.
    pub fn add(&self, line: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        let b = &v["block"];
        let n = |k: &str| b[k].as_u64().unwrap_or(0);
        self.read_bytes.fetch_add(n("read_bytes"), Relaxed);
        self.write_bytes.fetch_add(n("write_bytes"), Relaxed);
        self.throttled
            .fetch_add(n("rate_limiter_throttled_events"), Relaxed);
    }
}

/// The metrics pipe, next to the API socket.
pub(super) const METRICS_FIFO: &str = "metrics.fifo";

/// Reads Firecracker's metrics lines from the pipe at `path` into `io` until `done`. Opened
/// for reading and writing, it never reads an end of file while no writer has it open.
/// Firecracker opens it non-blocking: a full pipe loses a line, never stalls the VMM (ADR 0030).
pub(super) fn read_metrics(
    path: &Path,
    io: Arc<DiskIo>,
    mut done: watch::Receiver<bool>,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let rx = tokio::net::unix::pipe::Receiver::from_file(f)
        .with_context(|| format!("metrics pipe {}", path.display()))?;
    tokio::spawn(async move {
        let mut lines = BufReader::new(rx).lines();
        loop {
            tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(l)) => io.add(&l),
                    _ => break,
                },
                _ = done.wait_for(|d| *d) => break,
            }
        }
    });
    Ok(())
}

/// One running Firecracker.
#[allow(dead_code)] // dir, api and console are kept for operators and tests
pub struct Process {
    pub dir: PathBuf,
    pub api: PathBuf,
    /// The vsock Unix socket on the host.
    pub vsock: PathBuf,
    pub console: PathBuf,
    pub client: Client,
    /// The chroot root when jailed: every path Firecracker opens is relative to it.
    pub chroot: Option<PathBuf>,
    pub(super) uid: u32,
    pub(super) gid: u32,
    child: Child,
    pid: u32,
    done: tokio::sync::watch::Receiver<bool>,
}

/// The cgroup the jailer puts every machine's cgroup under (`/sys/fs/cgroup/<parent>/<id>`).
pub const CGROUP_PARENT: &str = "firecracker";

/// A machine's id as Firecracker and its jailer take it: letters, digits and dashes only.
pub fn fc_id(id: &str) -> String {
    id.replace('_', "-")
}

/// The jail's root directory for a machine.
pub fn jail_root(base: &Path, id: &str) -> PathBuf {
    base.join("firecracker").join(fc_id(id)).join("root")
}

/// The cgroup (v2) of a jailed machine, where its CPU and memory use are read.
pub fn cgroup_dir(id: &str) -> PathBuf {
    Path::new("/sys/fs/cgroup")
        .join(CGROUP_PARENT)
        .join(fc_id(id))
}

/// What a machine's cgroup says.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CgroupUse {
    /// CPU time since the cgroup was made, in microseconds.
    pub cpu_usec: u64,
    /// Memory its processes hold now.
    pub memory_bytes: u64,
}

/// `usage_usec` of a `cpu.stat`.
pub fn cpu_usec(cpu_stat: &str) -> Option<u64> {
    cpu_stat
        .lines()
        .find_map(|l| l.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
}

/// The memory snapshot of a machine (`snap.state`, `snap.mem`) as the host sees it: in its
/// chroot when jailed under `jail_base`, in its run dir otherwise.
pub fn snapshot_files(dir: &Path, jail_base: Option<&Path>, id: &str) -> [PathBuf; 2] {
    let root = jail_base.map(|b| jail_root(b, id));
    ["snap.state", "snap.mem"].map(|n| outside_path(root.as_deref(), dir, n))
}

/// Where a machine's snapshots with memory are kept (ADR 0031): beside its jail's root, so on
/// the pool and out of the jailer's reach, or in its run dir without the jailer. A file there
/// is moved from, and linked back to, `snapshot_files`: one filesystem.
pub fn memory_dir(dir: &Path, jail_base: Option<&Path>, id: &str) -> PathBuf {
    match jail_base {
        Some(b) => b.join("firecracker").join(fc_id(id)).join("snapshots"),
        None => dir.join("snapshots"),
    }
}

/// The jailer's command line for a machine: what to run, as whom, where, with what limits.
pub(super) fn jailer_args(j: &Jail, id: &str, binary: &Path) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec![
        "--id".into(),
        fc_id(id).into(),
        "--exec-file".into(),
        binary.into(),
        "--uid".into(),
        j.uid.to_string().into(),
        "--gid".into(),
        j.gid.to_string().into(),
        "--chroot-base-dir".into(),
        j.base.clone().into(),
        "--cgroup-version".into(),
        "2".into(),
        "--parent-cgroup".into(),
        CGROUP_PARENT.into(),
        "--new-pid-ns".into(),
    ];
    if j.cpu_millis > 0 {
        args.push("--cgroup".into());
        args.push(
            format!(
                "cpu.max={} {}",
                cpu_quota(j.cpu_millis).0,
                cpu_quota(j.cpu_millis).1
            )
            .into(),
        );
        // Under contention CPU goes by size: the default weight (100) per vCPU (ADR 0030).
        args.push("--cgroup".into());
        args.push(format!("cpu.weight={}", (j.cpu_millis / 10).max(1)).into());
    }
    if j.memory_mb > 0 {
        args.push("--cgroup".into());
        args.push(format!("memory.max={}", (j.memory_mb as u64) << 20).into());
    }
    args
}

/// The pid the jailer wrote for Firecracker: with a new pid namespace the jailer forks, the
/// process we spawned writes its child's pid to this file and exits, and the child is the one
/// to kill or adopt.
/// CFS accepts at least 1000µs quota. Preserve 1m precision below 10m with a 1s period;
/// normal sizes use the existing 100ms period.
pub(super) fn cpu_quota(millis: u32) -> (u64, u64) {
    let period = if millis < 10 { 1_000_000 } else { 100_000 };
    (u64::from(millis) * period / 1000, period)
}

pub(super) fn jailed_pid(root: &Path) -> Result<u32> {
    let path = root.join("firecracker.pid");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    text.trim()
        .parse()
        .with_context(|| format!("{}: {text:?}", path.display()))
}

/// The runtime files of a machine: the API and vsock sockets depend on whether it is jailed.
pub fn paths_for(
    dir: &Path,
    jail: Option<&Jail>,
    id: &str,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let (api, vsock, console, fclog) = paths(dir);
    match jail {
        Some(j) => {
            let root = jail_root(&j.base, id);
            (
                root.join("run/firecracker.socket"),
                root.join("vsock.sock"),
                console,
                fclog,
            )
        }
        None => (api, vsock, console, fclog),
    }
}

/// A machine's runtime files inside its run dir.
pub fn paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    (
        dir.join("api.sock"),
        dir.join("vsock.sock"),
        dir.join("console.log"),
        dir.join("firecracker.log"),
    )
}

impl Process {
    /// Launches Firecracker for machine `id` with runtime files under `dir` and waits for its
    /// API. Nothing is configured yet.
    pub async fn start(
        binary: &Path,
        id: &str,
        dir: &Path,
        pci: bool,
        jail: Option<&Jail>,
        console_max: u64,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let (api, vsock, console, fclog) = paths_for(dir, jail, id);
        let _ = tokio::fs::remove_file(&api).await;
        let _ = tokio::fs::remove_file(&vsock).await;
        // The console holds what the guest prints, the jailer's errors included: ours alone.
        let out = crate::console::Writer::open(dir, console_max).await?;
        // Firecracker's log levels are Error, Warning, Info, Debug, Trace.
        let (mut cmd, chroot, uid, gid) = match jail {
            Some(j) => {
                // The jailer makes the chroot and drops to uid:gid; the files Firecracker opens
                // are placed inside by `expose_*` once it answers. The root exists beforehand,
                // owned by the jail's user, so Firecracker can write its sockets and snapshots.
                let root = jail_root(&j.base, id);
                // The jailer populates the root (sys, dev, the exec file, the pid file) and
                // refuses what it finds there from a previous run; only the snapshot files
                // are ours to keep.
                if let Ok(mut rd) = tokio::fs::read_dir(&root).await {
                    while let Ok(Some(entry)) = rd.next_entry().await {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.starts_with("snap.") {
                            continue;
                        }
                        let path = entry.path();
                        if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                            let _ = tokio::fs::remove_dir_all(&path).await;
                        } else {
                            let _ = tokio::fs::remove_file(&path).await;
                        }
                    }
                }
                tokio::fs::create_dir_all(root.join("run")).await?;
                for d in [&root, &root.join("run")] {
                    std::os::unix::fs::chown(d, Some(j.uid), Some(j.gid))?;
                }
                let mut cmd = Command::new(&j.jailer);
                cmd.args(jailer_args(j, id, binary));
                cmd.arg("--").arg("--").arg("--level").arg("Warning");
                if pci {
                    cmd.arg("--enable-pci");
                }
                (cmd, Some(root), j.uid, j.gid)
            }
            None => {
                let _ = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(&fclog)
                    .await?;
                let mut cmd = Command::new(binary);
                cmd.arg("--api-sock")
                    .arg(&api)
                    .arg("--id")
                    .arg(fc_id(id))
                    .arg("--log-path")
                    .arg(&fclog)
                    .arg("--level")
                    .arg("Warning");
                if pci {
                    cmd.arg("--enable-pci");
                }
                (cmd, None, 0, 0)
            }
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // The daemon's store (ADR 0051) is not the jailer's or Firecracker's.
        for v in briqyard_api::listeners::ENV {
            cmd.env_remove(v);
        }
        cmd.process_group(0);
        cmd.kill_on_drop(false);
        let mut child = cmd.spawn().context("start firecracker")?;
        let pid = child.id().unwrap_or(0);
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let out = std::sync::Arc::new(tokio::sync::Mutex::new(out));
        let o1 = out.clone();
        let t1 = tokio::spawn(stamp(stdout, o1));
        let t2 = tokio::spawn(stamp(stderr, out));
        tokio::spawn(async move {
            let _ = t1.await;
            let _ = t2.await;
            let _ = tx.send(true);
        });
        let p = Self {
            dir: dir.to_path_buf(),
            api: api.clone(),
            vsock,
            console,
            client: Client::new(&api),
            chroot,
            uid,
            gid,
            child,
            pid,
            done: rx,
        };
        if let Err(e) = p.client.wait_api(Duration::from_secs(10)).await {
            p.kill();
            return Err(e);
        }
        let mut p = p;
        if let Some(root) = p.chroot.clone() {
            // The process we spawned is the jailer's parent: it exits once it has written the
            // pid file, so its exit is the wait, and the file is then there or never will be.
            let _ = p.child.wait().await;
            match jailed_pid(&root) {
                Ok(pid) => p.pid = pid,
                Err(e) => {
                    // A Firecracker that cannot be named is killed through its cgroup.
                    let _ = std::fs::write(cgroup_dir(id).join("cgroup.kill"), "1");
                    return Err(e.context("jailer pid"));
                }
            }
        }
        Ok(p)
    }

    /// The path Firecracker must be given for a file on the host: inside the chroot when
    /// jailed (hard-linked, or copied across filesystems, and readable by the jail's user).
    pub fn expose_file(&self, host: &Path, name: &str) -> Result<PathBuf> {
        match &self.chroot {
            Some(root) => place_file(root, host, name, self.uid, self.gid),
            None => Ok(host.to_path_buf()),
        }
    }

    /// The path Firecracker must be given for a block device: a node inside the chroot when
    /// jailed, owned by the jail's user.
    pub fn expose_block(&self, dev: &Path, name: &str) -> Result<PathBuf> {
        let root = match &self.chroot {
            Some(r) => r,
            None => return Ok(dev.to_path_buf()),
        };
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(dev).with_context(|| dev.display().to_string())?;
        let inside = root.join(name);
        let _ = std::fs::remove_file(&inside);
        nix::sys::stat::mknod(
            &inside,
            nix::sys::stat::SFlag::S_IFBLK,
            nix::sys::stat::Mode::from_bits_truncate(0o600),
            meta.rdev() as nix::sys::stat::dev_t,
        )
        .with_context(|| format!("mknod {}", inside.display()))?;
        std::os::unix::fs::chown(&inside, Some(self.uid), Some(self.gid))?;
        Ok(PathBuf::from("/").join(name))
    }

    /// Makes the metrics pipe next to the sockets, owned by the jail's user, reads it into
    /// `io` while the process runs, and tells Firecracker to write there.
    pub async fn metrics_to(&self, io: Arc<DiskIo>) -> Result<()> {
        let path = self.outside(METRICS_FIFO);
        let _ = std::fs::remove_file(&path);
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .with_context(|| format!("mkfifo {}", path.display()))?;
        std::os::unix::fs::chown(&path, Some(self.uid), Some(self.gid))?;
        read_metrics(&path, io, self.done())?;
        self.client.metrics(&self.inside(METRICS_FIFO)).await
    }

    /// Where Firecracker sees the vsock socket (inside the chroot when jailed) and a file name
    /// next to its sockets, for snapshots.
    pub fn inside(&self, name: &str) -> PathBuf {
        inside_path(self.chroot.as_deref(), &self.dir, name)
    }

    /// The host path of a file Firecracker writes next to its sockets.
    pub fn outside(&self, name: &str) -> PathBuf {
        outside_path(self.chroot.as_deref(), &self.dir, name)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// `true` once the process is gone and its console fully written.
    pub fn done(&self) -> watch::Receiver<bool> {
        self.done.clone()
    }

    pub fn kill(&self) {
        unsafe {
            libc::kill(self.pid as i32, libc::SIGKILL);
        }
    }

    /// Waits for the process to exit and its console to be fully written.
    pub async fn wait(&mut self) {
        let _ = self.child.wait().await;
        let mut done = self.done.clone();
        while !*done.borrow() {
            if done.changed().await.is_err() {
                break;
            }
        }
    }
}
