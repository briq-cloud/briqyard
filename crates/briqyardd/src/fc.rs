//! Firecracker: one process per machine, configured over its Unix socket API with a small
//! HTTP/1.1 client of our own (the requests are tiny and the socket is local).

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::watch;

/// Talks to one Firecracker over its API socket.
#[derive(Clone)]
pub struct Client {
    socket: PathBuf,
}

#[derive(Debug, thiserror::Error)]
#[error("firecracker: {status} {fault}")]
pub struct ApiError {
    pub status: u16,
    pub fault: String,
}

impl Client {
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
        }
    }

    async fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
        let mut s = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect {}", self.socket.display()))?;
        let body = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await?;
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).await?;
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| anyhow!("bad status line {line:?}"))?;
        let mut len = 0usize;
        loop {
            line.clear();
            r.read_line(&mut line).await?;
            let t = line.trim();
            if t.is_empty() {
                break;
            }
            if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
        let mut resp = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut resp).await?;
        }
        Ok((status, String::from_utf8_lossy(&resp).into_owned()))
    }

    async fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<String> {
        let (status, resp) = self.request(method, path, body).await?;
        if !(200..300).contains(&status) {
            let fault = serde_json::from_str::<serde_json::Value>(&resp)
                .ok()
                .and_then(|v| v["fault_message"].as_str().map(String::from))
                .unwrap_or(resp);
            return Err(ApiError { status, fault }.into());
        }
        Ok(resp)
    }

    async fn put<T: Serialize>(&self, path: &str, v: &T) -> Result<()> {
        self.call("PUT", path, Some(&serde_json::to_string(v)?))
            .await
            .map(|_| ())
    }

    pub async fn machine_config(&self, vcpus: u32, memory_mb: u32) -> Result<()> {
        self.put(
            "/machine-config",
            &json!({"vcpu_count": vcpus, "mem_size_mib": memory_mb, "smt": false}),
        )
        .await
    }

    pub async fn boot_source(&self, kernel: &Path, args: &str) -> Result<()> {
        self.put(
            "/boot-source",
            &json!({"kernel_image_path": kernel, "boot_args": args}),
        )
        .await
    }

    /// `cache` is "Unsafe" (no flush) or "Writeback" (a guest flush is a host fsync).
    pub async fn drive(
        &self,
        id: &str,
        path: &Path,
        root: bool,
        read_only: bool,
        cache: &str,
    ) -> Result<()> {
        self.put(&format!("/drives/{id}"), &json!({"drive_id": id, "path_on_host": path, "is_root_device": root, "is_read_only": read_only, "cache_type": cache})).await
    }

    pub async fn network_interface(&self, id: &str, tap: &str, mac: &str) -> Result<()> {
        self.put(
            &format!("/network-interfaces/{id}"),
            &json!({"iface_id": id, "host_dev_name": tap, "guest_mac": mac}),
        )
        .await
    }

    pub async fn vsock(&self, cid: u32, uds: &Path) -> Result<()> {
        self.put("/vsock", &json!({"guest_cid": cid, "uds_path": uds}))
            .await
    }

    pub async fn start(&self) -> Result<()> {
        self.put("/actions", &json!({"action_type": "InstanceStart"}))
            .await
    }

    pub async fn pause(&self) -> Result<()> {
        self.call("PATCH", "/vm", Some(r#"{"state":"Paused"}"#))
            .await
            .map(|_| ())
    }

    pub async fn resume(&self) -> Result<()> {
        self.call("PATCH", "/vm", Some(r#"{"state":"Resumed"}"#))
            .await
            .map(|_| ())
    }

    /// A full snapshot (VM state and memory) of a paused machine.
    pub async fn snapshot_create(&self, state: &Path, mem: &Path) -> Result<()> {
        self.put(
            "/snapshot/create",
            &json!({"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem}),
        )
        .await
    }

    /// Restores a snapshot into a fresh process and resumes it; the TAP is reopened by name.
    pub async fn snapshot_load(
        &self,
        state: &Path,
        mem: &Path,
        iface: &str,
        tap: &str,
    ) -> Result<()> {
        self.put(
            "/snapshot/load",
            &json!({"snapshot_path": state, "mem_backend": {"backend_type": "File", "backend_path": mem}, "resume_vm": true,
                    "network_overrides": [{"iface_id": iface, "host_dev_name": tap}]}),
        )
        .await
    }

    pub async fn info(&self) -> Result<serde_json::Value> {
        let s = self.call("GET", "/", None).await?;
        Ok(serde_json::from_str(&s)?)
    }

    pub async fn wait_api(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let last = match tokio::time::timeout(Duration::from_secs(1), self.info()).await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => e.to_string(),
                Err(_) => "timeout".to_string(),
            };
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!(
                    "firecracker API did not answer within {timeout:?}: {last}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// How to run Firecracker under its jailer: a chroot per machine under `base`, as `uid`.
#[derive(Clone, Debug)]
pub struct Jail {
    pub jailer: PathBuf,
    pub base: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// CPU time the machine may use, in whole CPUs (its vCPUs: a shared vCPU is one CPU's worth
    /// at most, so oversubscription stays fair); 0 for no limit.
    pub cpus: u32,
    /// Memory the Firecracker process may use, in MB (the guest's memory plus Firecracker's
    /// own); 0 for no limit.
    pub memory_mb: u32,
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
    uid: u32,
    gid: u32,
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

/// The jailer's command line for a machine: what to run, as whom, where, with what limits.
fn jailer_args(j: &Jail, id: &str, binary: &Path) -> Vec<std::ffi::OsString> {
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
    if j.cpus > 0 {
        args.push("--cgroup".into());
        args.push(format!("cpu.max={} 100000", j.cpus as u64 * 100_000).into());
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
fn jailed_pid(root: &Path) -> Result<u32> {
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
    ) -> Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let (api, vsock, console, fclog) = paths_for(dir, jail, id);
        let _ = tokio::fs::remove_file(&api).await;
        let _ = tokio::fs::remove_file(&vsock).await;
        // The console holds what the guest prints, the jailer's errors included: ours alone.
        let out = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&console)
            .await?;
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
}

impl Vm {
    fn inside(&self, name: &str) -> PathBuf {
        inside_path(self.chroot.as_deref(), &self.dir, name)
    }

    fn outside(&self, name: &str) -> PathBuf {
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
    /// API says the machine runs.
    async fn adopt(&self, id: &str, dir: &Path, jail: Option<&Jail>, pid: u32) -> Option<Vm>;

    /// Pauses the machine and writes its memory and state next to its sockets, for the
    /// next boot to resume. An error means the VMM refused and the machine runs on.
    async fn snapshot(&self, vm: &Vm) -> Result<()>;

    /// SIGKILL to the process and to its group.
    fn kill(&self, pid: u32);

    /// The machine id the process carries, when it is a VMM of ours.
    fn machine_of(&self, pid: u32) -> Option<String>;

    /// Every VMM on the host with the machine id it carries.
    fn processes(&self) -> Vec<(u32, String)>;
}

/// The Firecracker on this host.
pub struct Firecracker {
    pub binary: PathBuf,
    /// Firecracker's PCI transport.
    pub pci: bool,
}

#[async_trait]
impl Vmm for Firecracker {
    async fn boot(&self, b: &Boot) -> Result<Vm> {
        let mut resume = b.resume;
        let proc = loop {
            let mut proc =
                Process::start(&self.binary, &b.id, &b.dir, self.pci, b.jail.as_ref()).await?;
            let c = proc.client.clone();
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
                    .await
                };
                match load.await {
                    Ok(()) => break proc,
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
                c.drive("rootfs", &root, true, false, "Writeback").await?;
                c.drive("config", &config, false, true, "Unsafe").await?;
                if let Some(d) = &b.data {
                    let data = proc.expose_block(d, "data")?;
                    c.drive("data", &data, false, false, "Writeback").await?;
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
            break proc;
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
    async fn adopt(&self, id: &str, dir: &Path, jail: Option<&Jail>, pid: u32) -> Option<Vm> {
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
            chroot: jail.map(|j| jail_root(&j.base, id)),
            resumed: false,
            exited,
        })
    }

    async fn snapshot(&self, vm: &Vm) -> Result<()> {
        let c = Client::new(&vm.api);
        c.pause().await.context("pause")?;
        if let Err(err) = c
            .snapshot_create(&vm.inside("snap.state"), &vm.inside("snap.mem"))
            .await
        {
            let _ = c.resume().await;
            let _ = tokio::fs::remove_file(vm.outside("snap.state")).await;
            let _ = tokio::fs::remove_file(vm.outside("snap.mem")).await;
            return Err(err.context("snapshot (resumed)"));
        }
        Ok(())
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
}

/// The machine id a Firecracker command line carries (`firecracker --id m-… …`), as the
/// daemon spells it; `None` for any other process.
fn firecracker_id(cmdline: &[u8]) -> Option<String> {
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
fn machine_of(pid: u32) -> Option<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|c| firecracker_id(&c))
}

/// Whether Firecracker's `GET /` says the microVM runs.
fn api_running(info: &serde_json::Value) -> bool {
    info["state"].as_str() == Some("Running")
}

/// A file name next to Firecracker's sockets, as Firecracker sees it: at the root of the
/// chroot when jailed, in the run dir otherwise.
fn inside_path(chroot: Option<&Path>, dir: &Path, name: &str) -> PathBuf {
    match chroot {
        Some(_) => PathBuf::from("/").join(name),
        None => dir.join(name),
    }
}

/// The same file as the host sees it.
fn outside_path(chroot: Option<&Path>, dir: &Path, name: &str) -> PathBuf {
    match chroot {
        Some(r) => r.join(name),
        None => dir.join(name),
    }
}

/// Puts `host` at the jail root as `name` (a hard link, or a copy across filesystems), owned
/// by the jail's user and read-only for it (Firecracker only reads what it is given: a config
/// drive written 0600 is 0400 in the jail), and returns the path inside the chroot. An
/// earlier file of that name is replaced.
fn place_file(root: &Path, host: &Path, name: &str, uid: u32, gid: u32) -> Result<PathBuf> {
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
async fn stamp<R: tokio::io::AsyncRead + Unpin>(
    r: R,
    out: std::sync::Arc<tokio::sync::Mutex<tokio::fs::File>>,
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
        let mut o = out.lock().await;
        let _ = o.write_all(ts.as_bytes()).await;
        let _ = o.write_all(b" ").await;
        let _ = o.write_all(&line).await;
        if !line.ends_with(b"\n") {
            let _ = o.write_all(b"\n").await;
        }
    }
    let mut o = out.lock().await;
    let _ = o.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A stand-in for Firecracker's API socket: answers each connection with the next canned
    /// response and hands back the requests it read, in order.
    fn serve(socket: &Path, responses: Vec<&'static str>) -> tokio::task::JoinHandle<Vec<String>> {
        let ln = UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            let mut seen = Vec::new();
            for resp in responses {
                let (mut s, _) = ln.accept().await.unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = s.read(&mut buf).await.unwrap();
                    req.extend_from_slice(&buf[..n]);
                    if n == 0 || complete(&req) {
                        break;
                    }
                }
                seen.push(String::from_utf8(req).unwrap());
                s.write_all(resp.as_bytes()).await.unwrap();
            }
            seen
        })
    }

    /// Whether the head and the body announced by Content-Length are all there.
    fn complete(req: &[u8]) -> bool {
        let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        req.len() >= end + 4 + len
    }

    fn body(req: &str) -> serde_json::Value {
        let (_, b) = req.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(b).unwrap()
    }

    fn socket() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        (dir, path)
    }

    const NO_CONTENT: &str =
        "HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\nConnection: keep-alive\r\n\r\n";

    #[tokio::test]
    async fn put_sends_json_and_takes_204() {
        let (_dir, path) = socket();
        let server = serve(&path, vec![NO_CONTENT]);
        Client::new(&path).machine_config(2, 512).await.unwrap();
        let seen = server.await.unwrap();
        let req = &seen[0];
        assert!(req.starts_with("PUT /machine-config HTTP/1.1\r\n"), "{req}");
        assert!(
            req.contains("\r\nContent-Type: application/json\r\n"),
            "{req}"
        );
        assert!(req.contains("\r\nConnection: close\r\n"), "{req}");
        let b = body(req);
        assert_eq!(
            b,
            serde_json::json!({"vcpu_count": 2, "mem_size_mib": 512, "smt": false})
        );
        let len: usize = req
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(len, b.to_string().len());
    }

    #[tokio::test]
    async fn every_call_has_its_path_and_body() {
        let (_dir, path) = socket();
        let server = serve(&path, vec![NO_CONTENT; 9]);
        let c = Client::new(&path);
        c.boot_source(Path::new("/vmlinux"), "console=ttyS0")
            .await
            .unwrap();
        c.drive("rootfs", Path::new("/root"), true, false, "Writeback")
            .await
            .unwrap();
        c.network_interface("eth0", "tm1", "06:b1:0a:40:00:02")
            .await
            .unwrap();
        c.vsock(3, Path::new("/vsock.sock")).await.unwrap();
        c.start().await.unwrap();
        c.pause().await.unwrap();
        c.resume().await.unwrap();
        c.snapshot_create(Path::new("/snap.state"), Path::new("/snap.mem"))
            .await
            .unwrap();
        c.snapshot_load(
            Path::new("/snap.state"),
            Path::new("/snap.mem"),
            "eth0",
            "tm1",
        )
        .await
        .unwrap();
        let seen = server.await.unwrap();
        let first = |i: usize| seen[i].lines().next().unwrap().to_string();
        assert_eq!(first(0), "PUT /boot-source HTTP/1.1");
        assert_eq!(
            body(&seen[0]),
            serde_json::json!({"kernel_image_path": "/vmlinux", "boot_args": "console=ttyS0"})
        );
        assert_eq!(first(1), "PUT /drives/rootfs HTTP/1.1");
        assert_eq!(
            body(&seen[1]),
            serde_json::json!({"drive_id": "rootfs", "path_on_host": "/root", "is_root_device": true, "is_read_only": false, "cache_type": "Writeback"})
        );
        assert_eq!(first(2), "PUT /network-interfaces/eth0 HTTP/1.1");
        assert_eq!(
            body(&seen[2]),
            serde_json::json!({"iface_id": "eth0", "host_dev_name": "tm1", "guest_mac": "06:b1:0a:40:00:02"})
        );
        assert_eq!(first(3), "PUT /vsock HTTP/1.1");
        assert_eq!(
            body(&seen[3]),
            serde_json::json!({"guest_cid": 3, "uds_path": "/vsock.sock"})
        );
        assert_eq!(first(4), "PUT /actions HTTP/1.1");
        assert_eq!(
            body(&seen[4]),
            serde_json::json!({"action_type": "InstanceStart"})
        );
        assert_eq!(first(5), "PATCH /vm HTTP/1.1");
        assert_eq!(body(&seen[5]), serde_json::json!({"state": "Paused"}));
        assert_eq!(first(6), "PATCH /vm HTTP/1.1");
        assert_eq!(body(&seen[6]), serde_json::json!({"state": "Resumed"}));
        assert_eq!(first(7), "PUT /snapshot/create HTTP/1.1");
        assert_eq!(body(&seen[7])["snapshot_type"], "Full");
        assert_eq!(first(8), "PUT /snapshot/load HTTP/1.1");
        let load = body(&seen[8]);
        assert_eq!(load["resume_vm"], true);
        assert_eq!(load["mem_backend"]["backend_path"], "/snap.mem");
        assert_eq!(load["network_overrides"][0]["host_dev_name"], "tm1");
    }

    #[tokio::test]
    async fn a_fault_is_an_api_error() {
        let (_dir, path) = socket();
        let fault = r#"{"fault_message":"The requested operation is not supported after starting the microVM."}"#;
        let resp = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{fault}",
            fault.len()
        );
        let server = serve(&path, vec![Box::leak(resp.into_boxed_str())]);
        let err = Client::new(&path).start().await.unwrap_err();
        let api = err.downcast_ref::<ApiError>().expect("an ApiError");
        assert_eq!(api.status, 400);
        assert_eq!(
            api.fault,
            "The requested operation is not supported after starting the microVM."
        );
        assert_eq!(err.to_string(), format!("firecracker: 400 {}", api.fault));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_fault_that_is_not_json_keeps_the_body() {
        let (_dir, path) = socket();
        let server = serve(
            &path,
            vec!["HTTP/1.1 500 Internal Server Error\r\nContent-Length: 6\r\n\r\nboom!\n"],
        );
        let err = Client::new(&path).start().await.unwrap_err();
        let api = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!((api.status, api.fault.as_str()), (500, "boom!\n"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn info_reads_the_json_answer() {
        let (_dir, path) = socket();
        let info = r#"{"id":"m-1","state":"Running","vmm_version":"1.10.0"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{info}",
            info.len()
        );
        let server = serve(&path, vec![Box::leak(resp.into_boxed_str())]);
        let v = Client::new(&path).info().await.unwrap();
        assert_eq!(v["state"], "Running");
        let seen = server.await.unwrap();
        assert!(seen[0].starts_with("GET / HTTP/1.1\r\n"), "{}", seen[0]);
        assert!(seen[0].contains("Content-Length: 0\r\n"), "{}", seen[0]);
        assert!(seen[0].ends_with("\r\n\r\n"), "{}", seen[0]);
    }

    #[tokio::test]
    async fn a_bad_status_line_is_an_error() {
        let (_dir, path) = socket();
        let server = serve(&path, vec!["nonsense\r\n\r\n"]);
        let err = Client::new(&path).info().await.unwrap_err();
        assert!(err.to_string().contains("bad status line"), "{err}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wait_api_gives_up_without_a_socket() {
        let (_dir, path) = socket();
        let t0 = std::time::Instant::now();
        let err = Client::new(&path)
            .wait_api(Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(t0.elapsed() >= Duration::from_millis(100));
        let msg = err.to_string();
        assert!(msg.contains("did not answer within"), "{msg}");
        assert!(msg.contains("connect"), "{msg}");
    }

    #[tokio::test]
    async fn wait_api_returns_once_the_api_answers() {
        let (_dir, path) = socket();
        let server = serve(
            &path,
            vec!["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"],
        );
        Client::new(&path)
            .wait_api(Duration::from_secs(5))
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn adoption_checks() {
        // Only a Firecracker carrying the machine's id is ours: the binary by any path, the
        // id as the jailer spells it.
        let fc = b"/usr/local/bin/firecracker\0--id\0m-abc123\0--api-sock\0/run/api.sock\0";
        assert_eq!(firecracker_id(fc).as_deref(), Some("m_abc123"));
        assert_eq!(
            firecracker_id(b"firecracker\0--id\0m-x\0").as_deref(),
            Some("m_x")
        );
        assert_eq!(firecracker_id(b"firecracker\0--api-sock\0/x\0"), None);
        assert_eq!(firecracker_id(b"/usr/bin/jailer\0--id\0m-abc123\0"), None);
        assert_eq!(
            firecracker_id(b"/bin/sh\0-c\0firecracker --id m-abc123\0"),
            None
        );
        assert_eq!(firecracker_id(b""), None);
        // This process is not a Firecracker (and there is no /proc on a Mac): never killed.
        assert_eq!(machine_of(std::process::id()), None);
        assert!(api_running(
            &serde_json::json!({"id": "m-1", "state": "Running", "vmm_version": "1.10"})
        ));
        assert!(!api_running(&serde_json::json!({"state": "Paused"})));
        assert!(!api_running(&serde_json::json!({"state": "Not started"})));
        assert!(!api_running(&serde_json::json!({})));
    }

    #[test]
    fn jail_paths() {
        let base = Path::new("/var/lib/briqyard/jail");
        // Firecracker takes only letters, digits and dashes in an id.
        assert_eq!(fc_id("m_abc123"), "m-abc123");
        assert_eq!(
            jail_root(base, "m_abc123"),
            PathBuf::from("/var/lib/briqyard/jail/firecracker/m-abc123/root")
        );
        // The stats are read where the jailer, told the same parent, puts the cgroup.
        assert_eq!(
            cgroup_dir("m_abc123"),
            PathBuf::from("/sys/fs/cgroup/firecracker/m-abc123")
        );
        let dir = Path::new("/var/lib/briqyard/run/m_abc123");
        assert_eq!(
            paths(dir),
            (
                dir.join("api.sock"),
                dir.join("vsock.sock"),
                dir.join("console.log"),
                dir.join("firecracker.log")
            )
        );
        assert_eq!(paths_for(dir, None, "m_abc123"), paths(dir));
        let jail = Jail {
            jailer: "/usr/local/bin/jailer".into(),
            base: base.to_path_buf(),
            uid: 100_002,
            gid: 100_002,
            cpus: 1,
            memory_mb: 512,
        };
        let root = jail_root(base, "m_abc123");
        assert_eq!(
            paths_for(dir, Some(&jail), "m_abc123"),
            (
                root.join("run/firecracker.socket"),
                root.join("vsock.sock"),
                dir.join("console.log"),
                dir.join("firecracker.log")
            )
        );
    }

    #[test]
    fn inside_and_outside() {
        let dir = Path::new("/run/m_1");
        let root = Path::new("/jail/firecracker/m-1/root");
        assert_eq!(
            inside_path(None, dir, "snap.mem"),
            PathBuf::from("/run/m_1/snap.mem")
        );
        assert_eq!(
            outside_path(None, dir, "snap.mem"),
            PathBuf::from("/run/m_1/snap.mem")
        );
        assert_eq!(
            inside_path(Some(root), dir, "snap.mem"),
            PathBuf::from("/snap.mem")
        );
        assert_eq!(
            outside_path(Some(root), dir, "snap.mem"),
            PathBuf::from("/jail/firecracker/m-1/root/snap.mem")
        );
    }

    #[test]
    fn the_jailer_is_told_the_cgroup_parent_and_the_limits() {
        let jail = Jail {
            jailer: "/usr/local/bin/jailer".into(),
            base: "/var/lib/briqyard/jail".into(),
            uid: 100_002,
            gid: 100_002,
            cpus: 2,
            memory_mb: 768,
        };
        let args: Vec<String> =
            jailer_args(&jail, "m_abc123", Path::new("/usr/local/bin/firecracker"))
                .into_iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
        assert_eq!(
            args,
            [
                "--id",
                "m-abc123",
                "--exec-file",
                "/usr/local/bin/firecracker",
                "--uid",
                "100002",
                "--gid",
                "100002",
                "--chroot-base-dir",
                "/var/lib/briqyard/jail",
                "--cgroup-version",
                "2",
                "--parent-cgroup",
                CGROUP_PARENT,
                "--new-pid-ns",
                "--cgroup",
                "cpu.max=200000 100000",
                "--cgroup",
                "memory.max=805306368",
            ]
        );
        // No limit, no cgroup argument.
        let free = Jail {
            cpus: 0,
            memory_mb: 0,
            ..jail
        };
        let args = jailer_args(&free, "m_abc123", Path::new("/fc"));
        assert!(!args.iter().any(|a| a == "--cgroup"), "{args:?}");
    }

    #[test]
    fn the_pid_file_is_read_once_and_must_be_there() {
        let root = tempfile::tempdir().unwrap();
        let err = jailed_pid(root.path()).unwrap_err();
        assert!(format!("{err:#}").contains("firecracker.pid"), "{err:#}");
        std::fs::write(root.path().join("firecracker.pid"), "nope\n").unwrap();
        let err = jailed_pid(root.path()).unwrap_err();
        assert!(format!("{err:#}").contains("\"nope\\n\""), "{err:#}");
        std::fs::write(root.path().join("firecracker.pid"), "4242\n").unwrap();
        assert_eq!(jailed_pid(root.path()).unwrap(), 4242);
    }

    #[test]
    fn placing_a_file_in_the_jail() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let host = dir.path().join("vmlinux");
        std::fs::write(&host, b"kernel").unwrap();
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Not root: the chown fails and is ignored; the link is what matters.
        let inside = place_file(&root, &host, "vmlinux", 100_000, 100_000).unwrap();
        assert_eq!(inside, PathBuf::from("/vmlinux"));
        assert_eq!(std::fs::read(root.join("vmlinux")).unwrap(), b"kernel");
        // Read-only for Firecracker; a shared kernel stays readable by all.
        assert_eq!(mode(&root.join("vmlinux")), 0o444);
        // A new file of the same name replaces the earlier one.
        let host2 = dir.path().join("config.tar");
        std::fs::write(&host2, b"v2").unwrap();
        place_file(&root, &host2, "vmlinux", 100_000, 100_000).unwrap();
        assert_eq!(std::fs::read(root.join("vmlinux")).unwrap(), b"v2");
        // A config drive, written for the daemon alone, is the jail's user's alone.
        std::fs::set_permissions(&host2, std::fs::Permissions::from_mode(0o600)).unwrap();
        place_file(&root, &host2, "config.tar", 100_000, 100_000).unwrap();
        assert_eq!(mode(&root.join("config.tar")), 0o400);
        // A host file that does not exist cannot be placed.
        let err = place_file(&root, &dir.path().join("missing"), "x", 0, 0).unwrap_err();
        assert!(err.to_string().contains("into the jail"), "{err}");
    }

    #[tokio::test]
    async fn console_lines_are_stamped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .unwrap();
        let out = std::sync::Arc::new(tokio::sync::Mutex::new(f));
        stamp(&b"one\ntwo"[..], out).await;
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        for (line, want) in lines.iter().zip(["one", "two"]) {
            let (ts, rest) = line.split_once(' ').unwrap();
            chrono::DateTime::parse_from_rfc3339(ts).unwrap();
            assert_eq!(rest, want);
        }
        // The last line gets its newline even when the source had none.
        assert!(text.ends_with("two\n"));
    }
}
