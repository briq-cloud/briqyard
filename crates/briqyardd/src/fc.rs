//! Firecracker: one process per machine, configured over its Unix socket API with a small
//! HTTP/1.1 client of our own (the requests are tiny and the socket is local).

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

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

    #[allow(dead_code)] // suspend and resume: planned
    pub async fn pause(&self) -> Result<()> {
        self.call("PATCH", "/vm", Some(r#"{"state":"Paused"}"#))
            .await
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub async fn resume(&self) -> Result<()> {
        self.call("PATCH", "/vm", Some(r#"{"state":"Resumed"}"#))
            .await
            .map(|_| ())
    }

    /// A full snapshot (VM state and memory) of a paused machine.
    #[allow(dead_code)]
    pub async fn snapshot_create(&self, state: &Path, mem: &Path) -> Result<()> {
        self.put(
            "/snapshot/create",
            &json!({"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem}),
        )
        .await
    }

    /// Restores a snapshot into a fresh process and resumes it; the TAP is reopened by name.
    #[allow(dead_code)]
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

/// The jail's root directory for a machine.
pub fn jail_root(base: &Path, id: &str) -> PathBuf {
    base.join("firecracker")
        .join(id.replace('_', "-"))
        .join("root")
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
        let out = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&console)
            .await?;
        // Firecracker accepts only letters, digits and dashes in an instance id; its log levels
        // are Error, Warning, Info, Debug, Trace.
        let fc_id = id.replace('_', "-");
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
                cmd.arg("--id")
                    .arg(&fc_id)
                    .arg("--exec-file")
                    .arg(binary)
                    .arg("--uid")
                    .arg(j.uid.to_string())
                    .arg("--gid")
                    .arg(j.gid.to_string())
                    .arg("--chroot-base-dir")
                    .arg(&j.base)
                    .arg("--cgroup-version")
                    .arg("2")
                    .arg("--new-pid-ns");
                if j.cpus > 0 {
                    cmd.arg("--cgroup")
                        .arg(format!("cpu.max={} 100000", j.cpus as u64 * 100_000));
                }
                if j.memory_mb > 0 {
                    cmd.arg("--cgroup")
                        .arg(format!("memory.max={}", (j.memory_mb as u64) << 20));
                }
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
                    .open(&fclog)
                    .await?;
                let mut cmd = Command::new(binary);
                cmd.arg("--api-sock")
                    .arg(&api)
                    .arg("--id")
                    .arg(&fc_id)
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
        if let Some(root) = &p.chroot {
            // With a new pid namespace the jailer forks: the pid we spawned is its parent, and
            // the one that matters (to kill, to adopt) is in the file the jailer writes.
            for _ in 0..50 {
                if let Ok(text) = tokio::fs::read_to_string(root.join("firecracker.pid")).await {
                    if let Ok(pid) = text.trim().parse::<u32>() {
                        p.pid = pid;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        Ok(p)
    }

    /// The path Firecracker must be given for a file on the host: inside the chroot when
    /// jailed (hard-linked, or copied across filesystems, and readable by the jail's user).
    pub fn expose_file(&self, host: &Path, name: &str) -> Result<PathBuf> {
        let root = match &self.chroot {
            Some(r) => r,
            None => return Ok(host.to_path_buf()),
        };
        let inside = root.join(name);
        let _ = std::fs::remove_file(&inside);
        if std::fs::hard_link(host, &inside).is_err() {
            std::fs::copy(host, &inside)
                .with_context(|| format!("copy {} into the jail", host.display()))?;
        }
        let _ = std::os::unix::fs::chown(&inside, Some(self.uid), Some(self.gid));
        Ok(PathBuf::from("/").join(name))
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
        match &self.chroot {
            Some(_) => PathBuf::from("/").join(name),
            None => self.dir.join(name),
        }
    }

    /// The host path of a file Firecracker writes next to its sockets.
    pub fn outside(&self, name: &str) -> PathBuf {
        match &self.chroot {
            Some(r) => r.join(name),
            None => self.dir.join(name),
        }
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
