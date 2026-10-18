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

/// One running Firecracker.
#[allow(dead_code)] // dir, api and console are kept for operators and tests
pub struct Process {
    pub dir: PathBuf,
    pub api: PathBuf,
    pub vsock: PathBuf,
    pub console: PathBuf,
    pub client: Client,
    child: Child,
    pid: u32,
    done: tokio::sync::watch::Receiver<bool>,
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
    pub async fn start(binary: &Path, id: &str, dir: &Path, pci: bool) -> Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let (api, vsock, console, fclog) = paths(dir);
        let _ = tokio::fs::remove_file(&api).await;
        let _ = tokio::fs::remove_file(&vsock).await;
        let out = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&console)
            .await?;
        let _ = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&fclog)
            .await?;
        // Firecracker accepts only letters, digits and dashes in an instance id; its log levels
        // are Error, Warning, Info, Debug, Trace.
        let fc_id = id.replace('_', "-");
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
            child,
            pid,
            done: rx,
        };
        if let Err(e) = p.client.wait_api(Duration::from_secs(10)).await {
            p.kill();
            return Err(e);
        }
        Ok(p)
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
