//! The client of one Firecracker's API socket.

use super::*;

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

    pub(super) async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String)> {
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

    pub(super) async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String> {
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

    pub(super) async fn put<T: Serialize>(&self, path: &str, v: &T) -> Result<()> {
        self.call("PUT", path, Some(&serde_json::to_string(v)?))
            .await
            .map(|_| ())
    }

    pub(super) async fn patch<T: Serialize>(&self, path: &str, v: &T) -> Result<()> {
        self.call("PATCH", path, Some(&serde_json::to_string(v)?))
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

    /// `cache` is "Unsafe" (no flush) or "Writeback" (a guest flush is a host fsync); `rate`
    /// limits what the guest does on it. A writable drive takes the guest's discards (v1.17,
    /// the default `Sync` engine): the blocks a guest frees go back to the pool (ADR 0037).
    pub async fn drive(
        &self,
        id: &str,
        path: &Path,
        root: bool,
        read_only: bool,
        cache: &str,
        rate: Option<&DiskRate>,
    ) -> Result<()> {
        let mut d = json!({"drive_id": id, "path_on_host": path, "is_root_device": root, "is_read_only": read_only, "cache_type": cache});
        if !read_only {
            d["discard"] = json!(true);
        }
        if let Some(r) = rate {
            d["rate_limiter"] = r.rate_limiter();
        }
        self.put(&format!("/drives/{id}"), &d).await
    }

    /// A running machine's drive takes these limits now, its buckets full.
    pub async fn drive_rate(&self, id: &str, rate: &DiskRate) -> Result<()> {
        self.patch(
            &format!("/drives/{id}"),
            &json!({"drive_id": id, "rate_limiter": rate.rate_limiter()}),
        )
        .await
    }

    /// Where Firecracker writes its metrics, a line a minute (before the boot or the load).
    pub async fn metrics(&self, path: &Path) -> Result<()> {
        self.put("/metrics", &json!({"metrics_path": path})).await
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

    /// A full snapshot (VM state and memory) of a paused machine. `sync`: the files are
    /// fsynced before the call returns (`sync_snapshot_files`, v1.17); otherwise they are in
    /// the page cache only, and the caller syncs them before anything names them (ADR 0037).
    pub async fn snapshot_create(&self, state: &Path, mem: &Path, sync: bool) -> Result<()> {
        self.put(
            "/snapshot/create",
            &json!({"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem, "sync_snapshot_files": sync}),
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
