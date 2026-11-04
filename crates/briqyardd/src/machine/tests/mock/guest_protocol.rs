use super::*;
#[async_trait::async_trait]
impl guestc::Guest for Mock {
    async fn fs_sync(&self, vsock: &Path) -> Result<()> {
        self.record(format!("fs_sync {}", vsock.display()));
        match self.fs_sync_fault.load(Relaxed) {
            1 => Err(guestc::UnknownOp {
                op: "fs_sync".into(),
                init: String::new(),
            }
            .into()),
            2 => Err(anyhow!("sync failed")),
            3 => std::future::pending().await,
            _ => Ok(()),
        }
    }

    async fn destination_control(
        &self,
        vsock: &Path,
        request: guest::Request,
    ) -> Result<guest::Response> {
        anyhow::ensure!(
            !self.destination_refuse.load(Relaxed),
            "injected destination response loss"
        );
        let status = if request.op == "destination_bind_v1" {
            self.record(format!("destination_bind_v1 {}", vsock.display()));
            let bind = request
                .destination_bind
                .context("missing destination bind")?;
            bind.validate().map_err(|e| anyhow!(e))?;
            let mut requests = self.destination_requests.lock().unwrap();
            let mut statuses = self.clone_status.lock().unwrap();
            let status = statuses.get_mut(vsock).context("sandbox barrier missing")?;
            if let Some(previous) = requests.get(vsock) {
                anyhow::ensure!(
                    previous.fingerprint_bytes()? == bind.fingerprint_bytes()?,
                    "sandbox destination replay differs"
                );
                let status = status.clone();
                drop(statuses);
                drop(requests);
                return Ok(guest::Response {
                    clone_status: Some(status),
                    sha256: self.destination_hash(vsock)?,
                    ..guest::Response::new("ok")
                });
            }
            anyhow::ensure!(
                status.profile == guest::SANDBOX_READY_V1 && status.stage == "builder",
                "sandbox barrier unavailable"
            );
            requests.insert(vsock.into(), bind.clone());
            status.identity = Some(guest::CloneIdentity {
                generation: bind.identity.generation,
                hostname: bind.identity.hostname,
                ip: bind.identity.ip,
                mac: bind.identity.mac,
                machine_id: "0123456789abcdef0123456789abcdef".into(),
            });
            status.stage = "destination_done".into();
            status.clone()
        } else {
            self.clone_control(vsock, request).await?
        };
        anyhow::ensure!(
            !self.destination_ack_loss.swap(false, Relaxed),
            "injected completed bind ACK loss"
        );
        let sha256 = self.destination_hash(vsock)?;
        Ok(guest::Response {
            clone_status: Some(status),
            sha256,
            ..guest::Response::new("ok")
        })
    }

    async fn clone_control(
        &self,
        vsock: &Path,
        request: guest::Request,
    ) -> Result<guest::CloneStatus> {
        self.record(format!("{} {}", request.op, vsock.display()));
        let mut statuses = self.clone_status.lock().unwrap();
        let status = statuses
            .get_mut(vsock)
            .ok_or_else(|| anyhow!("no clone protocol"))?;
        match request.op.as_str() {
            "clone_configure_v1" => {
                let c = request
                    .clone_configure
                    .ok_or_else(|| anyhow!("missing configuration"))?;
                c.validate().map_err(|e| anyhow!(e))?;
                anyhow::ensure!(status.stage == "builder", "clone barrier unavailable");
                status.identity = Some(guest::CloneIdentity {
                    generation: c.generation,
                    hostname: c.hostname,
                    ip: c.ip,
                    mac: c.mac,
                    machine_id: "0123456789abcdef0123456789abcdef".into(),
                });
                status.stage = "identity_done".into();
            }
            "clone_activate_v1" => {
                anyhow::ensure!(
                    status
                        .identity
                        .as_ref()
                        .is_some_and(|i| i.generation == request.clone_generation),
                    "generation conflict"
                );
                status.stage = "active".into();
            }
            _ => return Err(anyhow!("unsupported clone op")),
        }
        Ok(status.clone())
    }
    async fn ping(&self, vsock: &Path) -> Result<guest::Response> {
        let (pid, _, exited) = self.proc_at(vsock)?;
        self.record(format!("ping {pid}"));
        if *exited.borrow() {
            return Err(guestc::Unreachable("guest exited".into()).into());
        }
        let clone_status = self.clone_status.lock().unwrap().get(vsock).cloned();
        let assigned_run = self.run_proofs.lock().unwrap().get(vsock).cloned();
        let mut response = guest::Response {
            kind: "pong".into(),
            version: self.init_version.lock().unwrap().clone(),
            file_stream_v1: self.file_stream_v1.load(Relaxed),
            exec_stream_v1: self.exec_stream_v1.load(Relaxed),
            assigned_run: assigned_run.clone(),
            main_pid: if assigned_run.is_some() {
                42
            } else {
                clone_status
                    .as_ref()
                    .filter(|s| s.stage == "active")
                    .map_or(0, |_| 42)
            },
            sha256: self.destination_hash(vsock)?,
            clone_status,
            init_sha256: self
                .init_digests
                .lock()
                .unwrap()
                .get(vsock)
                .cloned()
                .unwrap_or_default(),
            ..Default::default()
        };
        match self.run_fault.load(Relaxed) {
            1 => {
                if let Some(proof) = &mut response.assigned_run {
                    proof.boot_bundle_sha256 = "f".repeat(64);
                }
            }
            2 => {
                if let Some(proof) = &mut response.assigned_run {
                    proof.boot_marker = "0123456789abcdef0123456789abcdef".into();
                }
            }
            3 => response.init_sha256 = "f".repeat(64),
            4 => {
                self.procs
                    .lock()
                    .unwrap()
                    .iter_mut()
                    .find(|p| p.pid == pid)
                    .unwrap()
                    .uid += 1
            }
            5 => anyhow::bail!("injected lost run observation"),
            7 => response.sha256 = "f".repeat(64),
            8 => {
                response.main_pid = 0;
                self.run_fault.store(0, Relaxed);
            }
            9 => {
                response.main_pid = 0;
                self.run_fault.store(10, Relaxed);
            }
            10 => {
                if let Some(proof) = &mut response.assigned_run {
                    proof.boot_marker = "fedcba9876543210fedcba9876543210".into();
                }
            }
            _ => {}
        }
        Ok(response)
    }

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
    async fn exec_stream_v1(
        &self,
        vsock: &Path,
        req: guest::Request,
    ) -> Result<Box<dyn guestc::Conn>> {
        anyhow::ensure!(req.op == "exec_stream_v1", "distinct operation required");
        self.session(vsock, req).await
    }
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

impl Mock {
    fn destination_hash(&self, vsock: &Path) -> Result<String> {
        if self.destination_bad_ack.load(Relaxed) {
            return Ok("wrong".into());
        }
        self.destination_requests
            .lock()
            .unwrap()
            .get(vsock)
            .map(crate::machine::templates::sandbox::binding_hash)
            .transpose()
            .map(|v| v.unwrap_or_default())
    }
}
