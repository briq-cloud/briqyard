//! Private first continuation. Observation is durable evidence, never publication authority.
use super::*;

impl Manager {
    /// Caller must not hold the entry lock. Every invocation reserves a new authority;
    /// an existing/uncertain attempt is deliberately not replayed as another launch.
    #[allow(dead_code)]
    pub(in crate::machine) async fn launch_assigned_run(
        &self,
        entry: &Arc<Entry>,
        checkpoint: bool,
    ) -> Result<RunRef> {
        self.reserve_assigned_run(entry, checkpoint).await?;
        self.boot_reserved_assigned_run(entry).await
    }

    pub(super) async fn boot_reserved_assigned_run(&self, entry: &Arc<Entry>) -> Result<RunRef> {
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        let id = entry.snapshot().id;
        let mut current: Current = self.inner.store.get(RUNS, &id)?.context("run missing")?;
        self.check_run_creation_authority(&current)?;
        self.verify_run_prelaunch_backing(&current).await?;
        anyhow::ensure!(
            !current.launch_started
                && current.record_fingerprint(&entry.snapshot())?
                    == current.record_fingerprint(&current.target)?,
            "run already attempted or controls changed"
        );
        // Persist an irreversible attempt before network/config effects or spawn. Even a
        // crash before spawn is ambiguous and cannot authorize a second process.
        let prior = current.clone();
        current.launch_started = true;
        self.persist_run_transition(entry, prior, &current)?;
        self.unplug(&id, &current.target.ip).await?;
        let tap = self.inner.net.quarantine(&id).await?;
        self.verify_run_prelaunch_backing(&current).await?;
        let rec = &current.target;
        let dir = self.inner.cfg.run_dir().join(&id);
        tokio::fs::create_dir_all(&dir).await?;
        let config_drive = dir.join("config.tar");
        match &current.mode {
            Mode::Fresh { drive_base64, .. } => {
                crate::machine::start::write_drive(
                    &config_drive,
                    &guest::base64_decode(drive_base64).map_err(|e| anyhow!(e))?,
                )?;
            }
            Mode::Checkpoint { .. } => {} // Preserve exactly the frozen CURRENT drive.
        }
        let boot = fc::Boot {
            id: id.clone(),
            dir,
            jail: self.jail_for(rec),
            vcpus: rec.size.vcpus,
            memory_mb: rec.size.memory_mb,
            kernel: self.inner.cfg.kernel.clone(),
            boot_args: self.boot_args(),
            config_drive,
            root: self.inner.zfs.device(&rec.root_dataset()).await?,
            data: Some(self.inner.zfs.device(&rec.data_dataset()).await?),
            tap,
            mac: netw::mac_for(rec.ip.parse()?),
            resume: matches!(current.mode, Mode::Checkpoint { .. }),
            memory_clone: None,
            boot_identity: Some(current.expected_boot_identity.clone()),
            disk: self.disk_rate(rec),
            disk_io: entry.disk_io.clone(),
        };
        let _turn = self.inner.boot_gate.acquire().await?;
        self.check_run_creation_authority(&current)?;
        self.verify_run_prelaunch_backing(&current).await?;
        // No ResumeFailed fallback: a different boot requires different explicit authority.
        let live = self.inner.vmm.boot(&boot).await?;
        *entry.live.lock().unwrap() = Some(live.clone());
        anyhow::ensure!(
            live.resumed == matches!(current.mode, Mode::Checkpoint { .. }),
            "launch resume mode differs"
        );
        self.verify_run_process(&current, &live)?;
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10));
        let mut first_proof = None;
        let pong = loop {
            self.verify_run_process(&current, &live)?;
            let pong = match tokio::time::timeout_at(deadline, self.inner.guest.ping(&live.vsock))
                .await?
            {
                Ok(pong) => pong,
                Err(error)
                    if first_proof.is_none()
                        && error.is::<crate::guestc::Unreachable>()
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            self.verify_run_process(&current, &live)?;
            current.check_pong(&pong)?;
            if let Some(first) = &first_proof {
                anyhow::ensure!(
                    &pong.assigned_run == first,
                    "assigned boot marker changed on the same process"
                );
            } else {
                first_proof = Some(pong.assigned_run.clone());
            }
            if pong.main_pid > 0 {
                break pong;
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "assigned main readiness timed out"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let prior = current.clone();
        current.reference.phase = Phase::Observed;
        current.target.assigned_run = Some(current.reference.clone());
        current.target.pid = live.pid;
        current.target.boot_incarnation = live.incarnation.clone();
        current.target.boot_identity = live.boot_identity.clone();
        current.observed_main_pid = pong.main_pid;
        match current.mode {
            Mode::Fresh { .. } => current.observed_guest = pong.assigned_run,
            Mode::Checkpoint {
                ref assigned_lineage,
                ..
            } => {
                if assigned_lineage.is_some() {
                    current.observed_guest = pong.assigned_run
                } else {
                    current.observed_checkpoint = Some(pong)
                }
            }
        }
        self.verify_run_process(&current, &live)?;
        self.persist_run_transition(entry, prior, &current)?;
        self.verify_run_process(&current, &live)?;
        // No watch/probes/DNS/network activation or Entry trust at this boundary.
        Ok(current.reference)
    }

    pub(super) fn persist_run_transition(
        &self,
        entry: &Entry,
        prior: Current,
        current: &Current,
    ) -> Result<()> {
        let intent = Intent {
            schema: current.schema,
            current: current.clone(),
            reader: current.reader()?,
            predecessor: Some(prior),
        };
        intent.check()?;
        entry.identity_trusted.store(false, Relaxed);
        // Cache exact target before uncertain writes; launch_assigned_run never retries an
        // already reserved machine, even if the first transition write is uncertain.
        self.inner.store.ensure_assigned_run_lifecycle_floor()?;
        // The intent is checked against the machine file at once (a guest exit settles with
        // the memory record): repair a file a failed update write left at its predecessor.
        self.repair_outstanding_update_record(&current.machine)?;
        if current.reference.phase != Phase::Settled {
            let merged = projection::preserve_advisory(&current.target, &entry.snapshot())?;
            *entry.rec.lock().unwrap() = merged;
        }
        self.inner
            .store
            .put_durable(INTENTS, &current.machine, &intent)?;
        self.reconcile_assigned_run(&intent)?;
        let merged = projection::preserve_advisory(&current.target, &entry.snapshot())?;
        *entry.rec.lock().unwrap() = merged;
        Ok(())
    }

    pub(super) fn verify_run_process(&self, current: &Current, live: &fc::Vm) -> Result<()> {
        let identity = current
            .prior
            .launch_identity
            .as_ref()
            .context("run identity missing")?;
        let incarnation = live
            .incarnation
            .as_ref()
            .context("run incarnation missing")?;
        anyhow::ensure!(
            current.launch_started
                && !*live.exited.borrow()
                && live.pid > 0
                && incarnation.pid == live.pid
                && incarnation.start_ticks > 0
                && current.prior.boot_incarnation.as_ref() != Some(incarnation)
                && incarnation.host_boot_id == current.host_boot_id
                && self.inner.vmm.host_boot_id().as_deref() == Some(current.host_boot_id.as_str())
                && live.boot_identity.as_ref() == Some(&current.expected_boot_identity)
                && self.inner.vmm.verify_process(
                    &current.machine,
                    incarnation,
                    identity.uid,
                    identity.gid
                )
                && (current.reference.phase != Phase::Observed
                    || (current.target.pid == live.pid
                        && current.target.boot_incarnation.as_ref() == Some(incarnation))),
            "assigned run actual process/credentials/boot identity unconfirmed"
        );
        Ok(())
    }
}
impl Current {
    pub(super) fn check_pong(&self, pong: &guest::Response) -> Result<()> {
        anyhow::ensure!(pong.kind == "pong", "assigned run omitted pong");
        let origin = self
            .prior
            .clone_origin
            .as_ref()
            .context("creation origin missing")?;
        anyhow::ensure!(
            pong.init_sha256 == origin.artifact.init_sha256,
            "assigned run init differs"
        );
        match &self.mode {
            Mode::Fresh {
                guest_generation,
                expected_bundle_sha256,
                ..
            } => {
                let proof = pong
                    .assigned_run
                    .as_ref()
                    .context("assigned run proof missing")?;
                proof
                    .verify(
                        guest_generation,
                        &origin.artifact.init_sha256,
                        &proof.boot_marker,
                        expected_bundle_sha256,
                    )
                    .map_err(|e| anyhow!(e))?;
                anyhow::ensure!(
                    proof.boot_marker != origin.artifact.ram_marker && pong.clone_status.is_none(),
                    "fresh run reused creation RAM lineage"
                );
            }
            Mode::Checkpoint {
                assigned_lineage: Some(proof),
                ..
            } => {
                anyhow::ensure!(
                    pong.assigned_run.as_ref() == Some(proof.as_ref())
                        && pong.clone_status.is_none(),
                    "assigned checkpoint guest lineage differs"
                );
            }
            Mode::Checkpoint {
                assigned_lineage: None,
                ..
            } => {
                anyhow::ensure!(
                    pong.assigned_run.is_none(),
                    "checkpoint changed guest lineage"
                );
                templates::sandbox::check_ack(origin, pong, &["active"])?;
            }
        }
        Ok(())
    }
}
