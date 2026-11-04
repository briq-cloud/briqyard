//! Quarantined reconstruction of assigned VMM ownership; never a cold-start fallback.
use super::*;

impl Manager {
    fn assigned_process_proof(&self, record: &Record) -> Result<()> {
        self.validate_launch_record(record)?;
        let identity = record
            .launch_identity
            .as_ref()
            .context("launch identity missing")?;
        self.check_durable_launch_hold(&record.id, identity)?;
        let saved = record
            .boot_incarnation
            .as_ref()
            .context("saved incarnation missing")?;
        anyhow::ensure!(
            record.pid != 0
                && record.pid == saved.pid
                && self.inner.vmm.host_boot_id().as_deref() == Some(saved.host_boot_id.as_str())
                && self
                    .inner
                    .vmm
                    .verify_process(&record.id, saved, identity.uid, identity.gid),
            "original assigned process is unconfirmed"
        );
        Ok(())
    }

    /// Dispatch every launch-identity record before legacy incomplete-clone settlement.
    /// Failure retains reservations/backing; no PID absence or API failure proves exit.
    pub(in crate::machine) async fn recover_assigned_launch(&self, entry: &Arc<Entry>) -> bool {
        let _turn = entry.lock.lock().await;
        entry.identity_trusted.store(false, Relaxed);
        *entry.live.lock().unwrap() = None;
        let result = self.adopt_assigned_quarantined(entry).await;
        if let Err(error) = result {
            let _ = self.inner.net.quarantine(&entry.snapshot().id).await;
            tracing::warn!(machine = entry.snapshot().id, %error, "assigned adoption withheld; full reservation and backing retained");
            return false;
        }
        true
    }

    async fn adopt_assigned_quarantined(&self, entry: &Arc<Entry>) -> Result<()> {
        let record = entry.snapshot();
        self.inner.net.quarantine(&record.id).await?;
        let mut origin = self.settled_assigned_origin(&record)?;
        anyhow::ensure!(
            matches!(record.state.as_str(), state::STARTING | state::RUNNING)
                && !origin.mapping_exited
                && (record.state != state::RUNNING
                    || origin.stage == templates::CloneStage::Active),
            "assigned stopped, exited or contradictory state is not restartable"
        );
        let expected = &origin.artifact.boot_identity;
        anyhow::ensure!(
            origin.artifact.schema == 1
                && expected.known()
                && record.boot_identity.as_ref() == Some(expected),
            "assigned sealed boot identity is unavailable"
        );
        self.assigned_process_proof(&record)?;
        let dir = self.inner.cfg.run_dir().join(&record.id);
        let jail = self
            .jail_for(&record)
            .context("assigned launch requires its immutable jail")?;
        let paused = self
            .inner
            .vmm
            .adopt_paused(
                &record.id,
                &dir,
                Some(&jail),
                record.pid,
                entry.disk_io.clone(),
            )
            .await;
        self.assigned_process_proof(&record)?;
        let mut vm = match paused {
            Some(vm) => vm,
            None => self
                .inner
                .vmm
                .adopt(
                    &record.id,
                    &dir,
                    Some(&jail),
                    record.pid,
                    entry.disk_io.clone(),
                )
                .await
                .context("actual assigned VMM state is unavailable")?,
        };
        self.assigned_process_proof(&record)?;
        anyhow::ensure!(
            vm.pid == record.pid
                && vm.incarnation == record.boot_incarnation
                && !*vm.exited.borrow(),
            "adopted handle differs from original incarnation"
        );
        let observed_matches = match vm.boot_identity.as_ref() {
            None => expected.device_profile == fc::LEGACY_PROFILE,
            Some(observed) => {
                observed == &fc::BootIdentity::ambiguous(fc::REPORTING_PROFILE)
                    && expected.device_profile == fc::REPORTING_PROFILE
            }
        };
        anyhow::ensure!(
            observed_matches,
            "assigned observed device profile is unknown or contradictory"
        );
        // This is a LOCAL provisional handle, still quarantined and unpublished. Saved
        // artifact identity alone cannot set Entry trust or authorize ordinary operations.
        vm.boot_identity = Some(expected.clone());
        self.verify_live_launch(entry, &vm)?;
        if origin.stage == templates::CloneStage::UnboundPaused {
            self.freeze_assigned_configuration(entry, origin)?;
            origin = self.settled_assigned_origin(&entry.snapshot())?;
        }
        if vm.resumed {
            self.verify_live_launch(entry, &vm)?;
            self.inner.vmm.resume_assigned(&vm).await?;
            self.verify_live_launch(entry, &vm)?;
        }
        let pong = self.inner.guest.ping(&vm.vsock).await?;
        self.assigned_process_proof(&entry.snapshot())?;
        self.check_assigned_continuity(&entry.snapshot(), &origin, &pong)?;
        self.verify_live_launch(entry, &vm)?;
        if origin.stage == templates::CloneStage::Active {
            // Dependencies share the startup publication fence: source continuity cannot
            // authorize a via policy that exposes another unverified assigned target.
            let approved: Vec<_> = self
                .inner
                .machines
                .lock()
                .unwrap()
                .values()
                .filter_map(|other| {
                    let record = other.snapshot();
                    self.assignment_publication_allowed(
                        &record,
                        other.identity_trusted.load(Relaxed),
                    )
                    .then_some(record)
                })
                .collect();
            self.policy_for_records(&entry.snapshot(), &approved)?;
            // Fresh continuity precedes rebuilding any destination network/readiness.
            self.inner.net.count(&record.ip).await?;
            self.activate_clone_network(&entry.snapshot()).await?;
        }
        self.verify_live_launch(entry, &vm)?;
        *entry.live.lock().unwrap() = Some(vm.clone());
        entry.identity_trusted.store(true, Relaxed);
        *entry.stop_req.lock().unwrap() = None;
        if origin.stage == templates::CloneStage::Active {
            entry.set_state(state::RUNNING, |record| {
                record.init_version = pong.version;
                None
            });
            if let Err(error) = self.save(entry) {
                entry.identity_trusted.store(false, Relaxed);
                *entry.live.lock().unwrap() = None;
                let _ = self.inner.net.quarantine(&record.id).await;
                return Err(error);
            }
            let (_, _, generation) = self.reset_probes(entry);
            self.spawn_probes(entry, &vm, generation, false);
            if let Some(namespace) = self.namespace_of(&record.namespace) {
                self.refresh_dns(&namespace);
            }
        }
        self.watch(entry, &vm);
        Ok(())
    }

    fn check_assigned_continuity(
        &self,
        record: &Record,
        origin: &templates::CloneOrigin,
        pong: &guest::Response,
    ) -> Result<()> {
        let status = pong
            .clone_status
            .as_ref()
            .context("assigned guest omitted continuity status")?;
        anyhow::ensure!(
            pong.kind == "pong"
                && pong.init_sha256 == origin.artifact.init_sha256
                && status.protocol == 1
                && status.profile == guest::SANDBOX_READY_V1
                && status.ram_marker == origin.artifact.ram_marker,
            "assigned guest continuity differs from sealed init or RAM marker"
        );
        match origin.stage {
            templates::CloneStage::Configuring => {
                anyhow::ensure!(pong.main_pid == 0, "Configuring guest already has main");
                let binding = origin
                    .sandbox
                    .as_ref()
                    .context("assignment binding missing")?;
                let bind = binding
                    .bind
                    .as_ref()
                    .context("frozen Configuring payload missing")?;
                anyhow::ensure!(
                    bind.fingerprint_bytes()?
                        == templates::sandbox::destination_bind(record, origin)?
                            .fingerprint_bytes()?,
                    "Configuring payload differs"
                );
                match status.stage.as_str() {
                    "builder" => {
                        anyhow::ensure!(status.identity.is_none(), "builder has a tenant identity")
                    }
                    "destination_done" => {
                        templates::sandbox::check_ack(origin, pong, &["destination_done"])?
                    }
                    _ => anyhow::bail!("Configuring guest crossed unauthorized activation"),
                }
            }
            templates::CloneStage::IdentityDone | templates::CloneStage::Active => {
                self.check_assigned_bound_record(record)?;
                let allowed = if origin.stage == templates::CloneStage::Active {
                    &["active"][..]
                } else {
                    &["destination_done", "activating", "active"][..]
                };
                templates::sandbox::check_ack(origin, pong, allowed)?;
                anyhow::ensure!(
                    match status.stage.as_str() {
                        "active" => pong.main_pid > 0,
                        "destination_done" | "activating" => pong.main_pid == 0,
                        _ => false,
                    },
                    "assigned guest stage/main PID contradicts durable evidence"
                );
            }
            _ => anyhow::bail!("assigned stage has no adoption contract"),
        }
        Ok(())
    }
}
