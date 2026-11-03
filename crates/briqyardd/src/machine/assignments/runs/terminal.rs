//! Private terminal evidence. No public watcher or automatic restart consumes this yet.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::machine) enum Disposition {
    Stopped,
    Failed,
    CheckpointAvailable,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ExitProof {
    Observed {
        incarnation: fc::Incarnation,
    },
    HostBootEnded {
        incarnation: fc::Incarnation,
        current_host_boot_id: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Lineage {
    Creation { pong: Box<guest::Response> },
    Assigned { proof: guest::AssignedRunProof },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    state: templates::ArtifactFile,
    memory: templates::ArtifactFile,
    config: templates::ArtifactFile,
    workload_sha256: String,
    root: Disk,
    data: Disk,
    boot_identity: fc::BootIdentity,
    lineage: Lineage,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settlement {
    pub disposition: Disposition,
    pub exit: ExitProof,
    pub checkpoint: Option<Checkpoint>,
}
fn workload(record: &Record) -> Result<String> {
    let origin = record
        .clone_origin
        .as_ref()
        .context("creation origin missing")?;
    let (config, files) =
        crate::machine::start::resolved_guest_config(record, origin.configure.gateway.parse()?)?;
    Ok(sha(&serde_json::to_vec(&(config, files, record.size))?))
}
impl Checkpoint {
    pub(super) fn mode(&self) -> Mode {
        let (generation, init, marker, bind, assigned_lineage) = match &self.lineage {
            Lineage::Assigned { proof } => (
                proof.generation.clone(),
                proof.init_sha256.clone(),
                proof.boot_marker.clone(),
                String::new(),
                Some(Box::new(proof.clone())),
            ),
            Lineage::Creation { pong } => {
                let status = pong.clone_status.as_ref().unwrap();
                (
                    status.identity.as_ref().unwrap().generation.clone(),
                    pong.init_sha256.clone(),
                    status.ram_marker.clone(),
                    pong.sha256.clone(),
                    None,
                )
            }
        };
        Mode::Checkpoint {
            state: self.state.clone(),
            memory: self.memory.clone(),
            config: self.config.clone(),
            saved_generation: generation,
            saved_init_sha256: init,
            saved_marker: marker,
            saved_bind_sha256: bind,
            assigned_lineage,
        }
    }
    fn check(&self, current: &Current) -> Result<()> {
        match &current.mode {
            Mode::Fresh { drive_sha256, .. } => anyhow::ensure!(
                &self.config.sha256 == drive_sha256,
                "checkpoint config differs from observed Fresh bundle"
            ),
            Mode::Checkpoint { config, .. } => anyhow::ensure!(
                &self.config == config,
                "checkpoint config differs from observed saved lineage"
            ),
        }
        anyhow::ensure!(
            self.root == current.root
                && self.data == current.data
                && self.workload_sha256 == workload(&current.target)?
                && self.boot_identity == current.expected_boot_identity,
            "terminal checkpoint workload/backing/boot differs"
        );
        match &self.lineage {
            Lineage::Assigned { proof } => anyhow::ensure!(
                current.observed_guest.as_ref() == Some(proof),
                "checkpoint lost observed assigned lineage"
            ),
            Lineage::Creation { pong } => {
                anyhow::ensure!(
                    current.observed_guest.is_none() && current.observed_checkpoint.is_some(),
                    "checkpoint relabels assigned guest as creation"
                );
                current.check_pong(pong)?;
                anyhow::ensure!(pong.main_pid > 0, "saved checkpoint main missing");
            }
        }
        for file in [&self.state, &self.memory, &self.config] {
            anyhow::ensure!(
                file.bytes > 0 && file.inode > 0 && hex_id(&file.sha256, 64),
                "checkpoint manifest incomplete"
            );
        }
        Ok(())
    }
    pub(super) async fn verify_files(&self, manager: &Manager, record: &Record) -> Result<()> {
        anyhow::ensure!(
            self.workload_sha256 == workload(record)?,
            "checkpoint CURRENT workload changed"
        );
        let (root, data) = manager.current_run_disks(record).await?;
        anyhow::ensure!(
            root == self.root && data == self.data,
            "checkpoint CURRENT disks changed"
        );
        for (path, expected) in manager.run_checkpoint_paths(record).iter().zip([
            &self.state,
            &self.memory,
            &self.config,
        ]) {
            anyhow::ensure!(
                templates::fingerprint(path)? == *expected,
                "checkpoint CURRENT files changed"
            );
        }
        Ok(())
    }
}
impl Settlement {
    pub(super) fn check(&self, current: &Current) -> Result<()> {
        anyhow::ensure!(
            current.schema == 3
                && current.reference.phase == Phase::Settled
                && current.target.pid == 0,
            "invalid terminal authority"
        );
        let saved = current
            .target
            .boot_incarnation
            .as_ref()
            .context("terminal incarnation missing")?;
        match &self.exit {
            ExitProof::Observed { incarnation } => {
                anyhow::ensure!(incarnation == saved, "terminal exit incarnation differs")
            }
            ExitProof::HostBootEnded {
                incarnation,
                current_host_boot_id,
            } => anyhow::ensure!(
                incarnation == saved
                    && fc::valid_host_boot_id(current_host_boot_id)
                    && current_host_boot_id != &saved.host_boot_id
                    && fc::valid_host_boot_id(&saved.host_boot_id),
                "terminal host exit proof differs"
            ),
        }
        anyhow::ensure!(
            matches!(self.disposition, Disposition::CheckpointAvailable)
                == self.checkpoint.is_some(),
            "terminal disposition/manifest differs"
        );
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.check(current)?;
        }
        Ok(())
    }
}
impl Manager {
    #[allow(dead_code)]
    pub(in crate::machine) async fn settle_assigned_run(
        &self,
        entry: &Arc<Entry>,
        disposition: Disposition,
    ) -> Result<RunRef> {
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        self.settle_assigned_run_locked(entry, disposition).await
    }

    pub(super) async fn settle_assigned_run_locked(
        &self,
        entry: &Arc<Entry>,
        disposition: Disposition,
    ) -> Result<RunRef> {
        let record = entry.snapshot();
        anyhow::ensure!(
            self.inner
                .store
                .get::<Intent>(INTENTS, &record.id)?
                .is_none(),
            "run intent unresolved"
        );
        let prior: Current = self
            .inner
            .store
            .get(RUNS, &record.id)?
            .context("run missing")?;
        prior.check()?;
        self.check_run_creation_authority(&prior)?;
        anyhow::ensure!(
            prior.reference.phase == Phase::Observed
                && prior.record_fingerprint(&record)? == prior.record_fingerprint(&prior.target)?,
            "only exact observed run can settle"
        );
        let reader: Reader = self
            .inner
            .store
            .get(READERS, &record.id)?
            .context("run reader missing")?;
        anyhow::ensure!(
            serde_json::to_value(reader)? == serde_json::to_value(prior.reader()?)?,
            "terminal reader differs"
        );
        self.inner.store.ensure_assigned_run_lifecycle_floor()?;
        let (root, data) = self.current_run_disks(&record).await?;
        anyhow::ensure!(
            root == prior.root && data == prior.data,
            "terminal CURRENT disks changed"
        );
        let checkpoint = if matches!(disposition, Disposition::CheckpointAvailable) {
            let live = entry
                .live
                .lock()
                .unwrap()
                .clone()
                .context("live CURRENT checkpoint source missing")?;
            self.verify_run_process(&prior, &live)?;
            let pong = self.inner.guest.ping(&live.vsock).await?;
            self.verify_run_process(&prior, &live)?;
            prior.check_pong(&pong)?;
            anyhow::ensure!(
                pong.main_pid > 0 && pong.assigned_run == prior.observed_guest,
                "checkpoint guest differs from observed lineage"
            );
            self.verify_run_config(&prior)?;
            self.inner.vmm.snapshot(&live, true).await?;
            self.verify_run_process(&prior, &live)?;
            let paths = self.run_checkpoint_paths(&record);
            let saved = Checkpoint {
                state: templates::fingerprint(&paths[0])?,
                memory: templates::fingerprint(&paths[1])?,
                config: templates::fingerprint(&paths[2])?,
                workload_sha256: workload(&record)?,
                root,
                data,
                boot_identity: prior.expected_boot_identity.clone(),
                lineage: if let Some(proof) = &prior.observed_guest {
                    Lineage::Assigned {
                        proof: proof.clone(),
                    }
                } else {
                    Lineage::Creation {
                        pong: Box::new(pong),
                    }
                },
            };
            self.inner.vmm.kill_checked(&live)?;
            let mut exited = live.exited.clone();
            tokio::time::timeout(Duration::from_secs(15), exited.wait_for(|gone| *gone)).await??;
            Some(saved)
        } else {
            None
        };
        let incarnation = prior
            .target
            .boot_incarnation
            .clone()
            .context("run incarnation missing")?;
        let host = self
            .inner
            .vmm
            .host_boot_id()
            .filter(|id| fc::valid_host_boot_id(id))
            .context("current host boot unavailable")?;
        let exit = if host != incarnation.host_boot_id {
            ExitProof::HostBootEnded {
                incarnation,
                current_host_boot_id: host,
            }
        } else {
            let live = entry
                .live
                .lock()
                .unwrap()
                .clone()
                .context("positive live exit proof missing")?;
            anyhow::ensure!(
                *live.exited.borrow()
                    && live.pid == prior.target.pid
                    && live.incarnation.as_ref() == Some(&incarnation)
                    && live.boot_identity.as_ref() == Some(&prior.expected_boot_identity),
                "exact run exit unconfirmed; charges retained"
            );
            ExitProof::Observed { incarnation }
        };
        let mut current = prior.clone();
        current.schema = 3;
        current.prior_control_sha256 = projection::fingerprint(&current.prior)?;
        current.reference.schema = 3;
        current.reference.phase = Phase::Settled;
        current.target = Box::new(record);
        current.target.assigned_run = Some(current.reference.clone());
        current.target.pid = 0;
        current.target.suspended = checkpoint.is_some();
        current.settlement = Some(Box::new(Settlement {
            disposition,
            exit,
            checkpoint,
        }));
        self.unplug(&current.machine, &current.target.ip).await?;
        self.inner.net.quarantine(&current.machine).await?;
        self.persist_run_transition(entry, prior, &current)?;
        *entry.live.lock().unwrap() = None;
        Ok(current.reference)
    }
}
