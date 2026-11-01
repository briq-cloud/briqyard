use super::*;

impl Manager {
    pub(super) async fn current_run_disks(&self, record: &Record) -> Result<(Disk, Disk)> {
        anyhow::ensure!(record.volume.is_some(), "assigned work disk missing");
        let root = record.root_dataset();
        let data = record.data_dataset();
        let root = Disk {
            guid: self.inner.zfs.guid(&root).await?,
            dataset: root,
        };
        let data = Disk {
            guid: self.inner.zfs.guid(&data).await?,
            dataset: data,
        };
        anyhow::ensure!(
            root.guid != data.guid,
            "root and data identify the same dataset"
        );
        Ok((root, data))
    }

    pub(super) async fn plan_assigned_run(
        &self,
        entry: &Entry,
        checkpoint: bool,
    ) -> Result<Intent> {
        let prior = entry.snapshot();
        anyhow::ensure!(
            prior.assigned_run.is_none() && prior.pending.is_none() && prior.restoring.is_none(),
            "pending/current run or update intent requires explicit continuation integration"
        );
        let origin = self.settled_assigned_origin(&prior)?;
        self.check_assigned_bound_record(&prior)?;
        anyhow::ensure!(
            origin.stage == templates::CloneStage::Active,
            "only a completed tenant can continue"
        );
        let host_boot_id = self
            .inner
            .vmm
            .host_boot_id()
            .filter(|boot| fc::valid_host_boot_id(boot))
            .context("current host boot identity unavailable")?;
        let old = prior
            .boot_incarnation
            .as_ref()
            .context("prior run incarnation missing")?;
        let boot_ended =
            fc::valid_host_boot_id(&old.host_boot_id) && old.host_boot_id != host_boot_id;
        let explicit_exit = origin.mapping_exited
            && prior.pid == 0
            && matches!(prior.state.as_str(), state::STOPPED | state::ERROR);
        let live = entry.live.lock().unwrap().clone();
        anyhow::ensure!(
            boot_ended || (explicit_exit && live.as_ref().is_none_or(|live| *live.exited.borrow())),
            "old process exit is not positively established; all charges retained"
        );
        anyhow::ensure!(
            self.inner.store.get::<Current>(RUNS, &prior.id)?.is_none()
                && self
                    .inner
                    .store
                    .get::<Intent>(INTENTS, &prior.id)?
                    .is_none()
                && self
                    .inner
                    .store
                    .get::<Reader>(READERS, &prior.id)?
                    .is_none(),
            "run authority already exists"
        );
        let (root, data) = self.current_run_disks(&prior).await?;
        let expected_boot_identity = if checkpoint {
            anyhow::ensure!(
                prior.suspended && self.resume_compatible(&prior),
                "current checkpoint is absent or incompatible"
            );
            prior
                .boot_identity
                .clone()
                .context("checkpoint boot identity missing")?
        } else {
            self.inner
                .vmm
                .boot_identity(self.inner.cfg.balloon.enabled)
                .context("fresh boot identity unavailable")?
        };
        anyhow::ensure!(
            expected_boot_identity.schema == 1,
            "run boot identity schema unsupported"
        );
        let mode = if checkpoint {
            let paths = self.run_checkpoint_paths(&prior);
            Mode::Checkpoint {
                state: templates::fingerprint(&paths[0])?,
                memory: templates::fingerprint(&paths[1])?,
                config: templates::fingerprint(&paths[2])?,
                saved_generation: origin.configure.generation.clone(),
                saved_init_sha256: origin.artifact.init_sha256.clone(),
                saved_marker: origin.artifact.ram_marker.clone(),
                saved_bind_sha256: origin
                    .sandbox
                    .as_ref()
                    .and_then(|binding| binding.ack_sha256.clone())
                    .context("saved bind ACK missing")?,
            }
        } else {
            let guest_generation = generation()?;
            let namespace = self
                .namespace_of(&prior.namespace)
                .context("run namespace missing")?;
            let (mut config, files) =
                crate::machine::start::resolved_guest_config(&prior, namespace.subnet.gateway())?;
            config.assigned_run_generation = Some(guest_generation.clone());
            let (drive, expected_bundle_sha256) =
                crate::machine::start::assigned_config_drive(&config, &files)?;
            Mode::Fresh {
                guest_generation,
                drive_sha256: sha(&drive),
                drive_base64: guest::base64_encode(&drive),
                expected_bundle_sha256,
            }
        };
        let binding = origin.sandbox.as_ref().unwrap();
        let receipt = self
            .inner
            .store
            .get::<Receipt>(
                super::super::REQUESTS,
                &key(&prior.namespace, &binding.request_id),
            )?
            .context("durable creation receipt missing")?;
        let creation_reader = self
            .inner
            .store
            .get(templates::READERS, &prior.id)?
            .context("creation reader missing")?;
        let reference = RunRef {
            schema: 1,
            sequence: 1,
            phase: Phase::Reserved,
        };
        let mut target = prior.clone();
        target.assigned_run = Some(reference.clone());
        target.state = state::STARTING.into();
        target.pid = 0;
        target.suspended = checkpoint;
        target.clone_origin.as_mut().unwrap().mapping_exited = true;
        let current = Current {
            schema: 1,
            machine: prior.id.clone(),
            host_generation: generation()?,
            reference,
            receipt,
            prior_control_sha256: launch_identity::record_fingerprint(&prior)?,
            prior,
            target,
            creation_reader,
            root,
            data,
            host_boot_id,
            expected_boot_identity,
            mode,
            observed_guest: None,
        };
        let reader = current.reader()?;
        let intent = Intent {
            schema: 1,
            current,
            reader,
        };
        intent.check()?;
        Ok(intent)
    }

    pub(super) fn run_checkpoint_paths(&self, record: &Record) -> [PathBuf; 3] {
        let dir = self.inner.cfg.run_dir().join(&record.id);
        let jail = self.jail_for(record).map(|jail| jail.base);
        let [state, memory] = fc::snapshot_files(&dir, jail.as_deref(), &record.id);
        [state, memory, dir.join("config.tar")]
    }
}

impl Current {
    pub(super) fn check(&self) -> Result<()> {
        self.receipt.check()?;
        anyhow::ensure!(
            self.schema == 1
                && self.reference.schema == 1
                && self.reference.sequence == 1
                && hex_id(&self.host_generation, 64)
                && fc::valid_host_boot_id(&self.host_boot_id)
                && self.expected_boot_identity.schema == 1
                && self.machine == self.prior.id
                && self.receipt.machine == self.machine
                && self.target.id == self.machine
                && self.prior.assigned_run.is_none()
                && self.prior.pending.is_none()
                && self.prior.restoring.is_none()
                && self.prior_control_sha256 == launch_identity::record_fingerprint(&self.prior)?,
            "invalid exact run authority"
        );
        let origin = self
            .prior
            .clone_origin
            .as_ref()
            .context("creation provenance missing")?;
        let binding = origin
            .sandbox
            .as_ref()
            .context("creation binding missing")?;
        anyhow::ensure!(
            origin.stage == templates::CloneStage::Active
                && binding.request_id == self.receipt.request_id
                && binding.create_sha256 == self.receipt.create_sha256
                && self.prior.namespace == self.receipt.namespace
                && self.root.dataset == self.prior.root_dataset()
                && self.data.dataset == self.prior.data_dataset()
                && self.root.guid > 0
                && self.data.guid > 0
                && self.root.guid != self.data.guid,
            "run changes creation authority or current backing identity"
        );
        let old = self
            .prior
            .boot_incarnation
            .as_ref()
            .context("prior incarnation missing")?;
        anyhow::ensure!(
            (fc::valid_host_boot_id(&old.host_boot_id) && old.host_boot_id != self.host_boot_id)
                || (origin.mapping_exited
                    && self.prior.pid == 0
                    && matches!(self.prior.state.as_str(), state::STOPPED | state::ERROR)),
            "journal lacks positive old-process exit evidence"
        );
        if self.reference.phase == Phase::Reserved {
            anyhow::ensure!(
                self.target.pid == 0,
                "reserved run already claims a process"
            );
        }
        launch_identity::check_launch_pair(&self.prior, Some(&self.creation_reader))?;
        let mut projected = self.prior.clone();
        projected.assigned_run = Some(self.reference.clone());
        projected.state = state::STARTING.into();
        projected.pid = 0;
        projected.suspended = matches!(self.mode, Mode::Checkpoint { .. });
        projected.clone_origin.as_mut().unwrap().mapping_exited = true;
        if self.reference.phase == Phase::Observed {
            anyhow::ensure!(
                self.target.pid > 0
                    && self.target.boot_incarnation != self.prior.boot_incarnation
                    && self
                        .target
                        .boot_incarnation
                        .as_ref()
                        .is_some_and(|inc| inc.pid == self.target.pid
                            && inc.start_ticks > 0
                            && inc.host_boot_id == self.host_boot_id)
                    && self.target.boot_identity.as_ref() == Some(&self.expected_boot_identity),
                "observed run process evidence differs"
            );
            projected.boot_incarnation = self.target.boot_incarnation.clone();
            projected.boot_identity = self.target.boot_identity.clone();
            projected.pid = self.target.pid;
        }
        anyhow::ensure!(
            launch_identity::record_fingerprint(&projected)?
                == launch_identity::record_fingerprint(&self.target)?
                && self.target.assigned_run.as_ref() == Some(&self.reference),
            "run mutates frozen workload/history or pending intent"
        );
        match &self.mode {
            Mode::Fresh {
                guest_generation,
                drive_base64,
                drive_sha256,
                expected_bundle_sha256,
            } => {
                anyhow::ensure!(
                    hex_id(guest_generation, 64)
                        && guest_generation != &self.host_generation
                        && hex_id(expected_bundle_sha256, 64),
                    "invalid fresh guest generation or bundle"
                );
                let drive = guest::base64_decode(drive_base64).map_err(|error| anyhow!(error))?;
                anyhow::ensure!(sha(&drive) == *drive_sha256, "frozen drive bytes changed");
                let (config, files) = parse_drive(&drive)?;
                anyhow::ensure!(
                    config.assigned_run_generation.as_ref() == Some(guest_generation)
                        && config.template_profile.is_none(),
                    "fresh run is not its ordinary guest generation"
                );
                let gateway = origin.configure.gateway.parse()?;
                let (mut expected, expected_files) =
                    crate::machine::start::resolved_guest_config(&self.prior, gateway)?;
                expected.assigned_run_generation = Some(guest_generation.clone());
                anyhow::ensure!(
                    serde_json::to_value(&config)? == serde_json::to_value(expected)?
                        && files == expected_files,
                    "frozen drive differs from exact resolved current workload/files"
                );
                let measured = guest::boot_bundle_fingerprint_bytes(&config, &files)
                    .map_err(|error| anyhow!(error))?;
                anyhow::ensure!(
                    sha(&measured) == *expected_bundle_sha256,
                    "frozen drive/config evidence differs"
                );
                if let Some(proof) = &self.observed_guest {
                    proof.validate().map_err(|error| anyhow!(error))?;
                    anyhow::ensure!(
                        proof.generation == *guest_generation
                            && proof.boot_bundle_sha256 == *expected_bundle_sha256
                            && proof.init_sha256 == origin.artifact.init_sha256,
                        "observed guest tuple differs from expected evidence"
                    );
                }
            }
            Mode::Checkpoint {
                state,
                memory,
                config,
                saved_generation,
                saved_init_sha256,
                saved_marker,
                saved_bind_sha256,
            } => {
                anyhow::ensure!(
                    self.prior.suspended
                        && self.prior.boot_identity.as_ref() == Some(&self.expected_boot_identity)
                        && saved_generation == &origin.configure.generation
                        && saved_init_sha256 == &origin.artifact.init_sha256
                        && saved_marker == &origin.artifact.ram_marker
                        && Some(saved_bind_sha256) == binding.ack_sha256.as_ref()
                        && hex_id(saved_marker, 32)
                        && hex_id(saved_bind_sha256, 64)
                        && self.observed_guest.is_none(),
                    "checkpoint relabels or loses its saved creation lineage"
                );
                for file in [state, memory, config] {
                    anyhow::ensure!(
                        file.bytes > 0 && file.inode > 0 && hex_id(&file.sha256, 64),
                        "checkpoint file evidence missing"
                    );
                }
            }
        }
        anyhow::ensure!(
            self.reference.phase == Phase::Observed || self.observed_guest.is_none(),
            "reserved run cannot claim guest observation"
        );
        Ok(())
    }
    pub(super) fn reader(&self) -> Result<Reader> {
        Ok(Reader {
            schema: 1,
            machine: self.machine.clone(),
            host_generation: self.host_generation.clone(),
            reference: self.reference.clone(),
            current_sha256: sha(&serde_json::to_vec(self)?),
            root: self.root.clone(),
            data: self.data.clone(),
            backing: if matches!(self.mode, Mode::Fresh { .. }) {
                "current_disks"
            } else {
                "current_checkpoint"
            }
            .into(),
        })
    }
}
impl Intent {
    pub(super) fn check(&self) -> Result<()> {
        self.current.check()?;
        anyhow::ensure!(
            self.schema == 1
                && serde_json::to_value(&self.reader)?
                    == serde_json::to_value(self.current.reader()?)?,
            "run reader differs from current authority"
        );
        Ok(())
    }
}

pub(super) fn parse_drive(
    bytes: &[u8],
) -> Result<(guest::Config, crate::machine::start::GuestBootFiles)> {
    use std::io::Read;
    let mut archive = tar::Archive::new(bytes);
    let mut config = None;
    let mut files = Vec::new();
    for item in archive.entries()? {
        let mut item = item?;
        anyhow::ensure!(
            item.header().entry_type().is_file(),
            "non-file config drive entry"
        );
        let path = item.path()?.to_string_lossy().into_owned();
        let mode = item.header().mode()?;
        let mut data = Vec::new();
        item.read_to_end(&mut data)?;
        if path == guest::CONFIG_NAME {
            anyhow::ensure!(
                config.is_none() && files.is_empty(),
                "config drive ordering or duplicate config differs"
            );
            config = Some(serde_json::from_slice(&data)?);
        } else {
            let path = path
                .strip_prefix(guest::FILES_PREFIX)
                .context("unexpected config drive entry")?;
            files.push((format!("/{path}"), mode, data));
        }
    }
    Ok((config.context("config drive config missing")?, files))
}
