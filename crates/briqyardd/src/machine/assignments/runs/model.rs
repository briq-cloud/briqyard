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
            prior.pending.is_none() && prior.restoring.is_none(),
            "pending/current run or update intent requires explicit continuation integration"
        );
        let previous = self.inner.store.get::<Current>(RUNS, &prior.id)?;
        let origin = if let Some(previous) = &previous {
            previous.check()?;
            anyhow::ensure!(
                previous.reference.phase == Phase::Settled
                    && previous.record_fingerprint(&prior)?
                        == previous.record_fingerprint(&previous.target)?,
                "previous run is not exactly Settled"
            );
            self.check_run_creation_authority(previous)?;
            prior
                .clone_origin
                .clone()
                .context("creation origin missing")?
        } else {
            self.check_assigned_bound_record(&prior)?;
            self.settled_assigned_origin(&prior)?
        };
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
            previous.is_some()
                || boot_ended
                || (explicit_exit && live.as_ref().is_none_or(|live| *live.exited.borrow())),
            "old process exit is not positively established; all charges retained"
        );
        anyhow::ensure!(
            self.inner
                .store
                .get::<Intent>(INTENTS, &prior.id)?
                .is_none(),
            "pending run intent"
        );
        let reader = self.inner.store.get::<Reader>(READERS, &prior.id)?;
        anyhow::ensure!(
            match (&previous, reader) {
                (None, None) => prior.assigned_run.is_none(),
                (Some(old), Some(reader)) =>
                    serde_json::to_value(reader)? == serde_json::to_value(old.reader()?)?,
                _ => false,
            },
            "run reader/source differs"
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
            expected_boot_identity.known(),
            "run boot identity schema unsupported"
        );
        let mode = if let (true, Some(previous)) = (checkpoint, previous.as_ref()) {
            let saved = previous
                .settlement
                .as_ref()
                .and_then(|s| s.checkpoint.as_ref())
                .context("settled CURRENT checkpoint missing")?;
            saved.verify_files(self, &prior).await?;
            saved.mode()
        } else if checkpoint {
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
                assigned_lineage: None,
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
            schema: 3,
            sequence: previous.as_ref().map_or(Ok(1), |old| {
                old.reference
                    .sequence
                    .checked_add(1)
                    .context("run sequence exhausted")
            })?,
            phase: Phase::Reserved,
        };
        let mut target = prior.clone();
        target.assigned_run = Some(reference.clone());
        target.state = state::STARTING.into();
        target.pid = 0;
        target.suspended = checkpoint;
        target.clone_origin.as_mut().unwrap().mapping_exited = true;
        let current = Current {
            schema: 3,
            machine: prior.id.clone(),
            host_generation: generation()?,
            reference,
            receipt,
            prior_control_sha256: projection::fingerprint(&prior)?,
            prior: Box::new(prior),
            target: Box::new(target),
            creation_reader,
            root,
            data,
            host_boot_id,
            expected_boot_identity,
            mode,
            observed_guest: None,
            launch_started: false,
            observed_main_pid: 0,
            observed_checkpoint: None,
            previous_run_sha256: previous
                .as_ref()
                .map(Current::authority_sha256)
                .transpose()?,
            settlement: None,
        };
        let reader = current.reader()?;
        let intent = Intent {
            schema: 3,
            current,
            reader,
            predecessor: previous,
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
            matches!(self.schema, 1 | 3)
                && self.reference.schema == self.schema
                && self.reference.sequence > 0
                && hex_id(&self.host_generation, 64)
                && fc::valid_host_boot_id(&self.host_boot_id)
                && self.expected_boot_identity.known()
                && self.machine == self.prior.id
                && self.receipt.machine == self.machine
                && self.target.id == self.machine
                && self.prior.pending.is_none()
                && self.prior.restoring.is_none()
                && self.prior_control_sha256 == self.record_fingerprint(&self.prior)?,
            "invalid exact run authority"
        );
        match (&self.prior.assigned_run, &self.previous_run_sha256) {
            (None, None) => {
                anyhow::ensure!(self.reference.sequence == 1, "creation sequence differs")
            }
            (Some(old), Some(hash)) => anyhow::ensure!(
                self.schema == 3
                    && old.schema == 3
                    && old.phase == Phase::Settled
                    && old.sequence.checked_add(1) == Some(self.reference.sequence)
                    && hex_id(hash, 64),
                "settled predecessor differs"
            ),
            _ => anyhow::bail!("run lost predecessor authority"),
        }
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
            self.previous_run_sha256.is_some()
                || (fc::valid_host_boot_id(&old.host_boot_id)
                    && old.host_boot_id != self.host_boot_id)
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
        if self.previous_run_sha256.is_none() {
            launch_identity::check_launch_pair(&self.prior, Some(&self.creation_reader))?;
        } else {
            // Validate immutable creation history independently of a later run's PID/boot.
            // This local projection is never stored and never regains creation trust.
            let mut creation_history = self.prior.clone();
            creation_history.pid = 0;
            launch_identity::check_launch_pair(&creation_history, Some(&self.creation_reader))?;
        }
        let mut projected = self.prior.clone();
        projected.assigned_run = Some(self.reference.clone());
        projected.state = state::STARTING.into();
        projected.pid = 0;
        projected.suspended = matches!(self.mode, Mode::Checkpoint { .. });
        projected.clone_origin.as_mut().unwrap().mapping_exited = true;
        if matches!(self.reference.phase, Phase::Observed | Phase::Settled) {
            anyhow::ensure!(
                (self.target.pid > 0 || self.reference.phase == Phase::Settled)
                    && self.target.boot_incarnation != self.prior.boot_incarnation
                    && self
                        .target
                        .boot_incarnation
                        .as_ref()
                        .is_some_and(|inc| (inc.pid == self.target.pid
                            || self.reference.phase == Phase::Settled)
                            && inc.start_ticks > 0
                            && inc.host_boot_id == self.host_boot_id)
                    && self.target.boot_identity.as_ref() == Some(&self.expected_boot_identity),
                "observed run process evidence differs"
            );
            projected.boot_incarnation = self.target.boot_incarnation.clone();
            projected.boot_identity = self.target.boot_identity.clone();
            projected.pid = self.target.pid;
        }
        if self.reference.phase == Phase::Settled {
            let settled = self
                .settlement
                .as_ref()
                .context("settlement proof missing")?;
            settled.check(self)?;
            projected.pid = 0;
            projected.suspended = settled.checkpoint.is_some();
        } else {
            anyhow::ensure!(self.settlement.is_none(), "unsettled run claims settlement");
        }
        anyhow::ensure!(
            self.record_fingerprint(&projected)? == self.record_fingerprint(&self.target)?
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
                anyhow::ensure!(
                    self.observed_checkpoint.is_none(),
                    "fresh run claims checkpoint proof"
                );
                if let Some(proof) = &self.observed_guest {
                    proof.validate().map_err(|error| anyhow!(error))?;
                    anyhow::ensure!(
                        proof.generation == *guest_generation
                            && proof.boot_bundle_sha256 == *expected_bundle_sha256
                            && proof.init_sha256 == origin.artifact.init_sha256
                            && proof.boot_marker != origin.artifact.ram_marker,
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
                assigned_lineage,
            } => {
                anyhow::ensure!(
                    self.prior.suspended
                        && self.prior.boot_identity.as_ref() == Some(&self.expected_boot_identity),
                    "checkpoint boot identity differs"
                );
                if let Some(proof) = assigned_lineage {
                    proof.validate().map_err(|e| anyhow!(e))?;
                    anyhow::ensure!(
                        self.schema == 3
                            && saved_generation == &proof.generation
                            && saved_init_sha256 == &proof.init_sha256
                            && saved_marker == &proof.boot_marker
                            && saved_bind_sha256.is_empty()
                            && self.observed_checkpoint.is_none(),
                        "assigned checkpoint lineage differs"
                    );
                    if let Some(actual) = &self.observed_guest {
                        anyhow::ensure!(
                            actual == proof.as_ref(),
                            "assigned checkpoint observation differs"
                        );
                    }
                } else {
                    anyhow::ensure!(
                        saved_generation == &origin.configure.generation
                            && saved_init_sha256 == &origin.artifact.init_sha256
                            && saved_marker == &origin.artifact.ram_marker
                            && Some(saved_bind_sha256) == binding.ack_sha256.as_ref()
                            && hex_id(saved_marker, 32)
                            && hex_id(saved_bind_sha256, 64)
                            && self.observed_guest.is_none(),
                        "checkpoint loses creation lineage"
                    );
                    if let Some(pong) = &self.observed_checkpoint {
                        templates::sandbox::check_ack(origin, pong, &["active"])?;
                        anyhow::ensure!(
                            pong.kind == "pong"
                                && pong.main_pid == self.observed_main_pid
                                && pong.init_sha256 == *saved_init_sha256,
                            "checkpoint observation differs"
                        );
                    }
                }
                for file in [state, memory, config] {
                    anyhow::ensure!(
                        file.bytes > 0 && file.inode > 0 && hex_id(&file.sha256, 64),
                        "checkpoint file evidence missing"
                    );
                }
            }
        }
        anyhow::ensure!(
            if matches!(self.reference.phase, Phase::Observed | Phase::Settled) {
                self.launch_started
                    && self.observed_main_pid > 0
                    && match self.mode {
                        Mode::Fresh { .. } => self.observed_guest.is_some(),
                        Mode::Checkpoint {
                            ref assigned_lineage,
                            ..
                        } => {
                            if assigned_lineage.is_some() {
                                self.observed_guest.is_some()
                            } else {
                                self.observed_checkpoint.is_some()
                            }
                        }
                    }
            } else {
                self.observed_guest.is_none()
                    && self.observed_checkpoint.is_none()
                    && self.observed_main_pid == 0
            },
            "run phase lacks exact guest observation"
        );
        Ok(())
    }
    pub(super) fn reader(&self) -> Result<Reader> {
        Ok(Reader {
            schema: self.schema,
            machine: self.machine.clone(),
            host_generation: self.host_generation.clone(),
            reference: self.reference.clone(),
            current_sha256: self.authority_sha256()?,
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
            self.schema == self.current.schema
                && serde_json::to_value(&self.reader)?
                    == serde_json::to_value(self.current.reader()?)?,
            "run reader differs"
        );
        if let Some(prior) = &self.predecessor {
            prior.check()?;
            if prior.reference.phase == Phase::Settled {
                anyhow::ensure!(
                    self.current.schema == 3
                        && self.current.reference.phase == Phase::Reserved
                        && !self.current.launch_started
                        && self.current.previous_run_sha256.as_ref()
                            == Some(&prior.authority_sha256()?)
                        && self.current.reference.sequence
                            == prior
                                .reference
                                .sequence
                                .checked_add(1)
                                .context("sequence overflow")?
                        && self.current.host_generation != prior.host_generation
                        && self.current.record_fingerprint(&self.current.prior)?
                            == self.current.record_fingerprint(&prior.target)?
                        && self.current.root == prior.root
                        && self.current.data == prior.data
                        && self.current.receipt == prior.receipt
                        && self.current.prior.launch_identity == prior.target.launch_identity,
                    "next run changes settled authority"
                );
            } else {
                let mut projected = self.current.clone();
                projected.schema = prior.schema;
                projected.prior_control_sha256 = prior.prior_control_sha256.clone();
                projected.launch_started = prior.launch_started;
                projected.reference = prior.reference.clone();
                projected.target = prior.target.clone();
                projected.observed_guest = prior.observed_guest.clone();
                projected.observed_checkpoint = prior.observed_checkpoint.clone();
                projected.observed_main_pid = prior.observed_main_pid;
                projected.settlement = prior.settlement.clone();
                anyhow::ensure!(
                    projected.authority_sha256()? == prior.authority_sha256()?,
                    "run transition changes frozen authority"
                );
                anyhow::ensure!(
                    match (&prior.reference.phase, &self.current.reference.phase) {
                        (Phase::Reserved, Phase::Reserved) =>
                            !prior.launch_started && self.current.launch_started,
                        (Phase::Reserved, Phase::Observed) =>
                            prior.launch_started && self.current.launch_started,
                        (Phase::Observed, Phase::Settled) =>
                            self.current.schema == 3 && self.current.settlement.is_some(),
                        _ => false,
                    },
                    "invalid run transition"
                );
            }
        } else {
            anyhow::ensure!(
                self.current.reference.sequence == 1
                    && self.current.reference.phase == Phase::Reserved
                    && !self.current.launch_started
                    && self.current.previous_run_sha256.is_none(),
                "new run already launched"
            );
        }
        Ok(())
    }
}

pub(in crate::machine) fn parse_drive(
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
