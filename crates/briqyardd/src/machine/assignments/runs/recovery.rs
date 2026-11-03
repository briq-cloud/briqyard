use super::*;

/// Historical inputs never confer live ownership after an attempted launch.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RunRecovery {
    Prelaunch,
    DiscoveryNeeded,
    ObservedNeedsProof,
    Settled,
}

impl Manager {
    pub(super) fn reconcile_assigned_run(&self, intent: &Intent) -> Result<()> {
        intent.check()?;
        let run = &intent.current;
        self.check_run_creation_authority(run)?;
        let machine = self
            .inner
            .store
            .get::<Record>("machines", &run.machine)?
            .context("run machine record missing")?;
        let old_machine = match intent.predecessor.as_ref() {
            Some(_)
                if run
                    .settlement
                    .as_ref()
                    .is_some_and(|settlement| settlement.update.is_some()) =>
            {
                run.settlement
                    .as_ref()
                    .and_then(|settlement| settlement.update.as_ref())
                    .map(|update| update.target.as_ref())
                    .unwrap()
            }
            Some(old) if old.reference.sequence == run.reference.sequence => &old.target,
            Some(_) if run.consumed_update.is_some() => &run.prior,
            Some(old) => &old.target,
            None => &run.prior,
        };
        let prior = run.record_fingerprint(&machine)? == run.record_fingerprint(old_machine)?;
        let target = run.record_fingerprint(&machine)? == run.record_fingerprint(&run.target)?;
        anyhow::ensure!(
            prior || target,
            "run machine controls differ from exact journal evidence"
        );
        let current = self.inner.store.get::<Current>(RUNS, &run.machine)?;
        let reader = self.inner.store.get::<Reader>(READERS, &run.machine)?;
        let new_current = current
            .as_ref()
            .is_some_and(|value| value.authority_sha256().ok() == run.authority_sha256().ok());
        let old_current = match (&current, &intent.predecessor) {
            (None, None) => true,
            (Some(value), Some(old)) => value.authority_sha256()? == old.authority_sha256()?,
            _ => false,
        };
        let new_reader = reader.as_ref().is_some_and(|value| {
            serde_json::to_value(value).ok() == serde_json::to_value(&intent.reader).ok()
        });
        let old_reader = match (&reader, &intent.predecessor) {
            (None, None) => true,
            (Some(value), Some(old)) => {
                serde_json::to_value(value)? == serde_json::to_value(old.reader()?)?
            }
            _ => false,
        };
        anyhow::ensure!(
            new_current || old_current,
            "current run conflicts with durable intent"
        );
        anyhow::ensure!(
            new_reader || old_reader,
            "run reader conflicts with durable intent"
        );
        anyhow::ensure!(
            !(target && !prior) || new_current,
            "machine advanced before current-run authority"
        );
        anyhow::ensure!(
            !new_reader || (new_current && target),
            "run reader advanced before owning records"
        );
        self.inner.store.put_durable(RUNS, &run.machine, run)?;
        if prior {
            self.inner.store.put_durable(
                "machines",
                &run.machine,
                &projection::preserve_advisory(&run.target, &machine)?,
            )?;
        }
        self.inner
            .store
            .put_durable(READERS, &run.machine, &intent.reader)?;
        if let Some(hash) = &run.consumed_update_sha256 {
            if let Some(update) = self
                .inner
                .store
                .get::<UpdateIntent>(UPDATES, &run.machine)?
            {
                anyhow::ensure!(
                    update.digest()? == *hash
                        && run.consumed_update.as_ref().is_some_and(|consumed| consumed
                            .digest()
                            .ok()
                            .as_ref()
                            == Some(hash)),
                    "consumed assigned update intent differs"
                );
                self.inner.store.delete_durable(UPDATES, &run.machine)?;
            }
        }
        self.inner.store.delete_durable(INTENTS, &run.machine)?;
        Ok(())
    }

    pub(super) fn check_run_creation_authority(&self, run: &Current) -> Result<()> {
        let receipt = self
            .inner
            .store
            .get::<Receipt>(super::super::REQUESTS, &run.receipt.key())?
            .context("run creation receipt missing")?;
        anyhow::ensure!(receipt == run.receipt, "run creation receipt differs");
        self.check_durable_launch_hold(
            &run.machine,
            run.prior
                .launch_identity
                .as_ref()
                .context("run launch hold missing")?,
        )?;
        let creation_reader = self
            .inner
            .store
            .get::<templates::CloneReader>(templates::READERS, &run.machine)?
            .context("run creation reader missing")?;
        anyhow::ensure!(
            creation_reader == run.creation_reader,
            "run rewrites immutable creation reader"
        );
        Ok(())
    }

    /// Metadata repair only. Actual backing is rechecked before startup side effects.
    pub(in crate::machine) fn recover_assigned_runs(&self) -> Result<()> {
        let intents = self.inner.store.list::<Intent>(INTENTS)?;
        anyhow::ensure!(
            intents.is_empty() || self.inner.machines.lock().unwrap().is_empty(),
            "run recovery requires closed startup admission"
        );
        for intent in intents {
            let stored = self
                .inner
                .store
                .get::<Intent>(INTENTS, &intent.current.machine)?
                .context("run intent stored under wrong key")?;
            anyhow::ensure!(
                serde_json::to_value(&stored)? == serde_json::to_value(&intent)?,
                "run intent key conflict"
            );
            self.reconcile_assigned_run(&intent)?;
        }
        for update in self.inner.store.list::<UpdateIntent>(UPDATES)? {
            let stored = self
                .inner
                .store
                .get::<UpdateIntent>(UPDATES, &update.machine)?
                .context("assigned update stored under wrong key")?;
            anyhow::ensure!(
                serde_json::to_value(&stored)? == serde_json::to_value(&update)?,
                "assigned update key conflict"
            );
            self.recover_assigned_update(&update)?;
        }
        let machines = self.inner.store.list::<Record>("machines")?;
        for current in self.inner.store.list::<Current>(RUNS)? {
            current.check()?;
            self.check_run_creation_authority(&current)?;
            let stored = self
                .inner
                .store
                .get::<Current>(RUNS, &current.machine)?
                .context("current run key differs")?;
            anyhow::ensure!(
                serde_json::to_value(stored)? == serde_json::to_value(&current)?,
                "current run key conflict"
            );
            let machine = machines
                .iter()
                .find(|machine| machine.id == current.machine)
                .context("current run machine missing")?;
            let update = self
                .inner
                .store
                .get::<UpdateIntent>(UPDATES, &current.machine)?;
            let machine_matches = match update {
                Some(update) => {
                    update.check(&current)?;
                    updates::matches_authorized_update_target(machine, &current, &update)?
                }
                None => {
                    current.record_fingerprint(machine)?
                        == current.record_fingerprint(&current.target)?
                }
            };
            anyhow::ensure!(
                machine.assigned_run.as_ref() == Some(&current.reference) && machine_matches,
                "machine/current-run link differs"
            );
            let reader = self
                .inner
                .store
                .get::<Reader>(READERS, &current.machine)?
                .context("current run reader missing")?;
            anyhow::ensure!(
                serde_json::to_value(reader)? == serde_json::to_value(current.reader()?)?,
                "current run reader differs"
            );
        }
        for machine in machines
            .iter()
            .filter(|machine| machine.assigned_run.is_some())
        {
            anyhow::ensure!(
                self.inner
                    .store
                    .get::<Current>(RUNS, &machine.id)?
                    .is_some(),
                "run reference lacks durable current authority"
            );
        }
        for reader in self.inner.store.list::<Reader>(READERS)? {
            anyhow::ensure!(
                matches!(reader.schema, 1 | 3)
                    && self
                        .inner
                        .store
                        .get::<Current>(RUNS, &reader.machine)?
                        .is_some(),
                "orphan or unknown run reader"
            );
        }
        Ok(())
    }

    pub(in crate::machine) async fn verify_assigned_run_backing(&self) -> Result<()> {
        for current in self.inner.store.list::<Current>(RUNS)? {
            if self.classify_run_recovery(&current).await? == RunRecovery::DiscoveryNeeded {
                tracing::warn!(machine = current.machine, "assigned run consumption unresolved; quarantine/discovery required, backing and charges retained");
            }
            // This startup fence precedes forwarding/rules. Historical observation and
            // unresolved consumption both remain unpublished until actual live proof.
            self.unplug(&current.machine, &current.target.ip).await?;
            self.inner.net.quarantine(&current.machine).await?;
        }
        Ok(())
    }
    async fn verify_run_current_backing(&self, current: &Current) -> Result<()> {
        current.check()?;
        anyhow::ensure!(
            self.inner.vmm.host_boot_id().as_deref() == Some(current.host_boot_id.as_str()),
            "run host boot changed; explicit new authority required"
        );
        let (root, data) = self.current_run_disks(&current.prior).await?;
        anyhow::ensure!(
            root == current.root && data == current.data,
            "CURRENT run dataset GUID changed; backing retained"
        );
        Ok(())
    }

    /// Called only before the launch attempt reaches the VMM. Snapshot inputs must still
    /// exist exactly here, including during the durable attempted/pre-spawn window.
    pub(super) async fn verify_run_prelaunch_backing(&self, current: &Current) -> Result<()> {
        anyhow::ensure!(
            current.reference.phase == Phase::Reserved,
            "run already observed"
        );
        self.verify_run_current_backing(current).await?;
        let compatible = match current.mode {
            Mode::Fresh { .. } => {
                self.inner
                    .vmm
                    .boot_identity(self.inner.cfg.balloon.enabled)
                    .as_ref()
                    == Some(&current.expected_boot_identity)
            }
            Mode::Checkpoint { .. } => self.resume_compatible(&current.prior),
        };
        anyhow::ensure!(
            compatible,
            "run boot artifacts changed; no implicit fallback"
        );
        if let Mode::Checkpoint {
            state,
            memory,
            config,
            ..
        } = &current.mode
        {
            let paths = self.run_checkpoint_paths(&current.prior);
            for (path, expected) in paths.iter().zip([state, memory, config]) {
                anyhow::ensure!(
                    templates::fingerprint(path)? == *expected,
                    "CURRENT checkpoint evidence changed"
                );
            }
        }
        Ok(())
    }
    pub(super) fn verify_run_config(&self, current: &Current) -> Result<()> {
        let path = self.run_checkpoint_paths(&current.prior)[2].clone();
        match &current.mode {
            Mode::Fresh { drive_sha256, .. } => {
                anyhow::ensure!(
                    sha(&std::fs::read(path)?) == *drive_sha256,
                    "CURRENT fresh config changed"
                );
            }
            Mode::Checkpoint { config, .. } => {
                anyhow::ensure!(
                    templates::fingerprint(&path)? == *config,
                    "CURRENT checkpoint config changed"
                );
            }
        }
        Ok(())
    }

    pub(super) async fn classify_run_recovery(&self, current: &Current) -> Result<RunRecovery> {
        self.check_run_creation_authority(current)?;
        current.check()?;
        if current.reference.phase == Phase::Settled {
            let (root, data) = self.current_run_disks(&current.target).await?;
            let expected_root = match self
                .inner
                .store
                .get::<UpdateIntent>(UPDATES, &current.machine)?
            {
                Some(update) => {
                    update.check(current)?;
                    match update.root_swap.as_ref().and_then(|swap| swap.target_guid) {
                        Some(guid) => Disk {
                            dataset: current.root.dataset.clone(),
                            guid,
                        },
                        None => current.root.clone(),
                    }
                }
                None => current.root.clone(),
            };
            anyhow::ensure!(
                root == expected_root && data == current.data,
                "settled CURRENT disks changed"
            );
            if let Some(checkpoint) = current
                .settlement
                .as_ref()
                .and_then(|s| s.checkpoint.as_ref())
            {
                checkpoint.verify_files(self, &current.target).await?;
            }
            return Ok(RunRecovery::Settled);
        }
        if current.reference.phase == Phase::Reserved
            && current.launch_started
            && self
                .inner
                .vmm
                .host_boot_id()
                .as_ref()
                .is_some_and(|host| fc::valid_host_boot_id(host) && host != &current.host_boot_id)
        {
            let (root, data) = self.current_run_disks(&current.target).await?;
            anyhow::ensure!(
                root == current.root && data == current.data,
                "unresolved CURRENT disks changed"
            );
            return Ok(RunRecovery::DiscoveryNeeded);
        }
        self.verify_run_current_backing(current).await?;
        if !current.launch_started {
            self.verify_run_prelaunch_backing(current).await?;
            return Ok(RunRecovery::Prelaunch);
        }
        if current.reference.phase != Phase::Observed {
            if matches!(current.mode, Mode::Checkpoint { .. }) {
                self.verify_run_config(current)?;
            }
            // Neither remaining nor missing snapshot inputs prove whether a VMM consumed
            // them. No exact observed incarnation exists for read-only API adoption.
            return Ok(RunRecovery::DiscoveryNeeded);
        }
        self.verify_run_config(current)?;
        // Snapshot state/memory are historical inputs after durable observation. Native
        // resume consumes them; a live handle still needs exact process/API/guest proof.
        Ok(RunRecovery::ObservedNeedsProof)
    }
}
