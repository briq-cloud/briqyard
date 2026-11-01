use super::*;
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
        let prior = launch_identity::record_fingerprint(&machine)? == run.prior_control_sha256;
        let target = launch_identity::record_fingerprint(&machine)?
            == launch_identity::record_fingerprint(&run.target)?;
        anyhow::ensure!(
            prior || target,
            "run machine controls differ from exact journal evidence"
        );
        let current = self.inner.store.get::<Current>(RUNS, &run.machine)?;
        let reader = self.inner.store.get::<Reader>(READERS, &run.machine)?;
        anyhow::ensure!(
            current.as_ref().is_none_or(
                |current| serde_json::to_value(current).ok() == serde_json::to_value(run).ok()
            ) && reader
                .as_ref()
                .is_none_or(|reader| serde_json::to_value(reader).ok()
                    == serde_json::to_value(&intent.reader).ok()),
            "current run or reader conflicts with durable intent"
        );
        anyhow::ensure!(
            !target || current.is_some(),
            "machine advanced before current-run authority"
        );
        anyhow::ensure!(
            reader.is_none() || (current.is_some() && target),
            "run reader advanced before owning records"
        );
        self.inner.store.put_durable(RUNS, &run.machine, run)?;
        if prior {
            self.inner
                .store
                .put_durable("machines", &run.machine, &run.target)?;
        }
        self.inner
            .store
            .put_durable(READERS, &run.machine, &intent.reader)?;
        self.inner.store.delete_durable(INTENTS, &run.machine)
    }

    fn check_run_creation_authority(&self, run: &Current) -> Result<()> {
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
            anyhow::ensure!(
                machine.assigned_run.as_ref() == Some(&current.reference)
                    && launch_identity::record_fingerprint(machine)?
                        == launch_identity::record_fingerprint(&current.target)?,
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
                reader.schema == 1
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
            current.check()?;
            anyhow::ensure!(
                self.inner.vmm.host_boot_id().as_deref() == Some(current.host_boot_id.as_str()),
                "run host boot changed; explicit new authority required"
            );
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
            let (root, data) = self.current_run_disks(&current.prior).await?;
            anyhow::ensure!(
                root == current.root && data == current.data,
                "CURRENT run dataset GUID changed; backing retained"
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
        }
        Ok(())
    }
}
