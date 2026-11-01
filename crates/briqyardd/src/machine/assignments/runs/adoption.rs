//! Read-only reconstruction of an OBSERVED run. Never resumes, launches or publishes.
use super::*;

impl Manager {
    #[allow(dead_code)]
    pub(in crate::machine) async fn adopt_observed_assigned_run(
        &self,
        entry: &Arc<Entry>,
    ) -> Result<fc::Vm> {
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        entry.identity_trusted.store(false, Relaxed);
        *entry.live.lock().unwrap() = None;
        let record = entry.snapshot();
        self.unplug(&record.id, &record.ip).await?;
        self.inner.net.quarantine(&record.id).await?;
        anyhow::ensure!(
            self.inner
                .store
                .get::<Intent>(INTENTS, &record.id)?
                .is_none(),
            "run intent requires exact journal repair"
        );
        let current: Current = self
            .inner
            .store
            .get(RUNS, &record.id)?
            .context("current run missing")?;
        anyhow::ensure!(
            launch_identity::record_fingerprint(&record)?
                == launch_identity::record_fingerprint(&current.target)?
                && record.assigned_run.as_ref() == Some(&current.reference),
            "run machine differs from observation"
        );
        let reader: Reader = self
            .inner
            .store
            .get(READERS, &record.id)?
            .context("run reader missing")?;
        anyhow::ensure!(
            serde_json::to_value(reader)? == serde_json::to_value(current.reader()?)?,
            "run reader differs"
        );
        anyhow::ensure!(
            self.classify_run_recovery(&current).await?
                == recovery::RunRecovery::ObservedNeedsProof,
            "run consumption unresolved; discovery needed, never retry launch"
        );
        self.verify_recorded_run_process(&current)?;
        let jail = self
            .jail_for(&record)
            .context("immutable run jail missing")?;
        let mut vm = self
            .inner
            .vmm
            .adopt(
                &record.id,
                &self.inner.cfg.run_dir().join(&record.id),
                Some(&jail),
                record.pid,
                entry.disk_io.clone(),
            )
            .await
            .context("exact observed VMM is not confirmed Running")?;
        self.verify_recorded_run_process(&current)?;
        // Same actual API device-profile contract as assigned creation adoption. The
        // remaining boot identity comes from this exact run's durable observation.
        let expected = &current.expected_boot_identity;
        let observed_matches = match vm.boot_identity.as_ref() {
            None => expected.device_profile == fc::LEGACY_PROFILE,
            Some(observed) => {
                observed == &fc::BootIdentity::ambiguous(fc::REPORTING_PROFILE)
                    && expected.device_profile == fc::REPORTING_PROFILE
            }
        };
        anyhow::ensure!(
            !vm.resumed && observed_matches,
            "run API state/device profile differs"
        );
        vm.boot_identity = Some(expected.clone());
        self.verify_run_process(&current, &vm)?;
        let pong = self.inner.guest.ping(&vm.vsock).await?;
        self.verify_recorded_run_process(&current)?;
        self.verify_run_process(&current, &vm)?;
        current.check_pong(&pong)?;
        anyhow::ensure!(pong.main_pid > 0, "observed run main is absent");
        if matches!(current.mode, Mode::Fresh { .. }) {
            anyhow::ensure!(
                pong.assigned_run == current.observed_guest,
                "run differs from saved boot marker or measured proof"
            );
        }
        self.classify_run_recovery(&current).await?;
        self.verify_run_process(&current, &vm)?;
        // Return a local provisional handle only. No Entry.live, trust, probes/watch,
        // network activation, DNS or API publication is authorized by this function.
        Ok(vm)
    }

    fn verify_recorded_run_process(&self, current: &Current) -> Result<()> {
        let identity = current
            .prior
            .launch_identity
            .as_ref()
            .context("run identity missing")?;
        let incarnation = current
            .target
            .boot_incarnation
            .as_ref()
            .context("observed incarnation missing")?;
        anyhow::ensure!(
            current.reference.phase == Phase::Observed
                && current.target.pid == incarnation.pid
                && incarnation.start_ticks > 0
                && incarnation.host_boot_id == current.host_boot_id
                && self.inner.vmm.host_boot_id().as_deref() == Some(current.host_boot_id.as_str())
                && self.inner.vmm.verify_process(
                    &current.machine,
                    incarnation,
                    identity.uid,
                    identity.gid
                ),
            "recorded run process/credentials/host boot unconfirmed"
        );
        Ok(())
    }
}
