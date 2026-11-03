//! Public live authority is earned from this run, never from a stopped lifecycle link.
use super::*;

impl Manager {
    pub(in crate::machine) fn validate_current_run_record(&self, record: &Record) -> Result<()> {
        let current: Current = self
            .inner
            .store
            .get(RUNS, &record.id)?
            .context("current run missing")?;
        current.check()?;
        self.check_run_creation_authority(&current)?;
        let update = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)?;
        let record_matches = match update {
            Some(update) => {
                update.check(&current)?;
                updates::matches_update_target(record, &update.target)
            }
            None => {
                current.record_fingerprint(record)?
                    == current.record_fingerprint(&current.target)?
            }
        };
        anyhow::ensure!(
            record_matches && record.assigned_run.as_ref() == Some(&current.reference),
            "record differs from current run authority"
        );
        let reader: Reader = self
            .inner
            .store
            .get(READERS, &record.id)?
            .context("current reader missing")?;
        anyhow::ensure!(
            serde_json::to_value(reader)? == serde_json::to_value(current.reader()?)?,
            "current reader differs"
        );
        anyhow::ensure!(
            self.inner
                .store
                .get::<Intent>(INTENTS, &record.id)?
                .is_none(),
            "run intent unresolved"
        );
        Ok(())
    }

    pub(in crate::machine) fn verified_run_publication(&self, record: &Record) -> Result<()> {
        self.validate_current_run_record(record)?;
        anyhow::ensure!(
            record
                .assigned_run
                .as_ref()
                .is_some_and(|r| r.phase == Phase::Observed),
            "run is not observed live authority"
        );
        let incarnation = record
            .boot_incarnation
            .as_ref()
            .context("run incarnation missing")?;
        let identity = record
            .launch_identity
            .as_ref()
            .context("run identity missing")?;
        anyhow::ensure!(
            self.inner.vmm.host_boot_id().as_deref() == Some(incarnation.host_boot_id.as_str())
                && record.pid == incarnation.pid
                && self.inner.vmm.verify_process(
                    &record.id,
                    incarnation,
                    identity.uid,
                    identity.gid
                ),
            "published current process is not confirmed"
        );
        Ok(())
    }

    pub(super) async fn publish_observed_run(
        &self,
        entry: &Arc<Entry>,
        asked: bool,
        at: Option<u64>,
    ) -> Result<()> {
        // Existing adopter proves Running API/device state and exact saved guest proof.
        // Its returned handle is still local and the destination remains quarantined.
        let vm = self.adopt_observed_assigned_run(entry).await?;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        self.check_version(entry, at)?;
        let current: Current = self
            .inner
            .store
            .get(RUNS, &entry.snapshot().id)?
            .context("run missing")?;
        self.verify_run_process(&current, &vm)?;
        self.validate_current_run_record(&entry.snapshot())?;
        let result: Result<()> = async {
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
            *entry.live.lock().unwrap() = Some(vm.clone());
            entry.identity_trusted.store(true, Relaxed);
            self.inner.net.count(&current.target.ip).await?;
            self.activate_clone_network(&entry.snapshot()).await?;
            self.verify_run_process(&current, &vm)?;
            let (_, _, generation) = self.reset_probes(entry);
            let was_running = entry.snapshot().state == state::RUNNING;
            entry.set_state(state::RUNNING, |record| {
                let now = Utc::now();
                if !was_running {
                    record.started_at = Some(now);
                }
                if asked || !was_running {
                    record.last_used_at = Some(now);
                }
                record.stopped_reason.clear();
                record.error.clear();
                record.error_reason.clear();
                Some(
                    Ev::normal(
                        reason::STARTED,
                        format!(
                            "assigned run {}, pid {}",
                            current.reference.sequence, vm.pid
                        ),
                    )
                    .data(json!({"pid": vm.pid})),
                )
            });
            self.save(entry)?;
            *entry.stop_req.lock().unwrap() = None;
            self.watch(entry, &vm);
            if let Some(namespace) = self.namespace_of(&current.target.namespace) {
                self.refresh_dns(&namespace);
            }
            self.spawn_probes(entry, &vm, generation, asked);
            Ok(())
        }
        .await;
        if let Err(error) = result {
            entry.identity_trusted.store(false, Relaxed);
            let _ = self.unplug(&current.machine, &current.target.ip).await;
            let _ = self.inner.net.quarantine(&current.machine).await;
            if let Some(namespace) = self.namespace_of(&current.target.namespace) {
                self.refresh_dns(&namespace);
            }
            return Err(error);
        }
        Ok(())
    }
}
