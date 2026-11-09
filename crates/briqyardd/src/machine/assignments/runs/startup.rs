//! Reboot exit evidence is consumed before the unchanged-host backing/adoption fence.
use super::*;

impl Manager {
    pub(in crate::machine) async fn prepare_assigned_reboot_exits(&self) -> Result<()> {
        let Some(host) = self
            .inner
            .vmm
            .host_boot_id()
            .filter(|host| fc::valid_host_boot_id(host))
        else {
            return Ok(());
        };
        let entries: Vec<_> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for entry in entries {
            let record = entry.snapshot();
            if !self.assigned_lifecycle(&record) {
                continue;
            }
            if let Some(current) = self.inner.store.get::<Current>(RUNS, &record.id)? {
                if current.reference.phase == Phase::Observed && current.host_boot_id != host {
                    // A new boot proves old process exit, never guest continuity. The
                    // terminal writer retains source UID/receipt and CURRENT backing.
                    self.settle_assigned_run(&entry, terminal::Disposition::Stopped)
                        .await?;
                    let why =
                        if record.state == state::STOPPING && record.stopped_reason == stop::USER {
                            stop::USER
                        } else {
                            stop::HOST
                        };
                    self.settle_stopped(&entry, why);
                    entry.identity_trusted.store(false, Relaxed);
                }
                continue;
            }
            if self.recover_creation_update_stopped(&entry).await? {
                continue;
            }
            let ended = record.boot_incarnation.as_ref().is_some_and(|old| {
                fc::valid_host_boot_id(&old.host_boot_id) && old.host_boot_id != host
            });
            if ended {
                let _namespace = self.inner.namespace_lifecycle.read().await;
                let _entry = entry.lock.lock().await;
                self.check_assigned_bound_record(&record)?;
                anyhow::ensure!(
                    self.reconcile_clone_exit(&entry).await?,
                    "creation exit unconfirmed"
                );
                *entry.live.lock().unwrap() = None;
                entry.identity_trusted.store(false, Relaxed);
                // Completed user stops remain user stops across a subsequent host boot.
                let why = if record.state == state::STOPPED && record.stopped_reason == stop::USER {
                    stop::USER
                } else {
                    stop::HOST
                };
                self.settle_stopped(&entry, why);
            }
        }
        Ok(())
    }

    pub(in crate::machine) async fn recover_current_run(&self, entry: &Arc<Entry>) -> bool {
        let reference = entry.snapshot().assigned_run;
        match reference.map(|reference| reference.phase) {
            Some(Phase::Observed) => match self.publish_observed_run(entry, false, None).await {
                Ok(()) => true,
                Err(error) => {
                    entry.identity_trusted.store(false, Relaxed);
                    tracing::warn!(machine = entry.snapshot().id, %error, "current-run adoption withheld; reservation retained");
                    false
                }
            },
            Some(Phase::Settled) => {
                let record = entry.snapshot();
                // A durable stopped record is already settled. Re-stopping it changes the
                // timestamp behind a pending update's exact source/predecessor binding.
                if (record.state != state::STOPPED || record.pid != 0)
                    && self.validate_current_run_record(&record).is_ok()
                {
                    let why = if record.stopped_reason.is_empty() {
                        stop::HOST
                    } else {
                        &record.stopped_reason
                    };
                    self.settle_stopped(entry, why);
                }
                false
            }
            _ => {
                entry.identity_trusted.store(false, Relaxed);
                let _ = self.inner.net.quarantine(&entry.snapshot().id).await;
                false
            }
        }
    }
}
