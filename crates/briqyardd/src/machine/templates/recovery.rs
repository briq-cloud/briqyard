//! Incomplete clone recovery never starts or activates a guest.
use super::*;

impl Manager {
    /// Caller owns the entry lifecycle lock. A missing PID/scan is never evidence that
    /// a launch on this boot cannot still materialize. Unknown ownership stays pinned.
    pub(in crate::machine) async fn reconcile_clone_exit(&self, e: &Entry) -> Result<bool> {
        let r = e.snapshot();
        let Some(origin) = r.clone_origin.as_ref() else {
            return Ok(true);
        };
        if origin.mapping_exited || origin.stage == CloneStage::Reserved {
            return Ok(true);
        }
        let launch_boot = origin
            .launch_host_boot_id
            .as_deref()
            .or_else(|| r.boot_incarnation.as_ref().map(|i| i.host_boot_id.as_str()));
        let current_boot = self.inner.vmm.host_boot_id();
        let previous_boot_ended =
            launch_boot
                .zip(current_boot.as_deref())
                .is_some_and(|(saved, current)| {
                    fc::valid_host_boot_id(saved)
                        && fc::valid_host_boot_id(current)
                        && saved != current
                });
        let gone = if previous_boot_ended {
            true
        } else if let Some(incarnation) = r
            .boot_incarnation
            .as_ref()
            .filter(|inc| launch_boot.is_none_or(|boot| boot == inc.host_boot_id))
        {
            self.inner
                .vmm
                .settle_clone_process(&r.id, incarnation)
                .await?
        } else {
            false
        };
        if gone {
            {
                let mut record = e.rec.lock().unwrap();
                record.clone_origin.as_mut().unwrap().mapping_exited = true;
                record.pid = 0;
            }
            self.inner
                .store
                .put_durable("machines", &r.id, &e.snapshot())?;
        }
        Ok(gone)
    }

    pub(in crate::machine) async fn recover_incomplete_clone(&self, e: &Arc<Entry>) {
        let _turn = e.lock.lock().await;
        let r = e.snapshot();
        if let Err(error) = self.unplug(&r.id, &r.ip).await {
            tracing::error!(machine = r.id, %error, "incomplete clone quarantine failed; backing retained");
            return;
        }
        match self.reconcile_clone_exit(e).await {
            Ok(true) => {
                if r.state != state::DESTROYING {
                    e.set_state(state::ERROR, |record| {
                        record.error = "interrupted memory clone; owned mapping exit confirmed; destroy to clean up".into();
                        record.error_reason = reason::START_FAILED.into();
                        None
                    });
                    let _ = self.save(e);
                }
            }
            Ok(false) => tracing::warn!(
                machine = r.id,
                "incomplete clone ownership unresolved; full reservation and backing retained"
            ),
            Err(error) => {
                tracing::error!(machine = r.id, %error, "incomplete clone exit unconfirmed; full reservation and backing retained")
            }
        }
    }
}
