//! Normal callers dispatch outside the legacy entry-held start path.
use super::*;
use terminal::Disposition;

pub(super) fn public_error(error: anyhow::Error) -> MError {
    match error.downcast::<MError>() {
        Ok(error) => error,
        Err(error) => MError::Other(error),
    }
}
impl Manager {
    pub(in crate::machine) fn assigned_lifecycle(&self, record: &Record) -> bool {
        record.launch_identity.is_some()
            && record
                .clone_origin
                .as_ref()
                .is_some_and(|o| o.stage == templates::CloneStage::Active)
    }

    pub(in crate::machine) fn start_assigned_boxed<'a>(
        &'a self,
        entry: &'a Arc<Entry>,
        asked: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), MError>> + Send + 'a>> {
        Box::pin(self.start_assigned_public(entry, None, true, asked))
    }

    pub(in crate::machine) async fn start_assigned_public(
        &self,
        entry: &Arc<Entry>,
        at: Option<u64>,
        wake: bool,
        asked: bool,
    ) -> Result<(), MError> {
        // Reuse the existing disk/lifecycle turn: coalesce requests without holding the
        // entry lock while reserve takes warm -> namespace -> sandbox -> entry.
        let _turn = entry.backup_turn.clone().lock_owned().await;
        {
            let _entry = entry.assigned_stopped_lock().await;
            self.check_version(entry, at)?;
            let record = entry.snapshot();
            if !self.assigned_lifecycle(&record) {
                return Err(MError::Conflict("assignment changed".into()));
            }
            if matches!(record.state.as_str(), state::DESTROYING | state::STOPPING) {
                return Err(MError::BadState(record.state));
            }
            if wake && record.state == state::STOPPED && record.stopped_reason == stop::USER {
                return Err(MError::NotRunning("stopped on request".into()));
            }
            if wake && record.state == state::ERROR {
                return Err(MError::BadState(record.state));
            }
            if record.restoring.is_some() {
                return Err(MError::Conflict(
                    "assigned continuation has an unfinished restore".into(),
                ));
            }
            if record.pending.is_some() {
                let update: UpdateIntent =
                    self.inner.store.get(UPDATES, &record.id)?.ok_or_else(|| {
                        MError::Conflict("assigned pending update lacks durable intent".into())
                    })?;
                let current = self.check_update_source(&update).map_err(public_error)?;
                let matches = updates::matches_update_target(&record, &update.target)
                    || current.as_ref().is_some_and(|current| {
                        updates::matches_current_target(&record, current, &update).unwrap_or(false)
                    });
                if !matches {
                    return Err(MError::Conflict(
                        "assigned pending update differs from its durable intent".into(),
                    ));
                }
            }
            if record.state == state::RUNNING
                && self
                    .assignment_publication_allowed(&record, entry.identity_trusted.load(Relaxed))
            {
                entry.touch();
                return Ok(());
            }
            if record.assigned_run.is_none() {
                self.check_assigned_bound_record(&record)
                    .map_err(public_error)?;
            }
        }
        let record = entry.snapshot();
        let current: Option<Current> = self.inner.store.get(RUNS, &record.id)?;
        match current.as_ref().map(|run| &run.reference.phase) {
            Some(Phase::Observed) => self
                .publish_observed_run(entry, asked, at)
                .await
                .map_err(public_error),
            Some(Phase::Reserved) => {
                let run = current.as_ref().unwrap();
                if run.launch_started {
                    return Err(MError::Conflict("assigned launch outcome unresolved; backing/charges retained, no second launch".into()));
                }
                self.boot_reserved_assigned_run(entry)
                    .await
                    .map_err(public_error)?;
                self.publish_observed_run(entry, asked, at)
                    .await
                    .map_err(public_error)
            }
            Some(Phase::Settled) | None => {
                // Resolve dependencies before reserving a process attempt. No pending
                // specification is applied or dropped by this dispatcher.
                self.policy_for(&record)?;
                let gateway = if record.egress.via_gateway() {
                    Some(self.ensure_gateway(&record.namespace).await?)
                } else {
                    None
                };
                let checkpoint =
                    record.pending.is_none() && record.suspended && self.resume_compatible(&record);
                self.reserve_assigned_run_version(entry, checkpoint, at)
                    .await
                    .map_err(public_error)?;
                if let Some(current) = self
                    .inner
                    .store
                    .get::<Current>(RUNS, &record.id)
                    .map_err(public_error)?
                {
                    if let Some(update) = current.consumed_update.as_deref() {
                        self.cleanup_consumed_image_update(entry, update);
                    }
                }
                drop(gateway);
                self.boot_reserved_assigned_run(entry)
                    .await
                    .map_err(public_error)?;
                self.publish_observed_run(entry, asked, None)
                    .await
                    .map_err(public_error)
            }
        }
    }

    pub(in crate::machine) async fn stop_assigned_public(
        &self,
        entry: &Arc<Entry>,
        why: &str,
        grace: Duration,
        suspend: bool,
        at: Option<u64>,
    ) -> Result<(), MError> {
        let _turn = entry.backup_turn.clone().lock_owned().await;
        let suspend = if suspend {
            !self
                .inner
                .store
                .get::<UpdateIntent>(UPDATES, &entry.snapshot().id)?
                .is_some_and(|update| update.change.volume.is_some())
        } else {
            false
        };
        let grace = if grace.is_zero() {
            Duration::from_secs(10)
        } else {
            grace
        };
        let live = {
            let _namespace = self.inner.namespace_lifecycle.read().await;
            let _entry = entry.lock.lock().await;
            self.check_version(entry, at)?;
            let record = entry.snapshot();
            self.validate_current_run_record(&record)
                .map_err(public_error)?;
            if record
                .assigned_run
                .as_ref()
                .is_some_and(|r| r.phase == Phase::Settled)
            {
                self.settle_stopped(entry, why);
                return Ok(());
            }
            if !self.assignment_publication_allowed(&record, entry.identity_trusted.load(Relaxed)) {
                return Err(MError::Conflict(
                    "unverified current run preserved; stop cannot infer ownership".into(),
                ));
            }
            *entry.stop_req.lock().unwrap() = Some(why.into());
            *entry.stop_deadline.lock().unwrap() =
                Some(tokio::time::Instant::now() + grace + Duration::from_secs(20));
            entry.set_state(state::STOPPING, |_| {
                Some(Ev::normal(reason::STOPPING, format!("stopping ({why})")))
            });
            self.save(entry)?;
            if suspend {
                self.settle_assigned_run_locked(entry, Disposition::CheckpointAvailable)
                    .await
                    .map_err(public_error)?;
                *entry.stop_req.lock().unwrap() = None;
                self.finish_run_stopped(entry, why);
                return Ok(());
            }
            entry
                .live
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| MError::NotRunning("current handle missing".into()))?
        };
        let asked = tokio::time::timeout(
            Duration::from_secs(5),
            self.inner.guest.shutdown(&live.vsock, grace),
        )
        .await
        .is_ok_and(|answer| answer.is_ok());
        let mut exited = live.exited.clone();
        if !asked
            || tokio::time::timeout(
                grace + Duration::from_secs(5),
                exited.wait_for(|gone| *gone),
            )
            .await
            .is_err()
        {
            self.inner.vmm.kill(live.pid);
        }
        tokio::time::timeout(Duration::from_secs(10), exited.wait_for(|gone| *gone))
            .await
            .map_err(|_| MError::Conflict("current exit unconfirmed; reservation retained".into()))?
            .map_err(|_| MError::Conflict("exit channel closed without positive proof".into()))?;
        // The watcher normally owns this; direct settlement coalesces an already-ended
        // process and makes the stop's completion independent of watcher scheduling.
        self.settle_current_run_exit(entry, live.pid).await;
        if entry
            .snapshot()
            .assigned_run
            .as_ref()
            .is_some_and(|r| r.phase != Phase::Settled)
        {
            return Err(MError::Conflict(
                "terminal journal unresolved; backing/charges retained".into(),
            ));
        }
        Ok(())
    }

    fn finish_run_stopped(&self, entry: &Entry, why: &str) {
        entry.identity_trusted.store(false, Relaxed);
        if let Some(task) = entry.prober.lock().unwrap().take() {
            task.abort();
        }
        self.reset_probes(entry);
        self.settle_stopped(entry, why);
        if let Some(namespace) = self.namespace_of(&entry.snapshot().namespace) {
            self.refresh_dns(&namespace);
        }
    }

    pub(in crate::machine) async fn settle_current_run_exit(&self, entry: &Arc<Entry>, pid: u32) {
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        let live = entry.live.lock().unwrap().clone();
        let Some(live) = live.filter(|live| live.pid == pid && *live.exited.borrow()) else {
            return;
        };
        let mut exit = live.exit.clone();
        let _ = exit.wait_for(|report| report.is_some()).await;
        let reported = exit.borrow().clone();
        let vmm_oom = live.vmm_oom.get() && reported.is_none();
        let report = reported.unwrap_or(guest::ExitReport {
            code: 255,
            ..Default::default()
        });
        let requested = entry.stop_req.lock().unwrap().clone();
        let disposition = if requested.is_none() && report.code != 0 {
            Disposition::Failed
        } else {
            Disposition::Stopped
        };
        if let Err(error) = self.settle_assigned_run_locked(entry, disposition).await {
            entry.identity_trusted.store(false, Relaxed);
            tracing::error!(machine = entry.snapshot().id, %error, "current-run exit journal unresolved; backing and charges retained");
            return;
        }
        *entry.stop_req.lock().unwrap() = None;
        if let Some(why) = requested {
            self.finish_run_stopped(entry, &why);
        } else if report.requested {
            self.finish_run_stopped(entry, stop::USER);
        } else {
            self.finish_run_stopped(entry, stop::EXIT);
            self.exited(entry, report.code, report.oom, vmm_oom, report.code != 0);
        }
    }
    pub(in crate::machine) async fn fail_assigned_probe(
        &self,
        entry: &Arc<Entry>,
        pid: u32,
        boot: bool,
        why: String,
    ) {
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        let record = entry.snapshot();
        if record.pid != pid
            || record.state != state::RUNNING
            || !self.assignment_publication_allowed(&record, entry.identity_trusted.load(Relaxed))
        {
            return;
        }
        let Some(live) = entry.live.lock().unwrap().clone() else {
            return;
        };
        let _ = self.inner.guest.shutdown(&live.vsock, Duration::ZERO).await;
        self.inner.vmm.kill(live.pid);
        let mut exited = live.exited.clone();
        if !tokio::time::timeout(Duration::from_secs(15), exited.wait_for(|gone| *gone))
            .await
            .is_ok_and(|proof| proof.is_ok())
        {
            return;
        }
        if self
            .settle_assigned_run_locked(entry, Disposition::Failed)
            .await
            .is_err()
        {
            return;
        }
        self.finish_run_stopped(entry, stop::EXIT);
        if boot {
            entry.set_state(state::ERROR, |record| {
                record.error = why;
                record.error_reason = reason::STARTUP_FAILED.into();
                Some(Ev::warning(reason::STARTUP_FAILED, record.error.clone()))
            });
            let _ = self.save(entry);
        } else {
            self.exited(entry, 255, false, false, true);
        }
    }
}

impl Entry {
    async fn assigned_stopped_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        loop {
            let guard = self.lock.lock().await;
            let deadline = *self.stop_deadline.lock().unwrap();
            let Some(deadline) = deadline.filter(|deadline| {
                self.snapshot().state == state::STOPPING && *deadline > tokio::time::Instant::now()
            }) else {
                return guard;
            };
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            drop(guard);
            let _ = tokio::time::timeout_at(deadline, changed).await;
        }
    }
}
