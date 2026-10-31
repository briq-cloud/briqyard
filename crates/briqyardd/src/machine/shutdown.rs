//! A machine ends: its exit, a stop, a destroy, and the restart policy that follows an exit.

use super::*;
use crate::profile::stage;
use std::time::Instant;

impl Manager {
    /// Settles the state after the Firecracker process exited.
    pub(super) async fn settle_exit(&self, e: &Arc<Entry>, pid: u32) {
        let machine = e.rec.lock().unwrap().id.clone();
        let started = Instant::now();
        stage("settle", "exit_observed", &machine, pid, started, true);
        let started = Instant::now();
        let _guard = e.lock.lock().await;
        stage("settle", "lock", &machine, pid, started, true);
        let mut exit = {
            let live = e.live.lock().unwrap();
            match live.as_ref() {
                Some(l) if l.pid == pid => l.exit.clone(),
                _ => return,
            }
        };
        let rec = e.snapshot();
        if rec.clone_origin.is_some() {
            let confirmed = e
                .live
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|live| *live.exited.borrow());
            if !confirmed {
                tracing::error!(
                    machine,
                    "clone exit unconfirmed: retaining process and reservation"
                );
                return;
            }
            e.rec
                .lock()
                .unwrap()
                .clone_origin
                .as_mut()
                .unwrap()
                .mapping_exited = true;
        }
        let started = Instant::now();
        let revoked = self.unplug(&rec.id, &rec.ip).await;
        stage("settle", "network", &machine, pid, started, revoked.is_ok());
        *e.live.lock().unwrap() = None;
        // The init's report, or none: the process is gone, so the wait ends either way. A
        // process that ended without the init's word (killed, a kernel panic) reads as 255;
        // nothing the guest prints on its console can set its exit.
        let started = Instant::now();
        let reported = exit.wait_for(|r| r.is_some()).await.is_ok();
        stage("settle", "exit_report", &machine, pid, started, reported);
        let report = exit.borrow().clone().unwrap_or(guest::ExitReport {
            code: 255,
            ..Default::default()
        });
        let (code, oom, requested) = (report.code, report.oom, report.requested);
        let stop_req = e.stop_req.lock().unwrap().take();
        if stop_req.is_none() && !requested {
            self.exited(e, code, oom, code != 0);
            return;
        }
        let Some(why) = stop_req else {
            e.set_state(state::STOPPED, |r| {
                r.pid = 0;
                r.stopped_at = Some(Utc::now());
                r.stopped_reason = stop::USER.into();
                Some(
                    Ev::normal(reason::STOPPED, "stopped on request")
                        .data(json!({ "reason": stop::USER })),
                )
            });
            let _ = self.save(e);
            return;
        };
        self.settle_stopped(e, &why);
    }

    /// A stop asked for `why` is done, its process gone: `stopped` with that reason, or
    /// `suspended` when it kept a memory snapshot.
    pub(super) fn settle_stopped(&self, e: &Entry, why: &str) {
        if e.snapshot().clone_origin.is_some()
            && e.live
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|v| !*v.exited.borrow())
        {
            tracing::error!(
                machine = e.snapshot().id,
                "clone stop exit unconfirmed; reservation retained"
            );
            return;
        }
        let started = Instant::now();
        let (machine, pid) = {
            let rec = e.rec.lock().unwrap();
            (rec.id.clone(), rec.pid)
        };
        *e.stop_deadline.lock().unwrap() = None;
        e.set_state(state::STOPPED, |r| {
            r.pid = 0;
            r.stopped_at = Some(Utc::now());
            r.stopped_reason = why.into();
            tracing::info!(machine = r.id, reason = why, "machine stopped");
            let ev = match r.suspended {
                true => Ev::normal(
                    reason::SUSPENDED,
                    format!("suspended ({why}): its memory snapshot kept"),
                ),
                false => Ev::normal(reason::STOPPED, format!("stopped ({why})")),
            };
            Some(ev.data(json!({ "reason": why })))
        });
        let saved = self.save(e);
        stage(
            "settle",
            "record_stopped",
            &machine,
            pid,
            started,
            saved.is_ok(),
        );
    }

    /// A process that ended on its own, or that a probe ended (`failed` whatever its code):
    /// the exit recorded and the restart policy's decision. A restart waits the backoff (ADR
    /// 0022): 10 s doubling to 5 minutes by `recent_restarts`, which a run of `RESET_AFTER`
    /// clears; from the third in a row it is a crash loop. Under the machine's lock.
    pub(super) fn exited(&self, e: &Arc<Entry>, code: i32, oom: bool, failed: bool) {
        let now = Utc::now();
        let mut restart = None;
        e.set_state(state::STOPPED, |r| {
            r.pid = 0;
            r.stopped_at = Some(now);
            if r.started_at.is_some_and(|t| now - t >= RESET_AFTER) {
                r.recent_restarts = 0;
            }
            let again = restarts_after_exit(&r.restart, failed, r.restarts);
            r.exit = Some(api::Exit {
                code,
                oom_killed: oom,
                at: now,
                restarting: again,
            });
            r.stopped_reason = stop::EXIT.into();
            if again {
                r.restarts += 1;
                r.recent_restarts += 1;
                e.meter.lock().unwrap().restarts += 1;
                let delay = restart_delay(r.recent_restarts);
                r.restarting_at = Some(now + delay);
                restart = Some((r.restarts, r.recent_restarts, delay, r.restart.clone()));
                tracing::warn!(
                    machine = r.id,
                    code,
                    oom,
                    restart = r.restarts,
                    delay_sec = delay.as_secs(),
                    "machine exited, restarting"
                );
            } else {
                r.restarts = 0;
                r.recent_restarts = 0;
                r.restarting_at = None;
                tracing::info!(machine = r.id, code, oom, "machine exited");
            }
            let ev = match (oom, code) {
                (true, _) => Ev::warning(reason::EXITED, "killed: out of memory"),
                (false, 0) if !failed => Ev::normal(reason::EXITED, "exited with code 0"),
                (false, _) => Ev::warning(reason::EXITED, format!("exited with code {code}")),
            };
            Some(ev.data(json!({ "code": code, "oom": oom, "restarting": again })))
        });
        if let Some((attempt, recent, delay, policy)) = &restart {
            let secs = delay.as_secs();
            let bound = match policy.policy.as_str() {
                "always" => "always".to_string(),
                _ => format!("at most {}", policy.max_retries),
            };
            e.note(
                Ev::warning(
                    reason::RESTARTING,
                    format!("restart {attempt} in {secs} s ({bound})"),
                )
                .data(json!({ "attempt": attempt, "policy": policy.policy, "delay_sec": secs })),
            );
            if *recent >= CRASH_LOOP_AT {
                e.note(
                    Ev::warning(
                        reason::CRASH_LOOP,
                        format!(
                            "restarted {recent} times in a row, no run of 10 minutes between: next in {secs} s"
                        ),
                    )
                    .data(json!({ "restarts": recent, "delay_sec": secs })),
                );
            }
        }
        let _ = self.save(e);
        let Some((_, _, delay, _)) = restart else {
            return;
        };
        let (m, e) = (self.clone(), e.clone());
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _turns = e.lock_for_start().await;
            let r = e.snapshot();
            if r.state != state::STOPPED || r.stopped_reason != stop::EXIT {
                return;
            }
            match m.start_boxed(&e, false).await {
                Ok(()) => {}
                Err(err @ MError::BootFailed(_)) => {
                    tracing::warn!(machine = r.id, err = %err, "restart")
                }
                Err(err) => tracing::error!(machine = r.id, err = %err, "restart"),
            }
        });
    }

    /// The last `max` bytes of the console since the current boot began.
    fn console_since(&self, r: &Record, max: u64) -> String {
        let dir = self.inner.cfg.run_dir().join(&r.id);
        let end = console::end(&dir).unwrap_or(0);
        let from = r.console_offset.max(end.saturating_sub(max));
        let Ok(Some((_, bytes))) = console::read_from(&dir, from) else {
            return String::new();
        };
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = bytes.take(max).read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }

    pub(super) fn last_console_lines(&self, r: &Record, n: usize) -> String {
        let text = self.console_since(r, 64 << 10);
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(n);
        lines[start..].join(" | ")
    }

    // --- stop ---

    /// Ends the process of a machine whose entry lock is held: asks the guest to stop and
    /// kills after `grace` (at once when zero), waits for Firecracker to be gone, then clears
    /// the entry itself, since the watcher cannot take the lock to settle it, and wakes whoever
    /// waited for that.
    pub(super) async fn end_process(&self, e: &Arc<Entry>, live: &fc::Vm, grace: Duration) {
        let mut exited = live.exited.clone();
        if !*exited.borrow() {
            let asked = !grace.is_zero()
                && tokio::time::timeout(
                    Duration::from_secs(5),
                    self.inner.guest.shutdown(&live.vsock, grace),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            let gone = asked
                && tokio::time::timeout(grace + Duration::from_secs(5), exited.wait_for(|x| *x))
                    .await
                    .is_ok();
            if !gone {
                self.inner.vmm.kill(live.pid);
                let _ = exited.wait_for(|x| *x).await;
            }
        }
        if e.snapshot().clone_origin.is_some() {
            if !*exited.borrow() {
                tracing::error!(
                    machine = e.snapshot().id,
                    "clone exit unconfirmed; backing and reservation retained"
                );
                return;
            }
            e.rec
                .lock()
                .unwrap()
                .clone_origin
                .as_mut()
                .unwrap()
                .mapping_exited = true;
            let _ = self.save(e);
        }
        *e.live.lock().unwrap() = None;
        *e.stop_req.lock().unwrap() = None;
        let r = e.snapshot();
        let _ = self.unplug(&r.id, &r.ip).await;
        e.changed.notify_waiters();
    }

    pub async fn stop(
        &self,
        id: &str,
        timeout: Duration,
        suspend: bool,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        self.ordinary_operation(&e.snapshot())?;
        self.stop_entry(&e, stop::USER, timeout, suspend, at)
            .await?;
        Ok(self.view(&e))
    }

    /// Asks the guest to end its process, then waits for Firecracker to exit; after the grace,
    /// kills. Takes the entry's lock only briefly so the watcher can settle the state. `at` is
    /// the caller's `If-Match`, checked under that lock.
    pub(super) async fn stop_entry(
        &self,
        e: &Arc<Entry>,
        why: &str,
        timeout: Duration,
        suspend: bool,
        at: Option<u64>,
    ) -> Result<(), MError> {
        let timeout = if timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            timeout
        };
        let total = Instant::now();
        let machine = e.rec.lock().unwrap().id.clone();
        let operation = if suspend { "suspend" } else { "stop" };
        let live = {
            let started = Instant::now();
            let _guard = e.lock.lock().await;
            let pid = e.rec.lock().unwrap().pid;
            stage(operation, "lock", &machine, pid, started, true);
            self.check_version(e, at)?;
            let r = e.snapshot();
            match r.state.as_str() {
                state::STOPPED | state::CREATED | state::ERROR => {
                    if r.state == state::STOPPED
                        && why == stop::USER
                        && r.stopped_reason != stop::USER
                    {
                        let mut rec = e.rec.lock().unwrap();
                        rec.stopped_reason = stop::USER.into();
                        let ev = Ev::normal(
                            reason::STOPPED,
                            format!("stopped on request (it was {})", r.stopped_reason),
                        );
                        e.note_locked(&mut rec, ev.data(json!({ "reason": stop::USER })));
                        drop(rec);
                        let _ = self.save(e);
                    }
                    return Ok(());
                }
                state::RUNNING => {}
                state::STOPPING => {
                    // Another stop is in flight: wait for the watcher to settle it. The wait
                    // is registered before the lock goes, or a settle in between is missed.
                    let settled = e.changed.notified();
                    tokio::pin!(settled);
                    settled.as_mut().enable();
                    drop(_guard);
                    let _ = tokio::time::timeout(timeout + Duration::from_secs(15), settled).await;
                    return Ok(());
                }
                other => return Err(MError::BadState(other.into())),
            }
            let live = e.live.lock().unwrap().clone();
            let live = match live {
                Some(l) => l,
                None => return Err(MError::NotRunning("no process".into())),
            };
            *e.stop_req.lock().unwrap() = Some(why.to_string());
            // What this call waits at most below, the lock released: a start waits as long.
            *e.stop_deadline.lock().unwrap() =
                Some(tokio::time::Instant::now() + timeout + Duration::from_secs(20));
            let started = Instant::now();
            e.set_state(state::STOPPING, |_| {
                Some(
                    Ev::normal(reason::STOPPING, format!("stopping ({why})"))
                        .data(json!({ "reason": why, "suspend": suspend })),
                )
            });
            let saved = self.save(e);
            stage(
                operation,
                "record_stopping",
                &machine,
                live.pid,
                started,
                saved.is_ok(),
            );
            // A suspend keeps a memory snapshot: the next start resumes in well under a
            // second. Refused, the machine is stopped the plain way.
            let started = Instant::now();
            let suspended = suspend
                && match self.inner.vmm.snapshot(&live, true).await {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::warn!(machine = r.id, err = %err, "suspend refused, stopping");
                        false
                    }
                };
            if suspend {
                stage(
                    operation, "snapshot", &machine, live.pid, started, suspended,
                );
            }
            if suspended {
                self.inner
                    .stats
                    .suspends
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // The guest is paused and saved: end the process; the watcher settles the
                // state with the reason set above. The watcher takes the entry's lock to do
                // it, so the lock is released before waiting, or the wait only ends when it
                // times out.
                let started = Instant::now();
                let identity = self.memory_identity(e, &e.snapshot());
                {
                    let mut rec = e.rec.lock().unwrap();
                    rec.suspended = true;
                    rec.boot_identity = identity;
                }
                let saved = self.save(e);
                stage(
                    operation,
                    "record_suspended",
                    &machine,
                    live.pid,
                    started,
                    saved.is_ok(),
                );
                let settled = e.changed.notified();
                tokio::pin!(settled);
                settled.as_mut().enable();
                let started = Instant::now();
                stage(operation, "kill_begin", &machine, live.pid, started, true);
                self.inner.vmm.kill(live.pid);
                drop(_guard);
                let settled = tokio::time::timeout(Duration::from_secs(15), settled).await;
                stage(
                    operation,
                    "kill_to_notify",
                    &machine,
                    live.pid,
                    started,
                    settled.is_ok(),
                );
                stage(
                    operation,
                    "total",
                    &machine,
                    live.pid,
                    total,
                    settled.is_ok(),
                );
                return Ok(());
            }
            live
        };
        let settled = e.changed.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        if let Err(err) = tokio::time::timeout(
            Duration::from_secs(5),
            self.inner.guest.shutdown(&live.vsock, timeout),
        )
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r)
        {
            tracing::warn!(machine = e.snapshot().id, err = %err, "guest shutdown request failed, killing");
            self.inner.vmm.kill(live.pid);
        }
        let mut exited = live.exited.clone();
        if !*exited.borrow()
            && tokio::time::timeout(timeout + Duration::from_secs(5), exited.changed())
                .await
                .is_err()
        {
            tracing::warn!(
                machine = e.snapshot().id,
                "guest did not stop in time, killing"
            );
            self.inner.vmm.kill(live.pid);
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), settled).await;
        Ok(())
    }

    // --- destroy ---

    /// A destroy through the API: missing is success.
    pub async fn destroy(&self, id: &str, at: Option<u64>) -> Result<(), MError> {
        match self.own_entry(id) {
            Err(MError::NotFound) => Ok(()),
            Err(err) => Err(err),
            Ok(_) => self.destroy_machine(id, at).await,
        }
    }

    /// One critical section under the entry's lock, from the state to the record's removal:
    /// nothing starts the machine in between, and a destroy that fails leaves it
    /// `destroying` for the sleeper's tick to try again. `at` is the caller's `If-Match`.
    pub(super) async fn destroy_machine(&self, id: &str, at: Option<u64>) -> Result<(), MError> {
        let e = match self.entry(id) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        let others = {
            let _guard = e.lock.lock().await;
            if !self.inner.machines.lock().unwrap().contains_key(id) {
                // A destroy that held the lock before this one finished the job.
                return Ok(());
            }
            self.destroy_locked(&e, id, at).await?
        };
        // Its lock released, it is gone: the machines its disks touched are tidied, each
        // under its own lock (ADR 0031).
        self.tidy_machines(others).await;
        Ok(())
    }

    /// The destroy's critical section. Returns the machines to tidy after it: those its disks
    /// were cloned from, whose snapshot may be free now, and the forks promoted over it,
    /// which hold its snapshots now.
    async fn destroy_locked(
        &self,
        e: &Arc<Entry>,
        id: &str,
        at: Option<u64>,
    ) -> Result<Vec<String>, MError> {
        let e = e.clone();
        self.check_version(&e, at)?;
        self.check_clone_readers(id, None)?;
        // No event: the destroy is one step, and `destroyed` ends it.
        e.set_state(state::DESTROYING, |_| None);
        let _ = self.save(&e);
        let live = e.live.lock().unwrap().clone();
        if let Some(live) = live {
            self.end_process(&e, &live, Duration::from_secs(5)).await;
            if e.snapshot().clone_origin.is_some() && !*live.exited.borrow() {
                return Err(MError::Conflict("clone VMM exit is unconfirmed".into()));
            }
        }
        if e.snapshot()
            .clone_origin
            .as_ref()
            .is_some_and(|o| !o.mapping_exited && o.stage != templates::CloneStage::Reserved)
        {
            return Err(MError::Conflict(
                "clone mapping exit proof is unavailable; all backing retained".into(),
            ));
        }
        for ep in self.endpoints_of(id) {
            let _ = self.delete_endpoint(&ep.id);
        }
        let rec = e.snapshot();
        self.unplug(id, &rec.ip).await?;
        self.inner.net.clear_connections(&rec.ip).await?;
        // Its last use, measured while its disks and counters are still there; the bucket
        // stays after it (ADR 0017).
        self.meter(std::slice::from_ref(&e), Utc::now()).await;
        self.inner
            .net
            .uncount(&rec.ip)
            .await
            .context("usage counters")?;
        // A fork is a clone of this machine's disks: it takes the snapshots over and lives on.
        // What this machine's disks were cloned from is read after that, since a promotion
        // moves it: the snapshot it leaves behind goes once nothing clones it.
        let z = &self.inner.zfs;
        let mut others = Vec::new();
        let had_disks = z.exists(&rec.dataset()).await.context("disks")?;
        if had_disks {
            let promoted = z
                .release_clones(&rec.dataset())
                .await
                .context("forks of the disks")?;
            others.extend(
                promoted
                    .iter()
                    .filter_map(|c| snapshots::machine_of(c))
                    .map(String::from),
            );
            for ds in z.volumes_under(&rec.dataset()).await.context("disks")? {
                if let Some((origin, _)) = z.origin(&ds).await.context("origin of the disks")? {
                    others.extend(
                        snapshots::machine_of(&origin)
                            .filter(|m| *m != id)
                            .map(String::from),
                    );
                }
            }
            z.destroy(&rec.dataset()).await.context("disks")?;
        }
        let _ = tokio::fs::remove_dir_all(self.inner.cfg.run_dir().join(id)).await;
        if let Some(j) = self.jail_for(&rec) {
            let _ =
                tokio::fs::remove_dir_all(fc::jail_root(&j.base, id).parent().unwrap_or(&j.base))
                    .await;
        }
        for snapshot in &rec.snapshots {
            if snapshot.clone_artifact.is_some() {
                self.remove_memory(&rec, &snapshot.id);
            }
        }
        if let Some(origin) = &rec.clone_origin {
            if origin.mapping_exited || origin.stage == templates::CloneStage::Reserved {
                let (_, gone) = tokio::sync::watch::channel(true);
                self.release_clone_reader(id, &gone)?;
            } else {
                return Err(MError::Conflict(
                    "clone mapping exit proof is unavailable; backing retained".into(),
                ));
            }
        }
        // Its backups stay, for a restore: a holder keeps them listed, counted and finite.
        self.hold_at_destroy(&rec, had_disks, e.backup_turn.clone())
            .await?;
        self.forget(&e)?;
        self.remove_machine(&e);
        self.inner
            .events
            .emit(Ev::normal(reason::DESTROYED, "destroyed").of(id, &rec.namespace));
        tracing::info!(machine = id, "machine destroyed");
        others.sort();
        others.dedup();
        Ok(others)
    }
}

/// Whether a machine whose process ended on its own (a failure: an exit code other than 0, or
/// a probe that ended it; after `restarts` restarts in a row) is started again.
pub(super) fn restarts_after_exit(
    policy: &api::RestartPolicy,
    failed: bool,
    restarts: u32,
) -> bool {
    match policy.policy.as_str() {
        "always" => true,
        "on-failure" => failed && restarts < policy.max_retries,
        _ => false,
    }
}

/// A run this long ends a crash loop: the backoff starts over at its exit (ADR 0022).
pub(super) const RESET_AFTER: chrono::Duration = chrono::Duration::minutes(10);

/// The restart in a crash loop from which each one is a `crash_loop` event.
const CRASH_LOOP_AT: u32 = 3;

/// How long the `n`th restart since a run of `RESET_AFTER` waits: 10 s, doubling, at most
/// 5 minutes, as Kubernetes's CrashLoopBackOff.
pub(super) fn restart_delay(n: u32) -> Duration {
    let doubled = 10u64 << n.saturating_sub(1).min(5);
    Duration::from_secs(doubled.min(300))
}
