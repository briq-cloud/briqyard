//! Live operation timer. The host retains the dispatch fence through consumption
//! and guest acceptance, then uses this guard for the entire connection.
//! Only exact durable journal ACKs may reach `apply_committed` or `revoke_committed`.
use briqyard_api::execution::{
    admission::{ActiveOperation, ActivePhase},
    clock::ClockSample,
    MAX_COMMAND_SECONDS,
};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct ActiveLease {
    inner: Arc<Inner>,
}
struct Inner {
    state: Mutex<State>,
    changed: Notify,
}
struct State {
    evidence: ActiveOperation,
    deadline: tokio::time::Instant,
    operation_deadline: tokio::time::Instant,
    ended: bool,
    running: bool,
}

fn narrowed_deadline(
    expires_ms: u64,
    sample: &ClockSample,
) -> anyhow::Result<tokio::time::Instant> {
    let upper = sample
        .wall
        .checked_add(sample.uncertainty)
        .ok_or_else(|| anyhow::anyhow!("execution clock range"))?;
    let remaining = Duration::from_millis(expires_ms)
        .checked_sub(upper)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| anyhow::anyhow!("active execution lease expired"))?;
    Ok(tokio::time::Instant::from_std(sample.monotonic) + remaining)
}

impl ActiveLease {
    /// Evidence must come from a committed first-frame acknowledgement, never a
    /// Reserved/Consumed status read. Construction grants no dispatch permission.
    pub fn from_committed(evidence: ActiveOperation, sample: &ClockSample) -> anyhow::Result<Self> {
        anyhow::ensure!(
            evidence.phase == ActivePhase::Active,
            "operation is not active"
        );
        let deadline = Self::validate(&evidence, sample)?;
        let operation_deadline = narrowed_deadline(evidence.binding.operation_deadline_ms, sample)?;
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    evidence,
                    deadline,
                    operation_deadline,
                    ended: false,
                    running: false,
                }),
                changed: Notify::new(),
            }),
        })
    }

    /// Activation retains the original consumption-time monotonic bounds. A new
    /// qualified wall observation can narrow them, but cannot revive elapsed time.
    pub fn from_committed_bounded(
        evidence: ActiveOperation,
        sample: &ClockSample,
        initial_deadline: tokio::time::Instant,
        operation_deadline: tokio::time::Instant,
    ) -> anyhow::Result<Self> {
        let now = tokio::time::Instant::now();
        anyhow::ensure!(
            now < initial_deadline && now < operation_deadline,
            "initial execution authorization expired before active commit"
        );
        let lease = Self::from_committed(evidence, sample)?;
        {
            let mut state = lease.inner.state.lock().unwrap();
            state.deadline = state.deadline.min(initial_deadline);
            state.operation_deadline = state.operation_deadline.min(operation_deadline);
        }
        Ok(lease)
    }

    fn validate(e: &ActiveOperation, sample: &ClockSample) -> anyhow::Result<tokio::time::Instant> {
        let expiry = e
            .lease_expires_at
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("active execution lease range"))?;
        anyhow::ensure!(
            e.binding.is_valid()
                && e.checked_at
                    <= sample
                        .interval()
                        .ok_or_else(|| anyhow::anyhow!("execution clock range"))?
                        .now
                && e.lease_expires_at <= e.checked_at.saturating_add(MAX_COMMAND_SECONDS)
                && expiry <= e.binding.operation_deadline_ms
                && e.lease_expires_at <= e.binding.source.expires_at
                && e.protection.expires_at_ms >= expiry
                && e.protection.installation == e.binding.ownership
                && e.protection.generation == e.binding.ownership_generation
                && e.protection.resources == e.binding.resource_set.resources
                && e.protection.resource_revision == e.binding.resource_set.revision,
            "active execution lease binding"
        );
        let deadline = narrowed_deadline(expiry, sample)?;
        anyhow::ensure!(
            deadline > tokio::time::Instant::now()
                && deadline - tokio::time::Instant::from_std(sample.monotonic)
                    <= Duration::from_secs(MAX_COMMAND_SECONDS),
            "active execution lease exceeds freshness"
        );
        Ok(deadline)
    }

    /// Serialize this call with revoke/completion *after* journal fsync. Applying
    /// an ACK after old monotonic expiry refuses even if wall time moved backward.
    pub fn apply_committed(
        &self,
        evidence: ActiveOperation,
        sample: &ClockSample,
    ) -> anyhow::Result<()> {
        let mut state = self.inner.state.lock().unwrap();
        anyhow::ensure!(
            !state.ended
                && tokio::time::Instant::now() < state.deadline
                && tokio::time::Instant::now() < state.operation_deadline,
            "active execution lease ended"
        );
        // Fresh qualification must still cover the old lease, not merely the new one.
        narrowed_deadline(state.evidence.lease_expires_at * 1000, sample)?;
        anyhow::ensure!(
            evidence.phase == ActivePhase::Active
                && evidence.binding == state.evidence.binding
                && state.evidence.sequence.checked_add(1) == Some(evidence.sequence)
                && evidence.lease_expires_at > state.evidence.lease_expires_at
                && evidence.checked_at >= state.evidence.checked_at,
            "active execution lease ordering"
        );
        let deadline = Self::validate(&evidence, sample)?.min(state.operation_deadline);
        state.evidence = evidence;
        state.deadline = deadline;
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(())
    }

    pub fn revoke_committed(&self, evidence: &ActiveOperation) -> anyhow::Result<()> {
        let mut state = self.inner.state.lock().unwrap();
        anyhow::ensure!(
            evidence.phase == ActivePhase::Revoked
                && evidence.binding == state.evidence.binding
                && evidence.sequence == state.evidence.sequence,
            "active execution revocation binding"
        );
        state.ended = true;
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(())
    }

    /// A fresh observation of the actual retained live lease, never journal status.
    pub fn observe(&self, expected: &ActiveOperation, sample: &ClockSample) -> anyhow::Result<()> {
        let state = self.inner.state.lock().unwrap();
        anyhow::ensure!(
            !state.ended
                && state.evidence == *expected
                && tokio::time::Instant::now() < state.deadline
                && tokio::time::Instant::now() < state.operation_deadline,
            "active execution lease ended or changed"
        );
        narrowed_deadline(state.evidence.lease_expires_at * 1000, sample)?;
        Ok(())
    }
    pub fn end(&self) {
        self.inner.state.lock().unwrap().ended = true;
        self.inner.changed.notify_waiters();
    }
    pub fn check_io(&self) -> std::io::Result<()> {
        let check = || -> anyhow::Result<()> {
            let sample = ClockSample::read()
                .ok_or_else(|| anyhow::anyhow!("qualified execution clock unavailable"))?;
            let state = self.inner.state.lock().unwrap();
            anyhow::ensure!(
                !state.ended
                    && tokio::time::Instant::now() < state.deadline
                    && tokio::time::Instant::now() < state.operation_deadline,
                "active execution lease ended"
            );
            narrowed_deadline(state.evidence.lease_expires_at * 1000, &sample)?;
            Ok(())
        };
        check().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "active execution authorization unavailable",
            )
        })
    }

    /// The guard owns a timer independent of guest traffic. Quiet reads/writes
    /// wake on expiry/revoke. It never restarts `work` after an update or failure.
    pub fn run<'a, F: Future + 'a>(
        &'a self,
        work: F,
    ) -> impl Future<Output = anyhow::Result<F::Output>> + 'a {
        self.run_qualified(work, ClockSample::read)
    }

    fn run_qualified<'a, F: Future + 'a>(
        &'a self,
        work: F,
        clock: impl Fn() -> Option<ClockSample> + 'a,
    ) -> impl Future<Output = anyhow::Result<F::Output>> + 'a {
        struct EndOnDrop(ActiveLease);
        impl Drop for EndOnDrop {
            fn drop(&mut self) {
                self.0.inner.state.lock().unwrap().ended = true;
                self.0.inner.changed.notify_waiters();
            }
        }
        // Construct the owner synchronously: dropping an unpolled guard also ends
        // the command. A second guard cannot take ownership of the same operation.
        let end = (|| -> anyhow::Result<EndOnDrop> {
            let mut state = self.inner.state.lock().unwrap();
            anyhow::ensure!(
                !state.ended && !state.running,
                "active execution already guarded"
            );
            state.running = true;
            Ok(EndOnDrop(self.clone()))
        })();
        async move {
            let _end = end?;
            tokio::pin!(work);
            let checked_work = futures::future::poll_fn(|cx| {
                let sample = match clock() {
                    Some(sample) => sample,
                    None => {
                        return std::task::Poll::Ready(Err(anyhow::anyhow!(
                            "qualified execution clock unavailable"
                        )))
                    }
                };
                {
                    let state = self.inner.state.lock().unwrap();
                    if state.ended
                        || tokio::time::Instant::now() >= state.deadline
                        || narrowed_deadline(state.evidence.lease_expires_at * 1000, &sample)
                            .is_err()
                    {
                        return std::task::Poll::Ready(Err(anyhow::anyhow!(
                            "active execution lease ended"
                        )));
                    }
                }
                work.as_mut().poll(cx).map(Ok)
            });
            tokio::pin!(checked_work);
            loop {
                let changed = self.inner.changed.notified();
                tokio::pin!(changed);
                // Register before reading state: no update can be missed between the
                // snapshot and select, including a revocation with no guest activity.
                changed.as_mut().enable();
                let deadline = {
                    let sample = clock()
                        .ok_or_else(|| anyhow::anyhow!("qualified execution clock unavailable"))?;
                    let mut state = self.inner.state.lock().unwrap();
                    let wall_deadline =
                        narrowed_deadline(state.evidence.lease_expires_at * 1000, &sample)?;
                    state.deadline = state.deadline.min(wall_deadline);
                    anyhow::ensure!(
                        !state.ended && tokio::time::Instant::now() < state.deadline,
                        "active execution lease ended"
                    );
                    state.deadline.min(state.operation_deadline)
                };
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => {
                        self.inner.state.lock().unwrap().ended = true;
                        anyhow::bail!("active execution lease expired");
                    }
                    _ = &mut changed => continue,
                    result = &mut checked_work => {
                        let sample = clock().ok_or_else(|| anyhow::anyhow!("qualified execution clock unavailable"))?;
                        let mut state = self.inner.state.lock().unwrap();
                        anyhow::ensure!(!state.ended, "active execution lease ended");
                        state.ended = true;
                        anyhow::ensure!(tokio::time::Instant::now() < state.deadline,
                            "active execution lease expired");
                        narrowed_deadline(state.evidence.lease_expires_at * 1000, &sample)?;
                        return result;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqyard_api::execution::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn evidence() -> ActiveOperation {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../briqyard-api/tests/fixtures/execution-v1.json"
        ))
        .unwrap();
        let g: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
        let mut limits = g.limits;
        limits.execution_mode = Some(ExecutionMode::RenewableExecV1);
        limits.max_duration_seconds = 60;
        ActiveOperation {
            binding: ActiveOperationBinding {
                operation_id: "operation".into(),
                admission: "admission".into(),
                grant_digest: token_digest("grant"),
                permit_digest: token_digest("permit"),
                request_digest: token_digest("request"),
                authority: "authority".into(),
                authority_epoch: "epoch".into(),
                host_instance: "host-instance".into(),
                ownership: "owner".into(),
                ownership_generation: 1,
                policy_revision: "policy".into(),
                delegation: "delegation".into(),
                delegation_version: 1,
                principal: g.principal,
                source: g.source,
                team: g.team,
                subject: g.subject,
                metadata_revision: g.metadata_revision,
                target: g.target,
                resource_set: g.resource_set.clone(),
                limits,
                guest_timeout_ms: 60_000,
                started_at_ms: 999_000,
                operation_deadline_ms: 1_079_000,
            },
            phase: ActivePhase::Active,
            sequence: 0,
            checked_at: 999,
            lease_expires_at: 1000,
            protection: briqyard_api::execution::admission::InstalledProtection {
                installation: "owner".into(),
                generation: 1,
                admission: "protection".into(),
                expires_at_ms: 1_060_000,
                resources: g.resource_set.resources,
                resource_revision: g.resource_set.revision,
            },
        }
    }
    fn clock(base: tokio::time::Instant) -> impl Fn() -> Option<ClockSample> + Send {
        move || {
            Some(ClockSample {
                wall: Duration::from_millis(999_900) + (tokio::time::Instant::now() - base),
                monotonic: tokio::time::Instant::now().into_std(),
                uncertainty: Duration::ZERO,
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn active_commit_cannot_reconstruct_expired_initial_monotonic_authority() {
        let base = tokio::time::Instant::now();
        let mut evidence = evidence();
        evidence.checked_at = 100;
        evidence.lease_expires_at = 107;
        evidence.binding.started_at_ms = 100_000;
        evidence.binding.operation_deadline_ms = 180_000;
        // The first qualified interval is [96,104] at this monotonic origin.
        let initial = base + Duration::from_secs(3);
        let operation = base + Duration::from_secs(76);
        tokio::time::advance(Duration::from_millis(3500)).await;
        let fresh = ClockSample {
            wall: Duration::from_millis(101_500),
            uncertainty: Duration::from_secs(1),
            monotonic: tokio::time::Instant::now().into_std(),
        };
        // The new interval, translated to that origin, is [97,99]. It overlaps
        // the original evidence yet reconstructs a later lease deadline.
        assert!(ActiveLease::from_committed(evidence.clone(), &fresh).is_ok());
        assert!(
            ActiveLease::from_committed_bounded(evidence.clone(), &fresh, initial, operation)
                .is_err()
        );
        let lease = ActiveLease::from_committed_bounded(
            evidence,
            &fresh,
            base + Duration::from_secs(4),
            operation,
        )
        .unwrap();
        let state = lease.inner.state.lock().unwrap();
        assert!(state.deadline <= base + Duration::from_secs(4));
        assert!(state.operation_deadline <= operation);
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_connection_wakes_at_lease_expiry_without_an_io_frame() {
        let base = tokio::time::Instant::now();
        let lease = ActiveLease::from_committed(evidence(), &clock(base)().unwrap()).unwrap();
        let runner = lease.clone();
        let task = tokio::spawn(async move {
            runner
                .run_qualified(std::future::pending::<()>(), clock(base))
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(101)).await;
        assert!(task.await.unwrap().is_err());
        let mut renewed = evidence();
        renewed.sequence = 1;
        renewed.lease_expires_at = 1001;
        assert!(lease
            .apply_committed(renewed, &clock(base)().unwrap())
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn continuation_changes_timer_once_without_restarting_work_and_revoke_wakes_it() {
        let base = tokio::time::Instant::now();
        let lease = ActiveLease::from_committed(evidence(), &clock(base)().unwrap()).unwrap();
        let runner = lease.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let started = count.clone();
        let task = tokio::spawn(async move {
            runner
                .run_qualified(
                    async move {
                        started.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<()>().await
                    },
                    clock(base),
                )
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(50)).await;
        let mut renewed = evidence();
        renewed.sequence = 1;
        renewed.checked_at = 999;
        renewed.lease_expires_at = 1001;
        lease
            .apply_committed(renewed.clone(), &clock(base)().unwrap())
            .unwrap();
        assert!(lease
            .apply_committed(renewed.clone(), &clock(base)().unwrap())
            .is_err());
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        renewed.phase = ActivePhase::Revoked;
        lease.revoke_committed(&renewed).unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        renewed.phase = ActivePhase::Active;
        renewed.sequence += 1;
        renewed.lease_expires_at += 1;
        assert!(lease
            .apply_committed(renewed, &clock(base)().unwrap())
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn committed_revocation_during_terminal_poll_rejects_success() {
        let base = tokio::time::Instant::now();
        let lease = ActiveLease::from_committed(evidence(), &clock(base)().unwrap()).unwrap();
        let revoker = lease.clone();
        let result = lease
            .run_qualified(
                async move {
                    let mut revoked = evidence();
                    revoked.phase = ActivePhase::Revoked;
                    revoker.revoke_committed(&revoked).unwrap();
                },
                clock(base),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn clock_loss_cancellation_and_completed_work_cannot_resume() {
        let base = tokio::time::Instant::now();
        for stop in ["clock", "cancel", "complete", "unpolled"] {
            let lease = ActiveLease::from_committed(evidence(), &clock(base)().unwrap()).unwrap();
            match stop {
                "unpolled" => drop(lease.run_qualified(std::future::pending::<()>(), clock(base))),
                "clock" => assert!(lease
                    .run_qualified(std::future::pending::<()>(), || None)
                    .await
                    .is_err()),
                "complete" => {
                    lease.run_qualified(async {}, clock(base)).await.unwrap();
                }
                "cancel" => {
                    let mut future =
                        Box::pin(lease.run_qualified(std::future::pending::<()>(), clock(base)));
                    assert!(futures::poll!(&mut future).is_pending());
                    drop(future);
                }
                _ => unreachable!(),
            }
            let mut renewed = evidence();
            renewed.sequence = 1;
            renewed.lease_expires_at = 1001;
            assert!(
                lease
                    .apply_committed(renewed, &clock(base)().unwrap())
                    .is_err(),
                "{stop}"
            );
        }
        let mut pending = evidence();
        pending.phase = ActivePhase::Consumed;
        assert!(ActiveLease::from_committed(pending, &clock(base)().unwrap()).is_err());
    }
}
