//! Scoped execution never takes the administrator route or wakes a machine. The
//! caller supplies an installed trusted ownership snapshot and the regional key set.
//! No HTTP route calls this boundary until authenticated snapshot installation exists.
use super::*;
use api::execution::{
    self as access, admission::Journal, DispatchContext, Operation, Target, Trust,
};

/// Exact request from the authenticated ownership installer, before a grant or
/// operation permit exists. The installer keeps its revision fence until ACK.
pub struct ExecutionProtectionRequest<'a> {
    pub admission: &'a str,
    pub expires_at_ms: u64,
    pub target: &'a Target,
    pub subject: &'a str,
    pub resources: &'a [Target],
    pub resource_revision: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProtectionReceipt {
    pub admission: String,
    pub expires_at_ms: u64,
    pub targets: Vec<Target>,
    pub resource_revision: String,
}

pub struct ScopedCredentials<'a> {
    pub grant: &'a str,
    pub permit: &'a str,
    pub allocations: &'a [&'a str],
}

impl Manager {
    /// Install a pre-permit idle bound on every exact local run. The trusted caller
    /// retains its ownership revision fence across this call. This receipt alone
    /// does not freeze membership or authorize descriptor issuance.
    pub async fn protect_execution_resources(
        &self,
        request: ExecutionProtectionRequest<'_>,
        journal: &tokio::sync::Mutex<Journal>,
        clock_uncertainty_seconds: u64,
    ) -> Result<ExecutionProtectionReceipt, MError> {
        let targets = request.resources;
        if targets.is_empty() || targets.len() > access::MAX_RESOURCES {
            return Err(invalid("invalid execution protection resources"));
        }
        let mut ordered = targets.iter().collect::<Vec<_>>();
        ordered.sort_by(|a, b| a.machine.cmp(&b.machine));
        if ordered
            .windows(2)
            .any(|pair| pair[0].machine == pair[1].machine)
            || ordered.iter().any(|t| t.host != self.inner.host_id)
        {
            return Err(MError::Conflict(
                "execution protection requires distinct local runs".into(),
            ));
        }
        let entries = ordered
            .iter()
            .map(|t| self.entry(&t.machine))
            .collect::<Result<Vec<_>, _>>()?;
        let locks = entries.iter().map(|e| e.lock.clone()).collect::<Vec<_>>();
        let _turns = tokio::time::timeout(Duration::from_secs(10), local_turns(&locks))
            .await
            .map_err(|_| MError::Conflict("execution resources remain busy".into()))?;
        let ledger = journal.lock().await;
        self.scoped_journal(&ledger)?;
        for (target, entry) in ordered.iter().zip(&entries) {
            if self.scoped_target(entry, ledger.instance())? != **target {
                return Err(MError::Conflict("execution target changed".into()));
            }
        }
        let entry = entries
            .iter()
            .find(|e| e.snapshot().id == request.target.machine)
            .ok_or_else(|| invalid("execution target missing from resources"))?;
        if !targets.contains(request.target) {
            return Err(invalid("execution primary target missing from resources"));
        }
        if entry.snapshot().metadata.get("briq_id").map(String::as_str) != Some(request.subject) {
            return Err(MError::Conflict("execution subject changed".into()));
        }
        execution_clock(clock_uncertainty_seconds)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid("execution clock unavailable"))?
            .as_millis();
        let expires_at_ms = request.expires_at_ms;
        if u128::from(expires_at_ms) <= now_ms + u128::from(clock_uncertainty_seconds) * 1000
            || u128::from(expires_at_ms) > now_ms + 60_000
        {
            return Err(invalid("execution protection interval exceeds policy"));
        }
        let snapshot = self.execution_namespace_snapshot(targets)?;
        if execution_mutations::execution_resource_revision(targets, &snapshot)?
            != request.resource_revision
        {
            return Err(MError::Conflict(
                "execution namespace generation changed".into(),
            ));
        }
        self.inner
            .execution_fence
            .lock()
            .unwrap()
            .protect(
                &self.inner.store,
                &snapshot,
                expires_at_ms,
                execution_mutations::execution_now_ms()?,
            )
            .map_err(|_| MError::Conflict("execution namespace protection unresolved".into()))?;
        self.inner
            .idle_protection
            .lock()
            .unwrap()
            .accept(&self.inner.store, request.admission, targets, expires_at_ms)
            .map_err(|_| MError::Conflict("execution protection persistence unresolved".into()))?;
        // A successful fsync is followed by a final live identity check while every
        // lifecycle turn remains held. No ACK can refer to a replaced run.
        for (target, entry) in ordered.iter().zip(&entries) {
            if self.scoped_target(entry, ledger.instance())? != **target {
                return Err(MError::Conflict(
                    "execution target changed after protection".into(),
                ));
            }
        }
        if entry.snapshot().metadata.get("briq_id").map(String::as_str) != Some(request.subject) {
            return Err(MError::Conflict(
                "execution subject changed after protection".into(),
            ));
        }
        Ok(ExecutionProtectionReceipt {
            admission: request.admission.into(),
            expires_at_ms,
            targets: targets.to_vec(),
            resource_revision: request.resource_revision.into(),
        })
    }
    /// Read-only discovery of one actual run. Lifecycle callers must hold the same
    /// machine lock while using this value for admission. Events invalidate placement
    /// conservatively; it is never inferred from a reusable logical machine ID.
    pub async fn execution_target(
        &self,
        id: &str,
        journal: &tokio::sync::Mutex<Journal>,
    ) -> Result<Target, MError> {
        let e = self.entry(id)?;
        let _turn = e.lock.lock().await;
        let ledger = journal.lock().await;
        self.scoped_journal(&ledger)?;
        self.scoped_target(&e, ledger.instance())
    }

    fn scoped_journal(&self, journal: &Journal) -> Result<(), MError> {
        if journal.role() != &access::admission::Role::Host(self.inner.host_id.clone()) {
            return Err(invalid("execution journal belongs to another host"));
        }
        Ok(())
    }

    fn scoped_target(&self, e: &Entry, admission_instance: &str) -> Result<Target, MError> {
        let record = e.snapshot();
        self.ordinary_operation(&record)?;
        if record.state != state::RUNNING || *e.removed.lock().unwrap() {
            return Err(MError::NotRunning(
                "scoped execution requires the live run".into(),
            ));
        }
        let live = e
            .live
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MError::NotRunning("no live execution identity".into()))?;
        let incarnation = live
            .incarnation
            .as_ref()
            .ok_or_else(|| MError::Conflict("execution process identity unavailable".into()))?;
        // Positive live kernel evidence, never an old record or a process ID alone.
        if *live.exited.borrow()
            || fc::Incarnation::read(live.pid).as_ref() != Some(incarnation)
            || record.boot_incarnation.as_ref() != Some(incarnation)
        {
            return Err(MError::Conflict(
                "execution process identity changed".into(),
            ));
        }
        Ok(Target {
            host: self.inner.host_id.clone(),
            machine: record.id,
            namespace: record.namespace,
            run: access::process_run_id(
                &incarnation.host_boot_id,
                incarnation.pid,
                incarnation.start_ticks,
                admission_instance,
            ),
            placement: format!("version-{}", record.version),
        })
    }

    /// The ownership snapshot must be from the authenticated metadata installer, never
    /// assembled by copying the submitted grant. The caller retains its revision fence
    /// through this call. The host checks every frozen local run itself before dispatch.
    pub async fn scoped_exec(
        &self,
        request: api::ExecRequest,
        credentials: ScopedCredentials<'_>,
        trust: &Trust<'_>,
        context: &DispatchContext<'_>,
        journal: &tokio::sync::Mutex<Journal>,
        clock_uncertainty_seconds: u64,
    ) -> Result<api::ExecResult, MError> {
        if context.operation != Operation::Exec
            || context.resource_set.resources.is_empty()
            || context.resource_set.resources.len() > access::MAX_RESOURCES
        {
            return Err(invalid("unsupported scoped operation"));
        }
        self.own_entry(&context.target.machine)?;
        // Stable order is shared by every scoped operation. Stop/move/restore already
        // use these lifecycle locks. Remote frozen members need a distributed fence;
        // that capability is deliberately unavailable in this first local boundary.
        let mut resources = context.resource_set.resources.iter().collect::<Vec<_>>();
        resources.sort_by(|a, b| a.machine.cmp(&b.machine));
        if resources.windows(2).any(|r| r[0].machine == r[1].machine)
            || resources.iter().any(|r| r.host != self.inner.host_id)
        {
            return Err(MError::Conflict(
                "frozen execution resources require local authority".into(),
            ));
        }
        let entries = resources
            .iter()
            .map(|r| self.entry(&r.machine))
            .collect::<Result<Vec<_>, _>>()?;
        let locks = entries.iter().map(|e| e.lock.clone()).collect::<Vec<_>>();
        let turns = tokio::time::timeout(Duration::from_secs(10), local_turns(&locks))
            .await
            .map_err(|_| MError::Conflict("execution resources remain busy".into()))?;
        let mut ledger = journal.lock().await;
        self.scoped_journal(&ledger)?;
        for (resource, e) in resources.iter().zip(&entries) {
            if self.scoped_target(e, ledger.instance())? != **resource {
                return Err(MError::Conflict("execution target changed".into()));
            }
        }
        let entry = entries
            .iter()
            .find(|e| e.snapshot().id == context.target.machine)
            .ok_or_else(|| invalid("execution target missing from frozen resources"))?;
        // The external identity is bound to the host's operator-owned machine metadata.
        if entry.snapshot().metadata.get("briq_id").map(String::as_str) != Some(context.subject) {
            return Err(MError::Conflict("execution subject changed".into()));
        }
        let clock = execution_clock(clock_uncertainty_seconds)?;
        let bundle = access::verify_bundle(
            credentials.grant,
            credentials.permit,
            credentials.allocations,
            trust,
            clock,
            context,
        )
        .map_err(|_| invalid("execution credentials refused"))?;
        let digest = access::exec_request_digest(&request, &bundle.permit().limits)
            .map_err(|_| invalid("execution request exceeds its authority"))?;
        if digest != context.request_digest {
            return Err(invalid("execution request commitment mismatch"));
        }
        let deadline = guestc::CommandDeadline::new(bundle.permit().exp, clock.uncertainty)
            .map_err(not_running_if_unreachable)?;
        let snapshot = self.execution_namespace_snapshot(&context.resource_set.resources)?;
        if execution_mutations::execution_resource_revision(
            &context.resource_set.resources,
            &snapshot,
        )? != context.resource_set.revision
            || !self
                .inner
                .execution_fence
                .lock()
                .unwrap()
                .check_protected(
                    &snapshot,
                    bundle
                        .permit()
                        .exp
                        .checked_mul(1000)
                        .ok_or_else(|| invalid("execution deadline exceeds range"))?,
                    execution_mutations::execution_now_ms()?,
                )
                .map_err(|_| MError::Conflict("execution namespace protection unresolved".into()))?
        {
            return Err(MError::Conflict(
                "execution namespace generation or protection changed".into(),
            ));
        }
        // This fsync is the final no-replay boundary. Every subsequent failure is an
        // uncertain consumed outcome, including cancellation before any guest frame.
        ledger
            .consume(&bundle, clock)
            .map_err(|_| MError::Conflict("execution admission refused; query status".into()))?;
        let in_use = entries
            .iter()
            .map(|e| InUse::new(e.clone()))
            .collect::<Vec<_>>();
        let live = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MError::NotRunning("execution run ended".into()))?;
        // Recheck after synchronous durable I/O; timeout_at alone polls its inner
        // future before deciding that its deadline has passed.
        deadline.check().map_err(|_| {
            MError::Conflict("execution admission consumed after expiry; outcome unresolved".into())
        })?;
        let remaining_ms = deadline
            .remaining()
            .map_err(not_running_if_unreachable)?
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if remaining_ms == 0 {
            return Err(invalid("execution authority expired"));
        }
        let greq = guest::Request {
            op: "exec".into(),
            cmd: request.cmd,
            env: request.env,
            cwd: request.cwd,
            stdin: request.stdin.into_bytes(),
            timeout_ms: request.timeout_ms.min(remaining_ms),
            ..Default::default()
        };
        let handshake_deadline = deadline
            .instant
            .min(tokio::time::Instant::now() + Duration::from_secs(10));
        let mut conn = tokio::time::timeout_at(
            handshake_deadline,
            self.inner
                .guest
                .scoped_session(&live.vsock, greq, deadline.clone()),
        )
        .await
        .map_err(|_| MError::NotRunning("scoped command dispatch unresolved".into()))?
        .map_err(not_running_if_unreachable)?;
        // The allocation and lifecycle fences covered the initial guest frame.
        drop(ledger);
        drop(turns);
        let out = tokio::time::timeout_at(
            deadline.instant,
            guestc::collect_limited(&mut conn, bundle.permit().limits.max_output_bytes),
        )
        .await
        .map_err(|_| {
            MError::NotRunning("execution authorization expired; outcome unresolved".into())
        })?
        .map_err(not_running_if_unreachable)?;
        // Drop the guest connection at the authorization deadline on all error paths.
        // Cleanup of detached work is not inferred from closing this connection.
        drop(conn);
        drop(in_use);
        journal
            .lock()
            .await
            .finish(bundle.permit(), execution_clock(clock_uncertainty_seconds)?)
            .map_err(|_| MError::Conflict("execution completion persistence unresolved".into()))?;
        Ok(api::ExecResult {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.code,
            timed_out: out.timed_out,
        })
    }
}
fn execution_clock(uncertainty: u64) -> Result<access::Clock, MError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid("execution clock unavailable"))?
        .as_secs();
    if uncertainty > 5 {
        return Err(invalid("execution clock uncertainty exceeds policy"));
    }
    Ok(access::Clock { now, uncertainty })
}

// Other lifecycle operations may hold a machine while starting its gateway. Never
// wait for a second resource while retaining a subset, even in stable ID order.
async fn local_turns(
    locks: &[Arc<tokio::sync::Mutex<()>>],
) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
    loop {
        let mut held = Vec::with_capacity(locks.len());
        let mut busy = None;
        for lock in locks {
            match lock.clone().try_lock_owned() {
                Ok(turn) => held.push(turn),
                Err(_) => {
                    busy = Some(lock.clone());
                    break;
                }
            }
        }
        let Some(busy) = busy else {
            return held;
        };
        drop(held);
        drop(busy.lock_owned().await);
        tokio::task::yield_now().await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn scoped_resource_wait_never_retains_a_partial_set_of_lifecycle_locks() {
        let first = Arc::new(tokio::sync::Mutex::new(()));
        let second = Arc::new(tokio::sync::Mutex::new(()));
        let blocker = second.lock().await;
        let locks = [first.clone(), second.clone()];
        let turns = local_turns(&locks);
        tokio::pin!(turns);
        assert!(futures::poll!(&mut turns).is_pending());
        assert!(
            first.try_lock().is_ok(),
            "gateway/lifecycle lock must remain available while another resource is busy"
        );
        drop(blocker);
        let held = tokio::time::timeout(Duration::from_secs(1), turns)
            .await
            .unwrap();
        assert_eq!(held.len(), 2);
    }
}
