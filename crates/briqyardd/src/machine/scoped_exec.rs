//! Scoped execution never takes the administrator route or wakes a machine. The
//! caller supplies an installed trusted ownership snapshot and the regional key set.
//! No HTTP route calls this boundary until authenticated snapshot installation exists.
use super::execution_resources::ExecutionResourceScope;
use super::*;
use api::execution::{
    self as access,
    admission::{HostOwnership, Journal},
    DispatchContext, Operation, Target, Trust,
};

/// Exact request from the authenticated ownership installer, before a grant or
/// operation permit exists. The installer keeps its revision fence until ACK.
pub struct ExecutionProtectionRequest<'a> {
    pub admission: &'a str,
    pub expires_at_ms: u64,
    pub scope: ExecutionResourceScope<'a>,
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

/// Independently installed binding and discovery seeds. Submitted credentials must
/// never supply either part of this trusted context.
pub struct ScopedExecutionContext<'a> {
    pub binding: &'a DispatchContext<'a>,
    pub scope: ExecutionResourceScope<'a>,
}

/// The authenticated handler transfers its exact initial admission fence. It is
/// released only after guest acceptance, durable active ACK and registry publication.
pub struct RenewableDispatch<'a> {
    pub guard: tokio::sync::RwLockReadGuard<'a, ()>,
    pub registry: Arc<crate::guestc::active_operations::ActiveOperations>,
    pub policy: access::admission::HostOperationPolicy,
}

impl Manager {
    pub async fn execution_public_members(
        &self,
        resources: &access::ResourceSet,
        team: &str,
        journal: &tokio::sync::Mutex<Journal>,
    ) -> Result<Vec<access::PublicResource>, MError> {
        let mut public = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for target in &resources.resources {
            let e = self.entry(&target.machine)?;
            let record = {
                let _turn = e.lock.lock().await;
                let ledger = journal.lock().await;
                if self.scoped_target(&e, ledger.instance())? != *target {
                    return Err(MError::Conflict("execution closure member changed".into()));
                }
                e.snapshot()
            };
            if let Some(id) = record.metadata.get("briq_id") {
                if record.metadata.get("team").map(String::as_str) != Some(team)
                    || !ids.insert(id.clone())
                {
                    return Err(MError::Conflict(
                        "public execution ownership changed".into(),
                    ));
                }
                public.push(access::PublicResource {
                    id: id.clone(),
                    target: target.clone(),
                });
            } else if self
                .gateway_of(&target.namespace)
                .as_ref()
                .map(|g| g.snapshot().id)
                != Some(target.machine.clone())
            {
                return Err(MError::Conflict("unclassified execution dependency".into()));
            }
        }
        Ok(public)
    }
    pub async fn resolve_execution_public_seed(
        &self,
        seed: &access::PublicSeed,
        journal: &tokio::sync::Mutex<Journal>,
    ) -> Result<Target, MError> {
        let e = self.entry(&seed.machine)?;
        let _turn = e.lock.lock().await;
        let ledger = journal.lock().await;
        self.scoped_journal(&ledger)?;
        let target = self.scoped_target(&e, ledger.instance())?;
        let record = e.snapshot();
        if record.metadata.get("briq_id") != Some(&seed.id)
            || record.metadata.get("team") != Some(&seed.team)
            || record.namespace != seed.namespace
            || seed
                .expected_version
                .is_some_and(|v| target.placement != format!("version-{v}"))
        {
            return Err(MError::Conflict("public execution seed changed".into()));
        }
        Ok(target)
    }
    /// Resolve the complete closure from installed seeds, then classify every member.
    /// A missing public identity does not make a machine native: only the host's
    /// registered namespace gateway is a supported native dependency.
    pub async fn verify_execution_ownership(
        &self,
        owner: &HostOwnership,
        journal: &tokio::sync::Mutex<Journal>,
    ) -> Result<access::ResourceSet, MError> {
        if owner.public_seeds.is_empty()
            || !owner.public_seeds.contains(&owner.primary)
            || owner.public_resources.len() > access::MAX_RESOURCES
        {
            return Err(invalid("invalid installed public execution scope"));
        }
        let scope = ExecutionResourceScope {
            primary: &owner.primary,
            required: &owner.public_seeds,
        };
        let discovered = self.execution_resources(scope, journal).await?;
        if discovered != owner.resource_set {
            return Err(MError::Conflict(
                "execution ownership closure changed".into(),
            ));
        }
        let mut mapped = std::collections::BTreeSet::new();
        let mut public_ids = std::collections::BTreeSet::new();
        for public in &owner.public_resources {
            if !mapped.insert(public.target.machine.clone())
                || !public_ids.insert(public.id.clone())
                || public.id.is_empty()
                || !discovered.resources.contains(&public.target)
            {
                return Err(invalid("invalid installed public execution mapping"));
            }
            let e = self.entry(&public.target.machine)?;
            let _turn = e.lock.lock().await;
            let ledger = journal.lock().await;
            if self.scoped_target(&e, ledger.instance())? != public.target {
                return Err(MError::Conflict("public execution run changed".into()));
            }
            let record = e.snapshot();
            if record.metadata.get("briq_id") != Some(&public.id)
                || record.metadata.get("team") != Some(&owner.team)
                || record.namespace != public.target.namespace
                || (public.target == owner.primary && public.id != owner.subject)
            {
                return Err(MError::Conflict(
                    "public execution ownership changed".into(),
                ));
            }
        }
        for resource in &discovered.resources {
            if mapped.contains(&resource.machine) {
                continue;
            }
            let gateway = self
                .gateway_of(&resource.namespace)
                .ok_or_else(|| MError::Conflict("unclassified execution dependency".into()))?;
            if gateway.snapshot().id != resource.machine {
                return Err(MError::Conflict("unclassified execution dependency".into()));
            }
            if gateway.snapshot().metadata.contains_key("briq_id") {
                return Err(MError::Conflict(
                    "public execution dependency omitted".into(),
                ));
            }
        }
        for seed in &owner.public_seeds {
            if !mapped.contains(&seed.machine) {
                return Err(invalid("unmapped public execution seed"));
            }
        }
        if self
            .execution_public_members(&discovered, &owner.team, journal)
            .await?
            != owner.public_resources
        {
            return Err(MError::Conflict("public execution mapping changed".into()));
        }
        Ok(discovered)
    }
    /// Install a pre-permit idle bound on every exact local run. The trusted caller
    /// retains its ownership revision fence across this call. This receipt alone
    /// does not freeze membership or authorize descriptor issuance.
    pub async fn protect_execution_resources(
        &self,
        request: ExecutionProtectionRequest<'_>,
        journal: &tokio::sync::Mutex<Journal>,
        _clock_uncertainty_seconds: u64,
    ) -> Result<ExecutionProtectionReceipt, MError> {
        self.validate_execution_scope(request.scope)?;
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
            .find(|e| e.snapshot().id == request.scope.primary.machine)
            .ok_or_else(|| invalid("execution target missing from resources"))?;
        if !targets.contains(request.scope.primary) {
            return Err(invalid("execution primary target missing from resources"));
        }
        if entry.snapshot().metadata.get("briq_id").map(String::as_str) != Some(request.subject) {
            return Err(MError::Conflict("execution subject changed".into()));
        }
        let sample = access::clock::ClockSample::read()
            .ok_or_else(|| invalid("qualified execution clock unavailable"))?;
        let now_ms = u128::from(
            sample
                .upper_ms()
                .ok_or_else(|| invalid("execution clock range"))?,
        );
        let expires_at_ms = request.expires_at_ms;
        if u128::from(expires_at_ms) <= now_ms
            || u128::from(expires_at_ms) > now_ms + u128::from(access::MAX_COMMAND_SECONDS) * 1000
        {
            return Err(invalid("execution protection interval exceeds policy"));
        }
        let snapshot = self.execution_namespace_snapshot(targets)?;
        self.validate_execution_set_locked(
            request.scope,
            targets,
            request.resource_revision,
            ledger.instance(),
        )?;
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
        self.validate_execution_set_locked(
            request.scope,
            targets,
            request.resource_revision,
            ledger.instance(),
        )?;
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

    pub(super) fn scoped_journal(&self, journal: &Journal) -> Result<(), MError> {
        if journal.role() != &access::admission::Role::Host(self.inner.host_id.clone()) {
            return Err(invalid("execution journal belongs to another host"));
        }
        Ok(())
    }

    pub(super) fn scoped_target(
        &self,
        e: &Entry,
        admission_instance: &str,
    ) -> Result<Target, MError> {
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
        installed: ScopedExecutionContext<'_>,
        journal: &tokio::sync::Mutex<Journal>,
        clock_uncertainty_seconds: u64,
    ) -> Result<api::ExecResult, MError> {
        self.scoped_exec_inner(
            request,
            credentials,
            trust,
            installed,
            journal,
            clock_uncertainty_seconds,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn renewable_scoped_exec(
        &self,
        request: api::ExecRequest,
        credentials: ScopedCredentials<'_>,
        trust: &Trust<'_>,
        installed: ScopedExecutionContext<'_>,
        journal: &tokio::sync::Mutex<Journal>,
        clock_uncertainty_seconds: u64,
        renewable: RenewableDispatch<'_>,
    ) -> Result<api::ExecResult, MError> {
        self.scoped_exec_inner(
            request,
            credentials,
            trust,
            installed,
            journal,
            clock_uncertainty_seconds,
            Some(renewable),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn scoped_exec_inner(
        &self,
        request: api::ExecRequest,
        credentials: ScopedCredentials<'_>,
        trust: &Trust<'_>,
        installed: ScopedExecutionContext<'_>,
        journal: &tokio::sync::Mutex<Journal>,
        clock_uncertainty_seconds: u64,
        renewable: Option<RenewableDispatch<'_>>,
    ) -> Result<api::ExecResult, MError> {
        let ScopedExecutionContext {
            binding: context,
            scope,
        } = installed;
        if context.operation != Operation::Exec
            || context.resource_set.resources.is_empty()
            || context.resource_set.resources.len() > access::MAX_RESOURCES
        {
            return Err(invalid("unsupported scoped operation"));
        }
        if context.target != scope.primary {
            return Err(invalid("installed execution primary changed"));
        }
        self.validate_execution_scope(scope)?;
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
        let sample = access::clock::ClockSample::read()
            .ok_or_else(|| invalid("qualified execution clock unavailable"))?;
        let clock = sample
            .interval()
            .ok_or_else(|| invalid("execution clock range"))?;
        let bundle = access::verify_bundle(
            credentials.grant,
            credentials.permit,
            credentials.allocations,
            trust,
            clock,
            context,
        )
        .map_err(|_| invalid("execution credentials refused"))?;
        if bundle.permit().limits.execution_mode.is_some() != renewable.is_some() {
            return Err(invalid(
                "scoped execution mode requires its exact dispatch path",
            ));
        }
        let digest = access::exec_request_digest(&request, &bundle.permit().limits)
            .map_err(|_| invalid("execution request exceeds its authority"))?;
        if digest != context.request_digest {
            return Err(invalid("execution request commitment mismatch"));
        }
        let mut deadline = guestc::CommandDeadline::from_sample(bundle.permit().exp, &sample)
            .map_err(not_running_if_unreachable)?;
        let snapshot = self.execution_namespace_snapshot(&context.resource_set.resources)?;
        self.validate_execution_set_locked(
            scope,
            &context.resource_set.resources,
            &context.resource_set.revision,
            ledger.instance(),
        )?;
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
        let initial_active = if let Some(control) = &renewable {
            let sample = access::clock::ClockSample::read()
                .ok_or_else(|| invalid("qualified execution clock unavailable"))?;
            let started_at_ms: u64 = sample
                .wall
                .as_millis()
                .try_into()
                .map_err(|_| invalid("execution clock range"))?;
            let policy = &control.policy;
            if ledger
                .operation_policy(&bundle.permit().grant_digest)
                .map_err(|_| invalid("operation policy unavailable"))?
                != Some(policy)
                || policy.host_instance != ledger.instance()
            {
                return Err(invalid("operation policy unavailable"));
            }
            let binding = access::ActiveOperationBinding {
                operation_id: bundle.permit().admission.clone(),
                admission: bundle.permit().admission.clone(),
                grant_digest: bundle.permit().grant_digest.clone(),
                permit_digest: access::token_digest(credentials.permit),
                request_digest: digest,
                authority: bundle.permit().authority.clone(),
                authority_epoch: bundle.permit().authority_epoch.clone(),
                host_instance: ledger.instance().into(),
                ownership: policy.ownership.clone(),
                ownership_generation: policy.ownership_generation,
                policy_revision: policy.policy_revision.clone(),
                delegation: policy.delegation.clone(),
                delegation_version: policy.delegation_version,
                principal: bundle.grant().principal.clone(),
                source: bundle.grant().source.clone(),
                team: bundle.grant().team.clone(),
                subject: bundle.grant().subject.clone(),
                metadata_revision: bundle.grant().metadata_revision.clone(),
                target: context.target.clone(),
                resource_set: context.resource_set.clone(),
                limits: bundle.permit().limits.clone(),
                guest_timeout_ms: request.timeout_ms,
                started_at_ms,
                operation_deadline_ms: started_at_ms
                    .checked_add(access::MAX_OPERATION_MILLIS)
                    .ok_or_else(|| invalid("operation envelope range"))?,
            };
            let protection = ledger
                .protection(&bundle.grant().idle.admission)
                .map_err(|_| invalid("operation protection unavailable"))?
                .cloned()
                .ok_or_else(|| invalid("operation protection unavailable"))?;
            self.inner
                .idle_protection
                .lock()
                .unwrap()
                .require_renewable(&self.inner.store, &protection.admission)
                .map_err(|_| invalid("renewable recovery protection unavailable"))?;
            let operation_deadline = tokio::time::Instant::from_std(sample.monotonic)
                + Duration::from_millis(
                    binding
                        .operation_deadline_ms
                        .checked_sub(
                            sample
                                .upper_ms()
                                .ok_or_else(|| invalid("operation clock range"))?,
                        )
                        .ok_or_else(|| invalid("operation envelope elapsed"))?,
                );
            Some((binding, protection, operation_deadline))
        } else {
            None
        };
        ledger
            .consume(&bundle, execution_clock(clock_uncertainty_seconds)?)
            .map_err(|_| MError::Conflict("execution admission refused; query status".into()))?;
        let operation_deadline = initial_active.as_ref().map(|(_, _, deadline)| *deadline);
        if let Some((binding, protection, _)) = initial_active {
            ledger
                .record_consumed_operation(
                    &bundle,
                    binding,
                    protection,
                    execution_clock(clock_uncertainty_seconds)?,
                )
                .map_err(|_| invalid("consumed operation persistence unresolved"))?;
        }
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
        deadline.refresh().map_err(|_| {
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
            op: if renewable.is_some() {
                "exec_renewable_v1"
            } else {
                "exec"
            }
            .into(),
            cmd: request.cmd,
            env: request.env,
            cwd: request.cwd,
            stdin: request.stdin.into_bytes(),
            timeout_ms: if renewable.is_some() {
                request.timeout_ms
            } else {
                request.timeout_ms.min(remaining_ms)
            },
            ..Default::default()
        };
        let handshake_deadline = deadline
            .instant
            .min(tokio::time::Instant::now() + Duration::from_secs(10));
        let mut conn = tokio::time::timeout_at(handshake_deadline, async {
            if renewable.is_some() {
                self.inner
                    .guest
                    .renewable_session(&live.vsock, greq, deadline.clone())
                    .await
            } else {
                self.inner
                    .guest
                    .scoped_session(&live.vsock, greq, deadline.clone())
                    .await
            }
        })
        .await
        .map_err(|_| MError::NotRunning("scoped command dispatch unresolved".into()))?
        .map_err(not_running_if_unreachable)?;
        let mut active_owner = None;
        let mut active_lease = None;
        let mut terminal_deadline = deadline.instant;
        if let Some(control) = renewable {
            let evidence = ledger
                .acknowledge_active_operation(
                    &bundle.permit().admission,
                    execution_clock(clock_uncertainty_seconds)?,
                )
                .map_err(|_| invalid("active operation acknowledgement unresolved"))?;
            let sample = access::clock::ClockSample::read()
                .ok_or_else(|| invalid("qualified execution clock unavailable"))?;
            let lease = guestc::active_lease::ActiveLease::from_committed_bounded(
                evidence,
                &sample,
                deadline.instant,
                operation_deadline.ok_or_else(|| invalid("operation deadline missing"))?,
            )
            .map_err(not_running_if_unreachable)?;
            active_owner = Some(
                control
                    .registry
                    .register(&bundle.permit().admission, lease.clone())
                    .map_err(not_running_if_unreachable)?,
            );
            terminal_deadline =
                tokio::time::Instant::now() + Duration::from_millis(request.timeout_ms + 10_000);
            conn = Box::new(guestc::active_operations::ActiveConnection {
                conn,
                lease: lease.clone(),
            });
            active_lease = Some(lease);
            // Every initial-generation check, first guest ACK, durable ACK and live
            // publication preceded this release. Control changes may now progress.
            drop(control.guard);
        }
        // The allocation and lifecycle fences covered the initial guest frame.
        drop(ledger);
        drop(turns);
        let collect = async {
            let limits = &bundle.permit().limits;
            match limits.output_mode {
                Some(api::execution::OutputMode::CapturePerStreamV1) => {
                    guestc::collect_capture(&mut conn, limits.max_output_bytes).await
                }
                None => guestc::collect_limited(&mut conn, limits.max_output_bytes).await,
            }
        };
        let guarded = async {
            if let Some(lease) = &active_lease {
                lease.run(collect).await?
            } else {
                collect.await
            }
        };
        let out = tokio::time::timeout_at(terminal_deadline, guarded)
            .await
            .map_err(|_| {
                MError::NotRunning("execution deadline expired; outcome unresolved".into())
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
        drop(active_owner);
        Ok(api::ExecResult {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.code,
            timed_out: out.timed_out,
        })
    }
}
fn execution_clock(_uncertainty: u64) -> Result<access::Clock, MError> {
    access::clock::ClockSample::read()
        .and_then(|sample| sample.interval())
        .ok_or_else(|| invalid("qualified execution clock unavailable"))
}

// Other lifecycle operations may hold a machine while starting its gateway. Never
// wait for a second resource while retaining a subset, even in stable ID order.
pub(super) async fn local_turns(
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
