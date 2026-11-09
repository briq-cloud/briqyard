//! Dormant regional synchronous execution. The caller is a trusted, authenticated
//! control handler that independently supplies the current delegation intent ID.
//! It must fence policy/membership changes and old ownership through the protected
//! deadline. Source identity and expiry come from the independently authenticated
//! installed delegation control snapshot. Revocation must be propagated through
//! the journal's retained delegation revoke before new admission. No per-command
//! remote lookup is needed. No public route calls this coordinator.
use crate::execution_host::{HostTransport, Route};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::{
    execution::{
        admission::{AuthorityPayload, OperationIntent, OperationPhase, PreparedAdmission},
        channel::{AdmissionStatus, BundleRequest, Dispatch, Prepare, StatusRequest},
        exec_request_digest, token_digest, verify_delegation, AllocationRef, Clock,
        DelegationContext, DispatchContext, DurableIssuer, IssueCredentials, IssueError, Operation,
        Permit, Trust, MAX_BODY_BYTES,
    },
    ExecRequest, ExecResult,
};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(super) enum Error {
    Binding,
    Conflict,
    Journal,
    Unconfirmed,
}

pub(super) struct Control {
    pub id: String,
    pub delegation_intent: String,
    pub grant: String,
    pub projection_digest: String,
    pub request: ExecRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Status {
    pub phase: OperationPhase,
    pub unconfirmed: bool,
}

pub(super) enum ExecOutcome {
    /// Only the first confirmed execution receives transient bounded guest output.
    Completed { status: Status, result: ExecResult },
    /// Every retained ID is status-only, regardless of its prior phase.
    Existing(Status),
}

pub(super) struct Coordinator<'a> {
    pub issuer: &'a mut DurableIssuer,
    pub host: &'a HostTransport,
    pub host_id: &'a str,
}

impl Coordinator<'_> {
    pub fn status(&mut self, id: &str) -> Result<Option<Status>, Error> {
        let op = self
            .issuer
            .installation_journal()
            .operation_intent(id)
            .map_err(|_| Error::Journal)?;
        Ok(op.map(|op| Status {
            phase: op.phase,
            unconfirmed: op.unconfirmed
                || matches!(
                    op.phase,
                    OperationPhase::Reserved
                        | OperationPhase::Dispatched
                        | OperationPhase::Consumed
                ),
        }))
    }

    /// Explicit recovery observation. Host absence or an uncertain reply never
    /// establishes non-execution and never permits another prepare or dispatch.
    pub async fn observe(&mut self, id: &str, clock: Clock) -> Result<Status, Error> {
        let saved = self
            .issuer
            .installation_journal()
            .operation_intent(id)
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Binding)?
            .clone();
        if saved.phase == OperationPhase::Finished {
            return self.status(id)?.ok_or(Error::Binding);
        }
        let reply: AdmissionStatus = match self
            .host
            .call(
                Route::Status,
                &StatusRequest {
                    admission: id.into(),
                },
            )
            .await
        {
            Ok(reply) => reply,
            Err(_) => {
                self.issuer
                    .installation_journal()
                    .mark_operation_unconfirmed(id, clock)
                    .map_err(|_| Error::Journal)?;
                return Err(Error::Unconfirmed);
            }
        };
        if saved.phase == OperationPhase::Dispatched
            && reply.dispatched
            && matches!(
                reply.journal,
                Some(
                    briqyard_api::execution::admission::Status::Consumed
                        | briqyard_api::execution::admission::Status::Finished
                )
            )
        {
            self.issuer
                .installation_journal()
                .record_operation_evidence(id, OperationPhase::Consumed, None, clock)
                .map_err(|_| Error::Journal)?;
        }
        self.status(id)?.ok_or(Error::Binding)
    }

    /// One call per new ID. Any existing ID, including a crash before issuance,
    /// returns local status only. No retry chooses a new host or resends a frame.
    pub async fn exec(
        &mut self,
        control: Control,
        trust: &Trust<'_>,
        mut fresh_clock: impl FnMut() -> Result<Clock, Error>,
    ) -> Result<ExecOutcome, Error> {
        let clock = fresh_clock()?;
        let journal = self.issuer.installation_journal();
        let projection = journal
            .presented_projection(&control.delegation_intent, &control.grant, clock)
            .map_err(|_| Error::Binding)?;
        if projection.projection.digest() != control.projection_digest {
            return Err(Error::Binding);
        }
        if let Some(old) = journal
            .operation_intent(&control.id)
            .map_err(|_| Error::Journal)?
        {
            if old.delegation != control.delegation_intent
                || exec_request_digest(&control.request, &old.permit.limits)
                    .map_err(|_| Error::Conflict)?
                    != old.request_digest
            {
                return Err(Error::Conflict);
            }
            return Ok(ExecOutcome::Existing(Status {
                phase: old.phase,
                unconfirmed: old.unconfirmed
                    || matches!(
                        old.phase,
                        OperationPhase::Reserved
                            | OperationPhase::Dispatched
                            | OperationPhase::Consumed
                    ),
            }));
        }
        if !journal
            .delegation_intent_ready(&control.delegation_intent)
            .map_err(|_| Error::Journal)?
        {
            return Err(Error::Binding);
        }
        let installed = journal
            .delegation_intent(&control.delegation_intent)
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Binding)?
            .clone();
        let registration = journal
            .authority_intent(&installed.registration)
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Binding)?
            .clone();
        let ownership = journal
            .authority_intent(&installed.ownership)
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Binding)?
            .clone();
        let protection = journal
            .protection_intent(&installed.protection)
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Binding)?
            .clone();
        let (AuthorityPayload::Registration(reg), AuthorityPayload::Ownership(owner)) =
            (&registration.payload, &ownership.payload)
        else {
            return Err(Error::Binding);
        };
        if installed.host != self.host_id
            || !installed.trusted_source.as_ref().is_some_and(|source| {
                source.expires_at > clock.now.saturating_add(clock.uncertainty)
            })
            || installed.authority_epoch != journal.instance()
            || registration.host != self.host_id
            || ownership.host != self.host_id
            || protection.host != self.host_id
            || reg.host_instance != owner.host_instance
            || reg.epoch != journal.instance()
            || installed.request.installation != owner.installation
            || installed.request.generation != owner.generation
            || installed.request.protection_expires_at_ms != protection.request.expires_at_ms
        {
            return Err(Error::Binding);
        }
        let tokens: Vec<&str> = installed
            .request
            .allocations
            .iter()
            .map(String::as_str)
            .collect();
        let checked = verify_delegation(
            &installed.request.grant,
            &tokens,
            trust,
            clock,
            &DelegationContext {
                principal: &installed.request.principal,
                team: &owner.team,
                subject: &owner.subject,
                target: &owner.primary,
                resource_set: &owner.resource_set,
                metadata_revision: &owner.metadata_revision,
                authority: &reg.authority,
                authority_epoch: &reg.epoch,
            },
        )
        .map_err(|_| Error::Binding)?;
        if checked.grant().id != installed.request.id
            || installed.trusted_source.as_ref() != Some(&checked.grant().source)
            || token_digest(&installed.request.grant) != installed.expected.grant_digest
            || checked.allocation_digests() != installed.expected.allocation_digests
            || checked.grant().idle.admission != protection.request.admission
            || checked.grant().idle.expires_at != protection.request.expires_at_ms / 1000
            || !checked.grant().operations.contains(&Operation::Exec)
        {
            return Err(Error::Binding);
        }
        let limits = checked.grant().limits.clone();
        let max_output_bytes = limits.max_output_bytes;
        let digest = exec_request_digest(&control.request, &limits).map_err(|_| Error::Binding)?;
        let exp = checked
            .allocations()
            .iter()
            .fold(checked.grant().exp, |expiry, a| expiry.min(a.exp))
            .min(checked.grant().source.expires_at)
            .min(protection.request.expires_at_ms / 1000)
            .min(clock.now.saturating_add(60));
        if exp <= clock.now.saturating_add(clock.uncertainty)
            || control.request.timeout_ms > exp.saturating_sub(clock.now).saturating_mul(1000)
        {
            return Err(Error::Binding);
        }
        // Choose the qualified interval's lower bound, after credential lower
        // bounds have been verified against that same interval.
        let issued_at = clock
            .now
            .checked_sub(clock.uncertainty)
            .ok_or(Error::Binding)?;
        let permit = Permit {
            v: 1,
            iss: trust.authority_issuer.into(),
            aud: trust.audience.into(),
            iat: issued_at,
            nbf: issued_at,
            exp,
            admission: control.id.clone(),
            authority: reg.authority.clone(),
            authority_epoch: reg.epoch.clone(),
            grant_digest: token_digest(&installed.request.grant),
            allocations: checked
                .allocations()
                .iter()
                .zip(checked.allocation_digests())
                .map(|(a, digest)| AllocationRef {
                    id: a.id.clone(),
                    epoch: a.epoch.clone(),
                    digest: digest.clone(),
                    units: 1,
                })
                .collect(),
            target: owner.primary.clone(),
            operation: Operation::Exec,
            request_digest: digest.clone(),
            metadata_revision: owner.metadata_revision.clone(),
            limits,
        };
        let bundle = BundleRequest {
            installation: owner.installation.clone(),
            generation: owner.generation,
            delegation: installed.request.id.clone(),
            grant: installed.request.grant.clone(),
            allocations: installed.request.allocations.clone(),
            permit: String::new(),
        };
        // The immutable intent is fsynced before the first permit is signed or
        // capacity is debited. A crash here burns the ID conservatively.
        journal
            .begin_operation(
                OperationIntent {
                    id: control.id.clone(),
                    delegation: control.delegation_intent,
                    authority_epoch: reg.epoch.clone(),
                    host: self.host_id.into(),
                    host_instance: reg.host_instance.clone(),
                    request_digest: digest.clone(),
                    permit: permit.clone(),
                    phase: OperationPhase::Intent,
                    permit_digest: None,
                    prepared: None,
                    outcome_digest: None,
                    unconfirmed: false,
                },
                clock,
            )
            .map_err(|_| Error::Journal)?;
        let context = DispatchContext {
            principal: &installed.request.principal,
            team: &owner.team,
            subject: &owner.subject,
            target: &owner.primary,
            resource_set: &owner.resource_set,
            metadata_revision: &owner.metadata_revision,
            authority: &reg.authority,
            authority_epoch: &reg.epoch,
            installed_allocations: &permit.allocations,
            operation: Operation::Exec,
            request_digest: &digest,
        };
        let issue_clock = fresh_clock()?;
        let token = self
            .issuer
            .issue_with_preflight(
                IssueCredentials {
                    grant: &bundle.grant,
                    allocations: &tokens,
                },
                permit.clone(),
                trust,
                issue_clock,
                &context,
                |token| {
                    let mut bundle = bundle.clone();
                    bundle.permit = token.into();
                    let prepare = Prepare {
                        bundle: bundle.clone(),
                        request_digest: digest.clone(),
                        admission: control.id.clone(),
                    };
                    let dispatch = Dispatch {
                        bundle,
                        admission: control.id.clone(),
                        request: control.request.clone(),
                    };
                    if serde_json::to_vec(&prepare).map_or(true, |b| b.len() > MAX_BODY_BYTES)
                        || serde_json::to_vec(&dispatch).map_or(true, |b| b.len() > MAX_BODY_BYTES)
                    {
                        return Err(IssueError::Verify(
                            briqyard_api::execution::VerifyError::Encoding,
                        ));
                    }
                    Ok(())
                },
            )
            .map_err(|_| Error::Binding)?;
        self.issuer
            .installation_journal()
            .bind_operation_permit(
                &control.id,
                token_digest(&token),
                fresh_clock().map_err(|_| Error::Unconfirmed)?,
            )
            .map_err(|_| Error::Journal)?;
        let mut bundle = bundle;
        bundle.permit = token;
        let prepare = Prepare {
            bundle: bundle.clone(),
            request_digest: digest,
            admission: control.id.clone(),
        };
        let ack: PreparedAdmission = match self.host.call(Route::Prepare, &prepare).await {
            Ok(ack) => ack,
            Err(_) => {
                return self
                    .unconfirmed(&control.id, fresh_clock().map_err(|_| Error::Unconfirmed)?)
            }
        };
        if self
            .issuer
            .installation_journal()
            .acknowledge_operation_prepare(
                &control.id,
                ack,
                fresh_clock().map_err(|_| Error::Unconfirmed)?,
            )
            .is_err()
        {
            return self.unconfirmed(&control.id, fresh_clock().map_err(|_| Error::Unconfirmed)?);
        }
        self.issuer
            .installation_journal()
            .mark_operation_dispatch(&control.id, fresh_clock().map_err(|_| Error::Unconfirmed)?)
            .map_err(|_| Error::Journal)?;
        let dispatch = Dispatch {
            bundle,
            admission: control.id.clone(),
            request: control.request,
        };
        let result: ExecResult = match self.host.call(Route::Dispatch, &dispatch).await {
            Ok(result) => result,
            Err(_) => {
                return self
                    .unconfirmed(&control.id, fresh_clock().map_err(|_| Error::Unconfirmed)?)
            }
        };
        let output_bytes = result
            .stdout
            .len()
            .checked_add(result.stderr.len())
            .ok_or(Error::Unconfirmed)?;
        if output_bytes as u64 > max_output_bytes {
            return self.unconfirmed(&control.id, fresh_clock().map_err(|_| Error::Unconfirmed)?);
        }
        // Retain only a commitment to the bounded terminal response.
        let bytes = serde_json::to_vec(&result).map_err(|_| Error::Binding)?;
        let outcome = URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        self.issuer
            .installation_journal()
            .record_operation_evidence(
                &control.id,
                OperationPhase::Finished,
                Some(outcome),
                fresh_clock().map_err(|_| Error::Unconfirmed)?,
            )
            .map_err(|_| Error::Journal)?;
        Ok(ExecOutcome::Completed {
            status: Status {
                phase: OperationPhase::Finished,
                unconfirmed: false,
            },
            result,
        })
    }

    fn unconfirmed(&mut self, id: &str, clock: Clock) -> Result<ExecOutcome, Error> {
        self.issuer
            .installation_journal()
            .mark_operation_unconfirmed(id, clock)
            .map_err(|_| Error::Journal)?;
        Err(Error::Unconfirmed)
    }
}
