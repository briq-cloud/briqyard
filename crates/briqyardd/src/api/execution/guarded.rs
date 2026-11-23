//! Host installation and dispatch on a dedicated opt-in authenticated TLS listener.
use crate::machine::{
    guarded_exec::{
        ChannelDispatch, ExecutionProtectionRequest, GuardedManager, ScopedCredentials,
        ScopedExecutionContext,
    },
    ExecutionResourceScope,
};
use axum::{
    extract::{DefaultBodyLimit, FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use briqyard_api::{
    self as api,
    execution::{
        self as access,
        admission::{
            Error as JournalError, HostDelegation, HostOwnership, HostRegistration,
            InstalledProtection, Journal, PreparedAdmission,
        },
        channel::*,
        AllocationRef, Clock, DelegationContext, DispatchContext, Operation, Trust,
        VerificationKey,
    },
};
use context::{AdmissionTurns, RequestIdentity, RequestRole, SealedContextSource};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

use super::context;
mod renewal;

type Answer<T> = Result<Json<T>, StatusCode>;
type Channel = State<Arc<GuardedHostExecutionChannel>>;

struct InstallerRequest(RequestIdentity);
struct ExecutionRequest(RequestIdentity);

#[axum::async_trait]
impl FromRequestParts<Arc<GuardedHostExecutionChannel>> for InstallerRequest {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        st: &Arc<GuardedHostExecutionChannel>,
    ) -> Result<Self, Self::Rejection> {
        st.authorize(&parts.headers, RequestRole::Installer)
            .map(Self)
    }
}

#[axum::async_trait]
impl FromRequestParts<Arc<GuardedHostExecutionChannel>> for ExecutionRequest {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        st: &Arc<GuardedHostExecutionChannel>,
    ) -> Result<Self, Self::Rejection> {
        st.authorize(&parts.headers, RequestRole::Execution)
            .map(Self)
    }
}

fn ack<T: Serialize>(
    host_instance: &str,
    generation: u64,
    value: &T,
) -> Result<InstallationAck, StatusCode> {
    let bytes = serde_json::to_vec(value).map_err(|_| StatusCode::CONFLICT)?;
    Ok(InstallationAck {
        host_instance: host_instance.into(),
        generation,
        digest: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
    })
}

/// A construction error leaves no listener. Tokens must be independently provisioned.
pub struct GuardedHostExecutionChannel {
    manager: GuardedManager,
    journal: Mutex<Journal>,
    admission: AdmissionTurns,
    active: Arc<crate::guestc::guarded_operations::GuardedOperations>,
    installer_token: String,
    execution_token: String,
    keys: Vec<VerificationKey>,
    central_issuer: String,
    authority_issuer: String,
    audience: String,
    clock_uncertainty_seconds: u64,
}

impl GuardedHostExecutionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: GuardedManager,
        journal: Journal,
        installer_token: String,
        execution_token: String,
        keys: Vec<VerificationKey>,
        central_issuer: String,
        authority_issuer: String,
        audience: String,
        clock_uncertainty_seconds: u64,
    ) -> Result<Self, StatusCode> {
        if installer_token.is_empty()
            || execution_token.is_empty()
            || installer_token == execution_token
            || keys.is_empty()
            || central_issuer.is_empty()
            || authority_issuer.is_empty()
            || audience.is_empty()
            || clock_uncertainty_seconds > 5
        {
            return Err(StatusCode::FORBIDDEN);
        }
        let admission = AdmissionTurns::new(&journal)?;
        Ok(Self {
            manager,
            journal: Mutex::new(journal),
            admission,
            active: Arc::new(crate::guestc::guarded_operations::GuardedOperations::default()),
            installer_token,
            execution_token,
            keys,
            central_issuer,
            authority_issuer,
            audience,
            clock_uncertainty_seconds,
        })
    }

    /// Select protected admission before publishing the listener. The protected
    /// startup driver must supply committed guard evidence, even when closed.
    pub fn with_sealed_contexts(mut self, source: Arc<dyn SealedContextSource>) -> Self {
        self.admission = self.admission.with_sealed_contexts(source);
        self
    }

    fn trust<'a>(&'a self, keys: &'a [VerificationKey]) -> Trust<'a> {
        Trust {
            keys,
            central_issuer: &self.central_issuer,
            authority_issuer: &self.authority_issuer,
            audience: &self.audience,
        }
    }

    fn registered_keys(
        &self,
        registration: &HostRegistration,
    ) -> Result<Vec<VerificationKey>, StatusCode> {
        registered_keys(&self.keys, &self.authority_issuer, registration)
    }

    fn clock(&self) -> Result<Clock, StatusCode> {
        access::clock::ClockSample::read()
            .and_then(|sample| sample.interval())
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)
    }

    fn authorize(
        &self,
        headers: &HeaderMap,
        role: RequestRole,
    ) -> Result<RequestIdentity, StatusCode> {
        let expected = match role {
            RequestRole::Installer => &self.installer_token,
            RequestRole::Execution => &self.execution_token,
        };
        let got = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if got.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        self.admission
            .capture(role, got.as_bytes(), expected.as_bytes())
    }

    async fn authorized_journal(
        &self,
        request: &RequestIdentity,
    ) -> Result<MutexGuard<'_, Journal>, StatusCode> {
        self.admission.writer(request, &self.journal).await
    }
}

fn registered_keys(
    configured: &[VerificationKey],
    authority_issuer: &str,
    registration: &HostRegistration,
) -> Result<Vec<VerificationKey>, StatusCode> {
    let keys = configured
        .iter()
        .filter(|k| match k.role {
            access::KeyRole::Central => true,
            access::KeyRole::Authority => {
                k.kid == registration.key_id
                    && k.authority.as_deref() == Some(&registration.authority)
                    && k.issuer == authority_issuer
                    && k.public_key == registration.public_key
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    if keys
        .iter()
        .filter(|k| k.role == access::KeyRole::Authority)
        .count()
        != 1
        || keys.iter().all(|k| k.role != access::KeyRole::Central)
    {
        return Err(StatusCode::CONFLICT);
    }
    Ok(keys)
}

/// Dedicated router. The execution listener owns TLS and never merges administrator routes.
pub fn router(state: Arc<GuardedHostExecutionChannel>) -> Router {
    Router::new()
        .route("/internal/execution/v1/instance", get(instance))
        .route("/internal/execution/v1/clock", get(authorization_clock))
        .route("/internal/execution/v1/register", post(register))
        .route("/internal/execution/v1/discover", post(discover))
        .route("/internal/execution/v1/ownership", post(ownership))
        .route("/internal/execution/v1/protect", post(protect))
        .route("/internal/execution/v1/delegation", post(delegation))
        .route("/internal/execution/v1/invalidate", post(invalidate))
        .route("/internal/execution/v1/revoke", post(revoke))
        .route("/internal/execution/v1/prepare", post(prepare))
        .route("/internal/execution/v1/dispatch", post(dispatch))
        .route("/internal/execution/v1/status", post(status))
        .route("/internal/execution/v1/policy", post(renewal::policy))
        .route(
            "/internal/execution/v1/continue",
            post(renewal::continue_operation),
        )
        .route("/internal/execution/v1/active", post(renewal::active))
        .layer(DefaultBodyLimit::max(access::MAX_BODY_BYTES))
        .with_state(state)
}

async fn authorization_clock(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
) -> Answer<ClockObservation> {
    let _read = st.admission.read(&request, &st.journal).await?;
    let sample = st.clock()?;
    Ok(Json(ClockObservation {
        now: sample.now,
        uncertainty: sample.uncertainty,
    }))
}

async fn instance(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
) -> Answer<Instance> {
    let _read = st.admission.read(&request, &st.journal).await?;
    let journal = st.authorized_journal(&request).await?;
    Ok(Json(Instance {
        host_instance: journal.instance().into(),
    }))
}

async fn register(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(record): Json<HostRegistration>,
) -> Answer<InstallationAck> {
    if request.protected() {
        return Err(StatusCode::FORBIDDEN);
    }
    let _write = st.admission.write(&request, &st.journal).await?;
    let mut journal = st.authorized_journal(&request).await?;
    st.registered_keys(&record)?;
    register_host(&mut journal, &st.active, &record, st.clock()?)?;
    let response = ack(journal.instance(), record.generation, &record)?;
    st.admission.publish(&journal)?;
    Ok(Json(response))
}

fn register_host(
    journal: &mut Journal,
    active: &crate::guestc::guarded_operations::GuardedOperations,
    record: &HostRegistration,
    clock: Clock,
) -> Result<(), StatusCode> {
    let Ok(current) = journal.registration() else {
        active.end_all();
        return Err(StatusCode::CONFLICT);
    };
    let changed = current != Some(record);
    match journal.register_host(record.clone(), clock) {
        Ok(()) => {}
        Err(
            JournalError::Binding
            | JournalError::Exhausted
            | JournalError::AlreadyAdmitted
            | JournalError::Full,
        ) => return Err(StatusCode::CONFLICT),
        Err(_) => {
            active.end_all();
            return Err(StatusCode::CONFLICT);
        }
    }
    if changed {
        active.end_all();
    }
    Ok(())
}

async fn discover(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(req): Json<access::DiscoveryRequest>,
) -> Answer<access::DiscoveryReceipt> {
    let _read = st.admission.read(&request, &st.journal).await?;
    let journal = st.authorized_journal(&request).await?;
    if journal
        .registration()
        .map_err(|_| StatusCode::CONFLICT)?
        .is_none()
        || journal.instance() != req.host_instance
    {
        return Err(StatusCode::CONFLICT);
    }
    drop(journal);
    if req.seeds.is_empty()
        || req.seeds.len() > access::MAX_RESOURCES
        || req.seeds.iter().filter(|s| s.id == req.primary_id).count() != 1
    {
        return Err(StatusCode::CONFLICT);
    }
    let team = &req.seeds[0].team;
    if req.seeds.iter().any(|s| &s.team != team) {
        return Err(StatusCode::CONFLICT);
    }
    let mut public = Vec::new();
    for seed in &req.seeds {
        let target = st
            .manager
            .resolve_execution_public_seed(seed, &st.journal)
            .await
            .map_err(|_| StatusCode::CONFLICT)?;
        public.push(access::PublicResource {
            id: seed.id.clone(),
            target,
        });
    }
    let primary = public
        .iter()
        .find(|p| p.id == req.primary_id)
        .ok_or(StatusCode::CONFLICT)?
        .target
        .clone();
    let required = public.iter().map(|p| p.target.clone()).collect::<Vec<_>>();
    let resource_set = st
        .manager
        .discover_execution_resources(
            ExecutionResourceScope {
                primary: &primary,
                required: &required,
            },
            &st.journal,
            req.require_renewable,
        )
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let all_public = st
        .manager
        .execution_public_members(&resource_set, team, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    if public.iter().any(|seed| !all_public.contains(seed)) {
        return Err(StatusCode::CONFLICT);
    }
    drop(st.authorized_journal(&request).await?);
    Ok(Json(access::DiscoveryReceipt {
        host_instance: req.host_instance,
        primary,
        public_seeds: required,
        public_resources: all_public,
        resource_set,
    }))
}

async fn ownership(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(owner): Json<HostOwnership>,
) -> Answer<InstallationAck> {
    let _write = st.admission.write(&request, &st.journal).await?;
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    st.authorized_journal(&request)
        .await?
        .install_ownership(owner.clone(), st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(ack(&owner.host_instance, owner.generation, &owner)?))
}

async fn protect(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(req): Json<Protect>,
) -> Answer<ProtectionAck> {
    let _read = st.admission.read(&request, &st.journal).await?;
    let owner = st
        .authorized_journal(&request)
        .await?
        .installed_ownership(&req.installation)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    if owner.generation != req.generation {
        return Err(StatusCode::CONFLICT);
    }
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let receipt = st
        .manager
        .protect_execution_resources(
            ExecutionProtectionRequest {
                admission: &req.admission,
                expires_at_ms: req.expires_at_ms,
                scope: ExecutionResourceScope {
                    primary: &owner.primary,
                    required: &owner.public_seeds,
                },
                subject: &owner.subject,
                resources: &owner.resource_set.resources,
                resource_revision: &owner.resource_set.revision,
            },
            &st.journal,
            st.clock_uncertainty_seconds,
        )
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    st.authorized_journal(&request)
        .await?
        .record_protection(
            InstalledProtection {
                installation: req.installation,
                generation: req.generation,
                admission: receipt.admission.clone(),
                expires_at_ms: receipt.expires_at_ms,
                resources: receipt.targets.clone(),
                resource_revision: receipt.resource_revision.clone(),
            },
            st.clock()?,
        )
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(ProtectionAck {
        admission: receipt.admission,
        expires_at_ms: receipt.expires_at_ms,
        resources: receipt.targets,
        revision: receipt.resource_revision,
    }))
}

#[derive(Clone, Copy, Debug)]
enum DelegationRefusal {
    OwnershipRead,
    OwnershipMissing,
    RegistrationMissing,
    Generation,
    OwnershipLive,
    RegisteredKeys,
    Verification,
    ProtectionRead,
    ProtectionMissing,
    ProtectionBinding,
    JournalInstall,
    PolicyInstall,
}

fn delegation_conflict(stage: DelegationRefusal) -> StatusCode {
    tracing::warn!(target: "execution_installation", diagnostic = "execution_installation", stage = ?stage, "execution installation refused");
    StatusCode::CONFLICT
}

async fn delegation(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(req): Json<InstallDelegation>,
) -> Answer<HostDelegation> {
    let _write = st.admission.write(&request, &st.journal).await?;
    let owner = st
        .authorized_journal(&request)
        .await?
        .installed_ownership(&req.installation)
        .map_err(|_| delegation_conflict(DelegationRefusal::OwnershipRead))?
        .cloned()
        .ok_or_else(|| delegation_conflict(DelegationRefusal::OwnershipMissing))?;
    let registration = request
        .registration()
        .ok_or_else(|| delegation_conflict(DelegationRefusal::RegistrationMissing))?;
    if owner.generation != req.generation {
        return Err(delegation_conflict(DelegationRefusal::Generation));
    }
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| delegation_conflict(DelegationRefusal::OwnershipLive))?;
    let allocation_tokens = req
        .allocations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let keys = st
        .registered_keys(registration)
        .map_err(|_| delegation_conflict(DelegationRefusal::RegisteredKeys))?;
    let checked = access::verify_delegation(
        &req.grant,
        &allocation_tokens,
        &st.trust(&keys),
        st.clock()?,
        &DelegationContext {
            principal: &req.principal,
            team: &owner.team,
            subject: &owner.subject,
            target: &owner.primary,
            resource_set: &owner.resource_set,
            metadata_revision: &owner.metadata_revision,
            authority: &registration.authority,
            authority_epoch: &registration.epoch,
        },
    )
    .map_err(|error| {
        tracing::warn!(target: "execution_installation", diagnostic = "execution_installation", stage = "host_verification", category = ?error, "execution installation refused");
        delegation_conflict(DelegationRefusal::Verification)
    })?;
    let protection = st
        .authorized_journal(&request)
        .await?
        .protection(&checked.grant().idle.admission)
        .map_err(|_| delegation_conflict(DelegationRefusal::ProtectionRead))?
        .cloned()
        .ok_or_else(|| delegation_conflict(DelegationRefusal::ProtectionMissing))?;
    if checked.grant().id != req.id
        || protection.installation != req.installation
        || protection.generation != req.generation
        || !idle_receipt_covers(
            &protection,
            req.protection_expires_at_ms,
            checked.grant().idle.expires_at,
            checked.grant().exp,
        )
    {
        return Err(delegation_conflict(DelegationRefusal::ProtectionBinding));
    }
    let record = HostDelegation {
        id: req.id,
        version: req.version,
        ownership: req.installation,
        ownership_generation: req.generation,
        grant_digest: access::token_digest(&req.grant),
        allocation_digests: checked.allocation_digests().to_vec(),
        principal: checked.grant().principal.clone(),
        expires_at: checked.grant().exp,
    };
    st.authorized_journal(&request)
        .await?
        .install_delegation(record.clone(), st.clock()?)
        .map_err(|_| delegation_conflict(DelegationRefusal::JournalInstall))?;
    Ok(Json(record))
}

fn idle_receipt_covers(
    receipt: &InstalledProtection,
    requested_ms: u64,
    signed_seconds: u64,
    grant_exp: u64,
) -> bool {
    receipt.expires_at_ms == requested_ms
        && receipt.expires_at_ms / 1000 == signed_seconds
        && signed_seconds >= grant_exp
}

async fn invalidate(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(req): Json<Invalidate>,
) -> Answer<Instance> {
    let _write = st.admission.write(&request, &st.journal).await?;
    let mut journal = st.authorized_journal(&request).await?;
    let order = journal.revocation_order();
    journal
        .invalidate_ownership(&req.installation, req.generation, order)
        .map_err(|_| {
            if journal.owned().is_err() {
                st.active.end_all();
            }
            StatusCode::CONFLICT
        })?;
    st.active
        .revoke_where(|admission| journal.active_operation(admission).ok().flatten().cloned());
    Ok(Json(Instance {
        host_instance: journal.instance().into(),
    }))
}

async fn revoke(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(req): Json<Revoke>,
) -> Answer<Instance> {
    let _write = st.admission.write(&request, &st.journal).await?;
    let mut journal = st.authorized_journal(&request).await?;
    let order = journal.revocation_order();
    journal
        .revoke_delegation(&req.id, req.version, order)
        .map_err(|_| {
            if journal.owned().is_err() {
                st.active.end_all();
            }
            StatusCode::CONFLICT
        })?;
    st.active
        .revoke_where(|admission| journal.active_operation(admission).ok().flatten().cloned());
    Ok(Json(Instance {
        host_instance: journal.instance().into(),
    }))
}

fn dispatch_context<'a>(
    owner: &'a HostOwnership,
    registration: &'a HostRegistration,
    principal: &'a str,
    refs: &'a [AllocationRef],
    request_digest: &'a str,
) -> DispatchContext<'a> {
    DispatchContext {
        principal,
        team: &owner.team,
        subject: &owner.subject,
        target: &owner.primary,
        resource_set: &owner.resource_set,
        metadata_revision: &owner.metadata_revision,
        authority: &registration.authority,
        authority_epoch: &registration.epoch,
        installed_allocations: refs,
        operation: Operation::Exec,
        request_digest,
    }
}

// Parse only to form a candidate context. The signed permit is verified against
// this candidate and the independently installed allocation digests before use.
fn candidate_refs(token: &str) -> Result<Vec<AllocationRef>, StatusCode> {
    if token.len() > access::MAX_TOKEN_BYTES {
        return Err(StatusCode::CONFLICT);
    }
    let mut parts = token.split('.');
    let (_head, Some(body), _signature, None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StatusCode::CONFLICT);
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| StatusCode::CONFLICT)?;
    let permit: access::Permit =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::CONFLICT)?;
    Ok(permit.allocations)
}

async fn installed(
    st: &GuardedHostExecutionChannel,
    request: &RequestIdentity,
    req: &BundleRequest,
) -> Result<(HostOwnership, HostDelegation), StatusCode> {
    let journal = st.authorized_journal(request).await?;
    let owner = journal
        .installed_ownership(&req.installation)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let delegation = journal
        .delegation(&req.delegation)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    if owner.generation != req.generation
        || delegation.ownership != req.installation
        || delegation.ownership_generation != req.generation
        || delegation.grant_digest != access::token_digest(&req.grant)
        || delegation.allocation_digests
            != req
                .allocations
                .iter()
                .map(|a| access::token_digest(a))
                .collect::<Vec<_>>()
    {
        return Err(StatusCode::CONFLICT);
    }
    Ok((owner, delegation))
}

async fn prepare(
    State(st): Channel,
    ExecutionRequest(request): ExecutionRequest,
    Json(req): Json<Prepare>,
) -> Answer<PreparedAdmission> {
    let _read = st.admission.read(&request, &st.journal).await?;
    if request.protected()
        && st
            .authorized_journal(&request)
            .await?
            .status(&req.admission)
            .map_err(|_| StatusCode::CONFLICT)?
            .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }
    let registration = request.registration().ok_or(StatusCode::CONFLICT)?;
    let (owner, delegation) = installed(&st, &request, &req.bundle).await?;
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let refs = candidate_refs(&req.bundle.permit)?;
    let context = dispatch_context(
        &owner,
        registration,
        &delegation.principal,
        &refs,
        &req.request_digest,
    );
    let tokens = req
        .bundle
        .allocations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let keys = st.registered_keys(registration)?;
    let checked = access::verify_bundle(
        &req.bundle.grant,
        &req.bundle.permit,
        &tokens,
        &st.trust(&keys),
        st.clock()?,
        &context,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    if checked.permit().admission != req.admission
        || checked.permit().request_digest != req.request_digest
    {
        return Err(StatusCode::CONFLICT);
    }
    if checked.permit().limits.execution_mode.is_some() {
        renewal::installed_policy(
            &*st.authorized_journal(&request).await?,
            &req.bundle,
            &delegation,
        )?;
    }
    let host_instance = st.authorized_journal(&request).await?.instance().to_owned();
    let record = PreparedAdmission {
        admission: req.admission,
        delegation: req.bundle.delegation,
        grant_digest: access::token_digest(&req.bundle.grant),
        permit_digest: access::token_digest(&req.bundle.permit),
        request_digest: req.request_digest,
        allocation_refs: checked.permit().allocations.clone(),
        ownership: req.bundle.installation,
        ownership_generation: req.bundle.generation,
        host_instance: host_instance.clone(),
        expires_at: checked.permit().exp,
        dispatched: false,
    };
    let mut journal = st.authorized_journal(&request).await?;
    if request.protected()
        && journal
            .status(&record.admission)
            .map_err(|_| StatusCode::CONFLICT)?
            .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }
    journal
        .install(&checked, &host_instance, st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    journal
        .prepare(record.clone(), st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(record))
}

async fn dispatch(
    State(st): Channel,
    ExecutionRequest(request): ExecutionRequest,
    Json(req): Json<Dispatch>,
) -> Answer<api::ExecResult> {
    let admission_guard = st.admission.read(&request, &st.journal).await?;
    let registration = request.registration().ok_or(StatusCode::CONFLICT)?;
    let (owner, delegation) = installed(&st, &request, &req.bundle).await?;
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let prepared = st
        .authorized_journal(&request)
        .await?
        .prepared(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    if prepared.delegation != req.bundle.delegation
        || prepared.ownership != req.bundle.installation
        || prepared.ownership_generation != owner.generation
        || prepared.grant_digest != access::token_digest(&req.bundle.grant)
        || prepared.permit_digest != access::token_digest(&req.bundle.permit)
    {
        return Err(StatusCode::CONFLICT);
    }
    let context = dispatch_context(
        &owner,
        registration,
        &delegation.principal,
        &prepared.allocation_refs,
        &prepared.request_digest,
    );
    let tokens = req
        .bundle
        .allocations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let keys = st.registered_keys(registration)?;
    let checked = access::verify_bundle(
        &req.bundle.grant,
        &req.bundle.permit,
        &tokens,
        &st.trust(&keys),
        st.clock()?,
        &context,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    if checked.permit().admission != req.admission
        || checked.permit().allocations != prepared.allocation_refs
        || access::exec_request_digest(&req.request, &checked.permit().limits)
            .map_err(|_| StatusCode::CONFLICT)?
            != prepared.request_digest
    {
        return Err(StatusCode::CONFLICT);
    }
    let renewable_policy = if checked.permit().limits.execution_mode.is_some() {
        Some(renewal::installed_policy(
            &*st.authorized_journal(&request).await?,
            &req.bundle,
            &delegation,
        )?)
    } else {
        None
    };
    let mut journal = st.authorized_journal(&request).await?;
    journal
        .mark_dispatched(&req.admission, st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    let dispatched = journal
        .prepared(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    drop(journal);
    let credentials = ScopedCredentials {
        grant: &req.bundle.grant,
        permit: &req.bundle.permit,
        allocations: &tokens,
    };
    let installed = ScopedExecutionContext {
        binding: &context,
        scope: ExecutionResourceScope {
            primary: &owner.primary,
            required: &owner.public_seeds,
        },
    };
    let result = st
        .manager
        .channel_scoped_exec(
            req.request,
            credentials,
            &st.trust(&keys),
            installed,
            &st.journal,
            st.clock_uncertainty_seconds,
            ChannelDispatch {
                guard: admission_guard,
                registry: st.active.clone(),
                policy: renewable_policy,
                admission: &st.admission,
                request: request.clone(),
                prepared: dispatched,
            },
        )
        .await;
    result.map(Json).map_err(|_| StatusCode::CONFLICT)
}

async fn status(
    State(st): Channel,
    ExecutionRequest(request): ExecutionRequest,
    Json(req): Json<StatusRequest>,
) -> Answer<AdmissionStatus> {
    let _read = st.admission.read(&request, &st.journal).await?;
    let journal = st.authorized_journal(&request).await?;
    let prepared = journal
        .prepared(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?;
    let state = journal
        .status(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?;
    if request.protected() && prepared.is_none() && state.is_some() {
        return Err(StatusCode::CONFLICT);
    }
    Ok(Json(AdmissionStatus {
        prepared: prepared.is_some(),
        dispatched: prepared.is_some_and(|p| p.dispatched),
        journal: state,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guestc::{active_lease::ActiveLease, guarded_operations::GuardedOperations};
    use briqyard_api::execution::{
        admission::{ActiveOperation, Role},
        clock::ClockSample,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn refused_registration_leaves_an_owned_active_lease_running() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../briqyard-api/tests/fixtures/execution-continuation-v1.json"
        ))
        .unwrap();
        let evidence: ActiveOperation = serde_json::from_value(fixture["active"].clone()).unwrap();
        let sample = ClockSample {
            wall: Duration::from_secs(1035),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_secs(1),
        };
        let clock = Clock {
            now: 1010,
            uncertainty: 1,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut journal =
            Journal::open(&dir.path().join("host"), Role::Host("host-1".into())).unwrap();
        let current = HostRegistration {
            authority: "authority-1".into(),
            epoch: "epoch-2".into(),
            key_id: "key-2".into(),
            public_key: [7; 32],
            host_instance: journal.instance().into(),
            generation: 2,
        };
        let active = Arc::new(GuardedOperations::default());
        register_host(&mut journal, &active, &current, clock).unwrap();

        let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
        let _owner = active
            .register(&evidence.binding.admission, lease.clone())
            .unwrap();
        lease.observe(&evidence, &sample).unwrap();

        register_host(&mut journal, &active, &current, clock).unwrap();
        lease.observe(&evidence, &sample).unwrap();

        let stale = HostRegistration {
            epoch: "epoch-1".into(),
            generation: 1,
            ..current.clone()
        };
        let other_host = HostRegistration {
            host_instance: "another-host".into(),
            generation: 3,
            ..current.clone()
        };
        for refused in [stale, other_host] {
            assert_eq!(
                register_host(&mut journal, &active, &refused, clock),
                Err(StatusCode::CONFLICT)
            );
            assert_eq!(journal.registration().unwrap(), Some(&current));
            assert!(active.get(&evidence.binding.admission).is_some());
            lease.observe(&evidence, &sample).unwrap();
        }

        let next = HostRegistration {
            epoch: "epoch-3".into(),
            generation: 3,
            ..current
        };
        register_host(&mut journal, &active, &next, clock).unwrap();
        assert_eq!(journal.registration().unwrap(), Some(&next));
        assert!(lease.observe(&evidence, &sample).is_err());
    }

    #[tokio::test]
    async fn ambiguous_registration_persistence_contains_active_leases_and_poisons_the_journal() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../briqyard-api/tests/fixtures/execution-continuation-v1.json"
        ))
        .unwrap();
        let evidence: ActiveOperation = serde_json::from_value(fixture["active"].clone()).unwrap();
        let sample = ClockSample {
            wall: Duration::from_secs(1035),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_secs(1),
        };
        let clock = Clock {
            now: 1010,
            uncertainty: 1,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host");
        let mut journal = Journal::open(&path, Role::Host("host-1".into())).unwrap();
        let current = HostRegistration {
            authority: "authority-1".into(),
            epoch: "epoch-2".into(),
            key_id: "key-2".into(),
            public_key: [7; 32],
            host_instance: journal.instance().into(),
            generation: 2,
        };
        let active = Arc::new(GuardedOperations::default());
        register_host(&mut journal, &active, &current, clock).unwrap();

        let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
        let _owner = active
            .register(&evidence.binding.admission, lease.clone())
            .unwrap();
        lease.observe(&evidence, &sample).unwrap();

        std::fs::write(path.join("journal.next"), b"unresolved").unwrap();
        let next = HostRegistration {
            epoch: "epoch-3".into(),
            generation: 3,
            ..current.clone()
        };
        assert_eq!(
            register_host(&mut journal, &active, &next, clock),
            Err(StatusCode::CONFLICT)
        );
        assert!(lease.observe(&evidence, &sample).is_err());
        assert!(matches!(journal.owned(), Err(JournalError::Persistence)));
        assert!(matches!(
            journal.registration(),
            Err(JournalError::Persistence)
        ));
        assert!(matches!(
            journal.register_host(next.clone(), clock),
            Err(JournalError::Persistence)
        ));

        let later = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
        let _later_owner = active.register("later", later.clone()).unwrap();
        later.observe(&evidence, &sample).unwrap();
        assert_eq!(
            register_host(&mut journal, &active, &current, clock),
            Err(StatusCode::CONFLICT)
        );
        assert!(later.observe(&evidence, &sample).is_err());
    }

    #[test]
    fn exact_millisecond_receipt_covers_inward_rounded_grant() {
        let receipt = InstalledProtection {
            installation: "i".into(),
            generation: 1,
            admission: "a".into(),
            expires_at_ms: 1_700_000_001_234,
            resources: vec![],
            resource_revision: "r".into(),
        };
        assert!(idle_receipt_covers(
            &receipt,
            1_700_000_001_234,
            1_700_000_001,
            1_700_000_001
        ));
        assert!(!idle_receipt_covers(
            &receipt,
            1_700_000_001_000,
            1_700_000_001,
            1_700_000_001
        ));
        assert!(!idle_receipt_covers(
            &receipt,
            1_700_000_001_234,
            1_700_000_002,
            1_700_000_002
        ));
    }

    #[test]
    fn only_registered_authority_key_is_eligible_for_permit_verification() {
        let configured = vec![
            VerificationKey {
                kid: "central".into(),
                role: access::KeyRole::Central,
                issuer: "central".into(),
                authority: None,
                public_key: [1; 32],
            },
            VerificationKey {
                kid: "old".into(),
                role: access::KeyRole::Authority,
                issuer: "authority".into(),
                authority: Some("region".into()),
                public_key: [2; 32],
            },
            VerificationKey {
                kid: "current".into(),
                role: access::KeyRole::Authority,
                issuer: "authority".into(),
                authority: Some("region".into()),
                public_key: [3; 32],
            },
        ];
        let registration = HostRegistration {
            authority: "region".into(),
            epoch: "epoch".into(),
            key_id: "current".into(),
            public_key: [3; 32],
            host_instance: "host".into(),
            generation: 2,
        };
        let accepted = registered_keys(&configured, "authority", &registration).unwrap();
        assert_eq!(accepted.len(), 2);
        assert!(accepted.iter().any(|k| k.kid == "central"));
        assert!(accepted.iter().any(|k| k.kid == "current"));
        assert!(!accepted.iter().any(|k| k.kid == "old"));
        let wrong = HostRegistration {
            public_key: [2; 32],
            ..registration
        };
        assert!(registered_keys(&configured, "authority", &wrong).is_err());
    }
}
