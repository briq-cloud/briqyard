//! Host installation and dispatch on a dedicated opt-in authenticated TLS listener.
use crate::machine::{
    ExecutionProtectionRequest, ExecutionResourceScope, Manager, RenewableDispatch,
    ScopedCredentials, ScopedExecutionContext,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use briqyard_api::{
    self as api,
    execution::{
        self as access,
        admission::{
            HostDelegation, HostOwnership, HostRegistration, InstalledProtection, Journal,
            PreparedAdmission,
        },
        channel::*,
        AllocationRef, Clock, DelegationContext, DispatchContext, Operation, Trust,
        VerificationKey,
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

mod renewal;

type Answer<T> = Result<Json<T>, StatusCode>;
type Channel = State<Arc<HostExecutionChannel>>;

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
pub struct HostExecutionChannel {
    manager: Manager,
    journal: Mutex<Journal>,
    admission: RwLock<()>,
    active: Arc<crate::guestc::active_operations::ActiveOperations>,
    installer_token: String,
    execution_token: String,
    keys: Vec<VerificationKey>,
    central_issuer: String,
    authority_issuer: String,
    audience: String,
    clock_uncertainty_seconds: u64,
}

impl HostExecutionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: Manager,
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
        Ok(Self {
            manager,
            journal: Mutex::new(journal),
            admission: RwLock::new(()),
            active: Arc::new(crate::guestc::active_operations::ActiveOperations::default()),
            installer_token,
            execution_token,
            keys,
            central_issuer,
            authority_issuer,
            audience,
            clock_uncertainty_seconds,
        })
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

    fn authorize(&self, headers: &HeaderMap, installer: bool) -> Result<(), StatusCode> {
        let expected = if installer {
            &self.installer_token
        } else {
            &self.execution_token
        };
        let got = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if got.is_empty() || !api::constant_eq(got.as_bytes(), expected.as_bytes()) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(())
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
pub fn router(state: Arc<HostExecutionChannel>) -> Router {
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

async fn authorization_clock(State(st): Channel, headers: HeaderMap) -> Answer<ClockObservation> {
    st.authorize(&headers, true)?;
    let sample = st.clock()?;
    Ok(Json(ClockObservation {
        now: sample.now,
        uncertainty: sample.uncertainty,
    }))
}

async fn instance(State(st): Channel, headers: HeaderMap) -> Answer<Instance> {
    st.authorize(&headers, true)?;
    let _read = st.admission.read().await;
    let journal = st.journal.lock().await;
    Ok(Json(Instance {
        host_instance: journal.instance().into(),
    }))
}

async fn register(
    State(st): Channel,
    headers: HeaderMap,
    Json(record): Json<HostRegistration>,
) -> Answer<InstallationAck> {
    st.authorize(&headers, true)?;
    let _write = st.admission.write().await;
    let mut journal = st.journal.lock().await;
    st.registered_keys(&record)?;
    let changed = journal.registration().map_err(|_| StatusCode::CONFLICT)? != Some(&record);
    journal
        .register_host(record.clone(), st.clock()?)
        .map_err(|_| {
            st.active.end_all();
            StatusCode::CONFLICT
        })?;
    if changed {
        st.active.end_all();
    }
    Ok(Json(ack(journal.instance(), record.generation, &record)?))
}

async fn discover(
    State(st): Channel,
    headers: HeaderMap,
    Json(req): Json<access::DiscoveryRequest>,
) -> Answer<access::DiscoveryReceipt> {
    st.authorize(&headers, true)?;
    let _read = st.admission.read().await;
    let journal = st.journal.lock().await;
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
        .execution_resources(
            ExecutionResourceScope {
                primary: &primary,
                required: &required,
            },
            &st.journal,
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
    headers: HeaderMap,
    Json(owner): Json<HostOwnership>,
) -> Answer<InstallationAck> {
    st.authorize(&headers, true)?;
    let _write = st.admission.write().await;
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    st.journal
        .lock()
        .await
        .install_ownership(owner.clone(), st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(ack(&owner.host_instance, owner.generation, &owner)?))
}

async fn protect(
    State(st): Channel,
    headers: HeaderMap,
    Json(req): Json<Protect>,
) -> Answer<ProtectionAck> {
    st.authorize(&headers, true)?;
    let _read = st.admission.read().await;
    let owner = st
        .journal
        .lock()
        .await
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
    st.journal
        .lock()
        .await
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

async fn delegation(
    State(st): Channel,
    headers: HeaderMap,
    Json(req): Json<InstallDelegation>,
) -> Answer<HostDelegation> {
    st.authorize(&headers, true)?;
    let _write = st.admission.write().await;
    let owner = st
        .journal
        .lock()
        .await
        .installed_ownership(&req.installation)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let registration = st
        .journal
        .lock()
        .await
        .registration()
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
    let allocation_tokens = req
        .allocations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let keys = st.registered_keys(&registration)?;
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
    .map_err(|_| StatusCode::CONFLICT)?;
    let protection = st
        .journal
        .lock()
        .await
        .protection(&checked.grant().idle.admission)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
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
        return Err(StatusCode::CONFLICT);
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
    st.journal
        .lock()
        .await
        .install_delegation(record.clone(), st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
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
    headers: HeaderMap,
    Json(req): Json<Invalidate>,
) -> Answer<Instance> {
    st.authorize(&headers, true)?;
    let _write = st.admission.write().await;
    let mut journal = st.journal.lock().await;
    let order = journal.revocation_order();
    journal
        .invalidate_ownership(&req.installation, req.generation, order)
        .map_err(|_| {
            st.active.end_all();
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
    headers: HeaderMap,
    Json(req): Json<Revoke>,
) -> Answer<Instance> {
    st.authorize(&headers, true)?;
    let _write = st.admission.write().await;
    let mut journal = st.journal.lock().await;
    let order = journal.revocation_order();
    journal
        .revoke_delegation(&req.id, req.version, order)
        .map_err(|_| {
            st.active.end_all();
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
    st: &HostExecutionChannel,
    req: &BundleRequest,
) -> Result<(HostOwnership, HostRegistration, HostDelegation), StatusCode> {
    let journal = st.journal.lock().await;
    let owner = journal
        .installed_ownership(&req.installation)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let registration = journal
        .registration()
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
    Ok((owner, registration, delegation))
}

async fn prepare(
    State(st): Channel,
    headers: HeaderMap,
    Json(req): Json<Prepare>,
) -> Answer<PreparedAdmission> {
    st.authorize(&headers, false)?;
    let _read = st.admission.read().await;
    let (owner, registration, delegation) = installed(&st, &req.bundle).await?;
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let refs = candidate_refs(&req.bundle.permit)?;
    let context = dispatch_context(
        &owner,
        &registration,
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
    let keys = st.registered_keys(&registration)?;
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
        renewal::installed_policy(&*st.journal.lock().await, &req.bundle, &delegation)?;
    }
    let host_instance = st.journal.lock().await.instance().to_owned();
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
    let mut journal = st.journal.lock().await;
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
    headers: HeaderMap,
    Json(req): Json<Dispatch>,
) -> Answer<api::ExecResult> {
    st.authorize(&headers, false)?;
    let admission_guard = st.admission.read().await;
    let (owner, registration, delegation) = installed(&st, &req.bundle).await?;
    st.manager
        .verify_execution_ownership(&owner, &st.journal)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let prepared = st
        .journal
        .lock()
        .await
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
        &registration,
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
    let keys = st.registered_keys(&registration)?;
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
            &*st.journal.lock().await,
            &req.bundle,
            &delegation,
        )?)
    } else {
        None
    };
    st.journal
        .lock()
        .await
        .mark_dispatched(&req.admission, st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
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
    let result = if let Some(policy) = renewable_policy {
        st.manager
            .renewable_scoped_exec(
                req.request,
                credentials,
                &st.trust(&keys),
                installed,
                &st.journal,
                st.clock_uncertainty_seconds,
                RenewableDispatch {
                    guard: admission_guard,
                    registry: st.active.clone(),
                    policy,
                },
            )
            .await
    } else {
        let _legacy_fence = admission_guard;
        st.manager
            .scoped_exec(
                req.request,
                credentials,
                &st.trust(&keys),
                installed,
                &st.journal,
                st.clock_uncertainty_seconds,
            )
            .await
    };
    result.map(Json).map_err(|_| StatusCode::CONFLICT)
}

async fn status(
    State(st): Channel,
    headers: HeaderMap,
    Json(req): Json<StatusRequest>,
) -> Answer<AdmissionStatus> {
    st.authorize(&headers, false)?;
    let _read = st.admission.read().await;
    let journal = st.journal.lock().await;
    let prepared = journal
        .prepared(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(AdmissionStatus {
        prepared: prepared.is_some(),
        dispatched: prepared.is_some_and(|p| p.dispatched),
        journal: journal
            .status(&req.admission)
            .map_err(|_| StatusCode::CONFLICT)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
