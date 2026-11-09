//! Regional authority HTTP boundary on a dedicated opt-in authenticated TLS listener.
use crate::{
    execution_host::HostTransport,
    execution_install::{CommittedIdle, DelegationControl, Installer, Outcome, SignedDelegation},
    execution_operation::{Control, Coordinator, ExecOutcome},
};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use briqyard_api::execution::{
    admission::{HostRegistration, OwnershipControl},
    channel::{Invalidate, Revoke},
    Clock, Source, Trust, VerificationKey, MAX_BODY_BYTES,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{sync::Arc, time::Instant};
use tokio::sync::Mutex;

use briqyard_api::execution::clock::ClockSource;
#[cfg(test)]
use briqyard_api::execution::clock::QualifiedClock;

pub(super) struct Credentials {
    pub installer: String,
    pub gateway: String,
    pub administrator: String,
    pub host_administrator: String,
}

pub(super) struct TrustConfig {
    pub keys: Vec<VerificationKey>,
    pub central_issuer: String,
    pub authority_issuer: String,
    pub audience: String,
}
impl TrustConfig {
    fn borrowed(&self) -> Trust<'_> {
        Trust {
            keys: &self.keys,
            central_issuer: &self.central_issuer,
            authority_issuer: &self.authority_issuer,
            audience: &self.audience,
        }
    }
}

struct Service {
    issuer: Mutex<briqyard_api::execution::DurableIssuer>,
    host: HostTransport,
    host_id: String,
    credentials: Credentials,
    trust: TrustConfig,
    clock: Arc<dyn ClockSource>,
}

fn valid_credentials(c: &Credentials) -> bool {
    ![
        &c.installer,
        &c.gateway,
        &c.administrator,
        &c.host_administrator,
    ]
    .iter()
    .any(|v| v.is_empty() || v.bytes().any(|b| !b.is_ascii_graphic()))
        && c.installer != c.gateway
        && c.installer != c.administrator
        && c.gateway != c.administrator
        && c.installer != c.host_administrator
        && c.gateway != c.host_administrator
}

/// One service owns the exclusive issuer journal for its entire lifetime.
/// Construction never opens or rotates a journal per request.
pub(super) fn router(
    issuer: briqyard_api::execution::DurableIssuer,
    host: HostTransport,
    host_id: String,
    credentials: Credentials,
    fleet_config: &crate::config::Config,
    trust: TrustConfig,
    clock: Arc<dyn ClockSource>,
) -> Result<Router, &'static str> {
    if host_id.is_empty()
        || host_id != host.host_id()
        || credentials.host_administrator != host.administrator_token()
        || credentials.administrator != fleet_config.token
        || !valid_credentials(&credentials)
        || trust.keys.is_empty()
        || trust.central_issuer.is_empty()
        || trust.authority_issuer.is_empty()
        || trust.audience.is_empty()
    {
        return Err("invalid authority configuration");
    }
    let state = Arc::new(Service {
        issuer: Mutex::new(issuer),
        host,
        host_id,
        credentials,
        trust,
        clock,
    });
    Ok(Router::new()
        .route("/internal/authority/v1/:action", post(handle))
        .with_state(state))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    id: String,
    record: HostRegistration,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    id: String,
    registration: String,
    control: OwnershipControl,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    id: String,
    discovery: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Protection {
    id: String,
    ownership: String,
    committed: CommittedIdleDto,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedIdleDto {
    admission: String,
    expires_at_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    id: String,
    registration: String,
    control: DelegationControlDto,
    signed: SignedDelegationDto,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationControlDto {
    id: String,
    version: u64,
    principal: String,
    ownership: String,
    protection: String,
    source: Source,
    policy_revision: String,
    projection: briqyard_api::execution::admission::Projection,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedDelegationDto {
    grant: String,
    allocations: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invalidation {
    id: String,
    host_instance: String,
    request: Invalidate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    id: String,
    host_instance: String,
    request: Revoke,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    id: String,
    delegation_intent: String,
    grant: String,
    projection_digest: String,
    request: briqyard_api::ExecRequest,
}
#[derive(Serialize)]
struct Reply<T: Serialize> {
    state: &'static str,
    evidence: Option<T>,
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, StatusCode> {
    serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)
}
fn clock(source: &dyn ClockSource) -> Result<Clock, StatusCode> {
    let evidence = source.qualified().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    if evidence.valid_until <= Instant::now()
        || evidence.interval.now == 0
        || evidence.interval.uncertainty > 5
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(evidence.interval)
}
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(presented) = value.strip_prefix("Bearer ") else {
        return false;
    };
    // Fixed-time byte comparison for equal-length credentials.
    let left = presented.as_bytes();
    let right = token.as_bytes();
    let mut different = left.len() ^ right.len();
    for i in 0..left.len().max(right.len()) {
        different |=
            usize::from(left.get(i).copied().unwrap_or(0) ^ right.get(i).copied().unwrap_or(0));
    }
    different == 0
}

async fn handle(
    State(service): State<Arc<Service>>,
    Path(action): Path<String>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    let installer_role = matches!(
        action.as_str(),
        "identity"
            | "register"
            | "discover"
            | "ownership"
            | "protect"
            | "delegation"
            | "invalidate"
            | "revoke"
            | "installation_status"
    );
    let gateway_role = matches!(
        action.as_str(),
        "exec" | "projection" | "projection_lookup" | "operation_status" | "observe"
    );
    if !installer_role && !gateway_role {
        return StatusCode::NOT_FOUND.into_response();
    }
    let token = if installer_role {
        &service.credentials.installer
    } else {
        &service.credentials.gateway
    };
    if !authorized(&headers, token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/json")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let body = match to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        run(&service, action.as_str(), &body),
    )
    .await;
    match response {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(code)) => code.into_response(),
        Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
    }
}

fn value<T: Serialize>(v: T) -> Result<serde_json::Value, StatusCode> {
    serde_json::to_value(v).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
fn install_error(_: crate::execution_install::InstallError) -> StatusCode {
    StatusCode::CONFLICT
}
fn operation_error(error: crate::execution_operation::Error) -> StatusCode {
    use crate::execution_operation::Error;
    match error {
        Error::Conflict => StatusCode::CONFLICT,
        Error::Binding => StatusCode::UNPROCESSABLE_ENTITY,
        Error::Journal => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Unconfirmed => StatusCode::BAD_GATEWAY,
    }
}

async fn run(
    service: &Service,
    action: &str,
    body: &[u8],
) -> Result<serde_json::Value, StatusCode> {
    let mut issuer = service.issuer.lock().await;
    if action == "identity" {
        let _: Empty = parse(body)?;
        clock(service.clock.as_ref())?;
        let authority_epoch = issuer.instance().to_owned();
        let authority = match issuer.installation_journal().role() {
            briqyard_api::execution::admission::Role::Authority(id) => id.clone(),
            _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        let host: briqyard_api::execution::channel::Instance = service
            .host
            .call(crate::execution_host::Route::Instance, &())
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        clock(service.clock.as_ref())?;
        // Identity discovery is not installation readiness or a source of trusted keys.
        return value(serde_json::json!({
            "authority": authority,
            "authority_epoch": authority_epoch,
            "host": service.host_id,
            "host_instance": host.host_instance,
        }));
    }
    let host_id = &service.host_id;
    let mut installer = Installer {
        journal: issuer.installation_journal(),
        host: &service.host,
        host_id,
    };
    match action {
        "register" => {
            let dto: Registration = parse(body)?;
            let c = clock(service.clock.as_ref())?;
            let state = installer
                .register(&dto.id, dto.record, c)
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "registration", &dto.id, state)
        }
        "discover" => {
            let dto: Discovery = parse(body)?;
            let c = clock(service.clock.as_ref())?;
            let state = installer
                .discover(&dto.id, &dto.registration, dto.control, c)
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "discovery", &dto.id, state)
        }
        "ownership" => {
            let dto: Ownership = parse(body)?;
            let c = clock(service.clock.as_ref())?;
            let state = installer
                .ownership(&dto.id, &dto.discovery, c)
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "ownership", &dto.id, state)
        }
        "protect" => {
            let dto: Protection = parse(body)?;
            let c = clock(service.clock.as_ref())?;
            let state = installer
                .protect(
                    &dto.id,
                    &dto.ownership,
                    CommittedIdle {
                        admission: dto.committed.admission,
                        expires_at_ms: dto.committed.expires_at_ms,
                    },
                    c,
                )
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "protection", &dto.id, state)
        }
        "delegation" => {
            let dto: Delegation = parse(body)?;
            let c = clock(service.clock.as_ref())?;
            let state = installer
                .delegation(
                    &dto.id,
                    &dto.registration,
                    DelegationControl {
                        id: dto.control.id,
                        version: dto.control.version,
                        principal: dto.control.principal,
                        ownership: dto.control.ownership,
                        protection: dto.control.protection,
                        source: dto.control.source,
                        projection: dto.control.projection,
                        policy_revision: dto.control.policy_revision,
                    },
                    SignedDelegation {
                        grant: dto.signed.grant,
                        allocations: dto.signed.allocations,
                    },
                    &service.trust.borrowed(),
                    c,
                )
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "delegation", &dto.id, state)
        }
        "invalidate" => {
            let dto: Invalidation = parse(body)?;
            let c = installer.journal.revocation_order();
            let state = installer
                .invalidate(&dto.id, &dto.host_instance, dto.request, c)
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "invalidate", &dto.id, state)
        }
        "revoke" => {
            let dto: Revocation = parse(body)?;
            let c = installer.journal.revocation_order();
            let state = installer
                .revoke(&dto.id, &dto.host_instance, dto.request, c)
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "revoke", &dto.id, state)
        }
        "installation_status" => {
            let dto: InstallationStatus = parse(body)?;
            installation_reply(installer.journal, &dto.kind, &dto.id, Outcome::Pending)
        }
        "projection_lookup" => {
            let dto: ProjectionLookup = parse(body)?;
            value(
                installer
                    .journal
                    .lookup_projection(&dto.delegation, &dto.grant, clock(service.clock.as_ref())?)
                    .map_err(|_| StatusCode::CONFLICT)?,
            )
        }
        "projection" => {
            let dto: ProjectionRead = parse(body)?;
            value(
                installer
                    .journal
                    .presented_projection(
                        &dto.delegation_intent,
                        &dto.grant,
                        clock(service.clock.as_ref())?,
                    )
                    .map_err(|_| StatusCode::CONFLICT)?,
            )
        }
        "exec" => {
            let dto: Execution = parse(body)?;
            let mut coordinator = Coordinator {
                issuer: &mut issuer,
                host: &service.host,
                host_id,
            };
            let outcome = coordinator
                .exec(
                    Control {
                        id: dto.id,
                        delegation_intent: dto.delegation_intent,
                        grant: dto.grant,
                        projection_digest: dto.projection_digest,
                        request: dto.request,
                    },
                    &service.trust.borrowed(),
                    || {
                        clock(service.clock.as_ref())
                            .map_err(|_| crate::execution_operation::Error::Unconfirmed)
                    },
                )
                .await
                .map_err(operation_error)?;
            match outcome {
                ExecOutcome::Completed { status, result } => value(
                    serde_json::json!({"state":"completed", "status":{"phase":status.phase,"unconfirmed":status.unconfirmed}, "result":result}),
                ),
                ExecOutcome::Existing(status) => value(
                    serde_json::json!({"state":"existing", "status":{"phase":status.phase,"unconfirmed":status.unconfirmed}}),
                ),
            }
        }
        "operation_status" | "observe" => {
            let dto: Id = parse(body)?;
            let mut coordinator = Coordinator {
                issuer: &mut issuer,
                host: &service.host,
                host_id,
            };
            let status = if action == "observe" {
                Some(
                    coordinator
                        .observe(&dto.id, clock(service.clock.as_ref())?)
                        .await
                        .map_err(operation_error)?,
                )
            } else {
                coordinator.status(&dto.id).map_err(operation_error)?
            };
            value(Reply {
                state: if status.is_some() { "known" } else { "unknown" },
                evidence: status
                    .map(|s| serde_json::json!({"phase":s.phase,"unconfirmed":s.unconfirmed})),
            })
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationStatus {
    kind: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionRead {
    delegation_intent: String,
    grant: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionLookup {
    delegation: String,
    grant: String,
}

fn installation_reply(
    journal: &mut briqyard_api::execution::admission::Journal,
    kind: &str,
    id: &str,
    _outcome: Outcome,
) -> Result<serde_json::Value, StatusCode> {
    // Return only host acknowledgements, never signed credentials or authority keys.
    let (ready, evidence) = match kind {
        "registration" | "ownership" | "invalidate" | "revoke" => {
            let found = journal
                .authority_intent(id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let Some(intent) = found else {
                return value(Reply::<serde_json::Value> {
                    state: "unknown",
                    evidence: None,
                });
            };
            let matches_kind = matches!(
                (kind, &intent.payload),
                (
                    "registration",
                    briqyard_api::execution::admission::AuthorityPayload::Registration(_)
                ) | (
                    "ownership",
                    briqyard_api::execution::admission::AuthorityPayload::Ownership(_)
                ) | (
                    "invalidate",
                    briqyard_api::execution::admission::AuthorityPayload::Invalidate { .. }
                ) | (
                    "revoke",
                    briqyard_api::execution::admission::AuthorityPayload::Revoke { .. }
                )
            );
            if !matches_kind {
                return Err(StatusCode::BAD_REQUEST);
            }
            let evidence = if matches!(kind, "invalidate" | "revoke") {
                if intent.instance_confirmed {
                    Some(serde_json::json!({"host_instance":intent.host_instance}))
                } else {
                    None
                }
            } else {
                intent
                    .acknowledgement
                    .as_ref()
                    .map(|ack| serde_json::to_value(ack).unwrap())
            };
            (
                journal
                    .authority_intent_ready(id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                evidence,
            )
        }
        "discovery" => {
            let found = journal
                .discovery_intent(id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let Some(intent) = found else {
                return value(Reply::<serde_json::Value> {
                    state: "unknown",
                    evidence: None,
                });
            };
            (
                journal
                    .discovery_intent_ready(id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                intent
                    .receipt
                    .as_ref()
                    .map(|r| serde_json::to_value(r).unwrap()),
            )
        }
        "protection" => {
            let found = journal
                .protection_intent(id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let Some(intent) = found else {
                return value(Reply::<serde_json::Value> {
                    state: "unknown",
                    evidence: None,
                });
            };
            (
                journal
                    .protection_intent_ready(id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                intent
                    .acknowledgement
                    .as_ref()
                    .map(|r| serde_json::to_value(r).unwrap()),
            )
        }
        "delegation" => {
            let found = journal
                .delegation_intent(id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let Some(intent) = found else {
                return value(Reply::<serde_json::Value> {
                    state: "unknown",
                    evidence: None,
                });
            };
            (
                journal
                    .delegation_intent_ready(id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                intent.acknowledgement.as_ref().map(|r| {
                    serde_json::json!({"acknowledgement":r,"projection":intent.projection,
                        "intent":id,"authority_epoch":intent.authority_epoch,
                        "policy_revision":intent.policy_revision,"registration":intent.registration,
                        "ownership":intent.ownership,"protection":intent.protection})
                }),
            )
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    value(Reply {
        state: if ready { "ready" } else { "pending" },
        evidence,
    })
}

#[cfg(test)]
mod tests;
