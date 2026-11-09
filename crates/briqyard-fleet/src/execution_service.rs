//! Dormant regional authority HTTP boundary. Constructed only by a qualified caller;
//! the ordinary fleet router does not mount it or provision its credentials.
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

/// The producer must independently qualify its wall-clock interval. An expired
/// observation is never promoted into fresh evidence by reading SystemTime.
pub(super) struct QualifiedClock {
    pub interval: Clock,
    pub valid_until: Instant,
}
pub(super) trait ClockSource: Send + Sync {
    fn qualified(&self) -> Option<QualifiedClock>;
}

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
        "register"
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
        "exec" | "projection" | "operation_status" | "observe"
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
            let c = clock(service.clock.as_ref())?;
            let state = installer
                .invalidate(&dto.id, &dto.host_instance, dto.request, c)
                .await
                .map_err(install_error)?;
            installation_reply(installer.journal, "invalidate", &dto.id, state)
        }
        "revoke" => {
            let dto: Revocation = parse(body)?;
            let c = clock(service.clock.as_ref())?;
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
                        "intent":id,"authority_epoch":intent.authority_epoch})
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
mod tests {
    use super::*;
    use crate::registry::HostRec;
    use briqyard_api::execution::{
        admission::{Journal, Role},
        KeyRole,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tower::ServiceExt;

    struct FixedClock(Option<Clock>);
    impl ClockSource for FixedClock {
        fn qualified(&self) -> Option<QualifiedClock> {
            self.0.map(|interval| QualifiedClock {
                interval,
                valid_until: Instant::now() + std::time::Duration::from_secs(5),
            })
        }
    }
    struct StaleClock;
    impl ClockSource for StaleClock {
        fn qualified(&self) -> Option<QualifiedClock> {
            Some(QualifiedClock {
                interval: Clock {
                    now: 1000,
                    uncertainty: 1,
                },
                valid_until: Instant::now() - std::time::Duration::from_secs(1),
            })
        }
    }
    fn fixture(clock: Arc<dyn ClockSource>) -> (Router, tempfile::TempDir) {
        let host = HostRec {
            id: "host".into(),
            url: "https://127.0.0.1:1".into(),
            token: "host-admin".into(),
            tls_fingerprint: "ab".repeat(32),
            ..Default::default()
        };
        let (app, dir, _) = fixture_with_host(clock, host);
        (app, dir)
    }
    fn fixture_with_host(
        clock: Arc<dyn ClockSource>,
        host: HostRec,
    ) -> (Router, tempfile::TempDir, String) {
        let (app, dir, epoch) = configured_fixture(clock, host, |_, _| {});
        (app.unwrap(), dir, epoch)
    }
    fn configured_fixture(
        clock: Arc<dyn ClockSource>,
        host: HostRec,
        configure: impl FnOnce(&mut String, &mut Credentials),
    ) -> (Result<Router, &'static str>, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
        let issuer =
            briqyard_api::execution::DurableIssuer::new(journal, key, "authority".into()).unwrap();
        let epoch = issuer.instance().to_owned();
        let transport = HostTransport::new(
            &host,
            "host-installer",
            "host-execution",
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        let mut host_id = host.id;
        let mut credentials = Credentials {
            installer: "central-installer".into(),
            gateway: "gateway-only".into(),
            administrator: "fleet-admin".into(),
            host_administrator: "host-admin".into(),
        };
        configure(&mut host_id, &mut credentials);
        let app = router(
            issuer,
            transport,
            host_id,
            credentials,
            &crate::config::Config {
                token: "fleet-admin".into(),
                ..Default::default()
            },
            TrustConfig {
                keys: vec![VerificationKey {
                    kid: "central".into(),
                    role: KeyRole::Central,
                    issuer: "central".into(),
                    authority: None,
                    public_key: [1; 32],
                }],
                central_issuer: "central".into(),
                authority_issuer: "authority".into(),
                audience: "host".into(),
            },
            clock,
        );
        (app, dir, epoch)
    }
    #[test]
    fn constructor_checks_actual_host_and_fleet_administrator_credentials() {
        for change in 0..5 {
            let host = HostRec {
                id: "host".into(),
                url: "https://127.0.0.1:1".into(),
                token: "host-admin".into(),
                tls_fingerprint: "ab".repeat(32),
                ..Default::default()
            };
            let (result, _dir, _) =
                configured_fixture(Arc::new(FixedClock(None)), host, |host_id, credentials| {
                    if change == 0 {
                        *host_id = "another-host".into();
                    } else if change < 3 {
                        credentials.host_administrator = "unrelated-placeholder".into();
                        if change == 1 {
                            credentials.installer = "host-admin".into();
                        } else {
                            credentials.gateway = "host-admin".into();
                        }
                    } else {
                        credentials.administrator = "unrelated-placeholder".into();
                        if change == 3 {
                            credentials.installer = "fleet-admin".into();
                        } else {
                            credentials.gateway = "fleet-admin".into();
                        }
                    }
                });
            assert!(result.is_err());
        }
    }
    async fn request(app: &Router, action: &str, token: &str, body: Vec<u8>) -> Response {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/internal/authority/v1/{action}"))
            .header(header::CONTENT_TYPE, "application/json");
        if !token.is_empty() {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        app.clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn roles_body_limit_and_unknown_status_are_enforced_at_router() {
        let (app, _dir) = fixture(Arc::new(FixedClock(Some(Clock {
            now: 1000,
            uncertainty: 1,
        }))));
        let status = br#"{"id":"missing"}"#.to_vec();
        for token in ["", "central-installer", "fleet-admin"] {
            assert_eq!(
                request(&app, "projection", token, vec![]).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            request(
                &app,
                "projection",
                "gateway-only",
                br#"{"delegation_intent":"missing"}"#.to_vec()
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            request(
                &app,
                "projection",
                "gateway-only",
                br#"{"delegation_intent":"missing","grant":"presented"}"#.to_vec()
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&app, "operation_status", "", status.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &app,
                "operation_status",
                "central-installer",
                status.clone()
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &app,
                "installation_status",
                "gateway-only",
                br#"{"kind":"delegation","id":"missing"}"#.to_vec()
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&app, "register", "fleet-admin", vec![])
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&app, "revoke", "gateway-only", vec![])
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = request(&app, "operation_status", "gateway-only", status).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"state":"unknown","evidence":null})
        );
        assert_eq!(
            request(
                &app,
                "installation_status",
                "central-installer",
                br#"{"kind":"delegation","id":"missing"}"#.to_vec()
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&app, "exec", "gateway-only", vec![b'x'; MAX_BODY_BYTES + 1])
                .await
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    #[tokio::test]
    async fn stale_or_absent_clock_refuses_mutation_before_host_call() {
        for source in [
            Arc::new(StaleClock) as Arc<dyn ClockSource>,
            Arc::new(FixedClock(None)),
        ] {
            let host = HostRec {
                id: "host".into(),
                url: "https://127.0.0.1:1".into(),
                token: "host-admin".into(),
                tls_fingerprint: "ab".repeat(32),
                ..Default::default()
            };
            let (app, _dir, epoch) = fixture_with_host(source, host);
            let record = HostRegistration {
                authority: "region".into(),
                epoch,
                key_id: "authority".into(),
                public_key: Ed25519KeyPair::from_seed_unchecked(&[2; 32])
                    .unwrap()
                    .public_key()
                    .as_ref()
                    .try_into()
                    .unwrap(),
                host_instance: "instance".into(),
                generation: 1,
            };
            let body =
                serde_json::to_vec(&serde_json::json!({"id":"new","record":record})).unwrap();
            assert_eq!(
                request(&app, "register", "central-installer", body)
                    .await
                    .status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                request(
                    &app,
                    "observe",
                    "gateway-only",
                    br#"{"id":"unknown"}"#.to_vec()
                )
                .await
                .status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }
    #[tokio::test]
    async fn registration_route_returns_exact_ack_and_duplicate_is_status_only() {
        use axum::{extract::State, response::IntoResponse};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicUsize, Ordering};
        async fn endpoint(
            State(calls): State<Arc<AtomicUsize>>,
            uri: axum::http::Uri,
            body: axum::body::Bytes,
        ) -> Response {
            if uri.path().ends_with("/instance") {
                return Json(briqyard_api::execution::channel::Instance {
                    host_instance: "instance".into(),
                })
                .into_response();
            }
            calls.fetch_add(1, Ordering::SeqCst);
            let record: HostRegistration = serde_json::from_slice(&body).unwrap();
            Json(briqyard_api::execution::channel::InstallationAck {
                host_instance: record.host_instance,
                generation: record.generation,
                digest: URL_SAFE_NO_PAD.encode(Sha256::digest(body)),
            })
            .into_response()
        }
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let config = briqyard_api::tls::server_config(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host = HostRec {
            id: "host".into(),
            url: format!("https://{}", listener.local_addr().unwrap()),
            token: "host-admin".into(),
            tls_fingerprint: briqyard_api::tls::fingerprint(cert.cert.der()),
            ..Default::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let handle = axum_server::Handle::new();
        let running = handle.clone();
        let app_host = axum::Router::new()
            .fallback(endpoint)
            .with_state(calls.clone());
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(
                listener,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            )
            .handle(running)
            .serve(app_host.into_make_service())
            .await
        });
        let (app, _dir, epoch) = fixture_with_host(
            Arc::new(FixedClock(Some(Clock {
                now: 1000,
                uncertainty: 1,
            }))),
            host,
        );
        let record = HostRegistration {
            authority: "region".into(),
            epoch,
            key_id: "authority".into(),
            public_key: Ed25519KeyPair::from_seed_unchecked(&[2; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .try_into()
                .unwrap(),
            host_instance: "instance".into(),
            generation: 1,
        };
        let body =
            serde_json::to_vec(&serde_json::json!({"id":"registration", "record":record})).unwrap();
        let first = request(&app, "register", "central-installer", body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);
        let first: serde_json::Value =
            serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(first["state"], "ready");
        assert_eq!(first["evidence"]["host_instance"], "instance");
        let second = request(&app, "register", "central-installer", body).await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            request(
                &app,
                "installation_status",
                "central-installer",
                br#"{"kind":"ownership","id":"registration"}"#.to_vec()
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        handle.shutdown();
        task.abort();
    }

    #[test]
    fn credential_configuration_refuses_reuse_and_empty_values() {
        // Constructor validation is pure and occurs before a listener exists.
        let c = Credentials {
            installer: "i".into(),
            gateway: "g".into(),
            administrator: "a".into(),
            host_administrator: "h".into(),
        };
        assert!(valid_credentials(&c));
        for (i, g, a, h) in [
            ("", "g", "a", "h"),
            ("i", "", "a", "h"),
            ("x", "x", "a", "h"),
            ("a", "g", "a", "h"),
            ("i", "h", "a", "h"),
        ] {
            assert!(!valid_credentials(&Credentials {
                installer: i.into(),
                gateway: g.into(),
                administrator: a.into(),
                host_administrator: h.into()
            }));
        }
    }
}
