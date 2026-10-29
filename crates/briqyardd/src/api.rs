//! The HTTP API over the machine manager.

use crate::events::Filter;
use crate::machine::{detached, MError, Manager, Until};
use axum::body::Body;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use briqyard_api as api;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub mgr: Manager,
    pub token: String,
    /// A token of its own for `/metrics`, so a scraper never holds the API's.
    pub metrics_token: String,
    /// The listener is on loopback: `/metrics` and the OpenAPI document need no token.
    pub loopback: bool,
    pub openapi: &'static str,
    /// The SHA-256 of the API's certificate; empty on plain HTTP (ADR 0020).
    pub tls_fingerprint: String,
}

/// The most a request may ask for. Past these a value is a mistake, not a wish, and the
/// daemon adds margins to timeouts that must not overflow.
const MAX_STOP_SEC: u64 = 600;
const MAX_EXEC_MS: u64 = 3_600_000;
const MAX_WAIT_SEC: u64 = 600;
const MAX_LOG_LINES: usize = 5000;

/// A stop's grace, from the request's seconds; 0 is the manager's default.
fn stop_timeout(asked_sec: u64) -> Duration {
    Duration::from_secs(asked_sec.min(MAX_STOP_SEC))
}

/// An exec's timeout, in ms; 0 is the manager's default.
fn exec_timeout_ms(asked: u64) -> u64 {
    asked.min(MAX_EXEC_MS)
}

/// How long `/wait` blocks: a minute unless asked.
fn wait_timeout(asked_sec: Option<u64>) -> Duration {
    Duration::from_secs(asked_sec.unwrap_or(60).clamp(1, MAX_WAIT_SEC))
}

/// Lines per log page; 0 is the manager's default.
fn log_limit(asked: Option<usize>) -> usize {
    asked.unwrap_or(0).min(MAX_LOG_LINES)
}

/// Which token a path needs: none for liveness; none for `/metrics` and the OpenAPI document
/// on a loopback listener; the metrics token for `/metrics` when one is set; else the API's.
#[derive(Debug, PartialEq)]
enum Bearer {
    None,
    Api,
    Metrics,
}

fn bearer_for(path: &str, loopback: bool, metrics_token: bool) -> Bearer {
    match path {
        "/healthz" => Bearer::None,
        "/metrics" | "/v1/openapi.yaml" if loopback => Bearer::None,
        "/metrics" if metrics_token => Bearer::Metrics,
        _ => Bearer::Api,
    }
}

type S = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/openapi.yaml", get(openapi))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/machines", get(list_machines).post(create_machine))
        .route(
            "/v1/machines/:id",
            get(get_machine)
                .patch(update_machine)
                .delete(destroy_machine),
        )
        .route("/v1/machines/:id/start", post(start_machine))
        .route("/v1/machines/:id/wake", post(wake_machine))
        .route("/v1/machines/:id/stop", post(stop_machine))
        .route("/v1/machines/:id/restart", post(restart_machine))
        .route("/v1/machines/:id/touch", post(touch_machine))
        .route("/v1/machines/:id/wait", post(wait_machine))
        .route("/v1/machines/:id/exec", get(exec_session).post(exec))
        .route("/v1/machines/:id/files", get(get_file).put(put_file))
        .route("/v1/machines/:id/logs", get(logs))
        .route("/v1/machines/:id/stats", get(stats))
        .route(
            "/v1/machines/:id/backups",
            get(list_backups).post(make_backup),
        )
        .route(
            "/v1/machines/:id/backups/:backup",
            axum::routing::delete(delete_backup),
        )
        .route("/v1/backups", get(all_backups))
        .route("/v1/machines/:id/snapshots", get(snapshots).post(snapshot))
        .route(
            "/v1/machines/:id/snapshots/:snap",
            axum::routing::delete(delete_snapshot),
        )
        .route(
            "/v1/machines/:id/snapshots/:snap/restore",
            post(restore_snapshot),
        )
        .route("/v1/machines/:id/endpoints", post(create_endpoint))
        .route("/v1/endpoints", get(list_endpoints))
        .route(
            "/v1/endpoints/:id",
            get(get_endpoint).delete(delete_endpoint),
        )
        .route("/v1/images", get(list_images))
        .route("/v1/images/:key", axum::routing::delete(delete_image))
        .route("/v1/usage", get(usage))
        .route("/v1/top", get(top))
        .route("/v1/events", get(events))
        .route("/v1/tenants", get(list_tenants))
        .route("/v1/tenants/:id", get(get_tenant).delete(delete_tenant))
        .route(
            "/v1/tenants/:id/gateway",
            put(set_gateway).delete(delete_gateway),
        )
        .route("/v1/tenants/:id/quota", get(get_quota).put(set_quota))
        .layer(middleware::from_fn_with_state(state.clone(), auth_and_log))
        .with_state(state)
}

/// Every error response's body, with the status it maps to.
pub struct AppError {
    status: StatusCode,
    code: &'static str,
    error: String,
    /// With `boot_failed`: the machine left in `error`; with a stale `If-Match`, the machine.
    machine: Option<Box<api::Machine>>,
    /// With `gone`: the oldest event seq kept.
    oldest: Option<u64>,
}

/// The status and code of each manager error. `boot_failed` is a 409 like the other
/// "not in that state" answers; `capacity` stays a 503, which the control plane retries later.
fn status_of(e: &MError) -> (StatusCode, &'static str) {
    match e {
        MError::NotFound | MError::NoBackup(_) | MError::NoSnapshot(_) => {
            (StatusCode::NOT_FOUND, "not_found")
        }
        MError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
        MError::Conflict(_) | MError::NameTaken(_) => (StatusCode::CONFLICT, "conflict"),
        MError::NotRunning(_) => (StatusCode::CONFLICT, "not_running"),
        MError::BadState(_) => (StatusCode::CONFLICT, "bad_state"),
        MError::BootFailed(_) => (StatusCode::CONFLICT, "boot_failed"),
        MError::PullFailed(_) => (StatusCode::CONFLICT, "pull_failed"),
        MError::CreateFailed(_) => (StatusCode::CONFLICT, "create_failed"),
        MError::Moved(_) => (StatusCode::CONFLICT, "conflict"),
        MError::NotReady(_) => (StatusCode::CONFLICT, "not_ready"),
        MError::Gone { .. } => (StatusCode::GONE, "gone"),
        MError::Capacity(_) => (StatusCode::SERVICE_UNAVAILABLE, "capacity"),
        MError::Quota(_) => (StatusCode::FORBIDDEN, "quota"),
        MError::TenantInUse => (StatusCode::CONFLICT, "tenant_in_use"),
        MError::GatewayInUse => (StatusCode::CONFLICT, "gateway_in_use"),
        MError::Gateway(_) => (StatusCode::CONFLICT, "gateway"),
        MError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

impl From<MError> for AppError {
    fn from(e: MError) -> Self {
        let (status, code) = status_of(&e);
        let error = match &e {
            MError::Other(err) => format!("{err:#}"),
            other => other.to_string(),
        };
        let oldest = match &e {
            MError::Gone { oldest, .. } => Some(*oldest),
            _ => None,
        };
        let machine = match e {
            MError::BootFailed(m) => {
                // The image's fault, not an operator's: a warning.
                tracing::warn!(machine = m.id, err = %error, "boot failed");
                Some(m)
            }
            // A create's failure was logged where it happened (ADR 0048); a `/wait` reads it.
            MError::Moved(m)
            | MError::NotReady(m)
            | MError::PullFailed(m)
            | MError::CreateFailed(m)
            | MError::NameTaken(m) => Some(m),
            MError::Other(_) => {
                tracing::error!(err = %error, "request failed");
                None
            }
            _ => None,
        };
        AppError {
            status,
            code,
            error,
            machine,
            oldest,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            Json(api::ApiError {
                error: self.error,
                code: self.code.into(),
                request_id: String::new(),
                machine: self.machine,
                oldest: self.oldest,
            }),
        )
            .into_response();
        resp.extensions_mut().insert(IsError);
        resp
    }
}

#[derive(Clone, Copy)]
struct IsError;

async fn auth_and_log(State(st): S, req: Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| {
            use rand::RngCore;
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            hex::encode(b)
        });
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let expected = match bearer_for(&path, st.loopback, !st.metrics_token.is_empty()) {
        Bearer::None => "",
        Bearer::Api => st.token.as_str(),
        Bearer::Metrics => st.metrics_token.as_str(),
    };
    if !expected.is_empty() {
        let got = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !api::constant_eq(got.as_bytes(), expected.as_bytes()) {
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(api::ApiError {
                    error: "a bearer token is required".into(),
                    code: "unauthorized".into(),
                    request_id: request_id.clone(),
                    machine: None,
                    oldest: None,
                }),
            )
                .into_response();
            resp.headers_mut()
                .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
            return resp;
        }
    }
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
    if path != "/healthz" {
        tracing::info!(%method, path, status = resp.status().as_u16(), ms = start.elapsed().as_millis() as u64, request_id, "request");
    }
    resp
}

async fn openapi(State(st): S) -> Response {
    ([(header::CONTENT_TYPE, "application/yaml")], st.openapi).into_response()
}

async fn metrics(State(st): S) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        st.mgr.metrics(),
    )
        .into_response()
}

async fn status(State(st): S) -> Json<api::Status> {
    let (used, running, machines) = st.mgr.usage();
    Json(api::Status {
        version: api::VERSION.into(),
        host_id: st.mgr.host_id().into(),
        capacity: st.mgr.capacity(),
        used,
        machines,
        running,
        disk_free_mb: st.mgr.disk_free_mb().await,
        tls_fingerprint: st.tls_fingerprint.clone(),
        conditions: st.mgr.conditions(),
        started: Some(st.mgr.started()),
        vmm_version: st.mgr.vmm_version(),
        regions: Vec::new(),
    })
}

#[derive(Deserialize)]
struct ListQuery {
    tenant: Option<String>,
}

/// A listing's query: the tenant, and the label selectors, each `label=` one (ADR 0025).
fn list_query(query: Option<&str>) -> Result<(Option<String>, Vec<api::Label>), MError> {
    let (mut tenant, mut labels) = (None, Vec::new());
    for (k, v) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        match k.as_ref() {
            "tenant" => tenant = Some(v.into_owned()),
            "label" => labels.push(api::Label::parse(&v).map_err(MError::Invalid)?),
            _ => {}
        }
    }
    Ok((tenant, labels))
}

async fn list_machines(
    State(st): S,
    RawQuery(query): RawQuery,
) -> Result<Json<Vec<api::Machine>>, AppError> {
    let (tenant, labels) = list_query(query.as_deref())?;
    Ok(Json(st.mgr.list(tenant.as_deref(), &labels)))
}

// Every transition runs through `detached`: axum drops a handler's future when the client
// hangs up, and a create, start, stop or destroy cut short would leave the machine half-moved.

/// 201 once the machine is recorded, in `creating` (ADR 0048): its image, disks and start
/// follow; `/wait` waits for them.
async fn create_machine(
    State(st): S,
    Json(req): Json<api::CreateMachineRequest>,
) -> Result<(StatusCode, Json<api::Machine>), AppError> {
    let m = st.mgr.clone();
    let made = detached(async move { m.create(req).await }).await?;
    Ok((StatusCode::CREATED, Json(made)))
}

async fn get_machine(State(st): S, Path(id): Path<String>) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(st.mgr.get(&id)?))
}

/// `If-Match: <version>` (ADR 0019), the quotes of an HTTP entity tag allowed; absent is no
/// condition.
fn if_match(headers: &HeaderMap) -> Result<Option<u64>, AppError> {
    let Some(v) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let text = v.to_str().unwrap_or("").trim().trim_matches('"');
    match text.parse() {
        Ok(n) => Ok(Some(n)),
        Err(_) => Err(MError::Invalid(format!(
            "If-Match {text:?}: want a machine's version, a number"
        ))
        .into()),
    }
}

async fn update_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<api::UpdateMachineRequest>,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    // Detached too: a policy swap cut short between its two steps would leave none.
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.update(&id, req, at).await }).await?,
    ))
}

async fn destroy_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    detached(async move { m.destroy(&id, at).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(detached(async move { m.start(&id, at).await }).await?))
}

async fn wake_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(detached(async move { m.wake(&id, at).await }).await?))
}

async fn stop_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<api::StopRequest>>,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let req = body.map(|b| b.0).unwrap_or_default();
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move {
            m.stop(&id, stop_timeout(req.timeout_sec), req.suspend, at)
                .await
        })
        .await?,
    ))
}

async fn restart_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.restart(&id, at).await }).await?,
    ))
}

async fn touch_machine(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    st.mgr.touch(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WaitQuery {
    timeout: Option<u64>,
    /// `ready` (the default) or `running`.
    #[serde(rename = "for")]
    until: Option<String>,
}

/// What a `/wait` waits for: `ready` unless asked for `running` (ADR 0022).
fn wait_until(asked: Option<&str>) -> Result<Until, MError> {
    match asked {
        None | Some("ready") => Ok(Until::Ready),
        Some("running") => Ok(Until::Running),
        Some(other) => Err(MError::Invalid(format!(
            "for {other:?}: want \"ready\" or \"running\""
        ))),
    }
}

async fn wait_machine(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<api::Machine>, AppError> {
    let until = wait_until(q.until.as_deref())?;
    Ok(Json(
        st.mgr.wait(&id, until, wait_timeout(q.timeout)).await?,
    ))
}

async fn exec(
    State(st): S,
    Path(id): Path<String>,
    Json(mut req): Json<api::ExecRequest>,
) -> Result<Json<api::ExecResult>, AppError> {
    if req.cmd.is_empty() {
        return Err(MError::Invalid("cmd is required".into()).into());
    }
    req.timeout_ms = exec_timeout_ms(req.timeout_ms);
    Ok(Json(st.mgr.exec(&id, req).await?))
}

/// The largest message a session takes: its stdin frame, base64 in JSON, stays under the
/// guest protocol's largest frame.
const MAX_SESSION_MESSAGE: usize = 1 << 20;

/// An exec session (ADR 0029): the command starts, the machine woken first when asked, then
/// the upgrade; every refusal before it is an HTTP answer like any other.
async fn exec_session(
    State(st): S,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, AppError> {
    let ws = ws.map_err(|e| {
        MError::Invalid(format!(
            "a session is a WebSocket upgrade of GET /v1/machines/{id}/exec: {e}"
        ))
    })?;
    let pairs = url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes());
    let mut req = api::session::ExecSession::from_query(pairs).map_err(MError::Invalid)?;
    req.timeout_ms = exec_timeout_ms(req.timeout_ms);
    let session = st.mgr.open_session(&id, req).await?;
    Ok(ws
        .max_message_size(MAX_SESSION_MESSAGE)
        .max_frame_size(MAX_SESSION_MESSAGE)
        .on_upgrade(move |socket| crate::session::serve(socket, session)))
}

async fn put_file(
    State(st): S,
    Path(id): Path<String>,
    Json(req): Json<api::PutFileRequest>,
) -> Result<StatusCode, AppError> {
    st.mgr.put_file(&id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct FileQuery {
    path: String,
}

async fn get_file(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Result<Json<api::FileResponse>, AppError> {
    let data = st.mgr.get_file(&id, &q.path).await?;
    Ok(Json(api::FileResponse {
        path: q.path,
        base64: api::guest::base64_encode(&data),
    }))
}

#[derive(Deserialize)]
struct LogsQuery {
    since: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    follow: bool,
}

/// A page of the console; with `follow=true`, the lines and each new one as NDJSON, kept open
/// (ADR 0025).
async fn logs(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Response, AppError> {
    let since = q.since.as_deref().unwrap_or("");
    if !q.follow {
        return Ok(Json(st.mgr.logs(&id, since, log_limit(q.limit))?).into_response());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
    st.mgr.follow_logs(&id, since, tx)?;
    Ok(ndjson(rx))
}

/// A stream of lines as `application/x-ndjson`, until the sender is dropped.
fn ndjson(rx: tokio::sync::mpsc::Receiver<String>) -> Response {
    let lines = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|l| (Ok::<_, std::convert::Infallible>(l), rx))
    });
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(lines),
    )
        .into_response()
}

async fn make_backup(
    State(st): S,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<api::Backup>), AppError> {
    let m = st.mgr.clone();
    let b = detached(async move { m.backup(&id).await }).await?;
    Ok((StatusCode::CREATED, Json(b)))
}

/// The backups of a machine id, which may be a machine this host never had: the store is
/// shared, so a restore can start from any host.
async fn list_backups(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<Vec<api::Backup>>, AppError> {
    Ok(Json(st.mgr.backups(&id).await?))
}

#[derive(Deserialize)]
struct DeleteBackupQuery {
    #[serde(default)]
    chain: bool,
}

/// Deletes a backup of a machine of this host or of one destroyed here; with `chain`, the
/// backups that continue from it too.
async fn delete_backup(
    State(st): S,
    Path((id, backup)): Path<(String, String)>,
    Query(q): Query<DeleteBackupQuery>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_backup(&id, &backup, q.chain).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct BackupsQuery {
    tenant: Option<String>,
    machine: Option<String>,
}

/// Every backup of the host's machines, destroyed ones' included, of a tenant or all, of a
/// machine or all.
async fn all_backups(
    State(st): S,
    Query(q): Query<BackupsQuery>,
) -> Result<Json<Vec<api::Backup>>, AppError> {
    let (tenant, machine) = (q.tenant.as_deref(), q.machine.as_deref());
    Ok(Json(st.mgr.all_backups(tenant, machine).await?))
}

async fn stats(State(st): S, Path(id): Path<String>) -> Result<Json<api::MachineStats>, AppError> {
    Ok(Json(st.mgr.stats(&id).await?))
}

async fn snapshot(
    State(st): S,
    Path(id): Path<String>,
    body: Option<Json<api::SnapshotRequest>>,
) -> Result<(StatusCode, Json<api::Snapshot>), AppError> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let m = st.mgr.clone();
    let s = detached(async move { m.snapshot(&id, req).await }).await?;
    Ok((StatusCode::CREATED, Json(s)))
}

async fn restore_snapshot(
    State(st): S,
    Path((id, snap)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.restore_snapshot(&id, &snap, at).await }).await?,
    ))
}

async fn snapshots(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<Vec<api::Snapshot>>, AppError> {
    Ok(Json(st.mgr.snapshots(&id).await?))
}

async fn delete_snapshot(
    State(st): S,
    Path((id, snap)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_snapshot(&id, &snap).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_endpoint(
    State(st): S,
    Path(id): Path<String>,
    Json(req): Json<api::CreateEndpointRequest>,
) -> Result<(StatusCode, Json<api::Endpoint>), AppError> {
    Ok((StatusCode::CREATED, Json(st.mgr.create_endpoint(&id, req)?)))
}

async fn list_endpoints(State(st): S) -> Json<Vec<api::Endpoint>> {
    Json(
        st.mgr
            .all_endpoints()
            .iter()
            .map(|e| st.mgr.endpoint_view(e))
            .collect(),
    )
}

async fn get_endpoint(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Endpoint>, AppError> {
    let ep = st.mgr.endpoint(&id).ok_or(MError::NotFound)?;
    Ok(Json(st.mgr.endpoint_view(&ep)))
}

async fn delete_endpoint(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    st.mgr.delete_endpoint(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_images(State(st): S) -> Result<Json<Vec<api::Image>>, AppError> {
    Ok(Json(st.mgr.images().await?))
}

async fn delete_image(State(st): S, Path(key): Path<String>) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_image(&key).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The running machines' use over the tick's last window (ADR 0021).
async fn top(State(st): S, Query(q): Query<ListQuery>) -> Json<Vec<api::TopMachine>> {
    Json(st.mgr.top(q.tenant.as_deref()))
}

#[derive(Deserialize)]
struct UsageQuery {
    from: Option<String>,
    to: Option<String>,
    tenant: Option<String>,
}

/// The usage buckets of a range of hours (ADR 0017).
async fn usage(
    State(st): S,
    Query(q): Query<UsageQuery>,
) -> Result<Json<Vec<api::UsageBucket>>, AppError> {
    let (from, to) =
        crate::usage::range(q.from.as_deref(), q.to.as_deref()).map_err(MError::Invalid)?;
    Ok(Json(st.mgr.usage_buckets(from, to, q.tenant).await?))
}

#[derive(Deserialize)]
struct EventsQuery {
    since: Option<String>,
    tenant: Option<String>,
    machine: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    watch: bool,
}

/// The query's cursor and filter, checked: a seq (absent is 0), ids, a type.
fn events_query(q: EventsQuery) -> Result<(u64, Filter), MError> {
    let since = match q.since.as_deref() {
        None | Some("") => 0,
        Some(s) => s
            .parse()
            .map_err(|_| MError::Invalid(format!("since {s:?}: want a seq, a page's `next`")))?,
    };
    for id in [&q.tenant, &q.machine].into_iter().flatten() {
        if !api::valid_id(id) {
            return Err(MError::Invalid(format!("{id:?} is not an id")));
        }
    }
    if let Some(k) = &q.kind {
        if k != api::event::NORMAL && k != api::event::WARNING {
            return Err(MError::Invalid(format!(
                "type {k:?}: want \"normal\" or \"warning\""
            )));
        }
    }
    let f = Filter {
        tenant: q.tenant,
        machine: q.machine,
        kind: q.kind,
    };
    Ok((since, f))
}

/// Events after a cursor (ADR 0019); with `watch=true`, those and each new one, kept open as
/// NDJSON.
async fn events(State(st): S, Query(q): Query<EventsQuery>) -> Result<Response, AppError> {
    let (watch, limit) = (q.watch, api::events_limit(q.limit));
    let (since, f) = events_query(q)?;
    if !watch {
        return Ok(Json(st.mgr.events_page(since, f, limit).await?).into_response());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
    st.mgr
        .events()
        .watch(since, f, tx)
        .await
        .map_err(crate::machine::gone)?;
    Ok(ndjson(rx))
}

async fn list_tenants(State(st): S) -> Json<Vec<api::Tenant>> {
    Json(st.mgr.tenants())
}

async fn get_tenant(State(st): S, Path(id): Path<String>) -> Result<Json<api::Tenant>, AppError> {
    Ok(Json(st.mgr.tenant(&id)?))
}

async fn delete_tenant(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_tenant(&id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_gateway(
    State(st): S,
    Path(id): Path<String>,
    Json(spec): Json<api::GatewaySpec>,
) -> Result<Json<api::Tenant>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.set_gateway(&id, spec).await }).await?,
    ))
}

async fn delete_gateway(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_gateway(&id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_quota(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::TenantQuota>, AppError> {
    Ok(Json(st.mgr.quota(&id)?))
}

async fn set_quota(
    State(st): S,
    Path(id): Path<String>,
    Json(q): Json<api::Quota>,
) -> Result<Json<api::TenantQuota>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.set_quota(&id, q).await }).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bounds_hold_at_the_extremes() {
        // The margins the manager adds (10 s to an exec, 5 s to a stop) fit after the cap.
        assert_eq!(stop_timeout(u64::MAX), Duration::from_secs(MAX_STOP_SEC));
        assert_eq!(stop_timeout(0), Duration::ZERO);
        assert_eq!(stop_timeout(30), Duration::from_secs(30));
        assert_eq!(exec_timeout_ms(u64::MAX), MAX_EXEC_MS);
        assert_eq!(exec_timeout_ms(0), 0);
        assert_eq!(exec_timeout_ms(5000), 5000);
        assert!(Duration::from_millis(exec_timeout_ms(u64::MAX) + 10_000) > Duration::ZERO);
        assert_eq!(
            wait_timeout(Some(u64::MAX)),
            Duration::from_secs(MAX_WAIT_SEC)
        );
        assert_eq!(wait_timeout(Some(0)), Duration::from_secs(1));
        assert_eq!(wait_timeout(None), Duration::from_secs(60));
        assert_eq!(log_limit(Some(usize::MAX)), MAX_LOG_LINES);
        assert_eq!(log_limit(None), 0);
        assert_eq!(log_limit(Some(10)), 10);
    }

    #[test]
    fn the_description_lists_the_reasons_the_daemon_has() {
        let doc: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../../../api/openapi.yaml")).unwrap();
        let listed: Vec<&str> = doc["components"]["schemas"]["Event"]["properties"]["reason"]
            ["enum"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(listed, api::reason::ALL);
    }

    #[test]
    fn a_listing_reads_its_tenant_and_every_label() {
        assert_eq!(list_query(None).unwrap(), (None, vec![]));
        let (tenant, labels) =
            list_query(Some("tenant=t1&label=app%3Dweb&label=tier&other=x")).unwrap();
        assert_eq!(tenant.as_deref(), Some("t1"));
        assert_eq!(
            labels,
            [
                api::Label::parse("app=web").unwrap(),
                api::Label::parse("tier").unwrap()
            ]
        );
        // Unencoded, as a person types it.
        assert_eq!(list_query(Some("label=app=web")).unwrap().1.len(), 1);
        let e = AppError::from(list_query(Some("label=app!%3Dweb")).unwrap_err());
        assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "invalid"));
        assert!(e.error.contains("no !="), "{}", e.error);
    }

    #[test]
    fn wait_is_for_ready_unless_asked() {
        assert_eq!(wait_until(None).ok(), Some(Until::Ready));
        assert_eq!(wait_until(Some("ready")).ok(), Some(Until::Ready));
        assert_eq!(wait_until(Some("running")).ok(), Some(Until::Running));
        let e = AppError::from(wait_until(Some("up")).unwrap_err());
        assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "invalid"));
        assert_eq!(
            e.error,
            "invalid request: for \"up\": want \"ready\" or \"running\""
        );
    }

    #[test]
    fn if_match_is_a_version() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::IF_MATCH, HeaderValue::from_str(v).unwrap());
            m
        };
        assert_eq!(if_match(&HeaderMap::new()).ok(), Some(None));
        assert_eq!(if_match(&h("12")).ok(), Some(Some(12)));
        // An entity tag's quotes are taken off.
        assert_eq!(if_match(&h("\"12\"")).ok(), Some(Some(12)));
        let e = if_match(&h("*")).err().unwrap();
        assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "invalid"));
    }

    #[test]
    fn which_bearer_a_path_needs() {
        assert_eq!(bearer_for("/healthz", false, false), Bearer::None);
        assert_eq!(bearer_for("/v1/machines", true, true), Bearer::Api);
        // On loopback, a scrape and a browser need no secret.
        assert_eq!(bearer_for("/metrics", true, false), Bearer::None);
        assert_eq!(bearer_for("/v1/openapi.yaml", true, false), Bearer::None);
        // Elsewhere, the metrics token when there is one, else the API's.
        assert_eq!(bearer_for("/metrics", false, true), Bearer::Metrics);
        assert_eq!(bearer_for("/metrics", false, false), Bearer::Api);
        assert_eq!(bearer_for("/v1/openapi.yaml", false, true), Bearer::Api);
    }

    #[test]
    fn error_codes() {
        let m = api::Machine {
            id: "m_1".into(),
            state: api::state::ERROR.into(),
            error: "the guest did not come up: tail".into(),
            ..Default::default()
        };
        let e = AppError::from(MError::BootFailed(Box::new(m)));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "boot_failed"));
        assert_eq!(e.error, "boot failed: the guest did not come up: tail");
        assert_eq!(e.machine.as_ref().map(|m| m.id.as_str()), Some("m_1"));
        // A stale If-Match: 409 `conflict`, with the machine as it is now.
        let now = api::Machine {
            id: "m_1".into(),
            version: 12,
            ..Default::default()
        };
        let e = AppError::from(MError::Moved(Box::new(now)));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "conflict"));
        assert_eq!(e.error, "machine m_1 is at version 12: read it again");
        assert_eq!(e.machine.map(|m| m.version), Some(12));
        let e = AppError::from(MError::Gone {
            oldest: 40,
            message: "since 3: the events after it are gone; the oldest kept is 40".into(),
        });
        assert_eq!(
            (e.status, e.code, e.oldest),
            (StatusCode::GONE, "gone", Some(40))
        );
        let e = AppError::from(MError::NoBackup("m_1/20261021T101500.123Z".into()));
        assert_eq!((e.status, e.code), (StatusCode::NOT_FOUND, "not_found"));
        assert_eq!(e.error, "backup m_1/20261021T101500.123Z not found");
        // A `/wait` that ran out on a running machine its probes do not pass: the machine.
        let running = api::Machine {
            id: "m_1".into(),
            state: api::state::RUNNING.into(),
            probes_status: api::ProbesStatus {
                readiness: Some(api::ProbeStatus {
                    passed: false,
                    message: "HTTP 503".into(),
                    failures: 4,
                    at: chrono::Utc::now(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let e = AppError::from(MError::NotReady(Box::new(running)));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "not_ready"));
        assert_eq!(
            e.error,
            "machine m_1 is running, not ready: readiness: HTTP 503"
        );
        assert_eq!(e.machine.map(|m| m.state), Some("running".to_string()));
        // ADR 0048: on its way at the timeout, a create that failed, a name taken: the machine.
        let on_its_way = api::Machine {
            id: "m_1".into(),
            state: api::state::CREATING.into(),
            ..Default::default()
        };
        let e = AppError::from(MError::NotReady(Box::new(on_its_way.clone())));
        assert_eq!(
            (e.code, e.error.as_str()),
            ("not_ready", "machine m_1 is still creating")
        );
        let failed = api::Machine {
            state: api::state::ERROR.into(),
            error: "pull x: manifest unknown".into(),
            ..on_its_way.clone()
        };
        let e = AppError::from(MError::PullFailed(Box::new(failed.clone())));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "pull_failed"));
        assert_eq!(e.error, "pull failed: pull x: manifest unknown");
        let e = AppError::from(MError::CreateFailed(Box::new(failed)));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "create_failed"));
        assert!(e.machine.is_some());
        let e = AppError::from(MError::NameTaken(Box::new(on_its_way)));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "conflict"));
        assert_eq!(e.machine.map(|m| m.id), Some("m_1".to_string()));
        let e = AppError::from(MError::Quota(
            "tenant t1's quota: machines 1 of 1 used, 1 more asked".into(),
        ));
        assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "quota"));
        assert_eq!(
            e.error,
            "tenant t1's quota: machines 1 of 1 used, 1 more asked"
        );
        let e = AppError::from(MError::GatewayInUse);
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "gateway_in_use"));
        let e = AppError::from(MError::Gateway("t1".into()));
        assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "gateway"));
        assert_eq!(e.error, "the tenant's gateway: use /v1/tenants/t1/gateway");
        let e = AppError::from(MError::Capacity("1 MB used of 1".into()));
        assert_eq!(
            (e.status, e.code),
            (StatusCode::SERVICE_UNAVAILABLE, "capacity")
        );
        assert!(e.machine.is_none());
        let e = AppError::from(MError::Other(anyhow::anyhow!("boom")));
        assert_eq!(
            (e.status, e.code),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal")
        );
    }
}
