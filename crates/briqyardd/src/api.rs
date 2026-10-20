//! The HTTP API over the machine manager.

use crate::machine::{detached, MError, Manager};
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
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
        .route("/v1/machines/:id/touch", post(touch_machine))
        .route("/v1/machines/:id/wait", post(wait_machine))
        .route("/v1/machines/:id/exec", post(exec))
        .route("/v1/machines/:id/files", get(get_file).put(put_file))
        .route("/v1/machines/:id/logs", get(logs))
        .route("/v1/machines/:id/stats", get(stats))
        .route(
            "/v1/machines/:id/backups",
            get(list_backups).post(make_backup),
        )
        .route("/v1/machines/:id/snapshots", get(snapshots).post(snapshot))
        .route("/v1/machines/:id/endpoints", post(create_endpoint))
        .route("/v1/endpoints", get(list_endpoints))
        .route(
            "/v1/endpoints/:id",
            get(get_endpoint).delete(delete_endpoint),
        )
        .route("/v1/images", get(list_images))
        .route("/v1/images/:key", axum::routing::delete(delete_image))
        .route("/v1/tenants", get(list_tenants))
        .route("/v1/tenants/:id", axum::routing::delete(delete_tenant))
        .layer(middleware::from_fn_with_state(state.clone(), auth_and_log))
        .with_state(state)
}

/// Every error response's body, with the status it maps to.
pub struct AppError {
    status: StatusCode,
    code: &'static str,
    error: String,
    /// With `boot_failed`: the machine left in `error`.
    machine: Option<Box<api::Machine>>,
}

/// The status and code of each manager error. `boot_failed` is a 409 like the other
/// "not in that state" answers; `capacity` stays a 503, which the control plane retries later.
fn status_of(e: &MError) -> (StatusCode, &'static str) {
    match e {
        MError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        MError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
        MError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        MError::NotRunning(_) => (StatusCode::CONFLICT, "not_running"),
        MError::BadState(_) => (StatusCode::CONFLICT, "bad_state"),
        MError::BootFailed(_) => (StatusCode::CONFLICT, "boot_failed"),
        MError::Capacity(_) => (StatusCode::SERVICE_UNAVAILABLE, "capacity"),
        MError::TenantInUse => (StatusCode::CONFLICT, "tenant_in_use"),
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
        let machine = match e {
            MError::BootFailed(m) => {
                // The image's fault, not an operator's: a warning.
                tracing::warn!(machine = m.id, err = %error, "boot failed");
                Some(m)
            }
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
        if !constant_eq(got.as_bytes(), expected.as_bytes()) {
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(api::ApiError {
                    error: "a bearer token is required".into(),
                    code: "unauthorized".into(),
                    request_id: request_id.clone(),
                    machine: None,
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

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
        st.mgr.metrics().await,
    )
        .into_response()
}

async fn status(State(st): S) -> Json<api::Status> {
    let (used, running, machines) = st.mgr.usage();
    Json(api::Status {
        version: env!("CARGO_PKG_VERSION").into(),
        host_id: st.mgr.host_id().into(),
        capacity: st.mgr.capacity(),
        used,
        machines,
        running,
        disk_free_mb: st.mgr.disk_free_mb().await,
    })
}

#[derive(Deserialize)]
struct ListQuery {
    tenant: Option<String>,
}

async fn list_machines(State(st): S, Query(q): Query<ListQuery>) -> Json<Vec<api::Machine>> {
    Json(st.mgr.list(q.tenant.as_deref()))
}

// Every transition runs through `detached`: axum drops a handler's future when the client
// hangs up, and a create, start, stop or destroy cut short would leave the machine half-moved.

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

async fn update_machine(
    State(st): S,
    Path(id): Path<String>,
    Json(req): Json<api::UpdateMachineRequest>,
) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(st.mgr.update(&id, req)?))
}

async fn destroy_machine(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.destroy(&id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_machine(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Machine>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(detached(async move { m.start(&id).await }).await?))
}

async fn wake_machine(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Machine>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(detached(async move { m.wake(&id).await }).await?))
}

async fn stop_machine(
    State(st): S,
    Path(id): Path<String>,
    body: Option<Json<api::StopRequest>>,
) -> Result<Json<api::Machine>, AppError> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move {
            m.stop(&id, stop_timeout(req.timeout_sec), req.suspend)
                .await
        })
        .await?,
    ))
}

async fn touch_machine(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    st.mgr.touch(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WaitQuery {
    timeout: Option<u64>,
}

async fn wait_machine(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(
        st.mgr.wait_running(&id, wait_timeout(q.timeout)).await?,
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
}

async fn logs(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<api::LogsResponse>, AppError> {
    Ok(Json(st.mgr.logs(
        &id,
        q.since.as_deref().unwrap_or(""),
        log_limit(q.limit),
    )?))
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

async fn stats(State(st): S, Path(id): Path<String>) -> Result<Json<api::MachineStats>, AppError> {
    Ok(Json(st.mgr.stats(&id).await?))
}

async fn snapshot(
    State(st): S,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<api::Snapshot>), AppError> {
    let m = st.mgr.clone();
    let s = detached(async move { m.snapshot(&id).await }).await?;
    Ok((StatusCode::CREATED, Json(s)))
}

async fn snapshots(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<Vec<api::Snapshot>>, AppError> {
    Ok(Json(st.mgr.snapshots(&id).await?))
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

async fn list_tenants(State(st): S) -> Json<Vec<api::Tenant>> {
    Json(st.mgr.tenants())
}

async fn delete_tenant(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_tenant(&id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[allow(dead_code)]
fn _body(_: Body) {}

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
