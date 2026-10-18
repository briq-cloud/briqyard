//! The HTTP API over the machine manager.

use crate::machine::{MError, Manager};
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
    pub openapi: &'static str,
}

type S = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/openapi.yaml", get(openapi))
        .route("/v1/status", get(status))
        .route("/v1/machines", get(list_machines).post(create_machine))
        .route("/v1/machines/:id", get(get_machine).delete(destroy_machine))
        .route("/v1/machines/:id/start", post(start_machine))
        .route("/v1/machines/:id/wake", post(wake_machine))
        .route("/v1/machines/:id/stop", post(stop_machine))
        .route("/v1/machines/:id/touch", post(touch_machine))
        .route("/v1/machines/:id/wait", post(wait_machine))
        .route("/v1/machines/:id/exec", post(exec))
        .route("/v1/machines/:id/files", get(get_file).put(put_file))
        .route("/v1/machines/:id/logs", get(logs))
        .route("/v1/machines/:id/snapshots", get(snapshots).post(snapshot))
        .route("/v1/machines/:id/endpoints", post(create_endpoint))
        .route("/v1/endpoints", get(list_endpoints))
        .route(
            "/v1/endpoints/:id",
            get(get_endpoint).delete(delete_endpoint),
        )
        .route("/v1/tenants", get(list_tenants))
        .route("/v1/tenants/:id", axum::routing::delete(delete_tenant))
        .layer(middleware::from_fn_with_state(state.clone(), auth_and_log))
        .with_state(state)
}

/// Every error response's body, with the status it maps to.
pub struct AppError(StatusCode, &'static str, String, String);

impl From<MError> for AppError {
    fn from(e: MError) -> Self {
        let (status, code) = match &e {
            MError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            MError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
            MError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            MError::NotRunning(_) => (StatusCode::CONFLICT, "not_running"),
            MError::BadState(_) => (StatusCode::CONFLICT, "bad_state"),
            MError::Capacity(_) => (StatusCode::SERVICE_UNAVAILABLE, "capacity"),
            MError::TenantInUse => (StatusCode::CONFLICT, "tenant_in_use"),
            MError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let msg = match &e {
            MError::Other(err) => format!("{err:#}"),
            other => other.to_string(),
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(err = %msg, "request failed");
        }
        AppError(status, code, msg, String::new())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut resp = (
            self.0,
            Json(api::ApiError {
                error: self.2,
                code: self.1.into(),
                request_id: self.3,
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
    if !st.token.is_empty() && path != "/healthz" {
        let got = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !constant_eq(got.as_bytes(), st.token.as_bytes()) {
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(api::ApiError {
                    error: "a bearer token is required".into(),
                    code: "unauthorized".into(),
                    request_id: request_id.clone(),
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

async fn status(State(st): S) -> Json<api::Status> {
    let (used, running, machines) = st.mgr.usage();
    Json(api::Status {
        version: env!("CARGO_PKG_VERSION").into(),
        host_id: st.mgr.host_id().into(),
        capacity: st.mgr.capacity(),
        used,
        machines,
        running,
    })
}

#[derive(Deserialize)]
struct ListQuery {
    tenant: Option<String>,
}

async fn list_machines(State(st): S, Query(q): Query<ListQuery>) -> Json<Vec<api::Machine>> {
    Json(st.mgr.list(q.tenant.as_deref()))
}

async fn create_machine(
    State(st): S,
    Json(req): Json<api::CreateMachineRequest>,
) -> Result<(StatusCode, Json<api::Machine>), AppError> {
    Ok((StatusCode::CREATED, Json(st.mgr.create(req).await?)))
}

async fn get_machine(State(st): S, Path(id): Path<String>) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(st.mgr.get(&id)?))
}

async fn destroy_machine(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    st.mgr.destroy(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_machine(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(st.mgr.start(&id).await?))
}

async fn wake_machine(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(st.mgr.wake(&id).await?))
}

async fn stop_machine(
    State(st): S,
    Path(id): Path<String>,
    body: Option<Json<api::StopRequest>>,
) -> Result<Json<api::Machine>, AppError> {
    let req = body.map(|b| b.0).unwrap_or_default();
    Ok(Json(
        st.mgr
            .stop(&id, Duration::from_secs(req.timeout_sec), req.suspend)
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
    let timeout = Duration::from_secs(q.timeout.unwrap_or(60).clamp(1, 600));
    Ok(Json(st.mgr.wait_running(&id, timeout).await?))
}

async fn exec(
    State(st): S,
    Path(id): Path<String>,
    Json(req): Json<api::ExecRequest>,
) -> Result<Json<api::ExecResult>, AppError> {
    if req.cmd.is_empty() {
        return Err(MError::Invalid("cmd is required".into()).into());
    }
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
        q.limit.unwrap_or(0),
    )?))
}

async fn snapshot(
    State(st): S,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<api::Snapshot>), AppError> {
    Ok((StatusCode::CREATED, Json(st.mgr.snapshot(&id).await?)))
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

async fn list_tenants(State(st): S) -> Json<Vec<api::Tenant>> {
    Json(st.mgr.tenants())
}

async fn delete_tenant(State(st): S, Path(id): Path<String>) -> Result<StatusCode, AppError> {
    st.mgr.delete_tenant(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[allow(dead_code)]
fn _body(_: Body) {}
