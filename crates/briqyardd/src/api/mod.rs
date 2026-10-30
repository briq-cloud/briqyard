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

mod auth;
mod backups;
mod endpoints;
mod errors;
mod exec;
mod images;
mod machines;
mod namespaces;
mod observe;
#[cfg(test)]
mod tests;

use auth::*;
use backups::*;
use endpoints::*;
use errors::*;
use exec::*;
use images::*;
use machines::*;
use namespaces::*;
use observe::*;

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
/// on a loopback listener; for `/metrics`, the metrics token or the API's (the fleet relays a
/// host's with the API token it holds, ADR 0054); else the API's.
#[derive(Debug, PartialEq)]
enum Bearer {
    None,
    Api,
    MetricsOrApi,
}

fn bearer_for(path: &str, loopback: bool) -> Bearer {
    match path {
        "/healthz" => Bearer::None,
        "/metrics" | "/v1/openapi.yaml" if loopback => Bearer::None,
        "/metrics" => Bearer::MetricsOrApi,
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
        .route("/v1/machines/:id/move", post(move_machine))
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
        .merge(namespace_routes("/v1/namespaces"))
        // The former name (ADR 0055), answered until the control plane has moved.
        .merge(namespace_routes("/v1/tenants"))
        .layer(middleware::from_fn_with_state(state.clone(), auth_and_log))
        .with_state(state)
}

/// The routes of a namespace, under `prefix`.
fn namespace_routes(prefix: &str) -> Router<Arc<AppState>> {
    Router::new()
        .route(prefix, get(list_namespaces))
        .route(
            &format!("{prefix}/:id"),
            get(get_namespace).delete(delete_namespace),
        )
        .route(
            &format!("{prefix}/:id/gateway"),
            put(set_gateway).delete(delete_gateway),
        )
        .route(
            &format!("{prefix}/:id/quota"),
            get(get_quota).put(set_quota),
        )
}
