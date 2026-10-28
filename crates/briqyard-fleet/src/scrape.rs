//! What a Prometheus beside the fleet scrapes (ADR 0048): every host's `/metrics` relayed by
//! the fleet over the host's pinned TLS with the host's token, and the list of targets in
//! Prometheus's HTTP service discovery format, so hosts added or retired come and go without
//! an edit to its configuration.

use crate::{down, err, relay, to_host, unreachable_host, AppState};
use axum::extract::{Host, Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// A host answers its `/metrics` from memory (ADR 0021): a scrape that takes longer is a host
/// in trouble, said before Prometheus's own deadline (10 s by default) runs out.
const METRICS_TIMEOUT: Duration = Duration::from_secs(5);

/// The paths a scraper reads: the fleet's `/metrics`, the targets, a host's relayed metrics.
pub fn is_metrics(path: &str) -> bool {
    match path
        .strip_prefix("/v1/hosts/")
        .and_then(|rest| rest.strip_suffix("/metrics"))
    {
        Some(id) => !id.is_empty() && !id.contains('/'),
        None => path == "/metrics" || path == "/v1/metrics/targets",
    }
}

/// `GET /v1/hosts/{id}/metrics`: the host's own text as it is, through the client of its pinned
/// certificate and with its token, as every forwarded call. A down host is 503 `host_down`, one
/// that does not answer 502 `host_unreachable`: to Prometheus, `up == 0` either way.
pub async fn host_metrics(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(host) = st.reg.lock().unwrap().hosts.get(&id).cloned() else {
        return err(StatusCode::NOT_FOUND, "not_found", format!("no host {id}")).into_response();
    };
    if let Some(refused) = down(&host) {
        return refused;
    }
    let req = match to_host(&st, &host, Method::GET, "/metrics", &HeaderMap::new()) {
        Ok(r) => r.timeout(METRICS_TIMEOUT),
        Err(refused) => return refused.into_response(),
    };
    match req.send().await {
        Ok(resp) => relay(resp, &host).await,
        Err(e) => unreachable_host(&host, e),
    }
}

/// `GET /v1/metrics/targets`: the fleet's own `/metrics`, then one target per host that may run
/// a daemon (`Registry::listed`: a down host stays, so it is scraped as down), each through the
/// relay. Every target is at the address the caller reached the fleet at (`Host`): loopback
/// beside it, the proxy's name behind one. Labels are what does not change with a host's state
/// (`briqyard_fleet_host_state` says that): `instance` and `host` its id, `region`.
pub async fn targets(State(st): State<Arc<AppState>>, host: Option<Host>) -> Response {
    let Some(Host(addr)) = host else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "no Host header: the targets are at the address the fleet was reached at",
        )
        .into_response();
    };
    let mut out = vec![json!({ "targets": [addr], "labels": { "instance": "fleet" } })];
    for h in st.reg.lock().unwrap().listed() {
        out.push(json!({
            "targets": [addr],
            "labels": {
                "__metrics_path__": format!("/v1/hosts/{}/metrics", h.id),
                "instance": h.id,
                "host": h.id,
                "region": h.region,
            },
        }));
    }
    Json(out).into_response()
}

#[cfg(test)]
mod tests {
    use super::is_metrics;

    #[test]
    fn the_scrapers_paths() {
        for p in ["/metrics", "/v1/metrics/targets", "/v1/hosts/fc2/metrics"] {
            assert!(is_metrics(p), "{p}");
        }
        for p in [
            "/v1/hosts//metrics",
            "/v1/hosts/a/b/metrics",
            "/v1/hosts/fc2",
            "/v1/status",
            "/v1/machines/m_1/metrics",
        ] {
            assert!(!is_metrics(p), "{p}");
        }
    }
}
