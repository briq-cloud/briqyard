//! Registers the daemon with a briqyard-fleet and keeps the registration fresh. The bearer is
//! the daemon's own API token: the one credential the host and the fleet share.

use crate::config::FleetClient;
use crate::machine::Manager;
use briqyard_api as api;
use std::time::Duration;

pub async fn run(cfg: FleetClient, api_token: String, mgr: Manager) {
    if api_token.is_empty() {
        tracing::error!("fleet.url is set but token is empty: a fleet accepts a heartbeat only with the host's own token");
        return;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");
    loop {
        let (used, _, total) = mgr.usage();
        let req = api::RegisterHostRequest {
            id: mgr.host_id().to_string(),
            url: cfg.advertise.clone(),
            region: cfg.region.clone(),
            capacity: mgr.capacity(),
            used,
            machines: total,
            tenants: mgr.tenants().into_iter().map(|t| t.id).collect(),
            version: env!("CARGO_PKG_VERSION").into(),
            disk_free_mb: mgr.disk_free_mb().await,
        };
        let r = client
            .post(format!(
                "{}/v1/hosts/register",
                cfg.url.trim_end_matches('/')
            ))
            .bearer_auth(&api_token)
            .json(&req);
        match r.send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                let status = resp.status().as_u16();
                let why = resp
                    .json::<api::ApiError>()
                    .await
                    .map(|e| e.error)
                    .unwrap_or_default();
                tracing::warn!(status, why, "fleet heartbeat refused");
            }
            Err(e) => tracing::warn!(err = %e, "fleet heartbeat"),
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}
