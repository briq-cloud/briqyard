//! Registers the daemon with a briqyard-fleet and keeps the registration fresh.

use crate::config::FleetClient;
use crate::machine::Manager;
use briqyard_api as api;
use std::time::Duration;

pub async fn run(cfg: FleetClient, mgr: Manager) {
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
        let mut r = client
            .post(format!(
                "{}/v1/hosts/register",
                cfg.url.trim_end_matches('/')
            ))
            .json(&req);
        if !cfg.token.is_empty() {
            r = r.bearer_auth(&cfg.token);
        }
        match r.send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => tracing::warn!(status = resp.status().as_u16(), "fleet heartbeat refused"),
            Err(e) => tracing::warn!(err = %e, "fleet heartbeat"),
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}
