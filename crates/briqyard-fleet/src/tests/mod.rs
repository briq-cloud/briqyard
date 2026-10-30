//! The HTTP handlers, driven in process through the router. Hosts are stub daemons on
//! loopback: they answer the few routes the fleet asks and record what was asked.

use super::*;
use axum::body::Body;
use chrono::TimeZone;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

struct Fleet {
    st: Arc<AppState>,
    _dir: tempfile::TempDir,
}

/// A fleet on a fresh state directory, with the hosts of the configuration seeded as `run` does.
fn fleet(cfg: config::Config) -> Fleet {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("registry.json");
    fleet_at(cfg, dir, state_path)
}

fn fleet_at(mut cfg: config::Config, dir: tempfile::TempDir, state_path: PathBuf) -> Fleet {
    cfg.state_dir = dir.path().to_path_buf();
    let backup = backup::Backup::open(&cfg.backup).unwrap();
    let mut reg = Registry::default();
    let now = Utc::now();
    for h in &cfg.hosts {
        reg.heartbeat(static_host(h, now), now);
    }
    let st = Arc::new(AppState {
        state_path,
        policy: Policy {
            fill_ceiling: cfg.placement.fill_ceiling,
            down_after: Duration::seconds(cfg.placement.down_after_sec as i64),
        },
        cfg,
        reg: Mutex::new(reg),
        // A stub daemon that never answers fails its test rather than holding it forever.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap(),
        pinned: Mutex::new(HashMap::new()),
        upgrade: Default::default(),
        backup,
        key_turn: Default::default(),
        list_timeout: LIST_TIMEOUT,
        restores: Default::default(),
        refusals: Default::default(),
        written: Default::default(),
    });
    Fleet { st, _dir: dir }
}

/// A ready host in the registry, with no daemon behind it.
fn seed(st: &AppState, id: &str, cap: u32, used: u32, machines: usize, namespaces: &[&str]) {
    let now = Utc::now();
    let mut h = static_host(
        &config::StaticHost {
            id: id.into(),
            url: format!("http://10.0.0.{}:7420", id.len()),
            ..Default::default()
        },
        now,
    );
    h.capacity = api::Capacity {
        memory_mb: cap,
        vcpus: 32,
        cpu_millis: Some(32_000),
    };
    h.used = api::Capacity {
        memory_mb: used,
        vcpus: 0,
        cpu_millis: None,
    };
    h.machines = machines;
    h.namespaces = namespaces.iter().map(|t| t.to_string()).collect();
    let mut reg = st.reg.lock().unwrap();
    reg.heartbeat(h, now);
}

fn set_state(st: &AppState, id: &str, state: &str) {
    st.reg.lock().unwrap().hosts.get_mut(id).unwrap().state = state.into();
}

/// A fleet in front of `n` stub daemons, polled once so their capacity is known.
async fn fleet_with_daemons(n: usize) -> (Fleet, Vec<Running>) {
    fleet_in_regions(&vec!["fsn"; n]).await
}

/// A fleet in front of a stub daemon in each region given, `d1` in the first.
async fn fleet_in_regions(regions: &[&str]) -> (Fleet, Vec<Running>) {
    let mut daemons = Vec::new();
    let mut cfg = config::Config {
        token: "api".into(),
        ..Default::default()
    };
    for (i, region) in (1..).zip(regions) {
        let d = start_daemon(&format!("d{i}"), &format!("tok-{i}")).await;
        cfg.hosts.push(config::StaticHost {
            id: format!("d{i}"),
            url: d.url.clone(),
            token: format!("tok-{i}"),
            region: region.to_string(),
            ..Default::default()
        });
        daemons.push(d);
    }
    let f = fleet(cfg);
    poll_static_hosts_once(&f.st).await;
    (f, daemons)
}

/// One request through the router. The body comes back as text.
/// A call as a client makes it. A host's own call (a body with a `url`) comes from that url's
/// address, as it does through a fleet that terminates its connections; anything else from
/// loopback.
async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    let peer = body
        .as_ref()
        .and_then(|b| b["url"].as_str())
        .and_then(|u| url_host(u).parse().ok())
        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
    call_from(st, peer, method, path, token, body).await
}

/// `call` from the peer address given.
async fn call_from(
    st: &Arc<AppState>,
    peer: std::net::IpAddr,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    call_with(st, peer, &[], method, path, token, body).await
}

/// `call_from` with request headers of its own (a proxy's `X-Forwarded-For`).
async fn call_with(
    st: &Arc<AppState>,
    peer: std::net::IpAddr,
    extra: &[(&str, &str)],
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::new(
            peer, 40000,
        )));
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    if !token.is_empty() {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = match body {
        Some(v) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&v).unwrap())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app(st.clone()).oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let data = axum::body::to_bytes(body, 64 << 20).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(data.to_vec()).unwrap(),
    )
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text:?}"))
}

fn hosts(st: &Arc<AppState>) -> Vec<api::Host> {
    let reg = st.reg.lock().unwrap();
    let mut v: Vec<api::Host> = reg.hosts.values().map(|h| h.to_api()).collect();
    v.sort_by(|a, b| a.id.cmp(&b.id));
    v
}

fn saved(st: &AppState) -> Registry {
    serde_json::from_slice(&std::fs::read(&st.state_path).unwrap()).unwrap()
}

fn pinned(st: &AppState, namespace: &str) -> Option<String> {
    st.reg.lock().unwrap().namespaces.get(namespace).cloned()
}

fn create_body(namespace: &str, name: &str, memory_mb: u32) -> serde_json::Value {
    serde_json::to_value(api::CreateMachineRequest {
        namespace: namespace.into(),
        name: name.into(),
        image: "nginx".into(),
        size: api::Size {
            vcpus: 1,
            memory_mb,
            cpu_millis: None,
        },
        ..Default::default()
    })
    .unwrap()
}

/// A daemon's heartbeat body for `url`.
fn heartbeat(url: &str, memory_mb: u32, namespaces: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "id": "h_daemon", "url": url, "region": "par",
        "capacity": {"memory_mb": memory_mb, "vcpus": 32, "cpu_millis": 32000}, "used": {"memory_mb": 512, "vcpus": 1},
        "machines": namespaces.len(), "namespaces": namespaces, "version": "0.1", "disk_free_mb": 5000
    })
}

mod admin;
mod backups;
mod daemon;
mod endpoints;
mod events;
mod files;
mod hosts;
mod join;
mod join_trust;
mod listings;
mod metrics;
mod placement;
mod regions;
mod sessions;
mod tls;

use daemon::*;

/// The next chunk of a stream, one line here, as JSON.
async fn chunk(w: &mut reqwest::Response) -> serde_json::Value {
    let c = tokio::time::timeout(std::time::Duration::from_secs(5), w.chunk())
        .await
        .expect("a line in time")
        .unwrap()
        .expect("open");
    json(std::str::from_utf8(&c).unwrap().trim())
}

/// A condition a daemon reports, true or not.
fn pressure(kind: &str, status: bool) -> api::Condition {
    api::Condition {
        kind: kind.into(),
        status,
        since: Utc::now(),
        message: "pool 4.0 GB free of 100.0 (4%), under 10%".into(),
    }
}

fn gateway_body() -> serde_json::Value {
    serde_json::json!({"image": "proxy:1", "port": 3128})
}

fn certificate() -> (rcgen::CertifiedKey, String) {
    let c = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let fp = api::tls::fingerprint(c.cert.der());
    (c, fp)
}
