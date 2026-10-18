//! briqyard-fleet: the briqyard API across several hosts. Each tenant lives on one host; the
//! fleet places new tenants, forwards every machine request to the right daemon, keeps the
//! registry of hosts from their heartbeats, and adds or releases hosts through a provisioner.

mod bootstrap;
mod config;
mod provision;
mod registry;

use anyhow::{anyhow, Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use briqyard_api as api;
use chrono::{Duration, Utc};
use clap::Parser;
use registry::{HostRec, Policy, Registry, ScalePolicy};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "briqyard-fleet", version, about = "briqyard across hosts")]
struct Args {
    #[arg(long, default_value = "/etc/briqyard/fleet.yaml")]
    config: PathBuf,
}

struct AppState {
    cfg: config::Config,
    reg: Mutex<Registry>,
    policy: Policy,
    http: reqwest::Client,
    state_path: PathBuf,
    prov: Box<dyn provision::Provisioner>,
}

impl AppState {
    fn save(&self) {
        let reg = self.reg.lock().unwrap().clone();
        if let Ok(data) = serde_json::to_vec_pretty(&reg) {
            let tmp = self.state_path.with_extension("json.tmp");
            if std::fs::write(&tmp, data).is_ok() {
                let _ = std::fs::rename(&tmp, &self.state_path);
            }
        }
    }
}

type S = State<Arc<AppState>>;

fn main() {
    let args = Args::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_env("BRIQYARD_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    if let Err(err) = rt.block_on(run(args)) {
        tracing::error!(err = format!("{err:#}"), "briqyard-fleet failed");
        std::process::exit(1);
    }
}

fn static_host(h: &config::StaticHost, now: chrono::DateTime<Utc>) -> HostRec {
    HostRec {
        id: if h.id.is_empty() {
            h.url.clone()
        } else {
            h.id.clone()
        },
        url: h.url.clone(),
        token: h.token.clone(),
        region: h.region.clone(),
        provider: "static".into(),
        provider_id: String::new(),
        state: "ready".into(),
        capacity: Default::default(),
        used: Default::default(),
        machines: 0,
        tenants: vec![],
        last_seen: now,
        version: String::new(),
        disk_free_mb: 0,
        empty_since: None,
        note: String::new(),
        bootstrap_attempts: 0,
    }
}

async fn run(args: Args) -> Result<()> {
    let path = if args.config.exists() {
        Some(args.config.as_path())
    } else if args.config.as_path() == std::path::Path::new("/etc/briqyard/fleet.yaml") {
        None
    } else {
        return Err(anyhow!("config {} not found", args.config.display()));
    };
    let cfg = config::Config::load(path)?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    let state_path = cfg.state_dir.join("registry.json");
    let mut reg: Registry = std::fs::read(&state_path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    let now = Utc::now();
    for h in &cfg.hosts {
        reg.heartbeat(static_host(h, now), now);
    }
    let policy = Policy {
        fill_ceiling: cfg.placement.fill_ceiling,
        down_after: Duration::seconds(cfg.placement.down_after_sec as i64),
    };
    let state = Arc::new(AppState {
        cfg: cfg.clone(),
        reg: Mutex::new(reg),
        policy,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(900))
            .build()?,
        state_path,
        prov: provision::build(&cfg.provisioner),
    });
    tokio::spawn(poll_static_hosts(state.clone()));
    tokio::spawn(scaler(state.clone()));
    tokio::spawn(bootstrap::run(state.clone()));
    let app = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/status", get(status))
        .route("/v1/hosts", get(list_hosts))
        .route("/v1/hosts/register", post(register_host))
        .route("/v1/hosts/order", post(order_host))
        .route("/v1/hosts/:id/drain", post(drain_host))
        .route("/v1/hosts/:id/retire", post(retire_host))
        .route("/v1/hosts/:id", axum::routing::delete(forget_host))
        .route("/v1/machines", get(list_machines).post(create_machine))
        .route("/v1/endpoints", get(list_endpoints))
        .route("/v1/tenants", get(list_tenants))
        .route("/v1/tenants/:id", axum::routing::delete(delete_tenant))
        .route("/v1/machines/:id", any(by_machine))
        .route("/v1/machines/:id/*rest", any(by_machine))
        .route("/v1/endpoints/:id", any(by_endpoint))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("listen {}", cfg.listen))?;
    tracing::info!(
        addr = cfg.listen,
        version = env!("CARGO_PKG_VERSION"),
        provisioner = cfg.provisioner.kind,
        dry_run = cfg.provisioner.dry_run,
        "briqyard-fleet listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(api::ApiError {
            error: msg.into(),
            code: code.into(),
            request_id: String::new(),
        }),
    )
        .into_response()
}

async fn auth(State(st): S, req: Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path().to_string();
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    let want = if path == "/v1/hosts/register" {
        &st.cfg.host_token
    } else {
        &st.cfg.token
    };
    if path != "/healthz" && !want.is_empty() && bearer != *want {
        return err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a bearer token is required",
        );
    }
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let resp = next.run(req).await;
    if path != "/healthz" && path != "/v1/hosts/register" {
        tracing::info!(%method, path, status = resp.status().as_u16(), ms = start.elapsed().as_millis() as u64, "request");
    }
    resp
}

// --- hosts ---

async fn status(State(st): S) -> Json<serde_json::Value> {
    let reg = st.reg.lock().unwrap();
    let mut cap = api::Capacity::default();
    let mut used = api::Capacity::default();
    let (mut machines, mut ready) = (0, 0);
    for h in reg.hosts.values() {
        if h.state == "ready" {
            ready += 1;
            cap.memory_mb += h.capacity.memory_mb;
            cap.vcpus += h.capacity.vcpus;
            used.memory_mb += h.used.memory_mb;
            used.vcpus += h.used.vcpus;
            machines += h.machines;
        }
    }
    // The daemon's Status, plus what only a fleet knows.
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"), "host_id": "fleet",
        "capacity": cap, "used": used, "machines": machines, "running": machines,
        "hosts": reg.hosts.len(), "ready": ready, "tenants": reg.tenants.len(),
        "provisioner": st.cfg.provisioner.kind, "dry_run": st.cfg.provisioner.dry_run,
    }))
}

async fn list_hosts(State(st): S) -> Json<Vec<api::Host>> {
    let reg = st.reg.lock().unwrap();
    let mut hosts: Vec<api::Host> = reg.hosts.values().map(|h| h.to_api()).collect();
    hosts.sort_by(|a, b| a.id.cmp(&b.id));
    Json(hosts)
}

async fn register_host(State(st): S, Json(req): Json<api::RegisterHostRequest>) -> StatusCode {
    let now = Utc::now();
    {
        let mut reg = st.reg.lock().unwrap();
        reg.heartbeat(
            HostRec {
                id: req.id,
                url: req.url,
                token: req.api_token,
                region: req.region,
                provider: String::new(),
                provider_id: String::new(),
                state: "ready".into(),
                capacity: req.capacity,
                used: req.used,
                machines: req.machines,
                tenants: req.tenants,
                last_seen: now,
                version: req.version,
                disk_free_mb: req.disk_free_mb,
                empty_since: None,
                note: String::new(),
                bootstrap_attempts: 0,
            },
            now,
        );
    }
    st.save();
    StatusCode::NO_CONTENT
}

async fn drain_host(State(st): S, Path(id): Path<String>) -> Response {
    let mut reg = st.reg.lock().unwrap();
    match reg.hosts.get_mut(&id) {
        Some(h) => {
            h.state = "draining".into();
            drop(reg);
            st.save();
            StatusCode::NO_CONTENT.into_response()
        }
        None => err(StatusCode::NOT_FOUND, "not_found", "host not found"),
    }
}

/// Orders a host from the provisioner now, whether or not the autoscaler is on.
async fn order_host(State(st): S, Json(req): Json<api::OrderHostRequest>) -> Response {
    let reason = if req.reason.is_empty() {
        "ordered through the API".to_string()
    } else {
        req.reason
    };
    let counted = st
        .reg
        .lock()
        .unwrap()
        .hosts
        .values()
        .filter(|h| h.state != "down")
        .count();
    if counted >= st.cfg.provisioner.max_hosts {
        return err(
            StatusCode::CONFLICT,
            "max_hosts",
            format!("the fleet has {counted} hosts, its maximum"),
        );
    }
    match st.prov.create(&reason).await {
        Ok(server) => {
            let h = add_ordered(&st, server);
            (StatusCode::ACCEPTED, Json(h.to_api())).into_response()
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, "provisioner", format!("{e:#}")),
    }
}

/// Records a server the provisioner just made.
fn add_ordered(st: &AppState, server: provision::Server) -> HostRec {
    let dry = st.cfg.provisioner.dry_run || server.provider_id.starts_with("dry-run-");
    tracing::warn!(
        provider = st.prov.name(),
        provider_id = server.provider_id,
        note = server.note,
        dry_run = dry,
        "host ordered"
    );
    let now = Utc::now();
    let id = format!("h_{}", server.provider_id.replace(['/', ':'], "-"));
    let h = HostRec {
        id: id.clone(),
        url: server
            .ip
            .map(|ip| format!("http://{ip}:7420"))
            .unwrap_or_default(),
        token: bootstrap::new_token(),
        region: String::new(),
        provider: st.prov.name().into(),
        provider_id: server.provider_id,
        state: if dry {
            "dry-run".into()
        } else {
            "provisioning".into()
        },
        capacity: Default::default(),
        used: Default::default(),
        machines: 0,
        tenants: vec![],
        last_seen: now,
        version: String::new(),
        disk_free_mb: 0,
        empty_since: Some(now),
        note: server.note,
        bootstrap_attempts: 0,
    };
    st.reg.lock().unwrap().hosts.insert(id, h.clone());
    st.save();
    h
}

/// Drains a host and releases it at the provider once nothing runs on it: at once when it is
/// already empty, else from the scaler as soon as it is.
async fn retire_host(State(st): S, Path(id): Path<String>) -> Response {
    let host = {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(&id) {
            Some(h) => {
                if h.state == "ready" || h.state == "down" {
                    h.state = "draining".into();
                }
                h.clone()
            }
            None => return err(StatusCode::NOT_FOUND, "not_found", "host not found"),
        }
    };
    st.save();
    let empty = host.machines == 0 && host.tenants.is_empty();
    if empty || !matches!(host.state.as_str(), "draining") {
        match release_host(&st, &host).await {
            Ok(h) => return Json(h).into_response(),
            Err(e) => return err(StatusCode::BAD_GATEWAY, "provisioner", format!("{e:#}")),
        }
    }
    tracing::info!(
        host = id,
        machines = host.machines,
        "host draining; released once empty"
    );
    Json(host.to_api()).into_response()
}

/// Releases a host at its provider (nothing to do for a static one) and forgets it.
async fn release_host(st: &AppState, h: &HostRec) -> Result<api::Host> {
    if !h.provider_id.is_empty() {
        st.prov.release(&h.provider_id).await?;
    }
    tracing::warn!(host = h.id, provider_id = h.provider_id, "host released");
    {
        let mut reg = st.reg.lock().unwrap();
        reg.hosts.remove(&h.id);
        reg.tenants.retain(|_, x| *x != h.id);
        reg.machines.retain(|_, x| *x != h.id);
    }
    st.save();
    let mut out = h.to_api();
    out.state = "released".into();
    Ok(out)
}

async fn forget_host(State(st): S, Path(id): Path<String>) -> StatusCode {
    let mut reg = st.reg.lock().unwrap();
    reg.hosts.remove(&id);
    reg.tenants.retain(|_, h| *h != id);
    reg.machines.retain(|_, h| *h != id);
    drop(reg);
    st.save();
    StatusCode::NO_CONTENT
}

async fn get_json<T: serde::de::DeserializeOwned>(
    st: &AppState,
    h: &HostRec,
    path: &str,
) -> Option<T> {
    let mut r = st
        .http
        .get(format!("{}{}", h.url.trim_end_matches('/'), path));
    if !h.token.is_empty() {
        r = r.bearer_auth(&h.token);
    }
    r.send().await.ok()?.json::<T>().await.ok()
}

/// Static hosts send no heartbeat of their own; the fleet asks them.
async fn poll_static_hosts(st: Arc<AppState>) {
    loop {
        // From the configuration, not the registry: a static host forgotten through the API
        // is back on the next poll; it leaves the fleet by leaving the configuration.
        let now = Utc::now();
        let hosts: Vec<HostRec> = st.cfg.hosts.iter().map(|h| static_host(h, now)).collect();
        let mut unseen = false;
        for h in hosts {
            if let Some(s) = get_json::<api::Status>(&st, &h, "/v1/status").await {
                let tenants: Vec<String> = get_json::<Vec<api::Tenant>>(&st, &h, "/v1/tenants")
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|t| t.id)
                    .collect();
                let now = Utc::now();
                let mut rec = h.clone();
                rec.capacity = s.capacity;
                rec.used = s.used;
                rec.machines = s.machines;
                rec.tenants = tenants;
                rec.version = s.version;
                rec.disk_free_mb = s.disk_free_mb;
                st.reg.lock().unwrap().heartbeat(rec, now);
            } else if h.capacity.memory_mb == 0 {
                // Never answered yet (it may be starting with us): ask again soon.
                unseen = true;
            }
        }
        st.reg.lock().unwrap().sweep(&st.policy, Utc::now());
        st.save();
        tokio::time::sleep(std::time::Duration::from_secs(if unseen { 2 } else { 15 })).await;
    }
}

// --- the autoscaler ---

/// Every minute: releases the drained hosts that have emptied, and, when the autoscaler is
/// on, adds a host when no slot is left or releases one idle past the grace.
async fn scaler(st: Arc<AppState>) {
    let p = &st.cfg.provisioner;
    let idle = api::parse_sleep(&p.idle_grace)
        .ok()
        .flatten()
        .unwrap_or(std::time::Duration::from_secs(7200));
    let scale = ScalePolicy {
        min_hosts: p.min_hosts,
        max_hosts: p.max_hosts,
        slot_mb: p.slot_mb,
        idle_grace: Duration::from_std(idle).unwrap_or(Duration::hours(2)),
    };
    if p.enabled {
        tracing::info!(
            provisioner = st.prov.name(),
            dry_run = p.dry_run,
            min = scale.min_hosts,
            max = scale.max_hosts,
            "autoscaler on"
        );
    } else {
        tracing::info!("autoscaler off (provisioner.enabled: false); hosts are ordered and retired through the API");
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let retirable = st.reg.lock().unwrap().retirable();
        for h in retirable {
            if let Err(e) = release_host(&st, &h).await {
                tracing::error!(host = h.id, err = %e, "release a drained host");
            }
        }
        if !p.enabled {
            continue;
        }
        let decision = {
            let reg = st.reg.lock().unwrap();
            registry::decide(&reg, &st.policy, &scale, Utc::now())
        };
        match decision {
            registry::Decision::Nothing => {}
            registry::Decision::AddHost => match st.prov.create("the fleet has no slot left").await
            {
                Ok(server) => {
                    add_ordered(&st, server);
                }
                Err(e) => tracing::error!(err = %e, "add host"),
            },
            registry::Decision::ReleaseHost(id) => {
                let host = st.reg.lock().unwrap().hosts.get(&id).cloned();
                if let Some(h) = host {
                    if let Err(e) = release_host(&st, &h).await {
                        tracing::error!(host = id, err = %e, "release host");
                    }
                }
            }
        }
    }
}

// --- the machine API, forwarded ---

async fn forward(
    st: &AppState,
    host: &HostRec,
    method: Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let url = format!("{}{}", host.url.trim_end_matches('/'), path);
    let mut req = st.http.request(method, &url).body(body);
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        req = req.header(header::CONTENT_TYPE, ct);
    }
    if !host.token.is_empty() {
        req = req.bearer_auth(&host.token);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
            let rid = resp.headers().get("x-request-id").cloned();
            let data = resp.bytes().await.unwrap_or_default();
            let mut out = Response::new(Body::from(data));
            *out.status_mut() = status;
            if let Some(ct) = ct {
                out.headers_mut().insert(header::CONTENT_TYPE, ct);
            }
            if let Some(rid) = rid {
                out.headers_mut().insert("x-request-id", rid);
            }
            out.headers_mut().insert(
                "x-briqyard-host",
                HeaderValue::from_str(&host.id).unwrap_or(HeaderValue::from_static("?")),
            );
            out
        }
        Err(e) => err(
            StatusCode::BAD_GATEWAY,
            "host_unreachable",
            format!("host {}: {e}", host.id),
        ),
    }
}

/// Adds the host id to a machine JSON body.
fn with_host(body: Bytes, host: &str) -> Bytes {
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut v) if v.is_object() => {
            v["host"] = serde_json::Value::String(host.into());
            Bytes::from(serde_json::to_vec(&v).unwrap_or_default())
        }
        _ => body,
    }
}

async fn create_machine(State(st): S, headers: HeaderMap, body: Bytes) -> Response {
    let req: api::CreateMachineRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")),
    };
    let host = {
        let mut reg = st.reg.lock().unwrap();
        let chosen = match &req.fork {
            Some(f) => reg.host_of_machine(&f.machine_id).map(|h| h.id.clone()),
            None => None,
        }
        .or_else(|| {
            // Root disks are thin; a volume takes what it says, plus headroom.
            let disk = req
                .volume
                .as_ref()
                .map(|v| v.size_gb as u64 * 1024)
                .unwrap_or(0)
                + 2048;
            reg.place(&req.tenant, req.size.memory_mb, disk, &st.policy)
        });
        chosen.and_then(|id| reg.hosts.get(&id).cloned())
    };
    let host = match host {
        Some(h) => h,
        None => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity",
                "no host has room for this machine",
            )
        }
    };
    st.save();
    let resp = forward(&st, &host, Method::POST, "/v1/machines", &headers, body).await;
    if resp.status().is_success() {
        let (parts, body) = resp.into_parts();
        let data = axum::body::to_bytes(body, 16 << 20)
            .await
            .unwrap_or_default();
        if let Ok(m) = serde_json::from_slice::<api::Machine>(&data) {
            st.reg
                .lock()
                .unwrap()
                .machines
                .insert(m.id, host.id.clone());
            st.save();
        }
        return Response::from_parts(parts, Body::from(with_host(data, &host.id)));
    }
    resp
}

async fn list_machines(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let hosts = st.reg.lock().unwrap().ready();
    let mut all: Vec<serde_json::Value> = Vec::new();
    let path = match uri.query() {
        Some(q) => format!("/v1/machines?{q}"),
        None => "/v1/machines".into(),
    };
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            continue;
        }
        let data = axum::body::to_bytes(resp.into_body(), 64 << 20)
            .await
            .unwrap_or_default();
        if let Ok(ms) = serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
            let mut reg = st.reg.lock().unwrap();
            for mut m in ms {
                if let Some(id) = m["id"].as_str() {
                    reg.machines.insert(id.to_string(), h.id.clone());
                }
                m["host"] = serde_json::Value::String(h.id.clone());
                all.push(m);
            }
        }
    }
    Json(all).into_response()
}

async fn list_endpoints(State(st): S, headers: HeaderMap) -> Response {
    let hosts = st.reg.lock().unwrap().ready();
    let mut all: Vec<serde_json::Value> = Vec::new();
    for h in hosts {
        let resp = forward(
            &st,
            &h,
            Method::GET,
            "/v1/endpoints",
            &headers,
            Bytes::new(),
        )
        .await;
        if let Ok(data) = axum::body::to_bytes(resp.into_body(), 64 << 20).await {
            if let Ok(eps) = serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
                all.extend(eps);
            }
        }
    }
    Json(all).into_response()
}

async fn list_tenants(State(st): S) -> Json<Vec<api::Tenant>> {
    let reg = st.reg.lock().unwrap();
    let mut out: Vec<api::Tenant> = reg
        .tenants
        .iter()
        .map(|(t, h)| api::Tenant {
            id: t.clone(),
            subnet: String::new(),
            gateway: String::new(),
            machines: 0,
            created_at: Utc::now(),
            host: h.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Json(out)
}

async fn delete_tenant(State(st): S, Path(id): Path<String>, headers: HeaderMap) -> Response {
    let host = st.reg.lock().unwrap().host_of_tenant(&id).cloned();
    let host = match host {
        Some(h) => h,
        None => return StatusCode::NO_CONTENT.into_response(),
    };
    let resp = forward(
        &st,
        &host,
        Method::DELETE,
        &format!("/v1/tenants/{id}"),
        &headers,
        Bytes::new(),
    )
    .await;
    if resp.status().is_success() {
        st.reg.lock().unwrap().tenants.remove(&id);
        st.save();
    }
    resp
}

/// Finds the host of a machine: from the index, else by asking every host.
async fn locate_machine(st: &AppState, id: &str, headers: &HeaderMap) -> Option<HostRec> {
    if let Some(h) = st.reg.lock().unwrap().host_of_machine(id).cloned() {
        return Some(h);
    }
    let hosts = st.reg.lock().unwrap().ready();
    for h in hosts {
        let resp = forward(
            st,
            &h,
            Method::GET,
            &format!("/v1/machines/{id}"),
            headers,
            Bytes::new(),
        )
        .await;
        if resp.status().is_success() {
            st.reg
                .lock()
                .unwrap()
                .machines
                .insert(id.to_string(), h.id.clone());
            return Some(h);
        }
    }
    None
}

async fn by_machine(
    State(st): S,
    Path(params): Path<Vec<(String, String)>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let id = params
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let host = match locate_machine(&st, &id, &headers).await {
        Some(h) => h,
        None => return err(StatusCode::NOT_FOUND, "not_found", "machine not found"),
    };
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let is_delete = method == Method::DELETE && path == format!("/v1/machines/{id}");
    let plain_get = method == Method::GET && path == format!("/v1/machines/{id}");
    let resp = forward(&st, &host, method, &path, &headers, body).await;
    if is_delete && resp.status().is_success() {
        st.reg.lock().unwrap().machines.remove(&id);
        st.save();
    }
    if plain_get && resp.status().is_success() {
        let (parts, body) = resp.into_parts();
        let data = axum::body::to_bytes(body, 16 << 20)
            .await
            .unwrap_or_default();
        return Response::from_parts(parts, Body::from(with_host(data, &host.id)));
    }
    resp
}

async fn by_endpoint(
    State(st): S,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let hosts = st.reg.lock().unwrap().ready();
    for h in hosts {
        let resp = forward(&st, &h, method.clone(), &path, &headers, body.clone()).await;
        if resp.status() != StatusCode::NOT_FOUND {
            return resp;
        }
    }
    err(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("endpoint {id} not found"),
    )
}
