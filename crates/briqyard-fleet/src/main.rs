//! briqyard-fleet: the briqyard API across several hosts. Each tenant lives on one host; the
//! fleet places new tenants, forwards every machine request to the right daemon, keeps the
//! registry of hosts from their heartbeats, and adds or releases hosts through a provisioner.

mod backup;
mod bootstrap;
mod config;
mod provision;
mod registry;

use anyhow::{anyhow, Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, put};
use axum::{Json, Router};
use briqyard_api as api;
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use registry::{url_host, HostRec, Policy, Registry, ScalePolicy};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "briqyard-fleet", version, about = "briqyard across hosts")]
struct Args {
    #[arg(long, default_value = "/etc/briqyard/fleet.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make an age identity for the registry's backup (ADR 0032): written to OUT (0600), its
    /// recipient printed, for `backup.recipient`. Keep OUT off the fleet's host.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the registry from its backup in `backup.store`, decrypted with the identity, when
    /// the fleet has none (stop it first). Never over an existing registry.
    Restore {
        /// The age identity file of `backup.recipient`.
        #[arg(long)]
        identity: PathBuf,
        /// The object to restore: the newest, or a day's (`fleet/registry-2026-10-21.json.age`).
        #[arg(long, default_value = backup::LATEST)]
        from: String,
    },
}

struct AppState {
    cfg: config::Config,
    reg: Mutex<Registry>,
    policy: Policy,
    /// The client to hosts on plain HTTP.
    http: reqwest::Client,
    /// A client per pinned certificate (fingerprint → client), each accepting that one
    /// certificate and nothing else (ADR 0020).
    pinned: Mutex<HashMap<String, reqwest::Client>>,
    state_path: PathBuf,
    prov: Box<dyn provision::Provisioner>,
    /// The registry's backup, when `backup.store` is set (ADR 0032).
    backup: Option<backup::Backup>,
}

/// Writes a registry file, the fleet's alone (`0600`: it holds every host's token and pool
/// key): a temp file made afresh, synced, renamed over the old one, the directory synced.
fn write_registry(path: &std::path::Path, reg: &Registry) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("json.tmp");
    // A leftover keeps its own mode through `open`: made afresh, it is 0600.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&backup::encode(reg))?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    // The rename itself reaches the disk with the directory.
    std::fs::File::open(path.parent().unwrap_or(std::path::Path::new(".")))?.sync_all()
}

/// A host that does not even accept the connection is given five seconds. No deadline for
/// the whole call here: each call sets its own (`FORWARD_TIMEOUT`), a watch none.
fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(5))
}

impl AppState {
    /// The client for a host: the one of its pinned certificate, or the plain one when it has
    /// none. A pinned client speaks https only, so a pin never goes out in clear.
    fn client(&self, h: &HostRec) -> reqwest::Result<reqwest::Client> {
        if h.tls_fingerprint.is_empty() {
            return Ok(self.http.clone());
        }
        let mut pinned = self.pinned.lock().unwrap();
        if let Some(c) = pinned.get(&h.tls_fingerprint) {
            return Ok(c.clone());
        }
        let c = client_builder()
            .use_preconfigured_tls(api::tls::pinned_client(&h.tls_fingerprint))
            .https_only(true)
            .build()?;
        pinned.insert(h.tls_fingerprint.clone(), c.clone());
        Ok(c)
    }

    /// Writes the registry. A failure is logged at `error` and returned: a request answers
    /// 500 with it, a background task has nothing more to do with it.
    fn save(&self) -> Result<()> {
        let reg = self.reg.lock().unwrap().clone();
        let written = write_registry(&self.state_path, &reg);
        if let Err(e) = &written {
            tracing::error!(path = %self.state_path.display(), err = %e, "write the registry");
        }
        written.with_context(|| format!("write registry {}", self.state_path.display()))
    }
}

type S = State<Arc<AppState>>;

/// A forwarded call may legitimately run for minutes (an exec, a create pulling an image);
/// a watch has no end and is not given one.
const FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

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
        tls_fingerprint: h.tls_fingerprint.clone(),
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
        conditions: vec![],
        pool_key: Default::default(),
        unknown: Default::default(),
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
    let state_path = cfg.state_dir.join("registry.json");
    match args.cmd {
        Some(Cmd::Keygen { out }) => {
            println!("{}", backup::keygen(&out)?);
            return Ok(());
        }
        Some(Cmd::Restore { identity, from }) => {
            return restore(&cfg, &state_path, &identity, &from).await
        }
        None => {}
    }
    // The registry holds every host's token and pool key: the fleet's alone.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&cfg.state_dir)?;
        std::fs::set_permissions(&cfg.state_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("mode of {}", cfg.state_dir.display()))?;
    }
    let mut reg = Registry::load(&state_path)?;
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
        // A host that does not even accept the connection is given five seconds; each call
        // has its own deadline (`FORWARD_TIMEOUT`, none for a watch).
        http: client_builder().build()?,
        pinned: Mutex::new(HashMap::new()),
        state_path,
        prov: provision::build(&cfg.provisioner),
        backup: backup::Backup::open(&cfg.backup)?,
    });
    tokio::spawn(backup::run(state.clone()));
    tokio::spawn(poll_static_hosts(state.clone()));
    tokio::spawn(scaler(state.clone()));
    tokio::spawn(bootstrap::run(state.clone()));
    // The peer address is what a host's own calls are checked against (`the_host`).
    let app = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let listener = std::net::TcpListener::bind(&cfg.listen)
        .with_context(|| format!("listen {}", cfg.listen))?;
    listener.set_nonblocking(true)?;
    tracing::info!(
        addr = cfg.listen,
        tls = matches!(cfg.tls, config::Tls::Files { .. }),
        version = env!("CARGO_PKG_VERSION"),
        provisioner = cfg.provisioner.kind,
        dry_run = cfg.provisioner.dry_run,
        "briqyard-fleet listening"
    );
    match &cfg.tls {
        config::Tls::Files { cert, key } => {
            let read = |p: &PathBuf| {
                std::fs::read(p).with_context(|| format!("tls: read {}", p.display()))
            };
            let server = api::tls::server_config(&read(cert)?, &read(key)?)
                .with_context(|| format!("tls: {} and {}", cert.display(), key.display()))?;
            let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server));
            axum_server::from_tcp_rustls(listener, config)
                .serve(app)
                .await?
        }
        config::Tls::Unset | config::Tls::Off => axum_server::from_tcp(listener).serve(app).await?,
    }
    Ok(())
}

/// `briqyard-fleet restore`: the registry from its backup, written where the fleet keeps it,
/// only when there is none: a restore never replaces what a fleet wrote.
async fn restore(
    cfg: &config::Config,
    state_path: &std::path::Path,
    identity: &std::path::Path,
    from: &str,
) -> Result<()> {
    let Some(b) = backup::Backup::open(&cfg.backup)? else {
        return Err(anyhow!(
            "backup.store is not set: there is nothing to restore from"
        ));
    };
    if state_path.exists() {
        return Err(anyhow!(
            "{} exists: stop the fleet and move it aside first; a restore never writes over a registry",
            state_path.display()
        ));
    }
    let reg = b.fetch(from, &backup::identity(identity)?).await?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    write_registry(state_path, &reg).with_context(|| format!("write {}", state_path.display()))?;
    print!(
        "{}",
        restored(&reg, &format!("{} {from}", b.describe()), state_path)
    );
    Ok(())
}

/// What a restore wrote, for the operator to check before starting the fleet on it: the
/// fleet will trust each host by this address, token and pin.
fn restored(reg: &Registry, from: &str, path: &std::path::Path) -> String {
    let keys = reg
        .hosts
        .values()
        .filter(|h| !h.pool_key.is_empty())
        .count();
    let mut out = format!(
        "restored {} hosts ({keys} pool keys) and {} tenants from {from} into {}\n",
        reg.hosts.len(),
        reg.tenants.len(),
        path.display()
    );
    if let Some(newest) = reg.hosts.values().map(|h| h.last_seen).max() {
        out += &format!("newest heartbeat in it: {}\n", newest.to_rfc3339());
    }
    out += "the fleet will trust, once started:\n";
    let mut hosts: Vec<&HostRec> = reg.hosts.values().collect();
    hosts.sort_by(|a, b| a.id.cmp(&b.id));
    for h in hosts {
        let pin = if h.tls_fingerprint.is_empty() {
            "no pin".to_string()
        } else {
            format!(
                "pin {}…",
                &h.tls_fingerprint[..h.tls_fingerprint.len().min(16)]
            )
        };
        out += &format!(
            "  {}  {}  {pin}  {}  {}\n",
            h.id,
            h.url,
            if h.token.is_empty() {
                "no token"
            } else {
                "token"
            },
            if h.pool_key.is_empty() {
                "no pool key"
            } else {
                "pool key"
            }
        );
    }
    out
}

/// The HTTP API: every route, behind the bearer check.
fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/status", get(status))
        .route("/v1/hosts", get(list_hosts))
        .route("/v1/hosts/register", post(register_host))
        .route("/v1/hosts/key", post(host_key))
        .route("/v1/hosts/order", post(order_host))
        .route("/v1/hosts/:id/drain", post(drain_host))
        .route("/v1/hosts/:id/retire", post(retire_host))
        .route("/v1/hosts/:id", axum::routing::delete(forget_host))
        .route("/v1/machines", get(list_machines).post(create_machine))
        .route("/v1/endpoints", get(list_endpoints))
        .route("/v1/usage", get(usage))
        .route("/v1/backups", get(all_backups))
        .route("/v1/top", get(top))
        .route("/v1/events", get(events))
        .route("/v1/tenants", get(list_tenants))
        .route("/v1/tenants/:id", get(get_tenant).delete(delete_tenant))
        .route(
            "/v1/tenants/:id/gateway",
            put(set_gateway).delete(delete_gateway),
        )
        .route("/v1/tenants/:id/quota", get(get_quota).put(set_quota))
        .route("/v1/tenants/:id/unpin", post(unpin_tenant))
        .route("/v1/machines/:id", any(by_machine))
        // Backups live in a store every host shares: the listing goes to any host, even for
        // a machine that no longer exists anywhere; making one goes to the machine's host.
        .route(
            "/v1/machines/:id/backups",
            get(list_backups).post(by_machine),
        )
        .route("/v1/machines/:id/*rest", any(by_machine))
        .route("/v1/endpoints/:id", any(by_endpoint))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state)
}

/// An error the fleet answers itself; the daemon's `ApiError` body.
struct Refusal {
    status: StatusCode,
    code: &'static str,
    error: String,
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(api::ApiError {
                error: self.error,
                code: self.code.into(),
                request_id: String::new(),
                machine: None,
                oldest: None,
            }),
        )
            .into_response()
    }
}

fn err(status: StatusCode, code: &'static str, msg: impl Into<String>) -> Refusal {
    Refusal {
        status,
        code,
        error: msg.into(),
    }
}

/// The 500 a request answers when the registry could not be written.
fn registry_error(e: anyhow::Error) -> Refusal {
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "registry",
        format!("{e:#}"),
    )
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

async fn auth(State(st): S, req: Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path().to_string();
    // A heartbeat and a key request present the host's own token, checked against its record
    // by the handler.
    let open = path == "/healthz" || path == "/v1/hosts/register" || path == "/v1/hosts/key";
    if !open
        && !st.cfg.token.is_empty()
        && !api::constant_eq(bearer(req.headers()).as_bytes(), st.cfg.token.as_bytes())
    {
        return err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a bearer token is required",
        )
        .into_response();
    }
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let resp = next.run(req).await;
    if !open {
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

/// Who made a host's call, as the fleet sees it: the connection's peer, and whether the fleet
/// terminates the connection itself (its own TLS, or plain on loopback) so that the peer is the
/// host's. Behind `tls: off` the peer is whatever is in front, so it proves nothing.
#[derive(Clone, Copy, Debug)]
struct Caller {
    peer: Option<std::net::IpAddr>,
    checked: bool,
}

impl Caller {
    fn of(st: &AppState, info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>) -> Caller {
        Caller {
            peer: info.map(|i| i.0.ip().to_canonical()),
            checked: !matches!(st.cfg.tls, config::Tls::Off),
        }
    }
}

/// The record a host's own call belongs to: the one host at the address it advertises, when
/// the call presents that host's token and, where the fleet terminates the connection, comes
/// from that address (ADR 0026: a token on a disk that left our hands is not enough). Nothing
/// else passes, so no host can speak for another. `call` names the call for the log.
fn the_host<'a>(
    reg: &'a Registry,
    url: &str,
    headers: &HeaderMap,
    caller: Caller,
    call: &str,
) -> Result<&'a HostRec, Refusal> {
    let Some(rec) = reg.expecting(url) else {
        tracing::warn!(
            call,
            url,
            "host call refused: no host expected at this address"
        );
        return Err(err(
            StatusCode::FORBIDDEN,
            "unknown_host",
            format!(
                "no host is expected at {}: order one, or list it under hosts: with its token",
                url_host(url)
            ),
        ));
    };
    if rec.token.is_empty() || !api::constant_eq(bearer(headers).as_bytes(), rec.token.as_bytes()) {
        tracing::warn!(
            host = rec.id,
            call,
            "host call refused: not the host's token"
        );
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "the host's own token is required",
        ));
    }
    if caller.checked {
        let want = url_host(&rec.url)
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
        if want.is_none() || want != caller.peer {
            let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
            tracing::warn!(
                host = rec.id,
                call,
                peer,
                "host call refused: not from the host's address"
            );
            return Err(err(
                StatusCode::FORBIDDEN,
                "unknown_host",
                match want {
                    None => format!(
                        "host {} is known by the name in {}: the fleet checks a host's calls by its address, so its url must be one",
                        rec.id, rec.url
                    ),
                    Some(want) => format!(
                        "host {}'s calls come from {want}, not {}",
                        rec.id,
                        if peer.is_empty() { "an unknown address" } else { &peer }
                    ),
                },
            ));
        }
    }
    Ok(rec)
}

/// A host's pool key (ADR 0026), for the host alone: asked by its bootstrap to create the
/// pool, and by its daemon at a start that finds the key not loaded. Made at the first ask
/// and written to the registry before it is answered.
async fn host_key(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<api::HostKeyRequest>,
) -> Result<Response, Refusal> {
    let caller = Caller::of(&st, info);
    let (id, key, made) = {
        let mut reg = st.reg.lock().unwrap();
        let id = the_host(&reg, &req.url, &headers, caller, "pool key")?
            .id
            .clone();
        let (key, made) = reg.pool_key(&id).expect("the record was just found");
        (id, key, made)
    };
    if made {
        st.save().map_err(registry_error)?;
    }
    // A key in use is in the backup: written now when the store does not hold it yet.
    if let Some(b) = &st.backup {
        if !b.holds(&id, &key).await {
            if let Err(e) = b.push(&st.reg).await {
                tracing::error!(
                    host = id,
                    err = format!("{e:#}"),
                    "registry backup before a pool key"
                );
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "backup",
                    "the registry's backup could not be written, and no key is handed out before it is: the fleet's log says why",
                ));
            }
        }
    }
    let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
    tracing::info!(host = id, made, peer, "pool key served");
    Ok(Json(api::HostKey {
        key: key.expose().to_string(),
    })
    .into_response())
}

/// A daemon's heartbeat. It is taken for the one host record at its address, when it presents
/// that host's token: the one the bootstrap gave an ordered host, or the one `hosts:` lists.
/// Nothing else may register, so no host can speak for another.
async fn register_host(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<api::RegisterHostRequest>,
) -> Result<Response, Refusal> {
    let now = Utc::now();
    let caller = Caller::of(&st, info);
    {
        let mut reg = st.reg.lock().unwrap();
        let call = format!("heartbeat of {}", req.id);
        let rec = the_host(&reg, &req.url, &headers, caller, &call)?;
        if let Err(why) =
            registry::tls_matches(&rec.tls_fingerprint, &req.tls_fingerprint, &req.url)
        {
            tracing::warn!(
                host = rec.id,
                daemon = req.id,
                url = req.url,
                reported = req.tls_fingerprint,
                pinned = rec.tls_fingerprint,
                "registration refused: not the pinned certificate"
            );
            return Err(err(StatusCode::FORBIDDEN, "tls_mismatch", why));
        }
        let id = rec.id.clone();
        // What the host reports, applied to its record: the id, token, pin, provider fields
        // and state are the record's own (`heartbeat` leaves them).
        reg.heartbeat(
            HostRec {
                id,
                url: req.url,
                token: String::new(),
                tls_fingerprint: String::new(),
                region: req.region,
                provider: String::new(),
                provider_id: String::new(),
                state: String::new(),
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
                conditions: req.conditions,
                pool_key: Default::default(),
                unknown: Default::default(),
            },
            now,
        );
    }
    st.save().map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn drain_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(&id) {
            Some(h) => h.state = "draining".into(),
            None => return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found")),
        }
    }
    st.save().map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Orders a host from the provisioner now, whether or not the autoscaler is on.
async fn order_host(
    State(st): S,
    Json(req): Json<api::OrderHostRequest>,
) -> Result<Response, Refusal> {
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
        return Err(err(
            StatusCode::CONFLICT,
            "max_hosts",
            format!("the fleet has {counted} hosts, its maximum"),
        ));
    }
    let server = st
        .prov
        .create(&reason)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, "provisioner", format!("{e:#}")))?;
    let h = add_ordered(&st, server).map_err(registry_error)?;
    Ok((StatusCode::ACCEPTED, Json(h.to_api())).into_response())
}

/// Records a server the provisioner just made.
fn add_ordered(st: &AppState, server: provision::Server) -> Result<HostRec> {
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
            .map(|ip| bootstrap::host_url(&ip))
            .unwrap_or_default(),
        token: bootstrap::new_token(),
        // Pinned by the bootstrap, once the host has made its certificate.
        tls_fingerprint: String::new(),
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
        conditions: vec![],
        pool_key: Default::default(),
        unknown: Default::default(),
    };
    st.reg.lock().unwrap().hosts.insert(id, h.clone());
    st.save()?;
    Ok(h)
}

/// Drains a host and releases it at the provider once nothing runs on it: at once when it is
/// already empty, else from the scaler as soon as it is.
async fn retire_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    let host = {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(&id) {
            Some(h) => {
                if h.state == "ready" || h.state == "down" {
                    h.state = "draining".into();
                }
                h.clone()
            }
            None => return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found")),
        }
    };
    st.save().map_err(registry_error)?;
    let empty = host.machines == 0 && host.tenants.is_empty();
    if empty || !matches!(host.state.as_str(), "draining") {
        return match release_host(&st, &host).await {
            Ok(h) => Ok(Json(h).into_response()),
            Err(e) => Err(err(
                StatusCode::BAD_GATEWAY,
                "provisioner",
                format!("{e:#}"),
            )),
        };
    }
    tracing::info!(
        host = id,
        machines = host.machines,
        "host draining; released once empty"
    );
    Ok(Json(host.to_api()).into_response())
}

/// Releases a host at its provider (nothing to do for a static one) and forgets it.
async fn release_host(st: &AppState, h: &HostRec) -> Result<api::Host> {
    if !h.provider_id.is_empty() {
        st.prov.release(&h.provider_id).await?;
    }
    tracing::warn!(host = h.id, provider_id = h.provider_id, "host released");
    st.reg.lock().unwrap().forget(&h.id);
    st.save()?;
    let mut out = h.to_api();
    out.state = "released".into();
    Ok(out)
}

async fn forget_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    st.reg.lock().unwrap().forget(&id);
    st.save().map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn get_json<T: serde::de::DeserializeOwned>(
    st: &AppState,
    h: &HostRec,
    path: &str,
) -> Option<T> {
    let mut r = st
        .client(h)
        .ok()?
        .get(format!("{}{}", h.url.trim_end_matches('/'), path))
        .timeout(FORWARD_TIMEOUT);
    if !h.token.is_empty() {
        r = r.bearer_auth(&h.token);
    }
    r.send().await.ok()?.json::<T>().await.ok()
}

/// Static hosts send no heartbeat of their own; the fleet asks them.
async fn poll_static_hosts(st: Arc<AppState>) {
    loop {
        let unseen = poll_static_hosts_once(&st).await;
        tokio::time::sleep(std::time::Duration::from_secs(if unseen { 2 } else { 15 })).await;
    }
}

/// One round of the poll: every static host of the configuration is asked for its status and
/// tenants, then silent hosts are marked down. True when a host has never answered yet.
async fn poll_static_hosts_once(st: &AppState) -> bool {
    // From the configuration, not the registry: a static host forgotten through the API
    // is back on the next poll; it leaves the fleet by leaving the configuration.
    let now = Utc::now();
    let hosts: Vec<HostRec> = st.cfg.hosts.iter().map(|h| static_host(h, now)).collect();
    let mut unseen = false;
    for h in hosts {
        if let Some(s) = get_json::<api::Status>(st, &h, "/v1/status").await {
            let tenants: Vec<String> = get_json::<Vec<api::Tenant>>(st, &h, "/v1/tenants")
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
            rec.conditions = s.conditions;
            st.reg.lock().unwrap().heartbeat(rec, now);
        } else if h.capacity.memory_mb == 0 {
            // Never answered yet (it may be starting with us): ask again soon.
            unseen = true;
        }
    }
    st.reg.lock().unwrap().sweep(&st.policy, Utc::now());
    // A background task: a failed write is logged by `save`, and the next round writes again.
    let _ = st.save();
    unseen
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
                    let _ = add_ordered(&st, server);
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

/// A host that stopped answering is not asked: its machines are unreachable until it is back.
fn down(host: &HostRec) -> Option<Response> {
    (host.state == "down").then(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "host_down",
            format!(
                "host {} is down: its machines answer again once it does",
                host.id
            ),
        )
        .into_response()
    })
}

/// A request to a host, with the caller's content type and `If-Match` and the host's token,
/// through the client of its pinned certificate (ADR 0020).
fn to_host(
    st: &AppState,
    host: &HostRec,
    method: Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<reqwest::RequestBuilder, Refusal> {
    let url = format!("{}{}", host.url.trim_end_matches('/'), path);
    let client = st.client(host).map_err(|e| {
        err(
            StatusCode::BAD_GATEWAY,
            "host_unreachable",
            format!("host {}: a client for its certificate: {e}", host.id),
        )
    })?;
    let mut req = client.request(method, &url);
    for h in [header::CONTENT_TYPE, header::IF_MATCH] {
        if let Some(v) = headers.get(&h) {
            req = req.header(h, v);
        }
    }
    if !host.token.is_empty() {
        req = req.bearer_auth(&host.token);
    }
    Ok(req)
}

async fn forward(
    st: &AppState,
    host: &HostRec,
    method: Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refused) = down(host) {
        return refused;
    }
    let req = match to_host(st, host, method, path, headers) {
        Ok(r) => r.body(body).timeout(FORWARD_TIMEOUT),
        Err(refused) => return refused.into_response(),
    };
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
            format!("host {}: {}", host.id, causes(&e)),
        )
        .into_response(),
    }
}

/// A watch forwarded: the host's answer streamed through as it comes, with no deadline (its
/// heartbeat shows it is alive).
async fn forward_watch(st: &AppState, host: &HostRec, path: &str, headers: &HeaderMap) -> Response {
    if let Some(refused) = down(host) {
        return refused;
    }
    let req = match to_host(st, host, Method::GET, path, headers) {
        Ok(r) => r,
        Err(refused) => return refused.into_response(),
    };
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
            let mut out = Response::new(Body::from_stream(resp.bytes_stream()));
            *out.status_mut() = status;
            if let Some(ct) = ct {
                out.headers_mut().insert(header::CONTENT_TYPE, ct);
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
            format!("host {}: {}", host.id, causes(&e)),
        )
        .into_response(),
    }
}

/// An error and its sources, as one line: a refused certificate is two levels under reqwest's
/// "error sending request".
fn causes(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut next = e.source();
    while let Some(s) = next {
        out.push_str(": ");
        out.push_str(&s.to_string());
        next = s.source();
    }
    out
}

/// A forwarded response, its body read so it can be looked at and sent on.
async fn read(resp: Response) -> (axum::http::response::Parts, Bytes) {
    let (parts, body) = resp.into_parts();
    let data = axum::body::to_bytes(body, 64 << 20)
        .await
        .unwrap_or_default();
    (parts, data)
}

/// Adds the host id to a machine JSON body.
fn with_host(body: Bytes, host: &str) -> Bytes {
    with_field(body, "host", host)
}

/// Sets a field of a JSON object body; any other body is sent on as it is.
fn with_field(body: Bytes, key: &str, value: &str) -> Bytes {
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut v) if v.is_object() => {
            v[key] = serde_json::Value::String(value.into());
            Bytes::from(serde_json::to_vec(&v).unwrap_or_default())
        }
        _ => body,
    }
}

/// The `code` of an error body, empty when it is not one.
fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<api::ApiError>(body)
        .map(|e| e.code)
        .unwrap_or_default()
}

async fn create_machine(
    State(st): S,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let req: api::CreateMachineRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    let disk = disk_need(req.volume.as_ref().map(|v| v.size_gb));
    let (host, first) = {
        let mut reg = st.reg.lock().unwrap();
        let first = !reg.tenants.contains_key(&req.tenant);
        let source = req
            .fork
            .as_ref()
            .and_then(|f| reg.host_of_machine(&f.machine_id).map(|h| h.id.clone()));
        // The host the request is bound to: a fork's source's, else the tenant's.
        let bound = source
            .clone()
            .or_else(|| reg.tenants.get(&req.tenant).cloned());
        refuse_outside(&reg, bound.as_deref(), &req.tenant, &req.region)?;
        refuse_under_pressure(&reg, bound.as_deref())?;
        let chosen = match source {
            Some(id) => {
                reg.reserve(&id, req.size.memory_mb, disk);
                Some(id)
            }
            None => reg.place(
                &req.tenant,
                &req.region,
                req.size.memory_mb,
                disk,
                &st.policy,
            ),
        };
        (chosen.and_then(|id| reg.hosts.get(&id).cloned()), first)
    };
    let host = host.ok_or_else(|| no_room(&req.region, "this machine"))?;
    st.save().map_err(registry_error)?;
    let resp = forward(&st, &host, Method::POST, "/v1/machines", &headers, body).await;
    let (parts, data) = read(resp).await;
    if parts.status.is_success() {
        if let Ok(m) = serde_json::from_slice::<api::Machine>(&data) {
            st.reg
                .lock()
                .unwrap()
                .machines
                .insert(m.id, host.id.clone());
        }
        st.save().map_err(registry_error)?;
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    first_refused(&st, &req.tenant, first, &data)?;
    Ok(Response::from_parts(parts, Body::from(data)))
}

/// A create bound to a host of another region than it asks: 400, a tenant never spans
/// regions (ADR 0025).
fn refuse_outside(
    reg: &Registry,
    host: Option<&str>,
    tenant: &str,
    region: &str,
) -> Result<(), Refusal> {
    match host
        .and_then(|id| reg.hosts.get(id))
        .and_then(|h| h.outside(tenant, region))
    {
        Some(why) => Err(err(StatusCode::BAD_REQUEST, "invalid", why)),
        None => Ok(()),
    }
}

/// No host (of the region asked) with room for `what`: 503 `capacity`, which a caller tries
/// again later.
fn no_room(region: &str, what: &str) -> Refusal {
    let hosts = match region {
        "" => "no host".to_string(),
        r => format!("no host in region {r}"),
    };
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "capacity",
        format!("{hosts} has room for {what}"),
    )
}

/// A create on a host that takes nothing new while a condition is true (ADR 0021): a pinned
/// tenant's host, or a fork's source's. 503 `capacity`, which a caller tries again later.
fn refuse_under_pressure(reg: &Registry, host: Option<&str>) -> Result<(), Refusal> {
    match host
        .and_then(|id| reg.hosts.get(id))
        .and_then(|h| h.pressure())
    {
        Some(why) => Err(err(StatusCode::SERVICE_UNAVAILABLE, "capacity", why)),
        None => Ok(()),
    }
}

/// The disk a machine is placed for: root disks are thin, a volume takes what it says, plus
/// headroom.
fn disk_need(volume_gb: Option<u32>) -> u64 {
    volume_gb.map(|gb| gb as u64 * 1024).unwrap_or(0) + 2048
}

/// A host with no room for a tenant's first machine (or gateway): the pin the request made
/// goes, so a retry is placed afresh. A later one keeps it: the tenant's network is there.
fn first_refused(st: &AppState, tenant: &str, first: bool, answer: &[u8]) -> Result<(), Refusal> {
    if first && error_code(answer) == "capacity" {
        st.reg.lock().unwrap().unpin(tenant);
        st.save().map_err(registry_error)?;
    }
    Ok(())
}

/// Lists machines. A listing is the truth for whoever reads it (the control plane marks a
/// machine missing from it as gone), so it is never partial: a tenant's listing asks the
/// tenant's host alone, and a host that is down or does not answer fails the whole listing.
/// The `tenant` of a query.
fn query_tenant(uri: &Uri) -> Option<String> {
    uri.query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("tenant=")))
        .map(|t| t.to_string())
}

async fn list_machines(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let tenant = query_tenant(&uri);
    let hosts: Vec<HostRec> = {
        let reg = st.reg.lock().unwrap();
        match tenant.as_deref().and_then(|t| reg.host_of_tenant(t)) {
            Some(h) => vec![h.clone()],
            None => reg.listed(),
        }
    };
    let mut all: Vec<serde_json::Value> = Vec::new();
    let path = match uri.query() {
        Some(q) => format!("/v1/machines?{q}"),
        None => "/v1/machines".into(),
    };
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
            Ok(ms) => {
                let mut reg = st.reg.lock().unwrap();
                for mut m in ms {
                    if let Some(id) = m["id"].as_str() {
                        reg.machines.insert(id.to_string(), h.id.clone());
                    }
                    m["host"] = serde_json::Value::String(h.id.clone());
                    all.push(m);
                }
            }
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

fn unreadable(h: &HostRec, e: serde_json::Error) -> Response {
    err(
        StatusCode::BAD_GATEWAY,
        "host_unreachable",
        format!("host {}: unreadable listing: {e}", h.id),
    )
    .into_response()
}

/// Lists endpoints, never partially, like machines; each one is indexed to its host.
async fn list_endpoints(State(st): S, headers: HeaderMap) -> Response {
    let hosts = st.reg.lock().unwrap().listed();
    let mut all: Vec<api::Endpoint> = Vec::new();
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
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::Endpoint>>(&data) {
            Ok(eps) => {
                let mut reg = st.reg.lock().unwrap();
                for e in &eps {
                    reg.endpoints.insert(e.id.clone(), h.id.clone());
                }
                all.extend(eps);
            }
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

/// The backups of the hosts' machines, destroyed ones' included (ADR 0023): with a tenant,
/// its host's; else every host's, never partial.
async fn all_backups(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let hosts: Vec<HostRec> = {
        let reg = st.reg.lock().unwrap();
        match query_tenant(&uri).and_then(|t| reg.host_of_tenant(&t).cloned()) {
            Some(h) => vec![h],
            None => reg.listed(),
        }
    };
    let path = match uri.query() {
        Some(q) => format!("/v1/backups?{q}"),
        None => "/v1/backups".into(),
    };
    let mut all: Vec<api::Backup> = Vec::new();
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::Backup>>(&data) {
            Ok(bs) => all.extend(bs),
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

/// Usage of every host, never partial (ADR 0017): a usage report missing a host is a bill
/// missing a host. Every listed host is asked, the query as it came (the hosts check it), and
/// each bucket says which host measured it.
async fn usage(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let hosts = st.reg.lock().unwrap().listed();
    let path = match uri.query() {
        Some(q) => format!("/v1/usage?{q}"),
        None => "/v1/usage".into(),
    };
    let mut all: Vec<api::UsageBucket> = Vec::new();
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::UsageBucket>>(&data) {
            Ok(bs) => all.extend(bs.into_iter().map(|b| api::UsageBucket {
                host: h.id.clone(),
                ..b
            })),
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

/// The running machines' use (ADR 0021), asked as machines are listed: a tenant's of its
/// host, else of every host, never partial, each machine with its host.
async fn top(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let tenant = uri
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("tenant=")))
        .map(|t| t.to_string());
    let hosts: Vec<HostRec> = {
        let reg = st.reg.lock().unwrap();
        match tenant.as_deref().and_then(|t| reg.host_of_tenant(t)) {
            Some(h) => vec![h.clone()],
            None => reg.listed(),
        }
    };
    let path = match uri.query() {
        Some(q) => format!("/v1/top?{q}"),
        None => "/v1/top".into(),
    };
    let mut all: Vec<api::TopMachine> = Vec::new();
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::TopMachine>>(&data) {
            Ok(ms) => all.extend(ms.into_iter().map(|m| api::TopMachine {
                host: h.id.clone(),
                ..m
            })),
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

#[derive(serde::Deserialize)]
struct EventsQuery {
    since: Option<String>,
    tenant: Option<String>,
    machine: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    watch: bool,
}

/// Events (ADR 0019), which are per host. With a tenant, from the tenant's host; else with a
/// machine, from the machine's host: the host's own cursor, a watch streamed through. With
/// neither, every host, never partial, merged by time with each event's host and a cursor of
/// every host's: `<host>:<seq>,…`. A watch of every host is refused.
async fn events(
    State(st): S,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<EventsQuery>,
) -> Response {
    let path = match uri.query() {
        Some(query) => format!("/v1/events?{query}"),
        None => "/v1/events".into(),
    };
    let host = match (&q.tenant, &q.machine) {
        (Some(t), _) => st.reg.lock().unwrap().host_of_tenant(t).cloned().ok_or_else(|| {
            err(StatusCode::NOT_FOUND, "not_found", format!("tenant {t} not found"))
        }),
        (None, Some(m)) => locate(&st, Indexed::Machine, m).await.ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("machine {m} not found: a destroyed machine's events are read with its tenant, ?tenant=…&machine={m}"),
            )
        }),
        (None, None) if q.watch => Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "a watch through the fleet names a tenant or a machine: events are per host, and a stream of every host would go on without one that drops",
        )),
        (None, None) => return events_of_every_host(&st, &headers, &uri, q).await,
    };
    match host {
        Ok(h) if q.watch => forward_watch(&st, &h, &path, &headers).await,
        Ok(h) => forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await,
        Err(refused) => refused.into_response(),
    }
}

/// A fleet-wide cursor, `<host>:<seq>,…`, as each host's seq; a host it does not name reads
/// from its start.
fn parse_cursor(since: &str) -> Result<std::collections::HashMap<String, u64>, Refusal> {
    let bad = || {
        err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("since {since:?}: want <host>:<seq>,… as a fleet-wide read's `next` gave it"),
        )
    };
    since
        .split(',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (host, seq) = part.rsplit_once(':').ok_or_else(bad)?;
            Ok((host.to_string(), seq.parse().map_err(|_| bad())?))
        })
        .collect()
}

fn cursor(seqs: &std::collections::BTreeMap<String, u64>) -> String {
    let parts: Vec<String> = seqs.iter().map(|(h, s)| format!("{h}:{s}")).collect();
    parts.join(",")
}

async fn events_of_every_host(
    st: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    q: EventsQuery,
) -> Response {
    let mut since = match parse_cursor(q.since.as_deref().unwrap_or("")) {
        Ok(c) => c,
        Err(refused) => return refused.into_response(),
    };
    let limit = api::events_limit(q.limit);
    // The query as it came, for the hosts to read, but the cursor: each host gets its own.
    let rest: String = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty() && !kv.starts_with("since="))
        .map(|kv| format!("&{kv}"))
        .collect();
    let hosts = st.reg.lock().unwrap().listed();
    let mut all: Vec<api::Event> = Vec::new();
    let mut next = std::collections::BTreeMap::new();
    for h in hosts {
        let path = format!(
            "/v1/events?since={}{rest}",
            since.remove(&h.id).unwrap_or(0)
        );
        let resp = forward(st, &h, Method::GET, &path, headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<api::EventsPage>(&data) {
            Ok(page) => {
                next.insert(h.id.clone(), page.next.parse().unwrap_or(0));
                all.extend(page.events.into_iter().map(|e| api::Event {
                    host: h.id.clone(),
                    ..e
                }));
            }
            Err(e) => return unreadable(&h, e),
        }
    }
    all.sort_by(|a, b| (a.at, &a.host, a.seq).cmp(&(b.at, &b.host, b.seq)));
    // Past the limit, a host's cursor is its last event kept, so the next read goes on from it.
    if all.len() > limit {
        for e in all.drain(limit..) {
            let cut = next.get_mut(&e.host).expect("asked");
            *cut = (*cut).min(e.seq - 1);
        }
    }
    Json(api::EventsPage {
        events: all,
        next: cursor(&next),
    })
    .into_response()
}

async fn list_tenants(State(st): S) -> Json<Vec<api::Tenant>> {
    let reg = st.reg.lock().unwrap();
    let mut out: Vec<api::Tenant> = reg
        .tenants
        .iter()
        .map(|(t, h)| api::Tenant {
            id: t.clone(),
            subnet: String::new(),
            router: String::new(),
            machines: 0,
            created_at: Utc::now(),
            host: h.clone(),
            region: reg.region_of(t).unwrap_or_default().into(),
            gateway: None,
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Json(out)
}

async fn delete_tenant(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_tenant(&id).cloned();
    let host = match host {
        Some(h) => h,
        None => return Ok(StatusCode::NO_CONTENT.into_response()),
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
        st.reg.lock().unwrap().unpin(&id);
        st.save().map_err(registry_error)?;
    }
    Ok(resp)
}

/// A tenant, from its host, with that host and its region.
async fn get_tenant(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_tenant(&id).cloned();
    let host = host.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "tenant not found"))?;
    let path = format!("/v1/tenants/{id}");
    let resp = forward(&st, &host, Method::GET, &path, &headers, Bytes::new()).await;
    let (parts, data) = read(resp).await;
    let data = match parts.status.is_success() {
        true => with_field(with_host(data, &host.id), "region", &host.region),
        false => data,
    };
    Ok(Response::from_parts(parts, Body::from(data)))
}

/// Where a PUT on a tenant with no host yet places it (ADR 0025).
#[derive(serde::Deserialize, Default)]
struct PlaceQuery {
    #[serde(default)]
    region: String,
}

/// A PUT on a tenant that the tenant's host answers: one with no host yet is placed as its
/// first machine would be, in `region`, with `need_mb` and `need_disk_mb` as the need. The
/// host's answer, with the host.
async fn put_on_tenant(
    st: &AppState,
    id: &str,
    what: &str,
    region: &str,
    (need_mb, need_disk_mb): (u32, u64),
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    if !api::valid_id(id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "tenant must be a-z, 0-9, _ or -, at most 64 characters",
        ));
    }
    let (host, first) = {
        let mut reg = st.reg.lock().unwrap();
        let first = !reg.tenants.contains_key(id);
        let bound = reg.tenants.get(id).cloned();
        refuse_outside(&reg, bound.as_deref(), id, region)?;
        refuse_under_pressure(&reg, bound.as_deref())?;
        let chosen = reg.place(id, region, need_mb, need_disk_mb, &st.policy);
        (chosen.and_then(|h| reg.hosts.get(&h).cloned()), first)
    };
    let host = host.ok_or_else(|| no_room(region, &format!("this {what}")))?;
    st.save().map_err(registry_error)?;
    let path = format!("/v1/tenants/{id}/{what}");
    let resp = forward(st, &host, Method::PUT, &path, headers, body).await;
    let (parts, data) = read(resp).await;
    if parts.status.is_success() {
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    first_refused(st, id, first, &data)?;
    Ok(Response::from_parts(parts, Body::from(data)))
}

/// Puts a tenant's gateway on the tenant's host; a tenant with none yet is placed as its first
/// machine would be, the gateway's size as the need.
async fn set_gateway(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<PlaceQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let spec: api::GatewaySpec = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    let need = (spec.size().memory_mb, disk_need(spec.volume_gb));
    put_on_tenant(&st, &id, "gateway", &q.region, need, &headers, body).await
}

/// Puts a tenant's quota on the tenant's host (ADR 0025); a tenant with none yet is placed,
/// with no need: the quota is what its machines will be held to there.
async fn set_quota(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<PlaceQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    serde_json::from_slice::<api::Quota>(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    put_on_tenant(&st, &id, "quota", &q.region, (0, 0), &headers, body).await
}

/// A tenant's quota and use, from its host.
async fn get_quota(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_tenant(&id).cloned();
    let host = host.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "tenant not found"))?;
    let path = format!("/v1/tenants/{id}/quota");
    Ok(forward(&st, &host, Method::GET, &path, &headers, Bytes::new()).await)
}

/// Removes a tenant's gateway on its host; a tenant the fleet never placed has none.
async fn delete_gateway(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_tenant(&id).cloned();
    let Some(host) = host else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let path = format!("/v1/tenants/{id}/gateway");
    Ok(forward(&st, &host, Method::DELETE, &path, &headers, Bytes::new()).await)
}

/// Releases a tenant from its host without touching the host: its next machine is placed
/// afresh. For the operator moving a tenant (backups, then a restore elsewhere) or freeing
/// one stuck on a host that is full or gone.
async fn unpin_tenant(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    st.reg.lock().unwrap().unpin(&id);
    st.save().map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// What the fleet indexes to a host, and where a host is asked for one by id.
#[derive(Clone, Copy)]
enum Indexed {
    Machine,
    Endpoint,
}

impl Indexed {
    fn path(self, id: &str) -> String {
        match self {
            Indexed::Machine => format!("/v1/machines/{id}"),
            Indexed::Endpoint => format!("/v1/endpoints/{id}"),
        }
    }

    fn index(self, reg: &mut Registry) -> &mut std::collections::HashMap<String, String> {
        match self {
            Indexed::Machine => &mut reg.machines,
            Indexed::Endpoint => &mut reg.endpoints,
        }
    }
}

/// Finds the host of a machine or an endpoint: from the index, else by asking every host.
async fn locate(st: &AppState, what: Indexed, id: &str) -> Option<HostRec> {
    let hosts = {
        let mut reg = st.reg.lock().unwrap();
        let known = what.index(&mut reg).get(id).cloned();
        if let Some(h) = known.and_then(|hid| reg.hosts.get(&hid)) {
            return Some(h.clone());
        }
        reg.ready()
    };
    // A probe, not the caller's request: none of its headers (its `If-Match` is for the call).
    for h in hosts {
        let resp = forward(
            st,
            &h,
            Method::GET,
            &what.path(id),
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        if resp.status().is_success() {
            what.index(&mut st.reg.lock().unwrap())
                .insert(id.to_string(), h.id.clone());
            return Some(h);
        }
    }
    None
}

/// The backups of a machine id, from whichever host answers: the store is shared, and the
/// machine may be gone from every host.
async fn list_backups(
    State(st): S,
    Path(params): Path<Vec<(String, String)>>,
    headers: HeaderMap,
) -> Response {
    let id = params
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let path = format!("/v1/machines/{id}/backups");
    let known = st.reg.lock().unwrap().host_of_machine(&id).cloned();
    let hosts: Vec<HostRec> = match known {
        Some(h) => vec![h],
        None => st.reg.lock().unwrap().ready(),
    };
    let mut last = err(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_host",
        "no host is ready",
    )
    .into_response();
    for h in hosts {
        if h.state == "down" {
            continue;
        }
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if resp.status().is_success() {
            return resp;
        }
        last = resp;
    }
    last
}

async fn by_machine(
    State(st): S,
    Path(params): Path<Vec<(String, String)>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let id = params
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    // A destroyed machine (its backups' holder, ADR 0023) is found through its tenant.
    let host = match locate(&st, Indexed::Machine, &id).await {
        Some(h) => h,
        None => query_tenant(&uri)
            .and_then(|t| st.reg.lock().unwrap().host_of_tenant(&t).cloned())
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "machine not found"))?,
    };
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let own = format!("/v1/machines/{id}");
    let is_delete = method == Method::DELETE && path == own;
    let plain_get = method == Method::GET && path == own;
    let adds_endpoint = method == Method::POST && path == format!("{own}/endpoints");
    // A logs follow (ADR 0025) is streamed through, as a watch is.
    let follows = method == Method::GET
        && uri.path() == format!("{own}/logs")
        && uri
            .query()
            .is_some_and(|q| q.split('&').any(|kv| kv == "follow=true"));
    if follows {
        return Ok(forward_watch(&st, &host, &path, &headers).await);
    }
    let resp = forward(&st, &host, method, &path, &headers, body).await;
    if !resp.status().is_success() {
        return Ok(resp);
    }
    if is_delete {
        st.reg.lock().unwrap().machines.remove(&id);
        st.save().map_err(registry_error)?;
    }
    if plain_get {
        let (parts, data) = read(resp).await;
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    if adds_endpoint {
        let (parts, data) = read(resp).await;
        if let Ok(e) = serde_json::from_slice::<api::Endpoint>(&data) {
            st.reg
                .lock()
                .unwrap()
                .endpoints
                .insert(e.id, host.id.clone());
            st.save().map_err(registry_error)?;
        }
        return Ok(Response::from_parts(parts, Body::from(data)));
    }
    Ok(resp)
}

async fn by_endpoint(
    State(st): S,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let host = locate(&st, Indexed::Endpoint, &id).await.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("endpoint {id} not found"),
        )
    })?;
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let is_delete = method == Method::DELETE;
    let resp = forward(&st, &host, method, &path, &headers, body).await;
    if is_delete && resp.status().is_success() {
        st.reg.lock().unwrap().endpoints.remove(&id);
        st.save().map_err(registry_error)?;
    }
    Ok(resp)
}

#[cfg(test)]
mod tests;
