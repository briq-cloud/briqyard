//! briqyard-fleet: the briqyard API across several hosts. Each tenant lives on one host; the
//! fleet places new tenants, forwards every machine request to the right daemon, keeps the
//! registry of hosts from their heartbeats, and bootstraps the servers added to it. It buys no
//! server: it says what ran out (ADR 0042), and something outside adds hosts.

mod backup;
mod bootstrap;
mod config;
mod registry;
mod restores;
mod signals;
mod upgrade;

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
use registry::{url_host, HostRec, Policy, Registry, Resource};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "briqyard-fleet", version = api::VERSION, about = "briqyard across hosts")]
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
    /// Held by the host upgrade under way: one at a time (ADR 0027).
    upgrade: Arc<tokio::sync::Mutex<()>>,
    /// The registry's backup, when `backup.store` is set (ADR 0032).
    backup: Option<backup::Backup>,
    /// Key requests take turns: a key just made is answered, to its host or any other ask,
    /// only once it is written, and taken back when it could not be (ADR 0026).
    key_turn: tokio::sync::Mutex<()>,
    /// Restores forwarded and not over: what a backup's key is served for (ADR 0035).
    restores: restores::Restores,
    /// Creates refused for want of room, for an external scaler (ADR 0042).
    refusals: signals::Refusals,
    /// The registry file's writes take turns (ADR 0043); the digest of what the last one wrote.
    written: Arc<tokio::sync::Mutex<Option<[u8; 32]>>>,
}

/// Writes a registry file, the fleet's alone (`0600`: it holds every host's token and pool
/// key): a temp file made afresh, synced, renamed over the old one, the directory synced. One
/// writer at a time (`AppState::save`, or `restore` with the fleet stopped): the temp file's
/// name is fixed.
fn write_registry(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("json.tmp");
    // A leftover (a write cut short by a crash) keeps its own mode through `open`: made
    // afresh, it is 0600.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
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

    /// Writes the registry (ADR 0043). Writes take turns, and each encodes the registry when
    /// its turn comes: what it writes holds every change made before it was called, so a
    /// later write never lands an older registry. A turn that finds the registry as the last
    /// write left it writes nothing. The turn is held until the file and its directory are
    /// synced, even when the caller has gone. A failure is logged at `error` and returned.
    async fn save(&self) -> Result<()> {
        use sha2::{Digest, Sha256};
        let mut turn = self.written.clone().lock_owned().await;
        let data = backup::encode(&self.reg.lock().unwrap());
        let digest: [u8; 32] = Sha256::digest(&data).into();
        if *turn == Some(digest) {
            return Ok(());
        }
        let path = self.state_path.clone();
        let written = tokio::task::spawn_blocking(move || {
            write_registry(&path, &data)?;
            *turn = Some(digest);
            Ok::<(), std::io::Error>(())
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)));
        if let Err(e) = &written {
            tracing::error!(path = %self.state_path.display(), err = %e, "write the registry");
        }
        written.with_context(|| format!("write registry {}", self.state_path.display()))
    }

    /// Writes the registry after a host acted on a request: the host's answer is the truth
    /// and is relayed whatever this write does. A failure is logged by `save`, and the next
    /// write (a heartbeat's, within seconds) carries the change (ADR 0043).
    async fn save_after_host(&self) {
        let _ = self.save().await;
    }
}

type S = State<Arc<AppState>>;

/// A forwarded call may legitimately run for minutes (an exec, a create pulling an image);
/// a watch has no end and is not given one.
/// What a stop gives the calls in flight (ADR 0051): what arrives meanwhile waits in the
/// kernel's queue for the next process.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(2);
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
        ssh: String::new(),
        token: h.token.clone(),
        tls_fingerprint: h.tls_fingerprint.clone(),
        region: h.region.clone(),
        provider: "static".into(),
        state: "ready".into(),
        capacity: Default::default(),
        used: Default::default(),
        machines: 0,
        tenants: vec![],
        last_seen: now,
        version: String::new(),
        disk_free_mb: 0,
        note: String::new(),
        bootstrap_attempts: 0,
        public_tcp_ports: None,
        conditions: vec![],
        started: Default::default(),
        pool_key: Default::default(),
        unknown: Default::default(),
        holds: Vec::new(),
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
    upgrade::interrupted(&mut reg);
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
        upgrade: Default::default(),
        backup: backup::Backup::open(&cfg.backup)?,
        key_turn: Default::default(),
        restores: Default::default(),
        refusals: Default::default(),
        written: Default::default(),
    });
    tokio::spawn(backup::run(state.clone()));
    tokio::spawn(poll_static_hosts(state.clone()));
    tokio::spawn(forget_retired(state.clone()));
    tokio::spawn(bootstrap::run(state.clone()));
    // The peer address is what a host's own calls are checked against (`the_host`).
    let app = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    // Kept in systemd's store across a restart: calls made meanwhile wait (ADR 0051).
    let listeners = api::listeners::Listeners::from_env();
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&cfg.listen)
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| anyhow!("listen {}: want address:port", cfg.listen))?;
    let listener = listeners
        .tcp("api", addr)
        .with_context(|| format!("listen {}", cfg.listen))?;
    listener.set_nonblocking(true)?;
    if let Err(e) = listeners.release_unused() {
        tracing::warn!(err = %e, "listeners no longer used left in the store");
    }
    let handle = axum_server::Handle::new();
    {
        let handle = handle.clone();
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            // Nothing accepted from here; the calls in flight get DRAIN, then are cut.
            tracing::info!("shutting down");
            handle.graceful_shutdown(Some(DRAIN));
        });
    }
    tracing::info!(
        addr = cfg.listen,
        tls = matches!(cfg.tls, config::Tls::Files { .. }),
        version = api::VERSION,
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
                .handle(handle)
                .serve(app)
                .await?
        }
        config::Tls::Unset | config::Tls::Off => {
            axum_server::from_tcp(listener)
                .handle(handle)
                .serve(app)
                .await?
        }
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
    write_registry(state_path, &backup::encode(&reg))
        .with_context(|| format!("write {}", state_path.display()))?;
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
        "restored {} hosts ({keys} pool keys, {} retired) and {} tenants from {from} into {}\n",
        reg.hosts.len(),
        reg.retired_keys.len(),
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
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/hosts", get(list_hosts).post(add_host))
        .route("/v1/hosts/register", post(register_host))
        .route("/v1/hosts/key", post(host_key))
        .route("/v1/hosts/:id/drain", post(drain_host))
        .route("/v1/hosts/:id/undrain", post(undrain_host))
        .route("/v1/hosts/:id/upgrade", post(upgrade::upgrade_host))
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
        // A session (ADR 0029) is a WebSocket: relayed as bytes once both sides upgraded.
        .route("/v1/machines/:id/exec", get(exec_session).post(by_machine))
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

/// The token a client's path needs (empty: none): the metrics token for `/metrics` when one is
/// set, so a scraper never holds the API's, and none there on a loopback listener with nothing
/// in front (`tls` unset), as the daemon's (ADR 0021); else the API's.
fn token_for<'a>(cfg: &'a config::Config, path: &str) -> &'a str {
    match path {
        "/metrics" if cfg.tls == config::Tls::Unset => "",
        "/metrics" if !cfg.metrics_token.is_empty() => &cfg.metrics_token,
        _ => &cfg.token,
    }
}

async fn auth(State(st): S, req: Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path().to_string();
    // A heartbeat and a key request present the host's own token, checked against its record
    // by the handler.
    let open = path == "/healthz" || path == "/v1/hosts/register" || path == "/v1/hosts/key";
    let token = token_for(&st.cfg, &path);
    if !open
        && !token.is_empty()
        && !api::constant_eq(bearer(req.headers()).as_bytes(), token.as_bytes())
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

/// Prometheus text: hosts by state, each region's room and the creates refused for want of
/// it (ADR 0042).
async fn metrics(State(st): S) -> Response {
    let text = {
        let reg = st.reg.lock().unwrap();
        signals::render(&reg, &signals::regions(&reg, &st.policy, &st.refusals))
    };
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

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
        "version": api::VERSION, "host_id": "fleet",
        "capacity": cap, "used": used, "machines": machines, "running": machines,
        "hosts": reg.hosts.len(), "ready": ready, "tenants": reg.tenants.len(),
        "regions": signals::regions(&reg, &st.policy, &st.refusals),
    }))
}

async fn list_hosts(State(st): S) -> Json<Vec<api::Host>> {
    let reg = st.reg.lock().unwrap();
    let mut hosts: Vec<api::Host> = reg.hosts.values().map(|h| h.to_api()).collect();
    hosts.sort_by(|a, b| a.id.cmp(&b.id));
    Json(hosts)
}

/// Who made a host's call, as the fleet sees it, and whether that is known.
/// - The fleet terminates the connection (its own TLS, or plain on loopback): the peer.
/// - `tls: off` on a loopback listener: a proxy of ours in front, by construction (nothing
///   else reaches a loopback port), so the last `X-Forwarded-For` value, which the proxy
///   writes; a call without one is from an unknown address.
/// - `tls: off` on any other address: whatever is in front, unknown: the token alone.
#[derive(Clone, Copy, Debug)]
struct Caller {
    peer: Option<std::net::IpAddr>,
    checked: bool,
}

impl Caller {
    fn of(
        st: &AppState,
        info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
        headers: &HeaderMap,
    ) -> Caller {
        let connection = info.map(|i| i.0.ip().to_canonical());
        if !matches!(st.cfg.tls, config::Tls::Off) {
            return Caller {
                peer: connection,
                checked: true,
            };
        }
        let loopback = st
            .cfg
            .listen
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|a| a.ip().is_loopback());
        if !loopback {
            return Caller {
                peer: connection,
                checked: false,
            };
        }
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .last()
            .and_then(|v| {
                v.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .map(|ip| ip.to_canonical());
        Caller {
            peer: forwarded,
            checked: true,
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
                "no host is expected at {}: add it with `briqyard host add`, or list it under hosts: with its token",
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
    let caller = Caller::of(&st, info, &headers);
    // A backup's key is only read: it never waits behind a key being made.
    if let Some(want) = &req.key_id {
        return backup_key(&st, &req, &headers, caller, want);
    }
    let _turn = st.key_turn.lock().await;
    let (id, key, made) = {
        let mut reg = st.reg.lock().unwrap();
        let id = the_host(&reg, &req.url, &headers, caller, "pool key")?
            .id
            .clone();
        let (key, made) = reg.pool_key(&id).expect("the record was just found");
        (id, key, made)
    };
    if made {
        if let Err(e) = st.save().await {
            // Never served, never kept: the next ask makes one again.
            if let Some(h) = st.reg.lock().unwrap().hosts.get_mut(&id) {
                h.pool_key = Default::default();
            }
            return Err(registry_error(e));
        }
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

/// The pool key of a backup (ADR 0035): the host's own at any ask, as `host_key` serves it
/// (ADR 0045); another's, a live host's or a forgotten one's, for the host the fleet forwarded
/// a restore to, once per restore. A raw stream opens only with the pool key of the host that
/// sent it, so that is what is served. Never made here; another host's key is a `warn` line.
fn backup_key(
    st: &AppState,
    req: &api::HostKeyRequest,
    headers: &HeaderMap,
    caller: Caller,
    key_id: &str,
) -> Result<Response, Refusal> {
    let reg = st.reg.lock().unwrap();
    let host = the_host(&reg, &req.url, headers, caller, "backup key")?
        .id
        .clone();
    let Some((owner, key)) = reg.key_by_id(key_id) else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "no_key",
            format!("the fleet holds no pool key {key_id}: the backup was made on a host with a key file, or on a host forgotten before ADR 0035"),
        ));
    };
    // The last check: a refusal above leaves the restore's ask to it, and so does the host's
    // own key.
    let open = owner == host
        || req
            .restore
            .as_ref()
            .is_some_and(|rs| st.restores.take(&host, rs, std::time::Instant::now()));
    if !open {
        let what = req
            .restore
            .as_ref()
            .map(|rs| format!("{}/{}", rs.machine_id, rs.backup))
            .unwrap_or_else(|| "none named".into());
        tracing::warn!(
            host,
            key_id,
            restore = what,
            "backup key refused: no restore open"
        );
        return Err(err(
            StatusCode::FORBIDDEN,
            "no_restore",
            format!("a backup's key is served once, for a restore the fleet forwarded to this host: none open for {host} ({what})"),
        ));
    }
    let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
    // Its own key is routine; another host's is the hand-out worth a look.
    if owner == host {
        tracing::info!(host, owner, key_id, peer, "backup key served");
    } else {
        tracing::warn!(host, owner, key_id, peer, "backup key served");
    }
    Ok(Json(api::HostKey {
        key: key.expose().to_string(),
    })
    .into_response())
}

/// A daemon's heartbeat. It is taken for the one host record at its address, when it presents
/// that host's token: the one the bootstrap gave an added host, or the one `hosts:` lists.
/// Nothing else may register, so no host can speak for another.
async fn register_host(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<api::RegisterHostRequest>,
) -> Result<Response, Refusal> {
    let now = Utc::now();
    let caller = Caller::of(&st, info, &headers);
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
                ssh: String::new(),
                token: String::new(),
                tls_fingerprint: String::new(),
                region: req.region,
                provider: String::new(),
                state: String::new(),
                capacity: req.capacity,
                used: req.used,
                machines: req.machines,
                tenants: req.tenants,
                last_seen: now,
                version: req.version,
                disk_free_mb: req.disk_free_mb,
                note: String::new(),
                bootstrap_attempts: 0,
                public_tcp_ports: None,
                conditions: req.conditions,
                started: req.started,
                pool_key: Default::default(),
                unknown: Default::default(),
                holds: Vec::new(),
            },
            now,
        );
    }
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Places nothing new on a host (Kubernetes's cordon); its machines go on.
async fn drain_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    set_host_state(&st, &id, "draining", |_| true).await
}

/// Undoes a drain or a retire: the host takes new tenants again.
async fn undrain_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    set_host_state(&st, &id, "ready", |s| matches!(s, "draining" | "retiring")).await
}

/// Moves a host from a state `from` accepts to `to`; 409 from any other (an upgrade under way
/// owns its host's state, ADR 0027).
async fn set_host_state(
    st: &AppState,
    id: &str,
    to: &str,
    from: impl Fn(&str) -> bool,
) -> Result<Response, Refusal> {
    {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(id) {
            Some(h) if h.state == "upgrading" || !from(&h.state) => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "conflict",
                    format!("host {id} is {}", h.state),
                ))
            }
            Some(h) => h.state = to.into(),
            None => return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found")),
        }
    }
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Adds a server (Kubernetes's `kubeadm join`): recorded `provisioning` with a fresh token and
/// nothing pinned, then installed by the bootstrap, which pins its SSH key and certificate (ADR
/// 0028). Its API may be on the private network while SSH reaches its public address.
async fn add_host(State(st): S, Json(req): Json<api::AddHostRequest>) -> Result<Response, Refusal> {
    let h = new_added_host(&st.cfg.bootstrap, req, Utc::now())?;
    {
        let mut reg = st.reg.lock().unwrap();
        if let Some(other) = reg.hosts.values().find(|o| {
            o.id == h.id
                || (!o.url.is_empty() && url_host(&o.url) == url_host(&h.url))
                || (!h.ssh.is_empty() && o.ssh == h.ssh)
        }) {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                format!("host {} is already at {}", other.id, url_host(&other.url)),
            ));
        }
        reg.hosts.insert(h.id.clone(), h.clone());
    }
    st.save().await.map_err(registry_error)?;
    tracing::warn!(
        host = h.id,
        ssh = h.ssh,
        url = h.url,
        "host added; bootstrapped within two minutes"
    );
    Ok((StatusCode::ACCEPTED, Json(h.to_api())).into_response())
}

/// The record of a server added by hand, or why the request is refused.
fn new_added_host(
    b: &config::Bootstrap,
    req: api::AddHostRequest,
    now: chrono::DateTime<Utc>,
) -> Result<HostRec, Refusal> {
    let invalid = |m: String| err(StatusCode::BAD_REQUEST, "invalid", m);
    if !b.enabled {
        return Err(err(
            StatusCode::CONFLICT,
            "bootstrap_off",
            "bootstrap.enabled is false: the fleet installs no host",
        ));
    }
    let ssh_ok = !req.ssh.is_empty()
        && !req.ssh.starts_with('-')
        && req
            .ssh
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'));
    if !ssh_ok {
        return Err(invalid(format!(
            "ssh {:?}: want the server's address or name",
            req.ssh
        )));
    }
    let address = if req.address.is_empty() {
        req.ssh.clone()
    } else {
        req.address.clone()
    };
    let ip: std::net::Ipv4Addr = address.parse().map_err(|_| {
        invalid(format!(
            "address {address:?}: want the API's IPv4 address (its private one when it has one)"
        ))
    })?;
    let url = bootstrap::host_url(&ip.to_string());
    if address != req.ssh && bootstrap::private_address(b, &url).is_none() {
        return Err(invalid(format!(
            "address {address} is not in bootstrap.private_network ({:?}): an API apart from the SSH address lives on the private network",
            b.private_network
        )));
    }
    let id = if req.id.is_empty() {
        format!("h_{}", ip.to_string().replace(['.', ':'], "-"))
    } else {
        req.id
    };
    if !api::valid_id(&id) {
        return Err(invalid(format!("id {id:?}: a-z, 0-9, _ and -")));
    }
    let public_tcp_ports = Some(
        req.public_tcp_ports
            .unwrap_or_else(|| b.public_tcp_ports.clone()),
    );
    if public_tcp_ports.iter().flatten().any(|&p| p == 0) {
        return Err(invalid("public_tcp_ports: 0 is not a port".into()));
    }
    Ok(HostRec {
        id,
        url,
        ssh: if address == req.ssh {
            String::new()
        } else {
            req.ssh
        },
        token: bootstrap::new_token(),
        tls_fingerprint: String::new(),
        region: req.region,
        provider: "manual".into(),
        state: "provisioning".into(),
        capacity: Default::default(),
        used: Default::default(),
        machines: 0,
        tenants: vec![],
        last_seen: now,
        version: String::new(),
        disk_free_mb: 0,
        note: "added; waiting for the bootstrap".into(),
        bootstrap_attempts: 0,
        public_tcp_ports,
        conditions: vec![],
        started: Default::default(),
        pool_key: Default::default(),
        unknown: Default::default(),
        holds: Vec::new(),
    })
}

/// Takes nothing new on a host and forgets it once nothing runs on it: at once when it is
/// already empty, else from `forget_retired` as soon as it is. The server is the operator's to
/// give back (ADR 0042).
async fn retire_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    let host = {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(&id) {
            Some(h) if h.state == "upgrading" => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "conflict",
                    format!("host {id} is upgrading"),
                ))
            }
            Some(h) => {
                if matches!(h.state.as_str(), "ready" | "draining" | "down") {
                    h.state = "retiring".into();
                }
                h.clone()
            }
            None => return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found")),
        }
    };
    let empty = host.machines == 0 && host.tenants.is_empty();
    if empty || host.state != "retiring" {
        return Ok(Json(retired(&st, &host).await.map_err(registry_error)?).into_response());
    }
    st.save().await.map_err(registry_error)?;
    tracing::info!(
        host = id,
        machines = host.machines,
        "host retiring; forgotten once empty"
    );
    Ok(Json(host.to_api()).into_response())
}

/// Forgets a retired host: `retired` in the answer.
async fn retired(st: &AppState, h: &HostRec) -> Result<api::Host> {
    tracing::warn!(host = h.id, "host retired");
    st.reg.lock().unwrap().forget(&h.id);
    st.save().await?;
    let mut out = h.to_api();
    out.state = "retired".into();
    Ok(out)
}

/// What a forget of a host that holds a pool key costs, said by its refusal and by `force`.
const FORGET_KEYED: &str =
    "its pool key leaves the record and is kept only for its backups: the pool is unreadable at the host's next restart; retire it, or --force";

#[derive(serde::Deserialize, Default)]
struct ForgetQuery {
    #[serde(default)]
    force: bool,
}

/// Forgets a host. One whose record holds a pool key is refused unless `force`: the key goes
/// with the record (ADR 0026), and a static host polled back gets a new one its pool does not
/// open. Retiring a host forgets it once empty, on purpose.
async fn forget_host(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<ForgetQuery>,
) -> Result<Response, Refusal> {
    {
        let mut reg = st.reg.lock().unwrap();
        let keyed = reg.hosts.get(&id).is_some_and(|h| !h.pool_key.is_empty());
        if keyed && !q.force {
            return Err(err(
                StatusCode::CONFLICT,
                "pool_key",
                format!("host {id}: {FORGET_KEYED}"),
            ));
        }
        if keyed {
            tracing::warn!(
                host = id,
                "host forgotten with its pool key: {FORGET_KEYED}"
            );
        }
        reg.forget(&id);
    }
    st.save().await.map_err(registry_error)?;
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
            rec.started = s.started;
            st.reg.lock().unwrap().heartbeat(rec, now);
        } else if h.capacity.memory_mb == 0 {
            // Never answered yet (it may be starting with us): ask again soon.
            unseen = true;
        }
    }
    st.reg.lock().unwrap().sweep(&st.policy, Utc::now());
    // A background task: a failed write is logged by `save`, and the next round writes again.
    let _ = st.save().await;
    unseen
}

/// Every minute: forgets the retiring hosts that have emptied.
async fn forget_retired(st: Arc<AppState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let retirable = st.reg.lock().unwrap().retirable();
        for h in retirable {
            // A failed write is logged by `save`; the next pass writes again.
            let _ = retired(&st, &h).await;
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
        Ok(resp) => relay(resp, host).await,
        Err(e) => unreachable_host(host, e),
    }
}

/// A host's answer as the fleet's: its status, body, content type and request id, and the
/// host's id.
async fn relay(resp: reqwest::Response, host: &HostRec) -> Response {
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
    out.headers_mut()
        .insert("x-briqyard-host", host_header(host));
    out
}

fn host_header(host: &HostRec) -> HeaderValue {
    HeaderValue::from_str(&host.id).unwrap_or(HeaderValue::from_static("?"))
}

/// A host that did not answer: its id and why, never the URL (a session's query holds its env).
fn unreachable_host(host: &HostRec, e: reqwest::Error) -> Response {
    err(
        StatusCode::BAD_GATEWAY,
        "host_unreachable",
        format!("host {}: {}", host.id, causes(&e.without_url())),
    )
    .into_response()
}

/// The headers of a WebSocket handshake, passed through both ways as they are.
const UPGRADE_HEADERS: [header::HeaderName; 7] = [
    header::CONNECTION,
    header::UPGRADE,
    header::SEC_WEBSOCKET_KEY,
    header::SEC_WEBSOCKET_VERSION,
    header::SEC_WEBSOCKET_PROTOCOL,
    header::SEC_WEBSOCKET_EXTENSIONS,
    header::SEC_WEBSOCKET_ACCEPT,
];

/// An exec session (ADR 0029) forwarded unchanged: the client's handshake goes to the
/// machine's host with the host's token; the host's `101` comes back, and from then on the
/// bytes are copied both ways until either side closes. Any other answer is relayed as it is.
async fn exec_session(
    State(st): S,
    Path(id): Path<String>,
    mut req: Request,
) -> Result<Response, Refusal> {
    let client = req
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>()
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("a session is a WebSocket upgrade of GET /v1/machines/{id}/exec"),
            )
        })?;
    let host = locate(&st, Indexed::Machine, &id)
        .await
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "machine not found"))?;
    if let Some(refused) = down(&host) {
        return Ok(refused);
    }
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let mut to = to_host(&st, &host, Method::GET, &path, req.headers())?;
    for h in &UPGRADE_HEADERS {
        if let Some(v) = req.headers().get(h) {
            to = to.header(h, v);
        }
    }
    let resp = match to.send().await {
        Ok(r) => r,
        Err(e) => return Ok(unreachable_host(&host, e)),
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(relay(resp, &host).await);
    }
    let mut out = Response::new(Body::empty());
    *out.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    for h in &UPGRADE_HEADERS {
        if let Some(v) = resp.headers().get(h) {
            out.headers_mut().insert(h, v.clone());
        }
    }
    out.headers_mut()
        .insert("x-briqyard-host", host_header(&host));
    let machine = id.clone();
    tokio::spawn(async move {
        let (client, upstream) = match (client.await, resp.upgrade().await) {
            (Ok(c), Ok(u)) => (c, u),
            (c, u) => {
                let why = c
                    .err()
                    .map(|e| e.to_string())
                    .or(u.err().map(|e| causes(&e.without_url())));
                tracing::warn!(machine, err = why.unwrap_or_default(), "session upgrade");
                return;
            }
        };
        let mut client = hyper_util::rt::TokioIo::new(client);
        let mut upstream = upstream;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    Ok(out)
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
            out.headers_mut()
                .insert("x-briqyard-host", host_header(host));
            out
        }
        Err(e) => unreachable_host(host, e),
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

/// A create's hold on its host (ADR 0044) while the request lasts: `made` once the host made
/// the machine; dropped otherwise, the hold given back. A refusal, no answer and a caller that
/// hung up (its handler dropped mid-forward) all end here.
struct Held<'a> {
    st: &'a AppState,
    host: String,
    id: u64,
}

impl Held<'_> {
    fn made(mut self) {
        self.st
            .reg
            .lock()
            .unwrap()
            .made(&self.host, self.id, Utc::now());
        // Ids start at 1: nothing left to release.
        self.id = 0;
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.st.reg.lock() {
            reg.release(&self.host, self.id);
        }
    }
}

async fn create_machine(
    State(st): S,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let req: api::CreateMachineRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    let ask = Ask {
        tenant: &req.tenant,
        region: &req.region,
        memory_mb: req.size.memory_mb,
        disk_mb: disk_need(req.volume.as_ref().map(|v| v.size_gb)),
        what: "machine",
    };
    let (host, first, hold) = {
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
        refuse_under_pressure(&st, &reg, bound.as_deref(), &ask)?;
        let chosen = source.or_else(|| {
            reg.place(
                &req.tenant,
                &req.region,
                ask.memory_mb,
                ask.disk_mb,
                &st.policy,
            )
        });
        let Some(host) = chosen.and_then(|id| reg.hosts.get(&id).cloned()) else {
            return Err(no_room(&st, &reg, &ask));
        };
        let id = reg.hold(&host.id, ask.memory_mb, ask.disk_mb);
        (host, first, id)
    };
    let hold = Held {
        st: &st,
        host: host.id.clone(),
        id: hold,
    };
    // The pin is written before the host makes anything: a fleet restarted after the create
    // still sends the tenant's next machine there.
    st.save().await.map_err(registry_error)?;
    // A restore may ask for its backup's key while this forward lasts (ADR 0035).
    let restoring = req
        .restore
        .as_ref()
        .map(|rs| st.restores.open(&host.id, rs, std::time::Instant::now()));
    let resp = forward(&st, &host, Method::POST, "/v1/machines", &headers, body).await;
    if let Some(f) = restoring {
        st.restores.close(f);
    }
    let (parts, data) = read(resp).await;
    if parts.status.is_success() {
        hold.made();
        if let Ok(m) = serde_json::from_slice::<api::Machine>(&data) {
            st.reg
                .lock()
                .unwrap()
                .machines
                .insert(m.id, host.id.clone());
        }
        // The machine exists: its answer is the caller's, whatever this write does.
        st.save_after_host().await;
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    drop(hold);
    first_refused(&st, &req.tenant, first, &data).await;
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

/// What a placement asks for: what a refusal counts and logs.
struct Ask<'a> {
    tenant: &'a str,
    region: &'a str,
    memory_mb: u32,
    disk_mb: u64,
    /// `machine`, `gateway`, `quota`: for the refusal's message.
    what: &'a str,
}

/// No host (of the region asked) with room for a new tenant's machine: 503 `capacity`, which a
/// caller tries again later, counted by what ran out.
fn no_room(st: &AppState, reg: &Registry, ask: &Ask) -> Refusal {
    let hosts = match ask.region {
        "" => "no host".to_string(),
        r => format!("no host in region {r}"),
    };
    let resource = reg.shortage(ask.region, ask.memory_mb, ask.disk_mb, &st.policy);
    unschedulable(st, reg, ask.region, resource, ask, None);
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "capacity",
        format!("{hosts} has room for this {}", ask.what),
    )
}

/// A create on a host that takes nothing new while a condition is true (ADR 0021): a pinned
/// tenant's host, or a fork's source's. 503 `capacity`, which a caller tries again later,
/// counted as `pressure` in the host's region.
fn refuse_under_pressure(
    st: &AppState,
    reg: &Registry,
    host: Option<&str>,
    ask: &Ask,
) -> Result<(), Refusal> {
    let Some(h) = host.and_then(|id| reg.hosts.get(id)) else {
        return Ok(());
    };
    match h.pressure() {
        Some(why) => {
            unschedulable(st, reg, &h.region, Resource::Pressure, ask, Some(&h.id));
            Err(err(StatusCode::SERVICE_UNAVAILABLE, "capacity", why))
        }
        None => Ok(()),
    }
}

/// Counts a create refused for want of room and logs it at `warn` (ADR 0042): what ran out, in
/// which region (the host's, or the one asked), what was asked, and the most the region still
/// has on one host.
fn unschedulable(
    st: &AppState,
    reg: &Registry,
    region: &str,
    resource: Resource,
    ask: &Ask,
    host: Option<&str>,
) {
    st.refusals
        .count(signals::counted_region(reg, region), resource);
    // An ask of any region could have had a host of any region.
    let largest = reg
        .room(&st.policy)
        .into_iter()
        .filter(|(r, _)| region.is_empty() || r == region)
        .fold(api::Room::default(), |a, (_, (_, l))| api::Room {
            memory_mb: a.memory_mb.max(l.memory_mb),
            disk_mb: a.disk_mb.max(l.disk_mb),
        });
    tracing::warn!(
        resource = resource.as_str(),
        region,
        tenant = ask.tenant,
        host,
        memory_mb = ask.memory_mb,
        disk_mb = ask.disk_mb,
        largest_memory_mb = largest.memory_mb,
        largest_disk_mb = largest.disk_mb,
        "unschedulable"
    );
}

/// The disk a machine is placed for: root disks are thin, a volume takes what it says, plus
/// headroom.
fn disk_need(volume_gb: Option<u32>) -> u64 {
    volume_gb.map(|gb| gb as u64 * 1024).unwrap_or(0) + 2048
}

/// A host with no room for a tenant's first machine (or gateway): the pin the request made
/// goes, so a retry is placed afresh. A later one keeps it: the tenant's network is there.
async fn first_refused(st: &AppState, tenant: &str, first: bool, answer: &[u8]) {
    if first && error_code(answer) == "capacity" {
        st.reg.lock().unwrap().unpin(tenant);
        st.save_after_host().await;
    }
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

/// The backups of the hosts' machines, destroyed ones' included (ADR 0023): every host's, the
/// query as it came, never partial. A tenant's too: a host it moved from still holds the
/// backups of the machines destroyed there (ADR 0045).
async fn all_backups(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let hosts = st.reg.lock().unwrap().listed();
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

/// Usage of every host, never partial (ADR 0017): a usage report missing a host undercounts.
/// Every listed host is asked, the query as it came (the hosts check it), and
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
        st.save_after_host().await;
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
    let ask = Ask {
        tenant: id,
        region,
        memory_mb: need_mb,
        disk_mb: need_disk_mb,
        what,
    };
    let (host, first, hold) = {
        let mut reg = st.reg.lock().unwrap();
        let first = !reg.tenants.contains_key(id);
        let bound = reg.tenants.get(id).cloned();
        refuse_outside(&reg, bound.as_deref(), id, region)?;
        refuse_under_pressure(st, &reg, bound.as_deref(), &ask)?;
        let chosen = reg.place(id, region, need_mb, need_disk_mb, &st.policy);
        let Some(host) = chosen.and_then(|h| reg.hosts.get(&h).cloned()) else {
            return Err(no_room(st, &reg, &ask));
        };
        let id = reg.hold(&host.id, need_mb, need_disk_mb);
        (host, first, id)
    };
    let hold = Held {
        st,
        host: host.id.clone(),
        id: hold,
    };
    st.save().await.map_err(registry_error)?;
    let path = format!("/v1/tenants/{id}/{what}");
    let resp = forward(st, &host, Method::PUT, &path, headers, body).await;
    let (parts, data) = read(resp).await;
    if parts.status.is_success() {
        hold.made();
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    drop(hold);
    first_refused(st, id, first, &data).await;
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
    st.save().await.map_err(registry_error)?;
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

/// The host that holds the backups of a machine no host has (ADR 0045): the one whose
/// `/v1/backups?machine=` lists one of it, of `tenant` when given. Every host is asked at
/// once, a down one included, so a backup left on the host a tenant moved from is found; a
/// host that does not hold it answers from memory. With no host listing it, a host that
/// could not answer fails the search with its answer, since it may be the one. A host older
/// than the `machine` filter lists all it holds: what is not the machine's is not read.
async fn holder(
    st: &AppState,
    id: &str,
    tenant: Option<&str>,
) -> Result<Option<HostRec>, Box<Response>> {
    if !api::valid_id(id) {
        return Ok(None);
    }
    let mut path = format!("/v1/backups?machine={id}");
    if let Some(t) = tenant.filter(|t| api::valid_id(t)) {
        path.push_str(&format!("&tenant={t}"));
    }
    let hosts = st.reg.lock().unwrap().listed();
    let asked = hosts.into_iter().map(|h| {
        let path = &path;
        async move {
            let resp = forward(st, &h, Method::GET, path, &HeaderMap::new(), Bytes::new()).await;
            if !resp.status().is_success() {
                return Err(Box::new(resp));
            }
            let (_, data) = read(resp).await;
            let backups: Vec<api::Backup> =
                serde_json::from_slice(&data).map_err(|e| Box::new(unreadable(&h, e)))?;
            Ok(backups.iter().any(|b| b.machine_id == id).then_some(h))
        }
    });
    let mut failed = None;
    for answer in futures::future::join_all(asked).await {
        match answer {
            Ok(Some(h)) => return Ok(Some(h)),
            Ok(None) => {}
            Err(resp) => failed = failed.or(Some(resp)),
        }
    }
    failed.map_or(Ok(None), Err)
}

/// A host's memory and disk asked of it now, as its heartbeat would report them (ADR 0044).
/// Not answering within five seconds is nothing: the heartbeat comes.
async fn refresh(st: &AppState, host: &HostRec) {
    let asked = Utc::now();
    let status = get_json::<api::Status>(st, host, "/v1/status");
    let within = std::time::Duration::from_secs(5);
    if let Ok(Some(s)) = tokio::time::timeout(within, status).await {
        if let Some(h) = st.reg.lock().unwrap().hosts.get_mut(&host.id) {
            h.report(s.used, s.disk_free_mb, asked);
        }
    }
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
    // A destroyed machine is its backups alone (ADR 0023): reached on the host that holds
    // them, which a moved tenant left (ADR 0045).
    let host = match locate(&st, Indexed::Machine, &id).await {
        Some(h) => h,
        None if uri
            .path()
            .starts_with(&format!("/v1/machines/{id}/backups/")) =>
        {
            match holder(&st, &id, query_tenant(&uri).as_deref()).await {
                Ok(Some(h)) => h,
                Ok(None) => {
                    return Err(err(StatusCode::NOT_FOUND, "not_found", "machine not found"))
                }
                Err(answer) => return Ok(*answer),
            }
        }
        None => return Err(err(StatusCode::NOT_FOUND, "not_found", "machine not found")),
    };
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    // What the call is, by its path alone: a query (`?tenant=`) changes nothing of it.
    let own = format!("/v1/machines/{id}");
    let is_delete = method == Method::DELETE && uri.path() == own;
    let plain_get = method == Method::GET && uri.path() == own;
    let adds_endpoint = method == Method::POST && uri.path() == format!("{own}/endpoints");
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
        st.save_after_host().await;
        // What the machine held is free now, not at the host's next heartbeat (ADR 0044).
        refresh(&st, &host).await;
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
            st.save_after_host().await;
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
        st.save_after_host().await;
    }
    Ok(resp)
}

#[cfg(test)]
mod tests;
