//! briqyard-fleet: the briqyard API across several hosts. Each namespace lives on one host; the
//! fleet places new namespaces, forwards every machine request to the right daemon, keeps the
//! registry of hosts from their heartbeats, and bootstraps the servers added to it. It buys no
//! server: it says what ran out (ADR 0042), and something outside adds hosts.

mod backup;
mod bootstrap;
mod config;
mod create;
mod create_replay;
mod forward;
mod hosts;
mod join;
mod lists;
mod locate;
mod moves;
mod namespaces;
mod registry;
mod restores;
mod scrape;
mod signals;
mod upgrade;
mod warm;

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

use create::*;
use forward::*;
use hosts::*;
use join::*;
use lists::*;
use locate::*;
use namespaces::*;
use warm::*;

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
    /// How long a host has to answer a list built from several (`LIST_TIMEOUT`).
    list_timeout: std::time::Duration,
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
/// What a host is given to answer a list the fleet puts together from several hosts: one that
/// takes longer is listed as unreachable, so a single host never holds the list.
const LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
        egress_siblings_v1: false,
        named_memory_fork_v1: false,
        named_memory_profiles: Vec::new(),
        warm_pool_profiles: Vec::new(),
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
        namespaces: vec![],
        last_seen: now,
        version: String::new(),
        disk_free_mb: 0,
        note: String::new(),
        bootstrap_attempts: 0,
        public_tcp_ports: None,
        conditions: vec![],
        started: Default::default(),
        pool_key: Default::default(),
        labels: Default::default(),
        join_token: String::new(),
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
        require_egress_siblings: false,
        require_named_memory: false,
        named_memory_profile: "init-ready-v1".into(),
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
        list_timeout: LIST_TIMEOUT,
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
        "restored {} hosts ({keys} pool keys, {} retired) and {} namespaces from {from} into {}\n",
        reg.hosts.len(),
        reg.retired_keys.len(),
        reg.namespaces.len(),
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
        .route(&format!("{prefix}/:id/warm-pools"), get(warm_pools))
        .route(&format!("{prefix}/:id/warm-catalog"), get(warm_catalog))
        .route(
            &format!("{prefix}/:id/warm-catalog/:entry"),
            put(put_warm_catalog),
        )
        .route(
            &format!("{prefix}/:id/warm-pools/:name"),
            put(put_warm_pool).delete(delete_warm_pool),
        )
        .route(
            &format!("{prefix}/:id/warm-pools/:name/claims"),
            post(claim_warm_pool),
        )
        .route(&format!("{prefix}/:id/unpin"), post(unpin_namespace))
}

fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/metrics", get(metrics))
        .route("/v1/metrics/targets", get(scrape::targets))
        .route("/v1/status", get(status))
        .route("/v1/hosts", get(list_hosts).post(add_host))
        .route("/v1/hosts/register", post(register_host))
        .route("/v1/hosts/key", post(host_key))
        .route("/v1/hosts/join", post(join_host))
        .route("/v1/hosts/tokens", get(list_tokens).post(create_token))
        .route("/v1/hosts/tokens/:id", axum::routing::delete(revoke_token))
        .route("/install.sh", get(install_script))
        .route("/bootstrap-host.sh", get(bootstrap_script))
        .route("/v1/hosts/:id/drain", post(drain_host))
        .route("/v1/hosts/:id/undrain", post(undrain_host))
        .route("/v1/hosts/:id/upgrade", post(upgrade::upgrade_host))
        .route("/v1/hosts/:id/retire", post(retire_host))
        .route("/v1/hosts/:id/metrics", get(scrape::host_metrics))
        .route("/v1/hosts/:id", axum::routing::delete(forget_host))
        .route("/v1/machines", get(list_machines).post(create_machine))
        .route("/v1/endpoints", get(list_endpoints))
        .route("/v1/usage", get(usage))
        .route("/v1/backups", get(all_backups))
        .route("/v1/top", get(top))
        .route("/v1/events", get(events))
        .merge(namespace_routes("/v1/namespaces"))
        // The former name (ADR 0055), answered until the control plane has moved.
        .merge(namespace_routes("/v1/tenants"))
        .route("/v1/machines/:id", any(by_machine))
        // Backups live in a store every host shares: the listing goes to any host, even for
        // a machine that no longer exists anywhere; making one goes to the machine's host.
        .route(
            "/v1/machines/:id/backups",
            get(list_backups).post(by_machine),
        )
        // A session (ADR 0029) is a WebSocket: relayed as bytes once both sides upgraded.
        .route("/v1/machines/:id/exec", get(exec_session).post(by_machine))
        .route(
            "/v1/machines/:id/files/content",
            get(forward::file_stream).put(forward::file_stream),
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

/// The tokens that open a client's path (none set: open). A scraper's path (ADR 0054) takes
/// the metrics token, so a scraper never holds the API's, or the API's, which reads as much
/// elsewhere; none there on a loopback listener with nothing in front (`tls` unset), as the
/// daemon's (ADR 0021). Any other path, the API's.
fn tokens_for<'a>(cfg: &'a config::Config, path: &str) -> Vec<&'a str> {
    let tokens = match scrape::is_metrics(path) {
        true if cfg.tls == config::Tls::Unset => vec![],
        true => vec![cfg.metrics_token.as_str(), cfg.token.as_str()],
        false => vec![cfg.token.as_str()],
    };
    tokens.into_iter().filter(|t| !t.is_empty()).collect()
}

async fn auth(State(st): S, req: Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path().to_string();
    // A heartbeat and a key request present the host's own token, checked against its record
    // by the handler; a join presents a join token, and the scripts hold no secret (ADR 0059).
    let open = matches!(
        path.as_str(),
        "/healthz"
            | "/v1/hosts/register"
            | "/v1/hosts/key"
            | "/v1/hosts/join"
            | "/install.sh"
            | "/bootstrap-host.sh"
    );
    let tokens = tokens_for(&st.cfg, &path);
    let got = bearer(req.headers()).as_bytes();
    if !open && !tokens.is_empty() && !tokens.iter().any(|t| api::constant_eq(got, t.as_bytes())) {
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

#[cfg(test)]
mod tests;

/// A test binary ends with its parent, and in bounded time (briqyard-testing).
#[cfg(test)]
#[ctor::ctor(unsafe)]
fn exit_with_parent() {
    briqyard_testing::exit_with_parent();
}
