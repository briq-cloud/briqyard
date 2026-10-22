//! briqyardd runs machines on one server.

mod api;
mod conditions;
mod config;
mod console;
mod events;
mod fc;
mod guestc;
mod heartbeat;
mod image;
mod ingress;
mod machine;
mod metrics;
mod netw;
mod poolkey;
mod session;
mod store;
mod tls;
mod usage;
mod zfs;

use anyhow::{anyhow, Context, Result};
use briqyard_objstore as objstore;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

const OPENAPI: &str = include_str!("../../../api/openapi.yaml");

#[derive(Parser)]
#[command(
    name = "briqyardd",
    version = briqyard_api::VERSION,
    about = "briqyard host daemon: machines in Firecracker microVMs"
)]
struct Args {
    /// Configuration file.
    #[arg(long, default_value = "/etc/briqyard/config.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the SHA-256 of the API's certificate, making the certificate if there is none
    /// yet; nothing when the API is plain HTTP. What the fleet pins (ADR 0020).
    TlsFingerprint,
}

fn main() {
    let args = Args::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_env("BRIQYARD_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // Logs on stderr: stdout is a subcommand's answer (`tls-fingerprint`).
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    if let Err(err) = rt.block_on(run(args)) {
        tracing::error!(err = format!("{err:#}"), "briqyardd failed");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<()> {
    let default = PathBuf::from("/etc/briqyard/config.yaml");
    let path = if args.config.exists() {
        Some(args.config.as_path())
    } else if args.config == default {
        None
    } else {
        return Err(anyhow!("config {} not found", args.config.display()));
    };
    let cfg = config::Config::load(path)?;
    if let Some(Cmd::TlsFingerprint) = args.cmd {
        if cfg.serves_tls() {
            store::private_dir(&cfg.data_dir)?;
            println!("{}", api_certificate(&cfg)?);
        }
        return Ok(());
    }
    // Nothing the daemon writes is for other users: records, config drives and consoles hold
    // tenant secrets (ADR 0014).
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    if !nix::unistd::geteuid().is_root() {
        return Err(anyhow!(
            "briqyardd must run as root (ZFS, TAP devices, nftables)"
        ));
    }
    for p in [&cfg.firecracker, &cfg.kernel, &cfg.init] {
        std::fs::metadata(p).with_context(|| p.display().to_string())?;
    }
    if !cfg.jailer.as_os_str().is_empty() {
        std::fs::metadata(&cfg.jailer).with_context(|| cfg.jailer.display().to_string())?;
    } else {
        tracing::warn!("no jailer configured: Firecracker runs as root, for development only");
    }
    store::private_dir(&cfg.data_dir)?;
    // Made before anything else listens, so a host that cannot serve its API starts nothing.
    let tls = if cfg.serves_tls() {
        let fingerprint = api_certificate(&cfg)?;
        Some((
            fingerprint,
            tls::server_config(&cfg.tls_cert(), &cfg.tls_key())?,
        ))
    } else {
        None
    };
    let fingerprint = tls.as_ref().map(|(f, _)| f.clone()).unwrap_or_default();
    // The pool is encrypted (ADR 0026) and everything of the machines is on it: its key is
    // loaded before anything of it is read, and until it is, nothing starts.
    let zfs = zfs::Zfs::new(&cfg.storage.pool).await?;
    if !poolkey::unlock(&zfs, &cfg, terminated()).await? {
        tracing::info!("stopped before the pool's key was loaded");
        return Ok(());
    }
    let mounts = cfg.pool_mounts();
    zfs.layout(
        &mounts
            .iter()
            .map(|(n, d)| (*n, d.as_path()))
            .collect::<Vec<_>>(),
    )
    .await?;
    for (_, d) in &mounts {
        store::private_dir(d)?;
    }
    let store = store::Store::open(&cfg.state_dir())?;
    let mut images = image::Builder::new(
        zfs.clone(),
        cfg.image_dir(),
        cfg.init.clone(),
        cfg.root_disk_gb,
    )?;
    images.resolve_ttl = std::time::Duration::from_secs(cfg.image_resolve_minutes as u64 * 60);
    images.registries = cfg
        .registries
        .iter()
        .map(|r| (r.host.clone(), r.username.clone(), r.password.clone()))
        .collect();
    let dns = netw::dns::Resolver::new(&cfg.network.upstream_dns);
    let mgr = machine::Manager::new(cfg.clone(), store, zfs, images, dns).await?;
    let ing = ingress::Ingress::new(
        mgr.clone(),
        &cfg.ingress.bind,
        &cfg.ingress.http,
        std::time::Duration::from_secs(cfg.boot_timeout_sec.max(10)),
    );
    ing.start().await?;
    if let Some(f) = cfg.fleet.clone() {
        if !f.url.is_empty() {
            tokio::spawn(heartbeat::run(
                f,
                cfg.token.clone(),
                fingerprint.clone(),
                mgr.clone(),
            ));
        }
    }
    {
        let gc = mgr.clone();
        let keep = chrono::Duration::days(cfg.image_keep_days as i64);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                let n = gc.gc_images(keep).await;
                if n > 0 {
                    tracing::info!(removed = n, "image gc");
                }
            }
        });
    }
    let listener = std::net::TcpListener::bind(&cfg.listen)
        .with_context(|| format!("listen {}", cfg.listen))?;
    listener.set_nonblocking(true)?;
    let state = Arc::new(api::AppState {
        mgr: mgr.clone(),
        token: cfg.token.clone(),
        metrics_token: cfg.metrics_token.clone(),
        loopback: listener.local_addr()?.ip().is_loopback(),
        openapi: OPENAPI,
        tls_fingerprint: fingerprint.clone(),
    });
    tracing::info!(
        addr = cfg.listen,
        tls_fingerprint = fingerprint,
        version = briqyard_api::VERSION,
        host_id = mgr.host_id(),
        pool = cfg.storage.pool,
        "briqyardd listening"
    );
    let handle = axum_server::Handle::new();
    // SIGTERM (a stop, a reboot) suspends the machines; SIGUSR2 (an upgrade) leaves them
    // running for the next daemon to adopt (ADR 0027).
    let hand_over = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (handle, hand_over) = (handle.clone(), hand_over.clone());
        let watches = mgr.events().clone();
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut usr2 = signal(SignalKind::user_defined2())?;
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
                _ = usr2.recv() => hand_over.store(true, std::sync::atomic::Ordering::SeqCst),
            }
            tracing::info!("shutting down");
            // A watch never ends on its own: the server would wait for it. A request still
            // running after the grace (a long exec) is cut: the machines come first.
            watches.close();
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
    }
    let app = api::router(state).into_make_service();
    match tls {
        Some((_, server)) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server));
            axum_server::from_tcp_rustls(listener, config)
                .handle(handle)
                .serve(app)
                .await?
        }
        None => {
            axum_server::from_tcp(listener)
                .handle(handle)
                .serve(app)
                .await?
        }
    }
    let down = async {
        match hand_over.load(std::sync::atomic::Ordering::SeqCst) {
            true => Some(mgr.hand_over().await),
            false => {
                mgr.close().await;
                None
            }
        }
    };
    let held = match tokio::time::timeout(std::time::Duration::from_secs(60), down).await {
        Ok(held) => held,
        Err(_) => {
            // What was not done by then: the next daemon finds those machines as a crash
            // leaves them.
            tracing::warn!(
                hand_over = hand_over.load(std::sync::atomic::Ordering::SeqCst),
                "the shutdown ran past 60 s: ending without it"
            );
            None
        }
    };
    if held.is_some() {
        // A hand-over ends the process here, every machine's lock held: no transition begins
        // in what is left of it (ADR 0027).
        tracing::info!("handed over");
        std::process::exit(0);
    }
    Ok(())
}

/// Resolves at SIGINT or SIGTERM.
async fn terminated() {
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// The API's certificate, made on the first call, and its fingerprint.
fn api_certificate(cfg: &config::Config) -> Result<String> {
    tls::ensure(&cfg.tls_cert(), &cfg.tls_key(), &cfg.tls_names())
}
