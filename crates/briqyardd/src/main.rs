//! briqyardd runs machines on one server.

mod api;
mod config;
mod events;
mod fc;
mod guestc;
mod heartbeat;
mod image;
mod ingress;
mod machine;
mod netw;
mod objstore;
mod store;
mod usage;
mod zfs;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

const OPENAPI: &str = include_str!("../../../api/openapi.yaml");

#[derive(Parser)]
#[command(
    name = "briqyardd",
    version,
    about = "briqyard host daemon: machines in Firecracker microVMs"
)]
struct Args {
    /// Configuration file.
    #[arg(long, default_value = "/etc/briqyard/config.yaml")]
    config: PathBuf,
}

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
    let store = store::Store::open(&cfg.state_dir())?;
    let zfs = zfs::Zfs::new(&cfg.storage.pool, &cfg.jail_base()).await?;
    for d in [cfg.jail_base(), cfg.run_dir()] {
        store::private_dir(&d)?;
    }
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
            tokio::spawn(heartbeat::run(f, cfg.token.clone(), mgr.clone()));
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
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("listen {}", cfg.listen))?;
    let state = Arc::new(api::AppState {
        mgr: mgr.clone(),
        token: cfg.token.clone(),
        metrics_token: cfg.metrics_token.clone(),
        loopback: listener.local_addr()?.ip().is_loopback(),
        openapi: OPENAPI,
    });
    tracing::info!(
        addr = cfg.listen,
        version = env!("CARGO_PKG_VERSION"),
        host_id = mgr.host_id(),
        pool = cfg.storage.pool,
        "briqyardd listening"
    );
    let watches = mgr.events().clone();
    let shutdown = async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        tracing::info!("shutting down");
        // A watch never ends on its own: the server would wait for it.
        watches.close();
    };
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(60), mgr.close())
        .await
        .ok();
    Ok(())
}
