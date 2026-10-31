//! briqyardd runs machines on one server.

use briqyardd::{api, config, heartbeat, image, ingress, machine, netw, poolkey, store, tls, zfs};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

/// jemalloc: freed memory goes back to the system after a few seconds, so the daemon's RSS
/// follows what it holds rather than its peak (ADR 0052).
#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const OPENAPI: &str = briqyard_api::OPENAPI;

/// What a stop or a hand-over gives the API's requests and the endpoint connections in
/// flight, one bound for both (ADR 0051): what arrives meanwhile waits in the kernel's queue
/// for the next daemon, so the bound is paid by every waiting client whenever a connection
/// that never ends on its own (a pool, a WebSocket) is open. Long enough for a short request.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a stop or a hand-over may take in all.
const SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// The exit status of a hand-over: the unit restarts on it (`RestartForceExitStatus=`) and
/// counts it a success (`SuccessExitStatus=`), and systemd keeps its store across a restart.
const HANDED_OVER: i32 = 75;

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
    one_malloc_arena();
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

/// One arena for what still goes through glibc's malloc: libc's own allocations (a thread's
/// TLS destructors, for one). glibc gives each thread that allocates an arena of its own, up to
/// 8 per core, and keeps every one, each at least a 2 MB huge page; tokio's blocking pool
/// starts threads all the time, so the arenas followed the peak of threads and stayed (ADR
/// 0052). Before the runtime starts any thread.
fn one_malloc_arena() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: a setting of the C allocator, made while this is the only thread.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
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
    let began = std::time::Instant::now();
    let cfg = config::Config::load(path)?;
    if let Some(Cmd::TlsFingerprint) = args.cmd {
        if cfg.serves_tls() {
            store::private_dir(&cfg.data_dir)?;
            println!("{}", api_certificate(&cfg)?);
        }
        return Ok(());
    }
    // Nothing the daemon writes is for other users: records, config drives and consoles hold
    // namespace secrets (ADR 0014).
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
    let pool_ms = began.elapsed().as_millis() as u64;
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
        cfg.mirrors()?,
    )?;
    images.resolve_ttl = std::time::Duration::from_secs(cfg.image_resolve_minutes as u64 * 60);
    images.registries = cfg
        .registries
        .iter()
        .map(|r| (r.host.clone(), r.username.clone(), r.password.clone()))
        .collect();
    let dns = netw::dns::Resolver::new(&cfg.network.upstream_dns);
    let mgr = machine::Manager::new(cfg.clone(), store, zfs, images, dns).await?;
    let adopted_ms = began.elapsed().as_millis() as u64;
    // The listeners the previous daemon left in systemd's store (ADR 0051).
    let listeners = Arc::new(briqyard_api::listeners::Listeners::from_env());
    let ing = ingress::Ingress::new(
        mgr.clone(),
        &cfg.ingress.bind,
        &cfg.ingress.http,
        std::time::Duration::from_secs(cfg.boot_timeout_sec.max(10)),
        listeners.clone(),
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
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&cfg.listen)
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| anyhow!("listen {}: want address:port", cfg.listen))?;
    let listener = listeners
        .tcp("api", addr)
        .with_context(|| format!("listen {}", cfg.listen))?;
    listener.set_nonblocking(true)?;
    match listeners.release_unused() {
        Ok(gone) if !gone.is_empty() => tracing::info!(?gone, "listeners no longer used, closed"),
        Ok(_) => {}
        Err(e) => tracing::warn!(err = %e, "listeners no longer used left in the store"),
    }
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
    // What a client saw of the hand-over that started this daemon: from the previous one's
    // signal to now, and what this start spent.
    if let Some(gap_ms) = gap_since_hand_over(&cfg) {
        tracing::info!(
            gap_ms,
            pool_ms,
            adopted_ms,
            serving_ms = began.elapsed().as_millis() as u64,
            "serving again"
        );
    }
    let handle = axum_server::Handle::new();
    let app = api::router(state).into_make_service();
    let mut server = {
        let handle = handle.clone();
        tokio::spawn(async move {
            match tls {
                Some((_, server)) => {
                    let config =
                        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server));
                    axum_server::from_tcp_rustls(listener, config)
                        .handle(handle)
                        .serve(app)
                        .await
                }
                None => {
                    axum_server::from_tcp(listener)
                        .handle(handle)
                        .serve(app)
                        .await
                }
            }
        })
    };
    // SIGTERM (a stop, a reboot) suspends the machines; SIGUSR2 (an upgrade) leaves them
    // running for the next daemon to adopt (ADR 0027).
    let hand_over = {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut usr2 = signal(SignalKind::user_defined2())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => false,
            _ = term.recv() => false,
            _ = usr2.recv() => true,
            served = &mut server => {
                served??;
                return Err(anyhow!("the API stopped serving"));
            }
        }
    };
    tracing::info!(hand_over, "shutting down");
    let deadline = tokio::time::Instant::now() + DRAIN;
    if hand_over {
        mark_hand_over(&cfg);
    }
    // Nothing is accepted from here: the listeners stay in systemd's store, so what arrives
    // waits for the next daemon. A watch never ends on its own: the server would wait for it.
    // A request or a connection still open after the drain (a long exec, a WebSocket) is cut:
    // the machines come first.
    ing.stop_accepting();
    mgr.close_backup_admission();
    mgr.events().close();
    handle.graceful_shutdown(Some(DRAIN));
    let drain = async {
        // The API's requests in flight end, or are cut at the drain's end.
        match server.await {
            Ok(Err(e)) => tracing::warn!(err = %e, "the API's last requests"),
            Err(e) => tracing::warn!(err = %e, "the API's task"),
            Ok(Ok(())) => {}
        }
        let cut = ing.drain(deadline).await;
        if cut > 0 {
            tracing::info!(
                connections = cut,
                "endpoint connections cut at the drain's end"
            );
        }
    };
    let down = async {
        if hand_over {
            // The machines' locks are taken while the connections drain (ADR 0051): the gap
            // is the longer of the two, not their sum. The usage is written again once the
            // connections are done, with what they passed meanwhile.
            let (held, ()) = tokio::join!(mgr.hand_over(), drain);
            mgr.write_usage().await;
            Some(held)
        } else {
            // A stop drains first: suspending the machines would end the connections.
            drain.await;
            mgr.close().await;
            None
        }
    };
    let held = match tokio::time::timeout(SHUTDOWN, down).await {
        Ok(held) => held,
        Err(_) => {
            // What was not done by then: the next daemon finds those machines as a crash
            // leaves them.
            tracing::warn!(hand_over, "the shutdown ran past 60 s: ending without it");
            None
        }
    };
    if hand_over {
        // A hand-over ends the process here, every machine's lock held when it got them: no
        // transition begins in what is left of it (ADR 0027). Its status has the unit start
        // the next daemon at once, which keeps the listeners in systemd's store (ADR 0051).
        if held.is_some() {
            tracing::info!("handed over");
        }
        std::process::exit(HANDED_OVER);
    }
    Ok(())
}

/// Where a hand-over leaves the time of its signal for the next daemon's `serving again`.
fn hand_over_mark(cfg: &config::Config) -> PathBuf {
    cfg.run_dir().join("handed-over-at")
}

fn mark_hand_over(cfg: &config::Config) {
    let now = chrono::Utc::now().timestamp_millis().to_string();
    if let Err(e) = std::fs::write(hand_over_mark(cfg), now) {
        tracing::warn!(err = %e, "the hand-over's time not written");
    }
}

/// The milliseconds since the hand-over that started this daemon, read once.
fn gap_since_hand_over(cfg: &config::Config) -> Option<i64> {
    let path = hand_over_mark(cfg);
    let at: i64 = std::fs::read_to_string(&path).ok()?.trim().parse().ok()?;
    let _ = std::fs::remove_file(&path);
    Some(chrono::Utc::now().timestamp_millis() - at)
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
