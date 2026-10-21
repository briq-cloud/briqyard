//! The pool's key (ADR 0026). The pool is encrypted from its creation; after a reboot its key
//! is not loaded, and the daemon loads it before it reads or mounts anything of the pool:
//! asked of the fleet with the host's own token, or read from a file on a single host. The key
//! goes from its source to `zfs load-key`'s stdin: never in a log, a record or a file of ours.

use crate::config::{Config, KeySource};
use crate::zfs::{Key, Zfs};
use anyhow::{bail, Context, Result};
use briqyard_api as api;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

/// Makes sure the pool's key is loaded: nothing to do when it is, else loaded from its source,
/// tried again (5 s, doubling to a minute) until it is, or until `stop` resolves (`false`).
/// A pool that is not encrypted is refused.
pub async fn unlock(zfs: &Zfs, cfg: &Config, stop: impl Future<Output = ()>) -> Result<bool> {
    let pool = &cfg.storage.pool;
    let root = match zfs.key().await? {
        Key::None => bail!(
            "pool {pool} is not encrypted: every host's pool is (ADR 0026); \
             hack/bootstrap-host.sh creates it so"
        ),
        Key::Loaded => return Ok(true),
        Key::Locked { root } => root,
    };
    let source = cfg.key_source()?;
    let from = match &source {
        KeySource::Fleet { .. } => "fleet".to_string(),
        KeySource::File(p) => p.display().to_string(),
    };
    tokio::pin!(stop);
    let mut wait = Duration::from_secs(5);
    loop {
        match load(zfs, &source, &root).await {
            Ok(()) => {
                tracing::info!(pool, root, from, "pool key loaded");
                return Ok(true);
            }
            Err(e) => tracing::error!(
                pool,
                from,
                err = format!("{e:#}"),
                retry_in_sec = wait.as_secs(),
                "pool locked: its key could not be loaded, and nothing starts until it is"
            ),
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = &mut stop => return Ok(false),
        }
        wait = (wait * 2).min(Duration::from_secs(60));
    }
}

/// One try: the key from its source, checked, loaded on the encryption root.
async fn load(zfs: &Zfs, source: &KeySource, root: &str) -> Result<()> {
    let key = match source {
        KeySource::Fleet {
            url,
            advertise,
            token,
        } => from_fleet(url, advertise, token).await?,
        KeySource::File(p) => from_file(p)?,
    };
    check(&key)?;
    zfs.load_key(root, &key).await
}

/// A pool key is ZFS's `hex` format: 32 bytes as 64 hex digits. What is wrong is said
/// without the value.
fn check(key: &str) -> Result<()> {
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "the key is not 64 hex digits ({} characters)",
            key.chars().count()
        );
    }
    Ok(())
}

fn from_file(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text.trim().to_string())
}

/// `POST /v1/hosts/key` on the fleet, with the host's token, for the record at its address:
/// the fleet serves a host its own key and nobody else's.
async fn from_fleet(fleet: &str, advertise: &str, token: &str) -> Result<String> {
    let url = format!("{}/v1/hosts/key", fleet.trim_end_matches('/'));
    let resp = crate::heartbeat::client()
        .post(&url)
        .bearer_auth(token)
        .json(&api::HostKeyRequest {
            url: advertise.to_string(),
        })
        .send()
        .await
        .with_context(|| format!("ask {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let why = resp
            .json::<api::ApiError>()
            .await
            .map(|e| format!("{}: {}", e.code, e.error))
            .unwrap_or_default();
        bail!("{url} answered {status} {why}");
    }
    let key: api::HostKey = resp
        .json()
        .await
        .with_context(|| format!("read {url}'s answer"))?;
    Ok(key.key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::fake::Scripts;
    use axum::extract::Json;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;

    fn key() -> String {
        "0123456789abcdef".repeat(4)
    }

    /// A pool locked with `key()`.
    async fn locked() -> (Scripts, Zfs) {
        let s = Scripts::new();
        s.answer("keystatus", "unavailable\n");
        s.answer("encryptionroot", "byard\n");
        std::fs::write(s.dev.join("key"), key()).unwrap();
        let zfs = s.pool("byard").await.unwrap();
        (s, zfs)
    }

    fn with_file(path: &Path) -> Config {
        let mut cfg = Config::default();
        cfg.storage.key = format!("file:{}", path.display());
        cfg
    }

    /// A stand-in for the fleet's key route: `key()` for the bearer `host-token` asking for
    /// `http://10.0.0.5:7420`, refused otherwise.
    async fn fleet() -> String {
        async fn serve(
            headers: HeaderMap,
            Json(req): Json<api::HostKeyRequest>,
        ) -> Result<Json<api::HostKey>, StatusCode> {
            let bearer = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if bearer != "Bearer host-token" || req.url != "http://10.0.0.5:7420" {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Json(api::HostKey { key: key() }))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/v1/hosts/key", post(serve));
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    fn with_fleet(url: &str, token: &str) -> Config {
        let mut cfg = Config::default();
        cfg.storage.key = "fleet".into();
        cfg.token = token.into();
        cfg.fleet = Some(crate::config::FleetClient {
            url: url.into(),
            advertise: "http://10.0.0.5:7420".into(),
            region: String::new(),
        });
        cfg
    }

    #[tokio::test]
    async fn a_pool_that_is_not_encrypted_is_refused() {
        let (s, zfs) = locked().await;
        s.answer("keystatus", "-\n");
        let err = unlock(&zfs, &Config::default(), std::future::pending())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not encrypted"), "{err:#}");
    }

    /// A loaded key (a daemon restarted, not the host) needs no source: nothing is read.
    #[tokio::test]
    async fn a_loaded_key_is_left_alone() {
        let (s, zfs) = locked().await;
        s.answer("keystatus", "available\n");
        let cfg = with_file(Path::new("/nonexistent/pool.key"));
        assert!(unlock(&zfs, &cfg, std::future::pending()).await.unwrap());
    }

    #[tokio::test]
    async fn the_key_is_loaded_from_a_file() {
        let (_s, zfs) = locked().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.key");
        std::fs::write(&path, format!("{}\n", key())).unwrap();
        assert!(unlock(&zfs, &with_file(&path), std::future::pending())
            .await
            .unwrap());
        assert_eq!(zfs.key().await.unwrap(), Key::Loaded);
    }

    /// Each way a try fails says what failed, never the key.
    #[tokio::test]
    async fn a_failed_try_says_why() {
        let (_s, zfs) = locked().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.key");
        let source = KeySource::File(path.clone());
        let err = load(&zfs, &source, "byard").await.unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("read {}", path.display())),
            "{err:#}"
        );
        std::fs::write(&path, "not-a-key-but-a-secret").unwrap();
        let err = load(&zfs, &source, "byard").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not 64 hex digits") && !msg.contains("secret"),
            "{msg}"
        );
        std::fs::write(&path, "f".repeat(64)).unwrap();
        let err = load(&zfs, &source, "byard").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Incorrect key") && !msg.contains(&"f".repeat(64)),
            "{msg}"
        );
        assert_ne!(zfs.key().await.unwrap(), Key::Loaded);
    }

    /// Told to stop while it waits for its key, the daemon stops: nothing was loaded.
    #[tokio::test]
    async fn waiting_for_the_key_ends_at_a_stop() {
        let (_s, zfs) = locked().await;
        let cfg = with_file(Path::new("/nonexistent/pool.key"));
        assert!(!unlock(&zfs, &cfg, async {}).await.unwrap());
        assert_ne!(zfs.key().await.unwrap(), Key::Loaded);
    }

    #[tokio::test]
    async fn the_key_is_asked_of_the_fleet_as_the_host() {
        let url = fleet().await;
        let (_s, zfs) = locked().await;
        let source = with_fleet(&url, "another-token").key_source().unwrap();
        let err = load(&zfs, &source, "byard").await.unwrap_err();
        assert!(format!("{err:#}").contains("401"), "{err:#}");
        assert!(unlock(
            &zfs,
            &with_fleet(&url, "host-token"),
            std::future::pending()
        )
        .await
        .unwrap());
        assert_eq!(zfs.key().await.unwrap(), Key::Loaded);
    }
}
