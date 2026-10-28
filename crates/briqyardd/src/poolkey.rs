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
    zfs.load_key(root, &own(source).await?).await
}

/// The pool's key from its source, checked.
async fn own(source: &KeySource) -> Result<String> {
    let key = match source {
        KeySource::Fleet {
            url,
            advertise,
            token,
        } => from_fleet(url, advertise, token, None).await?,
        KeySource::File(p) => from_file(p)?,
    };
    check(&key)?;
    Ok(key)
}

/// The pool's key, asked of its source: what a backup's record is sealed with and names by
/// its id (ADR 0035). The caller keeps what it derives, never the key.
pub async fn pool_key(cfg: &Config) -> Result<String> {
    own(&cfg.key_source()?).await
}

/// The key a backup's streams are encrypted under, by its id (ADR 0035): the pool's own when
/// its key file has that id, else the fleet's answer for `restore`, the restore it forwarded
/// here, which may be any host's key, a forgotten host's included. A host with a key file and
/// no fleet restores its own backups only.
pub async fn by_id(cfg: &Config, key_id: &str, restore: &api::RestoreSpec) -> Result<String> {
    if let KeySource::File(p) = cfg.key_source()? {
        let key = from_file(&p)?;
        if api::poolkey::id(&key).as_deref() == Some(key_id) {
            return Ok(key);
        }
    }
    let Some(fleet) = cfg
        .fleet
        .as_ref()
        .filter(|f| !f.url.is_empty() && !f.advertise.is_empty() && !cfg.token.is_empty())
    else {
        bail!("pool key {key_id} is not this host's, and the host has no fleet to ask for it");
    };
    let key = from_fleet(
        &fleet.url,
        &fleet.advertise,
        &cfg.token,
        Some((key_id, restore)),
    )
    .await?;
    check(&key)?;
    if api::poolkey::id(&key).as_deref() != Some(key_id) {
        bail!("the fleet answered another key than {key_id}");
    }
    Ok(key)
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
/// the fleet serves a host its own key, or with a key id and the restore it is for, a
/// backup's (ADR 0035).
async fn from_fleet(
    fleet: &str,
    advertise: &str,
    token: &str,
    backup: Option<(&str, &api::RestoreSpec)>,
) -> Result<String> {
    let url = format!("{}/v1/hosts/key", fleet.trim_end_matches('/'));
    let resp = crate::heartbeat::client()
        .post(&url)
        .bearer_auth(token)
        .json(&api::HostKeyRequest {
            url: advertise.to_string(),
            key_id: backup.map(|(id, _)| id.to_string()),
            restore: backup.map(|(_, rs)| rs.clone()),
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

    /// The restore the stand-in fleet has open for this host.
    fn rs() -> api::RestoreSpec {
        api::RestoreSpec {
            machine_id: "m_src".into(),
            backup: "b1".into(),
        }
    }

    /// Another host's key, which the fleet holds too.
    fn other() -> String {
        "fedcba9876543210".repeat(4)
    }

    /// A stand-in for the fleet's key route: `key()` for the bearer `host-token` asking for
    /// `http://10.0.0.5:7420`, refused otherwise; with a `key_id`, `key()` or `other()` by
    /// their ids, for the restore of `m_src` alone (403 otherwise), 404 for any other id.
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
            let Some(want) = req.key_id else {
                return Ok(Json(api::HostKey { key: key() }));
            };
            if req.restore.map(|r| r.machine_id) != Some("m_src".into()) {
                return Err(StatusCode::FORBIDDEN);
            }
            [key(), other()]
                .into_iter()
                .find(|k| api::poolkey::id(k).as_deref() == Some(want.as_str()))
                .map(|key| Json(api::HostKey { key }))
                .ok_or(StatusCode::NOT_FOUND)
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

    /// A backup's key by its id (ADR 0035): the key file's when the id is its key's, else the
    /// fleet's answer; a host alone restores its own backups only.
    #[tokio::test]
    async fn a_backups_key_is_the_files_or_the_fleets() {
        let url = fleet().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.key");
        std::fs::write(&path, format!("{}\n", key())).unwrap();
        let (own, theirs) = (
            api::poolkey::id(&key()).unwrap(),
            api::poolkey::id(&other()).unwrap(),
        );
        let alone = with_file(&path);
        assert_eq!(pool_key(&alone).await.unwrap(), key());
        assert_eq!(by_id(&alone, &own, &rs()).await.unwrap(), key());
        let err = by_id(&alone, &theirs, &rs()).await.unwrap_err();
        assert!(format!("{err:#}").contains("no fleet to ask"), "{err:#}");
        // A key file on a host of a fleet: its own key, or the fleet's for another's.
        let mut filed = with_fleet(&url, "host-token");
        filed.storage.key = format!("file:{}", path.display());
        assert_eq!(by_id(&filed, &own, &rs()).await.unwrap(), key());
        assert_eq!(by_id(&filed, &theirs, &rs()).await.unwrap(), other());
        let err = by_id(&filed, &"0".repeat(32), &rs()).await.unwrap_err();
        assert!(format!("{err:#}").contains("404"), "{err:#}");
        // A host keyed by the fleet asks it, for its own id as for another's.
        let keyed = with_fleet(&url, "host-token");
        assert_eq!(pool_key(&keyed).await.unwrap(), key());
        assert_eq!(by_id(&keyed, &theirs, &rs()).await.unwrap(), other());
        // The restore it is for goes with the ask.
        let elsewhere = api::RestoreSpec {
            machine_id: "m_other".into(),
            ..rs()
        };
        let err = by_id(&keyed, &theirs, &elsewhere).await.unwrap_err();
        assert!(format!("{err:#}").contains("403"), "{err:#}");
    }
}
