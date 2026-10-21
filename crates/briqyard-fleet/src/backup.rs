//! The registry's backup (ADR 0032). The registry holds every host's token and pool key
//! (ADR 0026): lost, every pool is unreadable at its host's next reboot. The fleet writes it to
//! an object store (S3 or a directory, `briqyard-objstore`), encrypted with age to a recipient
//! whose identity is kept off the fleet's host, once a minute when it changed and before a host
//! is handed a key the store does not hold yet. `briqyard-fleet restore` brings it back.

use crate::registry::{PoolKey, Registry};
use anyhow::{anyhow, bail, Context, Result};
use briqyard_objstore::ObjectStore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// The newest backup; one more per UTC day (`registry-<day>.json.age`), the last of that day.
pub const LATEST: &str = "fleet/registry.json.age";

/// A write of the registry is given this long: a key request waits on it, and the store's
/// client allows an hour for a machine's backup.
const PUT_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);

pub struct Backup {
    store: ObjectStore,
    recipient: age::x25519::Recipient,
    /// What the store holds, as of the last write: held across a write, so writes take turns.
    last: tokio::sync::Mutex<Written>,
}

#[derive(Default)]
struct Written {
    digest: Option<[u8; 32]>,
    /// The pool key of each host in it.
    keys: HashMap<String, PoolKey>,
}

/// The registry as written: the same bytes as `registry.json`.
pub fn encode(reg: &Registry) -> Vec<u8> {
    serde_json::to_vec_pretty(reg).expect("a registry serializes")
}

impl Backup {
    /// The configured backup, or none when `backup.store` is empty.
    pub fn open(cfg: &crate::config::Backup) -> Result<Option<Backup>> {
        if cfg.store.is_empty() {
            return Ok(None);
        }
        Ok(Some(Backup {
            store: store(cfg)?,
            recipient: recipient(&cfg.recipient)?,
            last: Default::default(),
        }))
    }

    pub fn describe(&self) -> String {
        self.store.describe()
    }

    /// Writes the registry when it differs from what the store holds: the newest and the
    /// day's copy, encrypted. `false` when there was nothing to write. The registry is read
    /// once this write has its turn, so a write never lands an older registry over a newer one.
    pub async fn push(&self, reg: &std::sync::Mutex<Registry>) -> Result<bool> {
        let mut last = self.last.lock().await;
        let reg = reg.lock().unwrap().clone();
        let data = encode(&reg);
        let digest: [u8; 32] = Sha256::digest(&data).into();
        if last.digest == Some(digest) {
            return Ok(false);
        }
        let sealed = age::encrypt(&self.recipient, &data).context("encrypt the registry")?;
        let day = chrono::Utc::now().format("%Y-%m-%d");
        for object in [format!("fleet/registry-{day}.json.age"), LATEST.to_string()] {
            tokio::time::timeout(PUT_WITHIN, self.store.put_bytes(&object, &sealed))
                .await
                .map_err(|_| anyhow!("{object}: no answer within {} s", PUT_WITHIN.as_secs()))?
                .context("write the registry's backup")?;
        }
        *last = Written {
            digest: Some(digest),
            keys: reg
                .hosts
                .values()
                .filter(|h| !h.pool_key.is_empty())
                .map(|h| (h.id.clone(), h.pool_key.clone()))
                .collect(),
        };
        Ok(true)
    }

    /// Whether the last write holds this host's key as it is.
    pub async fn holds(&self, host: &str, key: &PoolKey) -> bool {
        self.last.lock().await.keys.get(host) == Some(key)
    }

    /// A backup read back: fetched, decrypted with the identity, parsed.
    pub async fn fetch(&self, object: &str, identity: &age::x25519::Identity) -> Result<Registry> {
        let sealed = self
            .store
            .get_bytes(object)
            .await
            .with_context(|| format!("read {object} from {}", self.store.describe()))?;
        open(&sealed, identity).with_context(|| format!("{object} from {}", self.store.describe()))
    }
}

/// A sealed registry opened: decrypted with the identity, parsed as a registry.
pub fn open(sealed: &[u8], identity: &age::x25519::Identity) -> Result<Registry> {
    let data = age::decrypt(identity, sealed)
        .map_err(|e| anyhow!("decrypt: {e} (not the identity of backup.recipient?)"))?;
    serde_json::from_slice(&data).context("parse the registry")
}

fn store(cfg: &crate::config::Backup) -> Result<ObjectStore> {
    ObjectStore::open(
        &cfg.store,
        &cfg.endpoint,
        &cfg.region,
        &std::env::var("BRIQYARD_S3_ACCESS_KEY").unwrap_or_default(),
        &std::env::var("BRIQYARD_S3_SECRET_KEY").unwrap_or_default(),
    )
}

/// An age X25519 recipient, `age1…`.
pub fn recipient(text: &str) -> Result<age::x25519::Recipient> {
    text.trim()
        .parse()
        .map_err(|e| anyhow!("backup.recipient: {e}: want an age recipient, age1…"))
}

/// The identity in an age identity file: its `AGE-SECRET-KEY-1…` line, comments aside.
pub fn identity(path: &Path) -> Result<age::x25519::Identity> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
    else {
        bail!("{}: no AGE-SECRET-KEY- line", path.display());
    };
    line.parse().map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// A new identity, written to `path` (made `0600`, never over a file) as `age-keygen` writes
/// one; answers its recipient.
pub fn keygen(path: &Path) -> Result<String> {
    use age::secrecy::ExposeSecret;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    writeln!(
        f,
        "# created: {}\n# public key: {recipient}\n{}",
        chrono::Utc::now().to_rfc3339(),
        id.to_string().expose_secret()
    )?;
    f.sync_all()?;
    Ok(recipient)
}

/// Writes the registry once a minute when it changed. A write that fails is an `error` and is
/// tried again at the next turn.
pub async fn run(st: std::sync::Arc<crate::AppState>) {
    let Some(backup) = st.backup.as_ref() else {
        return;
    };
    loop {
        match backup.push(&st.reg).await {
            Ok(true) => tracing::debug!(store = backup.describe(), "registry backed up"),
            Ok(false) => {}
            Err(e) => tracing::error!(
                store = backup.describe(),
                err = format!("{e:#}"),
                "registry backup"
            ),
        }
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write reads the registry once it has its turn: one that waited behind another
    /// writes the registry as it is then, never the one it was called with.
    #[tokio::test]
    async fn a_write_that_waited_writes_the_newest_registry() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("backup.key");
        let b = std::sync::Arc::new(backup(&dir.path().join("store"), &keygen(&key).unwrap()));
        let reg = std::sync::Arc::new(std::sync::Mutex::new(Registry::default()));
        let turn = b.last.lock().await;
        let waiting = {
            let (b, reg) = (b.clone(), reg.clone());
            tokio::spawn(async move { b.push(&reg).await })
        };
        tokio::task::yield_now().await;
        reg.lock()
            .unwrap()
            .tenants
            .insert("t-newer".into(), "h1".into());
        drop(turn);
        assert!(waiting.await.unwrap().unwrap());
        let back = b.fetch(LATEST, &identity(&key).unwrap()).await.unwrap();
        assert!(
            back.tenants.contains_key("t-newer"),
            "the registry as it was at the write"
        );
    }

    fn backup(dir: &Path, recipient: &str) -> Backup {
        Backup::open(&crate::config::Backup {
            store: format!("file://{}", dir.display()),
            recipient: recipient.into(),
            ..Default::default()
        })
        .unwrap()
        .unwrap()
    }

    /// Written encrypted, only when it changed, read back with the identity and with no other.
    #[tokio::test]
    async fn the_registry_is_written_sealed_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("backup.key");
        let rcpt = keygen(&key).unwrap();
        assert!(rcpt.starts_with("age1"), "{rcpt}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(keygen(&key).is_err(), "never over a file");
        let store = dir.path().join("store");
        let b = backup(&store, &rcpt);

        let mut reg = Registry::default();
        let mut h = crate::static_host(
            &crate::config::StaticHost {
                id: "h1".into(),
                url: "http://10.0.0.1:7420".into(),
                token: "h1-token".into(),
                ..Default::default()
            },
            chrono::Utc::now(),
        );
        h.note = "the first".into();
        reg.hosts.insert("h1".into(), h);
        let (k, _) = reg.pool_key("h1").unwrap();
        let reg = std::sync::Mutex::new(reg);
        assert!(!b.holds("h1", &k).await);
        assert!(b.push(&reg).await.unwrap());
        assert!(b.holds("h1", &k).await);
        assert!(!b.push(&reg).await.unwrap(), "unchanged: not written again");

        let sealed = std::fs::read(store.join(LATEST)).unwrap();
        let text = String::from_utf8_lossy(&sealed);
        assert!(text.starts_with("age-encryption.org/v1"), "{text}");
        assert!(
            !text.contains("h1-token") && !text.contains(k.expose()),
            "sealed"
        );
        let day = chrono::Utc::now().format("%Y-%m-%d");
        assert!(store
            .join(format!("fleet/registry-{day}.json.age"))
            .exists());

        let back = b.fetch(LATEST, &identity(&key).unwrap()).await.unwrap();
        assert_eq!(back.hosts["h1"].pool_key, k);
        assert_eq!(back.hosts["h1"].token, "h1-token");

        let other = dir.path().join("other.key");
        keygen(&other).unwrap();
        let err = b
            .fetch(LATEST, &identity(&other).unwrap())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("decrypt"), "{err:#}");
        assert!(recipient("age1nope").is_err());
        std::fs::write(&other, "# nothing\n").unwrap();
        assert!(identity(&other).is_err());
    }
}
