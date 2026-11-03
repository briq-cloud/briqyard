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

/// A write of the registry is given this long, retries included: a key request waits on it,
/// and the store's client retries for minutes, which suits a machine's backup.
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
        self.push_with(reg, |object, sealed| async move {
            self.store.put_bytes(&object, &sealed).await
        })
        .await
    }

    // Keep the publication transaction shared with stand-ins whose blocking work can
    // outlive the awaited PUT future, just as the local object store's writer can.
    async fn push_with<P, F>(&self, reg: &std::sync::Mutex<Registry>, mut put: P) -> Result<bool>
    where
        P: FnMut(String, std::sync::Arc<[u8]>) -> F,
        F: std::future::Future<Output = Result<()>>,
    {
        let mut last = self.last.lock().await;
        let reg = reg.lock().unwrap().clone();
        let data = encode(&reg);
        let digest: [u8; 32] = Sha256::digest(&data).into();
        if last.digest == Some(digest) {
            return Ok(false);
        }
        let sealed: std::sync::Arc<[u8]> = age::encrypt(&self.recipient, &data)
            .context("encrypt the registry")?
            .into();
        let day = chrono::Utc::now().format("%Y-%m-%d");
        for object in [format!("fleet/registry-{day}.json.age"), LATEST.to_string()] {
            tokio::time::timeout(PUT_WITHIN, put(object.clone(), sealed.clone()))
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

    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const CLEANUP_WITHIN: Duration = Duration::from_secs(10);

    type Worker = Arc<Mutex<Option<tokio::task::JoinHandle<Result<()>>>>>;

    struct BlockingPut {
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        release: Option<std::sync::mpsc::Sender<()>>,
        workers: Vec<(Worker, std::sync::mpsc::Receiver<()>)>,
    }

    // Signals even if the blocking writer unwinds. The retained JoinHandle separately
    // reports whether it completed successfully.
    struct Terminal(std::sync::mpsc::Sender<()>);

    impl Drop for Terminal {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    impl BlockingPut {
        fn new() -> Self {
            Self {
                objects: Default::default(),
                release: None,
                workers: Vec::new(),
            }
        }

        fn put(
            &mut self,
            object: String,
            sealed: Arc<[u8]>,
            gate: Option<tokio::sync::oneshot::Sender<()>>,
        ) -> impl std::future::Future<Output = Result<()>> + use<> {
            let objects = self.objects.clone();
            let (release, released) = std::sync::mpsc::channel();
            if gate.is_some() {
                assert!(self.release.replace(release).is_none());
            }
            let (terminal, ended) = std::sync::mpsc::channel();
            let worker = tokio::task::spawn_blocking(move || {
                let _terminal = Terminal(terminal);
                if let Some(entered) = gate {
                    let _ = entered.send(());
                    released
                        .recv_timeout(CLEANUP_WITHIN)
                        .context("blocking PUT gate was not released")?;
                }
                objects.lock().unwrap().insert(object, sealed.to_vec());
                Ok(())
            });
            let worker = Arc::new(Mutex::new(Some(worker)));
            self.workers.push((worker.clone(), ended));
            // Await the real JoinHandle, not an earlier completion notification. The
            // fixture retains it if this future is dropped while the writer runs.
            async move { Self::joined(&worker).await }
        }

        async fn joined(worker: &Worker) -> Result<()> {
            futures::future::poll_fn(|cx| {
                let mut task = worker.lock().unwrap();
                let Some(handle) = task.as_mut() else {
                    return std::task::Poll::Ready(Ok(()));
                };
                let result =
                    futures::ready!(std::future::Future::poll(std::pin::Pin::new(handle), cx));
                task.take();
                std::task::Poll::Ready(
                    result
                        .context("blocking PUT panicked")
                        .and_then(|result| result),
                )
            })
            .await
        }

        fn release(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
        }

        async fn join(&mut self) {
            self.release();
            let deadline = tokio::time::Instant::now() + CLEANUP_WITHIN;
            // Retain the handle if the cleanup deadline expires; Drop still waits for
            // its independent terminal signal, without replaying any write.
            while let Some((worker, _)) = self.workers.last_mut() {
                tokio::time::timeout_at(deadline, Self::joined(worker))
                    .await
                    .expect("blocking PUT cleanup deadline")
                    .expect("blocking PUT failed");
                self.workers.pop();
            }
        }
    }

    impl Drop for BlockingPut {
        fn drop(&mut self) {
            self.release();
            let deadline = Instant::now() + CLEANUP_WITHIN;
            for (_, terminal) in &self.workers {
                let ended = terminal
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .is_ok();
                assert!(
                    ended || std::thread::panicking(),
                    "blocking PUT drop deadline"
                );
            }
            // Every gate also has its own finite wait if the test/runtime disappears.
        }
    }

    async fn caller_abort_keeps_publication_turn(gate_latest: bool) {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let b = backup(dir.path(), &identity.to_public().to_string());
        let mut initial = Registry::default();
        initial.hosts.insert(
            "h1".into(),
            crate::static_host(
                &crate::config::StaticHost {
                    id: "h1".into(),
                    ..Default::default()
                },
                chrono::Utc::now(),
            ),
        );
        initial.pool_key("h1").unwrap();
        let reg = Mutex::new(initial);
        reg.lock()
            .unwrap()
            .namespaces
            .insert("snapshot-a".into(), "h1".into());
        let mut writes = Mutex::new(BlockingPut::new());
        let objects = writes.lock().unwrap().objects.clone();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        // Both callers run the same transaction as push, including its borrowed guard,
        // snapshot, encryption, daily/LATEST order, deadlines and Written commit.
        let mut a = Box::pin(b.push_with(&reg, |object, sealed| {
            let gate = if (object == LATEST) == gate_latest {
                entered.take()
            } else {
                None
            };
            writes.lock().unwrap().put(object, sealed, gate)
        }));
        tokio::time::timeout(CLEANUP_WITHIN, async {
            tokio::select! {
                result = &mut a => panic!("A ended before its blocking gate: {}", result.is_ok()),
                result = entering => result.expect("A entered the blocking writer"),
            }
        })
        .await
        .expect("A did not enter the blocking writer");
        drop(a);
        // A's real blocking writer remains gated after its async caller is dropped.
        reg.lock()
            .unwrap()
            .namespaces
            .insert("snapshot-b".into(), "h1".into());
        let expected_key = {
            let mut reg = reg.lock().unwrap();
            reg.hosts.get_mut("h1").unwrap().pool_key = PoolKey::default();
            reg.pool_key("h1").unwrap().0
        };
        let expected = encode(&reg.lock().unwrap());
        let attempts = Mutex::new(Vec::new());
        let mut b_call = Box::pin(b.push_with(&reg, |object, sealed| {
            attempts.lock().unwrap().push(object.clone());
            writes.lock().unwrap().put(object, sealed, None)
        }));
        // One explicit poll reaches the admission wait. No scheduler delay is used as
        // evidence: entering the callable proves the borrowed turn was released early.
        let pending = match futures::poll!(&mut b_call) {
            std::task::Poll::Pending => true,
            std::task::Poll::Ready(result) => {
                result.expect("B publication failed");
                false
            }
        };
        let entered_early = !attempts.lock().unwrap().is_empty();
        let mut committed_early = false;
        if entered_early {
            if pending {
                tokio::time::timeout(CLEANUP_WITHIN, &mut b_call)
                    .await
                    .expect("B completion deadline")
                    .expect("B publication failed");
            }
            committed_early = b.last.lock().await.digest == Some(Sha256::digest(&expected).into());
        }
        writes.lock().unwrap().release();
        if !entered_early && pending {
            tokio::time::timeout(CLEANUP_WITHIN, &mut b_call)
                .await
                .expect("B completion deadline")
                .expect("B publication failed");
        }
        drop(b_call);
        writes.get_mut().unwrap().join().await;
        let final_is_b = {
            let final_objects = objects.lock().unwrap();
            // Track B's actual daily name so crossing UTC midnight does not change
            // the oracle. An earlier day's object is outside B's two destinations.
            let targets = attempts.lock().unwrap();
            targets.len() == 2
                && targets.iter().any(|object| object == LATEST)
                && targets.iter().all(|object| {
                    let sealed = final_objects.get(object).expect("B's object exists");
                    let restored = open(sealed, &identity).expect("fake object decrypts");
                    restored.namespaces.contains_key("snapshot-b")
                        && restored
                            .hosts
                            .get("h1")
                            .is_some_and(|host| host.pool_key == expected_key)
                })
        };
        let ack_is_b = {
            let last = b.last.lock().await;
            last.digest == Some(Sha256::digest(&expected).into())
                && last.keys.get("h1") == Some(&expected_key)
        };
        assert!(
            !entered_early,
            "B entered PUT before A's blocking writer was terminal"
        );
        assert!(pending, "B must wait for publication admission");
        assert!(
            !committed_early,
            "B committed before A's blocking writer was terminal"
        );
        assert!(final_is_b, "both final objects must contain snapshot B");
        assert!(ack_is_b, "Written must acknowledge snapshot B");
    }

    #[tokio::test]
    async fn caller_abort_during_daily_keeps_publication_turn() {
        caller_abort_keeps_publication_turn(false).await;
    }

    #[tokio::test]
    async fn caller_abort_during_latest_keeps_publication_turn() {
        caller_abort_keeps_publication_turn(true).await;
    }

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
            .namespaces
            .insert("t-newer".into(), "h1".into());
        drop(turn);
        assert!(waiting.await.unwrap().unwrap());
        let back = b.fetch(LATEST, &identity(&key).unwrap()).await.unwrap();
        assert!(
            back.namespaces.contains_key("t-newer"),
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
