//! The registry's backup (ADR 0032). The registry holds every host's token and pool key
//! (ADR 0026): lost, every pool is unreadable at its host's next reboot. The fleet writes it to
//! an object store (S3 or a directory, `briqyard-objstore`), encrypted with age to a recipient
//! whose identity is kept off the fleet's host, once a minute when it changed and before a host
//! is handed a key the store does not hold yet. `briqyard-fleet restore` brings it back.

use crate::registry::{PoolKey, RegLock, Registry};
use anyhow::{anyhow, bail, Context, Result};
use briqyard_objstore::ObjectStore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The newest backup; one more per UTC day (`registry-<day>.json.age`), the last of that day.
pub const LATEST: &str = "fleet/registry.json.age";

/// A registry whose only change is heartbeat telemetry is written again after this long. A
/// bucket with versioning keeps every overwrite as a version and refuses a write to an object
/// that holds too many (thousands): the registry changes with every heartbeat, so writing each
/// change reached that limit in days and then failed for good. A registry at rest is written
/// after this long too, so its backup is never older and a broken store shows.
const TELEMETRY_REFRESH: std::time::Duration = std::time::Duration::from_secs(3600);
/// A write of the registry is given this long, retries included: a key request waits on it,
/// and the store's client retries for minutes, which suits a machine's backup.
const PUT_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);

pub struct Backup {
    store: ObjectStore,
    recipient: age::x25519::Recipient,
    turn: Arc<tokio::sync::Mutex<()>>,
    /// Historical ACK state; never held across I/O or an await.
    last: Arc<Mutex<Written>>,
    /// Acknowledgements of an earlier run of the fleet (ADR 0026): see `with_acks`.
    acks: Arc<Acks>,
    target: AckTarget,
    blocked: Arc<AtomicBool>,
    caller_outcomes: [AtomicU64; 4],
}

/// The keys the store acknowledged, by `ack_id`, kept in a file beside the registry so that a
/// restart during a store outage still serves a key the store already holds. Ids only: a hash
/// of the host and its key, never the key. The file names the backup it was acknowledged by
/// (store, endpoint, recipient): another target lists nothing.
#[derive(Default)]
struct Acks {
    path: Option<std::path::PathBuf>,
    target: AckTarget,
    ids: Mutex<std::collections::HashSet<String>>,
}

/// What identifies a backup: where it goes and to whom. No credential.
#[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct AckTarget {
    store: String,
    endpoint: String,
    recipient: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AckFile {
    #[serde(flatten)]
    target: AckTarget,
    ids: std::collections::HashSet<String>,
}

/// What identifies a published key: the host and the key's content, so a key that changed
/// matches no earlier acknowledgement.
fn ack_id(host: &str, key: &PoolKey) -> String {
    let mut h = Sha256::new();
    h.update(b"briqyard pool key ack v1\0");
    h.update(host.as_bytes());
    h.update(b"\0");
    h.update(key.expose().as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl Acks {
    /// The file's ids when it was written for `target`; a missing, unreadable, corrupt or
    /// foreign file knows none, so the key waits for a write to the store as before. Only a
    /// missing file is quiet.
    fn load(path: std::path::PathBuf, target: AckTarget) -> Acks {
        let ids = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<AckFile>(&bytes) {
                Ok(file) if file.target == target => file.ids,
                Ok(file) => {
                    let differs: Vec<&str> = [
                        ("store", file.target.store != target.store),
                        ("endpoint", file.target.endpoint != target.endpoint),
                        ("recipient", file.target.recipient != target.recipient),
                    ]
                    .into_iter()
                    .filter_map(|(name, differs)| differs.then_some(name))
                    .collect();
                    tracing::warn!(file = %path.display(), differs = ?differs, "published-key file is for another backup: ignored");
                    Default::default()
                }
                Err(e) => {
                    tracing::warn!(file = %path.display(), err = %e, "published-key file ignored");
                    Default::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
            Err(e) => {
                tracing::warn!(file = %path.display(), err = %e, "published-key file unreadable: ignored");
                Default::default()
            }
        };
        Acks {
            path: Some(path),
            target,
            ids: Mutex::new(ids),
        }
    }

    /// Replaces the ids with those of a registry the store just acknowledged. The file is
    /// made afresh `0600` and renamed, as the registry is.
    fn record(&self, keys: &HashMap<String, PoolKey>) {
        let ids: std::collections::HashSet<String> =
            keys.iter().map(|(host, key)| ack_id(host, key)).collect();
        if let Some(path) = &self.path {
            if let Err(e) = write_ids(path, &self.target, &ids) {
                tracing::warn!(file = %path.display(), err = format!("{e:#}"), "published keys not saved");
            }
        }
        if let Ok(mut known) = self.ids.lock() {
            *known = ids;
        }
    }

    fn holds(&self, host: &str, key: &PoolKey) -> bool {
        self.ids
            .lock()
            .is_ok_and(|ids| ids.contains(&ack_id(host, key)))
    }
}

/// With the backup off no store holds a copy: the file is removed, so a later run with a
/// backup does not take the old acknowledgements for it.
pub fn drop_acks(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(file = %path.display(), err = %e, "published-key file not removed");
        }
    }
}

fn write_ids(
    path: &Path,
    target: &AckTarget,
    ids: &std::collections::HashSet<String>,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    let body = AckFile {
        target: target.clone(),
        ids: ids.clone(),
    };
    file.write_all(&serde_json::to_vec(&body)?)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[derive(Default)]
struct Written {
    digest: Option<[u8; 32]>,
    /// The digest of the registry without its heartbeat telemetry (`stable_digest`), and when
    /// it was written: what decides that a change is only telemetry.
    stable: Option<[u8; 32]>,
    published: Option<std::time::Instant>,
    ack_timestamp_seconds: Option<u64>,
    /// The pool key of each host in it.
    keys: HashMap<String, PoolKey>,
}

/// Sanitized process-local observations only; no keys, digests or store details.
pub struct Observation {
    pub configured: bool,
    pub publication_observed: Option<bool>,
    pub last_ack_timestamp_seconds: Option<u64>,
    pub caller_outcomes: [u64; 4],
    /// match, mismatch, unknown (one-hot when rendered).
    pub durable_match: usize,
}

pub fn observe(
    backup: Option<&Backup>,
    written: &tokio::sync::Mutex<Option<[u8; 32]>>,
    durable_valid: &AtomicBool,
) -> Observation {
    let mut observation = Observation {
        configured: backup.is_some(),
        publication_observed: Some(false),
        last_ack_timestamp_seconds: None,
        caller_outcomes: [0; 4],
        durable_match: 2,
    };
    let Some(backup) = backup else {
        return observation;
    };
    observation.caller_outcomes =
        std::array::from_fn(|i| backup.caller_outcomes[i].load(Ordering::Relaxed));
    let Ok(last) = backup.last.try_lock() else {
        observation.publication_observed = None;
        return observation;
    };
    observation.publication_observed = Some(last.digest.is_some());
    observation.last_ack_timestamp_seconds = last.ack_timestamp_seconds;
    if let Ok(written) = written.try_lock() {
        if durable_valid.load(Ordering::Acquire) {
            if let (Some(ack), Some(durable)) = (last.digest, *written) {
                observation.durable_match = usize::from(ack != durable);
            }
        }
    }
    observation
}

struct CallerOutcome<'a>(Option<&'a [AtomicU64; 4]>);

impl CallerOutcome<'_> {
    fn settle(&mut self, result: &Result<bool>) {
        let outcome = match result {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(_) => 2,
        };
        self.0.take().unwrap()[outcome].fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for CallerOutcome<'_> {
    fn drop(&mut self) {
        if let Some(counters) = self.0.take() {
            counters[3].fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn ack_receipt_seconds() -> Option<u64> {
    chrono::Utc::now().timestamp().try_into().ok()
}

// Field drop follows Drop::drop: block admission BEFORE releasing the owned lease.
struct Publication {
    _turn: tokio::sync::OwnedMutexGuard<()>,
    blocked: Arc<AtomicBool>,
    armed: bool,
}

impl Publication {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if self.armed {
            self.blocked.store(true, Ordering::Release);
        }
    }
}

fn respond(reply: &mut Option<tokio::sync::oneshot::Sender<Result<bool>>>, result: Result<bool>) {
    if let Some(reply) = reply.take() {
        let _ = reply.send(result);
    }
}

/// Bound admission only; dropping a waiter starts no worker.
pub(super) async fn admit<F, D>(future: F, deadline: D) -> Result<F::Output>
where
    F: std::future::Future,
    D: std::future::Future<Output = ()>,
{
    tokio::select! {
        biased;
        result = future => Ok(result),
        _ = deadline => Err(anyhow!("registry admission: no turn within {} s", PUT_WITHIN.as_secs())),
    }
}

/// The digest of the registry without what each heartbeat rewrites (`last_seen`, `used`, free
/// disk, conditions, the machine count, the boot queue): the next report after a restore is the truth for all
/// of them. Two registries with the same digest differ in nothing a restore needs.
fn stable_digest(reg: &Registry) -> [u8; 32] {
    let mut stable = reg.clone();
    for h in stable.hosts.values_mut() {
        h.last_seen = chrono::DateTime::UNIX_EPOCH;
        h.used = Default::default();
        h.disk_free_mb = None;
        h.conditions.clear();
        h.machines = 0;
        h.boots_at_once = None;
        h.boot_queue = None;
    }
    Sha256::digest(encode(&stable)).into()
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
            turn: Default::default(),
            last: Default::default(),
            acks: Default::default(),
            target: AckTarget {
                store: cfg.store.clone(),
                endpoint: cfg.endpoint.clone(),
                recipient: cfg.recipient.trim().to_string(),
            },
            blocked: Default::default(),
            caller_outcomes: Default::default(),
        }))
    }

    /// Keeps the keys the store acknowledged in `path` (ADR 0026). After a restart a key
    /// listed there is served without a write to the store, so a store outage and a restart
    /// together do not lock a host out; a key not listed waits for a write, as before.
    pub fn with_acks(mut self, path: std::path::PathBuf) -> Backup {
        self.acks = Arc::new(Acks::load(path, self.target.clone()));
        self
    }

    pub fn describe(&self) -> String {
        self.store.describe()
    }

    /// Snapshot after admission, then publish daily and LATEST as one owned transaction.
    /// Caller cancellation or timeout never drops the worker's PUT future or lease.
    pub async fn push(&self, reg: &RegLock) -> Result<bool> {
        let store = self.store.clone();
        self.push_with(reg, move |object, sealed| {
            let store = store.clone();
            async move { store.put_bytes(&object, &sealed).await }
        })
        .await
    }

    async fn push_with<P, F>(&self, reg: &RegLock, put: P) -> Result<bool>
    where
        P: FnMut(String, Arc<[u8]>) -> F + Send + 'static,
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        self.push_with_deadlines(reg, put, || tokio::time::sleep(PUT_WITHIN))
            .await
    }

    async fn push_with_deadlines<P, F, D, T>(
        &self,
        reg: &RegLock,
        put: P,
        deadline: D,
    ) -> Result<bool>
    where
        P: FnMut(String, Arc<[u8]>) -> F + Send + 'static,
        F: std::future::Future<Output = Result<()>> + Send + 'static,
        D: FnMut() -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        self.push_with_clock(reg, put, deadline, ack_receipt_seconds)
            .await
    }

    async fn push_with_clock<P, F, D, T, C>(
        &self,
        reg: &RegLock,
        mut put: P,
        mut deadline: D,
        clock: C,
    ) -> Result<bool>
    where
        P: FnMut(String, Arc<[u8]>) -> F + Send + 'static,
        F: std::future::Future<Output = Result<()>> + Send + 'static,
        D: FnMut() -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
        C: FnOnce() -> Option<u64> + Send + 'static,
    {
        let mut outcome = CallerOutcome(Some(&self.caller_outcomes));
        let result = async {
            let turn = admit(self.turn.clone().lock_owned(), deadline()).await?;
            if self.blocked.load(Ordering::Acquire) {
                bail!("registry publication blocked after unexpected worker exit");
            }
            let reg = reg
                .lock()
                .map_err(|_| anyhow!("registry unavailable"))?
                .clone();
            let data = encode(&reg);
            let digest: [u8; 32] = Sha256::digest(&data).into();
            // Unchanged too is written after an hour: a fleet at rest still proves its backup works.
            {
                let last = self
                    .last
                    .lock()
                    .map_err(|_| anyhow!("backup ACK cache unavailable"))?;
                if last.digest == Some(digest)
                    && last
                        .published
                        .is_some_and(|at| at.elapsed() < TELEMETRY_REFRESH)
                {
                    return Ok(false);
                }
            }
            let stable = stable_digest(&reg);
            let telemetry_only = {
                let last = self
                    .last
                    .lock()
                    .map_err(|_| anyhow!("backup ACK cache unavailable"))?;
                last.stable == Some(stable)
                    && last
                        .published
                        .is_some_and(|at| at.elapsed() < TELEMETRY_REFRESH)
            };
            if telemetry_only {
                return Ok(false);
            }
            let sealed: Arc<[u8]> = age::encrypt(&self.recipient, &data)
                .context("encrypt the registry")?
                .into();
            let mut written = Written {
                ack_timestamp_seconds: None,
                digest: Some(digest),
                stable: Some(stable),
                published: Some(std::time::Instant::now()),
                keys: reg
                    .hosts
                    .values()
                    .filter(|h| !h.pool_key.is_empty())
                    .map(|h| (h.id.clone(), h.pool_key.clone()))
                    .collect(),
            };
            let objects = [
                format!(
                    "fleet/registry-{}.json.age",
                    chrono::Utc::now().format("%Y-%m-%d")
                ),
                LATEST.to_string(),
            ];
            let last = self.last.clone();
            let acks = self.acks.clone();
            let mut guard = Publication {
                _turn: turn,
                blocked: self.blocked.clone(),
                armed: true,
            };
            let (reply, answer) = tokio::sync::oneshot::channel();
            // No await between the snapshot and launch. The guard is owned even if the
            // spawned future is destroyed before its first poll.
            let worker = tokio::spawn(async move {
                let mut reply = Some(reply);
                let result = async {
                    for object in objects {
                        let future = put(object.clone(), sealed.clone());
                        tokio::pin!(future);
                        tokio::select! {
                            biased;
                            result = &mut future => result,
                            _ = deadline() => {
                                respond(&mut reply, Err(anyhow!(
                                    "{object}: no answer within {} s", PUT_WITHIN.as_secs()
                                )));
                                // Await the SAME future. Neither a lost caller nor its
                                // deadline permits cancellation, replacement or replay.
                                future.await
                            }
                        }
                        .context("write the registry's backup")?;
                    }
                    written.ack_timestamp_seconds = clock();
                    // Only now that the store acknowledged both objects.
                    acks.record(&written.keys);
                    *last
                        .lock()
                        .map_err(|_| anyhow!("backup ACK cache unavailable"))? = written;
                    Ok(true)
                }
                .await;
                // Returned backend errors are terminal client work. Unexpected destruction
                // instead leaves this armed, blocking later publication before lease drop.
                guard.disarm();
                respond(&mut reply, result);
            });
            drop(worker); // Detach: request cleanup must never abort publication.
            answer
                .await
                .map_err(|_| anyhow!("registry publication worker ended unexpectedly"))?
        }
        .await;
        outcome.settle(&result);
        result
    }

    /// Historical exact-key ACK eligibility; poisoning refuses eligibility.
    pub async fn holds(&self, host: &str, key: &PoolKey) -> bool {
        self.last
            .lock()
            .map(|last| last.keys.get(host) == Some(key) || self.acks.holds(host, key))
            .unwrap_or(false)
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

/// Writes the registry once a minute when it changed, heartbeat telemetry aside (an hour at most
/// between two writes). A write that fails is an `error` and is tried again at the next turn.
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
pub(super) mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const CLEANUP_WITHIN: Duration = Duration::from_secs(10);

    struct WorkerState {
        handle: Option<tokio::task::JoinHandle<Result<()>>>,
        failed: bool,
    }

    type Worker = Arc<Mutex<WorkerState>>;

    struct BlockingPut {
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        release: Option<std::sync::mpsc::Sender<()>>,
        workers: Vec<(Worker, std::sync::mpsc::Receiver<()>)>,
    }

    // The test owns release independently of the Arc retained by the transaction.
    // Unwinding must release the gate even while that transaction still owns state.
    struct PutFixture(Arc<Mutex<BlockingPut>>);

    impl PutFixture {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(BlockingPut::new())))
        }
    }

    impl std::ops::Deref for PutFixture {
        type Target = Arc<Mutex<BlockingPut>>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for PutFixture {
        fn drop(&mut self) {
            self.0.lock().unwrap().release();
        }
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
            let worker = Arc::new(Mutex::new(WorkerState {
                handle: Some(worker),
                failed: false,
            }));
            self.workers.push((worker.clone(), ended));
            // Await the real JoinHandle, not an earlier completion notification. The
            // fixture retains it if this future is dropped while the writer runs.
            async move { Self::joined(&worker).await }
        }

        async fn joined(worker: &Worker) -> Result<()> {
            futures::future::poll_fn(|cx| {
                let mut task = worker.lock().unwrap();
                let Some(handle) = task.handle.as_mut() else {
                    return std::task::Poll::Ready(if task.failed {
                        Err(anyhow!("blocking PUT previously failed"))
                    } else {
                        Ok(())
                    });
                };
                let result =
                    futures::ready!(std::future::Future::poll(std::pin::Pin::new(handle), cx));
                let result = result
                    .context("blocking PUT panicked")
                    .and_then(|result| result);
                task.failed = result.is_err();
                drop(task.handle.take());
                // Cleanup must still fail if a canceled caller's join already
                // consumed a gate-timeout or writer failure.
                std::task::Poll::Ready(result)
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
                drop(self.workers.pop());
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

    fn manual_deadline(
        target: usize,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send,
    ) {
        let (fire, fired) = tokio::sync::oneshot::channel();
        let mut fired = Some(fired);
        let mut index = 0;
        (
            fire,
            move || -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
                let current = index;
                index += 1;
                if current == target {
                    let fired = fired.take().unwrap();
                    Box::pin(async move {
                        let _ = fired.await;
                    })
                } else {
                    Box::pin(std::future::pending())
                }
            },
        )
    }

    async fn cleanup(b: &Backup, writes: &Arc<Mutex<BlockingPut>>) {
        // The worker owns the publication lease until its blocking PUT finishes.
        // Release the fixture gate before waiting for that lease, then join the PUTs.
        writes.lock().unwrap().release();
        let turn = tokio::time::timeout(CLEANUP_WITHIN, b.turn.lock())
            .await
            .expect("publication worker cleanup deadline");
        drop(turn);
        let mut writes = std::mem::replace(&mut *writes.lock().unwrap(), BlockingPut::new());
        writes.join().await;
    }

    pub(crate) async fn with_stalled_publication<F: std::future::Future<Output = ()>>(
        st: &crate::AppState,
        latest: bool,
        action: F,
    ) {
        let b = st.backup.as_ref().unwrap();
        st.reg
            .lock()
            .unwrap()
            .namespaces
            .insert("unrelated-change".into(), "h2".into());
        let writes = PutFixture::new();
        let actual = writes.clone();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let mut caller = Box::pin(b.push_with(&st.reg, move |object, sealed| {
            let gate = if (object == LATEST) == latest {
                entered.take()
            } else {
                None
            };
            actual.lock().unwrap().put(object, sealed, gate)
        }));
        bounded(async {
            tokio::select! {
                _ = &mut caller => panic!("publication ended before gate"),
                result = entering => result.unwrap(),
            }
        })
        .await;
        drop(caller);
        assert!(st.key_turn.try_lock().is_ok());
        bounded(action).await;
        writes.lock().unwrap().release();
        cleanup(b, &writes).await;
    }

    pub(crate) async fn acknowledge(st: &crate::AppState) {
        st.backup
            .as_ref()
            .unwrap()
            .push_with_clock(
                &st.reg,
                |_, _| async { Ok(()) },
                std::future::pending,
                || Some(99),
            )
            .await
            .unwrap();
    }

    pub(crate) async fn refuse_busy(b: &Backup, reg: &RegLock) -> Result<bool> {
        b.push_with_deadlines(
            reg,
            |_, _| async { panic!("publication admitted while blocking writer was active") },
            || std::future::ready(()),
        )
        .await
    }

    async fn caller_keeps_publication_turn(gate_latest: bool, timeout_caller: bool) {
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
        let reg = RegLock::new(initial);
        reg.lock()
            .unwrap()
            .namespaces
            .insert("snapshot-a".into(), "h1".into());
        let writes = PutFixture::new();
        let objects = writes.lock().unwrap().objects.clone();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let (fire, deadline) = manual_deadline(if gate_latest { 2 } else { 1 });
        let a_writes = writes.clone();
        // Both callers use the production ownership and transaction boundary.
        let mut a = Box::pin(b.push_with_deadlines(
            &reg,
            move |object, sealed| {
                let gate = if (object == LATEST) == gate_latest {
                    entered.take()
                } else {
                    None
                };
                a_writes.lock().unwrap().put(object, sealed, gate)
            },
            deadline,
        ));
        tokio::time::timeout(CLEANUP_WITHIN, async {
            tokio::select! {
                result = &mut a => panic!("A ended before its blocking gate: {}", result.is_ok()),
                result = entering => result.expect("A entered the blocking writer"),
            }
        })
        .await
        .expect("A did not enter the blocking writer");
        if timeout_caller {
            fire.send(()).expect("stage deadline receiver");
            assert!(tokio::time::timeout(CLEANUP_WITHIN, &mut a)
                .await
                .expect("caller timeout result deadline")
                .is_err());
        }
        drop(a);
        assert_eq!(
            outcomes(&b),
            if timeout_caller {
                [0, 0, 1, 0]
            } else {
                [0, 0, 0, 1]
            }
        );
        assert!(b.last.lock().unwrap().ack_timestamp_seconds.is_none());
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
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let b_attempts = attempts.clone();
        let b_writes = writes.clone();
        let admission_polled = Arc::new(AtomicBool::new(false));
        let observed = admission_polled.clone();
        let mut first_deadline = true;
        let mut b_call = Box::pin(b.push_with_deadlines(
            &reg,
            move |object, sealed| {
                b_attempts.lock().unwrap().push(object.clone());
                b_writes.lock().unwrap().put(object, sealed, None)
            },
            move || {
                let admission = first_deadline;
                first_deadline = false;
                let observed = observed.clone();
                async move {
                    // admit's biased select polls this only if lease acquisition
                    // returned Pending. This distinguishes admission from awaiting
                    // an already launched worker's reply in the same manual poll.
                    if admission {
                        observed.store(true, Ordering::SeqCst);
                    }
                    std::future::pending::<()>().await;
                }
            },
        ));
        // One explicit poll reaches the admission wait. No scheduler delay is used as
        // evidence: entering the callable proves the borrowed turn was released early.
        let pending = match futures::poll!(&mut b_call) {
            std::task::Poll::Pending => true,
            std::task::Poll::Ready(result) => {
                result.expect("B publication failed");
                false
            }
        };
        let waited_on_admission = admission_polled.load(Ordering::SeqCst);
        let entered_early = !attempts.lock().unwrap().is_empty();
        let mut committed_early = false;
        if entered_early {
            if pending {
                tokio::time::timeout(CLEANUP_WITHIN, &mut b_call)
                    .await
                    .expect("B completion deadline")
                    .expect("B publication failed");
            }
            committed_early =
                b.last.lock().unwrap().digest == Some(Sha256::digest(&expected).into());
        }
        writes.lock().unwrap().release();
        if !entered_early && pending {
            tokio::time::timeout(CLEANUP_WITHIN, &mut b_call)
                .await
                .expect("B completion deadline")
                .expect("B publication failed");
        }
        drop(b_call);
        cleanup(&b, &writes).await;
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
            let last = b.last.lock().unwrap();
            last.digest == Some(Sha256::digest(&expected).into())
                && last.keys.get("h1") == Some(&expected_key)
        };
        assert!(
            !entered_early,
            "B entered PUT before A's blocking writer was terminal"
        );
        assert!(
            pending && waited_on_admission,
            "B must wait for publication admission"
        );
        assert!(
            !committed_early,
            "B committed before A's blocking writer was terminal"
        );
        assert!(final_is_b, "both final objects must contain snapshot B");
        assert!(ack_is_b, "Written must acknowledge snapshot B");
        assert!(b.last.lock().unwrap().ack_timestamp_seconds.is_some());
        assert_eq!(
            outcomes(&b),
            if timeout_caller {
                [1, 0, 1, 0]
            } else {
                [1, 0, 0, 1]
            }
        );
    }

    #[tokio::test]
    async fn caller_abort_during_daily_keeps_publication_turn() {
        caller_keeps_publication_turn(false, false).await;
    }

    #[tokio::test]
    async fn caller_abort_during_latest_keeps_publication_turn() {
        caller_keeps_publication_turn(true, false).await;
    }

    #[tokio::test]
    async fn caller_timeout_during_daily_keeps_publication_turn() {
        caller_keeps_publication_turn(false, true).await;
    }

    #[tokio::test]
    async fn caller_timeout_during_latest_keeps_publication_turn() {
        caller_keeps_publication_turn(true, true).await;
    }

    async fn bounded<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(CLEANUP_WITHIN, future)
            .await
            .expect("test completion deadline")
    }

    fn outcomes(b: &Backup) -> [u64; 4] {
        std::array::from_fn(|i| b.caller_outcomes[i].load(Ordering::Relaxed))
    }

    #[tokio::test]
    async fn observation_is_coherent_bounded_and_historical() {
        let (_dir, b, reg) = fixture();
        let written = tokio::sync::Mutex::new(None);
        let valid = AtomicBool::new(false);
        let snapshot = || observe(Some(&b), &written, &valid);
        assert_eq!(snapshot().publication_observed, Some(false));
        assert_eq!(snapshot().last_ack_timestamp_seconds, None);
        assert_eq!(snapshot().durable_match, 2);
        let calls = Arc::new(AtomicU64::new(0));
        let puts = calls.clone();
        assert!(b
            .push_with_clock(
                &reg,
                move |_, _| {
                    puts.fetch_add(1, Ordering::Relaxed);
                    async { Ok(()) }
                },
                std::future::pending,
                || Some(123)
            )
            .await
            .unwrap());
        for _ in 0..2 {
            crate::signals::render_backup(&snapshot());
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(outcomes(&b), [1, 0, 0, 0]);
        assert!(!b
            .push_with_clock(
                &reg,
                |_, _| async { panic!("dedup PUT") },
                std::future::pending,
                || panic!("dedup changed receipt time")
            )
            .await
            .unwrap());
        assert_eq!(outcomes(&b), [1, 1, 0, 0]);
        let digest = b.last.lock().unwrap().digest;
        *written.lock().await = digest;
        assert_eq!(snapshot().durable_match, 2);
        valid.store(true, Ordering::Release);
        *written.lock().await = None;
        assert_eq!(snapshot().durable_match, 2);
        *written.lock().await = digest;
        assert_eq!(snapshot().durable_match, 0);
        let turn = b.turn.lock().await;
        b.blocked.store(true, Ordering::Release);
        assert_eq!(snapshot().last_ack_timestamp_seconds, Some(123));
        assert_eq!(snapshot().durable_match, 0);
        drop(turn);
        let durable = written.lock().await;
        assert_eq!(snapshot().publication_observed, Some(true));
        assert_eq!(snapshot().last_ack_timestamp_seconds, Some(123));
        assert_eq!(snapshot().durable_match, 2);
        drop(durable);
        *written.lock().await = Some([42; 32]);
        assert_eq!(snapshot().durable_match, 1);
        // Reverse the two digests: mismatch has no direction.
        {
            let mut last = b.last.lock().unwrap();
            last.digest = Some([42; 32]);
        }
        *written.lock().await = digest;
        assert_eq!(snapshot().durable_match, 1);
        {
            let _last = b.last.lock().unwrap();
            assert_eq!(snapshot().publication_observed, None);
            assert_eq!(snapshot().last_ack_timestamp_seconds, None);
            assert_eq!(snapshot().durable_match, 2);
        }
        let last = b.last.clone();
        assert!(std::panic::catch_unwind(move || {
            let _guard = last.lock().unwrap();
            panic!("synthetic poison");
        })
        .is_err());
        assert_eq!(snapshot().publication_observed, None);
        assert_eq!(snapshot().last_ack_timestamp_seconds, None);
        assert_eq!(snapshot().durable_match, 2);
        // Disabled observations do not touch either locked cache.
        let _durable = written.lock().await;
        let disabled = observe(None, &written, &valid);
        assert!(!disabled.configured);
        assert_eq!(disabled.publication_observed, Some(false));
        assert_eq!(disabled.caller_outcomes, [0; 4]);
    }

    #[tokio::test]
    async fn ack_commit_before_reply_consumption_can_have_canceled_caller() {
        let (_dir, b, reg) = fixture();
        let mut caller = Box::pin(b.push_with_clock(
            &reg,
            |_, _| async { Ok(()) },
            std::future::pending,
            || Some(55),
        ));
        assert!(futures::poll!(&mut caller).is_pending());
        // Lease release proves the owned transaction committed; caller is not polled.
        drop(bounded(b.turn.lock()).await);
        assert_eq!(b.last.lock().unwrap().ack_timestamp_seconds, Some(55));
        drop(caller);
        assert_eq!(outcomes(&b), [0, 0, 0, 1]);
        assert!(!b
            .push_with(&reg, |_, _| async { panic!("dedup issued PUT") })
            .await
            .unwrap());
        assert_eq!(outcomes(&b), [0, 1, 0, 1]);
        assert_eq!(b.last.lock().unwrap().ack_timestamp_seconds, Some(55));
    }

    #[tokio::test]
    async fn timeout_reply_not_consumed_before_drop_is_canceled() {
        let (_dir, b, reg) = fixture();
        let writes = PutFixture::new();
        let actual = writes.clone();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let (fire, mut deadline) = manual_deadline(1);
        let (elapsed, elapsed_wait) = tokio::sync::oneshot::channel();
        let mut elapsed = Some(elapsed);
        let mut index = 0;
        let mut caller = Box::pin(b.push_with_deadlines(
            &reg,
            move |object, sealed| actual.lock().unwrap().put(object, sealed, entered.take()),
            move || {
                let future = deadline();
                let elapsed = if index == 1 { elapsed.take() } else { None };
                index += 1;
                async move {
                    future.await;
                    if let Some(elapsed) = elapsed {
                        let _ = elapsed.send(());
                    }
                }
            },
        ));
        bounded(async {
            tokio::select! {
                _ = &mut caller => panic!("caller ended before entry"),
                result = entering => result.unwrap(),
            }
        })
        .await;
        fire.send(()).unwrap();
        bounded(elapsed_wait).await.unwrap();
        // Worker has sent timeout and is waiting on the gated SAME backend future.
        drop(caller);
        assert_eq!(outcomes(&b), [0, 0, 0, 1]);
        assert!(b.last.lock().unwrap().digest.is_none());
        cleanup(&b, &writes).await;
        assert!(b.last.lock().unwrap().digest.is_some());
        assert_eq!(outcomes(&b), [0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn preparation_failure_is_a_failed_caller_preserving_ack_history() {
        for seeded in [false, true] {
            let (_dir, b, reg) = fixture();
            if seeded {
                b.push_with_clock(
                    &reg,
                    |_, _| async { Ok(()) },
                    std::future::pending,
                    || Some(33),
                )
                .await
                .unwrap();
            }
            let prior = b.last.lock().unwrap().digest;
            assert!(std::panic::catch_unwind(|| {
                let _guard = reg.lock().unwrap();
                panic!("synthetic registry poison");
            })
            .is_err());
            assert!(b
                .push_with(&reg, |_, _| async { panic!("preparation issued PUT") })
                .await
                .is_err());
            assert_eq!(outcomes(&b), [u64::from(seeded), 0, 1, 0]);
            assert_eq!(b.last.lock().unwrap().digest, prior);
            assert_eq!(
                b.last.lock().unwrap().ack_timestamp_seconds,
                seeded.then_some(33)
            );
        }
    }

    #[tokio::test]
    async fn gated_ack_compares_with_durable_digest_at_observation_time() {
        let (_dir, b, reg) = fixture();
        let writes = PutFixture::new();
        let actual = writes.clone();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let mut caller = Box::pin(b.push_with_clock(
            &reg,
            move |object, sealed| actual.lock().unwrap().put(object, sealed, entered.take()),
            std::future::pending,
            || Some(77),
        ));
        bounded(async {
            tokio::select! {
                _ = &mut caller => panic!("caller ended before entry"),
                result = entering => result.unwrap(),
            }
        })
        .await;
        let written = tokio::sync::Mutex::new(Some([17; 32]));
        let valid = AtomicBool::new(true);
        assert_eq!(
            observe(Some(&b), &written, &valid).publication_observed,
            Some(false)
        );
        drop(caller);
        cleanup(&b, &writes).await;
        let observation = observe(Some(&b), &written, &valid);
        assert_eq!(observation.last_ack_timestamp_seconds, Some(77));
        assert_eq!(observation.durable_match, 1);
        assert_eq!(*written.lock().await, Some([17; 32]));
        assert_eq!(observation.caller_outcomes, [0, 0, 0, 1]);
    }

    fn fixture() -> (tempfile::TempDir, Backup, RegLock) {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let b = backup(dir.path(), &identity.to_public().to_string());
        let mut reg = Registry::default();
        reg.hosts.insert(
            "h1".into(),
            crate::static_host(
                &crate::config::StaticHost {
                    id: "h1".into(),
                    ..Default::default()
                },
                chrono::Utc::now(),
            ),
        );
        reg.pool_key("h1").unwrap();
        (dir, b, RegLock::new(reg))
    }

    #[tokio::test]
    async fn admission_deadline_and_unpolled_cancellation_start_no_work() {
        assert_eq!(PUT_WITHIN, Duration::from_secs(30));
        let (_dir, b, reg) = fixture();
        let turn = b.turn.lock().await;
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancel_calls = attempts.clone();
        let mut cancelled = Box::pin(b.push_with(&reg, move |_, _| {
            cancel_calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }));
        assert!(futures::poll!(&mut cancelled).is_pending());
        drop(cancelled);
        let calls = attempts.clone();
        let (fire, deadline) = manual_deadline(0);
        let mut waiting = Box::pin(b.push_with_deadlines(
            &reg,
            move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(()))
            },
            deadline,
        ));
        assert!(futures::poll!(&mut waiting).is_pending());
        fire.send(()).unwrap();
        assert!(bounded(&mut waiting).await.is_err());
        drop(waiting);
        drop(b.push_with(&reg, |_, _| async {
            panic!("unpolled caller started a PUT")
        }));
        drop(turn);
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert_eq!(outcomes(&b), [0, 0, 1, 1]);
        assert!(b.last.lock().unwrap().digest.is_none());
    }

    #[tokio::test]
    async fn caller_abort_after_launch_before_first_io_keeps_owned_worker() {
        let (_dir, b, reg) = fixture();
        let writes = PutFixture::new();
        let actual = writes.clone();
        let objects = writes.lock().unwrap().objects.clone();
        let mut caller = Box::pin(b.push_with(&reg, move |object, sealed| {
            actual.lock().unwrap().put(object, sealed, None)
        }));
        // The current-thread test has launched, but has not scheduled, the worker.
        assert!(futures::poll!(&mut caller).is_pending());
        assert!(objects.lock().unwrap().is_empty());
        drop(caller);
        cleanup(&b, &writes).await;
        assert_eq!(objects.lock().unwrap().len(), 2);
        assert!(b.last.lock().unwrap().digest.is_some());
        assert!(b.last.lock().unwrap().ack_timestamp_seconds.is_some());
        assert_eq!(outcomes(&b), [0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn returned_backend_errors_leave_no_ack_and_allow_retry() {
        for (fail_latest, seeded) in [(false, false), (true, false), (false, true), (true, true)] {
            let (_dir, b, reg) = fixture();
            if seeded {
                bounded(b.push_with(&reg, |_, _| async { Ok(()) }))
                    .await
                    .unwrap();
                reg.lock()
                    .unwrap()
                    .namespaces
                    .insert("next-snapshot".into(), "h1".into());
            }
            let prior_digest = b.last.lock().unwrap().digest;
            let prior_time = b.last.lock().unwrap().ack_timestamp_seconds;
            let writes = PutFixture::new();
            let actual = writes.clone();
            let result = bounded(b.push_with(&reg, move |object, sealed| {
                let fail = (object == LATEST) == fail_latest;
                let future = actual.lock().unwrap().put(object, sealed, None);
                async move {
                    future.await?;
                    // Model an error after the real publication, including sync failure.
                    if fail {
                        bail!("synthetic post-publication error");
                    }
                    Ok(())
                }
            }))
            .await;
            assert!(result.is_err());
            assert!(b.last.lock().unwrap().digest == prior_digest);
            assert_eq!(b.last.lock().unwrap().ack_timestamp_seconds, prior_time);
            assert_eq!(outcomes(&b), [u64::from(seeded), 0, 1, 0]);
            assert!(!b.blocked.load(Ordering::Acquire));
            cleanup(&b, &writes).await;
            assert!(bounded(b.push_with(&reg, |_, _| async { Ok(()) }))
                .await
                .unwrap());
            assert!(!bounded(b.push_with(&reg, |_, _| async {
                panic!("deduplicated snapshot issued a PUT")
            }))
            .await
            .unwrap());
        }
    }

    /// A bucket with versioning keeps each overwrite as a version and refuses a write to an
    /// object with too many (1,000 on some stores; the answer is a 400 `BadRequest`). Heartbeats
    /// rewrite `last_seen` and `used` every few seconds, so writing every change filled the
    /// limit in days and the backup then failed for good.
    #[tokio::test]
    async fn heartbeat_telemetry_does_not_write_a_version_each_minute() {
        const LIMIT: usize = 1000;
        let (_dir, b, reg) = fixture();
        let versions: Arc<Mutex<HashMap<String, usize>>> = Default::default();
        let store = versions.clone();
        let put = move |object: String, _: Arc<[u8]>| {
            let store = store.clone();
            async move {
                let mut store = store.lock().unwrap();
                let n = store.entry(object).or_default();
                if *n >= LIMIT {
                    bail!("400 Bad Request: the current object has too many versions");
                }
                *n += 1;
                Ok(())
            }
        };
        let push = || bounded(b.push_with(&reg, put.clone()));
        assert!(push().await.unwrap());
        // Three days of a heartbeat every ten seconds, a backup every minute.
        for beat in 1..=3 * 24 * 60 {
            {
                let mut reg = reg.lock().unwrap();
                let h = reg.hosts.get_mut("h1").unwrap();
                h.last_seen += chrono::Duration::seconds(60);
                h.used.memory_mb = beat % 97;
                h.disk_free_mb = Some(1000 + u64::from(beat % 31));
                h.boot_queue = Some(beat % 13);
                h.machines = (beat % 5) as usize;
            }
            assert!(!push().await.unwrap(), "beat {beat}");
        }
        let count = |object: &str| versions.lock().unwrap()[object];
        assert_eq!((count(LATEST), versions.lock().unwrap().len()), (1, 2));
        // A change a restore needs is written at once.
        reg.lock()
            .unwrap()
            .namespaces
            .insert("n1".into(), "h1".into());
        assert!(push().await.unwrap());
        assert_eq!(count(LATEST), 2);
        // Telemetry alone is written after an hour, so the backup is never older than that.
        reg.lock().unwrap().hosts.get_mut("h1").unwrap().used.vcpus += 1;
        assert!(!push().await.unwrap());
        {
            let mut last = b.last.lock().unwrap();
            last.published = Instant::now().checked_sub(TELEMETRY_REFRESH + Duration::from_secs(1));
        }
        assert!(push().await.unwrap());
        assert_eq!(count(LATEST), 3);
        // Nothing changed at all: still written after an hour, so an idle fleet's backup stays fresh.
        assert!(!push().await.unwrap());
        {
            let mut last = b.last.lock().unwrap();
            last.published = Instant::now().checked_sub(TELEMETRY_REFRESH + Duration::from_secs(1));
        }
        assert!(push().await.unwrap());
        assert_eq!(count(LATEST), 4);
    }

    fn synthetic_panic() -> Result<()> {
        panic!("synthetic publication worker panic")
    }

    #[tokio::test]
    async fn worker_panic_before_io_blocks_publication_but_keeps_historical_ack() {
        let (_dir, b, reg) = fixture();
        assert!(bounded(b.push_with(&reg, |_, _| async { Ok(()) }))
            .await
            .unwrap());
        reg.lock()
            .unwrap()
            .namespaces
            .insert("changed".into(), "h1".into());
        let result = bounded(b.push_with(&reg, |_, _| std::future::ready(synthetic_panic()))).await;
        assert!(result.is_err());
        let turn = bounded(b.turn.lock()).await;
        assert!(b.blocked.load(Ordering::Acquire));
        assert!(b.last.lock().unwrap().digest.is_some());
        drop(turn);
        let key = reg.lock().unwrap().hosts["h1"].pool_key.clone();
        assert!(b.holds("h1", &key).await);
        assert!(bounded(b.push_with(&reg, |_, _| async {
            panic!("blocked publication reached backend")
        }))
        .await
        .is_err());
    }

    #[tokio::test]
    async fn worker_panic_with_live_blocking_writer_blocks_the_next_turn() {
        let (_dir, b, reg) = fixture();
        let writes = PutFixture::new();
        let actual = writes.clone();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let (panic_now, panicking) = tokio::sync::oneshot::channel::<()>();
        let mut panicking = Some(panicking);
        let mut caller = Box::pin(b.push_with(&reg, move |object, sealed| {
            let future = actual.lock().unwrap().put(object, sealed, entered.take());
            let panicking = panicking.take().expect("first PUT");
            async move {
                tokio::select! {
                    _ = panicking => synthetic_panic(),
                    result = future => result,
                }
            }
        }));
        bounded(async {
            tokio::select! {
                _ = &mut caller => panic!("worker ended before blocking entry"),
                result = entering => result.expect("blocking writer entered"),
            }
        })
        .await;
        panic_now.send(()).unwrap();
        assert!(bounded(&mut caller).await.is_err());
        drop(caller);
        assert!(b.blocked.load(Ordering::Acquire));
        assert!(b.last.lock().unwrap().digest.is_none());
        assert!(bounded(b.push_with(&reg, |_, _| async {
            panic!("new publication passed the panic guard")
        }))
        .await
        .is_err());
        writes.lock().unwrap().release();
        cleanup(&b, &writes).await;
    }

    #[tokio::test]
    async fn poisoned_ack_cache_refuses_publication_and_key_eligibility() {
        let (_dir, b, reg) = fixture();
        bounded(b.push_with(&reg, |_, _| async { Ok(()) }))
            .await
            .unwrap();
        let key = reg.lock().unwrap().hosts["h1"].pool_key.clone();
        assert!(b.holds("h1", &key).await);
        let last = b.last.clone();
        let _ = std::panic::catch_unwind(move || {
            let _last = last.lock().unwrap();
            panic!("synthetic ACK cache poison");
        });
        assert!(!b.holds("h1", &key).await);
        assert!(bounded(b.push_with(&reg, |_, _| async {
            panic!("poisoned ACK cache reached backend")
        }))
        .await
        .is_err());
    }

    #[tokio::test]
    async fn timeout_can_later_ack_once_and_deduplicate_without_replay() {
        for (latest, fail, seeded) in [false, true].into_iter().flat_map(|latest| {
            [false, true]
                .into_iter()
                .flat_map(move |fail| [false, true].map(move |seeded| (latest, fail, seeded)))
        }) {
            let (_dir, b, reg) = fixture();
            if seeded {
                b.push_with_clock(
                    &reg,
                    |_, _| async { Ok(()) },
                    std::future::pending,
                    || Some(11),
                )
                .await
                .unwrap();
                reg.lock()
                    .unwrap()
                    .namespaces
                    .insert("changed".into(), "h1".into());
            }
            let prior_digest = b.last.lock().unwrap().digest;
            let writes = PutFixture::new();
            let actual = writes.clone();
            let objects = writes.lock().unwrap().objects.clone();
            let (entered, entering) = tokio::sync::oneshot::channel();
            let mut entered = Some(entered);
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let calls = attempts.clone();
            let (fire, deadline) = manual_deadline(if latest { 2 } else { 1 });
            let mut caller = Box::pin(b.push_with_clock(
                &reg,
                move |object, sealed| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let fail = fail && object == LATEST;
                    let gate = if (object == LATEST) == latest {
                        entered.take()
                    } else {
                        None
                    };
                    let future = actual.lock().unwrap().put(object, sealed, gate);
                    async move {
                        future.await?;
                        if fail {
                            bail!("synthetic late backend error");
                        }
                        Ok(())
                    }
                },
                deadline,
                || Some(22),
            ));
            bounded(async {
                tokio::select! {
                    _ = &mut caller => panic!("caller ended before gate"),
                    result = entering => result.unwrap(),
                }
            })
            .await;
            fire.send(()).unwrap();
            assert!(bounded(&mut caller).await.is_err());
            drop(caller);
            assert_eq!(b.last.lock().unwrap().digest, prior_digest);
            assert_eq!(
                b.last.lock().unwrap().ack_timestamp_seconds,
                seeded.then_some(11)
            );
            assert_eq!(outcomes(&b), [u64::from(seeded), 0, 1, 0]);
            assert!(b.turn.try_lock().is_err());
            writes.lock().unwrap().release();
            cleanup(&b, &writes).await;
            assert_eq!(objects.lock().unwrap().len(), 2);
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
            assert_eq!(b.last.lock().unwrap().digest.is_some(), seeded || !fail);
            assert_eq!(
                b.last.lock().unwrap().ack_timestamp_seconds,
                if fail { seeded.then_some(11) } else { Some(22) }
            );
            assert_eq!(outcomes(&b), [u64::from(seeded), 0, 1, 0]);
            if fail {
                continue;
            }
            assert!(
                !bounded(b.push_with(&reg, |_, _| async { panic!("late ACK was replayed") }))
                    .await
                    .unwrap()
            );
            assert_eq!(outcomes(&b), [u64::from(seeded), 1, 1, 0]);
            assert_eq!(b.last.lock().unwrap().ack_timestamp_seconds, Some(22));
        }
    }

    #[tokio::test]
    async fn unexpected_destruction_blocks_before_another_turn_is_admitted() {
        let turn = Arc::new(tokio::sync::Mutex::new(()));
        let blocked = Arc::new(AtomicBool::new(false));
        let guard = Publication {
            _turn: turn.clone().lock_owned().await,
            blocked: blocked.clone(),
            armed: true,
        };
        let mut waiting = Box::pin(turn.lock());
        assert!(futures::poll!(&mut waiting).is_pending());
        // Also covers a spawned transaction destroyed before its first poll.
        let unpolled = async move {
            let mut guard = guard;
            guard.disarm();
        };
        drop(unpolled);
        let _next = bounded(waiting).await;
        assert!(blocked.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn a_large_registry_uses_real_sdk_multipart_publication() {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let b = backup(dir.path(), &identity.to_public().to_string());
        let mut reg = Registry::default();
        // Above the object store's 32 MiB part boundary after age encryption.
        reg.unknown.insert(
            "multipart-marker".into(),
            serde_json::Value::String("m".repeat(33 << 20)),
        );
        reg.namespaces
            .insert("multipart-snapshot".into(), "h1".into());
        let reg = RegLock::new(reg);
        assert!(b.push(&reg).await.unwrap());
        let latest = b.fetch(LATEST, &identity).await.unwrap();
        assert!(latest.namespaces.contains_key("multipart-snapshot"));
        assert_eq!(
            latest.unknown["multipart-marker"].as_str().unwrap().len(),
            33 << 20
        );
        assert!(!b.push(&reg).await.unwrap());
    }

    /// A write reads the registry once it has its turn: one that waited behind another
    /// writes the registry as it is then, never the one it was called with.
    #[tokio::test]
    async fn a_write_that_waited_writes_the_newest_registry() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("backup.key");
        let b = std::sync::Arc::new(backup(&dir.path().join("store"), &keygen(&key).unwrap()));
        let reg = std::sync::Arc::new(RegLock::new(Registry::default()));
        let turn = b.turn.lock().await;
        let mut waiting = Box::pin(b.push(&reg));
        assert!(futures::poll!(&mut waiting).is_pending());
        reg.lock()
            .unwrap()
            .namespaces
            .insert("t-newer".into(), "h1".into());
        drop(turn);
        assert!(waiting.await.unwrap());
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
        let reg = RegLock::new(reg);
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

    fn registry_with_key(host: &str) -> (RegLock, PoolKey) {
        let mut reg = Registry::default();
        let h = crate::static_host(
            &crate::config::StaticHost {
                id: host.into(),
                url: "http://10.0.0.1:7420".into(),
                token: "t".into(),
                ..Default::default()
            },
            chrono::Utc::now(),
        );
        reg.hosts.insert(host.into(), h);
        let (k, _) = reg.pool_key(host).unwrap();
        (RegLock::new(reg), k)
    }

    /// A key the store acknowledged is still served after a restart, with the store out of
    /// reach; one it never acknowledged, a changed one and a corrupt file are not (ADR 0026).
    #[tokio::test]
    async fn an_acknowledged_key_survives_a_restart_without_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let rcpt = keygen(&dir.path().join("backup.key")).unwrap();
        let acks = dir.path().join("published-keys.json");
        let (reg, k) = registry_with_key("h1");

        let first = backup(&dir.path().join("store"), &rcpt).with_acks(acks.clone());
        assert!(first.push(&reg).await.unwrap());
        let saved = std::fs::read_to_string(&acks).unwrap();
        assert!(!saved.contains(k.expose()), "ids only, never the key");

        // After a restart nothing asks the store: the same target, whether or not it answers.
        let restart = || backup(&dir.path().join("store"), &rcpt);
        assert!(restart().with_acks(acks.clone()).holds("h1", &k).await);
        assert!(
            !restart().holds("h1", &k).await,
            "no file: it waits for a write"
        );
        let other = registry_with_key("h1").1;
        assert!(
            !restart().with_acks(acks.clone()).holds("h1", &other).await,
            "a key that changed matches no acknowledgement"
        );
        assert!(!restart().with_acks(acks.clone()).holds("h2", &k).await);

        // The same file under another store or another recipient lists nothing.
        let moved = backup(&dir.path().join("new-store"), &rcpt).with_acks(acks.clone());
        assert!(!moved.holds("h1", &k).await, "a new store holds no copy");
        let rotated = keygen(&dir.path().join("rotated.key")).unwrap();
        let rekeyed = backup(&dir.path().join("store"), &rotated).with_acks(acks.clone());
        assert!(
            !rekeyed.holds("h1", &k).await,
            "a new recipient holds no copy"
        );
        let saved = std::fs::read_to_string(&acks).unwrap();
        assert!(saved.contains("\"store\"") && saved.contains("\"recipient\""));
        assert!(!saved.contains("SECRET"), "no credential in the file");

        for corrupt in ["not json", "{\"a\":1}", ""] {
            std::fs::write(&acks, corrupt).unwrap();
            assert!(!restart().with_acks(acks.clone()).holds("h1", &k).await);
        }
        std::fs::remove_file(&acks).unwrap();
        assert!(!restart().with_acks(acks).holds("h1", &k).await);
    }

    /// With the backup off the file goes; a missing file is no error.
    #[test]
    fn the_acknowledgements_go_when_the_backup_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("published-keys.json");
        std::fs::write(&file, "{}").unwrap();
        drop_acks(&file);
        assert!(!file.exists());
        drop_acks(&file);
    }

    /// A file that cannot be saved is logged, and the key is still served from memory.
    #[tokio::test]
    async fn failing_to_save_the_acknowledgements_does_not_fail_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let rcpt = keygen(&dir.path().join("backup.key")).unwrap();
        let (reg, k) = registry_with_key("h1");
        let b = backup(&dir.path().join("store"), &rcpt)
            .with_acks(dir.path().join("no-such-dir/published-keys.json"));
        assert!(b.push(&reg).await.unwrap());
        assert!(b.acks.holds("h1", &k), "kept in memory");
        assert!(b.holds("h1", &k).await);
    }

    /// A cache poisoned by a panic refuses every key, whatever the file lists.
    #[tokio::test]
    async fn a_poisoned_cache_still_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let rcpt = keygen(&dir.path().join("backup.key")).unwrap();
        let acks = dir.path().join("published-keys.json");
        let (reg, k) = registry_with_key("h1");
        let first = backup(&dir.path().join("store"), &rcpt).with_acks(acks.clone());
        assert!(first.push(&reg).await.unwrap());
        let b = backup(&dir.path().join("store"), &rcpt).with_acks(acks);
        assert!(b.holds("h1", &k).await);
        let last = b.last.clone();
        let _ = std::thread::spawn(move || {
            let _guard = last.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(!b.holds("h1", &k).await);
    }
}
