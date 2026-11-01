//! The hosts the fleet knows, where each namespace lives, and the decisions made from that:
//! placement, and when to add or release a host. Pure logic, tested without a network.

use briqyard_api::{self as api, Capacity, Condition, DaemonStart, Host};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

mod tokens;
pub use tokens::*;

/// What a registry or host record holds that this fleet does not know, kept as it was and
/// written back: a fleet older than its registry (a rollback) loses nothing at its next write.
pub type Unknown = BTreeMap<String, serde_json::Value>;

/// A host's pool key (ADR 0026): 32 random bytes as 64 hex digits, ZFS's `hex` key format.
/// Never printed: its `Debug` shows nothing of it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PoolKey(String);

impl PoolKey {
    fn random() -> PoolKey {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        PoolKey(b.iter().map(|x| format!("{x:02x}")).collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The key itself, for the one answer that carries it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "PoolKey(none)"
        } else {
            "PoolKey(..)"
        })
    }
}

/// A host as the fleet keeps it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostRec {
    #[serde(default)]
    pub egress_siblings_v1: bool,
    #[serde(default)]
    pub named_memory_fork_v1: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_memory_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warm_pool_profiles: Vec<String>,
    pub id: String,
    pub url: String,
    /// The address the bootstrap reaches the server at over SSH, when it is not the API's
    /// (a host added with its API on a private network, ADR 0028); empty: the API's.
    #[serde(default)]
    pub ssh: String,
    /// The host's API token: what the fleet forwards with, and what the host's heartbeats
    /// present. Made at `host add` (the bootstrap writes it into the host) or set by `hosts:`.
    #[serde(default)]
    pub token: String,
    /// The SHA-256 of the host's API certificate: the only certificate the fleet accepts from
    /// it, and the one its heartbeats must report. Set by the bootstrap or by `hosts:`; empty
    /// for a host on plain HTTP (ADR 0020).
    #[serde(default)]
    pub tls_fingerprint: String,
    #[serde(default)]
    pub region: String,
    /// How the host came: `static` (`hosts:`), `manual` (`host add`) or `join` (a join token).
    #[serde(default)]
    pub provider: String,
    /// ready, draining, retiring, upgrading, down, provisioning, bootstrapped, joining, failed
    pub state: String,
    #[serde(default)]
    pub capacity: Capacity,
    /// What the host reported last, plus what its holds took since (ADR 0044).
    #[serde(default)]
    pub used: Capacity,
    #[serde(default)]
    pub machines: usize,
    #[serde(default)]
    #[serde(alias = "tenants")]
    pub namespaces: Vec<String>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub version: String,
    /// Free space for disks, in MB, from the last report, less what its holds took since.
    #[serde(default)]
    pub disk_free_mb: u64,
    /// The last thing the bootstrap or an upgrade said.
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub bootstrap_attempts: u32,
    /// `PUBLIC_TCP_PORTS` for this host's bootstrap (ADR 0028): what its public interface takes
    /// besides SSH, and its machines reach on it. Set when the fleet adds it, from the request or
    /// `bootstrap.public_tcp_ports`, so a later change of either leaves
    /// it; absent (a record from before): that fleet-wide value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_tcp_ports: Option<Vec<u16>>,
    /// Memory and disk pressure, from the last heartbeat (ADR 0021).
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// The labels of the join token the host came with (ADR 0059).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// The id of the join token the host came with (ADR 0059); empty: it did not join.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub join_token: String,
    /// The key of the host's pool (ADR 0026), made the first time the host asks for it and
    /// served to that host alone; never in `to_api`, gone with the record.
    #[serde(default, skip_serializing_if = "PoolKey::is_empty")]
    pub pool_key: PoolKey,
    /// Fields this fleet does not know, written back as they were.
    #[serde(flatten)]
    pub unknown: Unknown,
    /// The daemon's last start, from the last heartbeat (ADR 0027).
    #[serde(default)]
    pub started: Option<DaemonStart>,
    /// What placement counted on the host that its last report did not (ADR 0044). In memory
    /// only: the next report after a restart is the truth.
    #[serde(skip)]
    pub holds: Vec<Hold>,
}

/// A create (or a gateway) placed on a host, counted in its `used` and `disk_free_mb` until a
/// report counts it instead (ADR 0044).
#[derive(Clone, Debug, Default)]
pub struct Hold {
    id: u64,
    namespace: String,
    memory_mb: u32,
    cpu_millis: u32,
    disk_mb: u64,
    /// What it took from `disk_free_mb`: less than `disk_mb` when the host had less.
    took_disk_mb: u64,
    /// When the host answered the create: a report received after that counts the machine.
    made: Option<DateTime<Utc>>,
}

/// Whether a host in this state serves its machines. Placement takes only `ready`; a host
/// `draining` (taking nothing new), `retiring` (forgotten once empty) or `upgrading` (ADR
/// 0027) still answers for what it has.
pub fn serving(state: &str) -> bool {
    matches!(state, "ready" | "draining" | "retiring" | "upgrading")
}

/// The host part of a URL (`http://10.0.0.5:7420` → `10.0.0.5`).
pub fn url_host(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let rest = rest.split('/').next().unwrap_or(rest);
    rest.rsplit_once(':').map(|(h, _)| h).unwrap_or(rest)
}

impl HostRec {
    pub fn free_memory_mb(&self) -> u32 {
        self.capacity.memory_mb.saturating_sub(self.used.memory_mb)
    }

    pub fn free_cpu_millis(&self) -> u32 {
        self.capacity
            .cpu_millis()
            .saturating_sub(self.used.cpu_millis())
    }

    fn has_cpu(&self, need: u32) -> bool {
        self.capacity.cpu_millis.is_some() && self.free_cpu_millis() >= need
    }

    /// Takes what a hold asks from the host's figures and keeps it.
    fn take(&mut self, mut hold: Hold) {
        self.used.cpu_millis = Some(self.used.cpu_millis().saturating_add(hold.cpu_millis));
        self.used.memory_mb = self.used.memory_mb.saturating_add(hold.memory_mb);
        hold.took_disk_mb = hold.disk_mb.min(self.disk_free_mb);
        self.disk_free_mb -= hold.took_disk_mb;
        self.holds.push(hold);
    }

    /// The host's own figures, received at `at`: they replace what the fleet had, and the holds
    /// they do not count yet (a create not answered by then) are taken from them again.
    pub fn report(&mut self, used: Capacity, disk_free_mb: u64, at: DateTime<Utc>) {
        self.used = used;
        self.disk_free_mb = disk_free_mb;
        for hold in std::mem::take(&mut self.holds) {
            if hold.made.is_none_or(|made| made > at) {
                self.take(hold);
            }
        }
    }

    pub fn fill(&self) -> f64 {
        if self.capacity.memory_mb == 0 {
            return 1.0;
        }
        self.used.memory_mb as f64 / self.capacity.memory_mb as f64
    }

    pub fn to_api(&self) -> Host {
        Host {
            egress_siblings_v1: self.egress_siblings_v1,
            named_memory_fork_v1: self.named_memory_fork_v1,
            named_memory_profiles: self.named_memory_profiles.clone(),
            warm_pool_profiles: self.warm_pool_profiles.clone(),
            id: self.id.clone(),
            url: self.url.clone(),
            ssh: self.ssh.clone(),
            region: self.region.clone(),
            provider: self.provider.clone(),
            state: self.state.clone(),
            capacity: self.capacity,
            used: self.used,
            machines: self.machines,
            namespaces: self.namespaces.clone(),
            last_seen: self.last_seen,
            version: self.version.clone(),
            note: self.note.clone(),
            tls_fingerprint: self.tls_fingerprint.clone(),
            labels: self.labels.clone(),
            public_tcp_ports: self.public_tcp_ports.clone().unwrap_or_default(),
            conditions: self.conditions.clone(),
            started: self.started,
        }
    }

    /// Why the host takes nothing new: a condition that is true (ADR 0021).
    pub fn pressure(&self) -> Option<String> {
        api::under_pressure(&self.conditions)
            .map(|c| format!("host {} is under {}: {}", self.id, c.kind, c.message))
    }

    /// Why a machine asked in `region` cannot join `namespace` on this host: a namespace never spans
    /// regions (ADR 0025). No region asked: any.
    pub fn outside(&self, namespace: &str, region: &str) -> Option<String> {
        (!region.is_empty() && self.region != region).then(|| {
            format!(
                "namespace {namespace} is in region {:?} (host {}), not {region:?}: a namespace never spans regions",
                self.region, self.id
            )
        })
    }

    /// Whether a new namespace may be placed here: ready, under the ceiling, no pressure.
    fn takes_new_namespaces(&self, policy: &Policy) -> bool {
        self.has_memory_for_namespaces(policy) && self.pressure().is_none()
    }

    /// Ready and under the fill ceiling: what `takes_new_namespaces` asks but the conditions.
    fn has_memory_for_namespaces(&self, policy: &Policy) -> bool {
        self.state == "ready" && self.fill() < policy.fill_ceiling
    }

    /// Whether `need_disk_mb` fits in its pool: a host that reports no disk figure is not held
    /// to it.
    fn has_disk(&self, need_disk_mb: u64) -> bool {
        self.disk_free_mb == 0 || self.disk_free_mb >= need_disk_mb
    }
}

/// Whether a heartbeat's TLS is what the host's record pinned: the same fingerprint (both
/// empty for a host on plain HTTP), and an `https://` URL exactly when there is one. A host on
/// TLS with nothing pinned is refused: the pin comes from the bootstrap or the operator, never
/// from the heartbeat itself.
pub fn tls_matches(pinned: &str, reported: &str, url: &str) -> Result<(), String> {
    if reported != pinned {
        return Err(if pinned.is_empty() {
            format!(
                "the host serves TLS (certificate {reported}) and no fingerprint is pinned for it: \
                 the bootstrap pins it (a host that joined, at its first heartbeat), or hosts[].tls_fingerprint"
            )
        } else if reported.is_empty() {
            format!("the host serves plain HTTP and certificate {pinned} is pinned for it")
        } else {
            format!(
                "certificate {reported} is not the one pinned ({pinned}): another machine at \
                 this address, or a new certificate to pin"
            )
        });
    }
    if url.starts_with("https://") == pinned.is_empty() {
        return Err(format!(
            "{url}: a host {} must advertise {}",
            if pinned.is_empty() {
                "on plain HTTP"
            } else {
                "with a pinned certificate"
            },
            if pinned.is_empty() {
                "http://"
            } else {
                "https://"
            }
        ));
    }
    Ok(())
}

/// Placement settings.
#[derive(Clone, Debug)]
pub struct Policy {
    /// This placement requires the explicit namespace sibling capability.
    pub require_egress_siblings: bool,
    pub require_named_memory: bool,
    pub named_memory_profile: String,
    /// A host above this share of its memory takes no new namespace.
    pub fill_ceiling: f64,
    /// A host silent for this long is down.
    pub down_after: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_egress_siblings: false,
            require_named_memory: false,
            named_memory_profile: "init-ready-v1".into(),
            fill_ceiling: 0.85,
            down_after: Duration::seconds(60),
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Registry {
    pub hosts: HashMap<String, HostRec>,
    /// namespace → host id. A namespace's machines share a host, so its network needs no overlay.
    #[serde(alias = "tenants")]
    pub namespaces: HashMap<String, String>,
    /// Dispatch intents survive network cleanup and host removal without holding resources.
    #[serde(default)]
    pub sandbox_requests: HashMap<String, crate::create_replay::SandboxRoute>,
    #[serde(default)]
    pub namespace_versions: HashMap<String, u64>,
    /// machine id → host id, learned from creates and listings.
    pub machines: HashMap<String, String>,
    /// endpoint id → host id, learned the same way.
    #[serde(default)]
    pub endpoints: HashMap<String, String>,
    /// When each namespace was pinned by a placement (not by a heartbeat).
    #[serde(default)]
    pub pinned_at: HashMap<String, DateTime<Utc>>,
    /// The pool keys of forgotten hosts (ADR 0035): a host's backups are encrypted under its
    /// key, so the key outlives the record, for a restore on another host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_keys: Vec<RetiredKey>,
    /// The join tokens (ADR 0059): their hashes, never a secret.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_tokens: Vec<JoinTokenRec>,
    /// Fields this fleet does not know, written back as they were.
    #[serde(flatten)]
    pub unknown: Unknown,
    /// The id of the last hold made (ADR 0044).
    #[serde(skip)]
    last_hold: u64,
}

/// A forgotten host's pool key, kept for its backups.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetiredKey {
    pub host: String,
    pub key: PoolKey,
    pub retired_at: DateTime<Utc>,
}

impl Registry {
    /// The registry in `path`; none yet is an empty one. A file that cannot be read or parsed
    /// is an error, never an empty registry: the next write would replace every host's token
    /// and pool key with nothing (ADR 0026). Fields it does not know are kept (`unknown`).
    pub fn load(path: &std::path::Path) -> anyhow::Result<Registry> {
        use anyhow::Context;
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data)
                .with_context(|| format!("read the registry {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(e) => Err(e).with_context(|| format!("read the registry {}", path.display())),
        }
    }

    /// The record a heartbeat from `url` belongs to: the one host at that address.
    pub fn expecting(&self, url: &str) -> Option<&HostRec> {
        self.hosts
            .values()
            .find(|h| !h.url.is_empty() && url_host(&h.url) == url_host(url))
    }

    /// Applies a heartbeat (or a poll's answer) to the record of its id, added as ready when
    /// the fleet did not have it. What the host reports replaces what placement reserved.
    pub fn heartbeat(&mut self, h: HostRec, now: DateTime<Utc>) {
        let entry = self.hosts.entry(h.id.clone()).or_insert_with(|| HostRec {
            state: "ready".into(),
            ..h.clone()
        });
        entry.url = h.url;
        if !h.token.is_empty() {
            entry.token = h.token;
        }
        if !h.tls_fingerprint.is_empty() {
            entry.tls_fingerprint = h.tls_fingerprint;
        }
        if !h.region.is_empty() {
            entry.region = h.region;
        }
        entry.capacity = h.capacity;
        entry.report(h.used, h.disk_free_mb, now);
        entry.machines = h.machines;
        entry.namespaces = h.namespaces.clone();
        entry.version = h.version;
        entry.egress_siblings_v1 = h.egress_siblings_v1;
        entry.named_memory_fork_v1 = h.named_memory_fork_v1;
        entry.named_memory_profiles = h.named_memory_profiles;
        entry.warm_pool_profiles = h.warm_pool_profiles;
        entry.conditions = h.conditions.clone();
        entry.started = h.started;
        entry.last_seen = now;
        // A host that answers is ready, whatever it was (down, added, failed to bootstrap);
        // only what an operator asked is kept: a drain, a retire, an upgrade under way.
        if !serving(&entry.state) {
            entry.state = "ready".into();
        }
        // The host's list is the truth for the namespaces pinned to it: a pin whose namespace the host
        // no longer has (removed on the host, or a leftover) goes, so the name can be placed again.
        // A pin made at placement is younger than the machine it placed: the host lists the
        // namespace only once the create has landed, so a fresh pin is kept whatever the host says.
        let id = entry.id.clone();
        let pinned_at = &self.pinned_at;
        self.namespaces.retain(|t, host| {
            *host != id
                || h.namespaces.contains(t)
                || pinned_at
                    .get(t)
                    .map(|at| now - *at < Duration::minutes(10))
                    .unwrap_or(false)
        });
        for t in h.namespaces {
            self.namespaces.entry(t).or_insert_with(|| id.clone());
        }
        self.pinned_at
            .retain(|t, _| self.namespaces.contains_key(t));
    }

    /// The pool key of a host, made now when it has none (`true` then): the caller writes the
    /// registry before it hands a new key out, so a key in use is never one only memory held.
    pub fn pool_key(&mut self, id: &str) -> Option<(PoolKey, bool)> {
        let h = self.hosts.get_mut(id)?;
        let made = h.pool_key.is_empty();
        if made {
            h.pool_key = PoolKey::random();
        }
        Some((h.pool_key.clone(), made))
    }

    /// The pool key of id `key_id` (`briqyard_api::poolkey::id`), a host's or a forgotten
    /// host's, with whose it is: the key a backup is encrypted under (ADR 0035).
    pub fn key_by_id(&self, key_id: &str) -> Option<(String, PoolKey)> {
        let live = self.hosts.values().map(|h| (&h.id, &h.pool_key));
        let retired = self.retired_keys.iter().map(|r| (&r.host, &r.key));
        live.chain(retired)
            .find(|(_, k)| briqyard_api::poolkey::id(k.expose()).as_deref() == Some(key_id))
            .map(|(h, k)| (h.clone(), k.clone()))
    }

    /// Drops a host and everything indexed to it but its pool key, kept as a retired key: its
    /// backups stay readable (ADR 0035).
    pub fn forget(&mut self, id: &str) {
        if let Some(h) = self.hosts.remove(id).filter(|h| !h.pool_key.is_empty()) {
            self.retired_keys.push(RetiredKey {
                host: h.id,
                key: h.pool_key,
                retired_at: Utc::now(),
            });
        }
        self.namespaces.retain(|_, h| h != id);
        self.machines.retain(|_, h| h != id);
        self.endpoints.retain(|_, h| h != id);
        self.pinned_at
            .retain(|t, _| self.namespaces.contains_key(t));
    }

    /// Retiring hosts that have nothing left on them: ready to be forgotten. A drained host
    /// stays drained, whoever gave it (ADR 0027).
    pub fn retirable(&self) -> Vec<HostRec> {
        self.hosts
            .values()
            .filter(|h| h.state == "retiring" && h.machines == 0 && h.namespaces.is_empty())
            .cloned()
            .collect()
    }

    /// Marks silent hosts down.
    pub fn sweep(&mut self, policy: &Policy, now: DateTime<Utc>) {
        for h in self.hosts.values_mut() {
            if h.state == "ready" && now - h.last_seen > policy.down_after {
                h.state = "down".into();
            }
        }
    }

    /// The host of a namespace, or the best host for a new one: of `region` when one is asked
    /// (ADR 0025), the readiest with the most free memory under the ceiling and no pressure,
    /// with room for `need_mb` of memory and `need_disk_mb` of disk (a host that reports no
    /// disk figure is not held to it). The caller then holds the need on the host (`hold`),
    /// so a burst of creates does not all land on the host the last report showed emptiest.
    /// A pinned namespace's host under pressure or in another region is the caller's to refuse
    /// (`HostRec::pressure`, `other_region`).
    pub fn place(
        &mut self,
        namespace: &str,
        region: &str,
        need_mb: u32,
        need_disk_mb: u64,
        need_cpu_millis: u32,
        policy: &Policy,
    ) -> Option<String> {
        let id = match self.namespaces.get(namespace) {
            Some(h) => h.clone(),
            None => {
                let best = self
                    .hosts
                    .values()
                    .filter(|h| {
                        h.takes_new_namespaces(policy)
                            && (!policy.require_egress_siblings || h.egress_siblings_v1)
                            && (!policy.require_named_memory
                                || (h.named_memory_fork_v1
                                    && h.named_memory_profiles
                                        .iter()
                                        .any(|p| p == &policy.named_memory_profile)))
                            && (region.is_empty() || h.region == region)
                            && h.free_memory_mb() >= need_mb
                            && h.has_disk(need_disk_mb)
                            && h.has_cpu(need_cpu_millis)
                    })
                    .max_by_key(|h| h.free_memory_mb())?;
                let id = best.id.clone();
                self.namespaces.insert(namespace.to_string(), id.clone());
                self.pinned_at.insert(namespace.to_string(), Utc::now());
                id
            }
        };
        Some(id)
    }

    /// Counts a machine about to be created on a host as used (ADR 0044): its id, for the
    /// caller to `made` once the host made it, or to `release` when it did not. 0: no such
    /// host, nothing held.
    pub fn hold(
        &mut self,
        host: &str,
        need_mb: u32,
        need_disk_mb: u64,
        need_cpu_millis: u32,
    ) -> u64 {
        let Some(h) = self.hosts.get_mut(host) else {
            return 0;
        };
        self.last_hold += 1;
        h.take(Hold {
            id: self.last_hold,
            memory_mb: need_mb,
            cpu_millis: need_cpu_millis,
            disk_mb: need_disk_mb,
            ..Default::default()
        });
        self.last_hold
    }

    pub fn bind_hold_namespace(&mut self, host: &str, id: u64, namespace: &str) {
        if let Some(hold) = self
            .hosts
            .get_mut(host)
            .and_then(|h| h.holds.iter_mut().find(|hold| hold.id == id))
        {
            hold.namespace = namespace.into();
            self.note_namespace_create(namespace);
        }
    }
    pub fn namespace_inflight(&self, namespace: &str) -> bool {
        self.hosts.values().any(|host| {
            host.holds
                .iter()
                .any(|hold| hold.namespace == namespace && hold.made.is_none())
        })
    }
    /// The host made what hold `id` held, at `at`: the next report received after that counts
    /// it, and the hold goes then.
    pub fn made(&mut self, host: &str, id: u64, at: DateTime<Utc>) {
        if let Some(hold) = self
            .hosts
            .get_mut(host)
            .and_then(|h| h.holds.iter_mut().find(|x| x.id == id))
        {
            hold.made = Some(at);
        }
    }

    /// The host did not make what hold `id` held (it refused, or did not answer): what it took
    /// is given back at once.
    pub fn release(&mut self, host: &str, id: u64) {
        let Some(h) = self.hosts.get_mut(host) else {
            return;
        };
        let Some(i) = h.holds.iter().position(|x| x.id == id) else {
            return;
        };
        let hold = h.holds.remove(i);
        h.used.cpu_millis = Some(h.used.cpu_millis().saturating_sub(hold.cpu_millis));
        h.used.memory_mb = h.used.memory_mb.saturating_sub(hold.memory_mb);
        h.disk_free_mb += hold.took_disk_mb;
    }

    /// Pins a namespace to a host that holds it now, when it has no pin: a namespace made on a
    /// host without a placement (a move or a fork into a new one, ADR 0056). Kept at least as
    /// long as a placement's, until the host lists the namespace.
    pub fn pin(&mut self, namespace: &str, host: &str) {
        if !self.namespaces.contains_key(namespace) {
            self.namespaces.insert(namespace.into(), host.into());
            self.pinned_at.insert(namespace.into(), Utc::now());
        }
    }

    /// Releases a namespace from its host: its next machine is placed afresh. The host's next
    /// heartbeat pins it again if the namespace still has machines there.
    pub fn unpin(&mut self, namespace: &str) {
        self.namespaces.remove(namespace);
        self.pinned_at.remove(namespace);
    }

    /// Advance placement identity on every admitted create, including an existing network.
    pub fn note_namespace_create(&mut self, namespace: &str) {
        let version = self.namespace_versions.entry(namespace.into()).or_default();
        *version = version.saturating_add(1);
    }
    pub fn namespace_version(&self, namespace: &str) -> u64 {
        *self.namespace_versions.get(namespace).unwrap_or(&0)
    }
    pub fn host_of_namespace(&self, namespace: &str) -> Option<&HostRec> {
        self.namespaces
            .get(namespace)
            .and_then(|id| self.hosts.get(id))
    }

    /// A namespace's region: its host's. No second record of it, so the two cannot disagree.
    pub fn region_of(&self, namespace: &str) -> Option<&str> {
        self.host_of_namespace(namespace).map(|h| h.region.as_str())
    }

    pub fn host_of_machine(&self, machine: &str) -> Option<&HostRec> {
        self.machines.get(machine).and_then(|id| self.hosts.get(id))
    }

    /// Hosts that answer requests.
    pub fn ready(&self) -> Vec<HostRec> {
        self.sorted(|h| serving(&h.state))
    }

    /// Hosts a listing must ask: every one that may hold machines, down ones included, since
    /// a listing that cannot ask one of them fails rather than leaving its machines out.
    pub fn listed(&self) -> Vec<HostRec> {
        self.sorted(|h| serving(&h.state) || h.state == "down")
    }

    fn sorted(&self, keep: impl Fn(&HostRec) -> bool) -> Vec<HostRec> {
        let mut v: Vec<HostRec> = self.hosts.values().filter(|h| keep(h)).cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// What ran out when `place` found no host for a new namespace's machine: memory when no host
    /// of the region is ready and under its ceiling with `need_mb` free; else disk when none of
    /// those has `need_disk_mb`; else (those that have both are under a condition) what the
    /// condition of the one with the most memory free says: disk for `disk_pressure`, memory
    /// otherwise. Never `Pressure`: a new host fixes each of these.
    pub fn shortage(
        &self,
        region: &str,
        need_mb: u32,
        need_disk_mb: u64,
        need_cpu_millis: u32,
        policy: &Policy,
    ) -> Resource {
        let roomy: Vec<&HostRec> = self
            .hosts
            .values()
            .filter(|h| {
                h.has_memory_for_namespaces(policy)
                    && (region.is_empty() || h.region == region)
                    && h.free_memory_mb() >= need_mb
            })
            .collect();
        if roomy.is_empty() {
            return Resource::Memory;
        }
        let cpu_room: Vec<_> = roomy
            .into_iter()
            .filter(|h| h.has_cpu(need_cpu_millis))
            .collect();
        if cpu_room.is_empty() {
            return Resource::Cpu;
        }
        let Some(pressed) = cpu_room
            .iter()
            .filter(|h| h.has_disk(need_disk_mb))
            .max_by_key(|h| h.free_memory_mb())
        else {
            return Resource::Disk;
        };
        match api::under_pressure(&pressed.conditions) {
            Some(c) if c.kind == api::condition::DISK_PRESSURE => Resource::Disk,
            _ => Resource::Memory,
        }
    }

    /// Each region a host is in, with what its hosts that take a new namespace have free: the
    /// sum, and the most on one host (`(free, largest_slot)`). A host that reports no disk
    /// figure adds none.
    pub fn room(&self, policy: &Policy) -> BTreeMap<String, (api::Room, api::Room)> {
        let mut out: BTreeMap<String, (api::Room, api::Room)> = BTreeMap::new();
        for h in self.hosts.values() {
            let (free, largest) = out.entry(h.region.clone()).or_default();
            if !h.takes_new_namespaces(policy) {
                continue;
            }
            let (memory, disk) = (h.free_memory_mb() as u64, h.disk_free_mb);
            free.memory_mb += memory;
            free.disk_mb += disk;
            largest.memory_mb = largest.memory_mb.max(memory);
            largest.disk_mb = largest.disk_mb.max(disk);
        }
        out
    }
}

/// What a create found missing when no host took it (ADR 0042).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resource {
    Memory,
    Cpu,
    Disk,
    /// The host the create is bound to (a pinned namespace's, a fork's source's) is under a
    /// condition (ADR 0021): a new host does not fix it.
    Pressure,
}

impl Resource {
    pub const ALL: [Resource; 4] = [
        Resource::Memory,
        Resource::Cpu,
        Resource::Disk,
        Resource::Pressure,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Resource::Memory => "memory",
            Resource::Cpu => "cpu",
            Resource::Disk => "disk",
            Resource::Pressure => "pressure",
        }
    }
}

#[cfg(test)]
mod tests;
