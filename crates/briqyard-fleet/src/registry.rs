//! The hosts the fleet knows, where each namespace lives, and the decisions made from that:
//! placement, and when to add or release a host. Pure logic, tested without a network.

use briqyard_api::{self as api, Capacity, Condition, DaemonStart, Host};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
    /// How the host came: `static` (`hosts:`) or `manual` (`host add`).
    #[serde(default)]
    pub provider: String,
    /// ready, draining, retiring, upgrading, down, provisioning, bootstrapped, failed
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
    memory_mb: u32,
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

    /// Takes what a hold asks from the host's figures and keeps it.
    fn take(&mut self, mut hold: Hold) {
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
                 the bootstrap pins it, or hosts[].tls_fingerprint"
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
    if url.starts_with("https://") != !pinned.is_empty() {
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
    /// A host above this share of its memory takes no new namespace.
    pub fill_ceiling: f64,
    /// A host silent for this long is down.
    pub down_after: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
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
                            && (region.is_empty() || h.region == region)
                            && h.free_memory_mb() >= need_mb
                            && h.has_disk(need_disk_mb)
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
    pub fn hold(&mut self, host: &str, need_mb: u32, need_disk_mb: u64) -> u64 {
        let Some(h) = self.hosts.get_mut(host) else {
            return 0;
        };
        self.last_hold += 1;
        h.take(Hold {
            id: self.last_hold,
            memory_mb: need_mb,
            disk_mb: need_disk_mb,
            ..Default::default()
        });
        self.last_hold
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
        let Some(pressed) = roomy
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
    Disk,
    /// The host the create is bound to (a pinned namespace's, a fork's source's) is under a
    /// condition (ADR 0021): a new host does not fix it.
    Pressure,
}

impl Resource {
    pub const ALL: [Resource; 3] = [Resource::Memory, Resource::Disk, Resource::Pressure];

    pub fn as_str(self) -> &'static str {
        match self {
            Resource::Memory => "memory",
            Resource::Disk => "disk",
            Resource::Pressure => "pressure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, cap: u32, used: u32, machines: usize) -> HostRec {
        HostRec {
            id: id.into(),
            url: format!("http://{id}:7420"),
            ssh: String::new(),
            token: String::new(),
            tls_fingerprint: String::new(),
            region: "fsn".into(),
            provider: "static".into(),
            state: "ready".into(),
            capacity: Capacity {
                memory_mb: cap,
                vcpus: 32,
            },
            used: Capacity {
                memory_mb: used,
                vcpus: 0,
            },
            machines,
            namespaces: vec![],
            last_seen: Utc::now(),
            version: "0.1".into(),
            disk_free_mb: 0,
            note: String::new(),
            bootstrap_attempts: 0,
            public_tcp_ports: None,
            conditions: vec![],
            started: Default::default(),
            pool_key: PoolKey::default(),
            unknown: Unknown::new(),
            holds: Vec::new(),
        }
    }

    /// None yet is empty; a file that does not parse is an error, never an empty registry;
    /// what this fleet does not know is kept and written back, so a rollback loses nothing.
    #[test]
    fn a_registry_keeps_what_it_does_not_know_and_refuses_what_does_not_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        assert!(Registry::load(&path).unwrap().hosts.is_empty());
        let mut reg = Registry::default();
        reg.hosts.insert("h1".into(), host("h1", 1000, 0, 0));
        let (key, made) = reg.pool_key("h1").unwrap();
        assert!(made);
        assert_eq!(reg.pool_key("h1").unwrap(), (key.clone(), false));
        assert_eq!(format!("{key:?}"), "PoolKey(..)", "never printed");
        assert!(!format!("{:?}", reg.hosts["h1"]).contains(key.expose()));
        let mut v = serde_json::to_value(&reg).unwrap();
        v["hosts"]["h1"]["later"] = 1.into();
        v["later_too"] = serde_json::json!({"a": [1]});
        std::fs::write(&path, v.to_string()).unwrap();
        let back = Registry::load(&path).unwrap();
        assert_eq!(back.hosts["h1"].pool_key, key);
        let written = serde_json::to_value(&back).unwrap();
        assert_eq!(
            written["hosts"]["h1"]["later"], 1,
            "written back: {written}"
        );
        assert_eq!(written["later_too"], serde_json::json!({"a": [1]}));
        std::fs::write(&path, "{").unwrap();
        let err = Registry::load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("read the registry"), "{err:#}");
    }

    /// A condition of the host's, true or not.
    fn condition(kind: &str, status: bool) -> Condition {
        Condition {
            kind: kind.into(),
            status,
            since: Utc::now(),
            message: "pool 4.0 GB free of 100.0 (4%), under 10%".into(),
        }
    }

    #[test]
    fn a_host_under_pressure_takes_no_new_namespace() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut full = host("a", 100_000, 0, 1);
        full.conditions = vec![
            condition(api::condition::MEMORY_PRESSURE, false),
            condition(api::condition::DISK_PRESSURE, true),
        ];
        reg.heartbeat(full, now);
        reg.heartbeat(host("b", 100_000, 50_000, 5), now);
        let p = Policy::default();
        // The emptiest host is under pressure: the new namespace goes to the other one.
        assert_eq!(placed(&mut reg, "t1", 512, 0).unwrap().0, "b");
        assert_eq!(
            reg.hosts["a"].pressure().as_deref(),
            Some("host a is under disk_pressure: pool 4.0 GB free of 100.0 (4%), under 10%")
        );
        assert_eq!(reg.hosts["b"].pressure(), None);
        // Nor do the capacity signals count its memory as free.
        let (free, largest) = reg.room(&p)["fsn"];
        assert_eq!((free.memory_mb, largest.memory_mb), (49_488, 49_488));
        // The heartbeat that clears it lets it take namespaces again.
        let mut cleared = host("a", 100_000, 0, 1);
        cleared.conditions = vec![condition(api::condition::DISK_PRESSURE, false)];
        reg.heartbeat(cleared, now);
        assert_eq!(reg.place("t2", "", 512, 0, &p).as_deref(), Some("a"));
    }

    /// A host of `region` with `free` MB of memory and `disk` MB of disk free.
    fn roomy(id: &str, region: &str, free: u32, disk: u64) -> HostRec {
        let mut h = host(id, 100_000, 100_000 - free, 1);
        h.region = region.into();
        h.disk_free_mb = disk;
        h
    }

    #[test]
    fn room_counts_the_hosts_that_take_a_new_namespace() {
        let mut reg = Registry::default();
        let mut hosts = vec![
            roomy("a", "gra", 40_000, 500_000),
            roomy("b", "gra", 30_000, 900_000),
            // Its memory is free, it is not placed on: none of it counts.
            roomy("drained", "gra", 90_000, 900_000),
            roomy("down", "gra", 90_000, 900_000),
            roomy("pressed", "gra", 90_000, 900_000),
            roomy("full", "gra", 10_000, 900_000),
            // Reports no disk figure: its memory counts, no disk.
            roomy("v", "vin", 20_000, 0),
            roomy("gone", "sgp", 90_000, 900_000),
        ];
        hosts[2].state = "draining".into();
        hosts[3].state = "down".into();
        hosts[4].conditions = vec![condition(api::condition::DISK_PRESSURE, true)];
        hosts[7].state = "retiring".into();
        for h in hosts {
            reg.hosts.insert(h.id.clone(), h);
        }
        let room = reg.room(&Policy::default());
        let r = |memory_mb, disk_mb| api::Room { memory_mb, disk_mb };
        assert_eq!(room["gra"], (r(70_000, 1_400_000), r(40_000, 900_000)));
        assert_eq!(room["vin"], (r(20_000, 0), r(20_000, 0)));
        assert_eq!(
            room["sgp"],
            (r(0, 0), r(0, 0)),
            "a region whose hosts take nothing is listed, with nothing"
        );
        assert_eq!(room.len(), 3);
    }

    #[test]
    fn a_shortage_names_what_ran_out() {
        let mut reg = Registry::default();
        let mut pressed = roomy("pressed", "gra", 60_000, 900_000);
        pressed.conditions = vec![condition(api::condition::MEMORY_PRESSURE, true)];
        for h in [
            roomy("a", "gra", 40_000, 5_000),
            pressed,
            roomy("v", "vin", 20_000, 0),
        ] {
            reg.hosts.insert(h.id.clone(), h);
        }
        let p = Policy::default();
        let short = |region, mb, disk| reg.shortage(region, mb, disk, &p);
        // No host of gra under its ceiling has 70 GB.
        assert_eq!(short("gra", 70_000, 0), Resource::Memory);
        assert_eq!(short("sgp", 512, 0), Resource::Memory, "no host there");
        // a has the memory, not the disk; pressed has both, under memory pressure: memory.
        assert_eq!(short("gra", 50_000, 10_000), Resource::Memory);
        assert_eq!(short("gra", 30_000, 1_000_000), Resource::Disk);
        // Under disk pressure: disk.
        reg.hosts.get_mut("pressed").unwrap().conditions =
            vec![condition(api::condition::DISK_PRESSURE, true)];
        let short = |region, mb, disk| reg.shortage(region, mb, disk, &p);
        assert_eq!(short("gra", 50_000, 10_000), Resource::Disk);
        // No region asked: every region's hosts, and none has 1 TB.
        assert_eq!(short("", 30_000, 1_000_000), Resource::Disk);
        // What place refuses, shortage names; what it takes, it would not be asked about.
        assert_eq!(reg.place("t1", "gra", 30_000, 10_000, &p), None);
        assert_eq!(
            reg.place("t2", "gra", 30_000, 2_000, &p).as_deref(),
            Some("a")
        );
    }

    #[test]
    fn a_new_namespace_is_placed_in_its_region_and_its_region_is_its_hosts() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut gra = host("gra1", 100_000, 50_000, 1);
        gra.region = "gra".into();
        let mut vin = host("vin1", 100_000, 0, 0);
        vin.region = "vin".into();
        reg.heartbeat(gra, now);
        reg.heartbeat(vin.clone(), now);
        let p = Policy::default();
        // vin1 is the emptiest; t1 asks for gra.
        assert_eq!(reg.place("t1", "gra", 512, 0, &p).as_deref(), Some("gra1"));
        assert_eq!(reg.region_of("t1"), Some("gra"));
        assert_eq!(
            reg.place("t2", "", 512, 0, &p).as_deref(),
            Some("vin1"),
            "any"
        );
        assert_eq!(reg.place("t3", "sgp", 512, 0, &p), None, "no host there");
        assert_eq!(
            reg.place("t4", "gra", 60_000, 0, &p),
            None,
            "the region is full, whatever the others have"
        );
        assert_eq!(reg.region_of("t4"), None, "nothing pinned");
        // Pinned, a namespace's machines go to its host whatever is asked: the caller refuses
        // another region.
        assert_eq!(reg.place("t1", "vin", 512, 0, &p).as_deref(), Some("gra1"));
        let h = reg.host_of_namespace("t1").unwrap();
        assert_eq!(h.outside("t1", "gra"), None);
        assert_eq!(h.outside("t1", ""), None, "no region asked");
        assert_eq!(
            h.outside("t1", "vin").as_deref(),
            Some("namespace t1 is in region \"gra\" (host gra1), not \"vin\": a namespace never spans regions")
        );
        // A namespace a heartbeat pins is in its host's region.
        vin.namespaces = vec!["t9".into()];
        reg.heartbeat(vin, now);
        assert_eq!(reg.region_of("t9"), Some("vin"));
    }

    #[test]
    fn a_heartbeat_lands_on_the_record_at_its_address() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut added = host("h_srv-9", 0, 0, 0);
        added.url = "http://10.0.0.9:7420".into();
        added.state = "bootstrapped".into();
        added.provider = "manual".into();
        added.token = "t0k".into();
        added.tls_fingerprint = "ab".repeat(32);
        reg.hosts.insert(added.id.clone(), added);
        assert_eq!(
            reg.expecting("http://10.0.0.9:7421/")
                .map(|h| h.id.as_str()),
            Some("h_srv-9"),
            "the address, whatever the port"
        );
        assert_eq!(reg.expecting("http://10.0.0.8:7420").map(|h| &h.id), None);
        // The daemon reports under its own id; the fleet applies it to the record it added.
        let mut hb = host("h_srv-9", 64_000, 0, 0);
        hb.url = "http://10.0.0.9:7420".into();
        hb.token.clear();
        hb.provider.clear();
        reg.heartbeat(hb, now);
        assert_eq!(reg.hosts.len(), 1);
        let h = &reg.hosts["h_srv-9"];
        assert_eq!(
            h.state, "ready",
            "an added host is ready at its first heartbeat"
        );
        assert_eq!(h.provider, "manual", "a heartbeat does not touch it");
        assert_eq!(h.token, "t0k", "nor the token");
        assert_eq!(h.tls_fingerprint, "ab".repeat(32), "nor the pin");
        assert_eq!(h.capacity.memory_mb, 64_000);
        assert_eq!(url_host("http://[::1]:7420/x"), "[::1]");
        assert_eq!(url_host("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn a_heartbeat_must_report_the_pinned_certificate() {
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let https = "https://10.0.0.9:7420";
        let http = "http://10.0.0.9:7420";
        assert_eq!(tls_matches(&a, &a, https), Ok(()));
        assert_eq!(tls_matches("", "", http), Ok(()), "a host on plain HTTP");
        let err = tls_matches(&a, &b, https).unwrap_err();
        assert!(
            err.starts_with(&format!("certificate {b} is not the one pinned ({a})")),
            "{err}"
        );
        // No trust on first use: TLS with nothing pinned is refused.
        let err = tls_matches("", &b, https).unwrap_err();
        assert!(err.contains("no fingerprint is pinned"), "{err}");
        let err = tls_matches(&a, "", http).unwrap_err();
        assert!(err.contains("serves plain HTTP"), "{err}");
        // The URL the fleet dials follows the pin.
        assert!(tls_matches(&a, &a, http)
            .unwrap_err()
            .contains("must advertise https://"));
        assert!(tls_matches("", "", https)
            .unwrap_err()
            .contains("must advertise http://"));
    }

    #[test]
    fn a_heartbeat_drops_pins_the_host_no_longer_has() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut a = host("a", 1000, 0, 1);
        a.namespaces = vec!["t1".into(), "t2".into()];
        reg.heartbeat(a, now);
        reg.heartbeat(host("b", 1000, 500, 0), now);
        reg.namespaces.insert("tb".into(), "b".into());
        // A placement just pinned t3 to a (the emptier host); a does not list it yet: the pin stays.
        assert_eq!(
            reg.place("t3", "", 10, 0, &Policy::default()).as_deref(),
            Some("a")
        );
        let mut a = host("a", 1000, 0, 1);
        a.namespaces = vec!["t2".into()];
        reg.heartbeat(a.clone(), now);
        assert_eq!(reg.namespaces.get("t1"), None, "t1 left host a");
        assert_eq!(
            reg.namespaces.get("t3").map(String::as_str),
            Some("a"),
            "a fresh pin stays"
        );
        reg.pinned_at
            .insert("t3".into(), now - Duration::minutes(11));
        reg.heartbeat(a, now);
        assert_eq!(
            reg.namespaces.get("t3"),
            None,
            "an old pin the host never confirmed goes"
        );
        assert_eq!(reg.namespaces.get("t2").map(String::as_str), Some("a"));
        assert_eq!(
            reg.namespaces.get("tb").map(String::as_str),
            Some("b"),
            "another host's pin stays"
        );
    }

    #[test]
    fn retire_waits_for_the_host_to_empty() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut busy = host("a", 1000, 100, 1);
        busy.namespaces = vec!["t".into()];
        reg.heartbeat(busy, now);
        reg.hosts.get_mut("a").unwrap().state = "retiring".into();
        assert!(reg.retirable().is_empty());
        let mut empty = host("a", 1000, 0, 0);
        empty.namespaces.clear();
        reg.heartbeat(empty, now);
        reg.namespaces.clear();
        assert_eq!(
            reg.hosts["a"].state, "retiring",
            "a heartbeat keeps a retire"
        );
        assert_eq!(reg.retirable().len(), 1);
        // A drained host stays drained, empty or not: only a retire forgets.
        let mut fixed = host("s", 1000, 0, 0);
        fixed.namespaces.clear();
        reg.heartbeat(fixed, now);
        reg.hosts.get_mut("s").unwrap().state = "draining".into();
        assert_eq!(
            reg.retirable()
                .iter()
                .map(|h| h.id.as_str())
                .collect::<Vec<_>>(),
            ["a"]
        );
        assert_eq!(
            reg.place("t2", "", 10, 0, &Policy::default()),
            None,
            "no placement on a retiring host"
        );
        // A drain, an upgrade: kept by a heartbeat, never forgotten, nothing placed.
        for state in ["draining", "upgrading"] {
            reg.hosts.get_mut("a").unwrap().state = state.into();
            reg.heartbeat(host("a", 1000, 0, 0), now);
            assert_eq!(reg.hosts["a"].state, state);
            assert!(reg.retirable().is_empty(), "{state}");
            assert_eq!(
                reg.place("t2", "", 10, 0, &Policy::default()),
                None,
                "{state}"
            );
            assert!(
                reg.listed().iter().any(|h| h.id == "a"),
                "a listing asks a host {state}"
            );
        }
    }

    #[test]
    fn placement_pins_namespaces_and_picks_the_emptiest_host() {
        let now = Utc::now();
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 100_000, 90_000, 10), now);
        reg.heartbeat(host("b", 100_000, 20_000, 2), now);
        reg.heartbeat(host("c", 100_000, 50_000, 5), now);
        let p = Policy::default();
        assert_eq!(reg.place("t1", "", 512, 0, &p).as_deref(), Some("b"));
        assert_eq!(
            reg.place("t1", "", 512, 0, &p).as_deref(),
            Some("b"),
            "a namespace stays where it is"
        );
        // c is next; a is over the ceiling.
        reg.hosts.get_mut("b").unwrap().used.memory_mb = 99_000;
        assert_eq!(reg.place("t2", "", 512, 0, &p).as_deref(), Some("c"));
        assert_eq!(reg.place("t3", "", 60_000, 0, &p), None, "nothing has room");
        reg.hosts.get_mut("c").unwrap().disk_free_mb = 1000;
        assert_eq!(
            reg.place("t4", "", 512, 5000, &p),
            None,
            "c has memory but no disk"
        );
        assert_eq!(reg.place("t5", "", 512, 500, &p).as_deref(), Some("c"));
    }

    /// `place` and `hold`, as a create does them.
    fn placed(reg: &mut Registry, namespace: &str, mb: u32, disk: u64) -> Option<(String, u64)> {
        let host = reg.place(namespace, "", mb, disk, &Policy::default())?;
        let hold = reg.hold(&host, mb, disk);
        Some((host, hold))
    }

    #[test]
    fn a_hold_counts_until_a_report_after_the_create_or_its_failure() {
        let t0 = Utc::now();
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 100_000, 0, 0), t0);
        reg.heartbeat(host("b", 100_000, 10_000, 1), t0);
        let p = Policy::default();
        // A burst: the second namespace sees the first one's memory taken on a.
        let (a, t1) = placed(&mut reg, "t1", 60_000, 3000).unwrap();
        assert_eq!(a, "a");
        assert_eq!(reg.hosts["a"].used.memory_mb, 60_000);
        assert_eq!(placed(&mut reg, "t2", 50_000, 0).unwrap().0, "b");
        // A pinned namespace's machine holds too, memory and disk.
        reg.hosts.get_mut("a").unwrap().disk_free_mb = 10_000;
        let (_, t1b) = placed(&mut reg, "t1", 10_000, 4000).unwrap();
        assert_eq!(reg.hosts["a"].used.memory_mb, 70_000);
        assert_eq!(reg.hosts["a"].disk_free_mb, 6000);
        let (free, largest) = reg.room(&p)["fsn"];
        assert_eq!(
            (free.memory_mb, largest.memory_mb),
            (70_000, 40_000),
            "the capacity signals see the holds too"
        );
        assert_eq!(reg.hold("nobody", 5000, 0), 0, "no host, nothing held");
        // A report while both creates are under way: they still count, on its figures.
        let t2 = t0 + Duration::seconds(15);
        let mut report = host("a", 100_000, 1000, 0);
        report.disk_free_mb = 20_000;
        reg.heartbeat(report, t2);
        assert_eq!(reg.hosts["a"].used.memory_mb, 71_000);
        assert_eq!(reg.hosts["a"].disk_free_mb, 13_000);
        // The first failed: what it held is back at once, not at the next report.
        reg.release("a", t1);
        reg.release("a", t1);
        assert_eq!(reg.hosts["a"].used.memory_mb, 11_000, "released once");
        assert_eq!(reg.hosts["a"].disk_free_mb, 16_000);
        // The second was made: counted until a report received after it, then the host's.
        reg.made("a", t1b, t2 + Duration::seconds(1));
        let mut report = host("a", 100_000, 1000, 0);
        report.disk_free_mb = 20_000;
        reg.heartbeat(report.clone(), t2 + Duration::milliseconds(500));
        assert_eq!(
            reg.hosts["a"].used.memory_mb, 11_000,
            "a report from before"
        );
        report.used.memory_mb = 11_000;
        report.disk_free_mb = 16_000;
        reg.heartbeat(report, t2 + Duration::seconds(2));
        assert_eq!(
            reg.hosts["a"].used.memory_mb, 11_000,
            "the host's figure, once"
        );
        assert_eq!(reg.hosts["a"].disk_free_mb, 16_000);
        assert!(reg.hosts["a"].holds.is_empty());
        // A hold never takes disk a host does not report, nor gives back more than it took.
        let t3 = reg.hold("b", 1000, 50_000);
        assert_eq!(reg.hosts["b"].disk_free_mb, 0, "b reports no disk figure");
        reg.release("b", t3);
        assert_eq!(reg.hosts["b"].disk_free_mb, 0);
    }

    #[test]
    fn unpin_releases_a_namespace_for_a_new_placement() {
        let now = Utc::now();
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 100_000, 0, 0), now);
        reg.heartbeat(host("b", 100_000, 0, 0), now);
        let first = placed(&mut reg, "t1", 60_000, 0).unwrap().0;
        assert!(reg.pinned_at.contains_key("t1"));
        reg.unpin("t1");
        assert_eq!(reg.namespaces.get("t1"), None);
        assert!(!reg.pinned_at.contains_key("t1"));
        assert_ne!(
            placed(&mut reg, "t1", 10_000, 0).unwrap().0,
            first,
            "placed afresh, on the host with the most room"
        );
        reg.unpin("never-pinned");
    }

    #[test]
    fn forget_drops_the_host_and_its_index() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut a = host("a", 1000, 0, 1);
        a.namespaces = vec!["t1".into()];
        reg.heartbeat(a, now);
        reg.heartbeat(host("b", 1000, 0, 0), now);
        reg.machines.insert("m1".into(), "a".into());
        reg.machines.insert("m2".into(), "b".into());
        reg.endpoints.insert("e1".into(), "a".into());
        reg.namespaces.insert("t2".into(), "b".into());
        reg.forget("a");
        assert!(!reg.hosts.contains_key("a"));
        assert_eq!(reg.namespaces.get("t1"), None);
        assert_eq!(reg.namespaces.get("t2").map(String::as_str), Some("b"));
        assert_eq!(reg.machines.get("m1"), None);
        assert_eq!(reg.machines.get("m2").map(String::as_str), Some("b"));
        assert_eq!(reg.endpoints.get("e1"), None);
        assert_eq!(reg.listed().len(), 1);
        reg.forget("a");
        assert!(
            reg.retired_keys.is_empty(),
            "a host with no key leaves none"
        );
    }

    /// A forgotten host's pool key stays, found by its id beside the live hosts' (ADR 0035).
    #[test]
    fn a_forgotten_hosts_key_is_kept_for_its_backups() {
        let now = Utc::now();
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 1000, 0, 0), now);
        reg.heartbeat(host("b", 1000, 0, 0), now);
        let (ka, _) = reg.pool_key("a").unwrap();
        let (kb, _) = reg.pool_key("b").unwrap();
        let id = |k: &PoolKey| briqyard_api::poolkey::id(k.expose()).unwrap();
        assert_eq!(reg.key_by_id(&id(&kb)), Some(("b".into(), kb.clone())));
        reg.forget("a");
        assert_eq!(reg.key_by_id(&id(&ka)), Some(("a".into(), ka.clone())));
        assert_eq!(reg.key_by_id(&"0".repeat(32)), None);
        let back: Registry = serde_json::from_slice(&serde_json::to_vec(&reg).unwrap()).unwrap();
        assert_eq!(back.key_by_id(&id(&ka)), Some(("a".into(), ka)));
    }

    #[test]
    fn silent_hosts_go_down_and_come_back() {
        let now = Utc::now();
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 1000, 0, 0), now - Duration::seconds(120));
        reg.sweep(&Policy::default(), now);
        assert_eq!(reg.hosts["a"].state, "down");
        reg.heartbeat(host("a", 1000, 0, 0), now);
        assert_eq!(reg.hosts["a"].state, "ready");
    }
}
