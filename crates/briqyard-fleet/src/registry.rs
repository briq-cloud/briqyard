//! The hosts the fleet knows, where each tenant lives, and the decisions made from that:
//! placement, and when to add or release a host. Pure logic, tested without a network.

use briqyard_api::{Capacity, Host};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A host as the fleet keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostRec {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub provider: String,
    /// The provider's own id for the server, when the fleet provisioned it.
    #[serde(default)]
    pub provider_id: String,
    /// ready, draining, down, provisioning
    pub state: String,
    #[serde(default)]
    pub capacity: Capacity,
    #[serde(default)]
    pub used: Capacity,
    #[serde(default)]
    pub machines: usize,
    #[serde(default)]
    pub tenants: Vec<String>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub version: String,
    /// Free space for disks, in MB, from the last heartbeat.
    #[serde(default)]
    pub disk_free_mb: u64,
    /// When the host last had a machine, for the release decision.
    #[serde(default)]
    pub empty_since: Option<DateTime<Utc>>,
    /// The last thing the provisioner or the bootstrap said.
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub bootstrap_attempts: u32,
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
            region: self.region.clone(),
            provider: self.provider.clone(),
            state: self.state.clone(),
            capacity: self.capacity,
            used: self.used,
            machines: self.machines,
            tenants: self.tenants.clone(),
            last_seen: self.last_seen,
            version: self.version.clone(),
            note: self.note.clone(),
        }
    }
}

/// Placement settings.
#[derive(Clone, Debug)]
pub struct Policy {
    /// A host above this share of its memory takes no new tenant.
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
    /// tenant → host id. A tenant's machines share a host, so its network needs no overlay.
    pub tenants: HashMap<String, String>,
    /// machine id → host id, learned from creates and listings.
    pub machines: HashMap<String, String>,
}

impl Registry {
    /// Applies a heartbeat. A host the fleet did not know is added as ready.
    pub fn heartbeat(&mut self, mut h: HostRec, now: DateTime<Utc>) {
        // A server the fleet ordered registers under the daemon's own id: the record made at
        // the order (provider, its id, the token the bootstrap gave it) carries over by address.
        if !self.hosts.contains_key(&h.id) && !h.url.is_empty() {
            let ordered = self
                .hosts
                .values()
                .find(|x| {
                    matches!(x.state.as_str(), "provisioning" | "bootstrapped")
                        && !x.url.is_empty()
                        && url_host(&x.url) == url_host(&h.url)
                })
                .map(|x| x.id.clone());
            if let Some(id) = ordered {
                let old = self.hosts.remove(&id).unwrap();
                h.provider = old.provider;
                h.provider_id = old.provider_id;
                if h.token.is_empty() {
                    h.token = old.token;
                }
                if h.region.is_empty() {
                    h.region = old.region;
                }
                h.note = old.note;
            }
        }
        let entry = self.hosts.entry(h.id.clone()).or_insert_with(|| HostRec {
            state: "ready".into(),
            empty_since: Some(now),
            ..h.clone()
        });
        entry.url = h.url;
        if !h.token.is_empty() {
            entry.token = h.token;
        }
        if !h.region.is_empty() {
            entry.region = h.region;
        }
        entry.capacity = h.capacity;
        entry.used = h.used;
        entry.machines = h.machines;
        entry.tenants = h.tenants.clone();
        entry.version = h.version;
        entry.disk_free_mb = h.disk_free_mb;
        entry.last_seen = now;
        if entry.state == "down" {
            entry.state = "ready".into();
        }
        entry.empty_since = if h.machines == 0 {
            entry.empty_since.or(Some(now))
        } else {
            None
        };
        for t in h.tenants {
            self.tenants.entry(t).or_insert_with(|| entry.id.clone());
        }
    }

    /// Draining hosts that have nothing left on them: ready to be released.
    pub fn retirable(&self) -> Vec<HostRec> {
        self.hosts
            .values()
            .filter(|h| h.state == "draining" && h.machines == 0 && h.tenants.is_empty())
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

    /// The host of a tenant, or the best host for a new one: the readiest with the most free
    /// memory under the ceiling, with room for `need_mb` of memory and `need_disk_mb` of disk
    /// (a host that reports no disk figure is not held to it).
    pub fn place(
        &mut self,
        tenant: &str,
        need_mb: u32,
        need_disk_mb: u64,
        policy: &Policy,
    ) -> Option<String> {
        if let Some(h) = self.tenants.get(tenant) {
            return Some(h.clone());
        }
        let best = self
            .hosts
            .values()
            .filter(|h| {
                h.state == "ready"
                    && h.fill() < policy.fill_ceiling
                    && h.free_memory_mb() >= need_mb
                    && (h.disk_free_mb == 0 || h.disk_free_mb >= need_disk_mb)
            })
            .max_by_key(|h| h.free_memory_mb())?;
        let id = best.id.clone();
        self.tenants.insert(tenant.to_string(), id.clone());
        Some(id)
    }

    pub fn host_of_tenant(&self, tenant: &str) -> Option<&HostRec> {
        self.tenants.get(tenant).and_then(|id| self.hosts.get(id))
    }

    pub fn host_of_machine(&self, machine: &str) -> Option<&HostRec> {
        self.machines.get(machine).and_then(|id| self.hosts.get(id))
    }

    /// Hosts that answer requests.
    pub fn ready(&self) -> Vec<HostRec> {
        let mut v: Vec<HostRec> = self
            .hosts
            .values()
            .filter(|h| h.state == "ready" || h.state == "draining")
            .cloned()
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Memory free across ready hosts under the ceiling, and the largest single slot.
    pub fn free(&self, policy: &Policy) -> (u32, u32) {
        let mut total = 0;
        let mut largest = 0;
        for h in self.hosts.values() {
            if h.state != "ready" || h.fill() >= policy.fill_ceiling {
                continue;
            }
            let f = h.free_memory_mb();
            total += f;
            largest = largest.max(f);
        }
        (total, largest)
    }
}

/// What the autoscaler may do.
#[derive(Clone, Debug)]
pub struct ScalePolicy {
    pub min_hosts: usize,
    pub max_hosts: usize,
    /// Add a host when no ready host can take a machine of this size.
    pub slot_mb: u32,
    /// Release a host that has been empty for this long.
    pub idle_grace: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Nothing,
    AddHost,
    ReleaseHost(String),
}

/// Decides one step. Provisioning hosts count toward the maximum so one scale-up at a time.
pub fn decide(
    reg: &Registry,
    placement: &Policy,
    scale: &ScalePolicy,
    now: DateTime<Utc>,
) -> Decision {
    let counted = reg.hosts.values().filter(|h| h.state != "down").count();
    let provisioning = reg.hosts.values().any(|h| h.state == "provisioning");
    let (_, largest) = reg.free(placement);
    if largest < scale.slot_mb && counted < scale.max_hosts && !provisioning {
        return Decision::AddHost;
    }
    if counted > scale.min_hosts {
        let mut idle: Vec<&HostRec> = reg
            .hosts
            .values()
            .filter(|h| h.state == "ready" && h.machines == 0 && h.tenants.is_empty())
            .filter(|h| matches!(h.empty_since, Some(t) if now - t > scale.idle_grace))
            .filter(|h| !h.provider_id.is_empty())
            .collect();
        idle.sort_by_key(|h| h.empty_since);
        if let Some(h) = idle.first() {
            return Decision::ReleaseHost(h.id.clone());
        }
    }
    Decision::Nothing
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, cap: u32, used: u32, machines: usize) -> HostRec {
        HostRec {
            id: id.into(),
            url: format!("http://{id}:7420"),
            token: String::new(),
            region: "fsn".into(),
            provider: "static".into(),
            provider_id: String::new(),
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
            tenants: vec![],
            last_seen: Utc::now(),
            version: "0.1".into(),
            disk_free_mb: 0,
            empty_since: None,
            note: String::new(),
            bootstrap_attempts: 0,
        }
    }

    #[test]
    fn an_ordered_host_registers_under_its_own_id() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut ordered = host("h_srv-9", 0, 0, 0);
        ordered.url = "http://10.0.0.9:7420".into();
        ordered.state = "bootstrapped".into();
        ordered.provider = "scaleway".into();
        ordered.provider_id = "srv-9".into();
        ordered.token = "t0k".into();
        reg.hosts.insert(ordered.id.clone(), ordered);
        let mut hb = host("h_byard-20261019", 64_000, 0, 0);
        hb.url = "http://10.0.0.9:7420".into();
        hb.provider.clear();
        reg.heartbeat(hb, now);
        assert!(!reg.hosts.contains_key("h_srv-9"));
        let h = &reg.hosts["h_byard-20261019"];
        assert_eq!(h.state, "ready");
        assert_eq!(h.provider_id, "srv-9");
        assert_eq!(h.token, "t0k");
        assert_eq!(url_host("http://[::1]:7420/x"), "[::1]");
        assert_eq!(url_host("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn retire_waits_for_the_host_to_empty() {
        let now = Utc::now();
        let mut reg = Registry::default();
        let mut busy = host("a", 1000, 100, 1);
        busy.tenants = vec!["t".into()];
        reg.heartbeat(busy, now);
        reg.hosts.get_mut("a").unwrap().state = "draining".into();
        assert!(reg.retirable().is_empty());
        let mut empty = host("a", 1000, 0, 0);
        empty.tenants.clear();
        reg.heartbeat(empty, now);
        reg.tenants.clear();
        assert_eq!(
            reg.hosts["a"].state, "draining",
            "a heartbeat keeps a drain"
        );
        assert_eq!(reg.retirable().len(), 1);
        assert_eq!(
            reg.place("t2", 10, 0, &Policy::default()),
            None,
            "no placement on a draining host"
        );
    }

    #[test]
    fn placement_pins_tenants_and_picks_the_emptiest_host() {
        let now = Utc::now();
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 100_000, 90_000, 10), now);
        reg.heartbeat(host("b", 100_000, 20_000, 2), now);
        reg.heartbeat(host("c", 100_000, 50_000, 5), now);
        let p = Policy::default();
        assert_eq!(reg.place("t1", 512, 0, &p).as_deref(), Some("b"));
        assert_eq!(
            reg.place("t1", 512, 0, &p).as_deref(),
            Some("b"),
            "a tenant stays where it is"
        );
        // c is next; a is over the ceiling.
        reg.hosts.get_mut("b").unwrap().used.memory_mb = 99_000;
        assert_eq!(reg.place("t2", 512, 0, &p).as_deref(), Some("c"));
        assert_eq!(reg.place("t3", 60_000, 0, &p), None, "nothing has room");
        reg.hosts.get_mut("c").unwrap().disk_free_mb = 1000;
        assert_eq!(
            reg.place("t4", 512, 5000, &p),
            None,
            "c has memory but no disk"
        );
        assert_eq!(reg.place("t5", 512, 500, &p).as_deref(), Some("c"));
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

    #[test]
    fn scaling_decisions() {
        let now = Utc::now();
        let p = Policy::default();
        let scale = ScalePolicy {
            min_hosts: 1,
            max_hosts: 3,
            slot_mb: 8192,
            idle_grace: Duration::hours(2),
        };
        let mut reg = Registry::default();
        reg.heartbeat(host("a", 100_000, 95_000, 20), now);
        assert_eq!(
            decide(&reg, &p, &scale, now),
            Decision::AddHost,
            "no slot left"
        );
        reg.heartbeat(host("b", 100_000, 0, 0), now);
        assert_eq!(
            decide(&reg, &p, &scale, now),
            Decision::Nothing,
            "b has room and is young"
        );
        // A heartbeat never changes who provisioned a host; that is set when the fleet orders it.
        reg.hosts.get_mut("b").unwrap().provider_id = "srv-2".into();
        reg.hosts.get_mut("b").unwrap().empty_since = Some(now - Duration::hours(3));
        assert_eq!(
            decide(&reg, &p, &scale, now),
            Decision::ReleaseHost("b".into()),
            "b idle past the grace"
        );
        reg.hosts.get_mut("b").unwrap().provider_id.clear();
        assert_eq!(
            decide(&reg, &p, &scale, now),
            Decision::Nothing,
            "a static host is never released"
        );
    }
}
