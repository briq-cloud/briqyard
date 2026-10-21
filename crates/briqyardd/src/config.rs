//! The daemon's configuration file.

use crate::{fc, netw};
use anyhow::{bail, Context, Result};
use briqyard_api as api;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The API's address. Served over TLS unless it is loopback or `api_tls` is false.
    pub listen: String,
    /// TLS on the API with the daemon's own certificate (`<data_dir>/api-cert.pem`, ADR
    /// 0020). A loopback `listen` is plain HTTP whatever this says: nothing leaves the host.
    pub api_tls: bool,
    /// When set, required as `Authorization: Bearer <token>` on every request.
    pub token: String,
    /// A token of its own for `/metrics`, so a scraper never holds the API's. Unset, the
    /// API token is required there too, except on a loopback listener where `/metrics` and
    /// `/v1/openapi.yaml` are open.
    pub metrics_token: String,
    /// State, per-machine runtime files and the image cache.
    pub data_dir: PathBuf,
    pub firecracker: PathBuf,
    /// The jailer binary; empty runs Firecracker without it (development only: the jailer is
    /// what keeps a machine to its own user, chroot, pid namespace and cgroup).
    pub jailer: PathBuf,
    /// Where the jailer makes each machine's chroot (default `<data_dir>/jail`).
    pub jail_dir: PathBuf,
    /// The first uid of the range machines run as: one per machine, from here.
    pub jail_uid_base: u32,
    /// The uncompressed guest kernel every machine boots.
    pub kernel: PathBuf,
    /// Appended to the default boot arguments.
    pub kernel_args: String,
    /// Firecracker's PCI transport (needs a guest kernel with PCI support).
    pub pci: bool,
    /// The briqyard-init binary copied into every root disk.
    pub init: PathBuf,
    pub storage: Storage,
    /// Credentials for private registries, by host ("ghcr.io", "registry-1.docker.io").
    pub registries: Vec<Registry>,
    pub network: Network,
    /// The limits on every machine's internet traffic, unless the machine sets its own
    /// (ADR 0018).
    pub egress_limits: EgressLimits,
    /// The limits on each disk of every machine, by its size, unless the machine sets its own
    /// (ADR 0030).
    pub disk_limits: DiskLimits,
    pub ingress: Ingress,
    /// The size of every root disk (thin: only written blocks take space).
    pub root_disk_gb: u32,
    /// An image no machine uses is removed this many days after it was built.
    pub image_keep_days: u32,
    /// Closed hours of usage are kept this many days (ADR 0017).
    pub usage_keep_days: u32,
    /// Events are kept this many days (ADR 0019), and at most `events::MAX_EVENTS` of them.
    pub events_keep_days: u32,
    /// How long a tag's resolution (which digest `alpine:3.20` is) is reused before asking the
    /// registry again: a burst of creates makes one registry call, not one each.
    pub image_resolve_minutes: u32,
    /// How long a guest may take to answer after its process starts before the start fails.
    pub boot_timeout_sec: u64,
    /// Boots run at once; the rest wait their turn, each with the whole timeout once it
    /// starts. 0: half the hardware threads, at least 2.
    pub boots_at_once: u32,
    /// Sleep with a memory snapshot instead of a stop, so a wake resumes in well under a
    /// second. Costs the machine's memory in disk while it sleeps.
    pub suspend_on_sleep: bool,
    pub fleet: Option<FleetClient>,
    pub backup: Backup,
    /// What the daemon advertises: memory it may hand to machines (default: the host's memory
    /// minus 2 GB) and vCPUs (default: hardware threads times 4).
    pub capacity: Capacity,
    /// When the host is under pressure (ADR 0021).
    pub conditions: Conditions,
    /// A running machine's console is rotated past this size, one previous file kept.
    pub console_max_mb: u32,
}

/// The thresholds of the host's conditions (ADR 0021), in percent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Conditions {
    /// `memory_pressure`: committed memory over this share of capacity.
    pub memory_pct: u32,
    /// `disk_pressure`: the pool's free space under this share of its size.
    pub disk_free_pct: u32,
}

impl Default for Conditions {
    fn default() -> Self {
        Self {
            memory_pct: 95,
            disk_free_pct: 10,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Registry {
    pub host: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    pub backend: String,
    /// The ZFS pool (or dataset) that holds every disk.
    pub pool: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    /// The pool of tenant subnets, carved into /24s.
    pub range: String,
    /// Upstream DNS servers the gateway forwards to. Default: the host's resolv.conf, then 1.1.1.1.
    pub upstream_dns: Vec<String>,
    /// The host interface machines reach the internet through. Empty: the default route's.
    pub egress: String,
}

/// Limits on a machine's internet traffic, every field set: the host's defaults, and what a
/// machine runs with once its own values are put over them (ADR 0018).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressLimits {
    /// Destination ports refused, TCP and UDP.
    pub blocked_ports: Vec<u16>,
    /// New connections a minute; 0 is no limit.
    pub new_connections_per_minute: u32,
    /// Mbit/s, in and out together; 0 is no limit.
    pub bandwidth_mbit: u32,
}

impl Default for EgressLimits {
    /// Mail is what gets a server's address blocklisted first.
    fn default() -> Self {
        Self {
            blocked_ports: vec![25],
            new_connections_per_minute: 0,
            bandwidth_mbit: 0,
        }
    }
}

impl EgressLimits {
    /// These, with a machine's own values over them; the ports sorted, once each.
    pub fn with(&self, own: &api::EgressLimits) -> EgressLimits {
        let l = own.over(&self.view());
        let mut blocked_ports = l.blocked_ports.unwrap_or_default();
        blocked_ports.sort_unstable();
        blocked_ports.dedup();
        EgressLimits {
            blocked_ports,
            new_connections_per_minute: l.new_connections_per_minute.unwrap_or(0),
            bandwidth_mbit: l.bandwidth_mbit.unwrap_or(0),
        }
    }

    /// Nothing is limited: the machine needs nothing in the tables.
    pub fn is_none(&self) -> bool {
        self.blocked_ports.is_empty()
            && self.new_connections_per_minute == 0
            && self.bandwidth_mbit == 0
    }

    /// As the API shows them: every field there.
    pub fn view(&self) -> api::EgressLimits {
        api::EgressLimits {
            blocked_ports: Some(self.blocked_ports.clone()),
            new_connections_per_minute: Some(self.new_connections_per_minute),
            bandwidth_mbit: Some(self.bandwidth_mbit),
        }
    }
}

/// The host's disk limits (ADR 0030): a rate per vCPU of a machine's size, so a machine's
/// share of the disk follows its share of the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiskLimits {
    /// MB (2^20 bytes) a second per vCPU, on each disk; 0 is no limit.
    pub bandwidth_mb_per_vcpu: u32,
    /// Requests a second per vCPU, on each disk; 0 is no limit.
    pub iops_per_vcpu: u32,
    /// What each limit lets through at full speed once, after a start or a change, in
    /// seconds at its rate.
    pub burst_sec: u32,
}

impl Default for DiskLimits {
    /// At the default capacity (4 vCPUs a hardware thread) a host's machines add up to about
    /// a datacenter NVMe through ZFS: 1.5 GB/s and 200k requests a second for 48 vCPUs.
    fn default() -> Self {
        Self {
            bandwidth_mb_per_vcpu: 32,
            iops_per_vcpu: 4000,
            burst_sec: 10,
        }
    }
}

impl DiskLimits {
    /// What a machine of `vcpus` runs with: these for its size, its own values over them.
    pub fn with(&self, vcpus: u32, own: &api::DiskLimits) -> fc::DiskRate {
        let host = api::DiskLimits {
            bandwidth_mb: Some(self.bandwidth_mb_per_vcpu.saturating_mul(vcpus)),
            iops: Some(self.iops_per_vcpu.saturating_mul(vcpus)),
            burst_sec: Some(self.burst_sec),
        };
        let l = own.over(&host);
        fc::DiskRate {
            bandwidth_mb: l.bandwidth_mb.unwrap_or(0),
            iops: l.iops.unwrap_or(0),
            burst_sec: l.burst_sec.unwrap_or(0),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ingress {
    /// The range of host ports handed to TCP endpoints.
    pub tcp_ports: String,
    /// The shared HTTP listener that routes by host name; empty disables it.
    pub http: String,
    /// The suffix of HTTP endpoint host names.
    pub domain: String,
    /// The address TCP endpoints listen on. Loopback by default, like `listen`: a wider
    /// address needs `allowed_clients`.
    pub bind: String,
    /// The address endpoints are reported at (`Endpoint.address`): what a router on another
    /// machine dials. Default: `bind` when it is one address, else the host's primary address.
    pub advertise: String,
    /// The IPv4 networks (`a.b.c.d/n`) that may reach the API, the HTTP ingress and the TCP
    /// endpoints; the host's own loopback always may. Empty: anyone who can route to the
    /// address, so `listen`, `bind` and `http` must then be loopback or private addresses.
    pub allowed_clients: Vec<String>,
    /// Starts on a public address with `allowed_clients` empty: something else (your own
    /// firewall) keeps the daemon's ports from the internet.
    pub allow_public: bool,
}

/// Where backups go. Off until `store` is set.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Backup {
    /// `s3://bucket/prefix` or `file:///path`; empty turns backups off.
    pub store: String,
    /// The S3 endpoint (`https://s3.fr-par.scw.cloud`); credentials come from the
    /// environment, `BRIQYARD_S3_ACCESS_KEY` and `BRIQYARD_S3_SECRET_KEY`.
    pub endpoint: String,
    pub region: String,
    /// Backup snapshots kept on the host per machine: the newest is the base of the next
    /// incremental send, the rest only cost space.
    pub keep_snapshots: u32,
    /// The schedule of a machine created without one (ADR 0023): both or neither; none by
    /// default.
    pub default_every: String,
    pub default_keep: u32,
    /// Scheduled backups run at once, at most.
    pub at_once: u32,
    /// How long a destroyed machine's backups stay in the store.
    pub keep_destroyed_days: u32,
}

impl Backup {
    /// The schedule a machine created without one gets.
    pub fn default_policy(&self) -> Option<api::BackupPolicy> {
        (!self.default_every.is_empty()).then(|| api::BackupPolicy {
            every: self.default_every.clone(),
            keep: self.default_keep,
        })
    }

    fn check(&self) -> Result<()> {
        match self.default_policy() {
            None if self.default_keep > 0 => {
                bail!("backup.default_keep needs backup.default_every")
            }
            Some(p) => {
                p.check()
                    .map_err(|e| anyhow::anyhow!("backup.default_{e}"))?;
            }
            None => {}
        }
        if self.at_once < 1 {
            bail!("backup.at_once must be at least 1");
        }
        if self.keep_destroyed_days < 1 {
            bail!("backup.keep_destroyed_days must be at least 1");
        }
        Ok(())
    }
}

impl Default for Backup {
    fn default() -> Self {
        Self {
            store: String::new(),
            endpoint: String::new(),
            region: String::new(),
            keep_snapshots: 1,
            default_every: String::new(),
            default_keep: 0,
            at_once: 2,
            keep_destroyed_days: 30,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FleetClient {
    pub url: String,
    /// The URL the fleet reaches this daemon at. The heartbeat presents the daemon's own
    /// `token`, which the fleet expects for this address.
    pub advertise: String,
    pub region: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capacity {
    pub memory_mb: u32,
    pub vcpus: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7420".into(),
            api_tls: true,
            token: String::new(),
            metrics_token: String::new(),
            data_dir: "/var/lib/briqyard".into(),
            firecracker: "/usr/local/bin/firecracker".into(),
            jailer: PathBuf::new(),
            jail_dir: PathBuf::new(),
            jail_uid_base: 100_000,
            kernel: "/var/lib/briqyard/vmlinux".into(),
            kernel_args: String::new(),
            pci: false,
            init: "/usr/local/bin/briqyard-init".into(),
            storage: Storage::default(),
            registries: vec![],
            network: Network::default(),
            egress_limits: EgressLimits::default(),
            disk_limits: DiskLimits::default(),
            ingress: Ingress::default(),
            root_disk_gb: 8,
            image_keep_days: 14,
            usage_keep_days: 90,
            events_keep_days: 7,
            image_resolve_minutes: 10,
            boot_timeout_sec: 120,
            boots_at_once: 0,
            suspend_on_sleep: false,
            fleet: None,
            backup: Backup::default(),
            capacity: Capacity::default(),
            conditions: Conditions::default(),
            console_max_mb: 64,
        }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            backend: "zfs".into(),
            pool: "byard".into(),
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self {
            range: "10.64.0.0/10".into(),
            upstream_dns: vec![],
            egress: String::new(),
        }
    }
}

impl Default for Ingress {
    fn default() -> Self {
        Self {
            tcp_ports: "20000-29999".into(),
            http: String::new(),
            domain: "byard.localhost".into(),
            bind: "127.0.0.1".into(),
            advertise: String::new(),
            allowed_clients: vec![],
            allow_public: false,
        }
    }
}

impl Config {
    /// Reads a YAML file over the defaults. An empty path is the defaults.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let cfg = match path {
            None => Self::default(),
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("read config {}", p.display()))?;
                serde_yaml::from_str(&text)
                    .with_context(|| format!("parse config {}", p.display()))?
            }
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.storage.backend != "zfs" {
            bail!(
                "storage.backend: {:?} is not supported (zfs)",
                self.storage.backend
            );
        }
        if self.storage.pool.is_empty() {
            bail!("storage.pool is required");
        }
        if self.root_disk_gb < 1 {
            bail!("root_disk_gb must be at least 1");
        }
        if self.usage_keep_days < 1 {
            bail!("usage_keep_days must be at least 1");
        }
        if self.events_keep_days < 1 {
            bail!("events_keep_days must be at least 1");
        }
        if self.console_max_mb < 1 {
            bail!("console_max_mb must be at least 1");
        }
        if !(1..=100).contains(&self.conditions.memory_pct) {
            bail!("conditions.memory_pct: a share of capacity, 1 to 100");
        }
        if self.conditions.disk_free_pct > 99 {
            bail!("conditions.disk_free_pct: a share of the pool, 0 to 99");
        }
        for (name, p) in [
            ("firecracker", &self.firecracker),
            ("kernel", &self.kernel),
            ("init", &self.init),
        ] {
            if !p.is_absolute() {
                bail!("{name} must be an absolute path");
            }
        }
        for c in &self.ingress.allowed_clients {
            netw::cidr(c).with_context(|| format!("ingress.allowed_clients {c:?}"))?;
        }
        if let Err(e) = self.egress_limits.view().check() {
            bail!("egress_limits.{e}");
        }
        // The largest size's limits must be ones a machine could ask for.
        let largest = self.disk_limits.with(32, &api::DiskLimits::default());
        if let Err(e) = largest.view().check() {
            bail!("disk_limits: for 32 vCPUs, {e}");
        }
        self.backup.check()?;
        self.check_exposure()?;
        self.check_advertise()
    }

    /// The fleet dials `fleet.advertise` as written: its scheme must be the API's.
    fn check_advertise(&self) -> Result<()> {
        let Some(f) = &self.fleet else { return Ok(()) };
        if f.advertise.is_empty() {
            return Ok(());
        }
        let want = if self.serves_tls() { "https" } else { "http" };
        if !f.advertise.starts_with(&format!("{want}://")) {
            bail!(
                "fleet.advertise: {} but the API serves {} on {}: write {want}://…",
                f.advertise,
                if self.serves_tls() {
                    "TLS"
                } else {
                    "plain HTTP"
                },
                self.listen
            );
        }
        Ok(())
    }

    /// Whether the API is served over TLS: `api_tls`, unless `listen` is loopback.
    pub fn serves_tls(&self) -> bool {
        let loopback = self
            .listen
            .parse::<SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        self.api_tls && !loopback
    }

    /// The API certificate and its key (ADR 0020).
    pub fn tls_cert(&self) -> PathBuf {
        self.data_dir.join("api-cert.pem")
    }
    pub fn tls_key(&self) -> PathBuf {
        self.data_dir.join("api-key.pem")
    }

    /// The names the API certificate carries: the addresses the configuration gives the
    /// host. Nothing checks them (the fleet pins the fingerprint); they say whose it is.
    pub fn tls_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(a) = self.listen.parse::<SocketAddr>() {
            if !a.ip().is_unspecified() {
                names.push(a.ip().to_string());
            }
        }
        if let Some(f) = &self.fleet {
            let host = f.advertise.split("://").nth(1).unwrap_or("");
            let host = host.split('/').next().unwrap_or("");
            let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if !host.is_empty() {
                names.push(host.to_string());
            }
        }
        if !self.ingress.advertise.is_empty() {
            names.push(self.ingress.advertise.clone());
        }
        names.sort();
        names.dedup();
        names
    }

    /// Refuses an address the internet could reach when nothing says who may connect
    /// (ADR 0012): `ingress.allowed_clients` becomes the firewall, or `ingress.allow_public`
    /// says the operator has one.
    fn check_exposure(&self) -> Result<()> {
        let listen: SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("listen {:?}: want address:port", self.listen))?;
        let bind: IpAddr =
            self.ingress.bind.parse().with_context(|| {
                format!("ingress.bind {:?}: want an address", self.ingress.bind)
            })?;
        let mut binds = vec![("listen", listen.ip()), ("ingress.bind", bind)];
        if !self.ingress.http.is_empty() {
            let http: SocketAddr = self.ingress.http.parse().with_context(|| {
                format!("ingress.http {:?}: want address:port", self.ingress.http)
            })?;
            binds.push(("ingress.http", http.ip()));
        }
        if !self.ingress.allowed_clients.is_empty() || self.ingress.allow_public {
            return Ok(());
        }
        for (field, ip) in binds {
            if !netw::is_private(ip) {
                bail!(
                    "{field}: {ip} is reachable from outside the host: set ingress.allowed_clients \
                     to the networks that may connect, or ingress.allow_public: true if a \
                     firewall of your own keeps the daemon's ports from the internet"
                );
            }
        }
        Ok(())
    }

    pub fn run_dir(&self) -> PathBuf {
        self.data_dir.join("run")
    }
    pub fn image_dir(&self) -> PathBuf {
        self.data_dir.join("images")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }
    pub fn jail_base(&self) -> PathBuf {
        if self.jail_dir.as_os_str().is_empty() {
            self.data_dir.join("jail")
        } else {
            self.jail_dir.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes the YAML to a temp file and loads it the way the daemon does.
    fn load(yaml: &str) -> Result<Config> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, yaml).unwrap();
        Config::load(Some(&path))
    }

    #[test]
    fn defaults() {
        let c = Config::load(None).unwrap();
        assert_eq!(c.listen, "127.0.0.1:7420");
        assert!(c.api_tls);
        assert!(!c.serves_tls(), "a loopback API is plain HTTP");
        assert!(c.token.is_empty());
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/briqyard"));
        assert_eq!(c.firecracker, PathBuf::from("/usr/local/bin/firecracker"));
        assert!(c.jailer.as_os_str().is_empty());
        assert!(c.jail_dir.as_os_str().is_empty());
        assert_eq!(c.jail_uid_base, 100_000);
        assert_eq!(c.kernel, PathBuf::from("/var/lib/briqyard/vmlinux"));
        assert!(c.kernel_args.is_empty());
        assert!(!c.pci);
        assert_eq!(c.init, PathBuf::from("/usr/local/bin/briqyard-init"));
        assert_eq!(c.storage.backend, "zfs");
        assert_eq!(c.storage.pool, "byard");
        assert!(c.registries.is_empty());
        assert_eq!(c.network.range, "10.64.0.0/10");
        assert!(c.network.upstream_dns.is_empty());
        assert!(c.network.egress.is_empty());
        assert_eq!(c.egress_limits.blocked_ports, vec![25]);
        assert_eq!(c.egress_limits.new_connections_per_minute, 0);
        assert_eq!(c.egress_limits.bandwidth_mbit, 0);
        assert_eq!(c.disk_limits, DiskLimits::default());
        assert_eq!(c.ingress.tcp_ports, "20000-29999");
        assert!(c.ingress.http.is_empty());
        assert_eq!(c.ingress.domain, "byard.localhost");
        assert_eq!(c.ingress.bind, "127.0.0.1");
        assert!(c.ingress.advertise.is_empty());
        assert!(c.ingress.allowed_clients.is_empty());
        assert!(!c.ingress.allow_public);
        assert_eq!(c.root_disk_gb, 8);
        assert_eq!(c.image_keep_days, 14);
        assert_eq!(c.usage_keep_days, 90);
        assert_eq!(c.events_keep_days, 7);
        assert!(!c.suspend_on_sleep);
        assert!(c.fleet.is_none());
        assert_eq!(c.capacity.memory_mb, 0);
        assert_eq!(c.capacity.vcpus, 0);
        assert_eq!(
            c.conditions,
            Conditions {
                memory_pct: 95,
                disk_free_pct: 10
            }
        );
        assert_eq!(c.console_max_mb, 64);
    }

    #[test]
    fn an_empty_file_is_the_defaults() {
        // An empty document is YAML's null; serde-yaml gives every field its default.
        let c = load("").unwrap();
        assert_eq!(c.listen, "127.0.0.1:7420");
        assert_eq!(c.storage.pool, "byard");
    }

    #[test]
    fn a_missing_file_is_an_error_naming_it() {
        let err = Config::load(Some(Path::new("/nonexistent/briqyard.yaml"))).unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/briqyard.yaml"),
            "{err:#}"
        );
    }

    #[test]
    fn every_section() {
        let c = load(
            r#"
listen: 0.0.0.0:7420
api_tls: false
token: secret
data_dir: /data
firecracker: /opt/fc/firecracker
jailer: /opt/fc/jailer
jail_dir: /jails
jail_uid_base: 200000
kernel: /data/vmlinux
kernel_args: "loglevel=3"
pci: true
init: /opt/briqyard-init
storage:
  backend: zfs
  pool: tank/byard
registries:
  - host: ghcr.io
    username: bot
    password: pw
network:
  range: 10.128.0.0/10
  upstream_dns: ["1.1.1.1", "9.9.9.9"]
  egress: eth0
egress_limits:
  blocked_ports: [25, 465, 587]
  new_connections_per_minute: 600
  bandwidth_mbit: 200
disk_limits:
  bandwidth_mb_per_vcpu: 50
  iops_per_vcpu: 1000
  burst_sec: 5
ingress:
  tcp_ports: 30000-31000
  http: 0.0.0.0:8080
  domain: byard.example
  bind: 10.0.0.5
  advertise: 203.0.113.5
  allowed_clients: ["10.0.0.0/8", "203.0.113.9"]
  allow_public: true
root_disk_gb: 16
image_keep_days: 3
usage_keep_days: 30
events_keep_days: 2
suspend_on_sleep: true
fleet:
  url: http://fleet:7430
  advertise: http://10.0.0.5:7420
  region: fsn1
capacity:
  memory_mb: 65536
  vcpus: 128
conditions:
  memory_pct: 90
  disk_free_pct: 20
console_max_mb: 16
"#,
        )
        .unwrap();
        assert_eq!(c.listen, "0.0.0.0:7420");
        assert!(!c.api_tls);
        assert_eq!(c.token, "secret");
        assert_eq!(c.data_dir, PathBuf::from("/data"));
        assert_eq!(c.firecracker, PathBuf::from("/opt/fc/firecracker"));
        assert_eq!(c.jailer, PathBuf::from("/opt/fc/jailer"));
        assert_eq!(c.jail_dir, PathBuf::from("/jails"));
        assert_eq!(c.jail_uid_base, 200_000);
        assert_eq!(c.kernel, PathBuf::from("/data/vmlinux"));
        assert_eq!(c.kernel_args, "loglevel=3");
        assert!(c.pci);
        assert_eq!(c.init, PathBuf::from("/opt/briqyard-init"));
        assert_eq!(c.storage.pool, "tank/byard");
        assert_eq!(c.registries.len(), 1);
        assert_eq!(c.registries[0].host, "ghcr.io");
        assert_eq!(c.registries[0].username, "bot");
        assert_eq!(c.registries[0].password, "pw");
        assert_eq!(c.network.range, "10.128.0.0/10");
        assert_eq!(c.network.upstream_dns, vec!["1.1.1.1", "9.9.9.9"]);
        assert_eq!(c.network.egress, "eth0");
        assert_eq!(
            c.egress_limits,
            EgressLimits {
                blocked_ports: vec![25, 465, 587],
                new_connections_per_minute: 600,
                bandwidth_mbit: 200,
            }
        );
        assert_eq!(
            c.disk_limits,
            DiskLimits {
                bandwidth_mb_per_vcpu: 50,
                iops_per_vcpu: 1000,
                burst_sec: 5,
            }
        );
        assert_eq!(c.ingress.tcp_ports, "30000-31000");
        assert_eq!(c.ingress.http, "0.0.0.0:8080");
        assert_eq!(c.ingress.domain, "byard.example");
        assert_eq!(c.ingress.bind, "10.0.0.5");
        assert_eq!(c.ingress.advertise, "203.0.113.5");
        assert_eq!(c.ingress.allowed_clients, vec!["10.0.0.0/8", "203.0.113.9"]);
        assert!(c.ingress.allow_public);
        assert_eq!(c.root_disk_gb, 16);
        assert_eq!(c.image_keep_days, 3);
        assert_eq!(c.usage_keep_days, 30);
        assert_eq!(c.events_keep_days, 2);
        assert!(c.suspend_on_sleep);
        let f = c.fleet.unwrap();
        assert_eq!(f.url, "http://fleet:7430");
        assert_eq!(f.advertise, "http://10.0.0.5:7420");
        assert_eq!(f.region, "fsn1");
        assert_eq!(c.capacity.memory_mb, 65536);
        assert_eq!(c.capacity.vcpus, 128);
        assert_eq!(
            c.conditions,
            Conditions {
                memory_pct: 90,
                disk_free_pct: 20
            }
        );
        assert_eq!(c.console_max_mb, 16);
    }

    #[test]
    fn a_partial_section_keeps_the_other_defaults() {
        let c = load("ingress:\n  http: 127.0.0.1:8080\n").unwrap();
        assert_eq!(c.ingress.http, "127.0.0.1:8080");
        assert_eq!(c.ingress.tcp_ports, "20000-29999");
        assert_eq!(c.ingress.domain, "byard.localhost");
        // A rate set for every machine keeps port 25 blocked.
        let c = load("egress_limits:\n  new_connections_per_minute: 600\n").unwrap();
        assert_eq!(c.egress_limits.blocked_ports, vec![25]);
        assert_eq!(c.egress_limits.new_connections_per_minute, 600);
    }

    #[test]
    fn disk_limits_follow_the_size_under_a_machine_s_own() {
        let host = DiskLimits::default();
        let none = api::DiskLimits::default();
        let rate = |bandwidth_mb, iops, burst_sec| fc::DiskRate {
            bandwidth_mb,
            iops,
            burst_sec,
        };
        assert_eq!(host.with(1, &none), rate(32, 4000, 10));
        assert_eq!(host.with(4, &none), rate(128, 16000, 10));
        // Its own values are absolute, whatever its size; 0 lifts a limit.
        let own = api::DiskLimits {
            bandwidth_mb: Some(8),
            iops: Some(0),
            burst_sec: None,
        };
        assert_eq!(host.with(4, &own), rate(8, 0, 10));
        // A host with no limits limits nothing but what a machine asks for.
        let off = load("disk_limits:\n  bandwidth_mb_per_vcpu: 0\n  iops_per_vcpu: 0\n").unwrap();
        assert_eq!(off.disk_limits.burst_sec, 10, "the rest stays the default");
        assert_eq!(off.disk_limits.with(8, &none), rate(0, 0, 10));
        // The largest size's must be a value a machine could set.
        let err = load("disk_limits:\n  bandwidth_mb_per_vcpu: 4000\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "disk_limits: for 32 vCPUs, bandwidth_mb: at most 100000"
        );
    }

    #[test]
    fn a_machine_s_limits_are_its_own_over_the_host_s() {
        let host = EgressLimits {
            blocked_ports: vec![465, 25],
            new_connections_per_minute: 600,
            bandwidth_mbit: 0,
        };
        // Nothing of its own: the host's, the ports in order.
        let l = host.with(&api::EgressLimits::default());
        assert_eq!(l.blocked_ports, vec![25, 465]);
        assert_eq!((l.new_connections_per_minute, l.bandwidth_mbit), (600, 0));
        // Its own, field by field; `[]` and 0 lift a host default.
        let own = api::EgressLimits {
            blocked_ports: Some(vec![]),
            new_connections_per_minute: Some(0),
            bandwidth_mbit: Some(100),
        };
        let l = host.with(&own);
        assert_eq!(
            l,
            EgressLimits {
                blocked_ports: vec![],
                new_connections_per_minute: 0,
                bandwidth_mbit: 100,
            }
        );
        assert!(!l.is_none());
        assert!(host
            .with(&api::EgressLimits {
                bandwidth_mbit: Some(0),
                ..own
            })
            .is_none());
        let own = api::EgressLimits {
            blocked_ports: Some(vec![587, 25, 587]),
            ..Default::default()
        };
        assert_eq!(host.with(&own).blocked_ports, vec![25, 587]);
        // Shown with every field.
        assert_eq!(
            host.view(),
            api::EgressLimits {
                blocked_ports: Some(vec![465, 25]),
                new_connections_per_minute: Some(600),
                bandwidth_mbit: Some(0),
            }
        );
    }

    #[test]
    fn unknown_fields_are_refused_by_name() {
        // A typo at the top level, in a section, and in a list item: each names the field.
        for (yaml, field) in [
            ("listn: 127.0.0.1:1\n", "listn"),
            ("storage:\n  pol: byard\n", "pol"),
            ("registries:\n  - host: a\n    user: b\n", "user"),
            ("fleet:\n  urll: x\n", "urll"),
            ("fleet:\n  token: x\n", "token"),
            ("capacity:\n  memory: 1\n", "memory"),
            ("egress_limits:\n  bandwidth: 1\n", "bandwidth"),
            ("conditions:\n  memory: 1\n", "memory"),
        ] {
            let err = load(yaml).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("unknown field"), "{yaml:?}: {msg}");
            assert!(msg.contains(&format!("`{field}`")), "{yaml:?}: {msg}");
            assert!(msg.contains("parse config"), "{yaml:?}: {msg}");
        }
    }

    #[test]
    fn validation() {
        let err = load("storage:\n  backend: btrfs\n").unwrap_err();
        assert!(err.to_string().contains("storage.backend"), "{err}");
        assert!(err.to_string().contains("btrfs"), "{err}");

        let err = load("storage:\n  pool: \"\"\n").unwrap_err();
        assert!(
            err.to_string().contains("storage.pool is required"),
            "{err}"
        );

        let err = load("root_disk_gb: 0\n").unwrap_err();
        assert!(err.to_string().contains("root_disk_gb"), "{err}");
        let err = load("usage_keep_days: 0\n").unwrap_err();
        assert_eq!(err.to_string(), "usage_keep_days must be at least 1");
        let err = load("events_keep_days: 0\n").unwrap_err();
        assert_eq!(err.to_string(), "events_keep_days must be at least 1");
        let err = load("console_max_mb: 0\n").unwrap_err();
        assert_eq!(err.to_string(), "console_max_mb must be at least 1");
        for yaml in [
            "conditions:\n  memory_pct: 0\n",
            "conditions:\n  memory_pct: 101\n",
        ] {
            let err = load(yaml).unwrap_err();
            assert_eq!(
                err.to_string(),
                "conditions.memory_pct: a share of capacity, 1 to 100"
            );
        }
        let err = load("conditions:\n  disk_free_pct: 100\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "conditions.disk_free_pct: a share of the pool, 0 to 99"
        );
        // One threshold set keeps the other's default.
        let c = load("conditions:\n  disk_free_pct: 0\n").unwrap();
        assert_eq!(
            (c.conditions.memory_pct, c.conditions.disk_free_pct),
            (95, 0)
        );
        let err = load("egress_limits:\n  blocked_ports: [0]\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress_limits.blocked_ports: 0 is not a port"
        );
        let err = load("egress_limits:\n  bandwidth_mbit: 200000\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress_limits.bandwidth_mbit: at most 100000"
        );

        for (field, yaml) in [
            ("firecracker", "firecracker: bin/firecracker\n"),
            ("kernel", "kernel: vmlinux\n"),
            ("init", "init: ./briqyard-init\n"),
        ] {
            let err = load(yaml).unwrap_err();
            assert_eq!(err.to_string(), format!("{field} must be an absolute path"));
        }
        // The jailer may stay empty (no jail) and is not checked for an absolute path here.
        load("jailer: \"\"\n").unwrap();
    }

    #[test]
    fn the_backup_section() {
        let b = Config::load(None).unwrap().backup;
        assert!(b.store.is_empty());
        assert_eq!(b.keep_snapshots, 1);
        assert_eq!(b.default_policy(), None, "no schedule unless configured");
        assert_eq!((b.at_once, b.keep_destroyed_days), (2, 30));
        let b = load(
            "backup:\n  store: file:///b\n  default_every: 1d\n  default_keep: 5\n  at_once: 4\n  keep_destroyed_days: 7\n",
        )
        .unwrap()
        .backup;
        assert_eq!(
            b.default_policy(),
            Some(api::BackupPolicy {
                every: "1d".into(),
                keep: 5
            })
        );
        assert_eq!((b.at_once, b.keep_destroyed_days), (4, 7));
        for (yaml, want) in [
            (
                "default_every: 30m\n  default_keep: 2",
                r#"backup.default_every "30m": at least 1h"#,
            ),
            ("default_every: 6h", "backup.default_keep: at least 1"),
            (
                "default_keep: 3",
                "backup.default_keep needs backup.default_every",
            ),
            ("at_once: 0", "backup.at_once must be at least 1"),
            (
                "keep_destroyed_days: 0",
                "backup.keep_destroyed_days must be at least 1",
            ),
        ] {
            let err = load(&format!("backup:\n  {yaml}\n")).unwrap_err();
            assert_eq!(err.to_string(), want, "{yaml}");
        }
    }

    #[test]
    fn a_public_bind_is_refused_unless_someone_says_who_may_connect() {
        // Endpoints are the entry to every tenant: `bind: 0.0.0.0` alone is refused.
        let err = load("ingress:\n  bind: 0.0.0.0\n").unwrap_err().to_string();
        assert!(
            err.starts_with("ingress.bind: 0.0.0.0 is reachable"),
            "{err}"
        );
        assert!(err.contains("ingress.allowed_clients"), "{err}");
        assert!(err.contains("ingress.allow_public"), "{err}");

        for (yaml, field) in [
            (
                "listen: 0.0.0.0:7420\ningress:\n  bind: 127.0.0.1\n",
                "listen: 0.0.0.0",
            ),
            (
                "listen: \"[::]:7420\"\ningress:\n  bind: 127.0.0.1\n",
                "listen: ::",
            ),
            (
                "listen: 203.0.113.5:7420\ningress:\n  bind: 10.0.0.5\n",
                "listen: 203.0.113.5",
            ),
            (
                "ingress:\n  bind: 203.0.113.5\n",
                "ingress.bind: 203.0.113.5",
            ),
            (
                "ingress:\n  bind: 10.0.0.5\n  http: 0.0.0.0:8080\n",
                "ingress.http: 0.0.0.0",
            ),
        ] {
            let err = load(yaml).unwrap_err().to_string();
            assert!(err.starts_with(field), "{yaml:?}: {err}");
        }
        // Private addresses need nothing: loopback, RFC 1918, carrier-grade NAT.
        for bind in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.5",
            "192.168.64.3",
            "100.64.0.1",
        ] {
            load(&format!("ingress:\n  bind: {bind}\n  http: {bind}:8080\n")).unwrap();
        }
        // Either field lifts the refusal.
        load("ingress:\n  allowed_clients: [10.0.0.0/8]\n").unwrap();
        load("listen: 0.0.0.0:7420\ningress:\n  http: 0.0.0.0:8080\n  allow_public: true\n")
            .unwrap();
    }

    #[test]
    fn addresses_and_client_networks_are_checked_by_name() {
        for (yaml, msg) in [
            (
                "listen: localhost:7420\n",
                "listen \"localhost:7420\": want address:port",
            ),
            (
                "ingress:\n  bind: \"\"\n",
                "ingress.bind \"\": want an address",
            ),
            (
                "ingress:\n  bind: 127.0.0.1\n  http: 8080\n",
                "ingress.http \"8080\": want address:port",
            ),
            (
                "ingress:\n  allowed_clients: [10.0.0.0/33]\n",
                "ingress.allowed_clients \"10.0.0.0/33\"",
            ),
            (
                "ingress:\n  allowed_clients: [fd00::/8]\n",
                "ingress.allowed_clients \"fd00::/8\"",
            ),
        ] {
            let err = format!("{:#}", load(yaml).unwrap_err());
            assert!(err.contains(msg), "{yaml:?}: {err}");
        }
    }

    #[test]
    fn the_api_is_tls_unless_loopback_or_turned_off() {
        let c = load("listen: 0.0.0.0:7420\ningress:\n  allow_public: true\n").unwrap();
        assert!(c.serves_tls(), "a wider listen is TLS by default");
        let c = load("listen: 10.0.0.5:7420\n").unwrap();
        assert!(c.serves_tls());
        // The only way to plain HTTP off loopback: saying so.
        let c = load("listen: 10.0.0.5:7420\napi_tls: false\n").unwrap();
        assert!(!c.serves_tls());
        for listen in ["127.0.0.1:7420", "[::1]:7420"] {
            let c = load(&format!("listen: \"{listen}\"\n")).unwrap();
            assert!(!c.serves_tls(), "{listen}");
        }
    }

    #[test]
    fn fleet_advertise_has_the_apis_scheme() {
        let base = "listen: 10.0.0.5:7420\n";
        load(&format!(
            "{base}fleet:\n  url: https://fleet\n  advertise: https://10.0.0.5:7420\n"
        ))
        .unwrap();
        let err = load(&format!(
            "{base}fleet:\n  url: https://fleet\n  advertise: http://10.0.0.5:7420\n"
        ))
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "fleet.advertise: http://10.0.0.5:7420 but the API serves TLS on 10.0.0.5:7420: write https://…"
        );
        // A plain API (loopback, a host forwarded by its operator) advertises http.
        let err = load("fleet:\n  advertise: https://192.168.64.1:27420\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("serves plain HTTP on 127.0.0.1:7420: write http://"),
            "{err}"
        );
        load("fleet:\n  advertise: http://192.168.64.1:27420\n").unwrap();
        load("listen: 10.0.0.5:7420\napi_tls: false\nfleet:\n  advertise: http://10.0.0.5:7420\n")
            .unwrap();
    }

    #[test]
    fn the_certificate_names_the_configured_addresses() {
        let c = load(
            "listen: 10.0.0.5:7420\ningress:\n  advertise: 10.0.0.5\nfleet:\n  advertise: https://203.0.113.5:7420\n",
        )
        .unwrap();
        assert_eq!(c.tls_names(), ["10.0.0.5", "203.0.113.5"]);
        let c =
            load("listen: 0.0.0.0:7420\napi_tls: false\ningress:\n  allow_public: true\n").unwrap();
        assert!(
            c.tls_names().is_empty(),
            "an unspecified address names nothing"
        );
        let c = load("listen: \"[::]:7420\"\napi_tls: false\ningress:\n  allow_public: true\nfleet:\n  advertise: \"http://[fd00::5]:7420\"\n").unwrap();
        assert_eq!(c.tls_names(), ["fd00::5"]);
        let c = load("data_dir: /data\n").unwrap();
        assert_eq!(c.tls_cert(), PathBuf::from("/data/api-cert.pem"));
        assert_eq!(c.tls_key(), PathBuf::from("/data/api-key.pem"));
    }

    #[test]
    fn the_dev_config_is_plain_http_on_purpose() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../hack/config.dev.yaml");
        let c = Config::load(Some(&path)).unwrap();
        assert_eq!(c.listen, "0.0.0.0:7420");
        assert!(!c.serves_tls(), "the suites curl http://127.0.0.1:7420");
    }

    #[test]
    fn derived_directories() {
        let c = load("data_dir: /data\n").unwrap();
        assert_eq!(c.run_dir(), PathBuf::from("/data/run"));
        assert_eq!(c.image_dir(), PathBuf::from("/data/images"));
        assert_eq!(c.state_dir(), PathBuf::from("/data/state"));
        assert_eq!(c.jail_base(), PathBuf::from("/data/jail"));

        let c = load("data_dir: /data\njail_dir: /fast/jails\n").unwrap();
        assert_eq!(c.jail_base(), PathBuf::from("/fast/jails"));
        assert_eq!(c.run_dir(), PathBuf::from("/data/run"));
    }
}
