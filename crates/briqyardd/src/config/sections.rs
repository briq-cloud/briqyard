use super::*;

/// Cold-boot rollout; existing live and suspended devices retain their profile.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Balloon {
    pub enabled: bool,
}

/// Bind the reviewed init-ready recipe to an exact locally built init binary. Empty is
/// disabled. Image/runtime inputs are fixed by the reviewed recipe, not request shell text.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Templates {
    pub init_ready_init_sha256: String,
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
    /// The ZFS pool (or dataset) that holds every disk. Encrypted (ADR 0026).
    pub pool: String,
    /// Where the pool's key comes from when it is not loaded (ADR 0026): `fleet` (asked of
    /// `fleet.url` with the host's token) or `file:<absolute path>` (a single host).
    pub key: String,
}

/// Where the pool's key comes from (`storage.key`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// Asked of the fleet at `url` as the host at `advertise`, presenting `token`.
    Fleet {
        url: String,
        advertise: String,
        token: String,
    },
    File(PathBuf),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    /// The pool of namespace subnets, carved into /24s.
    pub range: String,
    /// Upstream DNS servers the gateway forwards to. Default: the host's resolv.conf, then 1.1.1.1.
    pub upstream_dns: Vec<String>,
    /// The host interface machines reach the internet through. Empty: the default route's.
    pub egress: String,
    /// TCP ports of the host's own services (an edge beside the daemon, ADR 0028) that
    /// machines with open egress reach at the host's addresses, as the internet does.
    pub host_ports: Vec<u16>,
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

    pub(super) fn check(&self) -> Result<()> {
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

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capacity {
    pub memory_mb: u32,
    pub vcpus: u32,
    /// Memory kept for the host and its other services when `memory_mb` is not set.
    pub reserved_memory_mb: u32,
    /// Hardware threads kept for them when `vcpus` is not set (ADR 0028).
    pub reserved_threads: u32,
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            memory_mb: 0,
            vcpus: 0,
            reserved_memory_mb: 2048,
            reserved_threads: 0,
        }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            backend: "zfs".into(),
            pool: "byard".into(),
            key: "file:/etc/briqyard/pool.key".into(),
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self {
            range: "10.64.0.0/10".into(),
            upstream_dns: vec![],
            egress: String::new(),
            host_ports: vec![],
        }
    }
}

impl Default for Ingress {
    fn default() -> Self {
        Self {
            // Kubernetes' NodePort range: no well-known service's port (an edge beside the
            // daemon listens on MongoDB's 27017, ADR 0028), and under the kernel's ephemeral
            // ports, which outgoing connections take.
            tcp_ports: "30000-32767".into(),
            http: String::new(),
            domain: "byard.localhost".into(),
            bind: "127.0.0.1".into(),
            advertise: String::new(),
            allowed_clients: vec![],
            allow_public: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::testutil::load;

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
  key: fleet
registries:
  - host: ghcr.io
    username: bot
    password: pw
registry_mirrors:
  docker.io: http://10.0.0.2:7440
network:
  range: 10.128.0.0/10
  upstream_dns: ["1.1.1.1", "9.9.9.9"]
  egress: eth0
  host_ports: [80, 443, 5432]
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
  url: http://10.0.0.2:7430
  advertise: http://10.0.0.5:7420
  region: fsn1
capacity:
  memory_mb: 65536
  vcpus: 128
  reserved_memory_mb: 3072
  reserved_threads: 2
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
        assert!(matches!(c.key_source().unwrap(), KeySource::Fleet { .. }));
        assert_eq!(c.registries.len(), 1);
        assert_eq!(c.registries[0].host, "ghcr.io");
        assert_eq!(c.registries[0].username, "bot");
        assert_eq!(c.registries[0].password, "pw");
        assert_eq!(
            c.mirrors().unwrap(),
            [crate::image::Mirror {
                registry: "docker.io".into(),
                host: "10.0.0.2:7440".into(),
                plain_http: true,
            }]
        );
        assert_eq!(c.network.range, "10.128.0.0/10");
        assert_eq!(c.network.upstream_dns, vec!["1.1.1.1", "9.9.9.9"]);
        assert_eq!(c.network.egress, "eth0");
        assert_eq!(c.network.host_ports, [80, 443, 5432]);
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
        assert_eq!(f.url, "http://10.0.0.2:7430");
        assert_eq!(f.advertise, "http://10.0.0.5:7420");
        assert_eq!(f.region, "fsn1");
        assert_eq!(c.capacity.memory_mb, 65536);
        assert_eq!(c.capacity.vcpus, 128);
        assert_eq!(c.capacity.reserved_memory_mb, 3072);
        assert_eq!(c.capacity.reserved_threads, 2);
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
        assert_eq!(c.ingress.tcp_ports, "30000-32767");
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
}
