//! The daemon's configuration file.

use crate::{fc, netw};
use anyhow::{bail, Context, Result};
use briqyard_api as api;
use serde::Deserialize;
use std::collections::BTreeMap;
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
    /// Fixed target-zero reporting device on subsequent cold boots only.
    pub balloon: Balloon,
    /// The briqyard-init binary copied into every root disk.
    pub init: PathBuf,
    pub storage: Storage,
    /// Credentials for private registries, by registry as a reference names it ("ghcr.io",
    /// "docker.io" for Docker Hub).
    pub registries: Vec<Registry>,
    /// A pull-through mirror per registry (`docker.io: http://10.0.0.2:7440`, ADR 0036): an
    /// image's content is pulled from it first and from the registry when it fails; a tag is
    /// always resolved by the registry.
    pub registry_mirrors: BTreeMap<String, String>,
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
    /// minus 2 GB and the ZFS cache's ceiling when set) and vCPUs (default: hardware threads
    /// times 4).
    pub capacity: Capacity,
    /// When the host is under pressure (ADR 0021).
    pub conditions: Conditions,
    /// A running machine's console is rotated past this size, one previous file kept.
    pub console_max_mb: u32,
}

mod sections;
#[cfg(test)]
mod testutil;
mod validate;

pub use sections::*;

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
            balloon: Balloon::default(),
            init: "/usr/local/bin/briqyard-init".into(),
            storage: Storage::default(),
            registries: vec![],
            registry_mirrors: BTreeMap::new(),
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

    /// The registries' mirrors (`registry_mirrors`), each checked.
    pub fn mirrors(&self) -> Result<Vec<crate::image::Mirror>> {
        self.registry_mirrors
            .iter()
            .map(|(registry, url)| {
                crate::image::Mirror::parse(registry, url)
                    .with_context(|| format!("registry_mirrors.{registry}"))
            })
            .collect()
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

    /// Where the pool's key comes from, checked: the fleet needs a fleet to ask, as the host
    /// it has a record for (its address and token); a file, an absolute path.
    pub fn key_source(&self) -> Result<KeySource> {
        let key = &self.storage.key;
        if key == "fleet" {
            let fleet = self.fleet.as_ref().filter(|f| !f.url.is_empty());
            match fleet {
                None => bail!("storage.key: fleet needs fleet.url"),
                Some(f) if f.advertise.is_empty() => {
                    bail!("storage.key: fleet needs fleet.advertise, the address the fleet knows the host at")
                }
                Some(_) if self.token.is_empty() => {
                    bail!("storage.key: fleet needs token, the host's own, which the fleet checks")
                }
                Some(f) => {
                    return Ok(KeySource::Fleet {
                        url: f.url.clone(),
                        advertise: f.advertise.clone(),
                        token: self.token.clone(),
                    })
                }
            }
        }
        match key.strip_prefix("file:").map(PathBuf::from) {
            Some(p) if p.is_absolute() => Ok(KeySource::File(p)),
            _ => bail!("storage.key: {key:?}: want fleet or file:<absolute path>"),
        }
    }

    /// The filesystems of the pool the daemon's own files live on, and where each is mounted
    /// (ADR 0014, 0026): nothing it writes about a machine stays on `/`.
    pub fn pool_mounts(&self) -> [(&'static str, PathBuf); 4] {
        [
            ("images", self.image_dir()),
            ("jail", self.jail_base()),
            ("state", self.state_dir()),
            ("run", self.run_dir()),
        ]
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
    use crate::config::testutil::load;

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
        assert_eq!(
            c.key_source().unwrap(),
            KeySource::File("/etc/briqyard/pool.key".into())
        );
        assert!(c.registries.is_empty());
        assert!(c.registry_mirrors.is_empty());
        assert_eq!(c.network.range, "10.64.0.0/10");
        assert!(c.network.upstream_dns.is_empty());
        assert!(c.network.egress.is_empty());
        assert_eq!(c.egress_limits.blocked_ports, vec![25]);
        assert_eq!(c.egress_limits.new_connections_per_minute, 0);
        assert_eq!(c.egress_limits.bandwidth_mbit, 0);
        assert_eq!(c.disk_limits, DiskLimits::default());
        assert_eq!(c.ingress.tcp_ports, "30000-32767");
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
        assert_eq!(c.capacity.reserved_memory_mb, 2048);
        assert_eq!(c.capacity.reserved_threads, 0);
        assert!(c.network.host_ports.is_empty());
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

    /// The pool's key comes from the fleet, as the host the fleet has a record for, or from
    /// a file named by an absolute path; anything else is refused at load (ADR 0026).
    #[test]
    fn the_key_source_is_checked() {
        let fleet =
            "token: t\nfleet:\n  url: http://10.0.0.2:7430\n  advertise: http://10.0.0.5:7420\n";
        let c = load(&format!("{fleet}storage:\n  key: fleet\n")).unwrap();
        assert!(matches!(c.key_source().unwrap(), KeySource::Fleet { .. }));
        let c = load("storage:\n  key: file:/root/k\n").unwrap();
        assert_eq!(c.key_source().unwrap(), KeySource::File("/root/k".into()));
        for (yaml, why) in [
            ("storage:\n  key: fleet\n", "fleet needs fleet.url"),
            (
                "token: t\nfleet:\n  url: http://10.0.0.2:7430\nstorage:\n  key: fleet\n",
                "fleet needs fleet.advertise",
            ),
            (
                "fleet:\n  url: http://10.0.0.2:7430\n  advertise: http://10.0.0.5:7420\nstorage:\n  key: fleet\n",
                "fleet needs token",
            ),
            ("storage:\n  key: file:k\n", "want fleet or file:<absolute path>"),
            ("storage:\n  key: /root/k\n", "want fleet or file:<absolute path>"),
            ("storage:\n  key: \"\"\n", "want fleet or file:<absolute path>"),
        ] {
            let err = load(yaml).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{yaml}: {err:#}");
        }
    }

    /// Everything the daemon writes about machines is on a filesystem of the pool.
    #[test]
    fn the_daemon_files_are_on_the_pool() {
        let c = load("data_dir: /data\n").unwrap();
        let mounts: Vec<(&str, String)> = c
            .pool_mounts()
            .iter()
            .map(|(n, d)| (*n, d.display().to_string()))
            .collect();
        assert_eq!(
            mounts,
            [
                ("images", "/data/images".to_string()),
                ("jail", "/data/jail".to_string()),
                ("state", "/data/state".to_string()),
                ("run", "/data/run".to_string()),
            ]
        );
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
