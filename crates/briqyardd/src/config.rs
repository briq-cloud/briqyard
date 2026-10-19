//! The daemon's configuration file.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The HTTP API address. Put it behind TLS or a private network before listening on
    /// anything but loopback.
    pub listen: String,
    /// When set, required as `Authorization: Bearer <token>` on every request.
    pub token: String,
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
    pub ingress: Ingress,
    /// The size of every root disk (thin: only written blocks take space).
    pub root_disk_gb: u32,
    /// An image no machine uses is removed this many days after it was built.
    pub image_keep_days: u32,
    /// Sleep with a memory snapshot instead of a stop, so a wake resumes in well under a
    /// second. Costs the machine's memory in disk while it sleeps.
    pub suspend_on_sleep: bool,
    pub fleet: Option<FleetClient>,
    /// What the daemon advertises: memory it may hand to machines (default: the host's memory
    /// minus 2 GB) and vCPUs (default: hardware threads times 4).
    pub capacity: Capacity,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ingress {
    /// The range of host ports handed to TCP endpoints.
    pub tcp_ports: String,
    /// The shared HTTP listener that routes by host name; empty disables it.
    pub http: String,
    /// The suffix of HTTP endpoint host names.
    pub domain: String,
    /// The address TCP endpoints listen on.
    pub bind: String,
    /// The address endpoints are reported at (`Endpoint.address`): what a router on another
    /// machine dials. Default: `bind` when it is one address, else the host's primary address.
    pub advertise: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FleetClient {
    pub url: String,
    pub token: String,
    /// The URL the fleet reaches this daemon at.
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
            token: String::new(),
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
            ingress: Ingress::default(),
            root_disk_gb: 8,
            image_keep_days: 14,
            suspend_on_sleep: false,
            fleet: None,
            capacity: Capacity::default(),
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
            bind: "0.0.0.0".into(),
            advertise: String::new(),
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
        for (name, p) in [
            ("firecracker", &self.firecracker),
            ("kernel", &self.kernel),
            ("init", &self.init),
        ] {
            if !p.is_absolute() {
                bail!("{name} must be an absolute path");
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
        assert_eq!(c.ingress.tcp_ports, "20000-29999");
        assert!(c.ingress.http.is_empty());
        assert_eq!(c.ingress.domain, "byard.localhost");
        assert_eq!(c.ingress.bind, "0.0.0.0");
        assert!(c.ingress.advertise.is_empty());
        assert_eq!(c.root_disk_gb, 8);
        assert_eq!(c.image_keep_days, 14);
        assert!(!c.suspend_on_sleep);
        assert!(c.fleet.is_none());
        assert_eq!(c.capacity.memory_mb, 0);
        assert_eq!(c.capacity.vcpus, 0);
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
ingress:
  tcp_ports: 30000-31000
  http: 0.0.0.0:8080
  domain: byard.example
  bind: 10.0.0.5
  advertise: 203.0.113.5
root_disk_gb: 16
image_keep_days: 3
suspend_on_sleep: true
fleet:
  url: http://fleet:7430
  token: ft
  advertise: http://10.0.0.5:7420
  region: fsn1
capacity:
  memory_mb: 65536
  vcpus: 128
"#,
        )
        .unwrap();
        assert_eq!(c.listen, "0.0.0.0:7420");
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
        assert_eq!(c.ingress.tcp_ports, "30000-31000");
        assert_eq!(c.ingress.http, "0.0.0.0:8080");
        assert_eq!(c.ingress.domain, "byard.example");
        assert_eq!(c.ingress.bind, "10.0.0.5");
        assert_eq!(c.ingress.advertise, "203.0.113.5");
        assert_eq!(c.root_disk_gb, 16);
        assert_eq!(c.image_keep_days, 3);
        assert!(c.suspend_on_sleep);
        let f = c.fleet.unwrap();
        assert_eq!(f.url, "http://fleet:7430");
        assert_eq!(f.token, "ft");
        assert_eq!(f.advertise, "http://10.0.0.5:7420");
        assert_eq!(f.region, "fsn1");
        assert_eq!(c.capacity.memory_mb, 65536);
        assert_eq!(c.capacity.vcpus, 128);
    }

    #[test]
    fn a_partial_section_keeps_the_other_defaults() {
        let c = load("ingress:\n  http: 127.0.0.1:8080\n").unwrap();
        assert_eq!(c.ingress.http, "127.0.0.1:8080");
        assert_eq!(c.ingress.tcp_ports, "20000-29999");
        assert_eq!(c.ingress.domain, "byard.localhost");
    }

    #[test]
    fn unknown_fields_are_refused_by_name() {
        // A typo at the top level, in a section, and in a list item: each names the field.
        for (yaml, field) in [
            ("listn: 127.0.0.1:1\n", "listn"),
            ("storage:\n  pol: byard\n", "pol"),
            ("registries:\n  - host: a\n    user: b\n", "user"),
            ("fleet:\n  urll: x\n", "urll"),
            ("capacity:\n  memory: 1\n", "memory"),
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
