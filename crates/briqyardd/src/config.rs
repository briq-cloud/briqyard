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
