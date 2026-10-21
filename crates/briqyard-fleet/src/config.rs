//! The fleet's configuration file.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    /// The fleet's own listener: `{ cert, key }` serves TLS; without it, plain HTTP, refused
    /// off loopback unless `off` says something in front terminates TLS (ADR 0020).
    pub tls: Tls,
    /// Required from API clients when set. A host's heartbeat presents the host's own token
    /// instead (`hosts[].token`, or the one the bootstrap gave it).
    pub token: String,
    pub state_dir: PathBuf,
    /// Hosts you manage yourself: polled, and expected to register with their token.
    pub hosts: Vec<StaticHost>,
    pub placement: Placement,
    pub provisioner: Provisioner,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaticHost {
    pub id: String,
    pub url: String,
    /// The host's API token: what the fleet forwards with, and what its heartbeats present.
    /// Without one the host is polled only.
    pub token: String,
    pub region: String,
    /// The SHA-256 of the host's API certificate (`briqyardd tls-fingerprint` on the host),
    /// with an `https://` URL; empty for a host on plain HTTP (ADR 0020).
    pub tls_fingerprint: String,
}

/// The fleet's listener.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Tls {
    /// Plain HTTP, on loopback only.
    #[default]
    Unset,
    /// Plain HTTP on any address: something else terminates TLS.
    Off,
    /// TLS with the operator's certificate chain and key, PEM.
    Files { cert: PathBuf, key: PathBuf },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsFiles {
    cert: PathBuf,
    key: PathBuf,
}

/// `tls: off` or `tls: { cert, key }`.
impl<'de> Deserialize<'de> for Tls {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        match serde_yaml::Value::deserialize(d)? {
            serde_yaml::Value::String(s) if s == "off" => Ok(Tls::Off),
            v @ serde_yaml::Value::Mapping(_) => serde_yaml::from_value::<TlsFiles>(v)
                .map(|f| Tls::Files {
                    cert: f.cert,
                    key: f.key,
                })
                .map_err(|e| D::Error::custom(format!("tls: {e}"))),
            _ => Err(D::Error::custom("tls: want `off` or `{ cert, key }`")),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Placement {
    pub fill_ceiling: f64,
    pub down_after_sec: u64,
}

impl Default for Placement {
    fn default() -> Self {
        Self {
            fill_ceiling: 0.85,
            down_after_sec: 60,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Provisioner {
    /// static, hetzner-robot, scaleway, ovh
    pub kind: String,
    /// Says what it would do and does nothing. The default.
    pub dry_run: bool,
    pub enabled: bool,
    pub min_hosts: usize,
    pub max_hosts: usize,
    /// Add a host when no ready host can take a machine of this size.
    pub slot_mb: u32,
    pub idle_grace: String,
    pub hetzner: Hetzner,
    pub scaleway: Scaleway,
    pub ovh: Ovh,
    pub bootstrap: Bootstrap,
}

/// Installing briqyardd on a server the provisioner delivered, over SSH.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Bootstrap {
    pub enabled: bool,
    pub ssh_user: String,
    /// The private key the provider installed on the server.
    pub ssh_key: PathBuf,
    /// The script to run; empty runs the hack/bootstrap-host.sh this build ships.
    pub script: PathBuf,
    /// `BRIQYARD_RELEASE` for the script: where the binaries are.
    pub release: String,
    /// `BRIQYARD_RELEASE_TOKEN`: a token that reads the release of a private GitHub
    /// repository; `BRIQYARD_RELEASE_TOKEN` in the fleet's environment overrides it.
    pub release_token: String,
    /// `BRIQYARD_POOL_DEVICE`: the drives for the ZFS pool, comma-separated, two for a mirror
    /// (a file when empty). A drive the OS is on gives its free space (ADR 0028).
    pub pool_device: String,
    /// The private network the hosts' APIs and endpoints live on (OVH's vRack), as a CIDR. A
    /// host whose API address is in it gets `PRIVATE_ADDRESS` with this prefix, and its
    /// public interface takes SSH and `public_tcp_ports` only (ADR 0028).
    pub private_network: String,
    /// `PRIVATE_INTERFACE`: the interface given the host's private address when it has none
    /// yet (servers of one model share interface names).
    pub private_interface: String,
    /// `PUBLIC_TCP_PORTS`: ports a private host's public interface takes besides SSH (an
    /// edge's beside the daemon), which its machines reach too (`network.host_ports`).
    pub public_tcp_ports: Vec<u16>,
    /// `FLEET_URL`: this fleet, as the new host reaches it.
    pub fleet_url: String,
    /// `ALLOWED_CLIENTS`: the networks (CIDRs) the host's API and endpoints accept
    /// connections from: this fleet's and the routers'. Required when the host listens on a
    /// public address.
    pub allowed_clients: Vec<String>,
    /// Tries, two minutes apart, before the host is marked `failed`.
    pub max_attempts: u32,
}

impl Default for Bootstrap {
    fn default() -> Self {
        Self {
            enabled: false,
            ssh_user: "root".into(),
            ssh_key: "/etc/briqyard/fleet_ssh_key".into(),
            script: PathBuf::new(),
            release: String::new(),
            release_token: String::new(),
            pool_device: String::new(),
            private_network: String::new(),
            private_interface: String::new(),
            public_tcp_ports: Vec::new(),
            fleet_url: String::new(),
            allowed_clients: Vec::new(),
            max_attempts: 90,
        }
    }
}

impl Default for Provisioner {
    fn default() -> Self {
        Self {
            kind: "static".into(),
            dry_run: true,
            enabled: false,
            min_hosts: 1,
            max_hosts: 3,
            slot_mb: 8192,
            idle_grace: "2h".into(),
            hetzner: Hetzner::default(),
            scaleway: Scaleway::default(),
            ovh: Ovh::default(),
            bootstrap: Bootstrap::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Hetzner {
    /// Robot credentials; `HETZNER_ROBOT_USER` / `HETZNER_ROBOT_PASSWORD` override these.
    pub user: String,
    pub password: String,
    pub product: String,
    pub location: String,
    pub ssh_key_fingerprint: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scaleway {
    /// `SCW_SECRET_KEY` overrides this.
    pub secret_key: String,
    pub project_id: String,
    pub zone: String,
    pub offer_id: String,
    pub os_id: String,
}

/// OVHcloud dedicated servers, ordered through the API's cart.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ovh {
    /// API credentials; `OVH_APPLICATION_KEY` / `OVH_APPLICATION_SECRET` / `OVH_CONSUMER_KEY`
    /// override these.
    pub application_key: String,
    pub application_secret: String,
    pub consumer_key: String,
    /// The plan code of the server to order (`25risem01-v2` for example).
    pub plan_code: String,
    /// `eco` (Kimsufi, So you Start, Rise) or `baremetal` (Advance, Scale).
    pub range: String,
    /// The data center the server is ordered in (`gra`, `rbx`, `sbg`...).
    pub datacenter: String,
    /// The name of an SSH key already in the account (`/me/sshKey`), installed with Ubuntu.
    pub ssh_key_name: String,
    /// The OVH subsidiary the order is made under.
    pub subsidiary: String,
}

impl Default for Ovh {
    fn default() -> Self {
        Self {
            application_key: String::new(),
            application_secret: String::new(),
            consumer_key: String::new(),
            plan_code: String::new(),
            range: "eco".into(),
            datacenter: String::new(),
            ssh_key_name: String::new(),
            subsidiary: "FR".into(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7430".into(),
            tls: Tls::Unset,
            token: String::new(),
            state_dir: "/var/lib/briqyard-fleet".into(),
            hosts: vec![],
            placement: Placement::default(),
            provisioner: Provisioner::default(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg: Self = match path {
            None => Self::default(),
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("read config {}", p.display()))?;
                serde_yaml::from_str(&text)
                    .with_context(|| format!("parse config {}", p.display()))?
            }
        };
        if let Ok(v) = std::env::var("HETZNER_ROBOT_USER") {
            cfg.provisioner.hetzner.user = v;
        }
        if let Ok(v) = std::env::var("HETZNER_ROBOT_PASSWORD") {
            cfg.provisioner.hetzner.password = v;
        }
        if let Ok(v) = std::env::var("SCW_SECRET_KEY") {
            cfg.provisioner.scaleway.secret_key = v;
        }
        if let Ok(v) = std::env::var("OVH_APPLICATION_KEY") {
            cfg.provisioner.ovh.application_key = v;
        }
        if let Ok(v) = std::env::var("OVH_APPLICATION_SECRET") {
            cfg.provisioner.ovh.application_secret = v;
        }
        if let Ok(v) = std::env::var("OVH_CONSUMER_KEY") {
            cfg.provisioner.ovh.consumer_key = v;
        }
        if let Ok(v) = std::env::var("BRIQYARD_RELEASE_TOKEN") {
            cfg.provisioner.bootstrap.release_token = v;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&mut self) -> Result<()> {
        let listen: SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("listen {:?}: want address:port", self.listen))?;
        if self.tls == Tls::Unset && !listen.ip().is_loopback() {
            bail!(
                "listen: {} is not loopback and tls is not set: give tls: {{ cert, key }} (a \
                 certificate for the fleet's name), or tls: off if something in front \
                 terminates TLS",
                listen.ip()
            );
        }
        let b = &self.provisioner.bootstrap;
        if !b.private_network.is_empty() {
            crate::bootstrap::Network::parse(&b.private_network)
                .map_err(|e| anyhow::anyhow!("provisioner.bootstrap.private_network {e}"))?;
        }
        for h in &mut self.hosts {
            let name = if h.id.is_empty() { &h.url } else { &h.id };
            if !h.tls_fingerprint.is_empty() {
                h.tls_fingerprint = briqyard_api::tls::parse_fingerprint(&h.tls_fingerprint)
                    .map_err(|e| anyhow::anyhow!("hosts {name}: tls_fingerprint {e}"))?;
            }
            let https = h.url.starts_with("https://");
            if https != !h.tls_fingerprint.is_empty() {
                bail!(
                    "hosts {name}: {} wants {}",
                    h.url,
                    if https {
                        "its tls_fingerprint: the fleet trusts a host's certificate by it alone"
                    } else {
                        "an https:// URL with a tls_fingerprint"
                    }
                );
            }
        }
        Ok(())
    }

    /// The fleet's own URL on its listen address, for a host that is given none.
    pub fn own_url(&self) -> String {
        let scheme = match self.tls {
            Tls::Files { .. } => "https",
            _ => "http",
        };
        format!("{scheme}://{}", self.listen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ENV_VARS: [&str; 7] = [
        "HETZNER_ROBOT_USER",
        "HETZNER_ROBOT_PASSWORD",
        "SCW_SECRET_KEY",
        "OVH_APPLICATION_KEY",
        "OVH_APPLICATION_SECRET",
        "OVH_CONSUMER_KEY",
        "BRIQYARD_RELEASE_TOKEN",
    ];

    /// `load` reads the process environment, which every test shares: one at a time, and each
    /// one puts the variables back as it found them.
    static ENV: Mutex<()> = Mutex::new(());

    fn with_env<T>(set: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _lock = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(&str, Option<String>)> = ENV_VARS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        for k in ENV_VARS {
            std::env::remove_var(k);
        }
        for (k, v) in set {
            std::env::set_var(k, v);
        }
        let out = f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    fn write(dir: &tempfile::TempDir, text: &str) -> PathBuf {
        let p = dir.path().join("fleet.yaml");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn defaults() {
        let cfg = with_env(&[], || Config::load(None).unwrap());
        assert_eq!(cfg.listen, "127.0.0.1:7430");
        assert_eq!(cfg.tls, Tls::Unset);
        assert_eq!(cfg.own_url(), "http://127.0.0.1:7430");
        assert_eq!(cfg.token, "");
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/briqyard-fleet"));
        assert!(cfg.hosts.is_empty());
        assert_eq!(cfg.placement.fill_ceiling, 0.85);
        assert_eq!(cfg.placement.down_after_sec, 60);
        let p = &cfg.provisioner;
        assert_eq!(p.kind, "static");
        assert!(p.dry_run, "a provisioner orders nothing unless told to");
        assert!(!p.enabled);
        assert_eq!((p.min_hosts, p.max_hosts), (1, 3));
        assert_eq!(p.slot_mb, 8192);
        assert_eq!(p.idle_grace, "2h");
        assert_eq!(p.hetzner.user, "");
        assert_eq!(p.scaleway.secret_key, "");
        assert_eq!(p.ovh.application_key, "");
        assert_eq!(p.ovh.plan_code, "");
        assert_eq!(p.ovh.range, "eco");
        assert_eq!(p.ovh.subsidiary, "FR");
        let b = &p.bootstrap;
        assert!(!b.enabled);
        assert_eq!(b.ssh_user, "root");
        assert_eq!(b.ssh_key, PathBuf::from("/etc/briqyard/fleet_ssh_key"));
        assert_eq!(b.script, PathBuf::new());
        assert_eq!(b.max_attempts, 90);
        assert_eq!(b.release_token, "");
        assert_eq!(b.private_network, "");
        assert!(b.public_tcp_ports.is_empty());
    }

    #[test]
    fn a_full_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            r#"
listen: 0.0.0.0:7430
tls:
  cert: /etc/briqyard/fleet.crt
  key: /etc/briqyard/fleet.key
token: api-t0k
state_dir: /tmp/fleet
hosts:
  - id: h1
    url: https://10.0.0.1:7420
    token: t1
    region: fsn
    tls_fingerprint: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
  - url: http://10.0.0.2:7420
placement:
  fill_ceiling: 0.9
  down_after_sec: 30
provisioner:
  kind: scaleway
  dry_run: false
  enabled: true
  min_hosts: 2
  max_hosts: 5
  slot_mb: 4096
  idle_grace: 30m
  hetzner:
    user: '#ws+u'
    password: p
    product: AX102
    location: FSN1
    ssh_key_fingerprint: 'ab:cd'
  scaleway:
    secret_key: s
    project_id: proj
    zone: fr-par-2
    offer_id: offer
    os_id: os
  ovh:
    application_key: ak
    application_secret: as
    consumer_key: ck
    plan_code: 25risem01-v2
    range: baremetal
    datacenter: gra
    ssh_key_name: fleet
    subsidiary: IE
  bootstrap:
    enabled: true
    ssh_user: ubuntu
    ssh_key: /etc/briqyard/key
    script: /opt/bootstrap.sh
    release: https://example/v1
    release_token: ghp-file
    pool_device: /dev/nvme0n1,/dev/nvme1n1
    private_network: 10.42.0.0/16
    private_interface: enp3s0f1
    public_tcp_ports: [7430, 80]
    fleet_url: https://fleet.example
    max_attempts: 3
"#,
        );
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.listen, "0.0.0.0:7430");
        assert_eq!(
            cfg.tls,
            Tls::Files {
                cert: "/etc/briqyard/fleet.crt".into(),
                key: "/etc/briqyard/fleet.key".into()
            }
        );
        assert_eq!(cfg.own_url(), "https://0.0.0.0:7430");
        assert_eq!(cfg.token, "api-t0k");
        assert_eq!(cfg.state_dir, PathBuf::from("/tmp/fleet"));
        assert_eq!(cfg.hosts.len(), 2);
        assert_eq!(cfg.hosts[0].id, "h1");
        assert_eq!(cfg.hosts[0].url, "https://10.0.0.1:7420");
        assert_eq!(cfg.hosts[0].token, "t1");
        assert_eq!(cfg.hosts[0].region, "fsn");
        assert_eq!(
            cfg.hosts[0].tls_fingerprint,
            "abcdef0123456789".repeat(4),
            "as openssl prints it, kept as the daemon reports it"
        );
        assert_eq!(cfg.hosts[1].tls_fingerprint, "");
        assert_eq!(cfg.hosts[1].id, "", "a host needs only its URL");
        assert_eq!(cfg.hosts[1].url, "http://10.0.0.2:7420");
        assert_eq!(cfg.placement.fill_ceiling, 0.9);
        assert_eq!(cfg.placement.down_after_sec, 30);
        let p = &cfg.provisioner;
        assert_eq!(p.kind, "scaleway");
        assert!(!p.dry_run);
        assert!(p.enabled);
        assert_eq!((p.min_hosts, p.max_hosts), (2, 5));
        assert_eq!(p.slot_mb, 4096);
        assert_eq!(p.idle_grace, "30m");
        assert_eq!(p.hetzner.user, "#ws+u");
        assert_eq!(p.hetzner.password, "p");
        assert_eq!(p.hetzner.product, "AX102");
        assert_eq!(p.hetzner.location, "FSN1");
        assert_eq!(p.hetzner.ssh_key_fingerprint, "ab:cd");
        assert_eq!(p.scaleway.secret_key, "s");
        assert_eq!(p.scaleway.project_id, "proj");
        assert_eq!(p.scaleway.zone, "fr-par-2");
        assert_eq!(p.scaleway.offer_id, "offer");
        assert_eq!(p.scaleway.os_id, "os");
        assert_eq!(p.ovh.application_key, "ak");
        assert_eq!(p.ovh.application_secret, "as");
        assert_eq!(p.ovh.consumer_key, "ck");
        assert_eq!(p.ovh.plan_code, "25risem01-v2");
        assert_eq!(p.ovh.range, "baremetal");
        assert_eq!(p.ovh.datacenter, "gra");
        assert_eq!(p.ovh.ssh_key_name, "fleet");
        assert_eq!(p.ovh.subsidiary, "IE");
        let b = &p.bootstrap;
        assert!(b.enabled);
        assert_eq!(b.ssh_user, "ubuntu");
        assert_eq!(b.ssh_key, PathBuf::from("/etc/briqyard/key"));
        assert_eq!(b.script, PathBuf::from("/opt/bootstrap.sh"));
        assert_eq!(b.release, "https://example/v1");
        assert_eq!(b.release_token, "ghp-file");
        assert_eq!(b.pool_device, "/dev/nvme0n1,/dev/nvme1n1");
        assert_eq!(b.private_network, "10.42.0.0/16");
        assert_eq!(b.private_interface, "enp3s0f1");
        assert_eq!(b.public_tcp_ports, [7430, 80]);
        assert_eq!(b.fleet_url, "https://fleet.example");
        assert_eq!(b.max_attempts, 3);
    }

    #[test]
    fn a_partial_file_keeps_the_other_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "token: t\nprovisioner:\n  kind: hetzner-robot\n");
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.token, "t");
        assert_eq!(cfg.listen, "127.0.0.1:7430");
        assert_eq!(cfg.provisioner.kind, "hetzner-robot");
        assert!(
            cfg.provisioner.dry_run,
            "dry_run stays on when the file is silent"
        );
        assert_eq!(cfg.provisioner.max_hosts, 3);
        assert_eq!(cfg.provisioner.bootstrap.max_attempts, 90);
    }

    #[test]
    fn unknown_fields_are_refused() {
        // A typo in a setting must not silently leave the default in force.
        let dir = tempfile::tempdir().unwrap();
        for (text, field) in [
            ("tokne: t\n", "tokne"),
            ("host_token: t\n", "host_token"),
            ("placement:\n  fill_ceilling: 0.5\n", "fill_ceilling"),
            ("provisioner:\n  dry: false\n", "dry"),
            ("provisioner:\n  bootstrap:\n    enable: true\n", "enable"),
            ("provisioner:\n  scaleway:\n    secret: s\n", "secret"),
            ("provisioner:\n  ovh:\n    plan: x\n", "plan"),
            ("hosts:\n  - url: http://h\n    tokn: t\n", "tokn"),
            ("tls:\n  cert: a\n  keys: b\n", "keys"),
        ] {
            let path = write(&dir, text);
            let err = with_env(&[], || Config::load(Some(&path)).unwrap_err());
            let msg = format!("{err:#}");
            assert!(msg.contains("parse config"), "{msg}");
            assert!(msg.contains(field), "{field} named in: {msg}");
        }
    }

    #[test]
    fn a_plain_listener_off_loopback_needs_tls_off() {
        let dir = tempfile::tempdir().unwrap();
        let load = |text: &str| {
            let path = write(&dir, text);
            with_env(&[], || Config::load(Some(&path)))
        };
        let err = load("listen: 0.0.0.0:7430\n").unwrap_err().to_string();
        assert!(
            err.starts_with("listen: 0.0.0.0 is not loopback and tls is not set"),
            "{err}"
        );
        assert!(err.contains("tls: off"), "{err}");
        let cfg = load("listen: 0.0.0.0:7430\ntls: off\n").unwrap();
        assert_eq!(cfg.tls, Tls::Off);
        assert_eq!(cfg.own_url(), "http://0.0.0.0:7430");
        load("listen: \"[::1]:7430\"\n").unwrap();
        for (text, msg) in [
            ("tls: on\n", "tls: want `off` or `{ cert, key }`"),
            ("tls: true\n", "tls: want `off` or `{ cert, key }`"),
            ("tls:\n  cert: a\n", "missing field `key`"),
            ("listen: localhost:7430\n", "want address:port"),
        ] {
            let err = format!("{:#}", load(text).unwrap_err());
            assert!(err.contains(msg), "{text:?}: {err}");
        }
    }

    #[test]
    fn a_host_on_tls_is_listed_with_its_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let load = |text: &str| {
            let path = write(&dir, text);
            with_env(&[], || Config::load(Some(&path)))
        };
        let fp = "ab".repeat(32);
        load(&format!(
            "hosts:\n  - url: https://10.0.0.1:7420\n    tls_fingerprint: {fp}\n"
        ))
        .unwrap();
        // No trust on first use: an https host without a pin, or a pin on plain HTTP.
        let err = load("hosts:\n  - id: h1\n    url: https://10.0.0.1:7420\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("hosts h1: https://10.0.0.1:7420 wants its tls_fingerprint"),
            "{err}"
        );
        let err = load(&format!(
            "hosts:\n  - url: http://10.0.0.1:7420\n    tls_fingerprint: {fp}\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.starts_with(
                "hosts http://10.0.0.1:7420: http://10.0.0.1:7420 wants an https:// URL"
            ),
            "{err}"
        );
        let err = load("hosts:\n  - url: https://h\n    tls_fingerprint: abc\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("64 hex digits"), "{err}");
    }

    #[test]
    fn the_private_network_is_a_cidr() {
        let dir = tempfile::tempdir().unwrap();
        let load = |net: &str| {
            let path = write(
                &dir,
                &format!("provisioner:\n  bootstrap:\n    private_network: \"{net}\"\n"),
            );
            with_env(&[], || Config::load(Some(&path)))
        };
        load("10.42.0.0/16").unwrap();
        for bad in ["10.42.0.0", "10.42.0.0/33", "fd00::/8", "vrack"] {
            let err = load(bad).unwrap_err().to_string();
            assert!(
                err.starts_with("provisioner.bootstrap.private_network "),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn the_dev_config_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../hack/fleet.dev.yaml");
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.tls, Tls::Off);
        assert!(cfg.hosts.iter().all(|h| h.tls_fingerprint.is_empty()));
    }

    #[test]
    fn a_missing_or_broken_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("none.yaml");
        let err = with_env(&[], || Config::load(Some(&missing)).unwrap_err());
        assert!(format!("{err:#}").contains("read config"), "{err:#}");
        let path = write(&dir, "listen: [\n");
        let err = with_env(&[], || Config::load(Some(&path)).unwrap_err());
        assert!(format!("{err:#}").contains("parse config"), "{err:#}");
    }

    #[test]
    fn the_environment_overrides_the_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "provisioner:\n  hetzner:\n    user: file-user\n    password: file-pass\n  scaleway:\n    secret_key: file-key\n  ovh:\n    application_key: file-ak\n    application_secret: file-as\n    consumer_key: file-ck\n",
        );
        let set = [
            ("HETZNER_ROBOT_USER", "env-user"),
            ("HETZNER_ROBOT_PASSWORD", "env-pass"),
            ("SCW_SECRET_KEY", "env-key"),
            ("OVH_APPLICATION_KEY", "env-ak"),
            ("OVH_APPLICATION_SECRET", "env-as"),
            ("OVH_CONSUMER_KEY", "env-ck"),
            ("BRIQYARD_RELEASE_TOKEN", "env-gh"),
        ];
        let cfg = with_env(&set, || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.provisioner.bootstrap.release_token, "env-gh");
        assert_eq!(cfg.provisioner.hetzner.user, "env-user");
        assert_eq!(cfg.provisioner.hetzner.password, "env-pass");
        assert_eq!(cfg.provisioner.scaleway.secret_key, "env-key");
        assert_eq!(cfg.provisioner.ovh.application_key, "env-ak");
        assert_eq!(cfg.provisioner.ovh.application_secret, "env-as");
        assert_eq!(cfg.provisioner.ovh.consumer_key, "env-ck");
        let cfg = with_env(&set, || Config::load(None).unwrap());
        assert_eq!(cfg.provisioner.hetzner.user, "env-user");
        assert_eq!(cfg.provisioner.scaleway.secret_key, "env-key");
        assert_eq!(cfg.provisioner.ovh.consumer_key, "env-ck");
        // One variable set leaves the others to the file.
        let cfg = with_env(&[("SCW_SECRET_KEY", "env-key")], || {
            Config::load(Some(&path)).unwrap()
        });
        assert_eq!(cfg.provisioner.hetzner.user, "file-user");
        assert_eq!(cfg.provisioner.hetzner.password, "file-pass");
        assert_eq!(cfg.provisioner.scaleway.secret_key, "env-key");
        assert_eq!(cfg.provisioner.ovh.application_key, "file-ak");
        assert_eq!(cfg.provisioner.ovh.application_secret, "file-as");
        assert_eq!(cfg.provisioner.ovh.consumer_key, "file-ck");
        // Without any, the file stands.
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.provisioner.hetzner.user, "file-user");
        assert_eq!(cfg.provisioner.scaleway.secret_key, "file-key");
        assert_eq!(cfg.provisioner.ovh.application_secret, "file-as");
    }
}
