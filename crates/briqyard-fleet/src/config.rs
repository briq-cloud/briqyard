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
    /// A token of its own for `/metrics`, so a scraper never holds the API's. Empty: the API's;
    /// none at all on a loopback listener with `tls` unset (ADR 0042).
    pub metrics_token: String,
    pub state_dir: PathBuf,
    /// Hosts you manage yourself: polled, and expected to register with their token.
    pub hosts: Vec<StaticHost>,
    pub placement: Placement,
    /// Installing briqyardd on a server added with `briqyard host add` (ADR 0028).
    pub bootstrap: Bootstrap,
    /// The registry's backup (ADR 0032): off until `store` is set.
    pub backup: Backup,
}

/// Where the registry's backup goes, encrypted to whom (ADR 0032).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Backup {
    /// `s3://bucket/prefix` or `file:///path`; empty turns the backup off. S3 credentials come
    /// from `BRIQYARD_S3_ACCESS_KEY` and `BRIQYARD_S3_SECRET_KEY`, as a host's.
    pub store: String,
    pub endpoint: String,
    pub region: String,
    /// The age recipient (`age1…`) the backup is encrypted to. Its identity (the private key)
    /// is kept off the fleet's host: `briqyard-fleet keygen` makes a pair.
    pub recipient: String,
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

/// Installing briqyardd on a server over SSH: at `host add`, and at `host upgrade`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Bootstrap {
    pub enabled: bool,
    pub ssh_user: String,
    /// The private key the server takes for `ssh_user`.
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
    /// `FLEET_ADDRESS`: the fleet's address on the private network. A private host resolves
    /// `fleet_url`'s name to it, so its calls come from the private address the fleet knows
    /// it by (ADR 0028); empty leaves the name to DNS.
    pub fleet_address: String,
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
            fleet_address: String::new(),
            allowed_clients: Vec::new(),
            max_attempts: 90,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7430".into(),
            tls: Tls::Unset,
            token: String::new(),
            metrics_token: String::new(),
            state_dir: "/var/lib/briqyard-fleet".into(),
            hosts: vec![],
            placement: Placement::default(),
            bootstrap: Bootstrap::default(),
            backup: Backup::default(),
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
                let parse = || format!("parse config {}", p.display());
                let mut doc: serde_yaml::Value = serde_yaml::from_str(&text).with_context(parse)?;
                match old_provisioner(&mut doc).with_context(parse)? {
                    // From the text, so that an error says where.
                    None => serde_yaml::from_str(&text).with_context(parse)?,
                    Some(warning) => {
                        tracing::warn!(config = %p.display(), "{warning}");
                        serde_yaml::from_value(doc).with_context(parse)?
                    }
                }
            }
        };
        if let Ok(v) = std::env::var("BRIQYARD_RELEASE_TOKEN") {
            cfg.bootstrap.release_token = v;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&mut self) -> Result<()> {
        match (
            self.backup.store.is_empty(),
            self.backup.recipient.is_empty(),
        ) {
            (true, true) => {}
            (false, false) => {
                crate::backup::recipient(&self.backup.recipient)?;
            }
            (false, true) => {
                bail!("backup.store needs backup.recipient: the registry is backed up encrypted")
            }
            (true, false) => bail!("backup.recipient needs backup.store"),
        }
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
        let b = &self.bootstrap;
        if !b.private_network.is_empty() {
            crate::bootstrap::Network::parse(&b.private_network)
                .map_err(|e| anyhow::anyhow!("bootstrap.private_network {e}"))?;
        }
        if !b.fleet_address.is_empty()
            && crate::bootstrap::private_address(b, &b.fleet_address).is_none()
        {
            bail!(
                "bootstrap.fleet_address {:?}: want an IPv4 address in private_network ({:?})",
                b.fleet_address,
                b.private_network
            );
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

/// v0.1.1 kept the bootstrap under `provisioner:`, beside the settings of the provisioners and
/// the autoscaler that ADR 0042 removed. For one release, `provisioner: { kind: static,
/// bootstrap: … }` is read as a top-level `bootstrap:`, and the warning to log is returned
/// (`None`: no `provisioner:`). Any other setting there configured something that is gone, and
/// is refused by name.
fn old_provisioner(doc: &mut serde_yaml::Value) -> Result<Option<&'static str>> {
    use serde_yaml::Value;
    let Some(top) = doc.as_mapping_mut() else {
        return Ok(None);
    };
    let mut old = match top.remove("provisioner") {
        None => return Ok(None),
        Some(Value::Mapping(m)) => m,
        Some(Value::Null) => Default::default(),
        Some(_) => bail!("provisioner: removed (ADR 0042): delete it"),
    };
    let move_it = match old.contains_key("bootstrap") {
        true => "move provisioner.bootstrap to a top-level bootstrap: and delete provisioner:",
        false => "delete provisioner:",
    };
    match old.remove("kind") {
        None => {}
        Some(Value::String(k)) if k == "static" => {}
        Some(k) => bail!(
            "provisioner.kind {}: the fleet no longer orders servers (ADR 0042): buy one \
             yourself and add it with `briqyard host add`; {move_it}",
            k.as_str().unwrap_or("?")
        ),
    }
    let bootstrap = old.remove("bootstrap");
    if let Some((key, _)) = old.into_iter().next() {
        bail!(
            "provisioner.{}: removed with the autoscaler and the provisioners (ADR 0042); {move_it}",
            key.as_str().unwrap_or("?")
        );
    }
    let Some(bootstrap) = bootstrap else {
        return Ok(Some("provisioner: is no longer read (ADR 0042): delete it"));
    };
    if top.contains_key("bootstrap") {
        bail!("provisioner.bootstrap and bootstrap: both set: keep bootstrap: alone (ADR 0042)");
    }
    top.insert("bootstrap".into(), bootstrap);
    Ok(Some(
        "provisioner.bootstrap is read as bootstrap: for this release only (ADR 0042): move it \
         to the top level and delete provisioner:",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ENV_VARS: [&str; 1] = ["BRIQYARD_RELEASE_TOKEN"];

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
        let b = &cfg.bootstrap;
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
  fleet_address: 10.42.0.11
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
        let b = &cfg.bootstrap;
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
        assert_eq!(b.fleet_address, "10.42.0.11");
        assert_eq!(b.max_attempts, 3);
    }

    #[test]
    fn a_partial_file_keeps_the_other_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "token: t\nbootstrap:\n  enabled: true\n");
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.token, "t");
        assert_eq!(cfg.listen, "127.0.0.1:7430");
        assert!(cfg.bootstrap.enabled);
        assert_eq!(cfg.bootstrap.ssh_user, "root");
        assert_eq!(cfg.bootstrap.max_attempts, 90);
    }

    #[test]
    fn unknown_fields_are_refused() {
        // A typo in a setting must not silently leave the default in force.
        let dir = tempfile::tempdir().unwrap();
        for (text, field) in [
            ("tokne: t\n", "tokne"),
            ("host_token: t\n", "host_token"),
            ("placement:\n  fill_ceilling: 0.5\n", "fill_ceilling"),
            ("bootstrap:\n  enable: true\n", "enable"),
            ("provisioner:\n  bootstrap:\n    enable: true\n", "enable"),
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
            let path = write(&dir, &format!("bootstrap:\n  private_network: \"{net}\"\n"));
            with_env(&[], || Config::load(Some(&path)))
        };
        load("10.42.0.0/16").unwrap();
        for bad in ["10.42.0.0", "10.42.0.0/33", "fd00::/8", "vrack"] {
            let err = load(bad).unwrap_err().to_string();
            assert!(
                err.starts_with("bootstrap.private_network "),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn the_fleet_address_is_on_the_private_network() {
        let dir = tempfile::tempdir().unwrap();
        let load = |addr: &str| {
            let path = write(
                &dir,
                &format!(
                    "bootstrap:\n  private_network: 10.42.0.0/16\n  fleet_address: \"{addr}\"\n"
                ),
            );
            with_env(&[], || Config::load(Some(&path)))
        };
        load("10.42.0.11").unwrap();
        load("").unwrap();
        for bad in ["10.43.0.1", "fleet.example.com", "fd00::1"] {
            let err = load(bad).unwrap_err().to_string();
            assert!(err.starts_with("bootstrap.fleet_address "), "{bad}: {err}");
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
    fn the_environment_overrides_the_release_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "bootstrap:\n  release_token: file-gh\n");
        let set = [("BRIQYARD_RELEASE_TOKEN", "env-gh")];
        let cfg = with_env(&set, || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.bootstrap.release_token, "env-gh");
        let cfg = with_env(&set, || Config::load(None).unwrap());
        assert_eq!(cfg.bootstrap.release_token, "env-gh");
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.bootstrap.release_token, "file-gh");
    }

    #[test]
    fn hosts_and_a_bootstrap_are_a_whole_fleet() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "hosts:\n  - id: h1\n    url: http://10.0.0.1:7420\n    token: t1\nbootstrap:\n  enabled: true\n  ssh_key: /etc/briqyard/key\n  release: \"0.1.1\"\n",
        );
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.hosts.len(), 1);
        assert!(cfg.bootstrap.enabled);
        assert_eq!(cfg.bootstrap.ssh_key, PathBuf::from("/etc/briqyard/key"));
        assert_eq!(cfg.bootstrap.release, "0.1.1");
    }

    /// v0.1.1's `provisioner: { kind: static, bootstrap }` (ADR 0042): read for one release,
    /// with a warning; what configured the provisioners or the autoscaler is refused by name.
    #[test]
    fn the_bootstrap_of_v0_1_1_is_read_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let load = |text: &str| {
            let path = write(&dir, text);
            with_env(&[], || Config::load(Some(&path)))
        };
        let old = "token: t\nprovisioner:\n  kind: static\n  bootstrap:\n    enabled: true\n    private_network: 10.42.0.0/16\n    fleet_address: 10.42.0.11\n    max_attempts: 3\n";
        let cfg = load(old).unwrap();
        assert_eq!(cfg.token, "t");
        assert!(cfg.bootstrap.enabled);
        assert_eq!(cfg.bootstrap.private_network, "10.42.0.0/16");
        assert_eq!(cfg.bootstrap.fleet_address, "10.42.0.11");
        assert_eq!(cfg.bootstrap.max_attempts, 3);
        assert_eq!(
            cfg.bootstrap.ssh_user, "root",
            "the rest defaults as at the top level"
        );
        load("provisioner:\n  bootstrap:\n    enabled: true\n").unwrap();
        load("provisioner:\n  kind: static\n").unwrap();

        let mut doc: serde_yaml::Value = serde_yaml::from_str(old).unwrap();
        let warning = old_provisioner(&mut doc).unwrap().unwrap();
        assert!(
            warning
                .starts_with("provisioner.bootstrap is read as bootstrap: for this release only"),
            "{warning}"
        );
        let mut doc: serde_yaml::Value = serde_yaml::from_str("provisioner: {}\n").unwrap();
        let warning = old_provisioner(&mut doc).unwrap().unwrap();
        assert!(
            warning.starts_with("provisioner: is no longer read"),
            "{warning}"
        );
        let mut doc: serde_yaml::Value =
            serde_yaml::from_str("bootstrap:\n  enabled: true\n").unwrap();
        assert_eq!(
            old_provisioner(&mut doc).unwrap(),
            None,
            "the new place: no warning"
        );

        for (text, msg) in [
            (
                "provisioner:\n  kind: ovh\n  bootstrap:\n    enabled: true\n",
                "provisioner.kind ovh: the fleet no longer orders servers",
            ),
            (
                "provisioner:\n  enabled: true\n",
                "provisioner.enabled: removed with the autoscaler",
            ),
            (
                "provisioner:\n  kind: static\n  dry_run: true\n",
                "provisioner.dry_run: removed",
            ),
            (
                "provisioner:\n  slot_mb: 4096\n",
                "provisioner.slot_mb: removed",
            ),
            (
                "provisioner:\n  hetzner:\n    user: u\n",
                "provisioner.hetzner: removed",
            ),
            (
                "provisioner:\n  bootstrap:\n    enabled: true\nbootstrap:\n  enabled: true\n",
                "provisioner.bootstrap and bootstrap: both set",
            ),
            ("provisioner: static\n", "provisioner: removed"),
        ] {
            let err = format!("{:#}", load(text).unwrap_err());
            assert!(err.contains(msg), "{text:?}: {err}");
            assert!(err.contains("ADR 0042"), "{text:?}: {err}");
        }
        // What to do names the bootstrap only when the file has one.
        let err = format!("{:#}", load("provisioner:\n  enabled: true\n").unwrap_err());
        assert!(err.ends_with("; delete provisioner:"), "{err}");
        let err = format!(
            "{:#}",
            load("provisioner:\n  enabled: true\n  bootstrap:\n    enabled: true\n").unwrap_err()
        );
        assert!(
            err.ends_with(
                "; move provisioner.bootstrap to a top-level bootstrap: and delete provisioner:"
            ),
            "{err}"
        );
        // A typo in the old place is refused as in the new one.
        let err = format!(
            "{:#}",
            load("provisioner:\n  bootstrap:\n    enable: true\n").unwrap_err()
        );
        assert!(err.contains("unknown field `enable`"), "{err}");
    }
}
