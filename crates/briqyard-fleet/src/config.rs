//! The fleet's configuration file.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    /// Required from API clients when set.
    pub token: String,
    /// Required from daemons on /v1/hosts/register when set.
    pub host_token: String,
    pub state_dir: PathBuf,
    /// Hosts you manage yourself; a host may also just register.
    pub hosts: Vec<StaticHost>,
    pub placement: Placement,
    pub provisioner: Provisioner,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaticHost {
    pub id: String,
    pub url: String,
    pub token: String,
    pub region: String,
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
    /// `BRIQYARD_POOL_DEVICE`: the drive for the ZFS pool (a file when empty).
    pub pool_device: String,
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
            pool_device: String::new(),
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
            token: String::new(),
            host_token: String::new(),
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
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ENV_VARS: [&str; 6] = [
        "HETZNER_ROBOT_USER",
        "HETZNER_ROBOT_PASSWORD",
        "SCW_SECRET_KEY",
        "OVH_APPLICATION_KEY",
        "OVH_APPLICATION_SECRET",
        "OVH_CONSUMER_KEY",
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
        assert_eq!(cfg.token, "");
        assert_eq!(cfg.host_token, "");
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
    }

    #[test]
    fn a_full_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            r#"
listen: 0.0.0.0:7430
token: api-t0k
host_token: host-t0k
state_dir: /tmp/fleet
hosts:
  - id: h1
    url: http://10.0.0.1:7420
    token: t1
    region: fsn
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
    pool_device: /dev/nvme1n1
    fleet_url: https://fleet.example
    max_attempts: 3
"#,
        );
        let cfg = with_env(&[], || Config::load(Some(&path)).unwrap());
        assert_eq!(cfg.listen, "0.0.0.0:7430");
        assert_eq!(cfg.token, "api-t0k");
        assert_eq!(cfg.host_token, "host-t0k");
        assert_eq!(cfg.state_dir, PathBuf::from("/tmp/fleet"));
        assert_eq!(cfg.hosts.len(), 2);
        assert_eq!(cfg.hosts[0].id, "h1");
        assert_eq!(cfg.hosts[0].url, "http://10.0.0.1:7420");
        assert_eq!(cfg.hosts[0].token, "t1");
        assert_eq!(cfg.hosts[0].region, "fsn");
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
        assert_eq!(b.pool_device, "/dev/nvme1n1");
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
            ("placement:\n  fill_ceilling: 0.5\n", "fill_ceilling"),
            ("provisioner:\n  dry: false\n", "dry"),
            ("provisioner:\n  bootstrap:\n    enable: true\n", "enable"),
            ("provisioner:\n  scaleway:\n    secret: s\n", "secret"),
            ("provisioner:\n  ovh:\n    plan: x\n", "plan"),
            ("hosts:\n  - url: http://h\n    tokn: t\n", "tokn"),
        ] {
            let path = write(&dir, text);
            let err = with_env(&[], || Config::load(Some(&path)).unwrap_err());
            let msg = format!("{err:#}");
            assert!(msg.contains("parse config"), "{msg}");
            assert!(msg.contains(field), "{field} named in: {msg}");
        }
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
        ];
        let cfg = with_env(&set, || Config::load(Some(&path)).unwrap());
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
