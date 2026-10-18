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
    /// static, hetzner-robot, scaleway
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
        Ok(cfg)
    }
}
