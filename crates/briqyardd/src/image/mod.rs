//! Turns an OCI image into a root disk, once per image, and remembers its config.
//!
//! The layers are streamed one at a time to a file and applied in manifest order to a scratch
//! directory the host controls, every path resolved inside it by the kernel (`extract`: a
//! symlink in a layer never leads outside), whiteouts honoured, devices skipped;
//! `briqyard-init` is added; then `mkfs.ext4 -d` builds the disk without mounting anything.
//! The host never mounts a guest filesystem, and never holds a layer in memory.

use crate::events::Events;
use crate::store::private_dir;
use crate::zfs::Zfs;
use anyhow::{Context, Result};
use builds::Builds;
use chrono::{DateTime, Utc};
use client::{client_config, READ_TIMEOUT};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;

mod builds;
mod client;
#[cfg(target_os = "linux")]
pub mod extract;
mod gc;
mod mirror;
mod pull;
#[cfg(test)]
mod tests;

pub use gc::Removal;
pub use mirror::Mirror;

/// Where briqyard-init lives inside every root disk.
pub const INIT_PATH: &str = "/.briqyard/init";

/// The snapshot machines clone.
pub const SNAP: &str = "base";

/// What the image says about how to run it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub workdir: String,
    pub user: String,
    pub volumes: Vec<String>,
    pub exposed_ports: Vec<u16>,
}

/// A built root disk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Image {
    pub r#ref: String,
    pub digest: String,
    /// The dataset name under images/: digest plus the init's hash, shortened.
    pub key: String,
    pub config: ImageConfig,
    pub size_gb: u32,
    pub built_at: DateTime<Utc>,
}

impl Image {
    pub fn dataset(&self) -> String {
        format!("images/{}", self.key)
    }
}

pub struct Builder {
    pub zfs: Zfs,
    pub dir: PathBuf,
    pub init: PathBuf,
    pub root_gb: u32,
    /// Credentials by registry host; anything else is pulled anonymously.
    pub registries: Vec<(String, String, String)>,
    /// Pull-through mirrors, at most one per registry (ADR 0036).
    mirrors: Vec<Mirror>,
    init_hash: String,
    /// One registry client: its connection pool and TLS sessions serve every pull.
    client: Client,
    /// The builds under way, by key (see `take`).
    building: Builds,
    /// What a reference resolved to, and when: a tag is asked of the registry once per
    /// `resolve_ttl`, a digest never.
    resolved: Mutex<HashMap<String, (String, std::time::Instant)>>,
    pub resolve_ttl: std::time::Duration,
    /// Where a pull is logged (`image_pulled`); the manager sets it.
    pub events: Option<Events>,
    /// Pulls run at once (`PULLS_AT_ONCE`, ADR 0048): an image already built takes no turn.
    pulls: tokio::sync::Semaphore,
}

/// Pulls and builds of different images at once on a host (ADR 0048); one image's creates
/// share one build.
pub const PULLS_AT_ONCE: usize = 4;

impl Builder {
    pub fn new(
        zfs: Zfs,
        dir: PathBuf,
        init: PathBuf,
        root_gb: u32,
        mirrors: Vec<Mirror>,
    ) -> Result<Self> {
        let data =
            std::fs::read(&init).with_context(|| format!("init binary {}", init.display()))?;
        let init_hash = hex::encode(Sha256::digest(&data));
        private_dir(&dir)?;
        private_dir(&dir.join("meta"))?;
        // Only a mirror may be plain HTTP: what it serves is checked by digest.
        let plain: Vec<String> = mirrors
            .iter()
            .filter(|m| m.plain_http)
            .map(|m| m.host.clone())
            .collect();
        Ok(Self {
            zfs,
            dir,
            init,
            root_gb,
            registries: vec![],
            mirrors,
            init_hash,
            client: Client::new(client_config(plain, READ_TIMEOUT)),
            building: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            resolve_ttl: std::time::Duration::from_secs(600),
            events: None,
            pulls: tokio::sync::Semaphore::new(PULLS_AT_ONCE),
        })
    }

    fn auth_for(&self, r: &Reference) -> RegistryAuth {
        let host = r.registry();
        self.registries
            .iter()
            .find(|(h, _, _)| h == host)
            .map(|(_, u, p)| RegistryAuth::Basic(u.clone(), p.clone()))
            .unwrap_or(RegistryAuth::Anonymous)
    }

    fn key(&self, digest: &str) -> String {
        let h = Sha256::digest(format!("{digest}|{}|{}", self.init_hash, self.root_gb).as_bytes());
        hex::encode(h)[..20].to_string()
    }

    fn meta_path(&self, key: &str) -> PathBuf {
        self.dir.join("meta").join(format!("{key}.json"))
    }

    fn load(&self, key: &str) -> Option<Image> {
        let data = std::fs::read(self.meta_path(key)).ok()?;
        serde_json::from_slice(&data).ok()
    }
}
