//! Turns an OCI image into a root disk, once per image, and remembers its config.
//!
//! The layers are streamed one at a time to a file and applied in manifest order to a scratch
//! directory the host controls, every path resolved inside it by the kernel (`extract`: a
//! symlink in a layer never leads outside), whiteouts honoured, devices skipped;
//! `briqyard-init` is added; then `mkfs.ext4 -d` builds the disk without mounting anything.
//! The host never mounts a guest filesystem, and never holds a layer in memory.

use crate::events::{Ev, Events};
use crate::store::{private_dir, write_private};
use crate::zfs::Zfs;
use anyhow::{anyhow, Context, Result};
use briqyard_api::reason;
use chrono::{DateTime, Utc};
use oci_client::client::ClientConfig;
use oci_client::manifest::{ImageIndexEntry, OciImageManifest, Platform};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

#[cfg(target_os = "linux")]
mod extract;
#[cfg(target_os = "linux")]
use extract::{apply_layer, prepare_root};

/// The daemon runs on Linux alone: elsewhere, a build fails at its first layer.
#[cfg(not(target_os = "linux"))]
fn apply_layer(_: &std::path::Path, _: &str, _: std::fs::File) -> Result<usize> {
    Err(anyhow!("image extraction needs Linux (openat2)"))
}

#[cfg(not(target_os = "linux"))]
fn prepare_root(_: &std::path::Path, _: &std::path::Path) -> Result<()> {
    Err(anyhow!("image extraction needs Linux (openat2)"))
}

/// Where briqyard-init lives inside every root disk.
pub const INIT_PATH: &str = "/.briqyard/init";

/// The snapshot machines clone.
pub const SNAP: &str = "base";

/// The layer kinds the extractor reads: tar, plain or compressed with gzip or zstd.
const LAYER_MEDIA_TYPES: &[&str] = &[
    oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
    oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
    oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    "application/vnd.oci.image.layer.v1.tar+zstd",
];

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
}

/// The builds under way, by key: a waiter clones the receiver and is woken when the
/// builder's sender drops, which happens whether the build finished or its future was
/// dropped. The receiver is taken under the lock, so a wake-up is never missed.
type Builds = Mutex<HashMap<String, watch::Receiver<()>>>;

/// A build's hold on its key, freed on drop: a build whose future is dropped half way (the
/// request that asked for it went away) never leaves later creates waiting for it.
struct BuildSlot<'a> {
    building: &'a Builds,
    key: String,
    _done: watch::Sender<()>,
}

impl Drop for BuildSlot<'_> {
    // The key is freed before `_done` drops and wakes the waiters, so a woken waiter that
    // takes a turn finds it free.
    fn drop(&mut self) {
        self.building.lock().unwrap().remove(&self.key);
    }
}

enum Turn<'a> {
    Build(BuildSlot<'a>),
    Wait(watch::Receiver<()>),
}

/// Takes the build of `key`, or a ticket to wait for the one under way.
fn take<'a>(building: &'a Builds, key: &str) -> Turn<'a> {
    let mut b = building.lock().unwrap();
    if let Some(rx) = b.get(key) {
        return Turn::Wait(rx.clone());
    }
    let (tx, rx) = watch::channel(());
    b.insert(key.to_string(), rx);
    Turn::Build(BuildSlot {
        building,
        key: key.to_string(),
        _done: tx,
    })
}

/// What a reference last resolved to, kept on disk: when the registry refuses (a rate limit,
/// an outage), the image already on the host serves.
#[derive(Serialize, Deserialize)]
struct Resolution {
    reference: String,
    digest: String,
    at: DateTime<Utc>,
}

impl Builder {
    pub fn new(zfs: Zfs, dir: PathBuf, init: PathBuf, root_gb: u32) -> Result<Self> {
        let data =
            std::fs::read(&init).with_context(|| format!("init binary {}", init.display()))?;
        let init_hash = hex::encode(Sha256::digest(&data));
        private_dir(&dir)?;
        private_dir(&dir.join("meta"))?;
        Ok(Self {
            zfs,
            dir,
            init,
            root_gb,
            registries: vec![],
            init_hash,
            client: Client::new(ClientConfig {
                platform_resolver: Some(Box::new(host_platform)),
                ..Default::default()
            }),
            building: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            resolve_ttl: std::time::Duration::from_secs(600),
            events: None,
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

    /// Returns the built image for `reference`, pulling and building it when the host has not
    /// seen it. Concurrent calls for one image share a build.
    pub async fn ensure(&self, reference: &str) -> Result<Image> {
        let r: Reference = reference
            .parse()
            .map_err(|e| anyhow!("image {reference:?}: {e}"))?;
        let auth = self.auth_for(&r);
        let digest = self.resolve(&r, reference, &auth).await?;
        let key = self.key(&digest);
        // One build at a time per key.
        loop {
            match take(&self.building, &key) {
                Turn::Build(_slot) => {
                    return self.ensure_locked(&r, reference, &digest, &key).await;
                }
                Turn::Wait(mut rx) => {
                    // Returns when the builder is done, however it ended.
                    let _ = rx.changed().await;
                    if let Some(image) = self.load(&key) {
                        return Ok(image);
                    }
                    // No image: the build failed or its future was dropped. Take a turn.
                }
            }
        }
    }

    fn resolution_path(&self, reference: &str) -> PathBuf {
        let h = hex::encode(Sha256::digest(reference.as_bytes()));
        self.dir.join("meta").join(format!("ref-{}.json", &h[..20]))
    }

    /// The digest a reference names: pinned in the reference, remembered from a recent answer,
    /// asked of the registry, or, when the registry refuses, the one the host already built.
    async fn resolve(&self, r: &Reference, reference: &str, auth: &RegistryAuth) -> Result<String> {
        if let Some(d) = r.digest() {
            return Ok(d.to_string());
        }
        if let Some((d, at)) = self.resolved.lock().unwrap().get(reference) {
            if at.elapsed() < self.resolve_ttl {
                return Ok(d.clone());
            }
        }
        match self.client.pull_image_manifest(r, auth).await {
            Ok((_, digest)) => {
                self.resolved.lock().unwrap().insert(
                    reference.to_string(),
                    (digest.clone(), std::time::Instant::now()),
                );
                let rec = Resolution {
                    reference: reference.to_string(),
                    digest: digest.clone(),
                    at: Utc::now(),
                };
                let _ = write_private(
                    &self.resolution_path(reference),
                    &serde_json::to_vec(&rec).unwrap_or_default(),
                );
                Ok(digest)
            }
            Err(err) => {
                let last: Option<Resolution> = std::fs::read(self.resolution_path(reference))
                    .ok()
                    .and_then(|d| serde_json::from_slice(&d).ok());
                match last {
                    Some(rec) if self.load(&self.key(&rec.digest)).is_some() => {
                        tracing::warn!(
                            image = reference,
                            digest = rec.digest,
                            resolved_at = %rec.at,
                            err = %err,
                            "registry refused; the image already on the host serves"
                        );
                        Ok(rec.digest)
                    }
                    _ => Err(anyhow!(err)).with_context(|| format!("pull {reference}")),
                }
            }
        }
    }

    async fn ensure_locked(
        &self,
        r: &Reference,
        reference: &str,
        digest: &str,
        key: &str,
    ) -> Result<Image> {
        if let Some(cached) = self.load(key) {
            if self.zfs.exists(&cached.dataset()).await? {
                return Ok(cached);
            }
        }
        tracing::info!(image = reference, digest, key, "building image");
        let started = std::time::Instant::now();
        // Pulled by the digest resolved above, so a tag moved since names the same build.
        let pinned = r.clone_with_digest(digest.to_string());
        let (manifest, _, config) = self
            .client
            .pull_manifest_and_config(&pinned, &self.auth_for(r))
            .await
            .with_context(|| format!("pull {reference}"))?;
        check_layers(&manifest)?;
        let config = parse_config(config.as_bytes())?;
        let image = Image {
            r#ref: reference.to_string(),
            digest: digest.to_string(),
            key: key.to_string(),
            config,
            size_gb: self.root_gb,
            built_at: Utc::now(),
        };
        if let Err(e) = self.build(&pinned, &manifest, &image).await {
            let _ = self.zfs.destroy(&image.dataset()).await;
            let _ = std::fs::remove_dir_all(self.dir.join(format!("extract-{}", image.key)));
            return Err(e);
        }
        write_private(&self.meta_path(key), &serde_json::to_vec_pretty(&image)?)?;
        if let Some(ev) = &self.events {
            ev.emit(pulled(reference, digest, started.elapsed()));
        }
        Ok(image)
    }

    async fn build(&self, r: &Reference, manifest: &OciImageManifest, image: &Image) -> Result<()> {
        let scratch = self.dir.join(format!("extract-{}", image.key));
        let _ = std::fs::remove_dir_all(&scratch);
        let root = scratch.join("root");
        std::fs::create_dir_all(&root)?;
        // One layer at a time, in manifest order: streamed to a file, applied from it. The
        // daemon's memory during a build is the decompressor's buffer, whatever the image.
        let layer_file = scratch.join("layer");
        let mut files = 0;
        for layer in &manifest.layers {
            let mut out = tokio::fs::File::create(&layer_file).await?;
            self.client
                .pull_blob(r, layer, &mut out)
                .await
                .with_context(|| format!("pull layer {}", layer.digest))?;
            out.flush().await?;
            drop(out);
            let (root, path, media_type) =
                (root.clone(), layer_file.clone(), layer.media_type.clone());
            files += tokio::task::spawn_blocking(move || {
                apply_layer(&root, &media_type, std::fs::File::open(&path)?)
            })
            .await??;
        }
        let _ = std::fs::remove_file(&layer_file);
        let (root2, init) = (root.clone(), self.init.clone());
        tokio::task::spawn_blocking(move || prepare_root(&root2, &init)).await??;
        let dev = self
            .zfs
            .create(&image.dataset(), (self.root_gb as u64) << 30)
            .await?;
        let out = tokio::process::Command::new("mkfs.ext4")
            .args([
                "-q",
                "-F",
                "-L",
                "root",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0",
                "-d",
            ])
            .arg(&root)
            .arg(&dev)
            .output()
            .await
            .context("run mkfs.ext4")?;
        let _ = std::fs::remove_dir_all(&scratch);
        if !out.status.success() {
            return Err(anyhow!(
                "mkfs.ext4 {}: {}",
                dev.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        self.zfs.snapshot(&image.dataset(), SNAP).await?;
        tracing::info!(
            image = image.r#ref,
            files,
            dataset = image.dataset(),
            "image built"
        );
        Ok(())
    }
}

/// Why an image was removed (ADR 0021): `reason` in its `image_removed` event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// `DELETE /v1/images/{key}`.
    Request,
    /// No machine used it for `image_keep_days`.
    Unused,
    /// The pool is under `conditions.disk_free_pct`.
    DiskPressure,
}

impl Removal {
    fn reason(self) -> &'static str {
        match self {
            Removal::Request => "request",
            Removal::Unused => "unused",
            Removal::DiskPressure => "disk_pressure",
        }
    }
    fn why(self) -> &'static str {
        match self {
            Removal::Request => "on request",
            Removal::Unused => "unused past image_keep_days",
            Removal::DiskPressure => "unused, the pool under its free threshold",
        }
    }
}

/// The event of an image's removal.
fn removed(im: &Image, how: Removal) -> Ev {
    Ev::normal(
        reason::IMAGE_REMOVED,
        format!("removed {}: {}", im.r#ref, how.why()),
    )
    .data(serde_json::json!({
        "image": im.r#ref, "digest": im.digest, "key": im.key, "reason": how.reason(),
    }))
}

/// The event of a pull and build: which image, which digest, how long it took.
fn pulled(reference: &str, digest: &str, took: std::time::Duration) -> Ev {
    let secs = (took.as_secs_f64() * 10.0).round() / 10.0;
    Ev::normal(
        reason::IMAGE_PULLED,
        format!("pulled {reference} in {secs} s"),
    )
    .data(serde_json::json!({"image": reference, "digest": digest, "seconds": secs}))
}

/// Refuses an image with no layers or a layer kind the extractor cannot read, before any
/// layer is pulled.
fn check_layers(manifest: &OciImageManifest) -> Result<()> {
    if manifest.layers.is_empty() {
        return Err(anyhow!("image has no layers"));
    }
    for layer in &manifest.layers {
        if !LAYER_MEDIA_TYPES.contains(&layer.media_type.as_str()) {
            return Err(anyhow!(
                "layer {}: media type {:?} is not supported",
                layer.digest,
                layer.media_type
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
impl Builder {
    /// An image as if built, for tests of what clones one: its record, its dataset and the
    /// snapshot machines clone. `reference` pins a digest, so `ensure` asks no registry.
    pub(crate) async fn seed(&self, reference: &str, config: ImageConfig) -> Result<Image> {
        let r: Reference = reference.parse()?;
        let digest = r.digest().context("the reference pins no digest")?;
        let image = Image {
            r#ref: reference.to_string(),
            digest: digest.to_string(),
            key: self.key(digest),
            config,
            size_gb: self.root_gb,
            built_at: Utc::now(),
        };
        self.zfs.create(&image.dataset(), 1 << 20).await?;
        self.zfs.snapshot(&image.dataset(), SNAP).await?;
        write_private(&self.meta_path(&image.key), &serde_json::to_vec(&image)?)?;
        Ok(image)
    }
}

impl Builder {
    /// Every image the host has built, with how many machines still clone it.
    pub async fn list(&self) -> Result<Vec<(Image, usize)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.dir.join("meta"))? {
            let entry = entry?;
            let data = match std::fs::read(entry.path()) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let im: Image = match serde_json::from_slice(&data) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let clones = self
                .zfs
                .clones(&im.dataset(), SNAP)
                .await
                .unwrap_or_default()
                .len();
            out.push((im, clones));
        }
        out.sort_by_key(|(im, _)| im.built_at);
        Ok(out)
    }

    /// Removes an image nobody clones, an event saying why. `Ok(false)`: machines still use it.
    pub async fn remove(&self, key: &str, how: Removal) -> Result<bool> {
        let ds = format!("images/{key}");
        if self.zfs.exists(&ds).await? && !self.zfs.clones(&ds, SNAP).await?.is_empty() {
            return Ok(false);
        }
        let im = self.load(key);
        self.zfs.destroy(&ds).await?;
        let _ = std::fs::remove_file(self.meta_path(key));
        if let Some(im) = im {
            tracing::info!(
                image = im.r#ref,
                key,
                reason = how.reason(),
                "image removed"
            );
            if let Some(ev) = &self.events {
                ev.emit(removed(&im, how));
            }
        }
        Ok(true)
    }

    /// Removes images no machine clones that were built more than `keep` ago.
    pub async fn gc(&self, keep: chrono::Duration) -> Result<usize> {
        let mut removed = 0;
        for (im, clones) in self.list().await? {
            if clones == 0
                && Utc::now() - im.built_at > keep
                && self.remove(&im.key, Removal::Unused).await?
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Removes unused images, oldest first, until they freed `need` bytes or none is left
    /// (ADR 0021): no clone, and no key in `named` (the records' images: a create holds its
    /// record before it clones). What each takes is counted as freed, since ZFS frees a
    /// destroyed dataset's blocks in the background. How many went, and what they took.
    pub async fn free(&self, need: u64, named: &HashSet<String>) -> Result<(usize, u64)> {
        let (mut removed, mut freed) = (0, 0);
        for (im, clones) in self.list().await? {
            if freed >= need {
                break;
            }
            if clones > 0 || named.contains(&im.key) {
                continue;
            }
            let took = self.zfs.used(&im.dataset()).await?;
            if self.remove(&im.key, Removal::DiskPressure).await? {
                removed += 1;
                freed += took;
            }
        }
        Ok((removed, freed))
    }
}

fn host_platform(entries: &[ImageIndexEntry]) -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    };
    entries
        .iter()
        .find(|e| matches!(&e.platform, Some(Platform { os, architecture, .. }) if os == "linux" && architecture == arch))
        .map(|e| e.digest.clone())
}

fn parse_config(data: &[u8]) -> Result<ImageConfig> {
    let v: serde_json::Value = serde_json::from_slice(data).context("image config")?;
    let c = &v["config"];
    let strings = |key: &str| -> Vec<String> {
        c[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut env = BTreeMap::new();
    for kv in strings("Env") {
        if let Some((k, val)) = kv.split_once('=') {
            env.insert(k.to_string(), val.to_string());
        }
    }
    let volumes = c["Volumes"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let exposed_ports = c["ExposedPorts"]
        .as_object()
        .map(|o| {
            o.keys()
                .filter_map(|k| k.split('/').next().and_then(|p| p.parse().ok()))
                .collect()
        })
        .unwrap_or_default();
    Ok(ImageConfig {
        entrypoint: strings("Entrypoint"),
        cmd: strings("Cmd"),
        env,
        workdir: c["WorkingDir"].as_str().unwrap_or("").to_string(),
        user: c["User"].as_str().unwrap_or("").to_string(),
        volumes,
        exposed_ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_removal_is_an_event_that_says_why() {
        let im = Image {
            r#ref: "alpine:3.20".into(),
            digest: "sha256:abc".into(),
            key: "k1".into(),
            config: ImageConfig::default(),
            size_gb: 8,
            built_at: Utc::now(),
        };
        let dir = tempfile::tempdir().unwrap();
        let log = Events::open(dir.path()).unwrap();
        for how in [Removal::Request, Removal::Unused, Removal::DiskPressure] {
            log.emit(removed(&im, how));
        }
        let evs = log.read(0, &Default::default(), 10).unwrap().events;
        let got: Vec<(&str, &str, &str)> = evs
            .iter()
            .map(|e| {
                (
                    e.reason.as_str(),
                    e.message.as_str(),
                    e.data.as_ref().unwrap()["reason"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "image_removed",
                    "removed alpine:3.20: on request",
                    "request"
                ),
                (
                    "image_removed",
                    "removed alpine:3.20: unused past image_keep_days",
                    "unused"
                ),
                (
                    "image_removed",
                    "removed alpine:3.20: unused, the pool under its free threshold",
                    "disk_pressure"
                ),
            ]
        );
        assert_eq!(
            evs[0].data,
            Some(serde_json::json!({
                "image": "alpine:3.20", "digest": "sha256:abc", "key": "k1", "reason": "request"
            }))
        );
    }

    #[test]
    fn a_pull_is_an_event_with_its_digest_and_time() {
        let ev = pulled(
            "alpine:3.20",
            "sha256:abc",
            std::time::Duration::from_millis(4240),
        );
        let dir = tempfile::tempdir().unwrap();
        let log = Events::open(dir.path()).unwrap();
        log.emit(ev);
        let e = log
            .read(0, &Default::default(), 1)
            .unwrap()
            .events
            .remove(0);
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("image_pulled", "pulled alpine:3.20 in 4.2 s")
        );
        assert_eq!(
            e.data,
            Some(
                serde_json::json!({"image": "alpine:3.20", "digest": "sha256:abc", "seconds": 4.2})
            )
        );
        assert_eq!(e.machine_id, "");
    }

    #[test]
    fn config_parsing() {
        let c = parse_config(br#"{"config":{"Entrypoint":["docker-entrypoint.sh"],"Cmd":["postgres"],"Env":["PATH=/usr/bin","PGDATA=/var/lib/postgresql/data"],"WorkingDir":"","User":"","Volumes":{"/var/lib/postgresql/data":{}},"ExposedPorts":{"5432/tcp":{}}}}"#).unwrap();
        assert_eq!(c.entrypoint, vec!["docker-entrypoint.sh"]);
        assert_eq!(c.env["PGDATA"], "/var/lib/postgresql/data");
        assert_eq!(c.volumes, vec!["/var/lib/postgresql/data"]);
        assert_eq!(c.exposed_ports, vec![5432]);
    }

    #[test]
    fn layers_are_checked_before_any_pull() {
        let manifest = |layers: serde_json::Value| -> OciImageManifest {
            serde_json::from_value(serde_json::json!({
                "schemaVersion": 2,
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:c0", "size": 1},
                "layers": layers
            }))
            .unwrap()
        };
        let err = check_layers(&manifest(serde_json::json!([]))).unwrap_err();
        assert_eq!(err.to_string(), "image has no layers");
        let ok = serde_json::json!({"mediaType": oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, "digest": "sha256:a1", "size": 1});
        check_layers(&manifest(serde_json::json!([ok]))).unwrap();
        let odd = serde_json::json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+xz", "digest": "sha256:b2", "size": 1});
        let err = check_layers(&manifest(serde_json::json!([ok, odd]))).unwrap_err();
        assert_eq!(
            err.to_string(),
            "layer sha256:b2: media type \"application/vnd.oci.image.layer.v1.tar+xz\" is not supported"
        );
    }

    /// A build whose future is dropped half way frees its key: a waiter wakes and the next
    /// `ensure` of the key builds instead of waiting forever.
    #[tokio::test]
    async fn a_dropped_build_frees_its_key_and_wakes_its_waiters() {
        use futures::FutureExt;
        let building: Builds = Mutex::new(HashMap::new());
        let Turn::Build(slot) = take(&building, "k") else {
            panic!("the first taker builds");
        };
        let Turn::Wait(mut rx) = take(&building, "k") else {
            panic!("the second waits");
        };
        assert!(
            rx.changed().now_or_never().is_none(),
            "nothing to wake on yet"
        );
        drop(slot);
        assert!(rx.changed().now_or_never().is_some(), "woken by the drop");
        assert!(building.lock().unwrap().is_empty());
        assert!(matches!(take(&building, "k"), Turn::Build(_)));
        // A build that ended normally frees the key the same way.
        let Turn::Build(slot) = take(&building, "k2") else {
            panic!();
        };
        drop(slot);
        assert!(matches!(take(&building, "k2"), Turn::Build(_)));
    }
}
