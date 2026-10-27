//! Turns an OCI image into a root disk, once per image, and remembers its config.
//!
//! The layers are streamed one at a time to a file and applied in manifest order to a scratch
//! directory the host controls, every path resolved inside it (a symlink in a layer never
//! leads outside), whiteouts honoured, devices skipped; `briqyard-init` is added; then
//! `mkfs.ext4 -d` builds the disk without mounting anything. The host never mounts a guest
//! filesystem, and never holds a layer in memory.

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
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

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

/// Applies one layer, read as it is decompressed: whiteouts remove, everything else is
/// extracted inside `root`.
pub fn apply_layer<R: Read>(root: &Path, media_type: &str, layer: R) -> Result<usize> {
    let reader: Box<dyn Read + '_> = if media_type.ends_with("gzip") {
        Box::new(flate2::read::GzDecoder::new(layer))
    } else if media_type.ends_with("zstd") {
        Box::new(zstd::Decoder::new(layer)?)
    } else {
        Box::new(layer)
    };
    extract(root, reader)
}

/// Resolves `rel` inside `root`, following symlinks only within `root` (an absolute link
/// target is taken relative to `root`; `..` never climbs above it).
pub fn secure_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    let mut pending: Vec<String> = Path::new(rel)
        .components()
        .rev()
        .filter_map(component)
        .collect();
    let mut hops = 0;
    while let Some(part) = pending.pop() {
        if part == ".." {
            if out != root {
                out.pop();
            }
            continue;
        }
        let candidate = out.join(&part);
        match std::fs::symlink_metadata(&candidate) {
            Ok(m) if m.file_type().is_symlink() => {
                hops += 1;
                if hops > 255 {
                    return Err(anyhow!("{rel}: too many symlinks"));
                }
                let target = std::fs::read_link(&candidate)?;
                let comps: Vec<String> = target.components().rev().filter_map(component).collect();
                if target.is_absolute() {
                    out = root.to_path_buf();
                }
                pending.extend(comps);
            }
            _ => out = candidate,
        }
    }
    Ok(out)
}

/// Like `secure_join`, but the last component is never followed: this is where something is
/// about to be written or removed, and an existing symlink there must be replaced, not
/// written through (a layer that rewrites `usr/bin/lzcat -> /bin/busybox` would otherwise
/// clobber busybox itself). A path ending in `..` has no last name to keep: it resolves as
/// `secure_join` does, never above `root`.
pub fn secure_join_nofollow(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut parts: Vec<String> = Path::new(rel).components().filter_map(component).collect();
    match parts.pop() {
        Some(last) if last != ".." => Ok(secure_join(root, &parts.join("/"))?.join(last)),
        _ => secure_join(root, rel),
    }
}

fn component(c: Component<'_>) -> Option<String> {
    match c {
        Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
        Component::ParentDir => Some("..".into()),
        _ => None,
    }
}

/// Writes a tar stream under `root`. Returns the number of entries written.
pub fn extract<R: Read>(root: &Path, r: R) -> Result<usize> {
    let mut archive = tar::Archive::new(r);
    archive.set_preserve_permissions(false);
    let mut n = 0;
    // Hard links are made after every other entry, so their target exists; each is
    // resolved then, since a later entry may have replaced a directory of its path.
    let mut hardlinks: Vec<(String, String)> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        let clean = name.trim_start_matches('/').trim_end_matches('/');
        if clean.is_empty() || clean == "." {
            continue;
        }
        let base = clean.rsplit('/').next().unwrap_or(clean);
        if base == ".wh..wh..opq" {
            let dir = secure_join(root, clean.trim_end_matches(".wh..wh..opq"))?;
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    remove_any(&e.path());
                }
            }
            continue;
        }
        if let Some(victim) = base.strip_prefix(".wh.") {
            let parent = &clean[..clean.len() - base.len()];
            let target = secure_join_nofollow(root, &format!("{parent}{victim}"))?;
            if target != root {
                remove_any(&target);
            }
            continue;
        }
        let dest = secure_join_nofollow(root, clean)?;
        // A name that resolves to the root itself (`a/..`) may only set its mode.
        if dest == root && entry.header().entry_type() != tar::EntryType::Directory {
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The entry's own link name reads GNU long links and PAX `linkpath`; the header's
        // stops at 100 bytes.
        let link = entry
            .link_name()?
            .map(|p| p.into_owned())
            .unwrap_or_default();
        let header = entry.header();
        let mode = header.mode().unwrap_or(0o644) & 0o7777;
        let (uid, gid) = (
            header.uid().unwrap_or(0) as u32,
            header.gid().unwrap_or(0) as u32,
        );
        let mtime = header.mtime().unwrap_or(0);
        match header.entry_type() {
            tar::EntryType::Directory => {
                let is_real_dir = std::fs::symlink_metadata(&dest)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if !is_real_dir {
                    remove_any(&dest);
                    std::fs::create_dir_all(&dest)?;
                }
                std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode | 0o700))?;
                let _ = std::os::unix::fs::chown(&dest, Some(uid), Some(gid));
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode));
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                remove_any(&dest);
                let mut f = std::fs::File::create(&dest)?;
                std::io::copy(&mut entry, &mut f)?;
                drop(f);
                let _ = std::os::unix::fs::chown(&dest, Some(uid), Some(gid));
                std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))?;
                let _ = filetime(&dest, mtime);
            }
            tar::EntryType::Symlink => {
                remove_any(&dest);
                // Kept as is: the guest resolves it inside its own root.
                std::os::unix::fs::symlink(&link, &dest)?;
                let _ = std::os::unix::fs::lchown(&dest, Some(uid), Some(gid));
            }
            tar::EntryType::Link => {
                let target = link.to_string_lossy();
                hardlinks.push((
                    clean.to_string(),
                    target.trim_start_matches('/').to_string(),
                ));
                continue;
            }
            _ => continue,
        }
        n += 1;
    }
    for (name, target) in hardlinks {
        let dest = secure_join_nofollow(root, &name)?;
        if dest == root {
            continue;
        }
        let src = secure_join(root, &target)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        remove_any(&dest);
        if std::fs::hard_link(&src, &dest).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

fn remove_any(p: &Path) {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(p);
        }
        Err(_) => {}
    }
}

fn filetime(p: &Path, mtime: u64) -> std::io::Result<()> {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime);
    let f = std::fs::File::options().write(true).open(p)?;
    f.set_modified(t)
}

/// Adds what every guest needs: the init, mount points, writable name files. Every path is
/// resolved inside the root, and a symlink a layer left at one is replaced, never followed.
pub fn prepare_root(root: &Path, init: &Path) -> Result<()> {
    for d in ["proc", "sys", "dev", "run", "tmp", "etc", ".briqyard"] {
        dir_in_root(root, d)?;
    }
    std::fs::set_permissions(
        dir_in_root(root, "tmp")?,
        std::fs::Permissions::from_mode(0o1777),
    )?;
    let dest = file_in_root(root, INIT_PATH.trim_start_matches('/'))?;
    remove_any(&dest);
    std::fs::copy(init, &dest).context("copy init")?;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    // The init rewrites these at boot; a symlink (Debian's resolv.conf) or a missing file
    // would make that write land elsewhere or fail.
    for f in ["etc/hosts", "etc/resolv.conf", "etc/hostname"] {
        let p = file_in_root(root, f)?;
        if std::fs::symlink_metadata(&p).is_err() {
            std::fs::write(&p, b"")?;
        }
    }
    Ok(())
}

/// A directory at `rel` inside `root`: made when missing, a symlink there replaced.
fn dir_in_root(root: &Path, rel: &str) -> Result<PathBuf> {
    let p = secure_join_nofollow(root, rel)?;
    if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
        std::fs::remove_file(&p)?;
    }
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Where a file at `rel` inside `root` goes: its directory made, a symlink at it removed.
fn file_in_root(root: &Path, rel: &str) -> Result<PathBuf> {
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    let p = dir_in_root(root, dir)?.join(name);
    if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
        std::fs::remove_file(&p)?;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an archive with raw names: the tar crate refuses `..` and absolute links when
    /// writing, and those are what the extractor must survive.
    fn archive(entries: &[(&str, tar::EntryType, &str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, link, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_mode(0o755);
            h.set_size(body.len() as u64);
            {
                let g = h.as_gnu_mut().unwrap();
                g.name[..name.len()].copy_from_slice(name.as_bytes());
                g.linkname[..link.len()].copy_from_slice(link.as_bytes());
            }
            h.set_cksum();
            b.append(&h, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn extraction_stays_in_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let tar = archive(&[
            ("etc/", tar::EntryType::Directory, "", ""),
            ("etc/hello", tar::EntryType::Regular, "", "hi\n"),
            (
                "escape",
                tar::EntryType::Symlink,
                outside.path().to_str().unwrap(),
                "",
            ),
            ("escape/pwned", tar::EntryType::Regular, "", "x"),
            ("../../up", tar::EntryType::Regular, "", "y"),
            ("bin/sh", tar::EntryType::Regular, "", "#!"),
            ("bin/ash", tar::EntryType::Link, "bin/sh", ""),
            ("dev/null", tar::EntryType::Char, "", ""),
        ]);
        let n = extract(root.path(), &tar[..]).unwrap();
        assert!(n >= 5, "{n}");
        assert_eq!(
            std::fs::read_to_string(root.path().join("etc/hello")).unwrap(),
            "hi\n"
        );
        assert!(
            !outside.path().join("pwned").exists(),
            "written outside the root through a symlink"
        );
        assert!(root.path().join("up").exists());
        assert!(root.path().join("bin/ash").exists());
        assert!(
            std::fs::symlink_metadata(root.path().join("dev/null")).is_err(),
            "devices are skipped"
        );
    }

    #[test]
    fn a_name_ending_in_dotdot_stays_in_root() {
        // `x/../..` once resolved to `root/x/../..`, above the root: a directory entry
        // changed that directory's mode, a file entry or a whiteout removed it whole.
        for entry in [
            ("x/../../..", tar::EntryType::Directory, "", ""),
            ("y/../../..", tar::EntryType::Regular, "", "y"),
            ("../../.wh..", tar::EntryType::Regular, "", ""),
            ("a/..", tar::EntryType::Regular, "", "z"),
        ] {
            let base = tempfile::tempdir().unwrap();
            let root = base.path().join("a/b/c/root");
            std::fs::create_dir_all(&root).unwrap();
            for dir in ["a", "a/b", "a/b/c"] {
                std::fs::write(base.path().join(dir).join("keep"), "k").unwrap();
            }
            let b = base.path().join("a/b");
            std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o711)).unwrap();
            extract(
                &root,
                &archive(&[entry, ("etc/hello", tar::EntryType::Regular, "", "hi")])[..],
            )
            .unwrap();
            for dir in ["a", "a/b", "a/b/c"] {
                assert!(
                    base.path().join(dir).join("keep").exists(),
                    "{}: {dir} removed",
                    entry.0
                );
            }
            let mode = std::fs::metadata(&b).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o711, "{}: mode of a/b changed", entry.0);
            assert_eq!(
                std::fs::read_to_string(root.join("etc/hello")).unwrap(),
                "hi"
            );
        }
        for rel in ["..", "a/..", "a/b/../..", "../../x/..", "./.."] {
            assert_eq!(
                secure_join_nofollow(Path::new("/r"), rel).unwrap(),
                Path::new("/r"),
                "{rel}"
            );
        }
        assert_eq!(
            secure_join_nofollow(Path::new("/r"), "a/../b").unwrap(),
            Path::new("/r/b")
        );
    }

    #[test]
    fn a_hard_link_is_resolved_when_it_is_made() {
        // Hard links are made after the other entries. One resolved when read kept its
        // path through `a`, which a later entry turned into a link out of the root.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), "keep").unwrap();
        extract(
            root.path(),
            &archive(&[
                ("bin/sh", tar::EntryType::Regular, "", "#!"),
                ("a/victim", tar::EntryType::Link, "bin/sh", ""),
                (
                    "a",
                    tar::EntryType::Symlink,
                    outside.path().to_str().unwrap(),
                    "",
                ),
            ])[..],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(outside.path().join("victim")).unwrap(),
            "keep"
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_hard_link_to_a_link_out_of_the_root_stays_in_it() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), "keep").unwrap();
        let out = outside.path().join("f");
        extract(
            root.path(),
            &archive(&[
                ("out", tar::EntryType::Symlink, out.to_str().unwrap(), ""),
                ("copy", tar::EntryType::Link, "out", ""),
            ])[..],
        )
        .unwrap();
        // The source resolves inside the root, where nothing is: no link to the host file.
        let host = std::fs::metadata(&out).unwrap();
        assert_eq!(std::os::unix::fs::MetadataExt::nlink(&host), 1);
    }

    #[test]
    fn preparing_a_root_never_follows_its_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        for d in ["etc", "tmp", ".briqyard"] {
            let o = outside.path().join(d);
            std::fs::create_dir(&o).unwrap();
            std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::os::unix::fs::symlink(&o, root.path().join(d)).unwrap();
        }
        let init = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(init.path(), "init").unwrap();
        prepare_root(root.path(), init.path()).unwrap();
        for d in ["etc", "tmp", ".briqyard"] {
            let o = outside.path().join(d);
            assert_eq!(
                std::fs::read_dir(&o).unwrap().count(),
                0,
                "{d}: written outside"
            );
            let mode = std::fs::metadata(&o).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o700, "{d}: mode outside changed");
            assert!(std::fs::symlink_metadata(root.path().join(d))
                .unwrap()
                .is_dir());
        }
        assert_eq!(
            std::fs::read_to_string(root.path().join(".briqyard/init")).unwrap(),
            "init"
        );
        for f in ["etc/hosts", "etc/resolv.conf", "etc/hostname"] {
            assert!(root.path().join(f).is_file(), "{f}");
        }
    }

    #[test]
    fn a_long_link_target_is_kept_whole() {
        let target = format!("/{}/target", "d".repeat(150));
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "ln", &target).unwrap();
        let tar = b.into_inner().unwrap();
        let root = tempfile::tempdir().unwrap();
        extract(root.path(), &tar[..]).unwrap();
        assert_eq!(
            std::fs::read_link(root.path().join("ln")).unwrap(),
            Path::new(&target)
        );
    }

    #[test]
    fn whiteouts_of_links_remove_the_link_only() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), "keep").unwrap();
        extract(
            root.path(),
            &archive(&[
                ("data/f", tar::EntryType::Regular, "", "x"),
                ("ln", tar::EntryType::Symlink, "data", ""),
                (
                    "out",
                    tar::EntryType::Symlink,
                    outside.path().to_str().unwrap(),
                    "",
                ),
            ])[..],
        )
        .unwrap();
        extract(
            root.path(),
            &archive(&[
                (".wh.ln", tar::EntryType::Regular, "", ""),
                ("out/.wh..wh..opq", tar::EntryType::Regular, "", ""),
            ])[..],
        )
        .unwrap();
        assert!(std::fs::symlink_metadata(root.path().join("ln")).is_err());
        assert!(root.path().join("data/f").exists());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("f")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn rewriting_a_symlink_does_not_follow_it() {
        let root = tempfile::tempdir().unwrap();
        // Layer 1: merged usr: bin -> usr/bin, busybox, lzcat -> /bin/busybox.
        extract(
            root.path(),
            &archive(&[
                ("usr/bin/busybox", tar::EntryType::Regular, "", "BB"),
                ("bin", tar::EntryType::Symlink, "usr/bin", ""),
                ("usr/bin/lzcat", tar::EntryType::Symlink, "/bin/busybox", ""),
            ])[..],
        )
        .unwrap();
        // Layer 2 rewrites the same link: busybox must survive.
        extract(
            root.path(),
            &archive(&[("usr/bin/lzcat", tar::EntryType::Symlink, "/bin/busybox", "")])[..],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("usr/bin/busybox")).unwrap(),
            "BB"
        );
        assert!(std::fs::symlink_metadata(root.path().join("usr/bin/lzcat"))
            .unwrap()
            .file_type()
            .is_symlink());
        // A regular file written over a symlink replaces the link, not its target.
        extract(
            root.path(),
            &archive(&[("usr/bin/lzcat", tar::EntryType::Regular, "", "real")])[..],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("usr/bin/lzcat")).unwrap(),
            "real"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("usr/bin/busybox")).unwrap(),
            "BB"
        );
    }

    #[test]
    fn whiteouts() {
        let root = tempfile::tempdir().unwrap();
        extract(
            root.path(),
            &archive(&[
                ("a/x", tar::EntryType::Regular, "", "1"),
                ("a/y", tar::EntryType::Regular, "", "2"),
                ("b", tar::EntryType::Regular, "", "3"),
            ])[..],
        )
        .unwrap();
        extract(
            root.path(),
            &archive(&[
                ("a/.wh.x", tar::EntryType::Regular, "", ""),
                (".wh.b", tar::EntryType::Regular, "", ""),
            ])[..],
        )
        .unwrap();
        assert!(!root.path().join("a/x").exists());
        assert!(root.path().join("a/y").exists());
        assert!(!root.path().join("b").exists());
        extract(
            root.path(),
            &archive(&[
                ("a/.wh..wh..opq", tar::EntryType::Regular, "", ""),
                ("a/z", tar::EntryType::Regular, "", "4"),
            ])[..],
        )
        .unwrap();
        assert!(!root.path().join("a/y").exists());
        assert!(root.path().join("a/z").exists());
    }

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

    /// A layer is applied from a file, whatever its compression: the build never holds one
    /// in memory.
    #[test]
    fn a_layer_is_applied_from_a_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let tar = archive(&[("etc/hello", tar::EntryType::Regular, "", "hi\n")]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(&tar[..], 1).unwrap();
        for (name, media_type, bytes) in [
            ("plain", oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE, &tar),
            ("gz", oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE, &gz),
            ("zst", "application/vnd.oci.image.layer.v1.tar+zstd", &zst),
        ] {
            let layer = dir.path().join(name);
            std::fs::write(&layer, bytes).unwrap();
            let root = dir.path().join(format!("root-{name}"));
            std::fs::create_dir(&root).unwrap();
            let file: std::fs::File = std::fs::File::open(&layer).unwrap();
            assert_eq!(apply_layer(&root, media_type, file).unwrap(), 1, "{name}");
            assert_eq!(
                std::fs::read_to_string(root.join("etc/hello")).unwrap(),
                "hi\n",
                "{name}"
            );
        }
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
