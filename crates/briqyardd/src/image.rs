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
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::{ImageIndexEntry, OciImageManifest, Platform};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

#[cfg(target_os = "linux")]
pub mod extract;
#[cfg(target_os = "linux")]
use extract::{apply_layer, prepare_root};

/// The daemon runs on Linux alone: elsewhere, a build fails at its first layer.
#[cfg(not(target_os = "linux"))]
fn apply_layer(_: &Path, _: &str, _: std::fs::File) -> Result<usize> {
    Err(anyhow!("image extraction needs Linux (openat2)"))
}

#[cfg(not(target_os = "linux"))]
fn prepare_root(_: &Path, _: &Path) -> Result<()> {
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

/// A registry's pull-through mirror (ADR 0036): the registry it stands in for (`docker.io`,
/// as a reference names it) and its address as a registry name (`10.0.0.2:7440`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mirror {
    pub registry: String,
    pub host: String,
    pub plain_http: bool,
}

impl Mirror {
    /// `registry_mirrors` entry: `docker.io: http://10.0.0.2:7440`. A mirror is a registry
    /// of its own at the root of its address, so the URL has no path.
    pub fn parse(registry: &str, url: &str) -> Result<Mirror> {
        if registry.is_empty() || registry.contains(['/', ' ']) {
            return Err(anyhow!(
                "{registry:?} is not a registry name (docker.io, ghcr.io)"
            ));
        }
        let (plain_http, rest) = match (url.strip_prefix("http://"), url.strip_prefix("https://")) {
            (Some(rest), _) => (true, rest),
            (_, Some(rest)) => (false, rest),
            _ => return Err(anyhow!("{url:?}: want http:// or https://")),
        };
        let host = rest.trim_end_matches('/');
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err(anyhow!(
                "{url:?}: a mirror is a host and a port, with no path"
            ));
        }
        Ok(Mirror {
            registry: registry.to_string(),
            host: host.to_string(),
            plain_http,
        })
    }
}

/// How long a registry or a mirror may stay silent on a connection (each read, so a slow blob
/// is not cut). Above Zot's `syncTimeout` (10 minutes, `hack/mirror/zot.json`): a mirror's first
/// pull of an image copies it before answering. A mirror silent past it is left for the registry.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The registry client: HTTPS except to the `plain` hosts; a connect that does not complete
/// within 10 s, or a connection silent for `read_timeout`, fails that source.
fn client_config(plain: Vec<String>, read_timeout: std::time::Duration) -> ClientConfig {
    ClientConfig {
        platform_resolver: Some(Box::new(host_platform)),
        protocol: if plain.is_empty() {
            ClientProtocol::Https
        } else {
            ClientProtocol::HttpsExcept(plain)
        },
        connect_timeout: Some(std::time::Duration::from_secs(10)),
        read_timeout: Some(read_timeout),
        ..Default::default()
    }
}

/// Where a pull's content comes from: the registry's mirror first when it has one, then the
/// registry. Both by the same digest, so either serves the same bytes or fails.
struct Source {
    reference: Reference,
    auth: RegistryAuth,
    /// The mirror's host; None for the registry itself.
    mirror: Option<String>,
}

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
    /// A tag is asked of the registry itself, never of a mirror (ADR 0036), with a `HEAD`,
    /// which Docker Hub does not count as a pull: the digest is the one the registry names
    /// (an index's for a multi-platform image), and everything pulled after is checked by it.
    async fn resolve(&self, r: &Reference, reference: &str, auth: &RegistryAuth) -> Result<String> {
        if let Some(d) = r.digest() {
            return Ok(d.to_string());
        }
        if let Some((d, at)) = self.resolved.lock().unwrap().get(reference) {
            if at.elapsed() < self.resolve_ttl {
                return Ok(d.clone());
            }
        }
        match self.client.fetch_manifest_digest(r, auth).await {
            Ok(digest) => {
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
        let mut sources = self.sources(r, digest);
        let (manifest, config) = self
            .pull_manifest(&mut sources, reference)
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
        if let Err(e) = self.build(&mut sources, &manifest, &image).await {
            let _ = self.zfs.destroy(&image.dataset()).await;
            let _ = std::fs::remove_dir_all(self.dir.join(format!("extract-{}", image.key)));
            return Err(e);
        }
        write_private(&self.meta_path(key), &serde_json::to_vec_pretty(&image)?)?;
        if let Some(ev) = &self.events {
            let from = sources[0].mirror.as_deref();
            ev.emit(pulled(reference, digest, from, started.elapsed()));
        }
        Ok(image)
    }

    /// Where `digest` of `r` is pulled from: its registry's mirror, then the registry. The
    /// daemon sends a mirror no credentials: a mirror of a private registry holds its own.
    fn sources(&self, r: &Reference, digest: &str) -> Vec<Source> {
        let mut out = Vec::with_capacity(2);
        if let Some(m) = self.mirrors.iter().find(|m| m.registry == r.registry()) {
            out.push(Source {
                reference: Reference::with_digest(
                    m.host.clone(),
                    r.repository().to_string(),
                    digest.to_string(),
                ),
                auth: RegistryAuth::Anonymous,
                mirror: Some(m.host.clone()),
            });
        }
        out.push(Source {
            reference: r.clone_with_digest(digest.to_string()),
            auth: self.auth_for(r),
            mirror: None,
        });
        out
    }

    /// The image's manifest and config, from the first source that serves them.
    async fn pull_manifest(
        &self,
        sources: &mut Vec<Source>,
        reference: &str,
    ) -> Result<(OciImageManifest, String)> {
        loop {
            let s = &sources[0];
            match self
                .client
                .pull_manifest_and_config(&s.reference, &s.auth)
                .await
            {
                Ok((manifest, _, config)) => return Ok((manifest, config)),
                Err(err) => fall_back(sources, reference, "manifest", err)?,
            }
        }
    }

    /// One layer into `path`, from the first source that serves it.
    async fn pull_layer(
        &self,
        sources: &mut Vec<Source>,
        reference: &str,
        layer: &oci_client::manifest::OciDescriptor,
        path: &Path,
    ) -> Result<()> {
        loop {
            let s = &sources[0];
            let mut out = tokio::fs::File::create(path).await?;
            match self.client.pull_blob(&s.reference, layer, &mut out).await {
                Ok(()) => return Ok(out.flush().await?),
                Err(err) => fall_back(sources, reference, &layer.digest, err)
                    .with_context(|| format!("pull layer {}", layer.digest))?,
            }
        }
    }

    async fn build(
        &self,
        sources: &mut Vec<Source>,
        manifest: &OciImageManifest,
        image: &Image,
    ) -> Result<()> {
        let scratch = self.dir.join(format!("extract-{}", image.key));
        let _ = std::fs::remove_dir_all(&scratch);
        let root = scratch.join("root");
        std::fs::create_dir_all(&root)?;
        // One layer at a time, in manifest order: streamed to a file, applied from it. The
        // daemon's memory during a build is the decompressor's buffer, whatever the image.
        let layer_file = scratch.join("layer");
        let mut files = 0;
        for layer in &manifest.layers {
            self.pull_layer(sources, &image.r#ref, layer, &layer_file)
                .await?;
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

/// A source failed (the mirror is down, refused, or served bytes that are not the digest):
/// it is dropped for the rest of the pull and the next one serves. The last one's failure is
/// the pull's.
fn fall_back(
    sources: &mut Vec<Source>,
    reference: &str,
    what: &str,
    err: oci_client::errors::OciDistributionError,
) -> Result<()> {
    if sources.len() == 1 {
        return Err(anyhow!(err));
    }
    let s = sources.remove(0);
    tracing::warn!(
        image = reference,
        mirror = s.mirror.as_deref().unwrap_or(""),
        what,
        err = %err,
        "mirror failed; pulling from the registry"
    );
    Ok(())
}

/// The event of a pull and build: which image, which digest, where its content came from
/// (`from`: the mirror's host, or `registry`), how long it took.
fn pulled(reference: &str, digest: &str, mirror: Option<&str>, took: std::time::Duration) -> Ev {
    let secs = (took.as_secs_f64() * 10.0).round() / 10.0;
    let from = mirror.unwrap_or("registry");
    let via = mirror.map(|m| format!(" through {m}")).unwrap_or_default();
    Ev::normal(
        reason::IMAGE_PULLED,
        format!("pulled {reference} in {secs} s{via}"),
    )
    .data(serde_json::json!({"image": reference, "digest": digest, "from": from, "seconds": secs}))
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
    fn a_pull_is_an_event_with_its_digest_source_and_time() {
        let dir = tempfile::tempdir().unwrap();
        let log = Events::open(dir.path()).unwrap();
        log.emit(pulled(
            "alpine:3.20",
            "sha256:abc",
            Some("10.0.0.2:7440"),
            std::time::Duration::from_millis(1000),
        ));
        log.emit(pulled(
            "alpine:3.20",
            "sha256:abc",
            None,
            std::time::Duration::from_millis(4240),
        ));
        let mut evs = log.read(0, &Default::default(), 2).unwrap().events;
        assert_eq!(
            evs[0].message,
            "pulled alpine:3.20 in 1 s through 10.0.0.2:7440"
        );
        assert_eq!(evs[0].data.as_ref().unwrap()["from"], "10.0.0.2:7440");
        let e = evs.remove(1);
        assert_eq!(
            (e.reason.as_str(), e.message.as_str()),
            ("image_pulled", "pulled alpine:3.20 in 4.2 s")
        );
        assert_eq!(
            e.data,
            Some(
                serde_json::json!({"image": "alpine:3.20", "digest": "sha256:abc", "from": "registry", "seconds": 4.2})
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

    /// A registry on loopback serving manifests by tag or digest and blobs by digest, and
    /// logging each request as `METHOD manifests/<ref>` or `GET blobs/<digest>`.
    #[derive(Default)]
    struct FakeRegistry {
        manifests: HashMap<String, (Vec<u8>, String)>,
        blobs: HashMap<String, Vec<u8>>,
        log: Mutex<Vec<String>>,
    }

    fn sha(b: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(b)))
    }

    impl FakeRegistry {
        /// An image of one config and one layer, under `tag` and its digest. Its digest.
        fn add(&mut self, tag: &str, layer: &[u8]) -> String {
            let config = br#"{"config":{"Cmd":["sh"]}}"#.to_vec();
            let manifest = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
                "config": {"mediaType": oci_client::manifest::IMAGE_CONFIG_MEDIA_TYPE,
                           "digest": sha(&config), "size": config.len()},
                "layers": [{"mediaType": oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
                            "digest": sha(layer), "size": layer.len()}],
            }))
            .unwrap();
            let digest = sha(&manifest);
            self.blobs.insert(sha(&config), config);
            self.blobs.insert(sha(layer), layer.to_vec());
            self.manifests
                .insert(tag.into(), (manifest.clone(), digest.clone()));
            self.manifests
                .insert(digest.clone(), (manifest, digest.clone()));
            digest
        }

        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        /// Serves on a loopback port: its `host:port`.
        async fn serve(self) -> (String, std::sync::Arc<FakeRegistry>) {
            use axum::http::{header, Method, StatusCode, Uri};
            use axum::response::IntoResponse;
            let me = std::sync::Arc::new(self);
            let state = me.clone();
            let app = axum::Router::new().fallback(move |method: Method, uri: Uri| {
                let f = state.clone();
                async move {
                    let path = uri.path().to_string();
                    if path == "/v2/" {
                        return StatusCode::OK.into_response();
                    }
                    let (kind, name) =
                        match (path.rsplit_once("/manifests/"), path.rsplit_once("/blobs/")) {
                            (Some((_, r)), _) => ("manifests", r.to_string()),
                            (_, Some((_, d))) => ("blobs", d.to_string()),
                            _ => return StatusCode::NOT_FOUND.into_response(),
                        };
                    f.log
                        .lock()
                        .unwrap()
                        .push(format!("{method} {kind}/{name}"));
                    let found = match kind {
                        "manifests" => f.manifests.get(&name).map(|(b, d)| {
                            (
                                oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
                                b.clone(),
                                d.clone(),
                            )
                        }),
                        _ => f
                            .blobs
                            .get(&name)
                            .map(|b| ("application/octet-stream", b.clone(), name.clone())),
                    };
                    match found {
                        Some((media_type, body, digest)) => (
                            [
                                (header::CONTENT_TYPE, media_type.to_string()),
                                (
                                    header::HeaderName::from_static("docker-content-digest"),
                                    digest,
                                ),
                            ],
                            body,
                        )
                            .into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            });
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let host = l.local_addr().unwrap().to_string();
            tokio::spawn(async move { axum::serve(l, app).await });
            (host, me)
        }
    }

    /// A builder whose registries are `origin` (the image's) and its mirror at `mirror`, both
    /// plain HTTP on loopback.
    async fn builder(dir: &Path, origin: &str, mirror: &str) -> Builder {
        let fake = crate::zfs::fake::Fake::open("byard").await.unwrap();
        let init = dir.join("init");
        std::fs::write(&init, b"init").unwrap();
        let mirror = Mirror::parse(origin, &format!("http://{mirror}")).unwrap();
        let mut b = Builder::new(
            fake.zfs.clone(),
            dir.join("images"),
            init,
            8,
            vec![mirror.clone()],
        )
        .unwrap();
        let plain = vec![origin.to_string(), mirror.host.clone()];
        b.client = Client::new(client_config(plain, std::time::Duration::from_secs(1)));
        b
    }

    /// Resolves `reference` and pulls its manifest and layer as a build does: the layer's
    /// bytes, and which mirror served (None: the registry).
    async fn pull(
        b: &Builder,
        reference: &str,
        dir: &Path,
    ) -> Result<(String, Vec<u8>, Option<String>)> {
        let r: Reference = reference.parse()?;
        let digest = b.resolve(&r, reference, &RegistryAuth::Anonymous).await?;
        let mut sources = b.sources(&r, &digest);
        let (manifest, _) = b.pull_manifest(&mut sources, reference).await?;
        let file = dir.join("layer");
        b.pull_layer(&mut sources, reference, &manifest.layers[0], &file)
            .await?;
        let from = sources[0].mirror.clone();
        Ok((digest, std::fs::read(&file)?, from))
    }

    /// ADR 0036: a tag is asked of the registry alone, by a HEAD, and the content by its
    /// digest of the mirror; the mirror's own idea of the tag is never asked.
    #[tokio::test]
    async fn a_tag_is_resolved_by_the_registry_and_the_content_pulled_from_the_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let mut origin = FakeRegistry::default();
        let want = origin.add("1", b"the layer");
        let mut mirror = FakeRegistry::default();
        assert_eq!(mirror.add("1", b"the layer"), want);
        // The mirror says the tag is another image: it must not matter.
        mirror.add("1", b"another layer");
        let (origin_host, origin) = origin.serve().await;
        let (mirror_host, mirror) = mirror.serve().await;
        let b = builder(dir.path(), &origin_host, &mirror_host).await;
        let (digest, layer, from) = pull(&b, &format!("{origin_host}/app:1"), dir.path())
            .await
            .unwrap();
        assert_eq!(digest, want);
        assert_eq!(layer, b"the layer");
        assert_eq!(from.as_deref(), Some(mirror_host.as_str()));
        assert_eq!(origin.requests(), ["HEAD manifests/1"]);
        let asked = mirror.requests();
        assert!(asked.iter().all(|r| !r.ends_with("/1")), "{asked:?}");
        assert_eq!(asked[0], format!("GET manifests/{want}"));
        assert_eq!(asked.len(), 3, "manifest, config, layer: {asked:?}");
    }

    /// A mirror that is down, silent, does not have the image, or serves other bytes for the
    /// digest is left for the registry, which serves the rest of the pull.
    #[tokio::test]
    async fn a_mirror_that_fails_or_lies_leaves_the_pull_to_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let mut origin = FakeRegistry::default();
        let want = origin.add("1", b"the layer");
        let (origin_host, origin) = origin.serve().await;
        let reference = format!("{origin_host}/app:1");

        // Down: nothing listens there.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let down = closed.local_addr().unwrap().to_string();
        drop(closed);
        // Empty: it has nothing.
        let (empty, _) = FakeRegistry::default().serve().await;
        // A lying layer: the manifest is right, the layer's bytes are not its digest.
        let mut liar = FakeRegistry::default();
        liar.add("1", b"the layer");
        let layer_digest = sha(b"the layer");
        liar.blobs
            .insert(layer_digest.clone(), b"evil layer".to_vec());
        let (lying_layer, liar) = liar.serve().await;
        // A lying manifest: other bytes under the image's digest.
        let mut forger = FakeRegistry::default();
        let other = forger.add("x", b"evil layer");
        let forged = forger.manifests[&other].clone();
        forger.manifests.insert(want.clone(), forged);
        let (lying_manifest, _) = forger.serve().await;

        // Silent: it takes the connection and never answers (bounded by the read timeout, 1 s
        // in these tests).
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let quiet = silent.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = silent.accept().await {
                held.push(s);
            }
        });

        for mirror in [down, empty, lying_layer, lying_manifest, quiet] {
            let b = builder(dir.path(), &origin_host, &mirror).await;
            let (digest, layer, from) = pull(&b, &reference, dir.path()).await.unwrap();
            assert_eq!(
                (digest.as_str(), layer.as_slice(), from),
                (want.as_str(), &b"the layer"[..], None),
                "mirror {mirror}"
            );
        }
        // The liar served the manifest and config; only the layer came from the registry.
        assert_eq!(liar.requests().len(), 3);
        assert!(origin
            .requests()
            .contains(&format!("GET blobs/{layer_digest}")));

        // With the registry gone too, the pull fails with the registry's error.
        let b = builder(dir.path(), "127.0.0.1:9", "127.0.0.1:9").await;
        let err = pull(&b, &format!("127.0.0.1:9/app@{want}"), dir.path())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("127.0.0.1:9"), "{err:#}");
    }
}
