//! Pulling an image from its registry or a mirror and building its root disk.

use crate::events::Ev;
use crate::store::write_private;
use anyhow::{anyhow, Context, Result};
use briqyard_api::reason;
use chrono::{DateTime, Utc};
use oci_client::manifest::OciImageManifest;
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use super::builds::{take, Turn};
#[cfg(target_os = "linux")]
use super::extract::{apply_layer, prepare_root};
use super::{Builder, Image, ImageConfig, SNAP};

/// The daemon runs on Linux alone: elsewhere, a build fails at its first layer.
#[cfg(not(target_os = "linux"))]
fn apply_layer(_: &Path, _: &str, _: std::fs::File) -> Result<usize> {
    Err(anyhow!("image extraction needs Linux (openat2)"))
}

#[cfg(not(target_os = "linux"))]
fn prepare_root(_: &Path, _: &Path) -> Result<()> {
    Err(anyhow!("image extraction needs Linux (openat2)"))
}

/// The layer kinds the extractor reads: tar, plain or compressed with gzip or zstd.
const LAYER_MEDIA_TYPES: &[&str] = &[
    oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
    oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
    oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    "application/vnd.oci.image.layer.v1.tar+zstd",
];

/// What a reference last resolved to, kept on disk: when the registry refuses (a rate limit,
/// an outage), the image already on the host serves.
#[derive(Serialize, Deserialize)]
struct Resolution {
    reference: String,
    digest: String,
    at: DateTime<Utc>,
}

/// Where a pull's content comes from: the registry's mirror first when it has one, then the
/// registry. Both by the same digest, so either serves the same bytes or fails.
pub(super) struct Source {
    reference: Reference,
    auth: RegistryAuth,
    /// The mirror's host; None for the registry itself.
    pub(super) mirror: Option<String>,
}

impl Builder {
    /// Returns the built image for `reference`, pulling and building it when the host has not
    /// seen it. Concurrent calls for one image share a build.
    pub async fn ensure(&self, reference: &str) -> Result<Image> {
        self.ensure_noting(reference, || {}).await
    }

    /// `ensure`, calling `pulling` once when this call waits for a pull: its own, a turn for
    /// one, or another call's of the same image (a create's `pulling` event, ADR 0048).
    pub async fn ensure_noting(&self, reference: &str, pulling: impl Fn()) -> Result<Image> {
        let noted = std::sync::Once::new();
        let pulling = || noted.call_once(&pulling);
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
                    return self
                        .ensure_locked(&r, reference, &digest, &key, pulling)
                        .await;
                }
                Turn::Wait(mut rx) => {
                    pulling();
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
    pub(super) async fn resolve(
        &self,
        r: &Reference,
        reference: &str,
        auth: &RegistryAuth,
    ) -> Result<String> {
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
        pulling: impl Fn(),
    ) -> Result<Image> {
        if let Some(cached) = self.load(key) {
            if self.zfs.exists(&cached.dataset()).await? {
                return Ok(cached);
            }
        }
        pulling();
        // A turn among the pulls of other images; the creates of this one wait on its key.
        let _turn = self.pulls.acquire().await?;
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
    pub(super) fn sources(&self, r: &Reference, digest: &str) -> Vec<Source> {
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
    pub(super) async fn pull_manifest(
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
    pub(super) async fn pull_layer(
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
        let out = crate::host_process::command("mkfs.ext4")
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
pub(super) fn pulled(
    reference: &str,
    digest: &str,
    mirror: Option<&str>,
    took: std::time::Duration,
) -> Ev {
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
pub(super) fn check_layers(manifest: &OciImageManifest) -> Result<()> {
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

pub(super) fn parse_config(data: &[u8]) -> Result<ImageConfig> {
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
