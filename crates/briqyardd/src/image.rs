//! Turns an OCI image into a root disk, once per image, and remembers its config.
//!
//! The layers are applied in order to a scratch directory the host controls, every path
//! resolved inside it (a symlink in a layer never leads outside), whiteouts honoured, devices
//! skipped; `briqyard-init` is added; then `mkfs.ext4 -d` builds the disk without mounting
//! anything. The host never mounts a guest filesystem.

use crate::zfs::Zfs;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use oci_client::client::{ClientConfig, ImageData};
use oci_client::manifest::{ImageIndexEntry, Platform};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

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
    init_hash: String,
    building: Mutex<HashMap<String, Arc<Notify>>>,
    /// What a reference resolved to, and when: a tag is asked of the registry once per
    /// `resolve_ttl`, a digest never.
    resolved: Mutex<HashMap<String, (String, std::time::Instant)>>,
    pub resolve_ttl: std::time::Duration,
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
        std::fs::create_dir_all(dir.join("meta"))?;
        Ok(Self {
            zfs,
            dir,
            init,
            root_gb,
            registries: vec![],
            init_hash,
            building: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            resolve_ttl: std::time::Duration::from_secs(600),
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
        let client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(host_platform)),
            ..Default::default()
        });
        let auth = self.auth_for(&r);
        let digest = self.resolve(&client, &r, reference, &auth).await?;
        let key = self.key(&digest);

        // One build at a time per key.
        let waiter = {
            let mut b = self.building.lock().unwrap();
            match b.get(&key) {
                Some(n) => Some(n.clone()),
                None => {
                    b.insert(key.clone(), Arc::new(Notify::new()));
                    None
                }
            }
        };
        if let Some(n) = waiter {
            n.notified().await;
            return self
                .load(&key)
                .ok_or_else(|| anyhow!("image build of {reference} failed"));
        }
        let result = self
            .ensure_locked(&client, &r, reference, &digest, &key)
            .await;
        let n = self.building.lock().unwrap().remove(&key);
        if let Some(n) = n {
            n.notify_waiters();
        }
        result
    }

    fn resolution_path(&self, reference: &str) -> PathBuf {
        let h = hex::encode(Sha256::digest(reference.as_bytes()));
        self.dir.join("meta").join(format!("ref-{}.json", &h[..20]))
    }

    /// The digest a reference names: pinned in the reference, remembered from a recent answer,
    /// asked of the registry, or, when the registry refuses, the one the host already built.
    async fn resolve(
        &self,
        client: &Client,
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
        match client.pull_image_manifest(r, auth).await {
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
                let _ = std::fs::write(
                    self.resolution_path(reference),
                    serde_json::to_vec(&rec).unwrap_or_default(),
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
        client: &Client,
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
        let accepted = vec![
            oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
            oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
            "application/vnd.oci.image.layer.v1.tar+zstd",
        ];
        let data = client
            .pull(r, &self.auth_for(r), accepted)
            .await
            .with_context(|| format!("pull {reference}"))?;
        let config = parse_config(&data.config.data)?;
        let image = Image {
            r#ref: reference.to_string(),
            digest: digest.to_string(),
            key: key.to_string(),
            config,
            size_gb: self.root_gb,
            built_at: Utc::now(),
        };
        if let Err(e) = self.build(&data, &image).await {
            let _ = self.zfs.destroy(&image.dataset()).await;
            let _ = std::fs::remove_dir_all(self.dir.join(format!("extract-{}", image.key)));
            return Err(e);
        }
        std::fs::write(self.meta_path(key), serde_json::to_vec_pretty(&image)?)?;
        Ok(image)
    }

    async fn build(&self, data: &ImageData, image: &Image) -> Result<()> {
        let scratch = self.dir.join(format!("extract-{}", image.key));
        let _ = std::fs::remove_dir_all(&scratch);
        let root = scratch.join("root");
        std::fs::create_dir_all(&root)?;
        // The client fetches layers concurrently and hands them back in completion order; an
        // image is its layers applied in manifest order, so put them back in it.
        let layers = ordered_layers(data);
        let root2 = root.clone();
        let init = self.init.clone();
        let files = tokio::task::spawn_blocking(move || -> Result<usize> {
            let mut n = 0;
            for (media_type, bytes) in &layers {
                n += apply_layer(&root2, media_type, bytes)?;
            }
            prepare_root(&root2, &init)?;
            Ok(n)
        })
        .await??;
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

/// The layers in manifest order, as (media type, bytes).
fn ordered_layers(data: &ImageData) -> Vec<(String, Vec<u8>)> {
    let mut layers: Vec<(String, Vec<u8>)> = data
        .layers
        .iter()
        .map(|l| (l.media_type.clone(), l.data.clone()))
        .collect();
    if let Some(manifest) = &data.manifest {
        let digests: Vec<String> = data.layers.iter().map(|l| l.sha256_digest()).collect();
        let mut ordered = Vec::with_capacity(layers.len());
        for want in &manifest.layers {
            if let Some(i) = digests.iter().position(|d| *d == want.digest) {
                ordered.push(layers[i].clone());
            }
        }
        if ordered.len() == layers.len() {
            layers = ordered;
        }
    }
    layers
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

    /// Removes an image nobody clones. `Ok(false)`: machines still use it.
    pub async fn remove(&self, key: &str) -> Result<bool> {
        let ds = format!("images/{key}");
        if self.zfs.exists(&ds).await? && !self.zfs.clones(&ds, SNAP).await?.is_empty() {
            return Ok(false);
        }
        self.zfs.destroy(&ds).await?;
        let _ = std::fs::remove_file(self.meta_path(key));
        Ok(true)
    }

    /// Removes images no machine clones that were built more than `keep` ago.
    pub async fn gc(&self, keep: chrono::Duration) -> Result<usize> {
        let mut removed = 0;
        for (im, clones) in self.list().await? {
            if clones == 0 && Utc::now() - im.built_at > keep && self.remove(&im.key).await? {
                tracing::info!(image = im.r#ref, key = im.key, "image removed: unused");
                removed += 1;
            }
        }
        Ok(removed)
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

/// Applies one layer: whiteouts remove, everything else is extracted inside `root`.
pub fn apply_layer(root: &Path, media_type: &str, bytes: &[u8]) -> Result<usize> {
    let reader: Box<dyn Read> = if media_type.ends_with("gzip") {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else if media_type.ends_with("zstd") {
        Box::new(zstd::Decoder::new(bytes)?)
    } else {
        Box::new(bytes)
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
/// clobber busybox itself).
pub fn secure_join_nofollow(root: &Path, rel: &str) -> Result<PathBuf> {
    let rel = rel.trim_end_matches('/');
    match rel.rsplit_once('/') {
        Some((parent, base)) if !base.is_empty() && base != ".." => {
            Ok(secure_join(root, parent)?.join(base))
        }
        _ => {
            if rel == ".." || rel.is_empty() {
                return Ok(root.to_path_buf());
            }
            Ok(root.join(rel))
        }
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
    let mut hardlinks: Vec<(PathBuf, String)> = Vec::new();
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
            remove_any(&target);
            continue;
        }
        let dest = secure_join_nofollow(root, clean)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
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
                let target = header
                    .link_name()?
                    .map(|p| p.to_path_buf())
                    .unwrap_or_default();
                // Kept as is: the guest resolves it inside its own root.
                std::os::unix::fs::symlink(&target, &dest)?;
                let _ = std::os::unix::fs::lchown(&dest, Some(uid), Some(gid));
            }
            tar::EntryType::Link => {
                let target = header
                    .link_name()?
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                hardlinks.push((dest, target.trim_start_matches('/').to_string()));
                continue;
            }
            _ => continue,
        }
        n += 1;
    }
    for (dest, target) in hardlinks {
        let src = secure_join(root, &target)?;
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

/// Adds what every guest needs: the init, mount points, writable name files.
pub fn prepare_root(root: &Path, init: &Path) -> Result<()> {
    for d in ["proc", "sys", "dev", "run", "tmp", "etc", ".briqyard"] {
        std::fs::create_dir_all(root.join(d))?;
    }
    let _ = std::fs::set_permissions(root.join("tmp"), std::fs::Permissions::from_mode(0o1777));
    let dest = root.join(INIT_PATH.trim_start_matches('/'));
    std::fs::copy(init, &dest).context("copy init")?;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    // The init rewrites these at boot; a symlink (Debian's resolv.conf) or a missing file
    // would make that write land elsewhere or fail.
    for f in ["etc/hosts", "etc/resolv.conf", "etc/hostname"] {
        let p = root.join(f);
        if let Ok(m) = std::fs::symlink_metadata(&p) {
            if m.file_type().is_symlink() {
                let _ = std::fs::remove_file(&p);
            }
        }
        if std::fs::symlink_metadata(&p).is_err() {
            std::fs::write(&p, b"")?;
        }
    }
    Ok(())
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
    fn config_parsing() {
        let c = parse_config(br#"{"config":{"Entrypoint":["docker-entrypoint.sh"],"Cmd":["postgres"],"Env":["PATH=/usr/bin","PGDATA=/var/lib/postgresql/data"],"WorkingDir":"","User":"","Volumes":{"/var/lib/postgresql/data":{}},"ExposedPorts":{"5432/tcp":{}}}}"#).unwrap();
        assert_eq!(c.entrypoint, vec!["docker-entrypoint.sh"]);
        assert_eq!(c.env["PGDATA"], "/var/lib/postgresql/data");
        assert_eq!(c.volumes, vec!["/var/lib/postgresql/data"]);
        assert_eq!(c.exposed_ports, vec![5432]);
    }
}
