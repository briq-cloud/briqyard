//! Listing and removing the images a host has built.

#[cfg(test)]
use super::ImageConfig;
use super::{Builder, Image, SNAP};
use crate::events::Ev;
#[cfg(test)]
use crate::store::write_private;
#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
use briqyard_api::reason;
use chrono::Utc;
#[cfg(test)]
use oci_client::Reference;
use std::collections::HashSet;

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
pub(super) fn removed(im: &Image, how: Removal) -> Ev {
    Ev::normal(
        reason::IMAGE_REMOVED,
        format!("removed {}: {}", im.r#ref, how.why()),
    )
    .data(serde_json::json!({
        "image": im.r#ref, "digest": im.digest, "key": im.key, "reason": how.reason(),
    }))
}

#[cfg(test)]
impl Builder {
    /// An image as if built, for tests of what clones one: its record, its dataset and the
    /// snapshot machines clone. `reference` pins a digest, so `ensure` asks no registry.
    pub(crate) async fn seed(&self, reference: &str, config: ImageConfig) -> Result<Image> {
        self.seed_with_config_digest(reference, config, "").await
    }

    pub(crate) async fn seed_with_config_digest(
        &self,
        reference: &str,
        config: ImageConfig,
        config_digest: &str,
    ) -> Result<Image> {
        let r: Reference = reference.parse()?;
        let digest = r.digest().context("the reference pins no digest")?;
        let image = Image {
            r#ref: reference.to_string(),
            digest: digest.to_string(),
            config_digest: config_digest.into(),
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
