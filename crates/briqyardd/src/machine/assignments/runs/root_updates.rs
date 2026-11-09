//! Root replacement under the existing assigned update journal.
use super::*;

impl Manager {
    pub(super) async fn ensure_assigned_root_update(&self, update: &UpdateIntent) -> Result<()> {
        if update.change.image.is_none() {
            anyhow::ensure!(
                update.resolved_image.is_none() && update.root_swap.is_none(),
                "image update authority exists without an image change"
            );
            return Ok(());
        }
        self.resolve_assigned_image_update(update).await?;
        let resolved: UpdateIntent = self
            .inner
            .store
            .get(UPDATES, &update.machine)?
            .context("resolved assigned image update missing")?;
        self.apply_assigned_root_update(resolved).await
    }

    pub(super) async fn apply_assigned_root_update(
        &self,
        mut resolved: UpdateIntent,
    ) -> Result<()> {
        let reference = resolved
            .change
            .image
            .as_deref()
            .context("assigned root update image missing")?;
        let current = self.check_update_source(&resolved)?;
        self.check_creation_update_backing(&resolved).await?;
        anyhow::ensure!(
            current
                .as_ref()
                .is_none_or(|current| current.reference.phase == Phase::Settled),
            "assigned image update requires a settled source"
        );

        let image = resolved
            .resolved_image
            .as_ref()
            .context("resolved assigned image missing")?;
        let mut swap = resolved
            .root_swap
            .clone()
            .context("resolved assigned root swap missing")?;
        self.check_update_source(&resolved)?;
        let base = image.dataset();
        anyhow::ensure!(
            image.r#ref == reference
                && self.inner.zfs.exists(&base).await?
                && self
                    .inner
                    .zfs
                    .snapshots(&base)
                    .await?
                    .iter()
                    .any(|snap| snap == crate::image::SNAP),
            "assigned image root snapshot is unavailable"
        );
        self.check_clone_readers(&resolved.machine, None)?;

        let zfs = &self.inner.zfs;
        let live = resolved.target.root_dataset();
        let next = format!("{live}.next");
        if swap.target_guid.is_none() {
            if zfs.exists(&next).await? {
                anyhow::ensure!(
                    zfs.origin(&next).await?.as_ref()
                        == Some(&(base.clone(), crate::image::SNAP.to_string())),
                    "assigned root .next belongs to another operation"
                );
                swap.target_guid = Some(zfs.guid(&next).await?);
            } else {
                anyhow::ensure!(
                    zfs.exists(&live).await? && zfs.guid(&live).await? == swap.source_guid,
                    "assigned root source changed before clone"
                );
                zfs.clone_snapshot(&base, crate::image::SNAP, &next).await?;
                anyhow::ensure!(
                    zfs.origin(&next).await?.as_ref()
                        == Some(&(base.clone(), crate::image::SNAP.to_string())),
                    "assigned root clone origin differs"
                );
                swap.target_guid = Some(zfs.guid(&next).await?);
            }
            resolved.root_swap = Some(swap.clone());
            self.check_update_source(&resolved)?;
            self.inner
                .store
                .put_durable(UPDATES, &resolved.machine, &resolved)?;
        }
        let target_guid = swap
            .target_guid
            .context("assigned root target GUID missing")?;
        anyhow::ensure!(
            target_guid != swap.source_guid,
            "assigned root clone reused source GUID"
        );

        let live_exists = zfs.exists(&live).await?;
        let next_exists = zfs.exists(&next).await?;
        let retired_exists = zfs.exists(&swap.retired_dataset).await?;
        let live_guid = if live_exists {
            Some(zfs.guid(&live).await?)
        } else {
            None
        };
        let next_guid = if next_exists {
            anyhow::ensure!(
                zfs.origin(&next).await?.as_ref()
                    == Some(&(base.clone(), crate::image::SNAP.to_string())),
                "assigned root .next origin differs"
            );
            Some(zfs.guid(&next).await?)
        } else {
            None
        };
        let retired_guid = if retired_exists {
            Some(zfs.guid(&swap.retired_dataset).await?)
        } else {
            None
        };
        if live_guid == Some(target_guid) {
            anyhow::ensure!(
                !next_exists
                    && retired_guid == Some(swap.source_guid)
                    && zfs.origin(&live).await?.as_ref()
                        == Some(&(base.clone(), crate::image::SNAP.to_string())),
                "installed assigned root conflicts with its durable update"
            );
            return Ok(());
        }
        anyhow::ensure!(
            next_guid == Some(target_guid),
            "assigned root target clone is missing or changed"
        );
        match live_guid {
            Some(guid) if guid == swap.source_guid => {
                anyhow::ensure!(
                    retired_guid.is_none(),
                    "assigned retired root conflicts with the live source"
                );
                zfs.rename(&live, &swap.retired_dataset).await?;
                anyhow::ensure!(
                    zfs.guid(&swap.retired_dataset).await? == swap.source_guid,
                    "assigned retired root identity differs after rename"
                );
            }
            None => anyhow::ensure!(
                retired_guid == Some(swap.source_guid),
                "assigned image update lost its source root"
            ),
            Some(_) => anyhow::bail!("assigned live root conflicts with update authority"),
        }
        anyhow::ensure!(
            !zfs.exists(&live).await?,
            "assigned root destination is unexpectedly occupied"
        );
        zfs.rename(&next, &live).await?;
        anyhow::ensure!(
            zfs.guid(&live).await? == target_guid
                && zfs.origin(&live).await?.as_ref()
                    == Some(&(base, crate::image::SNAP.to_string())),
            "assigned root installation differs from durable target"
        );
        Ok(())
    }

    async fn resolve_assigned_image_update(&self, update: &UpdateIntent) -> Result<()> {
        let Some(reference) = update.change.image.as_deref() else {
            anyhow::ensure!(
                update.resolved_image.is_none() && update.root_swap.is_none(),
                "image update authority exists without an image change"
            );
            return Ok(());
        };
        if update.resolved_image.is_some() {
            self.check_update_source(update)?;
            return Ok(());
        }
        let current = self.check_update_source(update)?;
        self.check_creation_update_backing(update).await?;
        anyhow::ensure!(
            current
                .as_ref()
                .is_none_or(|current| current.reference.phase == Phase::Settled),
            "assigned image update requires a settled source"
        );
        let image = self.inner.images.ensure(reference).await?;
        let source_guid = self.inner.zfs.guid(&update.target.root_dataset()).await?;
        anyhow::ensure!(
            source_guid
                == current.as_ref().map_or_else(
                    || update.creation_authority().unwrap().root.guid,
                    |current| current.root.guid
                ),
            "assigned image update source root differs from settled backing"
        );
        let suffix =
            sha(format!("{}:{}:{}", update.source_digest()?, image.key, source_guid).as_bytes());
        let mut resolved = update.clone();
        resolved.resolved_image = Some(image);
        resolved.root_swap = Some(RootSwap {
            source_guid,
            target_guid: None,
            retired_dataset: format!(
                "{}/root.u_{}",
                update.source_record.dataset(),
                &suffix[..24]
            ),
        });
        self.check_update_source(&resolved)?;
        self.inner
            .store
            .put_durable(UPDATES, &resolved.machine, &resolved)?;
        Ok(())
    }
}
