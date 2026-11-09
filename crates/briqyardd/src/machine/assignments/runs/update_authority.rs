//! Source authority for a stopped update before the first continuation exists.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreationSource {
    pub receipt: Receipt,
    pub reader: templates::CloneReader,
    pub root: Disk,
    pub data: Option<Disk>,
}

impl UpdateIntent {
    pub(super) fn source_digest(&self) -> Result<String> {
        match (&self.source_current_sha256, &self.creation_source) {
            (Some(hash), None) if self.schema == 1 => Ok(hash.clone()),
            (None, Some(creation)) if self.schema == 2 => {
                let bytes = serde_json::to_vec(&(creation, &self.source_record))?;
                Ok(sha(
                    &[b"assigned-update-creation-v2\0".as_slice(), &bytes].concat()
                ))
            }
            _ => anyhow::bail!("mixed or unknown assigned update source authority"),
        }
    }

    pub(super) fn check_source_shape(&self) -> Result<()> {
        match (&self.source_current_sha256, &self.creation_source) {
            (Some(hash), None) if self.schema == 1 && hex_id(hash, 64) => Ok(()),
            (None, Some(creation)) if self.schema == 2 => {
                let source = &self.source_record;
                let origin = source
                    .clone_origin
                    .as_ref()
                    .context("creation update origin missing")?;
                let binding = origin
                    .sandbox
                    .as_ref()
                    .context("creation update binding missing")?;
                creation.receipt.check()?;
                let incarnation = source
                    .boot_incarnation
                    .as_ref()
                    .context("creation update original incarnation missing")?;
                anyhow::ensure!(
                    incarnation.pid > 0
                        && incarnation.start_ticks > 0
                        && fc::valid_host_boot_id(&incarnation.host_boot_id)
                        && origin.launch_host_boot_id.as_deref()
                            == Some(incarnation.host_boot_id.as_str())
                        && source.boot_identity.as_ref() == Some(&origin.artifact.boot_identity),
                    "creation update original process ownership differs"
                );
                anyhow::ensure!(
                    source.assigned_run.is_none()
                        && source.pending.is_none()
                        && source.state == state::STOPPED
                        && source.pid == 0
                        && source.restoring.is_none()
                        && source.launch_identity.is_some()
                        && origin.stage == templates::CloneStage::Active
                        && origin.mapping_exited
                        && creation.receipt.machine == source.id
                        && creation.receipt.namespace == source.namespace
                        && creation.receipt.request_id == binding.request_id
                        && creation.receipt.create_sha256 == binding.create_sha256
                        && creation.root.dataset == source.root_dataset()
                        && creation.root.guid > 0
                        && match (&source.volume, &creation.data) {
                            (Some(_), Some(data)) =>
                                data.dataset == source.data_dataset()
                                    && data.guid > 0
                                    && data.guid != creation.root.guid,
                            (None, None) => true,
                            _ => false,
                        },
                    "creation update lacks exact stopped assignment or backing authority"
                );
                launch_identity::check_launch_pair(source, Some(&creation.reader))?;
                Manager::check_assigned_binding(source, origin)?;
                if let Some(swap) = &self.root_swap {
                    anyhow::ensure!(
                        swap.source_guid == creation.root.guid,
                        "creation update root source differs"
                    );
                }
                Ok(())
            }
            _ => anyhow::bail!("mixed or unknown assigned update source authority"),
        }
    }
}

impl Manager {
    pub(in crate::machine) fn creation_update_machines(
        &self,
    ) -> Result<std::collections::HashSet<String>> {
        Ok(self
            .inner
            .store
            .list::<UpdateIntent>(UPDATES)?
            .into_iter()
            .filter(|update| update.creation_source.is_some())
            .map(|update| update.machine)
            .collect())
    }

    /// Uses durable evidence only: recovery runs before launch-hold caches are loaded.
    pub(super) fn check_creation_update_authority(&self, update: &UpdateIntent) -> Result<()> {
        update.check_shape()?;
        let creation = update
            .creation_source
            .as_ref()
            .context("creation source missing")?;
        let source = &update.source_record;
        let origin = self.settled_assigned_origin_durable(source)?;
        Self::check_assigned_binding(source, &origin)?;
        anyhow::ensure!(
            origin.artifact.source_host == self.inner.host_id,
            "creation update belongs to another intrinsic host"
        );
        let receipt: Receipt = self
            .inner
            .store
            .get(super::super::REQUESTS, &creation.receipt.key())?
            .context("creation update permanent receipt missing")?;
        let reader: templates::CloneReader = self
            .inner
            .store
            .get(templates::READERS, &source.id)?
            .context("creation update reader missing")?;
        anyhow::ensure!(
            receipt == creation.receipt && reader == creation.reader,
            "creation update durable receipt or reader differs"
        );
        Ok(())
    }

    pub(super) fn check_update_source(&self, update: &UpdateIntent) -> Result<Option<Current>> {
        let current = self.inner.store.get::<Current>(RUNS, &update.machine)?;
        if update.creation_source.is_some() {
            anyhow::ensure!(
                current.is_none(),
                "creation update cannot replace an existing current run"
            );
            self.check_creation_update_authority(update)?;
            anyhow::ensure!(
                self.inner
                    .store
                    .get::<serde_json::Value>(READERS, &update.machine)?
                    .is_none(),
                "creation update has a continuation reader without current authority"
            );
        } else {
            let current = current
                .as_ref()
                .context("assigned update current run missing")?;
            update.check(current)?;
            self.check_run_creation_authority(current)?;
        }
        Ok(current)
    }

    pub(in crate::machine) async fn recover_creation_update_stopped(
        &self,
        entry: &Entry,
    ) -> Result<bool> {
        let record = entry.snapshot();
        let Some(update) = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)? else {
            return Ok(false);
        };
        if update.creation_source.is_none() {
            return Ok(false);
        }
        self.check_update_source(&update)?;
        anyhow::ensure!(
            record.state == state::STOPPED
                && record.pid == 0
                && updates::matches_update_target(&record, &update.target)
                && entry
                    .live
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_none_or(|live| *live.exited.borrow()),
            "creation update startup lacks exact stopped target"
        );
        self.check_creation_update_backing(&update).await?;
        entry.identity_trusted.store(false, Relaxed);
        Ok(true)
    }

    pub(super) async fn check_creation_update_backing(&self, update: &UpdateIntent) -> Result<()> {
        let Some(creation) = &update.creation_source else {
            return Ok(());
        };
        let data = match &creation.data {
            Some(data) => Some(Disk {
                dataset: data.dataset.clone(),
                guid: self.inner.zfs.guid(&data.dataset).await?,
            }),
            None => None,
        };
        anyhow::ensure!(
            data == creation.data,
            "creation update data backing changed"
        );
        let root = &creation.root.dataset;
        let zfs = &self.inner.zfs;
        if zfs.exists(root).await? {
            let guid = zfs.guid(root).await?;
            anyhow::ensure!(
                guid == creation.root.guid
                    || update
                        .root_swap
                        .as_ref()
                        .is_some_and(|swap| swap.target_guid == Some(guid)),
                "creation update root backing changed"
            );
        } else {
            let swap = update
                .root_swap
                .as_ref()
                .context("creation update source root missing")?;
            anyhow::ensure!(
                swap.target_guid.is_some()
                    && zfs.guid(&swap.retired_dataset).await? == creation.root.guid
                    && zfs.guid(&format!("{root}.next")).await? == swap.target_guid.unwrap(),
                "creation update interrupted root swap lacks exact backing"
            );
        }
        Ok(())
    }
}
