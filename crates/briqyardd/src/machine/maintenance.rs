//! Observation does not grant a later mutation or reserve maintenance admission.
use super::*;
use sha2::{Digest, Sha256};

impl Manager {
    pub(super) fn runtime_observation(&self) -> api::RuntimeObservation {
        api::RuntimeObservation {
            host_id: self.inner.host_id.clone(),
            version: briqyard_version::VERSION.into(),
            host_boot_id: self.inner.vmm.host_boot_id(),
            incarnation: self.inner.observation_incarnation.clone(),
            config: self.inner.cfg.loaded_identity.clone(),
        }
    }

    /// Inspect one exact sealed snapshot under its source lifecycle lock. No alias,
    /// reader reservation, catalog entry, or guest request is created by observation.
    pub async fn sealed_sandbox_recipe(
        &self,
        id: &str,
        snapshot: &str,
    ) -> Result<api::SealedSandboxRecipe, MError> {
        if self.recovery_fault().is_some() {
            return Err(MError::Conflict("host recovery is unresolved".into()));
        }
        let entry = self.own_entry(id)?;
        let _source = tokio::time::timeout(Duration::from_secs(5), entry.lock.lock())
            .await
            .map_err(|_| MError::Conflict("source lifecycle is busy".into()))?;
        let record = entry.snapshot();
        let sealed = record
            .snapshots
            .iter()
            .find(|s| s.id == snapshot)
            .ok_or_else(|| MError::NoSnapshot(snapshot.into()))?;
        let (artifact, _) = self.checked_clone_artifact(&record, sealed, &record.namespace)?;
        self.check_sandbox_artifact(&record, &artifact)?;
        Ok(api::SealedSandboxRecipe {
            observation: self.runtime_observation(),
            source_machine: record.id,
            namespace: artifact.namespace,
            snapshot: sealed.id.clone(),
            generation: artifact.generation,
            profile: artifact.profile,
            source_host: artifact.source_host,
            image: artifact.recipe.image,
            image_digest: artifact.recipe.image_digest,
            image_config_digest: artifact.recipe.image_config_digest,
            init_sha256: artifact.init_sha256,
            boot_identity_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&artifact.boot_identity).map_err(anyhow::Error::from)?,
            )),
            size: artifact.recipe.size,
            root_disk_gb: artifact.recipe.root_disk_gb,
            data_device: artifact.recipe.config.sandbox_device,
        })
    }
}
