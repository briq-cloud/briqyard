//! Observation does not grant a later mutation or reserve maintenance admission.
use super::*;
use sha2::{Digest, Sha256};

/// Both admission gates stay held through handover. Declaration order is also lock order.
#[derive(Debug)]
pub struct HandoverAdmission<'a> {
    _warm: tokio::sync::RwLockWriteGuard<'a, ()>,
    _namespace: tokio::sync::RwLockWriteGuard<'a, ()>,
}

#[cfg(test)]
mod tests;

impl Manager {
    pub(super) async fn warm_maintenance_admission_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<HandoverAdmission<'_>> {
        let warm = tokio::time::timeout_at(deadline, self.inner.warm_lock.write())
            .await
            .context("warm admission did not settle before handover deadline")?;
        let namespace = tokio::time::timeout_at(deadline, self.inner.namespace_lifecycle.write())
            .await
            .context("namespace admission did not settle before handover deadline")?;
        Ok(HandoverAdmission {
            _warm: warm,
            _namespace: namespace,
        })
    }

    pub async fn warm_catalog_eligibility(&self) -> api::WarmCatalogEligibility {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let Ok(_admission) = self.warm_maintenance_admission_until(deadline).await else {
            return self.maintenance_observation(api::WarmMaintenanceReason::Busy, None);
        };
        self.warm_catalog_eligibility_locked(deadline)
    }

    fn maintenance_observation(
        &self,
        reason: api::WarmMaintenanceReason,
        counts: Option<api::WarmMaintenanceCounts>,
    ) -> api::WarmCatalogEligibility {
        api::WarmCatalogEligibility {
            observation: self.runtime_observation(),
            eligible: reason == api::WarmMaintenanceReason::Eligible,
            reason,
            counts,
        }
    }

    pub(super) fn warm_catalog_eligibility_locked(
        &self,
        deadline: tokio::time::Instant,
    ) -> api::WarmCatalogEligibility {
        use api::WarmMaintenanceReason as R;
        if self.recovery_fault().is_some() {
            return self.maintenance_observation(R::RecoveryUnresolved, None);
        }
        let Ok(counts) = self.maintenance_counts(deadline) else {
            // Internal records can contain secrets. Never project decode errors or values.
            return self.maintenance_observation(R::StateUnknown, None);
        };
        let reason = if counts.desired_slots == 0
            && counts.pool_claims == 0
            && counts.warm_machines == 0
            && counts.launch_holds == 0
            && counts.launch_transitions == 0
            && counts.warm_names == 0
            && counts.pending_assignments == 0
            && counts.run_authorities == 0
        {
            R::Eligible
        } else {
            R::OutstandingWarmState
        };
        self.maintenance_observation(reason, Some(counts))
    }

    fn maintenance_counts(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<api::WarmMaintenanceCounts> {
        let mut budget = crate::store::InspectionBudget::new(deadline);
        let records = self
            .inner
            .store
            .inspect::<Record>("machines", &mut budget)?;
        let live: BTreeMap<_, _> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .iter()
            .map(|(id, entry)| (id.clone(), entry.snapshot()))
            .collect();
        let (pools, desired_slots, pool_claims) =
            self.maintenance_pools(&mut budget, &records, &live)?;
        let mut warm = std::collections::HashSet::new();
        for (key, record) in records.iter().chain(&live) {
            anyhow::ensure!(
                api::valid_id(&record.id) && key == &record.id,
                "maintenance machine key differs"
            );
            if has_warm_authority(&record) {
                warm.insert(record.id.clone());
            }
        }
        let launch_holds = self.maintenance_launch_holds(&mut budget)?;
        // Any transition is outstanding authority. Parsing failure is unknown, not absence.
        let launch_transitions = self
            .inner
            .store
            .inspect::<serde_json::Value>("launch-transitions", &mut budget)?
            .len();
        let warm_names = self.inner.warm_names.lock().unwrap().len();
        let pending_assignments = self.maintenance_assignments(&mut budget)?;
        let run_authorities = self.maintenance_runs(&mut budget, &records, &live)?;
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "state inspection deadline"
        );
        Ok(api::WarmMaintenanceCounts {
            pools,
            desired_slots,
            pool_claims,
            warm_machines: warm.len(),
            launch_holds,
            launch_transitions,
            warm_names,
            pending_assignments,
            run_authorities,
        })
    }

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

fn has_warm_authority(record: &Record) -> bool {
    record.warm_slot.is_some()
        || record.launch_identity.is_some()
        || record
            .assigned_run
            .as_ref()
            .is_some_and(|run| run.phase != assignments::runs::Phase::Settled)
}
