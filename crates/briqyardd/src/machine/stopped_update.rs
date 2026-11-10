//! Durable acceptance of a cold target, fenced by the native launch settlement.
use super::*;
use sha2::{Digest, Sha256};

/// Privileged record only: never part of a machine view or an event.
#[derive(Clone, Serialize, Deserialize)]
pub struct Accepted {
    commitment: String,
    receipt: api::StoppedUpdateReceipt,
}

impl std::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accepted")
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl Manager {
    fn stopped_update_authority(&self, e: &Entry, r: &Record) -> Result<String, MError> {
        // Ordinary image creation is the only lineage supported here. Assigned machines
        // keep their journal authority; neither a clone nor an unfinished create qualifies.
        if r.role.is_some()
            || r.from_source
            || r.fork.is_some()
            || r.template_birth.is_some()
            || r.clone_origin.is_some()
            || r.warm_slot.is_some()
            || r.launch_identity.is_some()
            || r.assigned_run.is_some()
            || r.restoring.is_some()
            || r.image_key.is_empty()
            || r.root_key.is_empty()
        {
            return Err(MError::Conflict(
                "stopped update requires ordinary image creation authority".into(),
            ));
        }
        self.ordinary_operation(r)?;
        if r.state != state::STOPPED
            || r.pid != 0
            || e.live
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|vm| !*vm.exited.borrow())
            || self.inner.vmm.launch_settlement(&r.id) != fc::LaunchSettlement::Settled
        {
            return Err(MError::Conflict(
                "stopped update requires confirmed VMM exit".into(),
            ));
        }
        self.inner
            .vmm
            .host_boot_id()
            .filter(|id| fc::valid_host_boot_id(id))
            .ok_or_else(|| MError::Conflict("stopped update requires host boot authority".into()))
    }

    /// A new claim always checks CAS and exit, even if its target is unchanged.
    pub async fn stopped_update(
        &self,
        id: &str,
        req: api::StoppedUpdateRequest,
        at: u64,
    ) -> Result<api::StoppedUpdateReceipt, MError> {
        if !api::valid_id(&req.claim_nonce) {
            return Err(MError::Invalid("claim_nonce must be a runtime id".into()));
        }
        let spec = api::SpecChange {
            image: Some(req.image.clone()),
            env: Some(req.env.clone()),
            ..Default::default()
        };
        spec.check().map_err(invalid)?;
        if let Some(probes) = &req.probes {
            probes.check().map_err(invalid)?;
        }
        // Canonical ordered environment and CAS are bound to this nonce. This digest
        // stays inside the private record because an environment may have low entropy.
        let commitment = hex::encode(Sha256::digest(
            serde_json::to_vec(&(id, at, &req)).map_err(anyhow::Error::from)?,
        ));
        let e = self.own_entry(id)?;
        let _guard = e.lock.lock().await;
        if !self.holds(&e) {
            return Err(MError::NotFound);
        }
        self.check_version(&e, Some(at))?;
        let removed = e.removed.lock().unwrap();
        if *removed {
            return Err(MError::NotFound);
        }
        let mut r = e.rec.lock().unwrap();
        if r.stopped_updates
            .get(&req.claim_nonce)
            .is_some_and(|a| a.commitment != commitment)
        {
            return Err(MError::Conflict(
                "claim nonce already binds a different request".into(),
            ));
        }
        let host_boot_id = self.stopped_update_authority(&e, &r)?;
        let mut next = r.clone();
        if let Some(probes) = req.probes.clone() {
            next.probes = probes;
        }
        next.pending = update::pending_after(&next, spec);
        next.pending_since = next
            .pending
            .as_ref()
            .map(|_| next.pending_since.unwrap_or_else(Utc::now));
        next.suspended = false;
        next.suspend_synced = false;
        let event = Ev::normal(reason::UPDATED, "stopped target accepted").of(id, &next.namespace);
        let receipt = e.events.commit_then_emit(event, |version| {
            next.version = version;
            let receipt = api::StoppedUpdateReceipt {
                claim_nonce: req.claim_nonce.clone(),
                machine_id: id.into(),
                namespace: next.namespace.clone(),
                version: next.version,
                host_id: self.inner.host_id.clone(),
                host_boot_id,
            };
            next.stopped_updates.insert(
                req.claim_nonce,
                Accepted {
                    commitment,
                    receipt: receipt.clone(),
                },
            );
            next.updated_at = Utc::now();
            // `removed` serializes this write with every ordinary persistence snapshot.
            // Once renamed, retain the complete target even when directory sync fails:
            // subsequent writers and starts must never see the pre-acceptance record.
            self.inner
                .store
                .put_durable_published("machines", id, &next, || {
                    *r = next.clone();
                    e.stopped_update_unsynced.store(true, Relaxed);
                })?;
            e.stopped_update_unsynced.store(false, Relaxed);
            Ok(receipt)
        })?;
        Ok(receipt)
    }

    /// Exact-nonce recovery never replays a mutation. Re-sync the persisted record before
    /// returning a receipt; a failed write cannot become successful through a memory view.
    pub async fn stopped_update_receipt(
        &self,
        id: &str,
        claim_nonce: &str,
    ) -> Result<api::StoppedUpdateReceipt, MError> {
        if !api::valid_id(claim_nonce) {
            return Err(MError::Invalid("claim_nonce must be a runtime id".into()));
        }
        let e = self.own_entry(id)?;
        let _guard = e.lock.lock().await;
        if !self.holds(&e) {
            return Err(MError::NotFound);
        }
        let removed = e.removed.lock().unwrap();
        if *removed {
            return Err(MError::NotFound);
        }
        let current = e.rec.lock().unwrap();
        let stored = self
            .inner
            .store
            .get::<Record>("machines", id)?
            .ok_or(MError::NotFound)?;
        let accepted = stored
            .stopped_updates
            .get(claim_nonce)
            .ok_or(MError::NotFound)?;
        let receipt = &accepted.receipt;
        let host_boot_id = self.stopped_update_authority(&e, &current)?;
        self.stopped_update_authority(&e, &stored)?;
        // No target inference or memory rollback: a renamed acceptance was already
        // published under the same write gate, even if its directory sync failed.
        if serde_json::to_value(&*current).map_err(anyhow::Error::from)?
            != serde_json::to_value(&stored).map_err(anyhow::Error::from)?
        {
            return Err(MError::NotFound);
        }
        if receipt.version != stored.version
            || receipt.machine_id != id
            || receipt.namespace != current.namespace
            || receipt.host_id != self.inner.host_id
            || receipt.host_boot_id != host_boot_id
        {
            return Err(MError::NotFound);
        }
        self.inner.store.sync_dir("machines")?;
        e.stopped_update_unsynced.store(false, Relaxed);
        Ok(receipt.clone())
    }
}
