//! Host-local pools reuse normal machine records, full admission, and template readers.
use super::*;
use sha2::{Digest, Sha256};

mod claims;
mod lifecycle;
#[cfg(test)]
mod tests;
const POOLS: &str = "warm-pools";
const MAX_DESIRED: u16 = 32;
const MAX_CLAIMS: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slot {
    pub pool: String,
    pub fingerprint: String,
    pub claimed: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claim {
    machine: String,
    name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pool {
    namespace: String,
    name: String,
    source_machine: String,
    snapshot: String,
    artifact: templates::CloneArtifact,
    fingerprint: String,
    desired: u16,
    #[serde(default)]
    closed: bool,
    #[serde(default)]
    claims: BTreeMap<String, Claim>,
    #[serde(default)]
    error: String,
}

fn key(namespace: &str, name: &str) -> Result<String, MError> {
    check_namespace_id(namespace)?;
    if !api::valid_name(name) {
        return Err(invalid("pool name must be a DNS label"));
    }
    Ok(hex::encode(Sha256::digest(format!("{namespace}\0{name}"))))
}

pub(super) fn ready_slot(r: &Record) -> bool {
    r.state == state::STARTING
        && r.warm_slot.is_some()
        && r.clone_origin
            .as_ref()
            .is_some_and(|o| o.stage == templates::CloneStage::Paused)
}

fn fingerprint(artifact: &templates::CloneArtifact) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(artifact)?)))
}

impl Manager {
    pub fn warm_pool_profiles(&self) -> Vec<String> {
        if self.inner.cfg.templates.warm_pools
            && self.inner.vmm.paused_slots_supported()
            && self
                .inner
                .vmm
                .host_boot_id()
                .is_some_and(|id| fc::valid_host_boot_id(&id))
        {
            self.named_memory_profiles()
        } else {
            Vec::new()
        }
    }

    fn require_warm_pools(&self) -> Result<(), MError> {
        if self.warm_pool_profiles().is_empty() {
            return Err(invalid("warm pools are disabled or unavailable"));
        }
        Ok(())
    }

    fn pool(&self, namespace: &str, name: &str) -> Result<Pool, MError> {
        self.inner
            .store
            .get(POOLS, &key(namespace, name)?)?
            .ok_or(MError::NotFound)
    }

    fn pool_save(&self, pool: &Pool) -> Result<(), MError> {
        Ok(self
            .inner
            .store
            .put_durable(POOLS, &key(&pool.namespace, &pool.name)?, pool)?)
    }

    fn pool_artifact(
        &self,
        namespace: &str,
        source: &str,
        snapshot: &str,
    ) -> Result<(String, templates::CloneArtifact), MError> {
        let e = self.own_entry(source)?;
        let r = e.snapshot();
        let s = r
            .snapshots
            .iter()
            .find(|s| s.id == snapshot || s.name.as_deref() == Some(snapshot))
            .ok_or_else(|| MError::NoSnapshot(snapshot.into()))?;
        let (artifact, _) = self.checked_clone_artifact(&r, s, namespace)?;
        Ok((s.id.clone(), artifact))
    }

    fn pool_current(&self, pool: &Pool) -> Result<(), MError> {
        if pool.closed {
            return Err(MError::Conflict("warm pool is closed".into()));
        }
        let (_, artifact) =
            self.pool_artifact(&pool.namespace, &pool.source_machine, &pool.snapshot)?;
        if fingerprint(&artifact)? != pool.fingerprint {
            return Err(MError::Conflict(
                "warm pool template generation or policy changed".into(),
            ));
        }
        Ok(())
    }

    fn pool_view(&self, pool: &Pool) -> api::WarmPool {
        let pool_key = key(&pool.namespace, &pool.name).expect("validated stored pool");
        let mut view = api::WarmPool {
            namespace: pool.namespace.clone(),
            name: pool.name.clone(),
            source_machine: pool.source_machine.clone(),
            snapshot: pool.snapshot.clone(),
            generation: pool.artifact.generation.clone(),
            profile: pool.artifact.profile.clone(),
            source_host: pool.artifact.source_host.clone(),
            desired: pool.desired,
            closed: pool.closed,
            slots: Vec::new(),
            creating: 0,
            ready: 0,
            claimed: 0,
            claim_receipts: pool.claims.len(),
            failed: 0,
            error: pool.error.clone(),
        };
        for e in self.inner.machines.lock().unwrap().values() {
            let r = e.rec.lock().unwrap();
            let Some(slot) = r.warm_slot.as_ref().filter(|s| s.pool == pool_key) else {
                continue;
            };
            let request_id = slot.claimed.clone().or_else(|| {
                pool.claims
                    .iter()
                    .find(|(_, c)| c.machine == r.id)
                    .map(|(id, _)| id.clone())
            });
            let status = if request_id.is_some() {
                view.claimed += 1;
                "claimed"
            } else {
                match r.state.as_str() {
                    _ if ready_slot(&r) => {
                        view.ready += 1;
                        "ready"
                    }
                    state::CREATING | state::STARTING => {
                        view.creating += 1;
                        "creating"
                    }
                    _ => {
                        view.failed += 1;
                        "failed"
                    }
                }
            };
            view.slots.push(api::WarmPoolSlot {
                machine_id: r.id.clone(),
                name: r.name.clone(),
                status: status.into(),
                machine_state: r.state.clone(),
                request_id,
            });
        }
        view
    }

    pub fn warm_pools(&self, namespace: &str) -> Result<Vec<api::WarmPool>, MError> {
        check_namespace_id(namespace)?;
        Ok(self
            .inner
            .store
            .list::<Pool>(POOLS)?
            .iter()
            .filter(|p| p.namespace == namespace)
            .map(|p| self.pool_view(p))
            .collect())
    }

    pub async fn put_warm_pool(
        &self,
        namespace: &str,
        name: &str,
        request: api::PutWarmPoolRequest,
    ) -> Result<api::WarmPool, MError> {
        let _turn = self.inner.warm_lock.lock().await;
        self.require_warm_pools()?;
        let pool_key = key(namespace, name)?;
        if request.desired > MAX_DESIRED {
            return Err(invalid("warm pool desired count exceeds32"));
        }
        let (snapshot, artifact) =
            self.pool_artifact(namespace, &request.source_machine, &request.snapshot)?;
        let fp = fingerprint(&artifact)?;
        let mut pool = match self.inner.store.get::<Pool>(POOLS, &pool_key)? {
            Some(old) => {
                if old.closed
                    || old.source_machine != request.source_machine
                    || old.snapshot != snapshot
                    || old.fingerprint != fp
                {
                    return Err(MError::Conflict(
                        "a pool name keeps its immutable template; drain it and use a new name"
                            .into(),
                    ));
                }
                old
            }
            None => Pool {
                namespace: namespace.into(),
                name: name.into(),
                source_machine: request.source_machine,
                snapshot,
                artifact,
                fingerprint: fp,
                desired: 0,
                closed: false,
                claims: BTreeMap::new(),
                error: String::new(),
            },
        };
        pool.desired = request.desired;
        self.pool_save(&pool)?;
        Ok(self.pool_view(&pool))
    }

    pub async fn delete_warm_pool(&self, namespace: &str, name: &str) -> Result<(), MError> {
        let _turn = self.inner.warm_lock.lock().await;
        let mut pool = self.pool(namespace, name)?;
        pool.closed = true;
        pool.desired = 0;
        self.pool_save(&pool)?;
        // Keep the bounded claim receipts after drain. A timeout retry cannot consume a new slot.
        Ok(())
    }
}
