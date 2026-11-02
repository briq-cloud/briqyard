//! Optional accelerator for the same exact sandbox_seed request; consumed authority never misses.
use super::*;

pub(super) fn unbound_ready_slot(record: &Record) -> bool {
    record.state == state::STARTING
        && record.launch_identity.is_some()
        && record
            .warm_slot
            .as_ref()
            .is_some_and(|slot| slot.claimed.is_none())
        && record.clone_origin.as_ref().is_some_and(|o| {
            o.stage == templates::CloneStage::UnboundPaused
                && o.identity.is_none()
                && o.sandbox.is_none()
                && !o.mapping_exited
        })
}

fn assignment_error(error: anyhow::Error) -> MError {
    match error.downcast::<MError>() {
        Ok(error) => error,
        Err(error) => MError::Other(error),
    }
}

impl Manager {
    // Called under warm -> namespace -> sandbox admission after request/recipe validation.
    pub(in crate::machine) async fn select_unbound_assignment(
        &self,
        request: &api::CreateMachineRequest,
    ) -> Result<Option<Arc<Entry>>, MError> {
        if !self.unbound_warm_available() {
            return Ok(None);
        }
        let seed = request
            .sandbox_seed
            .as_ref()
            .ok_or_else(|| invalid("sandbox selector missing"))?;
        let pools = self.inner.store.list::<Pool>(POOLS)?;
        for pool in pools {
            if pool.artifact.profile != guest::SANDBOX_READY_V1
                || pool.source_machine != seed.machine_id
                || pool.snapshot != seed.snapshot
                || pool.artifact.generation != seed.generation
            {
                continue;
            }
            if pool.closed || pool.desired == 0 {
                continue;
            }
            self.pool_current(&pool)?;
            if pool.artifact.recipe.image != request.image
                || !pool
                    .artifact
                    .recipe
                    .size
                    .matches_sandbox_resources(&request.size)
            {
                return Err(invalid("unbound pool resource identity differs"));
            }
            let pool_key = key(&pool.namespace, &pool.name)?;
            let candidates: Vec<_> = self
                .inner
                .machines
                .lock()
                .unwrap()
                .values()
                .filter(|entry| {
                    let record = entry.snapshot();
                    unbound_ready_slot(&record)
                        && record.warm_slot.as_ref().is_some_and(|s| {
                            s.pool == pool_key
                                && s.fingerprint == pool.fingerprint
                                && s.claimed.is_none()
                        })
                })
                .cloned()
                .collect();
            for entry in candidates {
                // A parked fill still owns entry. An unused busy slot is an accelerator miss.
                let Ok(turn) = entry.lock.try_lock() else {
                    continue;
                };
                let source = entry.snapshot();
                if !unbound_ready_slot(&source)
                    || source.clone_origin.as_ref().is_none_or(|origin| {
                        fingerprint(&origin.artifact).ok().as_deref()
                            != Some(pool.fingerprint.as_str())
                    })
                {
                    return Err(MError::Conflict(
                        "unbound slot no longer matches pool authority".into(),
                    ));
                }
                if self.destination_assignment_owns(&source.id)? {
                    continue;
                }
                let namespace = self
                    .namespace_of(&request.namespace)
                    .ok_or(MError::NotFound)?;
                let host = {
                    let machines = self.inner.machines.lock().unwrap();
                    let mut held = self.held_addresses(namespace.rec.subnet_index);
                    for record in machines
                        .values()
                        .map(|e| e.snapshot())
                        .chain(self.assignment_targets())
                    {
                        if record.namespace == request.namespace {
                            held.push(u32::from(record.host_num));
                        }
                    }
                    for (_, policy) in self.inner.policies.lock().unwrap().values() {
                        if let nft::Policy::Via { to, .. } = policy {
                            if let Ok(ip) = to.parse::<Ipv4Addr>() {
                                if ip.octets()[..3] == namespace.subnet.network.octets()[..3] {
                                    held.push(u32::from(ip.octets()[3]));
                                }
                            }
                        }
                    }
                    netw::first_free(held, 2, 254).ok_or_else(|| {
                        MError::Capacity("sandbox destination has no address left".into())
                    })? as u8
                };
                // All authority checks in the existing writer remain inside this same outer
                // admission turn; reservation precedes any uncertain durable intent write.
                self.stage_destination_assignment_locked(request.clone(), &entry, host)
                    .map_err(assignment_error)?;
                drop(turn);
                let digest = templates::sandbox::request_digest(request)?;
                return self
                    .commit_destination_assignment_admitted(
                        &request.namespace,
                        &seed.request_id,
                        &digest,
                    )
                    .await
                    .map(Some)
                    .map_err(assignment_error);
            }
        }
        Ok(None)
    }
}
