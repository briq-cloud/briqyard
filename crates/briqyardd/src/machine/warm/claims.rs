use super::*;

impl Manager {
    /// The receipt is durable before resume or worker launch. It never expires or gets
    /// recycled: retrying a lost response can only reach this same destination.
    pub async fn claim_warm_pool(
        &self,
        namespace: &str,
        name: &str,
        request: api::ClaimWarmPoolRequest,
    ) -> Result<api::Machine, MError> {
        let scope = self.inner.zfs.io_scope()?;
        scope
            .run(self.claim_warm_pool_admitted(namespace, name, request))
            .await
    }

    async fn claim_warm_pool_admitted(
        &self,
        namespace: &str,
        name: &str,
        request: api::ClaimWarmPoolRequest,
    ) -> Result<api::Machine, MError> {
        let claim_started = std::time::Instant::now();
        self.require_warm_pools()?;
        if !api::valid_name(&request.name) || !api::valid_id(&request.request_id) {
            return Err(invalid(
                "warm claim requires a DNS name and stable request_id",
            ));
        }
        #[cfg(test)]
        self.inner
            .vmm
            .warm_test_barrier("warm_claim_lock", "*")
            .await;
        let turn = if request.fail_fast {
            match self.inner.warm_lock.try_lock() {
                Ok(turn) => turn,
                Err(_) => {
                    let pool = self.pool(namespace, name)?;
                    if let Some(existing) = self.existing_warm_claim(&pool, &request.request_id)? {
                        if existing.name != request.name {
                            return Err(MError::Conflict(
                                "request_id already claims another name".into(),
                            ));
                        }
                        return self
                            .wait(
                                &existing.machine,
                                Until::Ready,
                                Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10)),
                            )
                            .await;
                    }
                    return Err(MError::PoolEmpty);
                }
            }
        } else {
            self.inner.warm_lock.lock().await
        };
        // Refill uses warm -> namespace -> entry; claims follow the same order.
        let _admission = if request.fail_fast {
            self.inner
                .namespace_lifecycle
                .try_read()
                .map_err(|_| MError::PoolEmpty)?
        } else {
            self.inner.namespace_lifecycle.read().await
        };
        let mut pool = self.pool(namespace, name)?;
        let pool_key = key(namespace, name)?;
        let existing = self.existing_warm_claim(&pool, &request.request_id)?;
        let is_new = existing.is_none();
        let e = if let Some(claim) = &existing {
            if claim.name != request.name {
                return Err(MError::Conflict(
                    "request_id already claims another name".into(),
                ));
            }
            self.entry(&claim.machine).map_err(|_| MError::Conflict("the previously claimed machine was destroyed; this request_id cannot consume another slot".into()))?
        } else {
            self.pool_current(&pool)?;
            if pool.claims.len() >= MAX_CLAIMS {
                return Err(MError::Conflict(
                    "pool claim receipt limit reached; use a new pool name".into(),
                ));
            }
            self.inner
                .machines
                .lock()
                .unwrap()
                .values()
                .find(|e| {
                    let r = e.snapshot();
                    ready_slot(&r)
                        && r.namespace == namespace
                        && r.warm_slot.as_ref().is_some_and(|slot| {
                            slot.pool == pool_key
                                && slot.fingerprint == pool.fingerprint
                                && slot.claimed.is_none()
                        })
                        && !pool.claims.values().any(|claim| claim.machine == r.id)
                })
                .cloned()
                .ok_or(MError::PoolEmpty)?
        };
        // A fill can publish Paused while still owning its lifecycle lock. Never alter
        // claimed/name/receipt until that fill has completed and readiness is rechecked.
        let entry_turn = if request.fail_fast && is_new {
            e.lock.try_lock().map_err(|_| MError::PoolEmpty)?
        } else {
            e.lock.lock().await
        };
        if !self.holds(&e) {
            self.inner
                .warm_names
                .lock()
                .unwrap()
                .retain(|_, id| id != &e.snapshot().id);
            return Err(MError::Conflict("claimed machine was destroyed".into()));
        }
        let before = e.snapshot();
        if before.namespace != namespace
            || !before.warm_slot.as_ref().is_some_and(|s| {
                s.pool == pool_key
                    && s.fingerprint == pool.fingerprint
                    && s.claimed
                        .as_ref()
                        .is_none_or(|id| id == &request.request_id)
            })
        {
            return Err(MError::Conflict(
                "claim destination differs from its immutable pool".into(),
            ));
        }
        if is_new
            && (!ready_slot(&before)
                || before
                    .warm_slot
                    .as_ref()
                    .is_none_or(|slot| slot.claimed.is_some())
                || pool.claims.values().any(|claim| claim.machine == before.id))
        {
            return Err(MError::PoolEmpty);
        }
        if let Some(claim) = existing.filter(|_| !pool.claims.contains_key(&request.request_id)) {
            pool.claims.insert(request.request_id.clone(), claim);
            self.pool_save(&pool)?;
        }
        if before
            .warm_slot
            .as_ref()
            .is_some_and(|s| s.claimed.as_deref() == Some(&request.request_id))
            && !ready_slot(&before)
        {
            drop(turn);
            drop(entry_turn);
            return self
                .wait(
                    &before.id,
                    Until::Ready,
                    Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10)),
                )
                .await;
        }
        if !ready_slot(&before) {
            return Err(MError::Conflict(
                "claimed destination is not a completed paused slot".into(),
            ));
        }
        self.pool_current(&pool)?;
        // Namespace create uses this same machine/name boundary. The entry lock above
        // stays held through both durable receipt publication and activation.
        {
            let machines = self.inner.machines.lock().unwrap();
            if machines.values().any(|other| {
                let r = other.snapshot();
                r.namespace == namespace
                    && r.name == request.name
                    && r.id != before.id
                    && r.state != state::DESTROYING
            }) {
                return Err(MError::Conflict("claim name is already taken".into()));
            }
            let mut names = self.inner.warm_names.lock().unwrap();
            if names
                .get(&(namespace.into(), request.name.clone()))
                .is_some_and(|id| id != &before.id)
            {
                return Err(MError::Conflict("claim name is already reserved".into()));
            }
            names.insert((namespace.into(), request.name.clone()), before.id.clone());
            pool.claims.insert(
                request.request_id.clone(),
                Claim {
                    machine: before.id.clone(),
                    name: request.name.clone(),
                },
            );
            self.pool_save(&pool)?;
        }
        {
            let mut r = e.rec.lock().unwrap();
            r.name = request.name;
            r.warm_slot.as_mut().unwrap().claimed = Some(request.request_id);
        }
        self.inner
            .store
            .put_durable("machines", &before.id, &e.snapshot())?;
        self.inner
            .warm_names
            .lock()
            .unwrap()
            .retain(|_, id| id != &before.id);
        if let Some(namespace) = self.namespace_of(namespace) {
            self.refresh_dns(&namespace);
        }
        crate::profile::stage(
            "warm_claim",
            "claim_durable",
            &before.id,
            before.pid,
            claim_started,
            true,
        );
        drop(turn);
        if ready_slot(&before) {
            let live =
                e.live.lock().unwrap().clone().ok_or_else(|| {
                    MError::Conflict("paused slot has no adopted owned VMM".into())
                })?;
            let result = self.activate_memory_clone(&e, &live).await;
            if let Err(error) = result {
                self.end_process(&e, &live, Duration::ZERO).await;
                if !*live.exited.borrow() {
                    return Err(MError::Conflict(
                        "claim exit unconfirmed; reservation retained".into(),
                    ));
                }
                return Err(
                    self.boot_failed(&e, format!("warm claim activation failed: {error:#}"))
                );
            }
            let (_, _, generation) = self.reset_probes(&e);
            e.set_state(state::RUNNING, |r| {
                r.started_at = Some(Utc::now());
                r.last_used_at = r.started_at;
                None
            });
            self.spawn_probes(&e, &live, generation, true);
            self.inner
                .store
                .put_durable("machines", &before.id, &e.snapshot())?;
        }
        drop(entry_turn);
        self.wait(
            &before.id,
            Until::Ready,
            Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10)),
        )
        .await
    }
    fn existing_warm_claim(&self, pool: &Pool, request_id: &str) -> Result<Option<Claim>, MError> {
        let pool_key = key(&pool.namespace, &pool.name)?;
        Ok(pool.claims.get(request_id).cloned().or_else(|| {
            self.inner.machines.lock().unwrap().values().find_map(|e| {
                let r = e.snapshot();
                (r.namespace == pool.namespace
                    && r.warm_slot.as_ref().is_some_and(|s| {
                        s.pool == pool_key && s.claimed.as_deref() == Some(request_id)
                    }))
                .then_some(Claim {
                    machine: r.id,
                    name: r.name,
                })
            })
        }))
    }
}
