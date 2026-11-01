use super::*;

impl Manager {
    pub(in crate::machine) async fn prepare_warm_slot(
        &self,
        e: &Entry,
        live: &fc::Vm,
    ) -> Result<String> {
        let started = std::time::Instant::now();
        let version = self.configure_memory_clone(e, live).await?;
        self.inner.vmm.pause(live).await.context("park warm slot")?;
        self.clone_stage(e, templates::CloneStage::Paused)?;
        crate::profile::stage(
            "warm_slot_fill",
            "park_durable",
            &e.snapshot().id,
            live.pid,
            started,
            true,
        );
        Ok(version)
    }

    /// Bounded work in the existing tick. A failed cleanup blocks refill rather than
    /// accumulating failed records or borrowing their capacity.
    pub(in crate::machine) async fn warm_step(&self) {
        let Ok(_turn) = self.inner.warm_lock.try_lock() else {
            return;
        };
        let enabled = self.require_warm_pools().is_ok();
        let pools = match self.inner.store.list::<Pool>(POOLS) {
            Ok(pools) => pools,
            Err(error) => {
                tracing::error!(%error, "warm pools unavailable");
                return;
            }
        };
        for mut pool in pools {
            let current = if enabled {
                self.pool_current(&pool)
            } else {
                Err(invalid("warm pools disabled; draining unused slots"))
            };
            let pool_key = match key(&pool.namespace, &pool.name) {
                Ok(key) => key,
                Err(_) => continue,
            };
            let entries: Vec<_> = self
                .inner
                .machines
                .lock()
                .unwrap()
                .values()
                .filter(|e| {
                    e.snapshot()
                        .warm_slot
                        .as_ref()
                        .is_some_and(|s| s.pool == pool_key && s.claimed.is_none())
                })
                .cloned()
                .collect();
            let mut remaining = 0;
            let mut blocked = false;
            for e in entries {
                let r = e.snapshot();
                // A durable claim intent owns its slot even before the record rename.
                if pool.claims.values().any(|c| c.machine == r.id) {
                    continue;
                }
                if current.is_err()
                    || remaining >= usize::from(pool.desired)
                    || !matches!(
                        r.state.as_str(),
                        state::CREATING | state::STARTING | state::WARM
                    )
                {
                    if let Err(error) = self.destroy_machine(&r.id, None).await {
                        pool.error = error.to_string();
                        blocked = true;
                    }
                } else {
                    remaining += 1;
                }
            }
            if let Err(error) = current {
                pool.error = error.to_string();
                let _ = self.pool_save(&pool);
                continue;
            }
            if !blocked && remaining < usize::from(pool.desired) {
                if let Err(error) = self.fill_warm_slot(&pool).await {
                    pool.error = error.to_string();
                } else {
                    pool.error.clear();
                }
            }
            let _ = self.pool_save(&pool);
        }
    }

    async fn fill_warm_slot(&self, pool: &Pool) -> Result<(), MError> {
        let name = format!("warm-{}", new_id("s").replace('_', "-"));
        let (e, how) = self.allocate_warm_slot(pool, name, None).await?;
        self.spawn_make_admitted(self.inner.zfs.io_scope()?, e, how);
        Ok(())
    }

    pub(super) async fn allocate_warm_slot(
        &self,
        pool: &Pool,
        name: String,
        claimed: Option<String>,
    ) -> Result<(Arc<Entry>, Make), MError> {
        let scope = self.inner.zfs.io_scope()?;
        scope
            .run(async {
                let request = api::CreateMachineRequest {
                    namespace: pool.namespace.clone(),
                    name,
                    size: pool.artifact.recipe.size,
                    sleep: "never".into(),
                    fork: Some(api::ForkSpec {
                        machine_id: pool.source_machine.clone(),
                        snapshot: Some(pool.snapshot.clone()),
                        copy: String::new(),
                    }),
                    ..Default::default()
                };
                let slot = Slot {
                    pool: key(&pool.namespace, &pool.name)?,
                    fingerprint: pool.fingerprint.clone(),
                    claimed,
                };
                let (e, how) = self.record_warm_slot(request, slot).await?;
                let origin = e
                    .snapshot()
                    .clone_origin
                    .ok_or_else(|| invalid("pool slot omitted template origin"))?;
                if fingerprint(&origin.artifact)? != pool.fingerprint {
                    return Err(MError::Conflict(
                        "pool template changed while reserving slot".into(),
                    ));
                }
                self.inner
                    .store
                    .put_durable("machines", &e.snapshot().id, &e.snapshot())?;
                Ok((e, how))
            })
            .await
    }

    /// Rebuild pending-name holds before admitting requests after a daemon restart.
    pub(in crate::machine) fn recover_warm_names(&self) -> Result<()> {
        let pools = self.inner.store.list::<Pool>(POOLS)?;
        let machines = self.inner.machines.lock().unwrap();
        let mut names = self.inner.warm_names.lock().unwrap();
        for pool in pools {
            for claim in pool.claims.values() {
                if machines
                    .get(&claim.machine)
                    .is_some_and(|e| ready_slot(&e.snapshot()) && e.snapshot().name != claim.name)
                {
                    names.insert(
                        (pool.namespace.clone(), claim.name.clone()),
                        claim.machine.clone(),
                    );
                }
            }
        }
        Ok(())
    }

    pub(in crate::machine) async fn recover_warm_slot(&self, e: &Arc<Entry>) -> bool {
        let _turn = e.lock.lock().await;
        let r = e.snapshot();
        let Some(origin) = &r.clone_origin else {
            return false;
        };
        let dir = self.inner.cfg.run_dir().join(&r.id);
        let jail = self.jail_for(&r);
        let vm = self
            .inner
            .vmm
            .adopt_paused(&r.id, &dir, jail.as_ref(), r.pid, e.disk_io.clone())
            .await;
        if let Some(mut vm) = vm {
            let bound = r
                .boot_incarnation
                .as_ref()
                .zip(vm.incarnation.as_ref())
                .is_some_and(|(saved, actual)| saved == actual);
            let identity = fc::BootIdentity::after_adoption(
                r.boot_identity.as_ref(),
                vm.boot_identity.as_ref(),
                bound,
            );
            if bound
                && identity.as_ref() == Some(&origin.artifact.boot_identity)
                && origin.stage == templates::CloneStage::Paused
                && origin.identity.is_some()
                && self
                    .inner
                    .store
                    .get::<templates::CloneReader>(templates::READERS, &r.id)
                    .ok()
                    .flatten()
                    .is_some_and(|reader| {
                        reader.generation == origin.artifact.generation
                            && reader.destination == r.id
                            && reader.stage == templates::CloneStage::Paused
                    })
            {
                vm.boot_identity = identity;
                e.identity_trusted.store(true, Relaxed);
                *e.live.lock().unwrap() = Some(vm.clone());
                self.watch(e, &vm);
                return true;
            }
        }
        // Share the non-activating, pidfd/boot-boundary settlement used by strict
        // clone recovery. An unknown pending launch never becomes an absence proof.
        let _ = self.unplug(&r.id, &r.ip).await;
        let gone = self.reconcile_clone_exit(e).await.unwrap_or(false);
        {
            let mut record = e.rec.lock().unwrap();
            record.state = state::ERROR.into();
            record.error = if gone {
                "warm slot adoption failed; exit confirmed, cleanup required".into()
            } else {
                "warm slot adoption failed; exit unknown, full reservation retained".into()
            };
        }
        let _ = self.save(e);
        false
    }
}
