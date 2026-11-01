use super::*;

pub(super) const MAX_SAMPLE_AGE: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
pub(in crate::machine) struct SampleBoundary {
    known_warm: std::collections::HashSet<String>,
    pending_memory_mb: u32,
}

#[derive(Clone)]
pub(in crate::machine) struct Sample {
    pub at: std::time::Instant,
    pub memory_mb: u32,
    pub pool: crate::zfs::Pool,
    pub boundary: SampleBoundary,
}

fn blocked(reason: &str, message: &str) -> api::WarmBlocked {
    api::WarmBlocked {
        reason: reason.into(),
        message: message.into(),
    }
}

pub(super) fn failure(error: &MError) -> api::WarmBlocked {
    let reason = match error {
        MError::Quota(_) => "quota",
        MError::Capacity(message) => ["budget", "headroom", "pressure", "catalog"]
            .into_iter()
            .find(|reason| message.starts_with(&format!("{reason}:")))
            .unwrap_or("capacity"),
        _ => "catalog",
    };
    blocked(reason, &error.to_string())
}

pub(super) fn add(a: api::WarmResources, b: api::WarmResources) -> Option<api::WarmResources> {
    Some(api::WarmResources {
        memory_mb: a.memory_mb.checked_add(b.memory_mb)?,
        cpu_millis: a.cpu_millis.checked_add(b.cpu_millis)?,
        root_disk_gb: a.root_disk_gb.checked_add(b.root_disk_gb)?,
    })
}

pub(super) fn resources(r: &Record) -> api::WarmResources {
    api::WarmResources {
        memory_mb: r.size.memory_mb,
        cpu_millis: r.size.cpu_millis(),
        root_disk_gb: r
            .clone_origin
            .as_ref()
            .map_or(0, |o| o.artifact.recipe.root_disk_gb),
    }
}

fn exceeds(a: api::WarmResources, b: api::WarmResources) -> bool {
    a.memory_mb > b.memory_mb || a.cpu_millis > b.cpu_millis || a.root_disk_gb > b.root_disk_gb
}

pub(super) struct Usage {
    pub(super) charged: api::WarmResources,
    filling_memory: u32,
    pub(super) fills: usize,
    draining: usize,
    counts: HashMap<String, usize>,
}

impl Manager {
    pub(super) fn catalog_entry(&self, pool: &Pool) -> Result<api::WarmCatalogEntry, MError> {
        self.inner
            .warm_policy
            .lock()
            .unwrap()
            .catalog
            .iter()
            .find(|e| {
                e.namespace == pool.namespace
                    && e.source_machine == pool.source_machine
                    && e.snapshot == pool.snapshot
                    && e.generation == pool.artifact.generation
                    && e.size.memory_mb == pool.artifact.recipe.size.memory_mb
                    && e.size.vcpus == pool.artifact.recipe.size.vcpus
                    && e.size.cpu_millis() == pool.artifact.recipe.size.cpu_millis()
            })
            .cloned()
            .ok_or_else(|| {
                invalid(
                    "catalog: pool does not match a configured immutable template and exact size",
                )
            })
    }

    // Receipts are read under the machines admission lock. Publication uses that same
    // lock, so durable claim intent changes classification without releasing resources.
    fn warm_usage(&self, machines: &HashMap<String, Arc<Entry>>) -> Result<Usage, MError> {
        let pools = self.inner.store.list::<Pool>(POOLS)?;
        self.warm_usage_from(machines, &pools)
    }

    pub(super) fn warm_usage_from(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        pools: &[Pool],
    ) -> Result<Usage, MError> {
        let claimed: std::collections::HashSet<_> = pools
            .iter()
            .flat_map(|p| p.claims.values().map(|c| c.machine.as_str()))
            .collect();
        let entries: HashMap<_, _> = pools
            .iter()
            .filter_map(|pool| {
                Some((
                    key(&pool.namespace, &pool.name).ok()?,
                    self.catalog_entry(pool).ok()?.id,
                ))
            })
            .collect();
        let mut use_ = Usage {
            charged: Default::default(),
            filling_memory: 0,
            fills: 0,
            draining: 0,
            counts: HashMap::new(),
        };
        for e in machines.values() {
            let r = e.snapshot();
            let Some(slot) = r
                .warm_slot
                .as_ref()
                .filter(|s| s.claimed.is_none() && !claimed.contains(r.id.as_str()))
            else {
                continue;
            };
            if r.clone_origin.is_none() {
                return Err(MError::Capacity(
                    "warm record lacks its full recipe reservation".into(),
                ));
            }
            use_.charged = add(use_.charged, resources(&r))
                .ok_or_else(|| MError::Capacity("warm accounting overflow".into()))?;
            use_.draining += usize::from(r.state == state::DESTROYING);
            if let Some(entry) = entries.get(&slot.pool) {
                *use_.counts.entry(entry.clone()).or_default() += 1;
            }
            if !ready_slot(&r) || e.lock.try_lock().is_err() {
                use_.fills += 1;
                use_.filling_memory = use_
                    .filling_memory
                    .checked_add(r.size.memory_mb)
                    .ok_or_else(|| MError::Capacity("warm fill accounting overflow".into()))?;
            }
        }
        Ok(use_)
    }

    pub(in crate::machine) async fn warm_probe(&self) -> Result<(), MError> {
        #[cfg(test)]
        if let Some(sample) = self.inner.warm_probe_override.lock().unwrap().clone() {
            *self.inner.warm_sample.lock().unwrap() = sample.clone();
            return sample
                .map(|_| ())
                .ok_or_else(|| MError::Capacity("pressure: measurement unavailable".into()));
        }
        // Invalidate before probing: a failed probe must never retain a usable old sample.
        *self.inner.warm_sample.lock().unwrap() = None;
        let began = std::time::Instant::now();
        let boundary = self.warm_probe_boundary()?;
        let memory_mb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| mem_available(&s))
            .ok_or_else(|| MError::Capacity("pressure: MemAvailable unavailable".into()))?;
        let pool = self.inner.zfs.pool().await.map_err(|error| {
            MError::Capacity(format!("pressure: pool measurement unavailable: {error}"))
        })?;
        *self.inner.warm_sample.lock().unwrap() = Some(Sample {
            at: began,
            memory_mb,
            pool,
            boundary,
        });
        Ok(())
    }

    // Capture before reading MemAvailable. Completion or claim cannot erase these
    // liabilities while the sample is usable; later fills are charged by their IDs.
    pub(in crate::machine) fn warm_probe_boundary(&self) -> Result<SampleBoundary, MError> {
        let machines = self.inner.machines.lock().unwrap();
        Ok(SampleBoundary {
            known_warm: machines
                .values()
                .filter_map(|entry| {
                    let record = entry.snapshot();
                    record.warm_slot.is_some().then_some(record.id)
                })
                .collect(),
            pending_memory_mb: self.warm_usage(&machines)?.filling_memory,
        })
    }

    pub(super) fn policy_blocked(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        candidate: Option<&Record>,
    ) -> Result<Option<api::WarmBlocked>, MError> {
        let p = self.inner.warm_policy.lock().unwrap().clone();
        if p.check_capacity(self.capacity()).is_err() {
            return Ok(Some(blocked(
                "capacity",
                "configured warm budget and headroom exceed host capacity",
            )));
        }
        let u = self.warm_usage(machines)?;
        let need = candidate.map(resources).unwrap_or_default();
        let Some(total) = add(u.charged, need) else {
            return Ok(Some(blocked("capacity", "warm accounting overflow")));
        };
        if exceeds(total, p.budget) {
            return Ok(Some(blocked("budget", "warm resource budget exhausted")));
        }
        let mut used = api::WarmResources::default();
        for e in machines.values() {
            let r = e.snapshot();
            if commits_memory(&r) {
                let n = api::WarmResources {
                    root_disk_gb: 0,
                    ..resources(&r)
                };
                used = add(used, n)
                    .ok_or_else(|| MError::Capacity("host accounting overflow".into()))?;
            }
        }
        let cap = self.capacity();
        let available = api::WarmResources {
            memory_mb: cap.memory_mb.saturating_sub(p.headroom.memory_mb),
            cpu_millis: cap.cpu_millis().saturating_sub(p.headroom.cpu_millis),
            root_disk_gb: u32::MAX,
        };
        let Some(committed) = add(
            used,
            api::WarmResources {
                root_disk_gb: 0,
                ..need
            },
        ) else {
            return Ok(Some(blocked("capacity", "host accounting overflow")));
        };
        if exceeds(committed, available) {
            return Ok(Some(blocked(
                "headroom",
                "ordinary workload headroom unavailable",
            )));
        }
        if candidate.is_some() && u.fills >= usize::from(p.max_fills) {
            return Ok(Some(blocked(
                "capacity",
                "maximum concurrent warm fills reached",
            )));
        }
        if let Some(candidate) = candidate {
            let pools = self.inner.store.list::<Pool>(POOLS)?;
            let pool = pools.iter().find(|pool| {
                key(&pool.namespace, &pool.name).ok().as_deref()
                    == candidate.warm_slot.as_ref().map(|s| s.pool.as_str())
            });
            if let Some(entry) = pool.and_then(|pool| self.catalog_entry(pool).ok()) {
                let count = u.counts.get(&entry.id).copied().unwrap_or(0) + 1;
                if count > usize::from(entry.max_ready) {
                    return Ok(Some(blocked("catalog", "catalog max_ready reached")));
                }
            } else {
                return Ok(Some(blocked(
                    "catalog",
                    "candidate no longer matches a configured entry",
                )));
            }
        }
        let Some(sample) = self.inner.warm_sample.lock().unwrap().clone() else {
            return Ok(Some(blocked(
                "pressure",
                "availability measurement unavailable",
            )));
        };
        if sample.at.elapsed() > MAX_SAMPLE_AGE {
            return Ok(Some(blocked("pressure", "availability measurement stale")));
        }
        if self.inner.zfs.stalled(crate::zfs::STALL_AFTER).is_some() {
            return Ok(Some(blocked("pressure", "storage stalled")));
        }
        let mut liability = sample
            .boundary
            .pending_memory_mb
            .checked_add(need.memory_mb);
        for entry in machines.values() {
            let record = entry.snapshot();
            if record.warm_slot.is_some() && !sample.boundary.known_warm.contains(&record.id) {
                liability = liability.and_then(|n| n.checked_add(record.size.memory_mb));
            }
        }
        let Some(liability) = liability else {
            return Ok(Some(blocked(
                "capacity",
                "sample memory liability overflow",
            )));
        };
        if sample
            .memory_mb
            .checked_sub(liability)
            .is_none_or(|n| n <= p.min_mem_available_mb)
        {
            return Ok(Some(blocked("pressure", "MemAvailable floor reached")));
        }
        let logical = u64::from(total.root_disk_gb) << 30;
        let Some(pool_size) = sample.pool.used.checked_add(sample.pool.free) else {
            return Ok(Some(blocked("capacity", "pool capacity overflow")));
        };
        let floor = (u64::from(p.headroom.disk_free_gb) << 30).max(
            pool_size
                .checked_mul(u64::from(self.inner.cfg.conditions.disk_free_pct))
                .map(|n| n.div_ceil(100))
                .unwrap_or(u64::MAX),
        );
        if sample
            .pool
            .free
            .checked_sub(logical)
            .is_none_or(|n| n <= floor)
        {
            return Ok(Some(blocked("pressure", "pool free-space floor reached")));
        }
        Ok(None)
    }

    pub(super) fn catalog_over_limit(&self, pool: &Pool) -> Result<bool, MError> {
        let entry = self.catalog_entry(pool)?;
        let machines = self.inner.machines.lock().unwrap();
        let usage = self.warm_usage(&machines)?;
        Ok(usage.counts.get(&entry.id).copied().unwrap_or(0) > usize::from(entry.max_ready))
    }

    pub(in crate::machine) fn admit_warm_policy(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        rec: &Record,
    ) -> Result<(), MError> {
        if rec.warm_slot.as_ref().is_some_and(|s| s.claimed.is_none()) {
            if let Some(reason) = self.policy_blocked(machines, Some(rec))? {
                return Err(MError::Capacity(format!(
                    "{}: {}",
                    reason.reason, reason.message
                )));
            }
        }
        Ok(())
    }

    pub async fn warm_catalog(&self, namespace: &str) -> Result<api::WarmCatalogStatus, MError> {
        check_namespace_id(namespace)?;
        let probe = self.warm_probe().await.err();
        let p = self.inner.warm_policy.lock().unwrap().clone();
        let machines = self.inner.machines.lock().unwrap();
        let usage = self.warm_usage(&machines)?;
        let mut blocked_ = self
            .policy_blocked(&machines, None)?
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(error) = probe {
            blocked_.push(blocked("pressure", &error.to_string()));
        }
        blocked_.extend(
            self.inner
                .store
                .list::<Pool>(POOLS)?
                .into_iter()
                .filter(|pool| pool.namespace == namespace)
                .filter_map(|pool| pool.blocked),
        );
        drop(machines);
        let sample = self.inner.warm_sample.lock().unwrap().clone();
        Ok(api::WarmCatalogStatus {
            entries: p
                .catalog
                .into_iter()
                .filter(|e| e.namespace == namespace)
                .collect(),
            budget: p.budget,
            charged: usage.charged,
            headroom: api::WarmResources {
                memory_mb: p.headroom.memory_mb,
                cpu_millis: p.headroom.cpu_millis,
                root_disk_gb: p.headroom.disk_free_gb,
            },
            min_mem_available_mb: p.min_mem_available_mb,
            max_fills: p.max_fills,
            fills: usage.fills,
            draining: usage.draining,
            memory_available_mb: sample.as_ref().map(|s| s.memory_mb),
            disk_free_bytes: sample.as_ref().map(|s| s.pool.free),
            measurement_age_ms: sample
                .as_ref()
                .map(|s| s.at.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
            blocked: blocked_,
            pools: self.warm_pools(namespace)?,
        })
    }

    pub async fn put_warm_catalog(
        &self,
        namespace: &str,
        id: &str,
        request: api::WarmDesiredRequest,
    ) -> Result<api::WarmPool, MError> {
        let entry = self
            .inner
            .warm_policy
            .lock()
            .unwrap()
            .catalog
            .iter()
            .find(|e| e.namespace == namespace && e.id == id)
            .cloned()
            .ok_or(MError::NotFound)?;
        self.put_warm_pool(
            namespace,
            id,
            api::PutWarmPoolRequest {
                source_machine: entry.source_machine,
                snapshot: entry.snapshot,
                desired: request.desired,
            },
        )
        .await
    }
}

fn mem_available(text: &str) -> Option<u32> {
    let line = text
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))?;
    let mut words = line.split_whitespace();
    words.next()?;
    let kb = words.next()?.parse::<u64>().ok()?;
    if words.next()? != "kB" || words.next().is_some() {
        return None;
    }
    (kb / 1024).try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mem_available_requires_exact_units_and_checked_numbers() {
        assert_eq!(mem_available("MemAvailable: 8192 kB\n"), Some(8));
        for text in [
            "MemFree: 8192 kB",
            "MemAvailable: 8 MB",
            "MemAvailable: -1 kB",
            "MemAvailable: 18446744073709551615 kB",
        ] {
            assert_eq!(mem_available(text), None);
        }
    }

    #[test]
    fn full_resource_addition_fails_closed_on_each_overflow() {
        for value in [
            api::WarmResources {
                memory_mb: u32::MAX,
                cpu_millis: 0,
                root_disk_gb: 0,
            },
            api::WarmResources {
                memory_mb: 0,
                cpu_millis: u32::MAX,
                root_disk_gb: 0,
            },
            api::WarmResources {
                memory_mb: 0,
                cpu_millis: 0,
                root_disk_gb: u32::MAX,
            },
        ] {
            assert!(add(
                value,
                api::WarmResources {
                    memory_mb: 1,
                    cpu_millis: 1,
                    root_disk_gb: 1
                }
            )
            .is_none());
        }
    }
}
