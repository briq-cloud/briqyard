//! In-memory observation of the same records and durable receipts used by admission.
use super::*;

impl Manager {
    pub(in crate::machine) fn warm_metrics(&self) -> metrics::warm::Snapshot {
        let policy = self.inner.warm_policy.lock().unwrap().clone();
        let probe = self
            .inner
            .warm_sample
            .lock()
            .unwrap()
            .as_ref()
            .map(|sample| {
                let age = sample.at.elapsed();
                metrics::warm::Probe {
                    age,
                    memory_mb: sample.memory_mb,
                    disk_free_bytes: sample.pool.free,
                    valid: age <= policy::MAX_SAMPLE_AGE,
                }
            });
        let mut snapshot = metrics::warm::Snapshot {
            budget: policy.budget,
            headroom: api::WarmResources {
                memory_mb: policy.headroom.memory_mb,
                cpu_millis: policy.headroom.cpu_millis,
                root_disk_gb: policy.headroom.disk_free_gb,
            },
            memory_floor_mb: policy.min_mem_available_mb,
            max_fills: policy.max_fills,
            probe,
            ..Default::default()
        };
        let machines = self.inner.machines.lock().unwrap();
        let Some(pools) = self
            .inner
            .warm_pool_cache
            .lock()
            .unwrap()
            .as_ref()
            .map(|cache| cache.values().cloned().collect::<Vec<_>>())
        else {
            return snapshot;
        };
        let Ok(usage) = self.warm_usage_from(&machines, &pools) else {
            return snapshot;
        };
        let mut rows = BTreeMap::new();
        for pool in &pools {
            let Ok(pool_key) = key(&pool.namespace, &pool.name) else {
                return snapshot;
            };
            let entry = self.catalog_entry(pool).ok();
            rows.insert(
                pool_key,
                metrics::warm::Pool {
                    namespace: pool.namespace.clone(),
                    name: pool.name.clone(),
                    catalog: entry.as_ref().map_or("unconfigured", |e| &e.id).into(),
                    kind: entry.as_ref().map_or("unconfigured", |e| &e.kind).into(),
                    size: pool.artifact.recipe.size,
                    desired: if pool.closed { 0 } else { pool.desired },
                    ceiling: entry.as_ref().map_or(0, |e| e.max_ready),
                    slots: [0; 5],
                    charged: Default::default(),
                    blocked: pool.blocked.as_ref().map(|b| b.reason.clone()),
                },
            );
        }
        let claimed: std::collections::HashSet<_> = pools
            .iter()
            .flat_map(|pool| pool.claims.values().map(|claim| claim.machine.as_str()))
            .collect();
        for machine in machines.values() {
            let record = machine.rec.lock().unwrap();
            let Some(slot) = &record.warm_slot else {
                continue;
            };
            let Some(row) = rows.get_mut(&slot.pool) else {
                return snapshot;
            };
            let owned = slot.claimed.is_some() || claimed.contains(record.id.as_str());
            let state = if owned {
                2
            } else if record.state == state::DESTROYING {
                3
            } else if ready_slot(&record) {
                1
            } else if matches!(record.state.as_str(), state::CREATING | state::STARTING) {
                0
            } else {
                4
            };
            row.slots[state] += 1;
            if !owned {
                let Some(charged) = policy::add(row.charged, policy::resources(&record)) else {
                    return snapshot;
                };
                row.charged = charged;
            }
        }
        snapshot.available = true;
        snapshot.charged = usage.charged;
        snapshot.fills = usage.fills;
        snapshot.pools = rows.into_values().collect();
        snapshot
    }
}
