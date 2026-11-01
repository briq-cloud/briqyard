use super::*;
use serde::Serialize;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::testutil::load;

    const POLICY: &str = "capacity: {memory_mb: 4096, vcpus: 4}\ntemplates:\n  enabled: true\n  warm_pools: true\n  warm_policy:\n    budget: {memory_mb: 2048, cpu_millis: 2000, root_disk_gb: 16}\n    headroom: {memory_mb: 512, cpu_millis: 1000, disk_free_gb: 8}\n    min_mem_available_mb: 512\n    max_fills: 1\n    catalog:\n      - id: shell-small\n        namespace: team\n        type: shell\n        source_machine: m_source\n        snapshot: s_one\n        generation: g_one\n        size: {memory_mb: 256, vcpus: 1, cpu_millis: 1000}\n        max_ready: 2\n";

    #[test]
    fn defaults_are_disabled_and_catalog_updates_are_strictly_validated() {
        let default = load("").unwrap();
        assert!(!default.templates.warm_pools);
        assert!(default.templates.warm_policy.catalog.is_empty());
        load(POLICY).unwrap();
        for (from, to) in [
            ("memory_mb: 2048", "memory_mb: 0"),
            ("max_fills: 1", "max_fills: 0"),
            ("max_ready: 2", "max_ready: 0"),
            ("vcpus: 1", "vcpus: 0"),
            ("generation: g_one", "generation: ../g_one"),
            ("type: shell", "unknown_type: shell"),
        ] {
            assert!(load(&POLICY.replace(from, to)).is_err(), "{to}");
        }
        let entry = POLICY.split("      - id:").nth(1).unwrap();
        assert!(load(&format!("{POLICY}      - id:{entry}")).is_err());
        assert!(
            load(&POLICY.replace("memory_mb: 4096, vcpus: 4", "memory_mb: 2048, vcpus: 2"))
                .is_err()
        );
        let p = load(POLICY).unwrap().templates.warm_policy;
        assert!(p
            .check_capacity(api::Capacity {
                memory_mb: u32::MAX,
                vcpus: 4,
                cpu_millis: None
            })
            .is_ok());
        let mut overflow = p;
        overflow.budget.memory_mb = u32::MAX;
        assert!(overflow
            .check_capacity(api::Capacity {
                memory_mb: u32::MAX,
                vcpus: 4,
                cpu_millis: None
            })
            .is_err());
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WarmPolicy {
    pub budget: api::WarmResources,
    pub headroom: WarmHeadroom,
    pub min_mem_available_mb: u32,
    pub max_fills: u16,
    pub catalog: Vec<api::WarmCatalogEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WarmHeadroom {
    pub memory_mb: u32,
    pub cpu_millis: u32,
    pub disk_free_gb: u32,
}

impl WarmPolicy {
    pub(crate) fn check_capacity(&self, capacity: api::Capacity) -> Result<()> {
        let memory = self.budget.memory_mb.checked_add(self.headroom.memory_mb);
        let cpu = self.budget.cpu_millis.checked_add(self.headroom.cpu_millis);
        if memory.is_none_or(|n| n > capacity.memory_mb)
            || cpu.is_none_or(|n| n > capacity.cpu_millis())
        {
            bail!("templates.warm_policy: budget and headroom exceed finite host capacity");
        }
        Ok(())
    }

    pub(super) fn check(&self, enabled: bool) -> Result<()> {
        if self.catalog.is_empty()
            && !enabled
            && self.budget == api::WarmResources::default()
            && self.headroom.memory_mb == 0
            && self.headroom.cpu_millis == 0
            && self.headroom.disk_free_gb == 0
            && self.min_mem_available_mb == 0
            && self.max_fills == 0
        {
            return Ok(());
        }
        let b = self.budget;
        if b.memory_mb == 0
            || b.cpu_millis == 0
            || b.root_disk_gb == 0
            || self.headroom.memory_mb == 0
            || self.headroom.cpu_millis == 0
            || self.headroom.disk_free_gb == 0
            || self.min_mem_available_mb == 0
            || self.max_fills == 0
            || self.max_fills > 32
        {
            bail!("templates.warm_policy requires positive budgets, headroom, memory floor and max_fills 1..32");
        }
        let mut ids = std::collections::HashSet::new();
        let mut bindings = std::collections::HashSet::new();
        for e in &self.catalog {
            e.size.check().map_err(anyhow::Error::msg)?;
            if !api::valid_name(&e.id)
                || !api::valid_id(&e.namespace)
                || !api::valid_id(&e.source_machine)
                || !api::valid_id(&e.snapshot)
                || !api::valid_id(&e.generation)
                || !api::valid_name(&e.kind)
                || e.max_ready == 0
                || !ids.insert(e.id.clone())
                || !bindings.insert((&e.namespace, &e.source_machine, &e.snapshot))
            {
                bail!("templates.warm_policy.catalog: invalid or duplicate binding");
            }
        }
        Ok(())
    }
}
