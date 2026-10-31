//! Physical host reservations and protection failures, separate from namespace quota use.
use super::*;

impl Record {
    pub(super) fn oom_class(&self) -> briqyard_api::host_process::OomClass {
        use briqyard_api::host_process::OomClass;
        match self.role {
            Some(Role::Gateway) => OomClass::Gateway,
            None => OomClass::Machine,
        }
    }
}

pub(super) fn host_memory(guest_mb: u32) -> Result<u32, MError> {
    api::vmm_memory_mb(guest_mb).ok_or_else(|| invalid("VMM memory ceiling overflow"))
}

impl Entry {
    /// A positive live adoption may have a larger or unknown existing ceiling.
    pub(super) fn memory_charge(&self, rec: &Record) -> u32 {
        let expected = api::vmm_memory_mb(rec.size.memory_mb).unwrap_or(u32::MAX);
        self.memory_protection
            .lock()
            .unwrap()
            .as_ref()
            .map_or(expected, |p| expected.max(p.charge_mb))
    }
}

impl Manager {
    pub(super) fn retain_memory_policy(&self, e: &Entry, vm: &fc::Vm) {
        let rec = e.snapshot();
        let policy = self.inner.vmm.memory_policy(
            vm,
            &rec.id,
            self.jail_for(&rec).is_some(),
            api::vmm_memory_mb(rec.size.memory_mb).unwrap_or(u32::MAX),
            rec.oom_class(),
        );
        let policy = if api::vmm_memory_mb(rec.size.memory_mb).is_none() {
            fc::MemoryProtection {
                charge_mb: u32::MAX,
                degraded: Some("vmm_ceiling_overflow"),
                contained: false,
            }
        } else {
            policy
        };
        if let Some(reason) = policy.degraded {
            tracing::warn!(
                machine = rec.id,
                reason,
                "live VMM retained with degraded memory protection"
            );
        }
        *e.memory_protection.lock().unwrap() = Some(policy);
    }

    pub(super) fn memory_admission(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
    ) -> Result<(), MError> {
        if let Some(reason) = *self.inner.memory_host.lock().unwrap() {
            return Err(MError::Capacity(format!(
                "host memory prerequisite: {reason}"
            )));
        }
        if machines.values().any(|e| {
            commits_memory(&e.snapshot())
                && e.memory_protection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|p| p.degraded.is_some())
        }) {
            return Err(MError::Capacity(
                "live VMM memory protection unresolved".into(),
            ));
        }
        Ok(())
    }
}
