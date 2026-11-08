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
    /// Nobody can state what this machine holds: a launch that failed with no proof its VMM
    /// never started, or a handle still live on a record that says `error` (its process could
    /// not be ended). A live handle on a stopped or leaving record is a transient with a known
    /// charge, which `commits_memory` counts.
    pub(super) fn unresolved_launch(&self) -> bool {
        self.launch_unproven
            .load(std::sync::atomic::Ordering::SeqCst)
            || (self.live.lock().unwrap().is_some() && self.snapshot().state == state::ERROR)
    }
    /// A destroying machine keeps its charge while its ownership is unresolved (ADR 0068). Once
    /// its process death is proven and its leaf retired, nothing of it holds memory (a clone's
    /// mapping exit was proven before that), and the disk teardown, which can queue behind
    /// many others, no longer counts. What no destroy decides stays: an assignment not yet
    /// settled, a launch pending, a live handle.
    pub(super) fn commits_memory(&self, rec: &Record) -> bool {
        let record = if rec.state == state::DESTROYING
            && self.leaf_retired.load(std::sync::atomic::Ordering::SeqCst)
        {
            rec.assigned_run.as_ref().is_some_and(run_unsettled)
        } else {
            commits_memory(rec) || rec.state == state::DESTROYING
        };
        record
            || self
                .launch_pending
                .load(std::sync::atomic::Ordering::SeqCst)
            || self.live.lock().unwrap().is_some()
    }
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
    /// Mark ownership before entering the factory, including a legacy resume fallback.
    pub(super) async fn boot_reserved(&self, e: &Entry, boot: &fc::Boot) -> Result<fc::Vm> {
        use std::sync::atomic::Ordering::SeqCst;
        e.leaf_retired.store(false, SeqCst);
        e.launch_unproven.store(false, SeqCst);
        e.launch_pending.store(true, SeqCst);
        let result = self.inner.vmm.boot(boot).await;
        if result.is_err() {
            let unproven =
                self.inner.vmm.launch_settlement(&boot.id) != fc::LaunchSettlement::Settled;
            e.launch_unproven.store(unproven, SeqCst);
            e.launch_pending.store(unproven, SeqCst);
        }
        result
    }

    /// Requires the entry lifecycle lock: a concurrent boot must not expose its previous
    /// settled epoch between setting the reservation and invalidating the factory epoch.
    pub(super) fn refresh_launch_reservation(&self, e: &Entry) {
        if e.launch_pending.load(std::sync::atomic::Ordering::SeqCst)
            && self.inner.vmm.launch_settlement(&e.snapshot().id) == fc::LaunchSettlement::Settled
        {
            e.launch_pending
                .store(false, std::sync::atomic::Ordering::SeqCst);
            e.launch_unproven
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
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
        self.memory_admission_for(machines, false)
    }

    /// `admitted`: the machine's own memory is counted already (a create's start, ADR 0048).
    /// It was admitted against this host a moment ago, and a charge somebody else cannot state
    /// must not strand it in `error`; the host-level refusals still apply.
    pub(super) fn memory_admission_for(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        admitted: bool,
    ) -> Result<(), MError> {
        if let Some(reason) = self.recovery_fault() {
            return Err(MError::Capacity(format!("startup: {reason}")));
        }
        if let Some(reason) = *self.inner.memory_host.lock().unwrap() {
            let hint = if reason == memory_host::CAPACITY_EXCEEDS_PHYSICAL {
                " (capacity.memory_mb + capacity.reserved_memory_mb + the ZFS cache ceiling must fit in physical memory: lower capacity.memory_mb or capacity.reserved_memory_mb)"
            } else {
                ""
            };
            return Err(MError::Capacity(format!(
                "host memory prerequisite: {reason}{hint}"
            )));
        }
        // A boot in flight or a destroy in its grace has a known charge, already counted by
        // `committed`. Only a charge nobody can state refuses every admission: a launch that
        // failed with no proof its VMM never started, a ceiling that overflows.
        if !admitted
            && machines.values().any(|e| {
                e.unresolved_launch()
                    || (e.commits_memory(&e.snapshot())
                        && e.memory_protection
                            .lock()
                            .unwrap()
                            .as_ref()
                            .is_some_and(|p| p.charge_mb == u32::MAX))
            })
        {
            return Err(MError::Capacity(
                "live VMM memory protection unresolved".into(),
            ));
        }
        Ok(())
    }
}
