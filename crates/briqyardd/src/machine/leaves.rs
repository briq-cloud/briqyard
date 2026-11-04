//! A VMM's cgroup leaf goes once its VMM is gone (ADR 0098), not when the machine does.

use super::*;

/// Leaves one periodic pass retires at most; the rest wait for the next pass.
const RETIRES_PER_PASS: usize = 128;

/// What the last pass saw, for `/metrics`: all leaves, and those no running VMM explains.
#[derive(Clone, Copy, Default)]
pub struct Leaves {
    pub total: usize,
    pub idle: usize,
}

/// A machine with no VMM and no transition under way: its leaf, if any, is empty for good
/// until the next start.
fn idle(r: &Record, has_vm: bool) -> bool {
    matches!(
        r.state.as_str(),
        state::STOPPED | state::ERROR | state::CREATED
    ) && r.pid == 0
        && !has_vm
}

impl Manager {
    /// Removes the machine's leaf when it has no VMM: under its lock, taken without waiting
    /// (a start, a stop or a destroy under way owns the leaf, and the pass finds it later).
    /// The VMM's death and its OOM evidence were settled before this can succeed
    /// (`retire_cgroup` asks for the death proof, which the evidence read precedes). Its last
    /// CPU time is counted first, since the leaf is where it is read. `Ok(true)`: removed.
    pub(super) async fn retire_idle_leaf(&self, e: &Arc<Entry>) -> Result<bool> {
        let Ok(_turn) = e.lock.try_lock() else {
            return Ok(false);
        };
        let r = e.snapshot();
        if !self.holds(e) || !idle(&r, e.live.lock().unwrap().is_some()) {
            return Ok(false);
        }
        let jailed = self.jail_for(&r).is_some();
        let last = match self.inner.vmm.final_cgroup_use(&r.id, jailed)? {
            fc::FinalCgroupUse::Absent => return Ok(false),
            fc::FinalCgroupUse::Present(last) => last,
        };
        let used = {
            let mut m = e.meter.lock().unwrap();
            m.counters(Utc::now(), Some(last.cpu_usec), None, (0, 0));
            m.drain()
        };
        self.inner
            .usage
            .lock()
            .unwrap()
            .add(&usage_identity(&r), used);
        // Removing a cgroup can wait on the kernel; not on a runtime thread.
        let (vmm, id) = (self.inner.vmm.clone(), r.id.clone());
        tokio::task::spawn_blocking(move || vmm.retire_cgroup(&id, jailed)).await??;
        Ok(true)
    }

    /// After a VMM's exit is settled: its leaf goes now when it can. A refusal (the kernel
    /// still tearing the group down, a start already under way) is the next pass's.
    pub(super) async fn retire_after_exit(&self, e: &Arc<Entry>) {
        if self.recovery_fault().is_some() {
            return;
        }
        if let Err(err) = self.retire_idle_leaf(e).await {
            tracing::debug!(machine = e.snapshot().id, err = %format!("{err:#}"), "idle cgroup leaf stays for the next pass");
        }
    }

    /// Every pass (the tick): reads the VMM parent once, retires up to `RETIRES_PER_PASS`
    /// leaves of machines without a VMM, and publishes how many leaves there are and how many
    /// of them nothing explains. The cost follows the leaves present, never the history, and
    /// a leak shows in `briqyard_cgroup_leaves_idle` before it can stall a start.
    pub(super) async fn sweep_leaves(&self) {
        if self.recovery_fault().is_some() {
            return;
        }
        let names = match self.inner.vmm.cgroup_leaves().await {
            Ok(names) => names,
            Err(err) => {
                tracing::debug!(err = %format!("{err:#}"), "cgroup leaves not listed");
                *self.inner.stats.leaves.lock().unwrap() = None;
                return;
            }
        };
        let mut idle_entries = Vec::new();
        let mut unowned = 0;
        {
            let machines = self.inner.machines.lock().unwrap();
            for id in &names {
                match machines.get(id) {
                    Some(e) if idle(&e.snapshot(), e.live.lock().unwrap().is_some()) => {
                        idle_entries.push(e.clone())
                    }
                    Some(_) => {}
                    None => unowned += 1,
                }
            }
        }
        let (mut retired, mut failed) = (0, 0);
        for e in idle_entries.iter().take(RETIRES_PER_PASS) {
            match self.retire_idle_leaf(e).await {
                Ok(true) => retired += 1,
                Ok(false) => {}
                Err(err) => {
                    failed += 1;
                    tracing::debug!(machine = e.snapshot().id, err = %format!("{err:#}"), "idle cgroup leaf not removed");
                }
            }
        }
        let stats = &self.inner.stats;
        stats.leaves_retired.fetch_add(retired, Relaxed);
        stats.leaves_retire_failed.fetch_add(failed, Relaxed);
        let idle_left = idle_entries.len() as u64 - retired + unowned;
        *stats.leaves.lock().unwrap() = Some(Leaves {
            total: names.len() - retired as usize,
            idle: idle_left as usize,
        });
        if retired > 0 || failed > 0 {
            tracing::info!(
                retired,
                failed,
                idle = idle_left,
                leaves = names.len() as u64 - retired,
                "idle cgroup leaves"
            );
        }
    }
}
