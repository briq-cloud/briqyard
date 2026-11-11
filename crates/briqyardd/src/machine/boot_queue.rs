//! The boot queue (ADR 0130): the boots a host has accepted that have not left the boot gate.
//! The heartbeat reports its depth next to the gate's size, so the fleet can tell a host with
//! room that is already booting many machines from an idle one.

use super::*;

/// One boot's place in the queue. The machine's flag says whether it holds one, so a create
/// that starts its machine counts once, and whoever clears the flag gives the place back once.
pub(super) struct BootQueued {
    manager: Manager,
    entry: Arc<Entry>,
    /// This guard took the place, so it gives it back when dropped.
    owner: bool,
}

impl Drop for BootQueued {
    fn drop(&mut self) {
        if self.owner {
            self.manager.boot_left(&self.entry);
        }
    }
}

/// A turn at the boot gate. The boot leaves the queue when the turn ends, with the permit.
pub(super) struct BootTurn<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
    manager: &'a Manager,
    entry: &'a Entry,
}

impl Drop for BootTurn<'_> {
    fn drop(&mut self) {
        self.manager.boot_left(self.entry);
    }
}

impl Manager {
    /// Waits for a turn at the boot gate (ADR 0129) for a boot already counted by `boot_queued`.
    pub(super) async fn boot_turn<'a>(
        &'a self,
        e: &'a Entry,
    ) -> Result<BootTurn<'a>, tokio::sync::AcquireError> {
        Ok(BootTurn {
            _permit: self.inner.boot_gate.acquire().await?,
            manager: self,
            entry: e,
        })
    }

    /// Counts a boot of `e` from now until its turn at the gate ends (`BootTurn`) or the guard
    /// goes, whichever comes first. A machine already counted (its create) is not counted twice.
    pub(super) fn boot_queued(&self, e: &Arc<Entry>) -> BootQueued {
        let owner = !e.boot_queued.swap(true, Relaxed);
        if owner {
            self.inner.boot_queue.fetch_add(1, Relaxed);
        }
        BootQueued {
            manager: self.clone(),
            entry: e.clone(),
            owner,
        }
    }

    /// The machine's boot is out of the gate, or gone: its place is given back, once.
    pub(super) fn boot_left(&self, e: &Entry) {
        if e.boot_queued.swap(false, Relaxed) {
            self.inner.boot_queue.fetch_sub(1, Relaxed);
        }
    }

    /// Boots accepted and not yet out of the gate: those holding a turn and those waiting.
    pub fn boot_queue(&self) -> u32 {
        self.inner.boot_queue.load(Relaxed)
    }

    /// How many boots the gate lets through at once (ADR 0129).
    pub fn boots_at_once(&self) -> u32 {
        self.inner.boots_at_once
    }
}
