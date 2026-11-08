//! The registry behind its lock, with a count of the times it was borrowed for a change.

use super::Registry;
use std::ops::{Deref, DerefMut};
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

struct Tracked {
    reg: Registry,
    /// Raised by every `DerefMut` of a guard: a change was possible, so a writer that last
    /// wrote an equal count has nothing new to write (ADR 0119).
    rev: u64,
}

/// The registry's lock. A guard reads through `Deref` and changes through `DerefMut`, which
/// counts: no code can change the registry without the count moving, and the count is read
/// under the same lock as the registry it describes.
pub struct RegLock(Mutex<Tracked>);

pub struct RegGuard<'a>(MutexGuard<'a, Tracked>);

impl RegLock {
    pub fn new(reg: Registry) -> Self {
        // 1, not 0: a writer's "last written" starts at 0, so the first write is never skipped.
        RegLock(Mutex::new(Tracked { reg, rev: 1 }))
    }

    pub fn lock(&self) -> LockResult<RegGuard<'_>> {
        self.0
            .lock()
            .map(RegGuard)
            .map_err(|e| PoisonError::new(RegGuard(e.into_inner())))
    }
}

impl RegGuard<'_> {
    /// How many times the registry was borrowed for a change, up to now.
    pub fn rev(&self) -> u64 {
        self.0.rev
    }
}

impl Deref for RegGuard<'_> {
    type Target = Registry;
    fn deref(&self) -> &Registry {
        &self.0.reg
    }
}

impl DerefMut for RegGuard<'_> {
    fn deref_mut(&mut self) -> &mut Registry {
        self.0.rev += 1;
        &mut self.0.reg
    }
}
