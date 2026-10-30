//! The builds under way on a host, one per image key.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::watch;

/// The builds under way, by key: a waiter clones the receiver and is woken when the
/// builder's sender drops, which happens whether the build finished or its future was
/// dropped. The receiver is taken under the lock, so a wake-up is never missed.
pub(super) type Builds = Mutex<HashMap<String, watch::Receiver<()>>>;

/// A build's hold on its key, freed on drop: a build whose future is dropped half way (the
/// request that asked for it went away) never leaves later creates waiting for it.
pub(super) struct BuildSlot<'a> {
    building: &'a Builds,
    key: String,
    _done: watch::Sender<()>,
}

impl Drop for BuildSlot<'_> {
    // The key is freed before `_done` drops and wakes the waiters, so a woken waiter that
    // takes a turn finds it free.
    fn drop(&mut self) {
        self.building.lock().unwrap().remove(&self.key);
    }
}

pub(super) enum Turn<'a> {
    Build(BuildSlot<'a>),
    Wait(watch::Receiver<()>),
}

/// Takes the build of `key`, or a ticket to wait for the one under way.
pub(super) fn take<'a>(building: &'a Builds, key: &str) -> Turn<'a> {
    let mut b = building.lock().unwrap();
    if let Some(rx) = b.get(key) {
        return Turn::Wait(rx.clone());
    }
    let (tx, rx) = watch::channel(());
    b.insert(key.to_string(), rx);
    Turn::Build(BuildSlot {
        building,
        key: key.to_string(),
        _done: tx,
    })
}
