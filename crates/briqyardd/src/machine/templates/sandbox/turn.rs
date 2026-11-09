//! One turn per sandbox request: creates and lookups of one (namespace, request id) take turns,
//! so a retry never reads a machine whose durable writes are still running.
use super::*;

type Key = (String, String);
type Lane = Arc<tokio::sync::Mutex<()>>;

/// The requests that have a holder or a waiter now. A request leaves the map when its last
/// holder or waiter lets go of it.
#[derive(Default)]
pub(in crate::machine) struct Turns {
    lanes: Mutex<HashMap<Key, Lane>>,
}

/// Held until dropped; the next in line for the same request then goes.
pub(in crate::machine) struct Turn<'a> {
    turns: &'a Turns,
    key: Key,
    lane: Lane,
    held: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Turns {
    pub(in crate::machine) async fn take(&self, namespace: &str, request_id: &str) -> Turn<'_> {
        let key = (namespace.to_string(), request_id.to_string());
        let lane = self
            .lanes
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_default()
            .clone();
        // Built before the wait: a caller dropped while waiting still cleans up after itself.
        let mut turn = Turn {
            turns: self,
            key,
            lane,
            held: None,
        };
        turn.held = Some(turn.lane.clone().lock_owned().await);
        turn
    }

    #[cfg(test)]
    pub(in crate::machine) fn len(&self) -> usize {
        self.lanes.lock().unwrap().len()
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        self.held = None;
        let mut lanes = self.turns.lanes.lock().unwrap();
        // Two owners are the map and this turn: nobody else holds or waits.
        if Arc::strong_count(&self.lane) == 2 {
            lanes.remove(&self.key);
        }
    }
}
