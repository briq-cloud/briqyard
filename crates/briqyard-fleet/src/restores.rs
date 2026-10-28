//! Restores in flight (ADR 0035): the fleet notes each create with `restore` it forwards to a
//! host, and serves a backup's pool key only to that host, for that restore, once. In memory:
//! a fleet restarted mid-restore refuses the key, the create fails, and the caller tries again.

use briqyard_api as api;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a forwarded restore may take to ask for its key.
const WITHIN: Duration = Duration::from_secs(15 * 60);
/// Restores open at once, at most: past it, the one closest to its deadline goes.
const MAX: usize = 4096;

/// A restore: the host it was forwarded to, the machine and the backup it names.
type Restore = (String, String, String);

#[derive(Default)]
pub struct Restores {
    open: Mutex<HashMap<Restore, Instant>>,
}

fn restore(host: &str, rs: &api::RestoreSpec) -> Restore {
    (host.to_string(), rs.machine_id.clone(), rs.backup.clone())
}

impl Restores {
    /// A restore forwarded to `host` at `now`.
    pub fn open(&self, host: &str, rs: &api::RestoreSpec, now: Instant) {
        let mut open = self.open.lock().unwrap();
        open.retain(|_, deadline| *deadline > now);
        if open.len() >= MAX {
            if let Some(first) = open.iter().min_by_key(|(_, d)| **d).map(|(r, _)| r.clone()) {
                open.remove(&first);
            }
        }
        open.insert(restore(host, rs), now + WITHIN);
    }

    /// The forward is over: whatever it did not ask for, it no longer can.
    pub fn close(&self, host: &str, rs: &api::RestoreSpec) {
        self.open.lock().unwrap().remove(&restore(host, rs));
    }

    /// Whether `host` has this restore open at `now`; taken, so a key is served once.
    pub fn take(&self, host: &str, rs: &api::RestoreSpec, now: Instant) -> bool {
        self.open
            .lock()
            .unwrap()
            .remove(&restore(host, rs))
            .is_some_and(|deadline| deadline > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(m: &str, b: &str) -> api::RestoreSpec {
        api::RestoreSpec {
            machine_id: m.into(),
            backup: b.into(),
        }
    }

    #[test]
    fn a_restore_is_served_once_to_its_host_for_its_backup_before_its_deadline() {
        let r = Restores::default();
        let now = Instant::now();
        assert!(!r.take("h1", &rs("m_1", "b1"), now), "no entry");
        r.open("h1", &rs("m_1", "b1"), now);
        assert!(!r.take("h2", &rs("m_1", "b1"), now), "another host");
        assert!(!r.take("h1", &rs("m_1", "b2"), now), "another backup");
        assert!(!r.take("h1", &rs("m_2", "b1"), now), "another machine");
        assert!(r.take("h1", &rs("m_1", "b1"), now));
        assert!(!r.take("h1", &rs("m_1", "b1"), now), "served once");
        r.open("h1", &rs("m_1", "b1"), now);
        assert!(!r.take("h1", &rs("m_1", "b1"), now + WITHIN), "expired");
        r.open("h1", &rs("m_1", "b1"), now);
        r.close("h1", &rs("m_1", "b1"));
        assert!(
            !r.take("h1", &rs("m_1", "b1"), now),
            "closed with its forward"
        );
    }

    #[test]
    fn open_restores_are_bounded() {
        let r = Restores::default();
        let now = Instant::now();
        for i in 0..MAX + 10 {
            r.open(
                "h",
                &rs(&format!("m_{i}"), ""),
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(r.open.lock().unwrap().len(), MAX);
        assert!(!r.take("h", &rs("m_0", ""), now), "the oldest went");
        assert!(r.take("h", &rs(&format!("m_{}", MAX + 9), ""), now));
        // Expired ones go first.
        r.open(
            "h",
            &rs("late", ""),
            now + WITHIN + Duration::from_secs(3600),
        );
        assert_eq!(r.open.lock().unwrap().len(), 1);
    }
}
