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

/// The forwards open for each restore, each with its id and deadline: two forwards of the same
/// restore at once each get their ask.
#[derive(Default)]
struct Open {
    next: u64,
    by: HashMap<Restore, Vec<(u64, Instant)>>,
}

impl Open {
    fn prune(&mut self, now: Instant) {
        self.by.retain(|_, v| {
            v.retain(|(_, deadline)| *deadline > now);
            !v.is_empty()
        });
    }

    fn len(&self) -> usize {
        self.by.values().map(Vec::len).sum()
    }
}

#[derive(Default)]
pub struct Restores {
    open: Mutex<Open>,
}

/// One forward of a restore, from `open`, for its `close`.
pub struct Forward(Restore, u64);

fn restore(host: &str, rs: &api::RestoreSpec) -> Restore {
    (host.to_string(), rs.machine_id.clone(), rs.backup.clone())
}

impl Restores {
    /// A restore forwarded to `host` at `now`.
    pub fn open(&self, host: &str, rs: &api::RestoreSpec, now: Instant) -> Forward {
        let mut open = self.open.lock().unwrap();
        open.prune(now);
        if open.len() >= MAX {
            let first = open
                .by
                .iter()
                .flat_map(|(r, v)| v.iter().map(move |(id, d)| (*d, r.clone(), *id)))
                .min_by_key(|(d, _, _)| *d);
            if let Some((_, r, id)) = first {
                open.by.entry(r).or_default().retain(|(i, _)| *i != id);
                open.prune(now);
            }
        }
        open.next += 1;
        let id = open.next;
        let r = restore(host, rs);
        open.by
            .entry(r.clone())
            .or_default()
            .push((id, now + WITHIN));
        Forward(r, id)
    }

    /// The forward is over: whatever it did not ask for, it no longer can.
    pub fn close(&self, f: Forward) {
        let mut open = self.open.lock().unwrap();
        if let Some(v) = open.by.get_mut(&f.0) {
            v.retain(|(id, _)| *id != f.1);
            if v.is_empty() {
                open.by.remove(&f.0);
            }
        }
    }

    /// Whether `host` has this restore open at `now`; one forward of it is taken, so a key is
    /// served once per forward.
    pub fn take(&self, host: &str, rs: &api::RestoreSpec, now: Instant) -> bool {
        let mut open = self.open.lock().unwrap();
        open.prune(now);
        let r = restore(host, rs);
        let Some(v) = open.by.get_mut(&r) else {
            return false;
        };
        v.remove(0);
        if v.is_empty() {
            open.by.remove(&r);
        }
        true
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
        let f = r.open("h1", &rs("m_1", "b1"), now);
        assert!(!r.take("h2", &rs("m_1", "b1"), now), "another host");
        assert!(!r.take("h1", &rs("m_1", "b2"), now), "another backup");
        assert!(!r.take("h1", &rs("m_2", "b1"), now), "another machine");
        assert!(r.take("h1", &rs("m_1", "b1"), now));
        assert!(!r.take("h1", &rs("m_1", "b1"), now), "served once");
        r.close(f);
        r.open("h1", &rs("m_1", "b1"), now);
        assert!(!r.take("h1", &rs("m_1", "b1"), now + WITHIN), "expired");
        let f = r.open("h1", &rs("m_1", "b1"), now);
        r.close(f);
        assert!(
            !r.take("h1", &rs("m_1", "b1"), now),
            "closed with its forward"
        );
    }

    /// Two forwards of the same restore at once each get their ask, whichever asks first, and
    /// one closing leaves the other's.
    #[test]
    fn concurrent_forwards_of_one_restore_each_get_their_ask() {
        let r = Restores::default();
        let now = Instant::now();
        let a = r.open("h1", &rs("m_1", "b1"), now);
        let b = r.open("h1", &rs("m_1", "b1"), now);
        assert!(r.take("h1", &rs("m_1", "b1"), now), "b asks first");
        r.close(a);
        assert!(r.take("h1", &rs("m_1", "b1"), now), "a's ask still served");
        assert!(!r.take("h1", &rs("m_1", "b1"), now));
        r.close(b);
        let a = r.open("h1", &rs("m_1", "b1"), now);
        let _b = r.open("h1", &rs("m_1", "b1"), now);
        r.close(a);
        assert!(
            r.take("h1", &rs("m_1", "b1"), now),
            "b's kept when a closes unasked"
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
