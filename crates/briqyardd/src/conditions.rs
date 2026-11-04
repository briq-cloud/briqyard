//! The host's conditions (ADR 0021): memory and disk pressure, decided by the tick on what it
//! measured, and a stalled pool (ADR 0046). Each is a pressure: true is trouble.

use crate::config;
use crate::zfs::Pool;
use briqyard_api::{self as api, condition};
use chrono::{DateTime, Utc};

const GB: f64 = (1u64 << 30) as f64;

/// The conditions as the tick last decided them.
#[derive(Clone, Debug)]
pub struct Conditions {
    list: Vec<api::Condition>,
}

impl Conditions {
    /// Every condition false since `now`: the daemon's start, until a tick says otherwise.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            list: condition::ALL
                .iter()
                // Live process protection and fleet holds are derived separately.
                .filter(|k| {
                    ![condition::MEMORY_PROTECTION, condition::MEMORY_ACCOUNTING].contains(k)
                })
                .map(|k| api::Condition {
                    kind: k.to_string(),
                    status: false,
                    since: now,
                    message: "not measured yet".into(),
                })
                .collect(),
        }
    }

    pub fn list(&self) -> Vec<api::Condition> {
        self.list.clone()
    }

    /// Sets a condition to what the tick found: the message always, `since` when the status
    /// changed. Returns the condition when it did.
    pub fn set(
        &mut self,
        kind: &str,
        (status, message): (bool, String),
        now: DateTime<Utc>,
    ) -> Option<api::Condition> {
        let c = self.list.iter_mut().find(|c| c.kind == kind)?;
        c.message = message;
        if c.status == status {
            return None;
        }
        c.status = status;
        c.since = now;
        Some(c.clone())
    }
}

/// `memory_pressure`: what running machines reserved over `memory_pct` of capacity.
pub fn memory(committed_mb: u32, capacity_mb: u32, t: &config::Conditions) -> (bool, String) {
    let (used, cap) = (committed_mb as u64, capacity_mb.max(1) as u64);
    let pct = used * 100 / cap;
    let over = used * 100 > t.memory_pct as u64 * cap;
    let mut msg = format!("{used} MB of {cap} committed ({pct}%)");
    if over {
        msg.push_str(&format!(", over {}%", t.memory_pct));
    }
    (over, msg)
}

/// What the pool lacks to be back at `disk_free_pct` free, in bytes; 0 when it is there.
pub fn disk_short(pool: Pool, t: &config::Conditions) -> u64 {
    (pool.size() * t.disk_free_pct as u64)
        .div_ceil(100)
        .saturating_sub(pool.free)
}

/// `disk_pressure`: the pool's free space under `disk_free_pct` of its size.
pub fn disk(pool: Pool, t: &config::Conditions) -> (bool, String) {
    let under = disk_short(pool, t) > 0;
    let pct = pool.free * 100 / pool.size().max(1);
    let mut msg = format!(
        "pool {:.1} GB free of {:.1} ({pct}%)",
        pool.free as f64 / GB,
        pool.size() as f64 / GB
    );
    if under {
        msg.push_str(&format!(", under {}%", t.disk_free_pct));
    }
    (under, msg)
}

/// `storage_stalled`: a `zfs` command has run past `zfs::STALL_AFTER` (ADR 0046), the oldest.
pub fn storage(stalled: Option<(std::time::Duration, String)>) -> (bool, String) {
    match stalled {
        Some((ran, what)) => (true, format!("{what} running for {} s", ran.as_secs())),
        None => (
            false,
            format!(
                "no zfs command running for over {} s",
                crate::zfs::STALL_AFTER.as_secs()
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    const DEFAULT: config::Conditions = config::Conditions {
        memory_pct: 95,
        disk_free_pct: 10,
    };

    #[test]
    fn memory_is_under_pressure_over_its_share() {
        assert_eq!(
            memory(950, 1000, &DEFAULT),
            (false, "950 MB of 1000 committed (95%)".into())
        );
        assert_eq!(
            memory(951, 1000, &DEFAULT),
            (true, "951 MB of 1000 committed (95%), over 95%".into())
        );
        // A host with no capacity is never divided by zero.
        assert!(memory(1, 0, &DEFAULT).0);
    }

    #[test]
    fn disk_is_under_pressure_under_its_free_share() {
        let gb = 1u64 << 30;
        let pool = |used: u64, free: u64| Pool {
            used: used * gb,
            free: free * gb,
        };
        assert_eq!(
            disk(pool(90, 10), &DEFAULT),
            (false, "pool 10.0 GB free of 100.0 (10%)".into())
        );
        assert_eq!(disk_short(pool(90, 10), &DEFAULT), 0);
        assert_eq!(
            disk(pool(92, 8), &DEFAULT),
            (true, "pool 8.0 GB free of 100.0 (8%), under 10%".into())
        );
        // What image removal has to free: back to 10 GB.
        assert_eq!(disk_short(pool(92, 8), &DEFAULT), 2 * gb);
        // A byte short is short.
        let p = Pool {
            used: 90 * gb + 1,
            free: 10 * gb - 1,
        };
        assert_eq!(disk_short(p, &DEFAULT), 1);
        // 0% never presses.
        let none = config::Conditions {
            disk_free_pct: 0,
            ..DEFAULT
        };
        assert!(!disk(pool(100, 0), &none).0);
    }

    #[test]
    fn storage_is_stalled_by_its_oldest_command() {
        let ran = std::time::Duration::from_secs(75);
        assert_eq!(
            storage(Some((ran, "zfs snapshot byard/m/m_1/root@fork-x".into()))),
            (
                true,
                "zfs snapshot byard/m/m_1/root@fork-x running for 75 s".into()
            )
        );
        assert_eq!(
            storage(None),
            (false, "no zfs command running for over 60 s".into())
        );
    }

    #[test]
    fn a_condition_changes_once_and_keeps_its_message_fresh() {
        let mut c = Conditions::new(t("2026-10-21T10:00:00Z"));
        assert_eq!(api::under_pressure(&c.list()), None);
        assert_eq!(c.list().len(), 3);
        // The same status: no change, the message follows the figures.
        let same = c.set(
            condition::DISK_PRESSURE,
            (false, "pool 50% free".into()),
            t("2026-10-21T10:00:15Z"),
        );
        assert_eq!(same, None);
        assert_eq!(c.list()[1].message, "pool 50% free");
        assert_eq!(c.list()[1].since, t("2026-10-21T10:00:00Z"));
        let on = c
            .set(
                condition::DISK_PRESSURE,
                (true, "pool 5% free".into()),
                t("2026-10-21T10:00:30Z"),
            )
            .unwrap();
        assert_eq!(
            (on.kind.as_str(), on.status, on.since),
            ("disk_pressure", true, t("2026-10-21T10:00:30Z"))
        );
        assert_eq!(
            api::under_pressure(&c.list()).map(|c| c.kind.as_str()),
            Some(condition::DISK_PRESSURE)
        );
        assert!(!c.list()[0].status, "memory as it was");
        let off = c
            .set(
                condition::DISK_PRESSURE,
                (false, "pool 20% free".into()),
                t("2026-10-21T10:01:00Z"),
            )
            .unwrap();
        assert!(!off.status);
        assert_eq!(
            c.set("pid_pressure", (true, String::new()), Utc::now()),
            None
        );
    }
}
