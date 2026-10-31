//! FIFO increments accumulate across flushes, like disk counters.

use super::*;
use chrono::{DateTime, Utc};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct BalloonCounters {
    updates: AtomicU64,
    update_failures: AtomicU64,
    reports: AtomicU64,
    reported_bytes: AtomicU64,
    report_failures: AtomicU64,
    last_update: Mutex<Option<DateTime<Utc>>>,
}

impl BalloonCounters {
    pub(super) fn add(&self, v: &serde_json::Value) {
        let n = |key: &str| v[key].as_u64().unwrap_or(0);
        let updates = n("stats_updates_count");
        self.updates.fetch_add(updates, Relaxed);
        if updates > 0 {
            *self.last_update.lock().unwrap() = Some(Utc::now());
        }
        self.update_failures
            .fetch_add(n("stats_update_fails"), Relaxed);
        self.reports.fetch_add(n("free_page_report_count"), Relaxed);
        self.reported_bytes
            .fetch_add(n("free_page_report_freed"), Relaxed);
        self.report_failures
            .fetch_add(n("free_page_report_fails"), Relaxed);
    }

    /// Prior incarnation samples cannot establish freshness in a new process.
    pub fn reset_observation(&self) {
        *self.last_update.lock().unwrap() = None;
    }

    pub fn sample(
        &self,
        read_at: DateTime<Utc>,
        result: Result<Option<BalloonStatistics>>,
    ) -> api::BalloonStats {
        let mut sample = api::BalloonStats {
            read_at,
            status: "unavailable".into(),
            last_stats_update_observed_at: *self.last_update.lock().unwrap(),
            stats_updates: self.updates.load(Relaxed),
            stats_update_failures: self.update_failures.load(Relaxed),
            free_page_reports: self.reports.load(Relaxed),
            free_page_reported_bytes: self.reported_bytes.load(Relaxed),
            free_page_report_failures: self.report_failures.load(Relaxed),
            ..Default::default()
        };
        match result {
            Ok(Some(stats)) => {
                sample.status = "available".into();
                sample.target_bytes = stats.target_pages.checked_mul(4096);
                sample.actual_bytes = stats.actual_pages.checked_mul(4096);
                sample.guest_free_bytes = stats.free_memory;
                sample.guest_available_bytes = stats.available_memory;
                sample.guest_cache_bytes = stats.disk_caches;
            }
            Err(_) => sample.status = "error".into(),
            Ok(None) => {}
        }
        sample
    }
}

pub fn memory_stat_bytes(stat: &str, key: &str) -> Option<u64> {
    stat.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == key).then(|| value.trim().parse().ok()).flatten()
    })
}
