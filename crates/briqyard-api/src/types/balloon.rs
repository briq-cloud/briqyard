//! Optional advisory memory telemetry. Reservations remain the machine's full size.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An API read is not a guest sample timestamp. Firecracker exposes no guest sample time.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BalloonStats {
    /// `available`, `unavailable` (no sample), or `error` (bounded read failed).
    pub status: String,
    pub read_at: DateTime<Utc>,
    /// Always false until the VMM supplies a guest sample timestamp.
    pub guest_sample_time_known: bool,
    /// Host observation of a FIFO stats-update increment, not the guest sample's time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_stats_update_observed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_free_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_available_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_cache_bytes: Option<u64>,
    pub stats_updates: u64,
    pub stats_update_failures: u64,
    pub free_page_reports: u64,
    /// Repeated discard submissions; never unique resident bytes reclaimed.
    pub free_page_reported_bytes: u64,
    pub free_page_report_failures: u64,
}
