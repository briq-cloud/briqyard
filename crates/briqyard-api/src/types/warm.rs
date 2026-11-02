//! Host-local paused slots of one immutable qualified memory template.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WarmResources {
    pub memory_mb: u32,
    pub cpu_millis: u32,
    pub root_disk_gb: u32,
    /// Full logical data-volume liability; zero permits no warm data volumes.
    pub data_disk_gb: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmCatalogEntry {
    pub id: String,
    pub namespace: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub source_machine: String,
    pub snapshot: String,
    pub generation: String,
    pub size: Size,
    pub max_ready: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmDesiredRequest {
    pub desired: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarmBlocked {
    pub reason: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarmCatalogStatus {
    pub entries: Vec<WarmCatalogEntry>,
    pub budget: WarmResources,
    pub charged: WarmResources,
    pub headroom: WarmResources,
    pub min_mem_available_mb: u32,
    pub max_fills: u16,
    pub fills: usize,
    pub draining: usize,
    pub memory_available_mb: Option<u32>,
    pub disk_free_bytes: Option<u64>,
    pub measurement_age_ms: Option<u64>,
    pub blocked: Vec<WarmBlocked>,
    pub pools: Vec<WarmPool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutWarmPoolRequest {
    pub source_machine: String,
    pub snapshot: String,
    pub desired: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimWarmPoolRequest {
    pub name: String,
    /// Stable across timeout retries. One key can consume at most one slot.
    pub request_id: String,
    #[serde(default)]
    pub fail_fast: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarmPool {
    pub namespace: String,
    pub name: String,
    pub source_machine: String,
    pub snapshot: String,
    pub generation: String,
    pub profile: String,
    pub source_host: String,
    pub desired: u16,
    pub closed: bool,
    pub slots: Vec<WarmPoolSlot>,
    pub creating: usize,
    pub ready: usize,
    /// Existing claimed machines, including failed claims awaiting destruction.
    pub claimed: usize,
    /// Durable historical request receipts, retained after machines are destroyed.
    pub claim_receipts: usize,
    pub failed: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarmPoolSlot {
    pub machine_id: String,
    pub name: String,
    pub status: String,
    pub machine_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_data_budget_is_zero_and_round_trip_preserves_explicit_liability() {
        let previous = serde_json::json!({"memory_mb": 256, "cpu_millis": 1000, "root_disk_gb": 8});
        let mut resources: WarmResources = serde_json::from_value(previous).unwrap();
        assert_eq!(resources.data_disk_gb, 0);
        resources.data_disk_gb = 12;
        let encoded = serde_json::to_value(resources).unwrap();
        assert_eq!(encoded["data_disk_gb"], 12);
        assert_eq!(
            serde_json::from_value::<WarmResources>(encoded).unwrap(),
            resources
        );
        for invalid in [serde_json::json!(-1), serde_json::json!(4294967296_u64)] {
            let value = serde_json::json!({"data_disk_gb": invalid});
            assert!(serde_json::from_value::<WarmResources>(value).is_err());
        }
    }
}
