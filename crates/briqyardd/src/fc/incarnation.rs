//! Evidence tying boot provenance to one actual host process, across daemon handovers.

use super::*;
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incarnation {
    pub pid: u32,
    pub start_ticks: u64,
    pub host_boot_id: String,
}

impl Incarnation {
    /// Missing /proc evidence is unavailable telemetry, never a reason to stop a guest.
    pub fn read(pid: u32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let host_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let host_boot_id = host_boot_id.trim().to_string();
        if host_boot_id.is_empty() {
            return None;
        }
        Some(Self {
            pid,
            start_ticks: start_ticks(&stat)?,
            host_boot_id,
        })
    }
}

/// The parenthesized comm may contain spaces and closing parentheses. Fields after
/// its final delimiter start at field 3; Linux starttime is field 22.
pub(super) fn start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
