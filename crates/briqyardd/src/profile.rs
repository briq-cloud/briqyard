//! Opt-in lifecycle stage durations. No request payload, filesystem path or guest data.

use std::sync::OnceLock;
use std::time::Instant;

static EPOCH: OnceLock<Instant> = OnceLock::new();

pub(crate) fn stage(
    operation: &str,
    stage: &str,
    machine: &str,
    pid: u32,
    start: Instant,
    completed: bool,
) {
    if !tracing::enabled!(target: "briqyardd::profile", tracing::Level::DEBUG) {
        return;
    }
    let epoch = EPOCH.get_or_init(|| start);
    tracing::debug!(
        target: "briqyardd::profile",
        profile = "lifecycle",
        operation,
        stage,
        machine,
        pid,
        finished_us = epoch.elapsed().as_micros() as u64,
        elapsed_us = start.elapsed().as_micros() as u64,
        completed,
        "lifecycle stage"
    );
}
