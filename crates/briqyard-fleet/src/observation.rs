//! Immutable serving-process identity; no configuration values are exposed.
use crate::{api, config};

pub(crate) fn new(cfg: &config::Config) -> api::RuntimeObservation {
    api::RuntimeObservation {
        host_id: "fleet".into(),
        version: briqyard_version::VERSION.into(),
        host_boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        incarnation: format!("{:032x}", rand::random::<u128>()),
        config: cfg.loaded_identity.clone(),
    }
}
