//! Operator-only pristine sandbox seeds and one-way destination assignments.
use super::*;
mod create;
mod disk;
mod policy;
mod receipt;
mod start;
pub(in crate::machine) use receipt::{replay, request_digest, Binding};

pub(in crate::machine) fn builder_config(device: Option<guest::SandboxDevice>) -> guest::Config {
    guest::Config {
        template_profile: Some(guest::SANDBOX_READY_V1.into()),
        sandbox_device: device,
        ..Default::default()
    }
}
pub(in crate::machine) use policy::pristine_config;
pub(in crate::machine) use start::binding_hash;
pub(in crate::machine) use start::{check_ack, destination_bind};
#[cfg(test)]
mod tests;
