//! briqyard's API types (what every client sends and receives) and the host–guest protocol
//! (what `briqyardd` and `briqyard-init` agree on).

pub mod auth;
pub mod guest;
#[cfg(feature = "listeners")]
pub mod listeners;
pub mod metrics;
#[cfg(feature = "tls")]
pub mod poolkey;
pub mod session;
#[cfg(feature = "tls")]
pub mod tls;
pub mod types;
pub mod version;

pub use auth::constant_eq;
pub use types::*;
pub use version::VERSION;

/// A test binary ends with its parent, and in bounded time (briqyard-testing).
#[cfg(test)]
#[ctor::ctor(unsafe)]
fn exit_with_parent() {
    briqyard_testing::exit_with_parent();
}
