//! briqyard's API types (what every client sends and receives) and the host–guest protocol
//! (what `briqyardd` and `briqyard-init` agree on).

pub mod guest;
pub mod types;

pub use types::*;
