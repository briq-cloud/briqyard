//! The daemon's modules, a library so that the fuzz targets (`fuzz/`, ADR 0033) reach what
//! parses bytes from guests, registries and the public; `main.rs` is the daemon.

pub mod api;
pub mod conditions;
pub mod config;
pub mod console;
pub mod events;
pub mod fc;
pub mod guestc;
pub mod heartbeat;
pub mod image;
pub mod ingress;
pub mod machine;
pub mod metrics;
pub mod netw;
pub mod poolkey;
pub mod session;
pub mod store;
pub mod tls;
pub mod usage;
pub mod zfs;

use briqyard_objstore as objstore;
