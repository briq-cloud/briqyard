//! Fixture-only tests. Every identity here is generated in memory for the test, belongs to
//! no host and authorizes nothing.

mod cert;
mod client;
pub(in crate::execution_service::protected) mod harness;
mod http;
mod inventory;
pub(in crate::execution_service::protected) mod pki;
mod tls;
