//! The v2 transition wire (interface revision 3.1): the durable evidence a host and an
//! authority keep, the signed reads that expose it, the permits that authorize one crossing,
//! the launch, death and resume evidence, and the private control envelopes.
//!
//! Like the rest of [`super`] this is bytes in, typed objects out: no I/O, no private key, no
//! policy. A decoded object is shaped by its schema and by the cross-field equalities and
//! hash links the contract fixes *inside* that object; the checks against a pinned Plan, a
//! query or another verifier's observation are methods the caller runs against its own
//! independently held state. Nothing here decides that an action may happen.
//!
//! * [`common`]: literals, the bearer secret, the `HostClock` envelope, the salted challenge.
//! * [`evidence`]: `Cut`, `Receipt`, `RegDone`, `Gate`, `Guard`, `Intent`, `Witness`.
//! * [`action`]: `Ticket`/`Permit`, `ROk`, `Packet`, the exact phase table of every action.
//! * [`reads`]: `HRead`, `ARead`, `ApiView`, the observe pair and capacity predicates.
//! * [`launch`]: `Launch`, `LDecision`/`LGrant`, `Death`, `Secrets`, `Resume`.
//! * [`control`]: client stage/query/enable, the trial3 control envelopes, the final read.

pub mod action;
pub mod common;
pub mod control;
pub mod evidence;
pub mod launch;
pub mod reads;

pub use action::*;
pub use common::*;
pub use control::*;
pub use evidence::*;
pub use launch::*;
pub use reads::*;

#[cfg(test)]
mod tests;
