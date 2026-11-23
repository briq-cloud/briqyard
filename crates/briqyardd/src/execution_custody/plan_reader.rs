//! Root custody's read of the two prior Plan commitments (interface v3.5 section c, SYL-268).
//!
//! Everything here is **observation**. A [`VerifiedPlanObservation`] says that, at one
//! point in time and for one nonce, the enrolled receiver and API both signed the same pin
//! of the same local Plan. It is not enrollment, a launch grant, a consumed owner or
//! permission to act: opening a journal, advancing an epoch, issuing a permit, calling a
//! service, launching, mutating a Gate or delivering a key or secret each need the full v3.1
//! and v3.4 authorization on their own. The type has no wire form, no constructor outside this
//! module and no conversion into any rooted act.
//!
//! * [`trust`]: the root-private trust record, loaded through a pinned directory chain.
//! * [`wire`]: the fixed local socket and its one framed exchange.
//! * [`verify`]: the pair check against the trust record and the local Plan.
//! * [`owner`]: the capture, out-of-lock read and compare-and-set join an operation owner
//!   implements; the target's `local_owner` implements it over its active attempt.

mod owner;
mod trust;
mod verify;
mod wire;

#[cfg(test)]
mod tests;

pub(in crate::execution_custody) use owner::fresh_nonce;
pub use owner::{
    OriginalOwner, OwnerRefusal, OwnerSnapshot, PlanReadOwner, PlanReader, ReadScope,
    RejoinedObservation, VerifiedPlanObservation,
};
#[cfg(test)]
pub(in crate::execution_custody) use trust::Ownership;
pub use trust::{EnrolledTrust, TrustLoader};
pub use wire::{EnrolledHelper, ReaderEndpoint, SOCKET_PATH};

use super::CustodyError;
use std::time::{Duration, Instant};
use thiserror::Error;

/// One exchange, from nonce generation through local consumption, takes at most this long.
const READ_BOUND: Duration = Duration::from_secs(5);

/// Why a read produced no observation. No variant carries key, plan or proof bytes.
#[derive(Debug, Error)]
pub enum PlanReadError {
    #[error("plan reader trust unavailable: {0}")]
    Trust(&'static str),
    #[error("plan reader {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("plan reader peer refused: {0}")]
    Peer(&'static str),
    #[error("plan read framing refused: {0}")]
    Frame(&'static str),
    #[error("plan read exceeded its five-second bound at {stage}")]
    Deadline { stage: &'static str },
    #[error("plan read proof refused: {0}")]
    Proof(&'static str),
    #[error("plan read scope refused: {0}")]
    Scope(&'static str),
    #[error("plan read owner refused: {0}")]
    Owner(&'static str),
    #[error(transparent)]
    Custody(#[from] CustodyError),
}

pub(crate) fn io(operation: &'static str, source: std::io::Error) -> PlanReadError {
    PlanReadError::Io { operation, source }
}

/// The five-second monotonic bound shared by every stage of one read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    pub(crate) fn start() -> Self {
        Self::within(READ_BOUND)
    }

    /// Test scope only: a production read never takes another bound.
    pub(crate) fn within(bound: Duration) -> Self {
        Self(
            Instant::now()
                .checked_add(bound)
                .expect("small monotonic bound"),
        )
    }

    pub(crate) fn remaining(self, stage: &'static str) -> Result<Duration, PlanReadError> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(PlanReadError::Deadline { stage })
    }

    pub(crate) fn check(self, stage: &'static str) -> Result<(), PlanReadError> {
        self.remaining(stage).map(|_| ())
    }
}
