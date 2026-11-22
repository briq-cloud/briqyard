//! Linux-only process custody primitives. Wire encoding and authorization belong to callers.

mod fd;
mod process;
mod transport;

pub mod artifacts;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};
use thiserror::Error;

pub use fd::{
    compare_open_descriptions, CandidatePidFd, Comparison, DescriptorFloor, ExitWitness,
    OriginalPidFd,
};
pub use process::{CustodianProcess, OpaqueKernelProcess, PeerIdentity};
pub use transport::{
    CandidateExchange, CompletedCustody, CustodianCompletion, CustodianExchange, FrameKind, Packet,
    PacketListener, PacketSocket, MAX_PACKET,
};

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EXIT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum CustodyError {
    #[error("{operation} is unsupported by this kernel: {source}")]
    Unsupported {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{operation} is denied by kernel security policy: {source}")]
    PermissionDenied {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid process identity: {0}")]
    Identity(&'static str),
    #[error("custody protocol violation: {0}")]
    Protocol(&'static str),
    #[error("custody stage {stage} exceeded its deadline")]
    Deadline { stage: &'static str },
    #[error("descriptor limit prevents a custody slot at {minimum}: soft={soft}, hard={hard}")]
    DescriptorLimit { minimum: i32, soft: u64, hard: u64 },
}

pub(crate) fn io_error(operation: &'static str, source: std::io::Error) -> CustodyError {
    match source.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
            CustodyError::Unsupported { operation, source }
        }
        Some(libc::EPERM) | Some(libc::EACCES) => {
            CustodyError::PermissionDenied { operation, source }
        }
        _ => CustodyError::Io { operation, source },
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StageDeadline {
    at: Instant,
    stage: &'static str,
}

impl StageDeadline {
    pub fn frame(stage: &'static str) -> Self {
        Self::new(stage, FRAME_TIMEOUT)
    }

    pub fn exit(stage: &'static str, outer: Duration) -> Result<Self, CustodyError> {
        if outer.is_zero() || outer > MAX_EXIT_TIMEOUT {
            return Err(CustodyError::Protocol("invalid exit-stage bound"));
        }
        Ok(Self::new(stage, outer))
    }

    fn new(stage: &'static str, duration: Duration) -> Self {
        let at = Instant::now()
            .checked_add(duration)
            .expect("small monotonic custody bound");
        Self { at, stage }
    }

    #[cfg(test)]
    fn short(stage: &'static str) -> Self {
        Self::new(stage, Duration::from_millis(30))
    }

    pub(crate) fn remaining(self) -> Result<Duration, CustodyError> {
        self.at
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(CustodyError::Deadline { stage: self.stage })
    }

    pub(crate) fn check(self) -> Result<(), CustodyError> {
        self.remaining().map(|_| ())
    }

    pub(crate) fn expired(self) -> CustodyError {
        CustodyError::Deadline { stage: self.stage }
    }
}

pub(crate) fn require_root(operation: &'static str) -> Result<(), CustodyError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(CustodyError::PermissionDenied {
            operation,
            source: std::io::Error::from_raw_os_error(libc::EPERM),
        });
    }
    Ok(())
}
