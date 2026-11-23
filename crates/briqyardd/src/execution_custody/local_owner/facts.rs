//! What the target's local owner measures, and who may produce it.
//!
//! Every fact an observation or an arm receipt reports comes through [`TargetFacts`] or a
//! [`RetainedProcess`]: the live kernel and service manager, never a caller's scalar. The
//! production implementation [`LiveHost`] measures processes from `/proc` and refuses every
//! fact whose preimage this slice cannot honestly produce ([`OwnerError::Unprovisioned`]); the
//! tests supply their own implementations inside this crate. Nothing outside the crate can
//! build a [`FinalIo`] or a [`UnitMeasure`] from numbers.

use super::OwnerError;
use crate::execution_custody::{CustodianProcess, OpaqueKernelProcess};
use briqyard_api::execution::sealed::{
    custody::Resource,
    objects::Proc,
    owner::{FragmentState, JobState, UnitState},
    prim::{BootId, HexDigest, PosInt},
};

/// A live process as the kernel reports it: boot, PID, start ticks and mapped executable.
/// The build label is a release pin's, not a kernel fact, so it is not part of a measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasuredProc {
    pub(super) boot: BootId,
    pub(super) pid: u64,
    pub(super) start: u64,
    pub(super) exe: HexDigest,
}

impl MeasuredProc {
    pub fn matches(&self, expected: &Proc) -> bool {
        self.boot == expected.boot
            && self.pid == expected.pid.get()
            && self.start == expected.start.get()
            && self.exe == expected.exe
    }

    pub fn pid(&self) -> u64 {
        self.pid
    }

    pub fn exe(&self) -> &HexDigest {
        &self.exe
    }
}

impl TryFrom<&OpaqueKernelProcess> for MeasuredProc {
    type Error = OwnerError;

    fn try_from(process: &OpaqueKernelProcess) -> Result<Self, OwnerError> {
        Ok(Self {
            boot: BootId::new(process.boot_id())
                .map_err(|_| OwnerError::Refused("kernel boot id is not a uuid"))?,
            pid: u64::from(process.pid()),
            start: process.start_ticks(),
            exe: HexDigest::from_raw(*process.executable()),
        })
    }
}

/// The retained descriptor of one original process: the only source of an exit. A PID that
/// cannot be found proves nothing; the retained pidfd turning readable does.
pub trait RetainedProcess {
    /// The process the descriptor names, after checking its identity did not change.
    fn identity(&self) -> Result<MeasuredProc, OwnerError>;
    /// Whether the retained descriptor reports that exact process has exited.
    fn has_exited(&self) -> Result<bool, OwnerError>;
}

impl RetainedProcess for CustodianProcess {
    fn identity(&self) -> Result<MeasuredProc, OwnerError> {
        self.verify_unchanged()?;
        MeasuredProc::try_from(self.process())
    }

    fn has_exited(&self) -> Result<bool, OwnerError> {
        Ok(self.descriptor().poll_exited()?.is_some())
    }
}

/// The four commitments to one unit's verified effective configuration and its live state.
/// `reloaded` is that the service manager's loaded unit is the on-disk fragment (no pending
/// reload). The preimages of `argv`, `sandbox` and `fdstore` are an open design decision
/// (ADR 0149): the production host does not produce this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitMeasure {
    pub(super) fragment: HexDigest,
    pub(super) argv: HexDigest,
    pub(super) sandbox: HexDigest,
    pub(super) fdstore: HexDigest,
    pub(super) job: JobState,
    pub(super) state: UnitState,
    pub(super) reloaded: bool,
}

/// The completed final I/O of an exited original: its last journal and side-store writes are
/// durable and no helper or writer remains. Opaque: only a measurement of the real store
/// produces one, and this slice has no such producer outside the tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalIo(());

impl FinalIo {
    #[cfg(test)]
    pub(super) fn completed() -> Self {
        Self(())
    }
}

/// The live host as the local owner sees it. An implementation that answers from its own
/// state is a fixture, not a measurement; only [`LiveHost`] is production.
pub trait TargetFacts {
    fn boot(&self) -> Result<BootId, OwnerError>;
    /// The live process with this PID, or `None` when no such process is running. Absence is
    /// never an exit: exits come from a [`RetainedProcess`].
    fn process(&self, pid: u64) -> Result<Option<MeasuredProc>, OwnerError>;
    fn fragment(&self, resource: Resource) -> Result<FragmentState, OwnerError>;
    fn unit(&self, resource: Resource) -> Result<UnitMeasure, OwnerError>;
    /// The executable the unit's guard maps, as measured at its fixed path.
    fn guard_image(&self, resource: Resource) -> Result<HexDigest, OwnerError>;
    /// The unit's current main process, when it is running one.
    fn unit_process(&self, resource: Resource) -> Result<Option<MeasuredProc>, OwnerError>;
    fn final_io(&self, resource: Resource) -> Result<FinalIo, OwnerError>;
}

/// The production host. Process facts come from the kernel. The service manager's effective
/// unit, the guard image path and the final-I/O record are not produced here: the commitments'
/// preimages and the authority's journal evidence are undecided (ADR 0149), so every call that
/// needs them refuses and the production collector cannot answer.
pub struct LiveHost(());

impl LiveHost {
    pub fn new() -> Result<Self, OwnerError> {
        crate::execution_custody::require_root("measure the sealed target")?;
        Ok(Self(()))
    }
}

const UNPROVISIONED_UNIT: &str = "effective-unit commitments are not specified";

impl TargetFacts for LiveHost {
    fn boot(&self) -> Result<BootId, OwnerError> {
        MeasuredProc::try_from(&OpaqueKernelProcess::current()?).map(|process| process.boot)
    }

    fn process(&self, pid: u64) -> Result<Option<MeasuredProc>, OwnerError> {
        let pid = i32::try_from(pid).map_err(|_| OwnerError::Refused("pid out of range"))?;
        match CustodianProcess::identify_peer(pid) {
            Ok(process) => MeasuredProc::try_from(&process).map(Some),
            Err(crate::execution_custody::CustodyError::Io { source, .. })
                if source.raw_os_error() == Some(libc::ENOENT)
                    || source.raw_os_error() == Some(libc::ESRCH) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn fragment(&self, _: Resource) -> Result<FragmentState, OwnerError> {
        Err(OwnerError::Unprovisioned(UNPROVISIONED_UNIT))
    }

    fn unit(&self, _: Resource) -> Result<UnitMeasure, OwnerError> {
        Err(OwnerError::Unprovisioned(UNPROVISIONED_UNIT))
    }

    fn guard_image(&self, _: Resource) -> Result<HexDigest, OwnerError> {
        Err(OwnerError::Unprovisioned(UNPROVISIONED_UNIT))
    }

    fn unit_process(&self, _: Resource) -> Result<Option<MeasuredProc>, OwnerError> {
        Err(OwnerError::Unprovisioned(UNPROVISIONED_UNIT))
    }

    fn final_io(&self, _: Resource) -> Result<FinalIo, OwnerError> {
        Err(OwnerError::Unprovisioned(
            "final-I/O evidence has no producer",
        ))
    }
}

pub(super) fn version_after(version: &PosInt) -> Result<PosInt, OwnerError> {
    PosInt::new(version.get() + 1).map_err(|_| OwnerError::Refused("evidence version exhausted"))
}
