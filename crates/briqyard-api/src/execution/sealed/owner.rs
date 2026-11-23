//! The owner layer's target-side wire: the read-only collector's request and its one bounded
//! answer, the install owner's arm receipt, the enrollment query and envelope, and B's
//! `owner.turn` evidence binding.
//!
//! The shapes are the staging owner grammar R and B already share byte for byte
//! (`owner.observe/v1`, `owner.observation/v1`, `owner.arm/v1`, `owner.enroll.query/v1`,
//! `owner.enroll/v1`, `owner.turn`). Nothing here is evidence by itself: a decoded value is
//! grammatical, never trusted. The target's local owner is the only producer of an observation
//! and an arm receipt; the signatures keep their pinned roles (`owner.enroll` is Rk,
//! `owner.turn` is Bk). Unknown, missing or duplicate fields refuse, and every value re-encodes
//! to the bytes it was read from.

use super::canonical::{CodecError, Wire};
use super::custody::{Capture, Resource};
use super::objects::{Proc, X};
use super::prim::{nullable, BootId, HexDigest, Ident, Nonce, PosInt};
use super::sig::Sig;
use super::transition::{Death, LKind, Launch};
use serde::{Deserialize, Serialize};

macro_rules! literal {
    ($(#[$meta:meta])* $name:ident, $text:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $text)]
            V1,
        }
    };
}

literal!(
    /// `owner.observe/v1`.
    ObserveFormat,
    "owner.observe/v1"
);
literal!(
    /// `owner.observation/v1`.
    ObservationFormat,
    "owner.observation/v1"
);
literal!(
    /// `owner.arm/v1`.
    ArmFormat,
    "owner.arm/v1"
);
literal!(
    /// `owner.enroll.query/v1`.
    EnrollQueryFormat,
    "owner.enroll.query/v1"
);
literal!(
    /// `owner.enroll/v1`.
    EnrollFormat,
    "owner.enroll/v1"
);

/// What a read is about. Never an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Point {
    #[serde(rename = "prearm")]
    Prearm,
    #[serde(rename = "launch")]
    Launch,
    #[serde(rename = "seal")]
    Seal,
}

/// Which independent verifier challenged the read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verifier {
    R,
    B,
}

/// `owner.observe/v1`: the verifier's fresh challenge for one resource and point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveRequest {
    pub format: ObserveFormat,
    pub x: X,
    pub registered: Ident,
    pub resource: Resource,
    pub point: Point,
    pub verifier: Verifier,
    pub nonce: Nonce,
}

impl Wire for ObserveRequest {
    fn validate(&self) -> Result<(), CodecError> {
        if self.point == Point::Seal && self.resource != Resource::Daemon {
            return Err(CodecError::Value("seal observation is daemon-only"));
        }
        Ok(())
    }
}

/// The loaded form of one unit's fragment path: the replaced file, not the loaded unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FragmentState {
    #[serde(rename = "legacy")]
    Legacy,
    #[serde(rename = "guarded")]
    Guarded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitState {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "exited")]
    Exited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "running")]
    Running,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitState {
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "failed")]
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTag {
    pub generation: PosInt,
    pub lockout: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Leases {
    #[serde(deserialize_with = "nullable")]
    pub daemon: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub authority: Option<HexDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Images {
    pub original: HexDigest,
    pub guard: HexDigest,
    pub custodian: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fragments {
    pub daemon: FragmentState,
    pub authority: FragmentState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retired {
    pub exit: ExitState,
    pub final_io: bool,
    #[serde(deserialize_with = "nullable")]
    pub receipt: Option<HexDigest>,
}

/// The four commitments to one unit's verified effective configuration, with the live job and
/// state. The commitments name what the service manager loaded, never a file just copied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitObservation {
    pub fragment: HexDigest,
    pub argv: HexDigest,
    pub sandbox: HexDigest,
    pub fdstore: HexDigest,
    pub job: JobState,
    pub state: UnitState,
}

/// `owner.observation/v1`: the target's facts for one challenged read. `version` is the
/// target's monotone evidence revision for the whole active local attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub format: ObservationFormat,
    pub request: ObserveRequest,
    pub boot: BootId,
    pub version: PosInt,
    pub target: TargetTag,
    pub leases: Leases,
    pub original: Proc,
    pub custodian: Proc,
    pub images: Images,
    pub fragments: Fragments,
    pub retired: Retired,
    pub unit: UnitObservation,
}

impl Wire for Observation {}

/// `owner.arm/v1`: written by the enrolled target install owner, for both resources together,
/// after both guarded fragments are installed and the effective-unit checks pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmReceipt {
    pub format: ArmFormat,
    pub x: X,
    pub registered: Ident,
    pub plan: HexDigest,
    pub target: Ident,
    pub boot: BootId,
    pub generation: PosInt,
    pub version: PosInt,
    pub lockout: HexDigest,
    pub resource: Resource,
    pub lease: HexDigest,
    pub original: Proc,
    pub custodian: Proc,
    pub fragment: HexDigest,
    pub argv: HexDigest,
    pub sandbox: HexDigest,
    pub fdstore: HexDigest,
}

impl Wire for ArmReceipt {}

impl ArmReceipt {
    /// `receipts.<resource> = H(ArmReceipt)`.
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        super::canonical::h(self)
    }
}

/// The captured Launch and its signed Capture, already durable on the target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCapture {
    pub launch: Launch,
    pub capture: Capture,
}

/// The committed retirement of the daemon: its retired Launch and the Death it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonRetirement {
    pub launch: Launch,
    pub death: Death,
}

/// The collector's one bounded answer. Which projections are non-null follows from the
/// target's own state and the request's resource and point, never from a caller flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collected {
    pub observation: Observation,
    #[serde(deserialize_with = "nullable")]
    pub arm: Option<ArmReceipt>,
    #[serde(deserialize_with = "nullable")]
    pub launch_capture: Option<LaunchCapture>,
    #[serde(deserialize_with = "nullable")]
    pub daemon_retirement: Option<DaemonRetirement>,
}

impl Wire for Collected {
    fn validate(&self) -> Result<(), CodecError> {
        if self.arm.is_some() && self.daemon_retirement.is_some() {
            return Err(CodecError::Value("arm and retirement projections"));
        }
        Ok(())
    }
}

/// `owner.enroll.query/v1`: B's fresh challenge to R's private enrollment listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollQuery {
    pub format: EnrollQueryFormat,
    pub x: X,
    pub registered: Ident,
    pub plan: HexDigest,
    pub target: Ident,
    pub challenge: Nonce,
}

impl Wire for EnrollQuery {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    pub daemon: HexDigest,
    pub authority: HexDigest,
}

/// `owner.enroll/v1`: R's committed enrollment revision, both fragment hashes and both arm
/// receipt digests. Signed by Rk only. `revision` is R's, never the target's version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollBody {
    pub format: EnrollFormat,
    pub x: X,
    pub registered: Ident,
    pub plan: HexDigest,
    pub target: Ident,
    pub revision: PosInt,
    pub fragments: Pair,
    pub receipts: Pair,
    pub challenge: Nonce,
}

impl Wire for EnrollBody {}

pub type Enrolled = Sig<EnrollBody>;

/// `owner.turn` body: B's evidence binding, signed by Bk only after its decision committed.
/// It sits beside the frozen `LGrant` and authorizes nothing on its own. `captured_launch`
/// and `capture` are the hashes B accepted for a launch and null for a seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnBody {
    pub x: X,
    pub registered: Ident,
    pub plan: HexDigest,
    pub resource: Resource,
    pub action: LKind,
    pub owner: Nonce,
    pub decision: HexDigest,
    pub boot: BootId,
    pub generation: PosInt,
    pub lockout: HexDigest,
    pub target_version: PosInt,
    #[serde(deserialize_with = "nullable")]
    pub captured_launch: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub capture: Option<HexDigest>,
}

impl Wire for TurnBody {
    fn validate(&self) -> Result<(), CodecError> {
        if self.action.resource() != self.resource {
            return Err(CodecError::Value("turn resource"));
        }
        let seal = self.action == LKind::Seal;
        let both = self.captured_launch.is_some() && self.capture.is_some();
        let neither = self.captured_launch.is_none() && self.capture.is_none();
        if (seal && !neither) || (!seal && !both) {
            return Err(CodecError::Value("turn capture evidence"));
        }
        Ok(())
    }
}

pub type Turn = Sig<TurnBody>;
