//! Launch and retirement evidence: the private `Launch` state, the two-signature launch
//! decision, `Death`, the provisioned `Secrets` and the observer `Resume` handshake.

use super::common::{expect_tag, refuse, Bearer, ResumeMode};
use super::evidence::{Gate, Guard};
use crate::execution::sealed::canonical::{h, wire, CodecError, Wire};
use crate::execution::sealed::custody::{CustodyWire, Resource};
use crate::execution::sealed::objects::{Members, Plan, Proc, Q, X};
use crate::execution::sealed::prim::{nullable, HexDigest, Ident, LitBool, LitU, Nonce};
use crate::execution::sealed::sig::{PinnedKey, Sig, SigError, Tag};
use serde::{Deserialize, Serialize};

/// `LKind`: the three launch-order actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LKind {
    #[serde(rename = "launch_d")]
    LaunchD,
    #[serde(rename = "seal")]
    Seal,
    #[serde(rename = "launch_a")]
    LaunchA,
}

impl LKind {
    /// The resource whose Launch the action consumes: the seal completes the daemon's.
    pub const fn resource(self) -> Resource {
        match self {
            LKind::LaunchD | LKind::Seal => Resource::Daemon,
            LKind::LaunchA => Resource::Authority,
        }
    }
}

/// `LDecision`: what both owners sign. `nonce` is the unique action claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LDecision {
    pub x: X,
    pub plan: HexDigest,
    pub action: LKind,
    pub owner: Nonce,
    pub expected: Proc,
    pub nonce: Nonce,
}

impl Wire for LDecision {}

impl LDecision {
    /// The decision is for this resource's Launch: same operation, plan, resource and
    /// owner; `launch_*` expects the old process, `seal` the new daemon the Launch
    /// observed (a seal before the successor is observed has nothing to expect).
    pub fn check_launch(&self, launch: &Launch) -> Result<(), CodecError> {
        let expected = match self.action {
            LKind::LaunchD | LKind::LaunchA => Some(&launch.old),
            LKind::Seal => launch.successor.as_ref(),
        };
        if self.x != launch.x
            || self.plan != launch.plan
            || self.action.resource() != launch.resource
            || self.owner != launch.owner
            || expected != Some(&self.expected)
        {
            return refuse("launch decision");
        }
        Ok(())
    }
}

/// `LGrant`: the receiver and API signatures over identical `LDecision` bodies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LGrant {
    pub receiver: Sig<LDecision>,
    pub api: Sig<LDecision>,
}

impl Wire for LGrant {
    fn validate(&self) -> Result<(), CodecError> {
        expect_tag(&self.receiver, Tag::LaunchReceiver)?;
        expect_tag(&self.api, Tag::LaunchApi)?;
        if self.receiver.body != self.api.body {
            return refuse("grant bodies differ");
        }
        self.receiver.validate()
    }
}

impl LGrant {
    pub fn verify(&self, rk: &PinnedKey, bk: &PinnedKey) -> Result<&LDecision, SigError> {
        let receiver = self.receiver.verify(Tag::LaunchReceiver, rk)?;
        let api = self.api.verify(Tag::LaunchApi, bk)?;
        if receiver != api {
            return Err(CodecError::Value("grant bodies differ").into());
        }
        Ok(receiver)
    }

    pub fn decision(&self) -> &LDecision {
        &self.receiver.body
    }

    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }
}

/// The body receiver POSTs to the host's `…/transition/seal`; its grant is a seal grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRequest {
    pub grant: LGrant,
    pub expected_gate: HexDigest,
}

impl Wire for SealRequest {
    fn validate(&self) -> Result<(), CodecError> {
        self.grant.validate()?;
        if self.grant.decision().action != LKind::Seal {
            return refuse("seal grant action");
        }
        Ok(())
    }
}

/// `Launch.stage`, in the only order it advances.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaunchStage {
    #[serde(rename = "closed")]
    Closed,
    #[serde(rename = "captured")]
    Captured,
    #[serde(rename = "consumed")]
    Consumed,
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "retired")]
    Retired,
}

/// `Launch`: the custodian-owned durable launch state of one resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub x: X,
    pub plan: HexDigest,
    pub resource: Resource,
    pub owner: Nonce,
    pub stage: LaunchStage,
    pub old: Proc,
    pub custodian: Proc,
    #[serde(deserialize_with = "nullable")]
    pub successor: Option<Proc>,
    #[serde(deserialize_with = "nullable")]
    pub death: Option<HexDigest>,
    pub nonce: Nonce,
}

impl Wire for Launch {
    /// closed, captured and consumed have a null successor and death; observed sets the
    /// verified successor; retired adds `H(Death)`.
    fn validate(&self) -> Result<(), CodecError> {
        let (successor, death) = match self.stage {
            LaunchStage::Closed | LaunchStage::Captured | LaunchStage::Consumed => (false, false),
            LaunchStage::Observed => (true, false),
            LaunchStage::Retired => (true, true),
        };
        if self.successor.is_some() != successor || self.death.is_some() != death {
            return refuse("launch stage fields");
        }
        Ok(())
    }
}

impl Launch {
    /// `H` of this exact snapshot: `Guard.launch` is the hash of the *consumed* one.
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    /// `next` is this Launch advanced one stage: everything else is immutable, the owner
    /// and capture nonce included, and the successor and death appear once and stay.
    pub fn check_next(&self, next: &Launch) -> Result<(), CodecError> {
        let one_step = (self.stage as u8) + 1 == next.stage as u8;
        let frozen = Launch {
            stage: self.stage,
            successor: self.successor.clone(),
            death: self.death.clone(),
            ..next.clone()
        };
        let keeps_successor = self.successor.is_none() || self.successor == next.successor;
        if !one_step || frozen != *self || !keeps_successor {
            return refuse("launch transition");
        }
        Ok(())
    }

    /// The capture's challenge is this Launch's nonce, and its identity is this Launch's.
    pub fn check_capture(&self, capture: &CustodyWire) -> Result<(), CodecError> {
        if capture.x != self.x
            || capture.plan != self.plan
            || capture.resource != self.resource
            || capture.owner != self.owner
            || capture.custodian != self.custodian
            || capture.old != self.old
            || capture.next.is_some()
            || capture.challenge != self.nonce
        {
            return refuse("launch capture");
        }
        Ok(())
    }

    /// The Death that retired this Launch: same owner and processes, and `H(Death)`.
    pub fn check_death(&self, death: &Death) -> Result<(), CodecError> {
        if death.x != self.x
            || death.plan != self.plan
            || death.resource != self.resource
            || death.owner != self.owner
            || death.old != self.old
            || death.custodian != self.custodian
            || Some(&death.next) != self.successor.as_ref()
            || Some(death.hash()?) != self.death
        {
            return refuse("launch death");
        }
        Ok(())
    }
}

/// `Death`: the local evidence chain of one exit. `H(Death)` is what Cut and Launch consume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Death {
    pub x: X,
    pub plan: HexDigest,
    pub resource: Resource,
    pub owner: Nonce,
    pub old: Proc,
    pub next: Proc,
    pub custodian: Proc,
    pub challenge: Nonce,
    pub profile: HexDigest,
    pub exited: LitBool<true>,
    pub external_writers: LitU<0>,
    pub durable: LitBool<true>,
}

impl Wire for Death {}

impl Death {
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    /// `Death.challenge = W.challenge`: the custody request wire this death completes.
    pub fn check_wire(&self, request: &CustodyWire) -> Result<(), CodecError> {
        if request.next.as_ref() != Some(&self.next)
            || request.challenge != self.challenge
            || request.x != self.x
            || request.plan != self.plan
            || request.resource != self.resource
            || request.owner != self.owner
            || request.old != self.old
            || request.custodian != self.custodian
        {
            return refuse("death wire");
        }
        Ok(())
    }
}

/// `Secrets.member`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Member {
    #[serde(rename = "hi")]
    Hi,
    #[serde(rename = "he")]
    He,
    #[serde(rename = "ni")]
    Ni,
    #[serde(rename = "ng")]
    Ng,
    #[serde(rename = "tr")]
    Tr,
}

/// `Secrets`: one private provisioned file per member and authorized recipient. Never sent
/// on HTTP; the bearer prints redacted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub x: X,
    pub plan: HexDigest,
    pub member: Member,
    pub value: Bearer,
}

impl Wire for Secrets {}

impl Secrets {
    /// The value hashes to the member digest the plan's set carries for this role.
    pub fn check_members(&self, members: &Members) -> Result<(), CodecError> {
        let expected = match self.member {
            Member::Hi => Some(&members.hi),
            Member::He => Some(&members.he),
            Member::Ni => Some(&members.ni),
            Member::Ng => Some(&members.ng),
            Member::Tr => members.tr.as_ref(),
        };
        if expected != Some(&self.value.digest()) {
            return refuse("secret member digest");
        }
        Ok(())
    }

    pub fn check_plan(&self, plan_hash: &HexDigest, plan: &Plan) -> Result<(), CodecError> {
        if self.x != plan.x || self.plan != *plan_hash {
            return refuse("secret plan");
        }
        Ok(())
    }
}

/// `Resume`: observer reattachment evidence. It grants no action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    pub q: Q,
    pub plan: HexDigest,
    pub resource: Resource,
    pub observed: Proc,
    pub launch: HexDigest,
    pub gate_or_guard: HexDigest,
    pub set: HexDigest,
    pub instance_or_epoch: Ident,
    pub mode: ResumeMode,
}

impl Wire for Resume {}

impl Resume {
    /// A daemon resume names the exact gate and its instance.
    pub fn check_gate(&self, gate: &Gate) -> Result<(), CodecError> {
        if self.resource != Resource::Daemon
            || self.gate_or_guard != gate.hash()?
            || self.instance_or_epoch != gate.instance
            || self.q.x != gate.x
            || self.plan != gate.plan
        {
            return refuse("resume gate");
        }
        Ok(())
    }

    /// An authority resume names the exact guard, its epoch, process and candidate set.
    pub fn check_guard(&self, guard: &Guard) -> Result<(), CodecError> {
        if self.resource != Resource::Authority
            || self.gate_or_guard != guard.hash()?
            || self.instance_or_epoch != guard.epoch
            || self.observed != guard.proc
            || self.set != guard.set
            || self.q.x != guard.x
            || self.plan != guard.plan
        {
            return refuse("resume guard");
        }
        Ok(())
    }
}

/// `resume.request` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRequestBody {
    pub x: X,
    pub plan: HexDigest,
    pub resource: Resource,
    pub owner: Nonce,
    pub nonce: Nonce,
}

/// `resume.challenge` body: the custodian's fresh `Resume` for one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeChallengeBody {
    pub request: HexDigest,
    pub resume: Resume,
}

impl Wire for ResumeChallengeBody {}

impl ResumeChallengeBody {
    /// The challenge answers exactly this request envelope, for its operation, plan and
    /// resource.
    pub fn check_request(&self, request: &Sig<ResumeRequestBody>) -> Result<(), CodecError> {
        expect_tag(request, Tag::ResumeRequest)?;
        let body = &request.body;
        if self.request != h(request)?
            || self.resume.q.x != body.x
            || self.resume.plan != body.plan
            || self.resume.resource != body.resource
        {
            return refuse("resume request");
        }
        Ok(())
    }
}

/// `…/transition/reattach` body: both owners signed identical `Resume` bodies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reattach {
    pub receiver: Sig<Resume>,
    pub api: Sig<Resume>,
}

impl Wire for Reattach {
    fn validate(&self) -> Result<(), CodecError> {
        expect_tag(&self.receiver, Tag::ResumeReceiver)?;
        expect_tag(&self.api, Tag::ResumeApi)?;
        if self.receiver.body != self.api.body {
            return refuse("reattach bodies differ");
        }
        Ok(())
    }
}

impl Reattach {
    pub fn verify(&self, rk: &PinnedKey, bk: &PinnedKey) -> Result<&Resume, SigError> {
        let receiver = self.receiver.verify(Tag::ResumeReceiver, rk)?;
        let api = self.api.verify(Tag::ResumeApi, bk)?;
        if receiver != api {
            return Err(CodecError::Value("reattach bodies differ").into());
        }
        Ok(receiver)
    }
}

wire!(ResumeRequestBody);
