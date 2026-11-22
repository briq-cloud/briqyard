//! The durable evidence: `Cut`, `Receipt`, `RegDone`, `Gate`, `Guard`, `Intent`, `Witness`.
//!
//! Each type validates the equalities and hash links the contract fixes inside it on every
//! decode: later fields are null before their transition, prior fields repeat identically,
//! and every embedded `Bind` is internally consistent.

use super::common::{expect_tag, refuse, Closure};
use super::launch::{Death, Launch, LaunchStage};
use crate::execution::sealed::canonical::{h, CodecError, Wire};
use crate::execution::sealed::custody::Resource;
use crate::execution::sealed::objects::{Ack, Bind, Ctx, Plan, Proc, X};
use crate::execution::sealed::prim::{nullable, HexDigest, Ident, KeyBytes, LitU, Nonce, PosInt};
use crate::execution::sealed::sig::{PinnedKey, Sig, SigError, Tag};
use serde::{Deserialize, Serialize};

/// A `Bind` is the original API decision for one registration: its context is the
/// registration's own and its generation is the prior high-water plus one.
pub fn check_bind(bind: &Bind) -> Result<(), CodecError> {
    if bind.ctx != bind.record.ctx(&bind.x.host) {
        return refuse("bind context");
    }
    if bind.prior.get() + 1 != bind.record.generation.get() {
        return refuse("bind generation");
    }
    Ok(())
}

/// A `Bind` is the one the pinned Plan authorizes: same operation and plan, the registered
/// host, the predecessor's high-water, the unchanged registration key and the new member set.
pub fn check_bind_plan(bind: &Bind, plan_hash: &HexDigest, plan: &Plan) -> Result<(), CodecError> {
    check_bind(bind)?;
    if bind.x != plan.x
        || bind.plan != *plan_hash
        || bind.registered != plan.registered
        || bind.prior != plan.pre.generation
        || bind.record.key_id != plan.pre_record.key_id
        || bind.record.public_key != plan.pre_record.public_key
        || bind.set != plan.new.set()?
    {
        return refuse("bind plan");
    }
    Ok(())
}

/// `Cut`: the typed evidence the daemon persists when it retires the predecessor's epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cut {
    pub x: X,
    pub plan: HexDigest,
    pub old: Ctx,
    pub old_set: HexDigest,
    pub new_instance: Ident,
    pub old_proc: Proc,
    pub new_proc: Proc,
    pub custody: HexDigest,
    pub profile: HexDigest,
    pub retired_epoch: Ident,
    pub prior_host_water: PosInt,
}

impl Wire for Cut {
    /// The old context is the intrinsic host's, the new instance differs, the retired epoch
    /// is the old one and the prior water is the old generation. Whether the two processes are
    /// the ones custody saw is the Death's and the kernel's to prove, not a tuple comparison.
    fn validate(&self) -> Result<(), CodecError> {
        if self.old.host != self.x.host
            || self.new_instance == self.old.instance
            || self.retired_epoch != self.old.epoch
            || self.prior_host_water != self.old.generation
        {
            return refuse("cut");
        }
        Ok(())
    }
}

impl Cut {
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    /// The cut is for the pinned plan: its X, its predecessor context and daemon, and its
    /// old member set.
    pub fn check_plan(&self, plan_hash: &HexDigest, plan: &Plan) -> Result<(), CodecError> {
        if self.x != plan.x
            || self.plan != *plan_hash
            || self.old != plan.pre
            || self.old_proc != plan.pre_d
            || self.old_set != plan.old.set()?
        {
            return refuse("cut plan");
        }
        Ok(())
    }

    /// `Cut.custody = H(daemon Death)`, and that Death is the one retiring `old_proc` for
    /// `new_proc` in this operation, under the same qualified profile.
    pub fn check_death(&self, death: &Death) -> Result<(), CodecError> {
        if self.custody != death.hash()?
            || death.resource != Resource::Daemon
            || death.x != self.x
            || death.plan != self.plan
            || death.old != self.old_proc
            || death.next != self.new_proc
            || death.profile != self.profile
        {
            return refuse("cut custody");
        }
        Ok(())
    }
}

/// `Receipt` body: the host's closure attestation for exactly one cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub cut: Cut,
    pub closure: Closure,
    pub writers: LitU<0>,
    pub leases: LitU<0>,
}

impl Wire for ReceiptBody {
    fn validate(&self) -> Result<(), CodecError> {
        self.cut.validate()
    }
}

impl ReceiptBody {
    pub fn new(cut: Cut) -> Self {
        Self {
            cut,
            closure: Closure::HostScopedWrites,
            writers: LitU,
            leases: LitU,
        }
    }
}

/// `Receipt = Sig("retired", …)`, signed by the host evidence key.
pub type Receipt = Sig<ReceiptBody>;

/// Verify a receipt under the pinned Hk.
pub fn verify_receipt(receipt: &Receipt, hk: &PinnedKey) -> Result<(), SigError> {
    receipt.verify(Tag::Retired, hk).map(|_| ())
}

/// `RegDone`: the stored acknowledgement of a host registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegDone {
    pub bind: Bind,
    pub claim: Nonce,
    pub permit: HexDigest,
    pub witness: HexDigest,
    pub ack: Ack,
    pub host_water: PosInt,
}

impl Wire for RegDone {
    /// The ACK is the registration's own native ACK and the host high-water is the
    /// registration's generation.
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.ack != self.bind.record.ack() || self.host_water != self.bind.record.generation {
            return refuse("registration done");
        }
        Ok(())
    }
}

/// `Gate.phase`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GatePhase {
    #[serde(rename = "closed")]
    Closed,
    #[serde(rename = "sealed")]
    Sealed,
    #[serde(rename = "armed")]
    Armed,
    #[serde(rename = "registered")]
    Registered,
    #[serde(rename = "released")]
    Released,
}

/// `Gate`: the host's durable phase. Prior fields are immutable, later ones null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub x: X,
    pub plan: HexDigest,
    pub phase: GatePhase,
    pub instance: Ident,
    #[serde(deserialize_with = "nullable")]
    pub cut: Option<Cut>,
    #[serde(deserialize_with = "nullable")]
    pub receipt: Option<Receipt>,
    #[serde(deserialize_with = "nullable")]
    pub bind: Option<Bind>,
    #[serde(deserialize_with = "nullable")]
    pub arm: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub done: Option<RegDone>,
    #[serde(deserialize_with = "nullable")]
    pub release: Option<HexDigest>,
}

impl Wire for Gate {
    /// Exactly the fields the phase has added are present. A signed gate always has the
    /// committed cut (before migration there is no signed gate at all), the new instance,
    /// and one X, plan and cut across every level.
    fn validate(&self) -> Result<(), CodecError> {
        let Some(cut) = &self.cut else {
            return refuse("gate cut");
        };
        cut.validate()?;
        if self.x != cut.x || self.plan != cut.plan || self.instance != cut.new_instance {
            return refuse("gate cut link");
        }
        let rank = self.phase as u8;
        let expect = [
            (self.receipt.is_some(), rank >= 1),
            (self.bind.is_some(), rank >= 2),
            (self.arm.is_some(), rank >= 2),
            (self.done.is_some(), rank >= 3),
            (self.release.is_some(), rank >= 4),
        ];
        if expect.iter().any(|(present, wanted)| present != wanted) {
            return refuse("gate phase fields");
        }
        if let Some(receipt) = &self.receipt {
            expect_tag(receipt, Tag::Retired)?;
            receipt.validate()?;
            if receipt.body.cut != *cut {
                return refuse("gate receipt cut");
            }
        }
        if let Some(bind) = &self.bind {
            check_bind(bind)?;
            if bind.x != self.x
                || bind.plan != self.plan
                || bind.prior != cut.prior_host_water
                || bind.record.host_instance != self.instance
            {
                return refuse("gate bind");
            }
        }
        if let Some(done) = &self.done {
            done.validate()?;
            if Some(&done.bind) != self.bind.as_ref() {
                return refuse("gate done bind");
            }
        }
        Ok(())
    }
}

impl Gate {
    /// `gate_hash = H(Gate)`.
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    /// The committed cut, which every valid gate carries.
    pub fn committed_cut(&self) -> &Cut {
        self.cut.as_ref().expect("a validated gate has its cut")
    }

    /// The host registration high-water this gate implies: the prior water until the
    /// registration commits, the registration's generation afterwards.
    pub fn implied_water(&self) -> u64 {
        match &self.done {
            Some(done) => done.host_water.get(),
            None => self.committed_cut().prior_host_water.get(),
        }
    }
}

/// `Guard.phase`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GuardPhase {
    #[serde(rename = "started")]
    Started,
    #[serde(rename = "adopted")]
    Adopted,
}

/// `Guard`: the authority's durable phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub x: X,
    pub plan: HexDigest,
    pub phase: GuardPhase,
    pub launch: HexDigest,
    pub proc: Proc,
    pub epoch: Ident,
    pub ordinary_kid: Ident,
    pub ordinary_key: KeyBytes,
    pub set: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub bind: Option<Bind>,
    #[serde(deserialize_with = "nullable")]
    pub armed_gate: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub adoption: Option<HexDigest>,
}

impl Wire for Guard {
    /// Started has no bind, armed gate or adoption; adopted sets all three together, and
    /// its bind is for this guard's epoch, candidate set and unchanged ordinary key.
    fn validate(&self) -> Result<(), CodecError> {
        let adopted = self.phase == GuardPhase::Adopted;
        if [
            self.bind.is_some(),
            self.armed_gate.is_some(),
            self.adoption.is_some(),
        ]
        .iter()
        .any(|present| *present != adopted)
        {
            return refuse("guard phase fields");
        }
        let Some(bind) = &self.bind else {
            return Ok(());
        };
        check_bind(bind)?;
        if bind.x != self.x
            || bind.plan != self.plan
            || bind.set != self.set
            || bind.record.epoch != self.epoch
            || bind.record.key_id != self.ordinary_kid
            || bind.record.public_key != *self.ordinary_key.as_array()
        {
            return refuse("guard bind");
        }
        Ok(())
    }
}

impl Guard {
    /// `guard_hash = H(Guard)`.
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    /// `Guard.launch = H(consumed authority Launch)`, taken before its successor and death are
    /// filled in.
    pub fn check_launch(&self, launch: &Launch) -> Result<(), CodecError> {
        if launch.stage != LaunchStage::Consumed
            || launch.resource != Resource::Authority
            || launch.x != self.x
            || launch.plan != self.plan
            || self.launch != launch.hash()?
        {
            return refuse("guard launch");
        }
        Ok(())
    }
}

/// `Intent.phase`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentPhase {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "ready")]
    Ready,
}

/// `Intent`: the authority's original registration intent. Pending has no ACK; ready has
/// exactly the registration's native ACK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: Ident,
    pub record: crate::execution::sealed::objects::Reg,
    pub claim: Nonce,
    pub permit: HexDigest,
    pub guard: HexDigest,
    pub witness: HexDigest,
    pub phase: IntentPhase,
    #[serde(deserialize_with = "nullable")]
    pub ack: Option<Ack>,
}

impl Wire for Intent {
    fn validate(&self) -> Result<(), CodecError> {
        match (&self.phase, &self.ack) {
            (IntentPhase::Pending, None) => Ok(()),
            (IntentPhase::Ready, Some(ack)) if *ack == self.record.ack() => Ok(()),
            _ => refuse("intent ack"),
        }
    }
}

/// `Witness` body: Ak's deterministic statement of the proposed post-commit facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessBody {
    pub x: X,
    pub plan: HexDigest,
    pub bind: Bind,
    pub claim: Nonce,
    pub permit: HexDigest,
    pub guard: HexDigest,
    pub proc: Proc,
    pub authority_water: PosInt,
    pub intent: Ident,
}

impl Wire for WitnessBody {
    /// The witness is for the bind's own intent, and the authority water it promises is
    /// the registration's generation (N+1).
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.x != self.bind.x
            || self.plan != self.bind.plan
            || self.intent != self.bind.intent
            || self.authority_water != self.bind.record.generation
        {
            return refuse("witness");
        }
        Ok(())
    }
}

/// `Witness = Sig("intent", …)`, signed by Ak.
pub type Witness = Sig<WitnessBody>;
