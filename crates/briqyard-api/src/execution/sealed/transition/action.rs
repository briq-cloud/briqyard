//! Action authorization: `Ticket`/`Permit`, `ROk`, the review request, the `Packet` that
//! carries one crossing and the exact phase table every action requires.

use super::common::{clock_is_from, expect_tag, refuse};
use super::evidence::{check_bind, GatePhase, GuardPhase, IntentPhase, Witness};
use super::reads::{ARead, HRead};
use crate::execution::sealed::canonical::{
    decode_with, encode, encode_with, h, CodecError, Limits, Wire,
};
use crate::execution::sealed::objects::{Bind, ClaimKind, Proc, X};
use crate::execution::sealed::prim::{nullable, HexDigest, Nonce, PosInt, Uint};
use crate::execution::sealed::sig::{PinnedKey, Sig, SigError, Tag};
use serde::{Deserialize, Serialize};

/// A Packet and its wrapper are at most 1 MiB; every enclosed object is at most 64 KiB.
pub const PACKET_LIMITS: Limits = Limits {
    max_bytes: 1024 * 1024,
    max_depth: Limits::MESSAGE.max_depth,
    max_array: Limits::MESSAGE.max_array,
};

/// B grants at most 30 s from `not_before`, in UTC milliseconds.
pub const MAX_PERMIT_MS: u64 = 30_000;

/// `Ticket`: the frozen body of one decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub x: X,
    pub plan: HexDigest,
    pub action: ClaimKind,
    pub claim: Nonce,
    pub owner: Nonce,
    pub challenge: Nonce,
    pub bind: Bind,
    pub prior_gate: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub auth_guard: Option<HexDigest>,
    pub retired: HexDigest,
    pub authority_proc: Proc,
    pub daemon_proc: Proc,
    pub host_proof: HexDigest,
    pub authority_proof: HexDigest,
    pub receiver_ok: HexDigest,
    pub not_before: Uint,
    pub expires: PosInt,
}

impl Wire for Ticket {
    /// Same scope as its Bind; `auth_guard` is nullable in the type but required in every
    /// Ticket; the window is non-empty and at most 30 s.
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.x != self.bind.x || self.plan != self.bind.plan {
            return refuse("ticket scope");
        }
        if self.auth_guard.is_none() {
            return refuse("ticket auth_guard");
        }
        let window = self.expires.get().checked_sub(self.not_before.get());
        if !window.is_some_and(|ms| (1..=MAX_PERMIT_MS).contains(&ms)) {
            return refuse("ticket window");
        }
        Ok(())
    }
}

impl Ticket {
    /// The qualified clock interval `[lo, hi]` (UTC ms) lies fully inside `[not_before,
    /// expires)`. Expiry is not an abort receipt: it only refuses the effect.
    pub fn window_contains(&self, lo_ms: u64, hi_ms: u64) -> bool {
        lo_ms <= hi_ms && lo_ms >= self.not_before.get() && hi_ms < self.expires.get()
    }
}

/// `Permit = Sig("decision", Ticket)`, signed by Bk.
pub type Permit = Sig<Ticket>;

/// `ROk` body: the receiver's approval of one reservation, echoing owner, claim and the
/// challenge it answers as `nonce`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ROkBody {
    pub x: X,
    pub plan: HexDigest,
    pub action: ClaimKind,
    pub bind: Bind,
    pub owner: Nonce,
    pub claim: Nonce,
    pub host_proof: HexDigest,
    pub authority_proof: HexDigest,
    pub daemon_proc: Proc,
    pub authority_proc: Proc,
    pub nonce: Nonce,
}

impl Wire for ROkBody {
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.x != self.bind.x || self.plan != self.bind.plan {
            return refuse("receiver ok scope");
        }
        Ok(())
    }
}

impl ROkBody {
    /// It answers exactly this review request: owner, claim and the challenge nonce.
    pub fn check_review(&self, review: &ReviewRequestBody) -> Result<(), CodecError> {
        if self.x != review.x
            || self.plan != review.plan
            || self.action != review.action
            || self.bind != review.bind
            || self.owner != review.owner
            || self.claim != review.claim
            || self.nonce != review.nonce
        {
            return refuse("receiver ok review");
        }
        Ok(())
    }
}

/// `ROk = Sig("receiver", …)`, signed by Rk.
pub type ROk = Sig<ROkBody>;

/// `review.request` body: B's reservation sent to R, with B's 5 s challenge as `nonce`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequestBody {
    pub x: X,
    pub plan: HexDigest,
    pub action: ClaimKind,
    pub bind: Bind,
    pub owner: Nonce,
    pub claim: Nonce,
    pub nonce: Nonce,
}

impl Wire for ReviewRequestBody {
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.x != self.bind.x || self.plan != self.bind.plan {
            return refuse("review scope");
        }
        Ok(())
    }
}

/// What an `ARead.intent` must be for an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentNeed {
    Absent,
    Pending,
    Ready,
}

/// The exact states an action needs, from the legal sequence: the gate phase, the guard
/// phase, the authority intent, and whether both registration high-waters are still the
/// prior `N` or already `N+1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseNeed {
    pub gate: GatePhase,
    pub guard: GuardPhase,
    pub intent: IntentNeed,
    pub registered_water: bool,
    pub ready: bool,
    pub certain: bool,
}

impl PhaseNeed {
    pub const fn of(action: ClaimKind) -> Self {
        match action {
            ClaimKind::Arm => Self {
                gate: GatePhase::Sealed,
                guard: GuardPhase::Started,
                intent: IntentNeed::Absent,
                registered_water: false,
                ready: false,
                certain: false,
            },
            ClaimKind::Adopt => Self {
                gate: GatePhase::Armed,
                guard: GuardPhase::Started,
                intent: IntentNeed::Absent,
                registered_water: false,
                ready: false,
                certain: false,
            },
            ClaimKind::Register => Self {
                gate: GatePhase::Armed,
                guard: GuardPhase::Adopted,
                intent: IntentNeed::Absent,
                registered_water: false,
                ready: false,
                certain: false,
            },
            ClaimKind::RecordAck => Self {
                gate: GatePhase::Registered,
                guard: GuardPhase::Adopted,
                intent: IntentNeed::Pending,
                registered_water: true,
                ready: false,
                certain: true,
            },
            ClaimKind::Release => Self {
                gate: GatePhase::Registered,
                guard: GuardPhase::Adopted,
                intent: IntentNeed::Ready,
                registered_water: true,
                ready: true,
                certain: true,
            },
        }
    }

    /// One H read and one A read are the states this action requires, for this Bind.
    pub fn check_reads(
        &self,
        bind: &Bind,
        host: &HRead,
        authority: &ARead,
    ) -> Result<(), CodecError> {
        let (gate, guard) = (&host.body.gate, &authority.body.guard);
        let water = if self.registered_water {
            bind.record.generation.get()
        } else {
            bind.prior.get()
        };
        let intent = match authority.body.intent.as_ref().map(|i| i.phase) {
            None => IntentNeed::Absent,
            Some(IntentPhase::Pending) => IntentNeed::Pending,
            Some(IntentPhase::Ready) => IntentNeed::Ready,
        };
        if gate.phase != self.gate
            || guard.phase != self.guard
            || intent != self.intent
            || host.body.water.get() != water
            || authority.body.native_water.get() != water
        {
            return refuse("phase need");
        }
        if self.gate >= GatePhase::Armed && gate.bind.as_ref() != Some(bind) {
            return refuse("phase need gate bind");
        }
        if guard.bind.as_ref().is_some_and(|b| b != bind) {
            return refuse("phase need guard bind");
        }
        let a = &authority.body;
        if (self.ready && !a.ready) || (self.certain && a.uncertain) {
            return refuse("phase need");
        }
        if let (Some(done), Some(intent)) = (&gate.done, &a.intent) {
            if done.claim != intent.claim
                || done.permit != intent.permit
                || done.witness != intent.witness
            {
                return refuse("phase need");
            }
        }
        if gate.phase == GatePhase::Armed
            && guard.phase == GuardPhase::Adopted
            && guard.armed_gate.as_ref() != Some(&host.body.gate_hash)
        {
            return refuse("phase need");
        }
        Ok(())
    }
}

/// `Packet = {p, ok, bh, ba, rh, ra}`: the verified signed responses of one crossing. `bh`
/// and `ba` are B's own reads, `rh` and `ra` R's, each with its own independent nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub p: Permit,
    pub ok: ROk,
    pub bh: HRead,
    pub ba: ARead,
    pub rh: HRead,
    pub ra: ARead,
}

impl Wire for Packet {
    fn validate(&self) -> Result<(), CodecError> {
        expect_tag(&self.p, Tag::Decision)?;
        expect_tag(&self.ok, Tag::Receiver)?;
        for read in [&self.bh, &self.rh] {
            expect_tag(read, Tag::HostRead)?;
        }
        for read in [&self.ba, &self.ra] {
            expect_tag(read, Tag::AuthorityRead)?;
        }
        let (t, ok) = (&self.p.body, &self.ok.body);
        t.validate()?;
        ok.validate()?;
        for part in [&self.bh, &self.rh] {
            part.validate()?;
        }
        for part in [&self.ba, &self.ra] {
            part.validate()?;
        }
        for len in [
            encode(&self.p)?.len(),
            encode(&self.ok)?.len(),
            encode(&self.bh)?.len(),
            encode(&self.ba)?.len(),
            encode(&self.rh)?.len(),
            encode(&self.ra)?.len(),
        ] {
            if len > Limits::MESSAGE.max_bytes {
                return Err(CodecError::TooLarge);
            }
        }

        let same_scope = [&self.bh, &self.rh]
            .iter()
            .all(|r| r.body.q.x == t.x && r.body.plan == t.plan && r.body.proc == t.daemon_proc)
            && [&self.ba, &self.ra].iter().all(|r| {
                r.body.q.x == t.x && r.body.plan == t.plan && r.body.proc == t.authority_proc
            });
        if !same_scope {
            return refuse("packet scope");
        }

        if ok.x != t.x
            || ok.plan != t.plan
            || ok.action != t.action
            || ok.bind != t.bind
            || ok.owner != t.owner
            || ok.claim != t.claim
            || ok.nonce != t.challenge
            || ok.daemon_proc != t.daemon_proc
            || ok.authority_proc != t.authority_proc
        {
            return refuse("packet receiver ok");
        }

        if t.host_proof != h(&self.bh)?
            || t.authority_proof != h(&self.ba)?
            || t.receiver_ok != h(&self.ok)?
            || ok.host_proof != h(&self.rh)?
            || ok.authority_proof != h(&self.ra)?
        {
            return refuse("packet proof hashes");
        }

        let gate = &self.bh.body.gate;
        if [&self.ba, &self.ra]
            .iter()
            .any(|read| !clock_is_from(&read.body.host_clock, &t.daemon_proc, &gate.instance))
        {
            return refuse("packet host clock");
        }
        let receipt = gate
            .receipt
            .as_ref()
            .ok_or(CodecError::Value("packet receipt"))?;
        if t.prior_gate != self.bh.body.gate_hash
            || t.retired != h(receipt)?
            || t.auth_guard.as_ref() != Some(&self.ba.body.guard_hash)
        {
            return refuse("packet links");
        }

        if self.bh.body.q.nonce == self.rh.body.q.nonce
            || self.ba.body.q.nonce == self.ra.body.q.nonce
            || self.bh.body.gate != self.rh.body.gate
            || self.bh.body.water != self.rh.body.water
            || self.ba.body.guard != self.ra.body.guard
            || self.ba.body.native_water != self.ra.body.native_water
            || self.ba.body.intent != self.ra.body.intent
            || self.ba.body.uncertain != self.ra.body.uncertain
            || self.ba.body.ready != self.ra.body.ready
        {
            return refuse("packet reads disagree");
        }

        let need = PhaseNeed::of(t.action);
        need.check_reads(&t.bind, &self.bh, &self.ba)?;
        need.check_reads(&t.bind, &self.rh, &self.ra)
    }
}

impl Packet {
    /// Decode a request body under the packet bound, for exactly one action.
    pub fn decode_for(bytes: &[u8], action: ClaimKind) -> Result<Self, CodecError> {
        let packet: Self = decode_with(bytes, PACKET_LIMITS)?;
        if packet.p.body.action != action {
            return refuse("packet action");
        }
        Ok(packet)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode_with(self, PACKET_LIMITS)
    }

    /// Verify the permit under Bk and the approval under Rk; the reads are verified by
    /// their own signers.
    pub fn verify_decision(&self, bk: &PinnedKey, rk: &PinnedKey) -> Result<(), SigError> {
        self.p.verify(Tag::Decision, bk)?;
        self.ok.verify(Tag::Receiver, rk)?;
        Ok(())
    }
}

/// `POST H …/transition/register` body: the packet and the authority's retained witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub packet: Packet,
    pub witness: Witness,
}

impl Wire for RegisterRequest {
    /// A register packet and a witness for exactly its permit, claim, bind, guard and
    /// authority process.
    fn validate(&self) -> Result<(), CodecError> {
        expect_tag(&self.witness, Tag::Intent)?;
        self.packet.validate()?;
        self.witness.validate()?;
        let (t, w) = (&self.packet.p.body, &self.witness.body);
        if t.action != ClaimKind::Register
            || w.x != t.x
            || w.plan != t.plan
            || w.bind != t.bind
            || w.claim != t.claim
            || w.permit != h(&self.packet.p)?
            || w.guard != self.packet.ba.body.guard_hash
            || w.proc != t.authority_proc
        {
            return refuse("register witness");
        }
        Ok(())
    }
}

impl RegisterRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode_with(bytes, PACKET_LIMITS)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode_with(self, PACKET_LIMITS)
    }
}
