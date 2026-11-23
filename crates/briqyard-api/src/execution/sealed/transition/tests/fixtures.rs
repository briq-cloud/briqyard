//! One coherent scenario: a registered predecessor (generation 2) replaced by a successor
//! instance and epoch whose registration is generation 3.

use crate::execution::sealed::canonical::{decode, encode, h, Wire};
use crate::execution::sealed::custody::Resource;
use crate::execution::sealed::objects::{
    Ack, Bind, ClaimKind, Ctx, Dims, HostClockBody, Members, Plan, Projection, Reg, Q,
};
use crate::execution::sealed::prim::{Build, Bytes, HexDigest, Nonce, PosInt, Uint};
use crate::execution::sealed::sig::{PinnedKey, Role, Sig, Signer, Tag};
use crate::execution::sealed::tests::{dg, fixture_nonce, id, key, pos, proc, x, TestSigner};
use crate::execution::sealed::transition::*;
use ed25519_dalek::SigningKey;
use serde::Serialize;

/// RFC 8032 7.1 "SHA(abc)" seed, played as Hk.
pub(super) struct HkSigner(SigningKey);

impl HkSigner {
    pub(super) fn new() -> Self {
        let seed: [u8; 32] =
            hex::decode("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
                .unwrap()
                .try_into()
                .unwrap();
        Self(SigningKey::from_bytes(&seed))
    }
    pub(super) fn pinned(&self) -> PinnedKey {
        PinnedKey::new(Role::Hk, self.public_key()).unwrap()
    }
}

impl Signer for HkSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.0.sign(message).to_bytes()
    }
}

pub(super) fn rk() -> PinnedKey {
    TestSigner::rk().pinned(Role::Rk)
}
pub(super) fn bk() -> PinnedKey {
    TestSigner::bk().pinned(Role::Bk)
}
pub(super) fn ak() -> PinnedKey {
    TestSigner::ak().pinned(Role::Ak)
}

/// `decode(encode(v))` must fail: the refusal is at the codec boundary.
pub(super) fn refused<T: Wire>(value: &T) -> bool {
    decode::<T>(&encode(value).unwrap()).is_err()
}

/// The value survives the codec unchanged.
pub(super) fn round_trip<T: Wire + PartialEq + std::fmt::Debug>(value: &T) {
    assert_eq!(&decode::<T>(&encode(value).unwrap()).unwrap(), value);
}

pub(super) fn plan_hash() -> HexDigest {
    dg('1')
}

pub(super) fn members(k: u8) -> Members {
    Members {
        hi: dg((b'0' + k) as char),
        he: dg((b'1' + k) as char),
        ni: dg((b'2' + k) as char),
        ng: dg((b'3' + k) as char),
        tr: Some(dg((b'4' + k) as char)),
    }
}

pub(super) fn old_set() -> HexDigest {
    members(1).set().unwrap()
}

pub(super) fn new_set() -> HexDigest {
    members(2).set().unwrap()
}

pub(super) fn plan() -> Plan {
    Plan {
        x: x(),
        registered: id("registered.test"),
        pre: pre_ctx(),
        pre_record: pre_record(),
        pre_intent: id("pre"),
        pre_d: daemon_old(),
        pre_a: authority_old(),
        next_d: dg('a'),
        next_a: dg('b'),
        dbuild: Build::new("fence-3").unwrap(),
        abuild: Build::new("fence-3").unwrap(),
        old: members(1),
        new: members(2),
        hk: key(1),
        ak: key(2),
        bk: key(3),
        rk: key(4),
        ordinary_key: key(5),
        exception: dg('a'),
        inputs: dg('b'),
    }
}

pub(super) fn reg(instance: &str, epoch: &str, generation: u64) -> Reg {
    Reg {
        authority: id("auth"),
        epoch: id(epoch),
        key_id: id("k"),
        public_key: TestSigner::rk().public_key(),
        host_instance: id(instance),
        generation: pos(generation),
    }
}

pub(super) fn pre_record() -> Reg {
    reg("hi", "ep", 2)
}

pub(super) fn pre_ctx() -> Ctx {
    pre_record().ctx(&x().host)
}

pub(super) fn new_record() -> Reg {
    reg("hi2", "ep2", 3)
}

pub(super) fn bind() -> Bind {
    let record = new_record();
    Bind {
        x: x(),
        plan: plan_hash(),
        registered: id("registered.test"),
        prior: pos(2),
        intent: id("register:sealed:op"),
        ctx: record.ctx(&x().host),
        record,
        set: new_set(),
    }
}

pub(super) fn daemon_old() -> crate::execution::sealed::objects::Proc {
    proc(10)
}
pub(super) fn daemon_new() -> crate::execution::sealed::objects::Proc {
    proc(20)
}
pub(super) fn custodian() -> crate::execution::sealed::objects::Proc {
    proc(30)
}
pub(super) fn authority_old() -> crate::execution::sealed::objects::Proc {
    proc(12)
}
pub(super) fn authority_new() -> crate::execution::sealed::objects::Proc {
    proc(40)
}

pub(super) fn daemon_death() -> Death {
    Death {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Daemon,
        owner: fixture_nonce(1),
        old: daemon_old(),
        next: daemon_new(),
        custodian: custodian(),
        challenge: fixture_nonce(8),
        profile: dg('7'),
        exited: crate::execution::sealed::prim::LitBool,
        external_writers: crate::execution::sealed::prim::LitU,
        durable: crate::execution::sealed::prim::LitBool,
    }
}

/// `h(C({"wire": death}))`: the digest of the wrapper a transport might put around a Death.
/// It is never the commitment: Cut and Launch consume `H(Death) = h(C(Death))` only.
pub(super) fn wrapped_death_hash(death: &Death) -> HexDigest {
    let wrapper = serde_json::json!({ "wire": death });
    crate::execution::sealed::canonical::h(&wrapper).unwrap()
}

/// `SHA-256(C(death))` computed outside the code under test's own `h`.
pub(super) fn independent_death_hash(death: &Death) -> HexDigest {
    use sha2::{Digest, Sha256};
    let bytes = crate::execution::sealed::canonical::encode(death).unwrap();
    HexDigest::from_raw(Sha256::digest(bytes).into())
}

pub(super) fn cut() -> Cut {
    Cut {
        x: x(),
        plan: plan_hash(),
        old: pre_ctx(),
        old_set: old_set(),
        new_instance: id("hi2"),
        old_proc: daemon_old(),
        new_proc: daemon_new(),
        custody: daemon_death().hash().unwrap(),
        profile: dg('7'),
        retired_epoch: id("ep"),
        prior_host_water: pos(2),
    }
}

pub(super) fn receipt() -> Receipt {
    Sig::sign(Tag::Retired, ReceiptBody::new(cut()), &HkSigner::new()).unwrap()
}

pub(super) fn reg_done() -> RegDone {
    let bind = bind();
    RegDone {
        ack: bind.record.ack(),
        host_water: bind.record.generation,
        bind,
        claim: fixture_nonce(11),
        permit: dg('a'),
        witness: dg('b'),
    }
}

pub(super) fn gate(phase: GatePhase) -> Gate {
    let rank = phase as u8;
    Gate {
        x: x(),
        plan: plan_hash(),
        phase,
        instance: id("hi2"),
        cut: Some(cut()),
        receipt: (rank >= 1).then(receipt),
        bind: (rank >= 2).then(bind),
        arm: (rank >= 2).then(|| dg('c')),
        done: (rank >= 3).then(reg_done),
        release: (rank >= 4).then(|| dg('d')),
    }
}

pub(super) fn guard(phase: GuardPhase) -> Guard {
    let adopted = phase == GuardPhase::Adopted;
    Guard {
        x: x(),
        plan: plan_hash(),
        phase,
        launch: dg('8'),
        proc: authority_new(),
        epoch: id("ep2"),
        ordinary_kid: id("k"),
        ordinary_key: Bytes::from_array(TestSigner::rk().public_key()),
        set: new_set(),
        bind: adopted.then(bind),
        armed_gate: adopted.then(|| gate(GatePhase::Armed).hash().unwrap()),
        adoption: adopted.then(|| dg('9')),
    }
}

pub(super) fn guard_hash(phase: GuardPhase) -> HexDigest {
    guard(phase).hash().unwrap()
}

pub(super) fn intent(phase: IntentPhase) -> Intent {
    let record = new_record();
    Intent {
        id: bind().intent,
        claim: fixture_nonce(11),
        permit: dg('a'),
        guard: guard_hash(GuardPhase::Adopted),
        witness: dg('b'),
        phase,
        ack: (phase == IntentPhase::Ready).then(|| record.ack()),
        record,
    }
}

pub(super) fn witness_body() -> WitnessBody {
    WitnessBody {
        x: x(),
        plan: plan_hash(),
        bind: bind(),
        claim: fixture_nonce(11),
        permit: dg('a'),
        guard: guard_hash(GuardPhase::Adopted),
        proc: authority_new(),
        authority_water: pos(3),
        intent: bind().intent,
    }
}

pub(super) fn q(nonce: Nonce) -> Q {
    Q { x: x(), nonce }
}

pub(super) fn dims(bytes: u64, fits: bool) -> Dims {
    Dims {
        bytes: Uint::new(bytes).unwrap(),
        counts: [Uint::new(0).unwrap(); 21],
        fits,
    }
}

/// One owner's rows, in order, each based on `basis`. `null` rows are the all-null rows of
/// actions already past.
pub(super) fn owner_cap(
    basis: &HexDigest,
    rows: &[ProjectionAction],
    null: &[ProjectionAction],
) -> OwnerCap {
    let projections = rows
        .iter()
        .map(|action| {
            if null.contains(action) {
                return Projection {
                    action: *action,
                    basis: basis.clone(),
                    target: None,
                    next: None,
                    reserve: None,
                    expected_ack: None,
                };
            }
            Projection {
                action: *action,
                basis: basis.clone(),
                target: Some(dg('e')),
                next: None,
                reserve: Some(dims(4096, true)),
                expected_ack: None::<Ack>,
            }
        })
        .collect();
    OwnerCap {
        actual: dims(1024, true),
        projections,
    }
}

pub(super) const H_ROWS: [ProjectionAction; 4] = [
    ProjectionAction::Seal,
    ProjectionAction::Arm,
    ProjectionAction::HostRegister,
    ProjectionAction::Release,
];
pub(super) const A_ROWS: [ProjectionAction; 2] = [
    ProjectionAction::AuthorityIntent,
    ProjectionAction::AuthorityAck,
];

pub(super) use crate::execution::sealed::objects::ProjectionAction;

fn past_h(phase: GatePhase) -> Vec<ProjectionAction> {
    [
        ProjectionAction::Seal,
        ProjectionAction::Arm,
        ProjectionAction::HostRegister,
        ProjectionAction::Release,
    ][..phase as usize]
        .to_vec()
}

pub(super) fn host_clock(outer: &Q, salt: &Nonce) -> HostClock {
    host_clock_with(outer, salt, daemon_new(), id("hi2"))
}

pub(super) fn host_clock_with(
    outer: &Q,
    salt: &Nonce,
    proc: crate::execution::sealed::objects::Proc,
    instance: crate::execution::sealed::prim::Ident,
) -> HostClock {
    let nonce = host_challenge_nonce(outer, &plan_hash(), salt).unwrap();
    let body = HostClockBody {
        q: Q {
            x: outer.x.clone(),
            nonce,
        },
        plan: plan_hash(),
        proc,
        instance,
        now: Uint::new(1_000).unwrap(),
        uncertainty: Uint::new(1).unwrap(),
    };
    Sig::sign(Tag::HostClock, body, &HkSigner::new()).unwrap()
}

pub(super) fn hread(gate: Gate, nonce: Nonce) -> HRead {
    let gate_hash = gate.hash().unwrap();
    let body = HReadBody {
        q: q(nonce),
        plan: plan_hash(),
        proc: daemon_new(),
        water: Uint::new(gate.implied_water()).unwrap(),
        cap: owner_cap(&gate_hash, &H_ROWS, &past_h(gate.phase)),
        gate_hash,
        gate,
    };
    Sig::sign(Tag::HostRead, body, &HkSigner::new()).unwrap()
}

/// What a test may bend in an authority read while keeping it signable.
#[derive(Clone, Default)]
pub(super) struct AOpts {
    pub ready: Option<bool>,
    pub uncertain: bool,
    pub clock_proc: Option<crate::execution::sealed::objects::Proc>,
    pub clock_instance: Option<crate::execution::sealed::prim::Ident>,
}

#[derive(Clone, Copy)]
pub(super) struct AuthorityChallenge {
    nonce: Nonce,
    salt: Nonce,
}

pub(super) fn aread(guard: Guard, intent: Option<Intent>, water: u64) -> ARead {
    aread_with(
        guard,
        intent,
        water,
        AuthorityChallenge {
            nonce: fixture_nonce(5),
            salt: fixture_nonce(105),
        },
        AOpts::default(),
    )
}

fn aread_with(
    guard: Guard,
    intent: Option<Intent>,
    water: u64,
    AuthorityChallenge { nonce, salt }: AuthorityChallenge,
    opts: AOpts,
) -> ARead {
    let guard_hash = guard.hash().unwrap();
    let outer = q(nonce);
    let past: &[ProjectionAction] = match intent.as_ref().map(|i| i.phase) {
        None => &[],
        Some(IntentPhase::Pending) => &[ProjectionAction::AuthorityIntent],
        Some(IntentPhase::Ready) => &[
            ProjectionAction::AuthorityIntent,
            ProjectionAction::AuthorityAck,
        ],
    };
    let ready = opts.ready.unwrap_or_else(|| {
        intent
            .as_ref()
            .is_some_and(|i| i.phase == IntentPhase::Ready)
    });
    let body = AReadBody {
        host_clock: host_clock_with(
            &outer,
            &salt,
            opts.clock_proc.unwrap_or_else(daemon_new),
            opts.clock_instance.unwrap_or_else(|| id("hi2")),
        ),
        q: outer,
        plan: plan_hash(),
        proc: authority_new(),
        cap: owner_cap(&guard_hash, &A_ROWS, past),
        guard_hash,
        guard,
        salt,
        native_water: Uint::new(water).unwrap(),
        intent,
        uncertain: opts.uncertain,
        ready,
    };
    Sig::sign(Tag::AuthorityRead, body, &TestSigner::ak()).unwrap()
}

/// The state pair an action needs, as (gate, guard, intent, water).
pub(super) fn states(action: ClaimKind) -> (Gate, Guard, Option<Intent>, u64) {
    match action {
        ClaimKind::Arm => (gate(GatePhase::Sealed), guard(GuardPhase::Started), None, 2),
        ClaimKind::Adopt => (gate(GatePhase::Armed), guard(GuardPhase::Started), None, 2),
        ClaimKind::Register => (gate(GatePhase::Armed), guard(GuardPhase::Adopted), None, 2),
        ClaimKind::RecordAck => (
            gate(GatePhase::Registered),
            guard(GuardPhase::Adopted),
            Some(intent(IntentPhase::Pending)),
            3,
        ),
        ClaimKind::Release => (
            gate(GatePhase::Registered),
            guard(GuardPhase::Adopted),
            Some(intent(IntentPhase::Ready)),
            3,
        ),
    }
}

/// Everything a packet is built from, so a test can break exactly one link and still sign.
pub(super) struct Parts {
    pub bg: Gate,
    pub rg: Gate,
    pub bguard: Guard,
    pub rguard: Guard,
    pub bintent: Option<Intent>,
    pub rintent: Option<Intent>,
    pub bwater: u64,
    pub rwater: u64,
    pub bopts: AOpts,
    pub ropts: AOpts,
    pub claim: Nonce,
    pub host_nonces: [Nonce; 2],
    pub authority_challenges: [AuthorityChallenge; 2],
    pub ok_nonce: Nonce,
    pub ok_claim: Nonce,
    pub ok_action: ClaimKind,
    pub ok_bind: Bind,
    pub ticket_bind: Bind,
    pub daemon_proc: crate::execution::sealed::objects::Proc,
    pub authority_proc: crate::execution::sealed::objects::Proc,
    pub auth_guard: Option<HexDigest>,
    pub retired: HexDigest,
    pub not_before: u64,
    pub expires: u64,
}

/// The registration's original claim is fixture_nonce(11); every other action has its own new claim.
pub(super) fn claim_of(action: ClaimKind) -> Nonce {
    if action == ClaimKind::Register {
        fixture_nonce(11)
    } else {
        fixture_nonce(21)
    }
}

pub(super) fn parts(action: ClaimKind) -> Parts {
    let (gate, guard, intent, water) = states(action);
    Parts {
        bg: gate.clone(),
        rg: gate,
        bguard: guard.clone(),
        rguard: guard,
        bintent: intent.clone(),
        rintent: intent,
        bwater: water,
        rwater: water,
        bopts: AOpts::default(),
        ropts: AOpts::default(),
        claim: claim_of(action),
        host_nonces: [fixture_nonce(1), fixture_nonce(2)],
        authority_challenges: [
            AuthorityChallenge {
                nonce: fixture_nonce(3),
                salt: fixture_nonce(103),
            },
            AuthorityChallenge {
                nonce: fixture_nonce(4),
                salt: fixture_nonce(104),
            },
        ],
        ok_nonce: fixture_nonce(13),
        ok_claim: claim_of(action),
        ok_action: action,
        ok_bind: bind(),
        ticket_bind: bind(),
        daemon_proc: daemon_new(),
        authority_proc: authority_new(),
        auth_guard: None,
        retired: h(&receipt()).unwrap(),
        not_before: 1_000_000,
        expires: 1_030_000,
    }
}

pub(super) fn packet(action: ClaimKind) -> Packet {
    build(action, parts(action))
}

pub(super) fn build(action: ClaimKind, p: Parts) -> Packet {
    let (bh, rh) = (hread(p.bg, p.host_nonces[0]), hread(p.rg, p.host_nonces[1]));
    let ba = aread_with(
        p.bguard,
        p.bintent,
        p.bwater,
        p.authority_challenges[0],
        p.bopts,
    );
    let ra = aread_with(
        p.rguard,
        p.rintent,
        p.rwater,
        p.authority_challenges[1],
        p.ropts,
    );
    let ok_body = ROkBody {
        x: x(),
        plan: plan_hash(),
        action: p.ok_action,
        bind: p.ok_bind,
        owner: fixture_nonce(12),
        claim: p.ok_claim,
        host_proof: h(&rh).unwrap(),
        authority_proof: h(&ra).unwrap(),
        daemon_proc: daemon_new(),
        authority_proc: authority_new(),
        nonce: p.ok_nonce,
    };
    let ok = Sig::sign(Tag::Receiver, ok_body, &TestSigner::rk()).unwrap();
    let ticket = Ticket {
        x: x(),
        plan: plan_hash(),
        action,
        claim: p.claim,
        owner: fixture_nonce(12),
        challenge: fixture_nonce(13),
        bind: p.ticket_bind,
        prior_gate: bh.body.gate_hash.clone(),
        auth_guard: p.auth_guard.or_else(|| Some(ba.body.guard_hash.clone())),
        retired: p.retired,
        authority_proc: p.authority_proc,
        daemon_proc: p.daemon_proc,
        host_proof: h(&bh).unwrap(),
        authority_proof: h(&ba).unwrap(),
        receiver_ok: h(&ok).unwrap(),
        not_before: Uint::new(p.not_before).unwrap(),
        expires: PosInt::new(p.expires).unwrap(),
    };
    let p = Sig::sign(Tag::Decision, ticket, &TestSigner::bk()).unwrap();
    Packet {
        p,
        ok,
        bh,
        ba,
        rh,
        ra,
    }
}

pub(super) fn json<T: Serialize>(value: &T) -> String {
    String::from_utf8(encode(value).unwrap()).unwrap()
}
