//! Ticket, Permit, ROk and the Packet of each of the five crossing actions: the exact phase
//! table, the proof-hash links, independent nonces and the permit window.

use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, encode, h, CodecError, Wire};
use crate::execution::sealed::objects::ClaimKind;
use crate::execution::sealed::sig::{Sig, SigError, Tag};
use crate::execution::sealed::tests::{dg, n, pos, TestSigner};
use crate::execution::sealed::transition::*;

const ALL: [ClaimKind; 5] = [
    ClaimKind::Arm,
    ClaimKind::Adopt,
    ClaimKind::Register,
    ClaimKind::RecordAck,
    ClaimKind::Release,
];

/// The packet is refused for exactly this reason, not merely refused.
fn packet_refused(action: ClaimKind, why: &'static str, tweak: impl FnOnce(&mut Parts)) -> bool {
    let mut p = parts(action);
    tweak(&mut p);
    build(action, p).validate() == Err(CodecError::Value(why))
}

#[test]
fn each_action_packet_is_valid_and_survives_the_packet_codec() {
    for action in ALL {
        let packet = packet(action);
        packet.validate().unwrap();
        let bytes = packet.encode().unwrap();
        assert_eq!(
            Packet::decode_for(&bytes, action).unwrap(),
            packet,
            "{action:?}"
        );
        packet.verify_decision(&bk(), &rk()).unwrap();
    }
}

#[test]
fn a_packet_decodes_only_for_its_own_action() {
    let bytes = packet(ClaimKind::Arm).encode().unwrap();
    assert!(Packet::decode_for(&bytes, ClaimKind::Adopt).is_err());
    assert!(Packet::decode_for(&bytes, ClaimKind::Arm).is_ok());
}

#[test]
fn the_phase_table_is_the_legal_sequence() {
    let need = |a| PhaseNeed::of(a);
    assert_eq!(need(ClaimKind::Arm).gate, GatePhase::Sealed);
    assert_eq!(need(ClaimKind::Adopt).gate, GatePhase::Armed);
    assert_eq!(need(ClaimKind::Adopt).guard, GuardPhase::Started);
    assert_eq!(need(ClaimKind::Register).guard, GuardPhase::Adopted);
    assert_eq!(need(ClaimKind::Register).intent, IntentNeed::Absent);
    assert_eq!(need(ClaimKind::RecordAck).intent, IntentNeed::Pending);
    assert_eq!(need(ClaimKind::Release).intent, IntentNeed::Ready);
    assert!(!need(ClaimKind::Register).registered_water);
    assert!(need(ClaimKind::RecordAck).registered_water);
}

#[test]
fn a_packet_for_the_wrong_phase_is_refused() {
    use GatePhase::*;
    use GuardPhase::*;
    for (action, gate_phase, guard_phase) in [
        (ClaimKind::Arm, Armed, Started),
        (ClaimKind::Arm, Sealed, Adopted),
        (ClaimKind::Register, Sealed, Adopted),
        (ClaimKind::Register, Armed, Started),
    ] {
        let reject = packet_refused(action, "phase need", |p| {
            p.bg = gate(gate_phase);
            p.rg = gate(gate_phase);
            p.bguard = guard(guard_phase);
            p.rguard = guard(guard_phase);
        });
        assert!(reject, "{action:?} accepted {gate_phase:?}/{guard_phase:?}");
    }
    assert!(packet_refused(ClaimKind::Register, "phase need", |p| {
        p.bintent = Some(intent(IntentPhase::Pending));
        p.rintent = Some(intent(IntentPhase::Pending));
        p.bwater = 3;
        p.rwater = 3;
    }));
    assert!(packet_refused(ClaimKind::RecordAck, "phase need", |p| {
        p.bintent = Some(intent(IntentPhase::Ready));
        p.rintent = Some(intent(IntentPhase::Ready));
    }));
    assert!(packet_refused(ClaimKind::Release, "phase need", |p| {
        p.bintent = Some(intent(IntentPhase::Pending));
        p.rintent = Some(intent(IntentPhase::Pending));
    }));
}

#[test]
fn water_is_n_before_the_registration_and_n_plus_one_after() {
    assert!(packet_refused(
        ClaimKind::Arm,
        "packet reads disagree",
        |p| p.bwater = 3
    ));
    assert!(packet_refused(
        ClaimKind::Arm,
        "packet reads disagree",
        |p| p.rwater = 3
    ));
    assert!(packet_refused(ClaimKind::Arm, "phase need", |p| {
        p.bwater = 3;
        p.rwater = 3
    }));
    assert!(packet_refused(ClaimKind::Register, "phase need", |p| {
        p.bwater = 3;
        p.rwater = 3
    }));
    assert!(packet_refused(
        ClaimKind::RecordAck,
        "packet reads disagree",
        |p| p.bwater = 2
    ));
    assert!(packet_refused(ClaimKind::RecordAck, "phase need", |p| {
        p.bwater = 2;
        p.rwater = 2
    }));
    assert!(packet_refused(
        ClaimKind::Release,
        "packet reads disagree",
        |p| p.rwater = 2
    ));
}

#[test]
fn the_four_logical_states_must_agree() {
    assert!(packet_refused(
        ClaimKind::Arm,
        "packet reads disagree",
        |p| {
            p.rg = gate(GatePhase::Armed);
        }
    ));
    assert!(packet_refused(
        ClaimKind::Register,
        "packet reads disagree",
        |p| {
            p.rguard = guard(GuardPhase::Started);
        }
    ));
    assert!(packet_refused(
        ClaimKind::RecordAck,
        "packet reads disagree",
        |p| {
            p.rintent = Some(intent(IntentPhase::Ready));
            p.rwater = 3;
        }
    ));
    assert!(packet_refused(
        ClaimKind::Arm,
        "packet reads disagree",
        |p| p.rwater = 3
    ));
}

#[test]
fn b_and_r_reads_use_independent_nonces() {
    assert!(packet_refused(
        ClaimKind::Arm,
        "packet reads disagree",
        |p| p.nonces = [1, 1, 3, 4]
    ));
    assert!(packet_refused(
        ClaimKind::Arm,
        "packet reads disagree",
        |p| p.nonces = [1, 2, 3, 3]
    ));
}

#[test]
fn the_receiver_approval_echoes_owner_claim_and_challenge() {
    assert!(packet_refused(ClaimKind::Arm, "packet receiver ok", |p| {
        p.ok_nonce = n(99)
    }));
    assert!(packet_refused(ClaimKind::Arm, "packet receiver ok", |p| {
        p.ok_claim = n(99)
    }));
    assert!(packet_refused(ClaimKind::Arm, "packet receiver ok", |p| {
        p.ok_action = ClaimKind::Adopt
    }));
    assert!(packet_refused(ClaimKind::Arm, "packet receiver ok", |p| {
        let mut b = bind();
        b.intent = crate::execution::sealed::tests::id("register:sealed:other");
        p.ok_bind = b;
    }));
}

#[test]
fn ticket_links_prior_gate_receipt_guard_and_processes() {
    assert!(packet_refused(ClaimKind::Arm, "packet links", |p| p
        .retired =
        dg('0')));
    assert!(packet_refused(ClaimKind::Arm, "packet links", |p| p
        .auth_guard =
        Some(dg('0'))));
    assert!(packet_refused(ClaimKind::Arm, "packet scope", |p| p
        .daemon_proc =
        crate::execution::sealed::tests::proc(99)));
    assert!(packet_refused(ClaimKind::Arm, "packet scope", |p| p
        .authority_proc =
        crate::execution::sealed::tests::proc(99)));
}

#[test]
fn proof_hashes_commit_to_the_complete_envelopes() {
    let mut packet = packet(ClaimKind::Arm);
    packet.validate().unwrap();
    let hash = h(&packet.bh).unwrap();
    assert_eq!(packet.p.body.host_proof, hash);
    assert_eq!(packet.p.body.receiver_ok, h(&packet.ok).unwrap());
    assert_eq!(packet.ok.body.host_proof, h(&packet.rh).unwrap());
    packet.bh.sig = crate::execution::sealed::prim::Bytes::from_array([0; 64]);
    assert!(
        packet.validate().is_err(),
        "a different envelope is a different hash"
    );
}

#[test]
fn ticket_requires_a_non_null_auth_guard_and_a_window_of_at_most_thirty_seconds() {
    let ticket = packet(ClaimKind::Arm).p.body;
    round_trip(&ticket);
    let mut t = ticket.clone();
    t.auth_guard = None;
    assert!(refused(&t));
    let mut t = ticket.clone();
    t.expires = pos(t.not_before.get() + 30_001);
    assert!(refused(&t));
    let mut t = ticket.clone();
    t.expires = pos(t.not_before.get());
    assert!(refused(&t));
    let mut t = ticket.clone();
    t.expires = pos(t.not_before.get() + 30_000);
    assert!(!refused(&t));
    let mut t = ticket;
    t.plan = dg('2');
    assert!(refused(&t));
}

#[test]
fn the_qualified_interval_must_lie_fully_inside_the_window() {
    let ticket = packet(ClaimKind::Arm).p.body;
    let (lo, hi) = (ticket.not_before.get(), ticket.expires.get());
    assert!(ticket.window_contains(lo, hi - 1));
    assert!(ticket.window_contains(lo + 5, lo + 10));
    assert!(!ticket.window_contains(lo - 1, lo + 5), "starts early");
    assert!(!ticket.window_contains(lo, hi), "the end is exclusive");
    assert!(
        !ticket.window_contains(lo + 10, lo + 5),
        "an inverted interval"
    );
}

#[test]
fn permit_and_approval_verify_only_under_their_own_roles() {
    let packet = packet(ClaimKind::Arm);
    assert_eq!(
        packet.p.verify(Tag::Decision, &rk()),
        Err(SigError::RoleNotPermitted)
    );
    assert_eq!(
        packet.ok.verify(Tag::Receiver, &bk()),
        Err(SigError::RoleNotPermitted)
    );
    assert!(packet.verify_decision(&rk(), &bk()).is_err());
    let swapped = Sig::sign(Tag::Decision, packet.p.body.clone(), &TestSigner::rk());
    assert!(swapped.is_ok(), "the signer cannot see the tag's role");
    assert_eq!(
        swapped.unwrap().verify(Tag::Decision, &bk()),
        Err(SigError::KeyMismatch)
    );
}

#[test]
fn review_request_is_answered_by_exactly_the_approval_that_echoes_it() {
    let packet = packet(ClaimKind::Arm);
    let review = ReviewRequestBody {
        x: packet.ok.body.x.clone(),
        plan: plan_hash(),
        action: ClaimKind::Arm,
        bind: bind(),
        owner: n(12),
        claim: n(21),
        nonce: n(13),
    };
    round_trip(&review);
    packet.ok.body.check_review(&review).unwrap();
    for mutate in [
        (|r: &mut ReviewRequestBody| r.nonce = n(1)) as fn(&mut _),
        |r| r.claim = n(1),
        |r| r.owner = n(1),
        |r| r.action = ClaimKind::Adopt,
    ] {
        let mut other = review.clone();
        mutate(&mut other);
        assert!(packet.ok.body.check_review(&other).is_err());
    }
}

#[test]
fn a_register_request_carries_the_authoritys_witness_for_exactly_its_permit() {
    let packet = packet(ClaimKind::Register);
    let mut body = witness_body();
    body.permit = h(&packet.p).unwrap();
    let witness = Sig::sign(Tag::Intent, body.clone(), &TestSigner::ak()).unwrap();
    let request = RegisterRequest {
        packet: packet.clone(),
        witness,
    };
    request.validate().unwrap();
    let bytes = request.encode().unwrap();
    assert_eq!(RegisterRequest::decode(&bytes).unwrap(), request);

    for mutate in [
        (|b: &mut WitnessBody| b.permit = dg('0')) as fn(&mut _),
        |b| b.claim = n(1),
        |b| b.guard = dg('0'),
        |b| b.proc = crate::execution::sealed::tests::proc(99),
    ] {
        let mut other = body.clone();
        mutate(&mut other);
        let witness = Sig::sign(Tag::Intent, other, &TestSigner::ak()).unwrap();
        assert!(RegisterRequest {
            packet: packet.clone(),
            witness
        }
        .validate()
        .is_err());
    }
    let arm = RegisterRequest {
        packet: self::packet(ClaimKind::Arm),
        witness: Sig::sign(Tag::Intent, body, &TestSigner::ak()).unwrap(),
    };
    assert_eq!(arm.validate(), Err(CodecError::Value("register witness")));
}

#[test]
fn a_packet_over_one_mebibyte_is_refused_and_inner_objects_stay_within_64_kib() {
    let bytes = packet(ClaimKind::Register).encode().unwrap();
    assert!(bytes.len() < 64 * 1024, "{} bytes", bytes.len());
    let mut huge = bytes.clone();
    huge.resize(PACKET_LIMITS.max_bytes + 1, b' ');
    assert_eq!(
        Packet::decode_for(&huge, ClaimKind::Register),
        Err(CodecError::TooLarge)
    );
    assert!(decode::<Packet>(&encode(&packet(ClaimKind::Arm)).unwrap()).is_ok());
}
