//! Launch, the two-signature launch grant, Death, Secrets and Resume.

use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, encode, CodecError};
use crate::execution::sealed::custody::{CustodyWire, Resource, Slot};
use crate::execution::sealed::objects::X;
use crate::execution::sealed::sig::{Sig, SigError, Tag};
use crate::execution::sealed::tests::{dg, fixture_nonce, id, proc, x, TestSigner};
use crate::execution::sealed::transition::*;

fn launch(stage: LaunchStage) -> Launch {
    let rank = stage as u8;
    Launch {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        stage,
        old: proc(12),
        custodian: proc(10),
        successor: (rank >= 3).then(authority_new),
        death: (rank >= 4).then(|| authority_death().hash().unwrap()),
        nonce: fixture_nonce(4),
    }
}

fn authority_death() -> Death {
    Death {
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        old: proc(12),
        next: authority_new(),
        custodian: proc(10),
        challenge: fixture_nonce(5),
        ..daemon_death()
    }
}

#[test]
fn launch_stages_have_the_successor_and_death_only_when_they_exist() {
    for stage in [
        LaunchStage::Closed,
        LaunchStage::Captured,
        LaunchStage::Consumed,
        LaunchStage::Observed,
        LaunchStage::Retired,
    ] {
        round_trip(&launch(stage));
    }
    for stage in [
        LaunchStage::Closed,
        LaunchStage::Captured,
        LaunchStage::Consumed,
    ] {
        let mut l = launch(stage);
        l.successor = Some(authority_new());
        assert!(refused(&l), "{stage:?} has no successor yet");
        let mut l = launch(stage);
        l.death = Some(dg('a'));
        assert!(refused(&l), "{stage:?} has no death yet");
    }
    let mut observed = launch(LaunchStage::Observed);
    observed.successor = None;
    assert!(refused(&observed));
    observed = launch(LaunchStage::Observed);
    observed.death = Some(dg('a'));
    assert!(refused(&observed), "observed has no death yet");
    let mut retired = launch(LaunchStage::Retired);
    retired.death = None;
    assert!(refused(&retired));
}

#[test]
fn a_launch_advances_one_stage_at_a_time_and_keeps_owner_and_nonce() {
    let stages = [
        LaunchStage::Closed,
        LaunchStage::Captured,
        LaunchStage::Consumed,
        LaunchStage::Observed,
        LaunchStage::Retired,
    ];
    for pair in stages.windows(2) {
        launch(pair[0]).check_next(&launch(pair[1])).unwrap();
    }
    assert!(launch(LaunchStage::Closed)
        .check_next(&launch(LaunchStage::Consumed))
        .is_err());
    assert!(launch(LaunchStage::Consumed)
        .check_next(&launch(LaunchStage::Consumed))
        .is_err());
    assert!(launch(LaunchStage::Observed)
        .check_next(&launch(LaunchStage::Consumed))
        .is_err());
    for mutate in [
        (|l: &mut Launch| l.owner = fixture_nonce(9)) as fn(&mut Launch),
        |l| l.nonce = fixture_nonce(9),
        |l| l.old = proc(13),
        |l| l.custodian = proc(11),
        |l| l.plan = dg('2'),
        |l| l.resource = Resource::Daemon,
    ] {
        let mut next = launch(LaunchStage::Captured);
        mutate(&mut next);
        assert!(launch(LaunchStage::Closed).check_next(&next).is_err());
    }
    let mut moved = launch(LaunchStage::Retired);
    moved.successor = Some(proc(77));
    assert!(
        launch(LaunchStage::Observed).check_next(&moved).is_err(),
        "the successor is fixed once observed"
    );
}

#[test]
fn the_spec_capture_wire_is_this_launchs_capture() {
    let capture = CustodyWire {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        custodian: proc(10),
        old: proc(12),
        next: None,
        challenge: fixture_nonce(4),
        slot: Slot::new(27).unwrap(),
    };
    launch(LaunchStage::Captured)
        .check_capture(&capture)
        .unwrap();
    for mutate in [
        (|c: &mut CustodyWire| c.challenge = fixture_nonce(5)) as fn(&mut CustodyWire),
        |c| c.owner = fixture_nonce(9),
        |c| c.old = proc(13),
        |c| c.next = Some(proc(18)),
        |c| c.resource = Resource::Daemon,
    ] {
        let mut other = capture.clone();
        mutate(&mut other);
        assert!(launch(LaunchStage::Captured).check_capture(&other).is_err());
    }
}

#[test]
fn guard_launch_is_the_hash_of_the_consumed_launch_only() {
    let consumed = launch(LaunchStage::Consumed);
    let mut g = guard(GuardPhase::Started);
    g.launch = consumed.hash().unwrap();
    g.check_launch(&consumed).unwrap();
    assert!(g.check_launch(&launch(LaunchStage::Observed)).is_err());
    assert!(g.check_launch(&launch(LaunchStage::Captured)).is_err());
    let mut daemon = consumed.clone();
    daemon.resource = Resource::Daemon;
    assert!(g.check_launch(&daemon).is_err());
}

#[test]
fn the_launch_death_link_names_the_same_owner_processes_and_hash() {
    let retired = launch(LaunchStage::Retired);
    retired.check_death(&authority_death()).unwrap();
    for mutate in [
        (|d: &mut Death| d.owner = fixture_nonce(9)) as fn(&mut Death),
        |d| d.old = proc(13),
        |d| d.next = proc(41),
        |d| d.profile = dg('0'),
        |d| d.custodian = proc(11),
    ] {
        let mut d = authority_death();
        mutate(&mut d);
        assert!(retired.check_death(&d).is_err());
    }
    assert!(launch(LaunchStage::Observed)
        .check_death(&authority_death())
        .is_err());
}

#[test]
fn death_is_true_exited_zero_writers_durable_and_its_challenge_is_the_wire_challenge() {
    let death = authority_death();
    round_trip(&death);
    let text = json(&death);
    for (from, to) in [
        (r#""exited":true"#, r#""exited":false"#),
        (r#""external_writers":0"#, r#""external_writers":1"#),
        (r#""durable":true"#, r#""durable":false"#),
    ] {
        assert!(text.contains(from));
        assert!(decode::<Death>(text.replace(from, to).as_bytes()).is_err());
    }
    let request = CustodyWire {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        custodian: proc(10),
        old: proc(12),
        next: Some(authority_new()),
        challenge: fixture_nonce(5),
        slot: Slot::new(27).unwrap(),
    };
    death.check_wire(&request).unwrap();
    let mut other = request;
    other.challenge = fixture_nonce(6);
    assert!(death.check_wire(&other).is_err());
}

fn decision(action: LKind) -> LDecision {
    LDecision {
        x: x(),
        plan: plan_hash(),
        action,
        owner: fixture_nonce(3),
        expected: proc(12),
        nonce: fixture_nonce(21),
    }
}

fn grant(body: &LDecision) -> LGrant {
    LGrant {
        receiver: Sig::sign(Tag::LaunchReceiver, body.clone(), &TestSigner::rk()).unwrap(),
        api: Sig::sign(Tag::LaunchApi, body.clone(), &TestSigner::bk()).unwrap(),
    }
}

#[test]
fn a_launch_grant_is_two_signatures_over_one_identical_decision() {
    for action in [LKind::LaunchD, LKind::Seal, LKind::LaunchA] {
        let g = grant(&decision(action));
        round_trip(&g);
        assert_eq!(g.verify(&rk(), &bk()).unwrap(), &decision(action));
    }
    assert_eq!(g_text(LKind::LaunchD), r#""action":"launch_d""#);
    assert_eq!(g_text(LKind::Seal), r#""action":"seal""#);
    assert_eq!(g_text(LKind::LaunchA), r#""action":"launch_a""#);

    let g = grant(&decision(LKind::LaunchA));
    assert!(g.verify(&bk(), &rk()).is_err(), "swapped keys");
    let mut other = decision(LKind::LaunchA);
    other.nonce = fixture_nonce(22);
    let mixed = LGrant {
        receiver: g.receiver.clone(),
        api: Sig::sign(Tag::LaunchApi, other, &TestSigner::bk()).unwrap(),
    };
    assert!(refused(&mixed), "bodies must be identical");
    let wrong_tag = LGrant {
        receiver: Sig::sign(Tag::LaunchApi, decision(LKind::LaunchA), &TestSigner::rk()).unwrap(),
        api: g.api.clone(),
    };
    assert_eq!(wrong_tag.verify(&rk(), &bk()), Err(SigError::WrongTag));
}

fn g_text(action: LKind) -> String {
    let text = json(&decision(action));
    let start = text.find(r#""action""#).unwrap();
    let end = start + text[start..].find(',').unwrap();
    text[start..end].to_owned()
}

#[test]
fn a_decision_is_for_this_resources_launch_owner_and_expected_process() {
    let consumed = launch(LaunchStage::Consumed);
    decision(LKind::LaunchA).check_launch(&consumed).unwrap();
    assert!(
        decision(LKind::LaunchD).check_launch(&consumed).is_err(),
        "launch_d is the daemon's"
    );
    let mut wrong_owner = decision(LKind::LaunchA);
    wrong_owner.owner = fixture_nonce(9);
    assert!(wrong_owner.check_launch(&consumed).is_err());
    let mut wrong_proc = decision(LKind::LaunchA);
    wrong_proc.expected = proc(13);
    assert!(wrong_proc.check_launch(&consumed).is_err());
    let mut wrong_plan = decision(LKind::LaunchA);
    wrong_plan.plan = dg('2');
    assert!(wrong_plan.check_launch(&consumed).is_err());

    let daemon = Launch {
        resource: Resource::Daemon,
        old: daemon_old(),
        successor: Some(daemon_new()),
        stage: LaunchStage::Observed,
        ..launch(LaunchStage::Observed)
    };
    let mut seal = decision(LKind::Seal);
    seal.expected = daemon_new();
    seal.check_launch(&daemon).unwrap();
    seal.expected = daemon_old();
    assert!(
        seal.check_launch(&daemon).is_err(),
        "seal expects the new daemon"
    );
    let mut launch_d = decision(LKind::LaunchD);
    launch_d.expected = daemon_old();
    launch_d.check_launch(&daemon).unwrap();
    let _: X = x();
}

#[test]
fn a_seal_request_carries_only_a_seal_grant() {
    let ok = SealRequest {
        grant: grant(&decision(LKind::Seal)),
        expected_gate: dg('a'),
    };
    round_trip(&ok);
    let launch_grant = SealRequest {
        grant: grant(&decision(LKind::LaunchD)),
        expected_gate: dg('a'),
    };
    assert!(refused(&launch_grant));
}

#[test]
fn secrets_are_redacted_validated_and_checked_against_the_member_digest() {
    let value = Bearer::from_random(&fixture_nonce(7));
    assert!(value.expose().starts_with("brx_") && value.expose().len() == 47);
    assert_eq!(format!("{value:?}"), "Bearer(<redacted>)");
    let secrets = Secrets {
        x: x(),
        plan: plan_hash(),
        member: Member::Ni,
        value: value.clone(),
    };
    assert!(!format!("{secrets:?}").contains(&value.expose()[4..]));
    round_trip(&secrets);
    let mut members = members(2);
    members.ni = value.digest();
    secrets.check_members(&members).unwrap();
    assert_eq!(
        value.digest().as_str().len(),
        64,
        "the digest is hex SHA-256 of the exact UTF-8 bearer bytes"
    );
    assert_eq!(
        value.digest(),
        crate::execution::sealed::prim::HexDigest::of(value.expose().as_bytes())
    );
    members.ni = dg('0');
    assert!(secrets.check_members(&members).is_err());
    let tr = Secrets {
        member: Member::Tr,
        ..secrets.clone()
    };
    let mut legacy = members.clone();
    legacy.ni = value.digest();
    legacy.tr = None;
    assert!(
        tr.check_members(&legacy).is_err(),
        "no transition member in a legacy set"
    );

    for bad in [
        "",
        "brx_",
        "brx_AAAA",
        "BRX_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "xxx_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "brx_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    ] {
        assert!(Bearer::new(bad).is_err(), "{bad}");
    }
    let text = json(&secrets);
    assert!(decode::<Secrets>(text.replace("\"ni\"", "\"zz\"").as_bytes()).is_err());
}

fn resume(resource: Resource) -> Resume {
    let gate = gate(GatePhase::Sealed);
    let guard = guard(GuardPhase::Started);
    let (gate_or_guard, instance_or_epoch, observed) = match resource {
        Resource::Daemon => (gate.hash().unwrap(), gate.instance.clone(), daemon_new()),
        Resource::Authority => (
            guard.hash().unwrap(),
            guard.epoch.clone(),
            guard.proc.clone(),
        ),
    };
    Resume {
        q: q(30),
        plan: plan_hash(),
        resource,
        observed,
        launch: dg('8'),
        gate_or_guard,
        set: new_set(),
        instance_or_epoch,
        mode: ResumeMode::ReattachReadOnly,
    }
}

#[test]
fn resume_names_the_exact_gate_or_guard_and_is_read_only() {
    let daemon = resume(Resource::Daemon);
    let authority = resume(Resource::Authority);
    round_trip(&daemon);
    daemon.check_gate(&gate(GatePhase::Sealed)).unwrap();
    assert!(
        daemon.check_gate(&gate(GatePhase::Armed)).is_err(),
        "another gate"
    );
    assert!(daemon.check_guard(&guard(GuardPhase::Started)).is_err());
    authority.check_guard(&guard(GuardPhase::Started)).unwrap();
    assert!(
        authority.check_guard(&guard(GuardPhase::Adopted)).is_err(),
        "never an abbreviated guard"
    );
    assert!(authority.check_gate(&gate(GatePhase::Sealed)).is_err());
    let text = json(&daemon);
    assert!(text.contains(r#""mode":"reattach_read_only""#));
    assert!(decode::<Resume>(text.replace("reattach_read_only", "reattach").as_bytes()).is_err());
}

#[test]
fn a_resume_challenge_answers_exactly_the_request_envelope() {
    let request = Sig::sign(
        Tag::ResumeRequest,
        ResumeRequestBody {
            x: x(),
            plan: plan_hash(),
            resource: Resource::Authority,
            owner: fixture_nonce(3),
            nonce: fixture_nonce(31),
        },
        &TestSigner::rk(),
    )
    .unwrap();
    let challenge = ResumeChallengeBody {
        request: crate::execution::sealed::canonical::h(&request).unwrap(),
        resume: resume(Resource::Authority),
    };
    round_trip(&challenge);
    challenge.check_request(&request).unwrap();
    let mut other = challenge.clone();
    other.request = dg('0');
    assert!(other.check_request(&request).is_err());
    let mut other = challenge.clone();
    other.resume.resource = Resource::Daemon;
    assert!(other.check_request(&request).is_err());
    let _ = encode(&request).unwrap();
}

#[test]
fn reattach_needs_identical_resume_bodies_under_both_roles() {
    let body = resume(Resource::Daemon);
    let reattach = Reattach {
        receiver: Sig::sign(Tag::ResumeReceiver, body.clone(), &TestSigner::rk()).unwrap(),
        api: Sig::sign(Tag::ResumeApi, body.clone(), &TestSigner::bk()).unwrap(),
    };
    round_trip(&reattach);
    assert_eq!(reattach.verify(&rk(), &bk()).unwrap(), &body);
    assert!(reattach.verify(&bk(), &rk()).is_err());
    let mut other = body;
    other.q.nonce = fixture_nonce(99);
    let mixed = Reattach {
        receiver: reattach.receiver.clone(),
        api: Sig::sign(Tag::ResumeApi, other, &TestSigner::bk()).unwrap(),
    };
    assert!(refused(&mixed));
    let _ = (CodecError::Schema, id("x"));
}
