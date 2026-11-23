//! Regression tests for the reviewed corrections: owner-partitioned capacity rows, the host
//! process link, the decision predicates, nested signature tags, the cross-scope checks and the
//! rules this codec must not invent. Each case is written against the contract clause it
//! cites and was run against the pre-correction code first.

use super::control::{status, StatusChallenge};
use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, encode, h, CodecError, Wire};
use crate::execution::sealed::custody::Resource;
use crate::execution::sealed::objects::{ClaimKind, Q};
use crate::execution::sealed::sig::{Sig, Tag};
use crate::execution::sealed::tests::{dg, fixture_nonce, id, pos, proc, x, TestSigner};
use crate::execution::sealed::transition::*;
use serde_json::{json, Value};

fn val<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn redecode<T: Wire>(value: &Value) -> Result<T, CodecError> {
    decode(&encode(value).unwrap())
}

fn row(action: &str, basis: &Value) -> Value {
    json!({"action": action, "basis": basis, "expected_ack": null, "next": null, "reserve": null, "target": null})
}

fn with_rows(read: &Value, rows: Vec<Value>) -> Value {
    let mut v = read.clone();
    v["body"]["cap"]["projections"] = Value::Array(rows);
    v
}

const H_ROWS: [&str; 4] = ["seal", "arm", "host_register", "release"];
const A_ROWS: [&str; 2] = ["authority_intent", "authority_ack"];

fn host_read() -> Value {
    val(&hread(gate(GatePhase::Closed), fixture_nonce(1)))
}

fn authority_read() -> Value {
    val(&aread(guard(GuardPhase::Started), None, 2))
}

fn rows_of(read: &Value, names: &[&str]) -> Vec<Value> {
    let basis = if read["body"].get("gate_hash").is_some() {
        &read["body"]["gate_hash"]
    } else {
        &read["body"]["guard_hash"]
    };
    names.iter().map(|name| row(name, basis)).collect()
}

#[test]
fn a_host_read_has_exactly_the_four_host_rows_in_order() {
    let read = host_read();
    redecode::<HRead>(&with_rows(&read, rows_of(&read, &H_ROWS))).unwrap();
    for (why, names) in [
        (
            "wrong order",
            vec!["arm", "seal", "host_register", "release"],
        ),
        (
            "extra authority row",
            vec![
                "seal",
                "arm",
                "host_register",
                "release",
                "authority_intent",
            ],
        ),
        ("missing release", vec!["seal", "arm", "host_register"]),
        (
            "foreign row in place",
            vec!["seal", "arm", "host_register", "authority_intent"],
        ),
        (
            "duplicate",
            vec!["seal", "seal", "host_register", "release"],
        ),
        ("empty", vec![]),
        (
            "all six placeholders",
            vec![
                "seal",
                "arm",
                "host_register",
                "release",
                "authority_intent",
                "authority_ack",
            ],
        ),
        (
            "authority rows only",
            vec!["authority_intent", "authority_ack"],
        ),
    ] {
        let rows = rows_of(&read, &names);
        assert!(redecode::<HRead>(&with_rows(&read, rows)).is_err(), "{why}");
    }
}

#[test]
fn an_authority_read_has_exactly_the_two_authority_rows_in_order() {
    let read = authority_read();
    redecode::<ARead>(&with_rows(&read, rows_of(&read, &A_ROWS))).unwrap();
    for (why, names) in [
        ("wrong order", vec!["authority_ack", "authority_intent"]),
        (
            "extra host row",
            vec!["authority_intent", "authority_ack", "seal"],
        ),
        (
            "host rows first",
            vec![
                "seal",
                "arm",
                "host_register",
                "release",
                "authority_intent",
                "authority_ack",
            ],
        ),
        ("missing ack", vec!["authority_intent"]),
        ("foreign row in place", vec!["seal", "authority_ack"]),
        ("duplicate", vec!["authority_intent", "authority_intent"]),
        ("empty", vec![]),
    ] {
        let rows = rows_of(&read, &names);
        assert!(redecode::<ARead>(&with_rows(&read, rows)).is_err(), "{why}");
    }
}

#[test]
fn the_two_owners_rows_are_the_six_in_the_contract_order() {
    use crate::execution::sealed::objects::PROJECTION_ORDER;
    let all: Vec<&str> = H_ROWS.iter().chain(A_ROWS.iter()).copied().collect();
    let names: Vec<String> = PROJECTION_ORDER
        .iter()
        .map(|a| val(a).as_str().unwrap().to_owned())
        .collect();
    assert_eq!(all, names);
}

#[test]
fn an_owners_rows_keep_their_basis_even_when_all_null() {
    let read = host_read();
    let mut rows = rows_of(&read, &H_ROWS);
    rows[2]["basis"] = json!("0".repeat(64));
    assert!(
        redecode::<HRead>(&with_rows(&read, rows)).is_err(),
        "a null row still has H(Gate)"
    );
    let read = authority_read();
    let mut rows = rows_of(&read, &A_ROWS);
    rows[1]["basis"] = json!("0".repeat(64));
    assert!(
        redecode::<ARead>(&with_rows(&read, rows)).is_err(),
        "a null row still has H(Guard)"
    );
}

#[test]
fn a_host_read_is_by_the_process_the_cut_started() {
    let mut body = hread(gate(GatePhase::Sealed), fixture_nonce(1)).body;
    assert_eq!(body.proc, body.gate.committed_cut().new_proc);
    body.proc = proc(99);
    assert!(
        refused(&body),
        "HRead.proc is gate.cut.new_proc for this serial"
    );
    let mut body = hread(gate(GatePhase::Sealed), fixture_nonce(1)).body;
    body.proc = daemon_old();
    assert!(refused(&body), "not the process the cut retired");
}

fn decision_refused(action: ClaimKind, why: &'static str, tweak: impl FnOnce(&mut Parts)) -> bool {
    let mut p = parts(action);
    tweak(&mut p);
    build(action, p).validate() == Err(CodecError::Value(why))
}

#[test]
fn release_needs_a_ready_authority_in_every_read() {
    packet(ClaimKind::Release).validate().unwrap();
    assert!(
        decision_refused(ClaimKind::Release, "phase need", |p| {
            p.bopts.ready = Some(false);
            p.ropts.ready = Some(false);
        }),
        "release with ready=false in both reads"
    );
    for (name, tweak) in [
        (
            "B's read",
            (|p: &mut Parts| p.bopts.ready = Some(false)) as fn(&mut Parts),
        ),
        ("R's read", |p| p.ropts.ready = Some(false)),
    ] {
        assert!(
            decision_refused(ClaimKind::Release, "packet reads disagree", tweak),
            "release with ready=false only in {name}"
        );
    }
}

#[test]
fn record_ack_needs_no_permanent_uncertainty_in_every_read() {
    packet(ClaimKind::RecordAck).validate().unwrap();
    assert!(decision_refused(ClaimKind::RecordAck, "phase need", |p| {
        p.bopts.uncertain = true;
        p.ropts.uncertain = true;
    }));
    for tweak in [
        (|p: &mut Parts| p.bopts.uncertain = true) as fn(&mut Parts),
        |p| p.ropts.uncertain = true,
    ] {
        assert!(decision_refused(
            ClaimKind::RecordAck,
            "packet reads disagree",
            tweak
        ));
    }
}

#[test]
fn the_registration_row_is_compared_by_its_original_claim_permit_and_witness() {
    for action in [ClaimKind::RecordAck, ClaimKind::Release] {
        let packet = packet(action);
        packet.validate().unwrap();
        let done = packet.bh.body.gate.done.as_ref().unwrap();
        let ticket = &packet.p.body;
        assert_ne!(ticket.claim, done.claim, "{action:?} has its own new claim");
        assert_eq!(packet.ba.body.intent.as_ref().unwrap().claim, done.claim);
        for (what, tweak) in [
            (
                "claim",
                (|i: &mut Intent| i.claim = fixture_nonce(1)) as fn(&mut Intent),
            ),
            ("permit", |i| i.permit = dg('0')),
            ("witness", |i| i.witness = dg('0')),
        ] {
            assert!(
                decision_refused(action, "phase need", |p| {
                    tweak(p.bintent.as_mut().unwrap());
                    tweak(p.rintent.as_mut().unwrap());
                }),
                "{action:?}: intent {what} must be the stored registration's"
            );
        }
        assert!(
            decision_refused(action, "phase need", |p| {
                let mut moved = p.bg.clone();
                moved.done.as_mut().unwrap().claim = ticket.claim;
                p.bg = moved.clone();
                p.rg = moved;
            }),
            "{action:?}: the new claim never stands for the original one"
        );
    }
}

#[test]
fn register_compares_the_adopted_guards_armed_gate_with_the_supplied_gate() {
    packet(ClaimKind::Register).validate().unwrap();
    assert!(decision_refused(ClaimKind::Register, "phase need", |p| {
        p.bguard.armed_gate = Some(dg('0'));
        p.rguard.armed_gate = Some(dg('0'));
    }));
}

#[test]
fn the_authoritys_host_clock_is_the_hosts_process_and_instance() {
    packet(ClaimKind::Arm).validate().unwrap();
    for action in [ClaimKind::Arm, ClaimKind::Register, ClaimKind::Release] {
        assert!(
            decision_refused(action, "packet host clock", |p| p.bopts.clock_proc =
                Some(proc(99))),
            "{action:?}: B's A read samples another host process"
        );
        assert!(
            decision_refused(action, "packet host clock", |p| p.ropts.clock_instance =
                Some(id("hi"))),
            "{action:?}: R's A read samples another host instance"
        );
    }
}

#[test]
fn a_cuts_profile_is_the_deaths_profile() {
    let mut death = daemon_death();
    death.profile = dg('0');
    let mut c = cut();
    c.custody = death.hash().unwrap();
    c.check_death(&death).unwrap_err();
    c.profile = dg('0');
    c.check_death(&death).unwrap();
}

fn release_view(water: u64) -> (ApiViewBody, crate::execution::sealed::objects::Bind) {
    let b = bind();
    let ack = b.record.ack();
    let snapshot = h(&json!({"bind": b, "intent": b.intent, "ack": ack})).unwrap();
    let view = ApiViewBody {
        q: q(fixture_nonce(9)),
        plan: plan_hash(),
        bind: Some(b.clone()),
        step: Some(ClaimKind::RecordAck),
        state: ApiState::Observed,
        claim: Some(fixture_nonce(21)),
        permit: Some(dg('a')),
        api_water: crate::execution::sealed::prim::Uint::new(water).unwrap(),
        row_ack: Some(ack),
        row_intent: Some(b.intent.clone()),
        snapshot: Some(snapshot),
        pause_owned: true,
        interlock_owned: true,
    };
    (view, b)
}

#[test]
fn a_release_view_is_record_ack_observed_with_the_row_triple_and_n_plus_one_together() {
    let (view, b) = release_view(3);
    view.check_release_ready(&b, &fixture_nonce(21)).unwrap();
    let (stale, b) = release_view(2);
    assert!(
        stale.check_release_ready(&b, &fixture_nonce(21)).is_err(),
        "N is the water before the registration commit"
    );
    let (mut view, b) = release_view(3);
    view.snapshot = None;
    view.row_ack = None;
    view.row_intent = None;
    assert!(
        view.check_release_ready(&b, &fixture_nonce(21)).is_err(),
        "no triple"
    );
    let (mut view, b) = release_view(3);
    view.step = Some(ClaimKind::Release);
    assert!(view.check_release_ready(&b, &fixture_nonce(21)).is_err());
}

#[test]
fn an_observed_record_ack_row_carries_its_triple_and_n_plus_one_but_later_steps_are_free() {
    let (view, _) = release_view(3);
    round_trip(&view);
    let (stale, _) = release_view(2);
    assert!(refused(&stale));
    let (mut no_triple, _) = release_view(3);
    no_triple.snapshot = None;
    no_triple.row_ack = None;
    no_triple.row_intent = None;
    assert!(refused(&no_triple));
    let (mut later, _) = release_view(3);
    later.step = Some(ClaimKind::Release);
    later.row_ack = None;
    later.row_intent = None;
    later.snapshot = None;
    round_trip(&later);
}

fn final_read(stage: FinalStage) -> FinalReadBody {
    FinalReadBody {
        q: q(fixture_nonce(8)),
        plan: plan_hash(),
        stage,
        trial: (stage != FinalStage::Held).then(|| dg('c')),
        release: Some(dg('d')),
        placement: if stage == FinalStage::Readmitted {
            Placement::Ready
        } else {
            Placement::Unknown
        },
        row_ack: Some(new_record().ack()),
    }
}

#[test]
fn verified_and_readmitted_need_the_trial_the_release_digest_and_the_original_ack() {
    for stage in [FinalStage::Verified, FinalStage::Readmitted] {
        round_trip(&final_read(stage));
        for (what, tweak) in [
            (
                "trial",
                (|f: &mut FinalReadBody| f.trial = None) as fn(&mut FinalReadBody),
            ),
            ("release", |f| f.release = None),
            ("row ack", |f| f.row_ack = None),
        ] {
            let mut f = final_read(stage);
            tweak(&mut f);
            assert!(refused(&f), "{stage:?} without {what}");
        }
    }
}

#[test]
fn readmitted_records_a_ready_placement_and_held_bans_nothing_but_a_trial() {
    let mut readmitted = final_read(FinalStage::Readmitted);
    readmitted.placement = Placement::Unknown;
    assert!(
        refused(&readmitted),
        "readmitted needs the last placement observation to be ready"
    );
    round_trip(&final_read(FinalStage::Verified));
    let mut held = final_read(FinalStage::Held);
    round_trip(&held);
    held.release = None;
    held.row_ack = None;
    round_trip(&held);
    held.placement = Placement::Ready;
    round_trip(&held);
    held.trial = Some(dg('c'));
    assert!(refused(&held));
}

fn client_state() -> ClientState {
    ClientState {
        q: q(fixture_nonce(42)),
        plan: plan_hash(),
        role: ClientRole::Ng,
        proc: proc(50),
        bind: bind(),
        member: members(2).ng,
        mode: ClientMode::Verification,
    }
}

#[test]
fn a_client_response_is_for_the_binds_operation_and_plan() {
    round_trip(&client_state());
    let mut other_x = client_state();
    other_x.q.x.serial = pos(2);
    assert!(refused(&other_x), "q.x must be bind.x");
    let mut other_plan = client_state();
    other_plan.plan = dg('2');
    assert!(refused(&other_plan), "bind.plan must be the plan");
}

#[test]
fn a_client_query_is_for_the_staged_operation_and_plan() {
    let state = client_state();
    let stage = ClientStageBody {
        x: x(),
        plan: plan_hash(),
        proc: state.proc.clone(),
        role: ClientRole::Ng,
        bind: bind(),
        member: state.member.clone(),
        nonce: fixture_nonce(41),
    };
    let query = ClientQueryBody {
        q: state.q.clone(),
        plan: plan_hash(),
        role: ClientRole::Ng,
        proc: state.proc.clone(),
    };
    state.check(&query, &stage).unwrap();
    let mut other_x = query.clone();
    other_x.q.x.serial = pos(2);
    let mut moved = state.clone();
    moved.q = other_x.q.clone();
    assert!(
        moved.check(&other_x, &stage).is_err(),
        "query q.x is the staged X"
    );
    let mut other_plan = query;
    other_plan.plan = dg('2');
    assert!(state.check(&other_plan, &stage).is_err());
}

#[test]
fn client_enable_pins_the_trial_to_its_bind() {
    let mut trial = super::control::trial();
    let enable = ClientEnableBody {
        x: x(),
        plan: plan_hash(),
        role: ClientRole::Ng,
        proc: proc(50),
        bind: bind(),
        trial: trial.hash().unwrap(),
        nonce: fixture_nonce(43),
    };
    assert!(
        enable.check_trial(&trial).is_err(),
        "the spec trial binds another Bind"
    );
    trial.bind_hash = h(&enable.bind).unwrap();
    let enable = ClientEnableBody {
        trial: trial.hash().unwrap(),
        ..enable
    };
    enable.check_trial(&trial).unwrap();
}

fn hk() -> HkSigner {
    HkSigner::new()
}

#[test]
fn a_nested_receipt_carries_the_retired_tag() {
    let mut g = gate(GatePhase::Sealed);
    g.receipt = Some(Sig::sign(Tag::Intent, ReceiptBody::new(cut()), &hk()).unwrap());
    assert_eq!(decode_err(&g), CodecError::Value("nested tag"));
    g.receipt = Some(receipt());
    round_trip(&g);
}

fn decode_err<T: Wire>(value: &T) -> CodecError {
    decode::<T>(&encode(value).unwrap())
        .map(|_| ())
        .unwrap_err()
}

#[test]
fn nested_launch_signatures_carry_their_own_tags() {
    let d = LDecision {
        x: x(),
        plan: plan_hash(),
        action: LKind::LaunchA,
        owner: fixture_nonce(3),
        expected: proc(12),
        nonce: fixture_nonce(21),
    };
    let ok = LGrant {
        receiver: Sig::sign(Tag::LaunchReceiver, d.clone(), &TestSigner::rk()).unwrap(),
        api: Sig::sign(Tag::LaunchApi, d.clone(), &TestSigner::bk()).unwrap(),
    };
    round_trip(&ok);
    let both_api = LGrant {
        receiver: Sig::sign(Tag::LaunchApi, d.clone(), &TestSigner::rk()).unwrap(),
        api: ok.api.clone(),
    };
    assert_eq!(decode_err(&both_api), CodecError::Value("nested tag"));
    let swapped = LGrant {
        receiver: ok.api.clone(),
        api: ok.receiver.clone(),
    };
    assert_eq!(decode_err(&swapped), CodecError::Value("nested tag"));
    let seal = SealRequest {
        grant: both_api,
        expected_gate: dg('a'),
    };
    assert!(refused(&seal));
}

#[test]
fn a_nested_host_clock_carries_the_host_clock_tag() {
    let mut body = aread(guard(GuardPhase::Adopted), None, 2).body;
    let clock = body.host_clock.body.clone();
    body.host_clock = Sig::sign(Tag::Retired, clock, &hk()).unwrap();
    assert_eq!(decode_err(&body), CodecError::Value("nested tag"));
}

#[test]
fn a_nested_witness_and_the_packet_parts_carry_their_tags() {
    let packet = packet(ClaimKind::Register);
    let mut body = witness_body();
    body.permit = h(&packet.p).unwrap();
    let wrong = Sig::sign(Tag::Decision, body, &TestSigner::ak()).unwrap();
    let request = RegisterRequest {
        packet: packet.clone(),
        witness: wrong,
    };
    assert_eq!(request.validate(), Err(CodecError::Value("nested tag")));

    let retag = |tweak: &dyn Fn(&mut Packet)| {
        let mut p = packet.clone();
        tweak(&mut p);
        p.validate()
    };
    let err = Err(CodecError::Value("nested tag"));
    assert_eq!(
        retag(&|p| p.p = Sig::sign(Tag::Receiver, p.p.body.clone(), &TestSigner::bk()).unwrap()),
        err
    );
    assert_eq!(
        retag(&|p| p.ok = Sig::sign(Tag::Decision, p.ok.body.clone(), &TestSigner::rk()).unwrap()),
        err
    );
    assert_eq!(
        retag(&|p| p.bh = Sig::sign(Tag::AuthorityRead, p.bh.body.clone(), &hk()).unwrap()),
        err
    );
    assert_eq!(
        retag(&|p| p.rh = Sig::sign(Tag::HostClock, p.rh.body.clone(), &hk()).unwrap()),
        err
    );
    assert_eq!(
        retag(&|p| p.ba = Sig::sign(Tag::HostRead, p.ba.body.clone(), &TestSigner::ak()).unwrap()),
        err
    );
    assert_eq!(
        retag(&|p| p.ra = Sig::sign(Tag::Intent, p.ra.body.clone(), &TestSigner::ak()).unwrap()),
        err
    );
}

#[test]
fn a_nested_observe_clock_reattach_and_archive_carry_their_tags() {
    let started = guard(GuardPhase::Started);
    let request = ObserveQueryBody {
        q: q(fixture_nonce(7)),
        plan: plan_hash(),
        kind: ObserveKind::Clock,
        id: None,
    };
    let salt = fixture_nonce(70);
    let clock = host_clock(&request.q, &salt);
    let u = |v| crate::execution::sealed::prim::Uint::new(v).unwrap();
    let mut response = AuthorityObserveBody {
        q: request.q.clone(),
        plan: plan_hash(),
        proc: authority_new(),
        guard: started.hash().unwrap(),
        salt,
        host_now: clock.body.now,
        host_uncertainty: clock.body.uncertainty,
        host_clock: clock.clone(),
        kind: ObserveKind::Clock,
        id: None,
        now: u(1_000),
        uncertainty: u(2),
        status: ObserveStatus::NotRequested,
        evidence: LitNull,
    };
    round_trip(&response);
    response.host_clock = Sig::sign(Tag::Retired, clock.body, &hk()).unwrap();
    assert_eq!(decode_err(&response), CodecError::Value("nested tag"));

    let resume = Resume {
        q: q(fixture_nonce(30)),
        plan: plan_hash(),
        resource: Resource::Daemon,
        observed: daemon_new(),
        launch: dg('8'),
        gate_or_guard: dg('9'),
        set: new_set(),
        instance_or_epoch: id("hi2"),
        mode: ResumeMode::ReattachReadOnly,
    };
    let swapped = Reattach {
        receiver: Sig::sign(Tag::ResumeApi, resume.clone(), &TestSigner::rk()).unwrap(),
        api: Sig::sign(Tag::ResumeReceiver, resume, &TestSigner::bk()).unwrap(),
    };
    assert_eq!(decode_err(&swapped), CodecError::Value("nested tag"));
}

#[test]
fn nested_trial_signatures_carry_their_tags() {
    use crate::execution::sealed::trial::{
        grant_hash, projection_hash, ExecOk, Finished, IssuedBody, Pair, StatusBody, TrialResult,
    };
    let t = super::control::trial();
    let issued_body = IssuedBody {
        trial: t.hash().unwrap(),
        grant_hash: grant_hash("YWJj.ZGVm.Z2hp"),
        projection_hash: projection_hash(b"{}"),
    };
    let execution = ExecOk {
        trial: t.hash().unwrap(),
        run: t.run.clone(),
        grant_id: t.grant_id.clone(),
        delegation_intent: t.delegation_intent.clone(),
        request_hash: t.command_hash.clone(),
        result: TrialResult::success(t.nonce),
    };
    let reply = |rt: Tag, bt: Tag, it: Tag| TrialReply {
        approvals: Pair {
            receiver: Sig::sign(rt, t.clone(), &TestSigner::rk()).unwrap(),
            api: Sig::sign(bt, t.clone(), &TestSigner::bk()).unwrap(),
        },
        issued: Sig::sign(it, issued_body.clone(), &TestSigner::bk()).unwrap(),
        execution: execution.clone(),
    };
    round_trip(&reply(
        Tag::Trial3Receiver,
        Tag::Trial3Api,
        Tag::Trial3Issued,
    ));
    for bad in [
        reply(Tag::Trial3Api, Tag::Trial3Api, Tag::Trial3Issued),
        reply(Tag::Trial3Receiver, Tag::Trial3Receiver, Tag::Trial3Issued),
        reply(Tag::Trial3Receiver, Tag::Trial3Api, Tag::Trial3Api),
    ] {
        assert_eq!(decode_err(&bad), CodecError::Value("nested tag"));
    }

    let status = status(StatusChallenge::B);
    let query = TrialQueryBody {
        q: Q {
            x: x(),
            nonce: fixture_nonce(60),
        },
        plan: dg('1'),
        trial: t.hash().unwrap(),
    };
    let archive = |tag: Tag| ArchiveReplyBody {
        q: query.q.clone(),
        plan: dg('1'),
        trial: query.trial.clone(),
        status: Sig::<StatusBody>::sign(tag, status.body.clone(), &TestSigner::ak()).unwrap(),
    };
    round_trip(&archive(Tag::Trial3Status));
    assert_eq!(
        decode_err(&archive(Tag::Trial3Issued)),
        CodecError::Value("nested tag")
    );
    let _ = Finished::Finished;
}

#[test]
fn a_resume_request_is_the_resume_request_tag() {
    let body = ResumeRequestBody {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        nonce: fixture_nonce(31),
    };
    let request = Sig::sign(Tag::ResumeApi, body, &TestSigner::rk()).unwrap();
    let challenge = ResumeChallengeBody {
        request: h(&request).unwrap(),
        resume: Resume {
            q: q(fixture_nonce(30)),
            plan: plan_hash(),
            resource: Resource::Authority,
            observed: authority_new(),
            launch: dg('8'),
            gate_or_guard: dg('9'),
            set: new_set(),
            instance_or_epoch: id("ep2"),
            mode: ResumeMode::ReattachReadOnly,
        },
    };
    assert!(challenge.check_request(&request).is_err());
}

// ---- rules the codec must not invent ------------------------------------------------------

#[test]
fn process_tuple_inequality_is_not_a_codec_rule() {
    let mut same_cut = cut();
    same_cut.new_proc = same_cut.old_proc.clone();
    round_trip(&same_cut);
    let mut same_death = daemon_death();
    same_death.next = same_death.old.clone();
    round_trip(&same_death);
    let launch = Launch {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        stage: LaunchStage::Observed,
        old: proc(12),
        custodian: proc(10),
        successor: Some(proc(12)),
        death: None,
        nonce: fixture_nonce(4),
    };
    round_trip(&launch);
}

#[test]
fn a_resume_challenge_nonce_is_the_custodians_to_choose() {
    let body = ResumeRequestBody {
        x: x(),
        plan: plan_hash(),
        resource: Resource::Authority,
        owner: fixture_nonce(3),
        nonce: fixture_nonce(31),
    };
    let request = Sig::sign(Tag::ResumeRequest, body, &TestSigner::rk()).unwrap();
    let challenge = ResumeChallengeBody {
        request: h(&request).unwrap(),
        resume: Resume {
            q: Q {
                x: x(),
                nonce: fixture_nonce(31),
            },
            plan: plan_hash(),
            resource: Resource::Authority,
            observed: authority_new(),
            launch: dg('8'),
            gate_or_guard: dg('9'),
            set: new_set(),
            instance_or_epoch: id("ep2"),
            mode: ResumeMode::ReattachReadOnly,
        },
    };
    challenge.check_request(&request).unwrap();
}

#[test]
fn a_bind_intent_is_any_valid_identifier() {
    let mut b = bind();
    b.intent = id("any.valid:intent/1");
    check_bind(&b).unwrap();
}
