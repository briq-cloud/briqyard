//! HRead, ARead, ApiView, the observe pair, the final read and the capacity predicates.

use super::fixtures::*;
use crate::execution::sealed::canonical::CodecError;
use crate::execution::sealed::objects::{ClaimKind, ProjectionAction, Q};
use crate::execution::sealed::prim::Bytes;
use crate::execution::sealed::sig::{Sig, SigError, Tag};
use crate::execution::sealed::tests::{dg, fixture_nonce, id, pos, x, TestSigner};
use crate::execution::sealed::transition::*;

const PHASES: [GatePhase; 5] = [
    GatePhase::Closed,
    GatePhase::Sealed,
    GatePhase::Armed,
    GatePhase::Registered,
    GatePhase::Released,
];

#[test]
fn host_reads_of_every_phase_are_valid_and_signed_by_hk() {
    for phase in PHASES {
        let read = hread(gate(phase), 1);
        round_trip(&read);
        read.verify(Tag::HostRead, &HkSigner::new().pinned())
            .unwrap();
        assert_eq!(
            read.verify(Tag::HostRead, &ak()),
            Err(SigError::RoleNotPermitted)
        );
    }
}

#[test]
fn a_host_read_links_its_gate_by_hash_scope_and_water() {
    let body = hread(gate(GatePhase::Sealed), 1).body;
    let mut b = body.clone();
    b.gate_hash = dg('0');
    assert!(refused(&b));
    let mut b = body.clone();
    b.water = crate::execution::sealed::prim::Uint::new(3).unwrap();
    assert!(refused(&b), "sealed water is the cut's prior water");
    let mut b = body.clone();
    b.plan = dg('2');
    assert!(refused(&b));
    let mut b = body.clone();
    b.q.x.serial = pos(2);
    assert!(refused(&b));
    let registered = hread(gate(GatePhase::Registered), 1).body;
    assert_eq!(registered.water.get(), 3, "registered water is N+1");
}

#[test]
fn host_capacity_rows_are_based_on_the_gate_and_past_rows_are_null() {
    let body = hread(gate(GatePhase::Armed), 1).body;
    let mut b = body.clone();
    b.cap.projections[1].basis = dg('0');
    assert!(refused(&b), "arm row basis is H(Gate)");
    let mut b = body.clone();
    b.cap.projections[0].target = Some(dg('e'));
    assert!(refused(&b), "seal is past for an armed gate");
    let mut b = body.clone();
    b.cap.projections[1].reserve = Some(dims(1, true));
    assert!(refused(&b), "arm is past for an armed gate");
    let mut b = body.clone();
    b.cap.projections[2].target = None;
    b.cap.projections[2].reserve = None;
    assert!(!refused(&b), "an unbindable future row may be all-null");
    let mut b = body;
    b.cap.projections[2].next = Some(dims(1, true));
    b.cap.projections[2].target = None;
    assert!(refused(&b), "a row without a target has no next");
}

#[test]
fn authority_reads_are_valid_and_signed_by_ak() {
    for (guard, intent, water) in [
        (guard(GuardPhase::Started), None, 2),
        (guard(GuardPhase::Adopted), None, 2),
        (
            guard(GuardPhase::Adopted),
            Some(intent(IntentPhase::Pending)),
            3,
        ),
        (
            guard(GuardPhase::Adopted),
            Some(intent(IntentPhase::Ready)),
            3,
        ),
    ] {
        let read = aread(guard, intent, water, 5);
        round_trip(&read);
        read.verify(Tag::AuthorityRead, &ak()).unwrap();
        assert_eq!(
            read.verify(Tag::AuthorityRead, &bk()),
            Err(SigError::RoleNotPermitted)
        );
    }
}

#[test]
fn an_authority_read_links_guard_process_and_the_salted_host_clock() {
    let body = aread(guard(GuardPhase::Adopted), None, 2, 5).body;
    let mut b = body.clone();
    b.guard_hash = dg('0');
    assert!(refused(&b));
    let mut b = body.clone();
    b.proc = crate::execution::sealed::tests::proc(99);
    assert!(refused(&b), "guard.proc is the actual process");
    let mut b = body.clone();
    b.salt = fixture_nonce(1);
    assert_eq!(
        decode_err(&b),
        CodecError::Value("host clock challenge"),
        "the nested clock answers the salted challenge"
    );
    let mut b = body.clone();
    b.q.nonce = fixture_nonce(77);
    assert_eq!(decode_err(&b), CodecError::Value("host clock challenge"));
    let mut b = body.clone();
    b.host_clock.body.plan = dg('2');
    assert_eq!(decode_err(&b), CodecError::Value("host clock scope"));
    let mut b = body;
    b.host_clock.body.uncertainty = crate::execution::sealed::prim::Uint::new(6).unwrap();
    assert!(refused(&b), "clock uncertainty is at most 5 s");
}

fn decode_err<T: crate::execution::sealed::canonical::Wire>(value: &T) -> CodecError {
    crate::execution::sealed::canonical::decode::<T>(
        &crate::execution::sealed::canonical::encode(value).unwrap(),
    )
    .map(|_| ())
    .unwrap_err()
}

#[test]
fn the_salted_challenge_is_a_sha256_of_the_canonical_outer_query_plan_and_salt() {
    let outer = q(5);
    let salt = fixture_nonce(105);
    let nonce = host_challenge_nonce(&outer, &plan_hash(), &salt).unwrap();
    let canonical = format!(
        r#"{{"outer":{},"plan":"{}","salt":"{}"}}"#,
        json(&outer),
        plan_hash(),
        salt.to_text()
    );
    let expected = <sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes());
    assert_eq!(nonce, Bytes::from_array(expected.into()));
    assert_ne!(
        nonce,
        host_challenge_nonce(&outer, &plan_hash(), &fixture_nonce(106)).unwrap()
    );
    assert_ne!(
        nonce,
        host_challenge_nonce(&q(6), &plan_hash(), &salt).unwrap()
    );
}

#[test]
fn ready_needs_a_ready_intent_and_no_permanent_uncertainty() {
    let body = aread(
        guard(GuardPhase::Adopted),
        Some(intent(IntentPhase::Ready)),
        3,
        5,
    )
    .body;
    assert!(body.ready);
    let mut b = body.clone();
    b.uncertain = true;
    assert!(refused(&b));
    let mut b = body.clone();
    b.intent = None;
    assert!(refused(&b));
    let pending = aread(
        guard(GuardPhase::Adopted),
        Some(intent(IntentPhase::Pending)),
        3,
        5,
    )
    .body;
    assert!(!pending.ready);
    let mut b = pending;
    b.ready = true;
    assert!(refused(&b), "pending is never ready");
    let mut b = body;
    b.ready = false;
    assert!(
        !refused(&b),
        "a stale clock may leave a ready intent unready"
    );
}

#[test]
fn an_actual_intent_must_be_the_adopted_guards_original() {
    let body = aread(
        guard(GuardPhase::Adopted),
        Some(intent(IntentPhase::Pending)),
        3,
        5,
    )
    .body;
    let mut b = body.clone();
    b.intent.as_mut().unwrap().id = id("register:sealed:other");
    assert!(refused(&b));
    let mut b = body.clone();
    b.intent.as_mut().unwrap().guard = dg('0');
    assert!(refused(&b));
    let mut b = body.clone();
    b.intent.as_mut().unwrap().record = reg("hi2", "ep2", 4);
    assert!(refused(&b));
    let mut b = body;
    b.guard = guard(GuardPhase::Started);
    b.guard_hash = b.guard.hash().unwrap();
    assert!(
        refused(&b),
        "an intent outside any binding is a refusal, not null"
    );
}

#[test]
fn authority_capacity_rows_report_passed_actions_as_all_null() {
    let started = aread(guard(GuardPhase::Started), None, 2, 5).body;
    let mut b = started.clone();
    b.cap.projections[0].basis = dg('0');
    assert!(refused(&b), "A rows are based on H(Guard)");
    let pending = aread(
        guard(GuardPhase::Adopted),
        Some(intent(IntentPhase::Pending)),
        3,
        5,
    )
    .body;
    assert!(pending.cap.projections[0].target.is_none());
    assert!(pending.cap.projections[1].target.is_some());
    let mut b = pending.clone();
    b.cap.projections[0].target = Some(dg('e'));
    assert!(refused(&b));
    let mut b = pending;
    b.cap.projections[1].target = Some(dg('e'));
    assert!(
        !refused(&b),
        "the ack row is still ahead of a pending intent"
    );
}

#[test]
fn intent_selection_follows_the_bind_or_the_preview_of_an_unbound_started_guard() {
    let started = aread(guard(GuardPhase::Started), None, 2, 5).body;
    started.check_selection(None).unwrap();
    started.check_selection(Some(&bind())).unwrap();
    let mut wrong_epoch = bind();
    wrong_epoch.record.epoch = id("ep9");
    wrong_epoch.ctx = wrong_epoch.record.ctx(&x().host);
    assert!(started.check_selection(Some(&wrong_epoch)).is_err());
    let mut wrong_set = bind();
    wrong_set.set = dg('0');
    assert!(started.check_selection(Some(&wrong_set)).is_err());

    let mut no_id = started.clone();
    no_id.uncertain = true;
    assert!(
        no_id.check_selection(None).is_err(),
        "no id selected, no marker"
    );
    assert!(
        no_id.check_selection(Some(&bind())).is_ok(),
        "a marker for the selected id"
    );

    let adopted = aread(
        guard(GuardPhase::Adopted),
        Some(intent(IntentPhase::Pending)),
        3,
        5,
    )
    .body;
    adopted.check_selection(None).unwrap();
    let mut other_preview = bind();
    other_preview.intent = id("register:sealed:other");
    adopted.check_selection(Some(&other_preview)).unwrap();
}

fn api_view(state: ApiState, bind_present: bool) -> ApiViewBody {
    ApiViewBody {
        q: q(9),
        plan: plan_hash(),
        bind: bind_present.then(bind),
        step: None,
        state,
        claim: None,
        permit: None,
        api_water: crate::execution::sealed::prim::Uint::new(2).unwrap(),
        row_ack: None,
        row_intent: None,
        snapshot: None,
        pause_owned: true,
        interlock_owned: true,
    }
}

fn with_identity(mut v: ApiViewBody) -> ApiViewBody {
    v.step = Some(ClaimKind::RecordAck);
    v.claim = Some(fixture_nonce(11));
    v
}

#[test]
fn api_view_states_have_exactly_their_identity_fields() {
    round_trip(&api_view(ApiState::Frozen, false));
    round_trip(&api_view(ApiState::Frozen, true));
    for state in [ApiState::Reserved, ApiState::Abandoned] {
        round_trip(&with_identity(api_view(state, true)));
        let mut with_permit = with_identity(api_view(state, true));
        with_permit.permit = Some(dg('a'));
        assert!(refused(&with_permit), "{state:?} never has a permit");
        assert!(
            refused(&api_view(state, true)),
            "{state:?} keeps bind, step and claim"
        );
        assert!(refused(&with_identity(api_view(state, false))));
    }
    round_trip(&with_identity(api_view(ApiState::Committing, true)));
    let mut conveyable = with_identity(api_view(ApiState::Committing, true));
    conveyable.permit = Some(dg('a'));
    round_trip(&conveyable);
    assert!(refused(&api_view(ApiState::Committing, true)));
    let mut observed = with_identity(api_view(ApiState::Observed, true));
    observed.step = Some(ClaimKind::Arm);
    assert!(refused(&observed), "observed retains the permit");
    observed.permit = Some(dg('a'));
    round_trip(&observed);
    let mut record_ack = with_identity(api_view(ApiState::Observed, true));
    record_ack.permit = Some(dg('a'));
    assert!(
        refused(&record_ack),
        "an observed record_ack keeps its row triple and N+1 water"
    );
    let mut frozen = api_view(ApiState::Frozen, true);
    frozen.claim = Some(fixture_nonce(1));
    assert!(refused(&frozen), "frozen has no claim");
    let mut frozen = api_view(ApiState::Frozen, false);
    frozen.step = Some(ClaimKind::Arm);
    assert!(refused(&frozen));
}

#[test]
fn the_row_triple_is_all_null_or_all_present_and_bound_to_the_original_row() {
    let b = bind();
    let ack = b.record.ack();
    let snapshot = crate::execution::sealed::canonical::h(&serde_json::json!({
        "bind": b,
        "intent": b.intent,
        "ack": ack,
    }))
    .unwrap();
    let mut ready = with_identity(api_view(ApiState::Observed, true));
    ready.permit = Some(dg('a'));
    ready.row_intent = Some(b.intent.clone());
    ready.row_ack = Some(ack);
    ready.snapshot = Some(snapshot);
    ready.api_water = crate::execution::sealed::prim::Uint::new(b.record.generation.get()).unwrap();
    round_trip(&ready);
    for mutate in [
        (|v: &mut ApiViewBody| v.snapshot = None) as fn(&mut ApiViewBody),
        |v| v.row_ack = None,
        |v| v.row_intent = None,
        |v| v.snapshot = Some(dg('0')),
        |v| v.row_intent = Some(id("register:sealed:other")),
        |v| v.row_ack.as_mut().unwrap().digest = fixture_nonce(1),
        |v| v.bind = None,
        |v| v.api_water = crate::execution::sealed::prim::Uint::new(2).unwrap(),
    ] {
        let mut v = ready.clone();
        mutate(&mut v);
        assert!(refused(&v));
    }
    ready.check_release_ready(&b, &fixture_nonce(11)).unwrap();
    assert!(ready.check_release_ready(&b, &fixture_nonce(12)).is_err());
    let mut arm_step = ready.clone();
    arm_step.step = Some(ClaimKind::Arm);
    assert!(arm_step
        .check_release_ready(&b, &fixture_nonce(11))
        .is_err());
    let mut unobserved = ready;
    unobserved.state = ApiState::Committing;
    assert!(unobserved
        .check_release_ready(&b, &fixture_nonce(11))
        .is_err());
}

#[test]
fn a_crossing_needs_the_committing_exact_slot_owned_holds_and_the_right_api_water() {
    let permit = dg('a');
    let mut v = with_identity(api_view(ApiState::Committing, true));
    v.step = Some(ClaimKind::Arm);
    v.permit = Some(permit.clone());
    v.check_crossing(&bind(), ClaimKind::Arm, &fixture_nonce(11), &permit)
        .unwrap();
    assert!(v
        .check_crossing(&bind(), ClaimKind::Adopt, &fixture_nonce(11), &permit)
        .is_err());
    assert!(v
        .check_crossing(&bind(), ClaimKind::Arm, &fixture_nonce(12), &permit)
        .is_err());
    assert!(v
        .check_crossing(&bind(), ClaimKind::Arm, &fixture_nonce(11), &dg('b'))
        .is_err());
    let mut released = v.clone();
    released.pause_owned = false;
    assert!(released
        .check_crossing(&bind(), ClaimKind::Arm, &fixture_nonce(11), &permit)
        .is_err());
    let mut observed = v.clone();
    observed.state = ApiState::Observed;
    assert!(observed
        .check_crossing(&bind(), ClaimKind::Arm, &fixture_nonce(11), &permit)
        .is_err());
    let mut registered = v;
    registered.step = Some(ClaimKind::Register);
    assert!(registered
        .check_crossing(&bind(), ClaimKind::Register, &fixture_nonce(11), &permit)
        .is_err());
    registered.api_water = crate::execution::sealed::prim::Uint::new(3).unwrap();
    registered
        .check_crossing(&bind(), ClaimKind::Register, &fixture_nonce(11), &permit)
        .unwrap();
}

fn observe_pair(
    kind: ObserveKind,
    id_text: Option<&str>,
) -> (ObserveQueryBody, AuthorityObserveBody) {
    let request = ObserveQueryBody {
        q: q(7),
        plan: plan_hash(),
        kind,
        id: id_text.map(id),
    };
    let salt = fixture_nonce(70);
    let clock = host_clock(&request.q, &salt);
    let (status, ident) = match kind {
        ObserveKind::Clock => (ObserveStatus::NotRequested, None),
        ObserveKind::Protection => (ObserveStatus::Unknown, id_text.map(id)),
    };
    let u = |v| crate::execution::sealed::prim::Uint::new(v).unwrap();
    let response = AuthorityObserveBody {
        q: request.q.clone(),
        plan: plan_hash(),
        proc: authority_new(),
        guard: guard_hash(GuardPhase::Started),
        salt,
        host_now: clock.body.now,
        host_uncertainty: clock.body.uncertainty,
        host_clock: clock,
        kind,
        id: ident,
        now: u(1_000),
        uncertainty: u(2),
        status,
        evidence: LitNull,
    };
    (request, response)
}

#[test]
fn observe_answers_exactly_its_query_with_a_null_evidence_and_two_statuses() {
    let (clock_req, clock_resp) = observe_pair(ObserveKind::Clock, None);
    let (prot_req, prot_resp) = observe_pair(ObserveKind::Protection, Some("protect:grant"));
    round_trip(&clock_req);
    round_trip(&clock_resp);
    round_trip(&prot_req);
    round_trip(&prot_resp);
    let started = guard(GuardPhase::Started);
    clock_resp.check_request(&clock_req, &started).unwrap();
    prot_resp.check_request(&prot_req, &started).unwrap();
    assert!(prot_resp.check_request(&clock_req, &started).is_err());
    assert!(clock_resp
        .check_request(&clock_req, &guard(GuardPhase::Adopted))
        .is_err());

    let wire = json(&prot_resp);
    assert!(wire.contains(r#""evidence":null"#));
    assert!(
        crate::execution::sealed::canonical::decode::<AuthorityObserveBody>(
            wire.replace(r#""evidence":null"#, r#""evidence":"x""#)
                .as_bytes()
        )
        .is_err()
    );
    let signed = Sig::sign(Tag::AuthorityObserve, prot_resp, &TestSigner::ak()).unwrap();
    signed.verify(Tag::AuthorityObserve, &ak()).unwrap();
}

#[test]
fn observe_kind_id_and_status_must_agree() {
    let (_, clock) = observe_pair(ObserveKind::Clock, None);
    let (_, prot) = observe_pair(ObserveKind::Protection, Some("protect:grant"));
    let mut b = clock.clone();
    b.status = ObserveStatus::Unknown;
    assert!(refused(&b));
    let mut b = clock.clone();
    b.id = Some(id("protect:grant"));
    assert!(refused(&b));
    let mut b = prot.clone();
    b.status = ObserveStatus::NotRequested;
    assert!(refused(&b));
    let mut b = prot.clone();
    b.id = None;
    assert!(refused(&b));
    let u = |v| crate::execution::sealed::prim::Uint::new(v).unwrap();
    let mut b = clock.clone();
    b.uncertainty = u(6);
    assert!(refused(&b));
    let mut b = clock.clone();
    b.host_now = u(1);
    assert!(refused(&b), "the host sample equals the nested clock reply");
    let mut b = clock;
    b.salt = fixture_nonce(1);
    assert!(refused(&b), "the nested clock answers A's salted challenge");
    let (query_clock_id, _) = observe_pair(ObserveKind::Clock, None);
    let mut bad = query_clock_id;
    bad.id = Some(id("x"));
    assert!(refused(&bad));
    let mut bad = observe_pair(ObserveKind::Protection, Some("p")).0;
    bad.id = None;
    assert!(refused(&bad));
}

#[test]
fn final_read_has_a_trial_commitment_only_once_verified() {
    let base = FinalReadBody {
        q: q(8),
        plan: plan_hash(),
        stage: FinalStage::Held,
        trial: None,
        release: Some(dg('d')),
        placement: Placement::Unknown,
        row_ack: Some(new_record().ack()),
    };
    round_trip(&base);
    for stage in [FinalStage::Verified, FinalStage::Readmitted] {
        let mut b = base.clone();
        b.stage = stage;
        assert!(refused(&b), "{stage:?} needs the archived trial commitment");
        b.trial = Some(dg('c'));
        b.placement = if stage == FinalStage::Readmitted {
            assert!(refused(&b), "readmitted needs the ready placement");
            Placement::Ready
        } else {
            Placement::Unknown
        };
        round_trip(&b);
        let mut no_release = b.clone();
        no_release.release = None;
        assert!(refused(&no_release), "{stage:?} needs the release digest");
        let mut no_ack = b.clone();
        no_ack.row_ack = None;
        assert!(refused(&no_ack), "{stage:?} needs the original row ACK");
    }
    let mut held_bare = base.clone();
    held_bare.release = None;
    held_bare.row_ack = None;
    round_trip(&held_bare);
    let mut held = base.clone();
    held.trial = Some(dg('c'));
    assert!(refused(&held));
    let query = FinalQueryBody {
        q: q(8),
        plan: plan_hash(),
    };
    base.check_query(&query).unwrap();
    let other = FinalQueryBody {
        q: Q {
            x: x(),
            nonce: fixture_nonce(9),
        },
        plan: plan_hash(),
    };
    assert!(base.check_query(&other).is_err());
}

#[test]
fn capacity_fits_only_with_exact_targets_and_fitting_reserves() {
    let hash = dg('f');
    let all = owner_cap(&hash, &H_ROWS, &[]);
    require_fit(&all, &[ProjectionAction::Arm, ProjectionAction::Release]).unwrap();
    let mut no_target = all.clone();
    no_target.projections[1].target = None;
    no_target.projections[1].reserve = None;
    assert!(
        require_fit(&no_target, &[ProjectionAction::Arm]).is_err(),
        "unknown is not fit"
    );
    let mut tight = all.clone();
    tight.projections[3].reserve = Some(dims(1, false));
    assert!(require_fit(&tight, &[ProjectionAction::Release]).is_err());
    assert!(require_fit(&tight, &[ProjectionAction::Arm]).is_ok());
    let mut next = all;
    next.projections[2].next = Some(dims(1, false));
    assert!(require_fit(&next, &[ProjectionAction::HostRegister]).is_err());
}
