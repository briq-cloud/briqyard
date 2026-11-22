//! Client stage/query/enable, the trial3 control envelopes and the final read, tied to the
//! contract's trial vectors where it publishes them.

use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, h};
use crate::execution::sealed::objects::{Q, X};
use crate::execution::sealed::sig::{Sig, SigError, Tag};
use crate::execution::sealed::tests::{dg, fixture_nonce, id, n, proc, x, TestSigner};
use crate::execution::sealed::transition::*;
use crate::execution::sealed::trial::{
    grant_hash, projection_hash, ExecOk, Finished, IssuedBody, Pair, StatusBody, Trial, TrialResult,
};

const TRIAL_C: &str = r#"{"bind_hash":"2222222222222222222222222222222222222222222222222222222222222222","briq":"bq_test","command_hash":"2185b234c3057b055f3b29f9a70ff91c3bf02ecbfff0e68a4a23f30528e30287","delegation_intent":"00000000-0000-4000-8000-000000000002","gateway_origin_hash":"a22d921f8a3627f28785fddc967a13ef72b3895f66606e838fd5f9effae14c2f","grant_id":"00000000-0000-4000-8000-000000000001","key_id":"key.test","machine":"machine.test","namespace":"ns.test","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","plan":"1111111111111111111111111111111111111111111111111111111111111111","run":"00000000-0000-4000-8000-000000000003","stack":"stack.test","team":"team.test","x":{"aud":"staging","host":"host.test","op":"0000000000000000000000000000000000000000000000000000000000000000","serial":1}}"#;
const TRIAL_HASH: &str = "19cb57255012b10e768c516d3b8db7bc30d45932a4612d63d5f9610d6f841b76";
const STATUS_B_SIG: &str =
    "mfZG9eB4fJHNXs3x3t57HF7D7VpuMB6PKkfqsJ4cxd1QANhso-iRkGhHEMZx4YZ7dGQbJUdQJz6r9Ueh-Dn4Ag";
const STATUS_B_HASH: &str = "c76d347393ec9b593327adfeddeaff66557525fe2cc9d2808c7052eb49cae137";
const STATUS_R_HASH: &str = "349f372c0208ced612812f743064b99033f8ac9188756fd685b73ec124c77ac1";

pub(super) fn trial() -> Trial {
    decode(TRIAL_C.as_bytes()).unwrap()
}

pub(super) fn status(nonce: u8) -> Sig<StatusBody> {
    let t = trial();
    let body = StatusBody {
        q: Q {
            x: t.x.clone(),
            nonce: n(nonce),
        },
        plan: t.plan.clone(),
        trial: t.hash().unwrap(),
        proc: proc(18),
        bind_hash: t.bind_hash.clone(),
        run: t.run.clone(),
        grant_id: t.grant_id.clone(),
        delegation_intent: t.delegation_intent.clone(),
        request_hash: t.command_hash.clone(),
        grant_hash: grant_hash("YWJj.ZGVm.Z2hp"),
        projection_hash: projection_hash(b"{}"),
        phase: Finished::Finished,
        outcome: TrialResult::success(t.nonce).outcome(),
    };
    Sig::sign(Tag::Trial3Status, body, &TestSigner::ak()).unwrap()
}

fn stage(role: ClientRole) -> ClientStageBody {
    let members = members(2);
    ClientStageBody {
        x: x(),
        plan: plan_hash(),
        proc: proc(50),
        role,
        bind: bind(),
        member: match role {
            ClientRole::Ni => members.ni,
            ClientRole::Ng => members.ng,
        },
        nonce: fixture_nonce(41),
    }
}

#[test]
fn client_stage_names_the_roles_member_in_the_set_the_bind_pins() {
    for role in [ClientRole::Ni, ClientRole::Ng] {
        let body = stage(role);
        round_trip(&body);
        body.check_members(&members(2)).unwrap();
        assert!(body.check_members(&members(3)).is_err());
        let signed = Sig::sign(Tag::ClientStage, body.clone(), &TestSigner::bk()).unwrap();
        signed.verify(Tag::ClientStage, &bk()).unwrap();
        assert_eq!(
            signed.verify(Tag::ClientStage, &rk()),
            Err(SigError::RoleNotPermitted)
        );
    }
    let mut crossed = stage(ClientRole::Ni);
    crossed.member = members(2).ng;
    assert!(
        crossed.check_members(&members(2)).is_err(),
        "ni never receives the ng role"
    );
    let mut wrong_plan = stage(ClientRole::Ni);
    wrong_plan.plan = dg('2');
    assert!(refused(&wrong_plan));
    assert!(decode::<ClientStageBody>(
        json(&stage(ClientRole::Ni))
            .replace("\"ni\"", "\"hi\"")
            .as_bytes()
    )
    .is_err());
}

#[test]
fn client_state_answers_one_query_from_the_staged_slot() {
    let stage = stage(ClientRole::Ng);
    let query = ClientQueryBody {
        q: q(42),
        plan: plan_hash(),
        role: ClientRole::Ng,
        proc: stage.proc.clone(),
    };
    for signer_role in [(TestSigner::bk(), bk()), (TestSigner::rk(), rk())] {
        let signed = Sig::sign(Tag::ClientQuery, query.clone(), &signer_role.0).unwrap();
        signed.verify(Tag::ClientQuery, &signer_role.1).unwrap();
    }
    assert!(
        Sig::sign(Tag::ClientQuery, query.clone(), &TestSigner::ak())
            .unwrap()
            .verify(Tag::ClientQuery, &ak())
            .is_err()
    );
    let state = ClientState {
        q: query.q.clone(),
        plan: plan_hash(),
        role: query.role,
        proc: query.proc.clone(),
        bind: stage.bind.clone(),
        member: stage.member.clone(),
        mode: ClientMode::Verification,
    };
    round_trip(&state);
    state.check(&query, &stage).unwrap();
    let normal = ClientState {
        mode: ClientMode::Normal,
        ..state.clone()
    };
    normal.check(&query, &stage).unwrap();
    for mutate in [
        (|s: &mut ClientState| s.q.nonce = fixture_nonce(1)) as fn(&mut ClientState),
        |s| s.proc = proc(51),
        |s| s.member = dg('0'),
        |s| s.role = ClientRole::Ni,
    ] {
        let mut other = state.clone();
        mutate(&mut other);
        assert!(other.check(&query, &stage).is_err());
    }
}

#[test]
fn client_enable_carries_h_trial_never_the_status_hash() {
    let trial = trial();
    assert_eq!(trial.hash().unwrap().as_str(), TRIAL_HASH);
    let mut pinned = trial.clone();
    pinned.bind_hash = h(&bind()).unwrap();
    let enable = ClientEnableBody {
        x: x(),
        plan: plan_hash(),
        role: ClientRole::Ng,
        proc: proc(50),
        bind: bind(),
        trial: pinned.hash().unwrap(),
        nonce: fixture_nonce(43),
    };
    round_trip(&enable);
    enable.check_trial(&pinned).unwrap();
    assert_ne!(enable.trial.as_str(), TRIAL_HASH);
    let mut other_trial = enable.clone();
    other_trial.trial = trial.hash().unwrap();
    assert!(
        other_trial.check_trial(&trial).is_err(),
        "the trial pins this exact Bind"
    );
    let mut with_status = enable.clone();
    with_status.trial = h(&status(1)).unwrap();
    assert!(with_status.check_trial(&pinned).is_err());
    let signed = Sig::sign(Tag::ClientEnable, enable, &TestSigner::bk()).unwrap();
    signed.verify(Tag::ClientEnable, &bk()).unwrap();
}

#[test]
fn the_archived_status_is_the_complete_b_challenged_envelope() {
    let b_status = status(1);
    assert_eq!(b_status.sig.to_text(), STATUS_B_SIG);
    assert_eq!(h(&b_status).unwrap().as_str(), STATUS_B_HASH);
    assert_eq!(h(&status(2)).unwrap().as_str(), STATUS_R_HASH);

    let query = TrialQueryBody {
        q: Q {
            x: x(),
            nonce: fixture_nonce(60),
        },
        plan: dg('1'),
        trial: trial().hash().unwrap(),
    };
    for tag in [Tag::Trial3Archive, Tag::Trial3Observe] {
        let signed = Sig::sign(tag, query.clone(), &TestSigner::rk()).unwrap();
        signed.verify(tag, &rk()).unwrap();
    }
    assert!(
        Sig::sign(Tag::Trial3Observe, query.clone(), &TestSigner::bk())
            .unwrap()
            .verify(Tag::Trial3Observe, &bk())
            .is_ok()
    );
    assert!(
        Sig::sign(Tag::Trial3Archive, query.clone(), &TestSigner::bk())
            .unwrap()
            .verify(Tag::Trial3Archive, &bk())
            .is_err()
    );

    let reply = ArchiveReplyBody {
        q: query.q.clone(),
        plan: dg('1'),
        trial: query.trial.clone(),
        status: b_status.clone(),
    };
    round_trip(&reply);
    reply.check_query(&query).unwrap();
    reply.verify_status(&ak()).unwrap();
    assert_eq!(
        reply.archived_status_hash().unwrap().as_str(),
        STATUS_B_HASH
    );
    let signed = Sig::sign(Tag::Trial3ArchiveReply, reply.clone(), &TestSigner::bk()).unwrap();
    signed.verify(Tag::Trial3ArchiveReply, &bk()).unwrap();
    assert_ne!(
        reply.archived_status_hash().unwrap(),
        h(&status(2)).unwrap(),
        "R's own status is a different envelope and never the archive"
    );

    let mut other_trial = reply.clone();
    other_trial.trial = dg('0');
    assert!(refused(&other_trial));
    let mut other_plan = reply.clone();
    other_plan.plan = dg('2');
    assert!(refused(&other_plan));
    let mut other_nonce = reply.clone();
    other_nonce.q.nonce = fixture_nonce(61);
    assert!(other_nonce.check_query(&query).is_err());
}

#[test]
fn offer_is_one_trial_for_the_queried_plan_and_bind_hash() {
    let query = OfferQueryBody {
        q: q(70),
        plan: dg('1'),
        bind_hash: dg('2'),
    };
    round_trip(&query);
    let offer = OfferBody {
        q: Q {
            x: trial().x,
            nonce: fixture_nonce(70),
        },
        trial: trial(),
    };
    round_trip(&offer);
    offer.check_query(&query).unwrap();
    let mut other_bind = query.clone();
    other_bind.bind_hash = dg('3');
    assert!(offer.check_query(&other_bind).is_err());
    let mut other_nonce = offer.clone();
    other_nonce.q.nonce = fixture_nonce(71);
    assert!(other_nonce.check_query(&query).is_err());
    let mut other_scope = offer.clone();
    other_scope.q.x = X {
        serial: crate::execution::sealed::tests::pos(2),
        ..x()
    };
    assert!(refused(&other_scope));
    let signed = Sig::sign(Tag::Trial3Offer, offer, &TestSigner::bk()).unwrap();
    signed.verify(Tag::Trial3Offer, &bk()).unwrap();
    assert!(Sig::sign(Tag::Trial3OfferQuery, query, &TestSigner::rk())
        .unwrap()
        .verify(Tag::Trial3OfferQuery, &rk())
        .is_ok());
}

#[test]
fn the_issue_reply_is_both_approvals_issuance_and_the_exact_execution() {
    let t = trial();
    let approvals = Pair {
        receiver: Sig::sign(Tag::Trial3Receiver, t.clone(), &TestSigner::rk()).unwrap(),
        api: Sig::sign(Tag::Trial3Api, t.clone(), &TestSigner::bk()).unwrap(),
    };
    let issued = Sig::sign(
        Tag::Trial3Issued,
        IssuedBody {
            trial: t.hash().unwrap(),
            grant_hash: grant_hash("YWJj.ZGVm.Z2hp"),
            projection_hash: projection_hash(b"{}"),
        },
        &TestSigner::bk(),
    )
    .unwrap();
    let execution = ExecOk {
        trial: t.hash().unwrap(),
        run: t.run.clone(),
        grant_id: t.grant_id.clone(),
        delegation_intent: t.delegation_intent.clone(),
        request_hash: t.command_hash.clone(),
        result: TrialResult::success(t.nonce),
    };
    let reply = TrialReply {
        approvals,
        issued,
        execution,
    };
    round_trip(&reply);
    let text = json(&reply);
    assert!(text.starts_with(r#"{"approvals":"#) && text.contains(r#","execution":{"#));
    assert!(
        !text.contains("grant\":"),
        "the raw grant is never part of the reply"
    );

    let mut wrong_run = reply.clone();
    wrong_run.execution.run = t.grant_id.clone();
    assert!(refused(&wrong_run));
    let mut other_issued = reply.clone();
    other_issued.issued.body.trial = dg('0');
    assert!(refused(&other_issued));
    let mut wrong_request = reply;
    wrong_request.execution.request_hash = dg('0');
    assert!(refused(&wrong_request));
    let _ = id("x");
}
