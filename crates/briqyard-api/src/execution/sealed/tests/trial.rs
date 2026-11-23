//! The sealed-trial vectors: C(Trial), the origin and command commitments, approvals,
//! issuance, status, the archived status commitment and the timeout rule.

use super::vectors::{AK_PUBLIC, BK_PUBLIC, RK_PUBLIC};
use super::*;
use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::objects::Q;
use crate::execution::sealed::sig::{Role, Sig, SigError, Tag};
use crate::execution::sealed::trial::{
    command_hash, command_preimage, grant_hash, projection_hash, trial_timeout_ms, ExecBody,
    ExecOk, Finished, IssuedBody, Job, Origin, Pair, StatusBody, TimeoutRefused, Trial,
    TrialRequest, TrialResult,
};

pub(super) const TRIAL_C: &str = r#"{"bind_hash":"2222222222222222222222222222222222222222222222222222222222222222","briq":"bq_test","command_hash":"2185b234c3057b055f3b29f9a70ff91c3bf02ecbfff0e68a4a23f30528e30287","delegation_intent":"00000000-0000-4000-8000-000000000002","gateway_origin_hash":"a22d921f8a3627f28785fddc967a13ef72b3895f66606e838fd5f9effae14c2f","grant_id":"00000000-0000-4000-8000-000000000001","key_id":"key.test","machine":"machine.test","namespace":"ns.test","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","plan":"1111111111111111111111111111111111111111111111111111111111111111","run":"00000000-0000-4000-8000-000000000003","stack":"stack.test","team":"team.test","x":{"aud":"staging","host":"host.test","op":"0000000000000000000000000000000000000000000000000000000000000000","serial":1}}"#;
const COMMAND_PREIMAGE_HEX: &str = "62726971796172642d657865632d726571756573742d7631000000000000000004000000000000000c2f62696e2f62757379626f7800000000000000067072696e746600000000000000022573000000000000002b4141414141414141414141414141414141414141414141414141414141414141414141414141414141414100000000000000000000000000000000000000000000000000000000000003e8";
const COMMAND_HASH: &str = "2185b234c3057b055f3b29f9a70ff91c3bf02ecbfff0e68a4a23f30528e30287";
const NATIVE_REQUEST_DIGEST: &str = "IYWyNMMFewVfOyn5pw_5HDvwLsv_8OaKSiPzBSjjAoc";
const ORIGIN_HASH: &str = "a22d921f8a3627f28785fddc967a13ef72b3895f66606e838fd5f9effae14c2f";
const REQUEST_JSON: &str = r#"{"cmd":["/bin/busybox","printf","%s","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],"cwd":"","env":{},"stdin":"","timeout_ms":1000,"wake":false}"#;
const TRIAL_HASH: &str = "19cb57255012b10e768c516d3b8db7bc30d45932a4612d63d5f9610d6f841b76";
const RA_HASH: &str = "a4e73e6a0166235868acc5857c06413661d3b6bf1b6763d273d9120194a74ff9";
const BA_HASH: &str = "00125cb9bbc3ea646a6c8385034f80a1301b3e6a8680867bf74d8031b29b3eac";
const GRANT_HASH: &str = "72ef7e4f5c3e51d52485efca7d2dafa0dc012ec85fcec59be88baebb241c2b84";
const PROJECTION_HASH: &str = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const ISSUED_HASH: &str = "c6818565608b749c634b96c910a36f0e60c259473ef49fa075e84d02c057d8f3";
const JOB_HASH: &str = "9ec3d6ebeb778d6471822ac025593997c9602a7bf87d353e94f776f90369c6bd";
const OUTCOME_PREIMAGE: &str = r#"{"stdout":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","stderr":"","exit_code":0,"timed_out":false}"#;
const OUTCOME: &str = "56b95774e301b14efdeb34933a1a1b56cb77b689dbeda4997df2fea5fdbb15cc";
const STATUS_B_SIG: &str =
    "mfZG9eB4fJHNXs3x3t57HF7D7VpuMB6PKkfqsJ4cxd1QANhso-iRkGhHEMZx4YZ7dGQbJUdQJz6r9Ueh-Dn4Ag";
const STATUS_B_HASH: &str = "c76d347393ec9b593327adfeddeaff66557525fe2cc9d2808c7052eb49cae137";
const STATUS_R_HASH: &str = "349f372c0208ced612812f743064b99033f8ac9188756fd685b73ec124c77ac1";

pub(super) fn trial() -> Trial {
    decode(TRIAL_C.as_bytes()).unwrap()
}

fn ra() -> Sig<Trial> {
    Sig::sign(Tag::Trial3Receiver, trial(), &TestSigner::rk()).unwrap()
}

fn ba() -> Sig<Trial> {
    Sig::sign(Tag::Trial3Api, trial(), &TestSigner::bk()).unwrap()
}

fn issued_body() -> IssuedBody {
    IssuedBody {
        trial: trial().hash().unwrap(),
        grant_hash: grant_hash("YWJj.ZGVm.Z2hp"),
        projection_hash: projection_hash(b"{}"),
    }
}

fn issued() -> Sig<IssuedBody> {
    Sig::sign(Tag::Trial3Issued, issued_body(), &TestSigner::bk()).unwrap()
}

fn job() -> Job {
    Job {
        approvals: Pair {
            receiver: ra(),
            api: ba(),
        },
        issued: issued(),
    }
}

fn status(nonce_byte: u8) -> Sig<StatusBody> {
    let t = trial();
    let body = StatusBody {
        q: Q {
            x: t.x.clone(),
            nonce: n(nonce_byte),
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

#[test]
fn trial_is_the_exact_canonical_bytes_and_hash() {
    let trial = trial();
    assert_eq!(encode(&trial).unwrap(), TRIAL_C.as_bytes());
    assert_eq!(trial.hash().unwrap().as_str(), TRIAL_HASH);
    assert_eq!(trial.nonce, n(0));
}

#[test]
fn origin_commitment_matches_the_preimage_and_vector() {
    let origin = Origin::new("https://gw.staging.example").unwrap();
    let preimage = [
        &b"briqyard/trial-origin/v3"[..],
        &[0],
        b"https://gw.staging.example",
    ]
    .concat();
    assert_eq!(HexDigest::of(&preimage).as_str(), ORIGIN_HASH);
    assert_eq!(origin.hash().as_str(), ORIGIN_HASH);
    trial().check_origin(&origin).unwrap();
}

#[test]
fn command_commitment_matches_the_raw_binary_preimage_and_the_native_digest() {
    assert_eq!(hex::encode(command_preimage(&n(0))), COMMAND_PREIMAGE_HEX);
    assert_eq!(command_hash(&n(0)).as_str(), COMMAND_HASH);
    let request = TrialRequest::for_nonce(n(0));
    assert_eq!(encode(&request).unwrap(), REQUEST_JSON.as_bytes());
    assert_eq!(
        request.native_request_digest().unwrap(),
        NATIVE_REQUEST_DIGEST
    );
    let native = Bytes::<32>::parse(NATIVE_REQUEST_DIGEST).unwrap();
    assert_eq!(
        HexDigest::from_raw(*native.as_array()).as_str(),
        COMMAND_HASH
    );
}

#[test]
fn the_native_request_is_the_closed_canary() {
    let native = TrialRequest::for_nonce(n(0)).to_native();
    assert_eq!(
        native.cmd,
        [
            "/bin/busybox",
            "printf",
            "%s",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ]
    );
    assert!(native.env.is_empty() && native.cwd.is_empty() && native.stdin.is_empty());
    assert_eq!((native.timeout_ms, native.wake), (1000, false));
}

#[test]
fn approvals_issuance_and_job_hash_vectors() {
    assert_eq!(h(&ra()).unwrap().as_str(), RA_HASH);
    assert_eq!(h(&ba()).unwrap().as_str(), BA_HASH);
    assert_eq!(grant_hash("YWJj.ZGVm.Z2hp").as_str(), GRANT_HASH);
    assert_eq!(projection_hash(b"{}").as_str(), PROJECTION_HASH);
    assert_eq!(h(&issued()).unwrap().as_str(), ISSUED_HASH);
    assert_eq!(h(&job()).unwrap().as_str(), JOB_HASH);
    let rk = TestSigner::rk().pinned(Role::Rk);
    let bk = TestSigner::bk().pinned(Role::Bk);
    assert_eq!(job().verify(&rk, &bk).unwrap(), &trial());
    let bytes = encode(&job()).unwrap();
    let decoded: Job = decode(&bytes).unwrap();
    assert_eq!(decoded, job());
}

#[test]
fn g_to_a_body_is_job_plus_the_exact_request() {
    let body = ExecBody {
        job: job(),
        request: TrialRequest::for_nonce(n(0)),
    };
    let bytes = encode(&body).unwrap();
    assert!(bytes.starts_with(b"{\"job\":{"));
    assert!(bytes.ends_with(format!(",\"request\":{REQUEST_JSON}}}").as_bytes()));
    assert_eq!(decode::<ExecBody>(&bytes).unwrap(), body);
}

#[test]
fn swapped_approval_keys_refuse() {
    let rk = TestSigner::rk().pinned(Role::Rk);
    let bk = TestSigner::bk().pinned(Role::Bk);
    let swapped = Pair {
        receiver: Sig::sign(Tag::Trial3Receiver, trial(), &TestSigner::bk()).unwrap(),
        api: Sig::sign(Tag::Trial3Api, trial(), &TestSigner::rk()).unwrap(),
    };
    assert_eq!(swapped.verify(&rk, &bk), Err(SigError::KeyMismatch));
    let as_roles_swapped = Pair {
        receiver: ra(),
        api: ba(),
    };
    assert_eq!(
        as_roles_swapped.verify(&bk, &rk),
        Err(SigError::RoleNotPermitted)
    );
}

#[test]
fn status_vectors_signature_and_archive_commitment() {
    let b = status(1);
    assert_eq!(b.sig.to_text(), STATUS_B_SIG);
    assert_eq!(h(&b).unwrap().as_str(), STATUS_B_HASH);
    assert_eq!(h(&status(2)).unwrap().as_str(), STATUS_R_HASH);
    assert_eq!(TrialResult::success(n(0)).outcome().as_str(), OUTCOME);
    assert_eq!(HexDigest::of(OUTCOME_PREIMAGE.as_bytes()).as_str(), OUTCOME);
    let ak = TestSigner::ak().pinned(Role::Ak);
    let body = b.verify(Tag::Trial3Status, &ak).unwrap();
    body.check(&trial(), &issued_body(), &TrialResult::success(n(0)))
        .unwrap();
    assert_eq!(
        Bytes::from_array(TestSigner::ak().public_key()).to_text(),
        AK_PUBLIC
    );
    let _ = (RK_PUBLIC, BK_PUBLIC);
    assert_ne!(h(&status(1)).unwrap(), h(&status(2)).unwrap());
    assert_eq!(trial().hash().unwrap().as_str(), TRIAL_HASH);
}

#[test]
fn status_for_another_outcome_or_binding_does_not_check() {
    let t = trial();
    let b = status(1);
    let other_result = TrialResult::success(n(1));
    assert!(b.body.check(&t, &issued_body(), &other_result).is_err());
    let mut other_issued = issued_body();
    other_issued.grant_hash = dg('9');
    assert!(b
        .body
        .check(&t, &other_issued, &TrialResult::success(n(0)))
        .is_err());
}

#[test]
fn exec_ok_binds_the_trial_and_the_actual_result() {
    let t = trial();
    let ok = ExecOk {
        trial: t.hash().unwrap(),
        run: t.run.clone(),
        grant_id: t.grant_id.clone(),
        delegation_intent: t.delegation_intent.clone(),
        request_hash: t.command_hash.clone(),
        result: TrialResult::success(n(0)),
    };
    ok.check(&t).unwrap();
    let bytes = encode(&ok).unwrap();
    assert_eq!(decode::<ExecOk>(&bytes).unwrap(), ok);
    let mut wrong = ok.clone();
    wrong.result = TrialResult::success(n(7));
    assert!(wrong.check(&t).is_err());
}

#[test]
fn timeout_rule_vectors() {
    assert_eq!(
        trial_timeout_ms(2_000_000_000, 60, 1_999_999_998_000),
        Ok(1000)
    );
    assert_eq!(
        trial_timeout_ms(2_000_000_000, 60, 1_999_999_998_001),
        Err(TimeoutRefused)
    );
}
