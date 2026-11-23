use super::super::verify::verify_pair;
use super::*;
use briqyard_api::execution::sealed::plan_pin::Pin;

struct Case {
    world: World,
    trust: EnrolledTrust,
    local: LocalPlan,
    request: Read,
}

fn case() -> Case {
    let world = World::new();
    let trust = world.trust();
    let local = world.local();
    let request = world.request(Resource::Daemon, ReadPoint::Launch, 5);
    Case {
        world,
        trust,
        local,
        request,
    }
}

impl Case {
    fn verify(&self, reply: &[u8]) -> Result<Pin, PlanReadError> {
        verify_pair(reply, &self.request, &self.local, &self.trust)
    }

    fn honest(&self) -> Vec<u8> {
        honest_pair(&self.request, &self.local)
    }

    /// Both observers, with their real enrolled keys and tags, sign this same altered body.
    fn both_sign(&self, alter: impl FnOnce(&mut ReadBody)) -> Vec<u8> {
        let mut body = body_for(&self.request, &self.local);
        alter(&mut body);
        sign_pair(
            (Tag::PlanReadReceiver, &FixtureSigner::rk(), body.clone()),
            (Tag::PlanReadApi, &FixtureSigner::bk(), body),
        )
    }

    fn body(&self) -> ReadBody {
        body_for(&self.request, &self.local)
    }
}

fn proof_refused(result: Result<Pin, PlanReadError>, text: &str) {
    let error = refused(result);
    assert!(matches!(error, PlanReadError::Proof(_)), "{error}");
    says(&error, text);
}

#[test]
fn the_exact_pair_verifies_to_this_plans_pin() {
    let case = case();
    let pin = case.verify(&case.honest()).unwrap();
    assert_eq!(pin, case.local.pin());
    assert_eq!(pin.plan, HexDigest::of(&case.world.plan_bytes));
}

#[test]
fn a_correct_pair_for_another_request_is_not_this_requests_pin() {
    let case = case();
    let stale = honest_pair(
        &case.world.request(Resource::Daemon, ReadPoint::Launch, 4),
        &case.local,
    );
    proof_refused(case.verify(&stale), "echo");
    for (resource, point) in [
        (Resource::Authority, ReadPoint::Launch),
        (Resource::Daemon, ReadPoint::Prearm),
        (Resource::Daemon, ReadPoint::Seal),
    ] {
        let other = honest_pair(&case.world.request(resource, point, 5), &case.local);
        proof_refused(case.verify(&other), "echo");
    }
}

#[test]
fn a_body_that_differs_from_the_plan_in_any_scope_field_is_refused() {
    let case = case();
    let mut other_host = case.local.plan().x.clone();
    other_host.host = id("intrinsic.other");
    let mut other_op = case.local.plan().x.clone();
    other_op.op = digest(0x42);
    let mut other_serial = case.local.plan().x.clone();
    other_serial.serial = PosInt::new(2).unwrap();
    for x in [other_host, other_op, other_serial] {
        let both_scope = case.both_sign(|body| {
            body.read.x = x.clone();
            body.pin.x = x.clone();
        });
        proof_refused(case.verify(&both_scope), "echo");
        let pin_scope = case.both_sign(|body| body.pin.x = x.clone());
        proof_refused(case.verify(&pin_scope), "pin scope");
    }
    let alias_both = case.both_sign(|body| {
        body.read.registered = id("alias.test");
        body.pin.registered = id("alias.test");
    });
    proof_refused(case.verify(&alias_both), "echo");
    let alias_pin = case.both_sign(|body| body.pin.registered = id("alias.test"));
    proof_refused(case.verify(&alias_pin), "pin scope");
    let digest_only = case.both_sign(|body| body.pin.plan = digest(0x77));
    proof_refused(case.verify(&digest_only), "this operation's Plan");
}

#[test]
fn independent_pins_that_disagree_are_refused_even_with_the_same_eligibility_digest() {
    let case = case();
    let mut other = case.world.plan.clone();
    other.new = members(9);
    assert_eq!(other.inputs, case.world.plan.inputs);
    assert_eq!(other.exception, case.world.plan.exception);
    let other_pin = LocalPlan::decode(&encode(&other).unwrap()).unwrap().pin();
    assert_ne!(other_pin.plan, case.local.digest().clone());

    let (mut receiver, mut api) = (case.body(), case.body());
    api.pin = other_pin.clone();
    let receiver_pins_ours = sign_pair(
        (
            Tag::PlanReadReceiver,
            &FixtureSigner::rk(),
            receiver.clone(),
        ),
        (Tag::PlanReadApi, &FixtureSigner::bk(), api.clone()),
    );
    proof_refused(case.verify(&receiver_pins_ours), "different bodies");
    receiver.pin = other_pin;
    api.pin = case.local.pin();
    let api_pins_ours = sign_pair(
        (
            Tag::PlanReadReceiver,
            &FixtureSigner::rk(),
            receiver.clone(),
        ),
        (Tag::PlanReadApi, &FixtureSigner::bk(), api),
    );
    proof_refused(case.verify(&api_pins_ours), "different bodies");
    let both_substituted = case.both_sign(|body| body.pin = receiver.pin.clone());
    proof_refused(case.verify(&both_substituted), "this operation's Plan");
}

#[test]
fn keys_that_are_not_the_enrolled_ones_are_refused() {
    let case = case();
    let body = case.body();
    let attacker = (FixtureSigner::attacker(9), FixtureSigner::attacker(10));
    let all_wrong = sign_pair(
        (Tag::PlanReadReceiver, &attacker.0, body.clone()),
        (Tag::PlanReadApi, &attacker.1, body.clone()),
    );
    proof_refused(case.verify(&all_wrong), "receiver proof");
    let wrong_receiver = sign_pair(
        (Tag::PlanReadReceiver, &attacker.0, body.clone()),
        (Tag::PlanReadApi, &FixtureSigner::bk(), body.clone()),
    );
    proof_refused(case.verify(&wrong_receiver), "receiver proof");
    let wrong_api = sign_pair(
        (Tag::PlanReadReceiver, &FixtureSigner::rk(), body.clone()),
        (Tag::PlanReadApi, &attacker.1, body),
    );
    proof_refused(case.verify(&wrong_api), "api proof");
}

#[test]
fn a_substituted_plan_under_fresh_attacker_keys_is_refused() {
    let case = case();
    let (rk, bk) = (FixtureSigner::attacker(9), FixtureSigner::attacker(10));
    let forged = plan_with(
        case.world.plan.x.clone(),
        "registered.test",
        rk.key(),
        bk.key(),
        0xd,
    );
    let forged_local = LocalPlan::decode(&encode(&forged).unwrap()).unwrap();
    let body = body_for(&case.request, &forged_local);
    let reply = sign_pair(
        (Tag::PlanReadReceiver, &rk, body.clone()),
        (Tag::PlanReadApi, &bk, body),
    );
    proof_refused(case.verify(&reply), "receiver proof");

    let forged_trust = World::with_plan(forged.clone());
    let attacker_trust = forged_trust.trust();
    let against_real_plan = verify_pair(&reply, &case.request, &case.local, &attacker_trust);
    proof_refused(against_real_plan, "local Plan keys differ");
    assert!(verify_pair(&reply, &case.request, &forged_local, &attacker_trust).is_ok());
}

#[test]
fn the_local_plans_keys_must_equal_the_enrolled_keys() {
    let case = case();
    for (rk, bk) in [
        (FixtureSigner::attacker(9).key(), FixtureSigner::bk().key()),
        (FixtureSigner::rk().key(), FixtureSigner::attacker(10).key()),
    ] {
        let other = LocalPlan::decode(
            &encode(&plan_with(
                case.world.plan.x.clone(),
                "registered.test",
                rk,
                bk,
                0xd,
            ))
            .unwrap(),
        )
        .unwrap();
        let reply = honest_pair(&case.request, &other);
        proof_refused(
            verify_pair(&reply, &case.request, &other, &case.trust),
            "local Plan keys differ",
        );
    }
}

#[test]
fn wrong_tags_and_wrong_roles_are_refused() {
    let case = case();
    let body = case.body();
    let (rk, bk) = (FixtureSigner::rk(), FixtureSigner::bk());
    let cases = [
        (
            "tags swapped",
            sign_pair(
                (Tag::PlanReadApi, &rk, body.clone()),
                (Tag::PlanReadReceiver, &bk, body.clone()),
            ),
        ),
        (
            "receiver under the api tag",
            sign_pair(
                (Tag::PlanReadApi, &rk, body.clone()),
                (Tag::PlanReadApi, &bk, body.clone()),
            ),
        ),
        (
            "api under the receiver tag",
            sign_pair(
                (Tag::PlanReadReceiver, &rk, body.clone()),
                (Tag::PlanReadReceiver, &bk, body.clone()),
            ),
        ),
        (
            "proofs in each other's slots",
            sign_pair(
                (Tag::PlanReadApi, &bk, body.clone()),
                (Tag::PlanReadReceiver, &rk, body.clone()),
            ),
        ),
        (
            "an effect tag",
            sign_pair(
                (Tag::Receiver, &rk, body.clone()),
                (Tag::Decision, &bk, body.clone()),
            ),
        ),
        (
            "an observation tag of another family",
            sign_pair(
                (Tag::QueryObserve, &rk, body.clone()),
                (Tag::QueryObserve, &bk, body.clone()),
            ),
        ),
        (
            "one signer for both",
            sign_pair(
                (Tag::PlanReadReceiver, &rk, body.clone()),
                (Tag::PlanReadApi, &rk, body),
            ),
        ),
    ];
    for (name, reply) in cases {
        let error = refused(case.verify(&reply));
        assert!(matches!(error, PlanReadError::Proof(_)), "{name}: {error}");
    }
}

#[test]
fn a_partial_duplicate_or_malformed_pair_is_refused() {
    let case = case();
    let pair: ReadPair = decode(&case.honest()).unwrap();
    let receiver_only = serde_json::json!({"receiver": pair.receiver}).to_string();
    let api_only = serde_json::json!({"api": pair.api}).to_string();
    for partial in [receiver_only, api_only, "{}".to_string()] {
        proof_refused(case.verify(partial.as_bytes()), "not canonical");
    }
    let doubled = encode(&ReadPair {
        receiver: pair.receiver.clone(),
        api: pair.receiver.clone(),
    })
    .unwrap();
    proof_refused(case.verify(&doubled), "observers share a key");
    let honest = case.honest();
    for bad in [
        [honest.clone(), b"\n".to_vec()].concat(),
        [b" ".to_vec(), honest.clone()].concat(),
        [honest.clone(), honest.clone()].concat(),
        Vec::new(),
    ] {
        proof_refused(case.verify(&bad), "not canonical");
    }
}

#[test]
fn a_request_for_another_operation_or_alias_is_refused() {
    let case = case();
    let mut request = case.request.clone();
    request.registered = id("alias.test");
    let reply = honest_pair(&request, &case.local);
    proof_refused(
        verify_pair(&reply, &request, &case.local, &case.trust),
        "request is not this operation's",
    );
    let mut request = case.request.clone();
    request.x.op = digest(0x42);
    let reply = honest_pair(&request, &case.local);
    proof_refused(
        verify_pair(&reply, &request, &case.local, &case.trust),
        "request is not this operation's",
    );
}

#[test]
fn no_single_byte_change_to_a_valid_pair_verifies() {
    let case = case();
    let honest = case.honest();
    assert!(case.verify(&honest).is_ok());
    for at in 0..honest.len() {
        let mut changed = honest.clone();
        changed[at] ^= 1;
        assert!(case.verify(&changed).is_err(), "byte {at}");
        changed.truncate(at);
        assert!(case.verify(&changed).is_err(), "truncated at {at}");
    }
}
