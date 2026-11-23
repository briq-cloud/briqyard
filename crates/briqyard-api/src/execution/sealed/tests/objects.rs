//! Plan, Members, Ctx, capacity and query objects.

use super::*;
use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::objects::{
    Bind, Cap, Dims, HostClockBody, Members, Plan, Projection, ProjectionAction, ProofQuery, Reg,
    PROJECTION_ORDER, Q,
};
use crate::execution::sealed::sig::{Role, Sig, SigError, Tag};

fn reg() -> Reg {
    Reg {
        authority: id("auth"),
        epoch: id("ep"),
        key_id: id("k"),
        public_key: TestSigner::rk().public_key(),
        host_instance: id("hi"),
        generation: pos(2),
    }
}

fn members(tr: Option<HexDigest>) -> Members {
    Members {
        hi: dg('a'),
        he: dg('b'),
        ni: dg('c'),
        ng: dg('d'),
        tr,
    }
}

fn plan() -> Plan {
    let reg = reg();
    Plan {
        x: x(),
        registered: id("registered.test"),
        pre: reg.ctx(&id("host.test")),
        pre_record: reg,
        pre_intent: id("intent.test"),
        pre_d: proc(10),
        pre_a: proc(12),
        next_d: dg('4'),
        next_a: dg('5'),
        dbuild: Build::new("d+build").unwrap(),
        abuild: Build::new("a+build").unwrap(),
        old: Members {
            hi: dg('0'),
            he: dg('1'),
            ni: dg('2'),
            ng: dg('3'),
            tr: None,
        },
        new: members(Some(dg('e'))),
        hk: key(1),
        ak: key(2),
        bk: key(3),
        rk: key(4),
        ordinary_key: key(5),
        exception: dg('6'),
        inputs: dg('7'),
    }
}

fn bind() -> Bind {
    let reg = reg();
    Bind {
        x: x(),
        plan: dg('1'),
        registered: id("registered.test"),
        prior: pos(1),
        intent: id("register:sealed:op"),
        ctx: reg.ctx(&id("host.test")),
        record: reg,
        set: members(Some(dg('e'))).set().unwrap(),
    }
}

#[test]
fn plan_round_trips_and_nullable_tr_is_explicit() {
    let bytes = encode(&plan()).unwrap();
    assert_eq!(decode::<Plan>(&bytes).unwrap(), plan());
    assert!(String::from_utf8(bytes)
        .unwrap()
        .contains(r#""old":{"he":"#));
    let with_null = encode(&members(None)).unwrap();
    assert!(String::from_utf8(with_null.clone())
        .unwrap()
        .ends_with(r#""tr":null}"#));
    assert_eq!(decode::<Members>(&with_null).unwrap(), members(None));
    let omitted = String::from_utf8(with_null)
        .unwrap()
        .replace(r#","tr":null"#, "");
    assert!(decode::<Members>(omitted.as_bytes()).is_err());
}

#[test]
fn members_set_is_the_hash_of_the_canonical_members() {
    let m = members(Some(dg('e')));
    assert_eq!(m.set().unwrap(), HexDigest::of(&encode(&m).unwrap()));
    assert_ne!(m.set().unwrap(), members(None).set().unwrap());
}

#[test]
fn plan_refuses_an_inconsistent_context_and_shared_keys() {
    let mut wrong_ctx = plan();
    wrong_ctx.pre.generation = pos(3);
    assert!(decode::<Plan>(&encode(&wrong_ctx).unwrap()).is_err());
    let mut other_host = plan();
    other_host.pre.host = id("other.host");
    assert!(decode::<Plan>(&encode(&other_host).unwrap()).is_err());
    for (a, b) in [(1, 2), (2, 3), (3, 4), (1, 5), (4, 5)] {
        let mut shared = plan();
        let keys = [
            &mut shared.hk,
            &mut shared.ak,
            &mut shared.bk,
            &mut shared.rk,
            &mut shared.ordinary_key,
        ];
        let copy = *keys[a - 1];
        *keys[b - 1] = copy;
        assert!(
            decode::<Plan>(&encode(&shared).unwrap()).is_err(),
            "{a} {b}"
        );
    }
}

fn member_slots(plan: &mut Plan) -> Vec<&mut HexDigest> {
    let (old, new) = (&mut plan.old, &mut plan.new);
    vec![
        &mut old.hi,
        &mut old.he,
        &mut old.ni,
        &mut old.ng,
        old.tr.as_mut().unwrap(),
        &mut new.hi,
        &mut new.he,
        &mut new.ni,
        &mut new.ng,
        new.tr.as_mut().unwrap(),
    ]
}

#[test]
fn plan_member_digests_are_unique_across_every_role_and_both_generations() {
    let mut full = plan();
    full.old.tr = Some(dg('4'));
    assert!(decode::<Plan>(&encode(&full).unwrap()).is_ok());
    for a in 0..10 {
        for b in a + 1..10 {
            let mut shared = full.clone();
            let copy = member_slots(&mut shared)[a].clone();
            *member_slots(&mut shared)[b] = copy;
            assert!(
                decode::<Plan>(&encode(&shared).unwrap()).is_err(),
                "slots {a} and {b} share a digest"
            );
        }
    }
}

#[test]
fn a_legacy_predecessor_without_a_transition_member_stays_valid() {
    let legacy = plan();
    assert!(legacy.old.tr.is_none());
    assert!(decode::<Plan>(&encode(&legacy).unwrap()).is_ok());
    let mut both_absent = plan();
    both_absent.new.tr = None;
    assert!(decode::<Plan>(&encode(&both_absent).unwrap()).is_ok());
}

fn dims(fits: bool) -> Dims {
    Dims {
        bytes: Uint::new(10).unwrap(),
        counts: [Uint::new(0).unwrap(); 21],
        fits,
    }
}

use super::super::prim::Uint;

fn row(action: ProjectionAction, target: Option<HexDigest>) -> Projection {
    let known = target.is_some();
    Projection {
        action,
        basis: dg('8'),
        target,
        next: known.then(|| dims(true)),
        reserve: known.then(|| dims(true)),
        expected_ack: None,
    }
}

#[test]
fn capacity_has_six_ordered_rows_and_unknown_means_all_null() {
    let rows = |t: Option<HexDigest>| {
        PROJECTION_ORDER
            .iter()
            .map(|a| row(*a, t.clone()))
            .collect()
    };
    let cap = Cap {
        actual: dims(true),
        projections: rows(Some(dg('9'))),
    };
    assert_eq!(decode::<Cap>(&encode(&cap).unwrap()).unwrap(), cap);
    let unknown = Cap {
        actual: dims(true),
        projections: rows(None),
    };
    assert_eq!(decode::<Cap>(&encode(&unknown).unwrap()).unwrap(), unknown);

    let mut reordered = cap.clone();
    reordered.projections.swap(0, 1);
    assert!(decode::<Cap>(&encode(&reordered).unwrap()).is_err());
    let mut short = cap.clone();
    short.projections.pop();
    assert!(decode::<Cap>(&encode(&short).unwrap()).is_err());
    let mut assumed = unknown.clone();
    assumed.projections[0].next = Some(dims(true));
    assert!(decode::<Cap>(&encode(&assumed).unwrap()).is_err());
}

#[test]
fn proof_queries_follow_their_target_signer_sets_and_api_has_no_preview() {
    let query = |preview| ProofQuery {
        q: Q {
            x: x(),
            nonce: n(1),
        },
        plan: dg('1'),
        preview,
    };
    for (tag, role) in [
        (Tag::QueryHost, Role::Ak),
        (Tag::QueryHost, Role::Bk),
        (Tag::QueryAuthority, Role::Hk),
        (Tag::QueryApi, Role::Hk),
        (Tag::QueryApi, Role::Ak),
    ] {
        let signer = TestSigner::ak();
        let signed = Sig::sign(tag, query(None), &signer).unwrap();
        signed.verify(tag, &signer.pinned(role)).unwrap();
    }
    for (tag, role) in [
        (Tag::QueryHost, Role::Hk),
        (Tag::QueryAuthority, Role::Ak),
        (Tag::QueryApi, Role::Bk),
    ] {
        let signer = TestSigner::ak();
        let signed = Sig::sign(tag, query(None), &signer).unwrap();
        assert_eq!(
            signed.verify(tag, &signer.pinned(role)),
            Err(SigError::RoleNotPermitted)
        );
    }
    let with_preview = Sig::sign(Tag::QueryApi, query(Some(bind())), &TestSigner::rk()).unwrap();
    let bytes = encode(&with_preview).unwrap();
    assert!(ProofQuery::decode_signed(&bytes, Tag::QueryApi).is_err());
    let host = Sig::sign(Tag::QueryHost, query(Some(bind())), &TestSigner::rk()).unwrap();
    assert!(ProofQuery::decode_signed(&encode(&host).unwrap(), Tag::QueryHost).is_ok());
    assert!(ProofQuery::decode_signed(&encode(&host).unwrap(), Tag::Trial3Api).is_err());
}

#[test]
fn host_clock_is_hk_only_and_integers_stay_safe() {
    let body = HostClockBody {
        q: Q {
            x: x(),
            nonce: n(1),
        },
        plan: dg('1'),
        proc: proc(18),
        instance: id("hi"),
        now: Uint::new(1_900_000_000).unwrap(),
        uncertainty: Uint::new(1).unwrap(),
    };
    let hk = TestSigner::ak();
    let signed = Sig::sign(Tag::HostClock, body.clone(), &hk).unwrap();
    assert_eq!(
        signed.verify(Tag::HostClock, &hk.pinned(Role::Ak)),
        Err(SigError::RoleNotPermitted)
    );
    signed.verify(Tag::HostClock, &hk.pinned(Role::Hk)).unwrap();
    assert!(Uint::new(9_007_199_254_740_991).is_ok());
    assert!(Uint::new(9_007_199_254_740_992).is_err());
    let mut excessive = serde_json::to_value(body).unwrap();
    excessive["uncertainty"] = serde_json::json!(6);
    let excessive = crate::execution::sealed::encode(&excessive).unwrap();
    assert!(crate::execution::sealed::decode::<HostClockBody>(&excessive).is_err());
    let _ = h(&signed);
}
