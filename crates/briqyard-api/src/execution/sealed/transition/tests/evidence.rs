//! Cut, Receipt, RegDone, Gate, Guard, Intent and Witness: valid objects round-trip through the
//! codec, and every phase predicate, null rule and hash link refuses its violation.

use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::custody::Resource;
use crate::execution::sealed::prim::{Bytes, HexDigest};
use crate::execution::sealed::sig::{Role, Sig, SigError, Tag};
use crate::execution::sealed::tests::{dg, fixture_nonce, id, key, pos, proc, x, TestSigner};
use crate::execution::sealed::transition::*;

#[test]
fn every_gate_phase_round_trips_with_exactly_its_fields() {
    for phase in [
        GatePhase::Closed,
        GatePhase::Sealed,
        GatePhase::Armed,
        GatePhase::Registered,
        GatePhase::Released,
    ] {
        round_trip(&gate(phase));
    }
}

#[test]
fn gate_fields_present_before_their_transition_are_refused() {
    let rank_fields = |g: &mut Gate, rank: usize| match rank {
        1 => g.receipt = Some(receipt()),
        2 => g.bind = Some(bind()),
        3 => g.arm = Some(dg('c')),
        4 => g.done = Some(reg_done()),
        _ => g.release = Some(dg('d')),
    };
    for (phase, early) in [
        (GatePhase::Closed, vec![1, 2, 3, 4, 5]),
        (GatePhase::Sealed, vec![2, 3, 4, 5]),
        (GatePhase::Armed, vec![4, 5]),
        (GatePhase::Registered, vec![5]),
    ] {
        for rank in early {
            let mut g = gate(phase);
            rank_fields(&mut g, rank);
            assert!(refused(&g), "{phase:?} accepted early field {rank}");
        }
    }
}

#[test]
fn gate_fields_missing_after_their_transition_are_refused() {
    let mut sealed = gate(GatePhase::Sealed);
    sealed.receipt = None;
    assert!(refused(&sealed));
    let mut armed = gate(GatePhase::Armed);
    armed.arm = None;
    assert!(refused(&armed));
    let mut armed = gate(GatePhase::Armed);
    armed.bind = None;
    assert!(refused(&armed));
    let mut registered = gate(GatePhase::Registered);
    registered.done = None;
    assert!(refused(&registered));
    let mut released = gate(GatePhase::Released);
    released.release = None;
    assert!(refused(&released));
}

#[test]
fn a_signed_gate_always_has_its_committed_cut_and_instance() {
    let mut no_cut = gate(GatePhase::Closed);
    no_cut.cut = None;
    assert!(refused(&no_cut));
    let mut wrong_instance = gate(GatePhase::Closed);
    wrong_instance.instance = id("hi");
    assert!(refused(&wrong_instance));
    let mut wrong_plan = gate(GatePhase::Closed);
    wrong_plan.plan = dg('2');
    assert!(refused(&wrong_plan));
}

#[test]
fn gate_levels_repeat_the_cut_and_the_bind_identically() {
    let mut g = gate(GatePhase::Sealed);
    let mut other = cut();
    other.profile = dg('9');
    other.custody = dg('9');
    g.receipt = Some(Sig::sign(Tag::Retired, ReceiptBody::new(other), &HkSigner::new()).unwrap());
    assert!(refused(&g), "receipt for another cut");

    let mut g = gate(GatePhase::Registered);
    let mut other = reg_done();
    other.bind.intent = id("register:sealed:other");
    g.done = Some(other);
    assert!(refused(&g), "done for another bind");

    let mut g = gate(GatePhase::Armed);
    g.bind.as_mut().unwrap().prior = pos(1);
    g.bind.as_mut().unwrap().record.generation = pos(2);
    g.bind.as_mut().unwrap().ctx = g.bind.as_ref().unwrap().record.ctx(&x().host);
    assert!(refused(&g), "bind not at the cut's prior water");

    let mut g = gate(GatePhase::Armed);
    g.bind.as_mut().unwrap().record.host_instance = id("hi");
    g.bind.as_mut().unwrap().ctx = g.bind.as_ref().unwrap().record.ctx(&x().host);
    assert!(refused(&g), "bind for another host instance");
}

#[test]
fn a_bind_is_internally_consistent() {
    let mut b = bind();
    b.ctx.reg_hash = dg('0');
    assert!(check_bind(&b).is_err());
    let mut b = bind();
    b.prior = pos(7);
    assert!(check_bind(&b).is_err());
    check_bind(&bind()).unwrap();
}

#[test]
fn bind_plan_pins_scope_prior_key_and_set() {
    let plan = plan();
    let hash = plan_hash();
    let b = bind();
    check_bind_plan(&b, &hash, &plan).unwrap();
    for mutate in [
        (|b: &mut crate::execution::sealed::objects::Bind| b.set = dg('0')) as fn(&mut _),
        |b| b.registered = id("other.test"),
        |b| b.plan = dg('2'),
        |b| b.record.key_id = id("other"),
        |b| b.record.public_key[0] ^= 1,
    ] {
        let mut changed = b.clone();
        mutate(&mut changed);
        changed.ctx = changed.record.ctx(&x().host);
        assert!(check_bind_plan(&changed, &hash, &plan).is_err());
    }
    let mut prior = b.clone();
    prior.prior = pos(1);
    prior.record.generation = pos(2);
    prior.ctx = prior.record.ctx(&x().host);
    assert!(check_bind_plan(&prior, &hash, &plan).is_err());
    cut().check_plan(&hash, &plan).unwrap();
}

#[test]
fn cut_invariants() {
    round_trip(&cut());
    let mut c = cut();
    c.new_instance = id("hi");
    assert!(refused(&c), "new instance must differ");
    let mut c = cut();
    c.retired_epoch = id("other");
    assert!(refused(&c), "retired epoch is the old epoch");
    let mut c = cut();
    c.prior_host_water = pos(3);
    assert!(refused(&c), "prior water is the old generation");
    let mut c = cut();
    c.old.host = id("other.test");
    assert!(refused(&c), "old context is the intrinsic host's");
}

#[test]
fn cut_commits_to_the_exact_daemon_death() {
    cut().check_death(&daemon_death()).unwrap();
    let mut wrong = daemon_death();
    wrong.profile = dg('0');
    assert!(cut().check_death(&wrong).is_err());
    let mut authority = daemon_death();
    authority.resource = Resource::Authority;
    assert!(cut().check_death(&authority).is_err());
    let mut other_proc = daemon_death();
    other_proc.next = proc(21);
    assert!(cut().check_death(&other_proc).is_err());
}

#[test]
fn cut_custody_is_the_death_hash_and_never_a_wrapper_around_it() {
    let death = daemon_death();
    assert_eq!(cut().custody, independent_death_hash(&death));
    let wrapped = wrapped_death_hash(&death);
    assert_ne!(wrapped, death.hash().unwrap());
    let mut wrapped_cut = cut();
    wrapped_cut.custody = wrapped;
    assert!(wrapped_cut.check_death(&death).is_err());
}

#[test]
fn receipt_is_signed_by_hk_only_and_closes_exactly_host_scoped_writes() {
    let r = receipt();
    verify_receipt(&r, &HkSigner::new().pinned()).unwrap();
    assert_eq!(
        verify_receipt(&r, &TestSigner::rk().pinned(Role::Rk)),
        Err(SigError::RoleNotPermitted)
    );
    let text = json(&r);
    assert!(text.contains(r#""closure":"host_scoped_writes""#));
    assert!(text.contains(r#""leases":0"#) && text.contains(r#""writers":0"#));
    round_trip(&r);
    for bad in [
        text.replace(r#""writers":0"#, r#""writers":1"#),
        text.replace(r#""leases":0"#, r#""leases":2"#),
        text.replace("host_scoped_writes", "northbound"),
    ] {
        assert!(decode::<Receipt>(bad.as_bytes()).is_err());
    }
}

#[test]
fn reg_done_stores_the_registrations_own_ack_and_high_water() {
    round_trip(&reg_done());
    let mut d = reg_done();
    d.ack.digest = Bytes::from_array([1; 32]);
    assert!(refused(&d));
    let mut d = reg_done();
    d.host_water = pos(4);
    assert!(refused(&d));
}

#[test]
fn guard_phase_fields_move_together() {
    round_trip(&guard(GuardPhase::Started));
    round_trip(&guard(GuardPhase::Adopted));
    for mutate in [
        (|g: &mut Guard| g.bind = Some(bind())) as fn(&mut Guard),
        |g| g.armed_gate = Some(dg('a')),
        |g| g.adoption = Some(dg('a')),
    ] {
        let mut g = guard(GuardPhase::Started);
        mutate(&mut g);
        assert!(refused(&g), "started with an adopted field");
    }
    for mutate in [
        (|g: &mut Guard| g.bind = None) as fn(&mut Guard),
        |g| g.armed_gate = None,
        |g| g.adoption = None,
    ] {
        let mut g = guard(GuardPhase::Adopted);
        mutate(&mut g);
        assert!(refused(&g), "adopted missing an adopted field");
    }
}

#[test]
fn an_adopted_guard_is_for_its_epoch_set_and_unchanged_key() {
    let mut g = guard(GuardPhase::Adopted);
    g.epoch = id("ep3");
    assert!(refused(&g));
    let mut g = guard(GuardPhase::Adopted);
    g.set = dg('6');
    assert!(refused(&g));
    let mut g = guard(GuardPhase::Adopted);
    g.ordinary_key = key(9);
    assert!(refused(&g));
    let mut g = guard(GuardPhase::Adopted);
    g.ordinary_kid = id("other");
    assert!(refused(&g));
}

#[test]
fn intent_pending_has_no_ack_and_ready_has_the_exact_one() {
    round_trip(&intent(IntentPhase::Pending));
    round_trip(&intent(IntentPhase::Ready));
    let mut p = intent(IntentPhase::Pending);
    p.ack = Some(new_record().ack());
    assert!(refused(&p));
    let mut r = intent(IntentPhase::Ready);
    r.ack = None;
    assert!(refused(&r));
    let mut r = intent(IntentPhase::Ready);
    r.ack.as_mut().unwrap().digest = fixture_nonce(1);
    assert!(refused(&r));
}

#[test]
fn witness_binds_the_original_intent_and_the_next_authority_water() {
    let w = Sig::sign(Tag::Intent, witness_body(), &TestSigner::ak()).unwrap();
    w.verify(Tag::Intent, &ak()).unwrap();
    assert_eq!(
        w.verify(Tag::Intent, &bk()),
        Err(SigError::RoleNotPermitted)
    );
    round_trip(&w);
    let mut b = witness_body();
    b.authority_water = pos(2);
    assert!(refused(&b));
    let mut b = witness_body();
    b.intent = id("register:sealed:other");
    assert!(refused(&b));
    let mut b = witness_body();
    b.plan = dg('2');
    assert!(refused(&b));
}

#[test]
fn hashes_are_over_the_complete_canonical_object() {
    let g = gate(GatePhase::Sealed);
    assert_eq!(g.hash().unwrap(), h(&g).unwrap());
    let bytes = encode(&g).unwrap();
    assert_eq!(HexDigest::of(&bytes), g.hash().unwrap());
}
