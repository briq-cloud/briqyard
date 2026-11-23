//! Regression tests for the exact-head review of 4fb97cb: each fails on that head.

use super::super::*;
use super::fixtures::*;
use super::flow::{daemon_at_guard, exit_original, guard_proc, retired_daemon, start_guard};
use briqyard_api::execution::sealed::transition::Cut;
use briqyard_api::execution::sealed::{
    canonical::h,
    custody::Resource,
    owner::UnitState,
    transition::{LKind, Launch, ReceiptBody},
};
use std::sync::atomic::Ordering;

fn refusal<T: std::fmt::Debug>(result: Result<T, OwnerError>, text: &str) {
    refused(result, text);
}

#[test]
fn a_daemon_exit_needs_the_retained_identity_and_an_unknown_one_is_refused() {
    let (world, ..) = super::flow::handed_off();
    exit_original(&world, Resource::Daemon);
    let before = world.attempt();
    world.retained[DAEMON].unknown.store(true, Ordering::SeqCst);
    refusal(
        world
            .owner
            .record_exit(Resource::Daemon, &world.retained[DAEMON]),
        "identity",
    );
    assert_eq!(world.attempt(), before, "nothing was recorded");
    world.retained[DAEMON]
        .unknown
        .store(false, Ordering::SeqCst);
    world
        .owner
        .record_exit(Resource::Daemon, &world.retained[DAEMON])
        .unwrap();
}

#[test]
fn a_descriptor_holding_another_process_does_not_witness_this_exit() {
    let (world, ..) = super::flow::handed_off();
    exit_original(&world, Resource::Daemon);
    let other = Retained {
        proc: measured(&proc(77, 0x33)),
        exit: world.retained[DAEMON].exit.clone(),
        unknown: world.retained[DAEMON].unknown.clone(),
    };
    refusal(
        world.owner.record_exit(Resource::Daemon, &other),
        "does not report this exit",
    );
}

#[test]
fn a_daemon_retirement_needs_the_custodians_final_io_not_a_typed_launch_and_death() {
    let (world, launch, _) = daemon_at_guard();
    world
        .owner
        .consume(Resource::Daemon, &measured(&guard_proc()))
        .unwrap();
    let (retired, death, profile) = retired_daemon(&world, &launch);
    let before = world.attempt();
    refusal(
        world.owner.record_retirement(&retired, &death, &profile),
        "fixture has no final I/O",
    );
    assert_eq!(world.attempt(), before);
    assert!(world.attempt().daemon.retirement.is_none());
    assert!(!world.attempt().daemon.final_io);
    world.host.0.lock().unwrap().final_io[0] = true;
    world
        .owner
        .record_retirement(&retired, &death, &profile)
        .unwrap();
    assert!(world.attempt().daemon.final_io);
}

/// The authority's launch gate: the daemon retired and sealed, the authority's original
/// exited with its final I/O recorded. Returns the launch_a grant and turn.
pub(super) fn authority_ready() -> (
    World,
    briqyard_api::execution::sealed::transition::LGrant,
    Turn,
) {
    let (world, launch, _) = daemon_at_guard();
    world
        .owner
        .consume(Resource::Daemon, &measured(&guard_proc()))
        .unwrap();
    let (retired, death, profile) = retired_daemon(&world, &launch);
    world.host.0.lock().unwrap().final_io[0] = true;
    world
        .owner
        .record_retirement(&retired, &death, &profile)
        .unwrap();
    let seal_grant = world.grant(&retired, LKind::Seal, death.next.clone(), &Key::bk());
    let mut seal_body = world.turn_body(&seal_grant, &launch, &world.capture(&launch, &Key::rk()));
    seal_body.captured_launch = None;
    seal_body.capture = None;
    let seal_turn = world.turn(seal_body, &Key::bk());
    world.owner.accept_seal(&seal_grant, &seal_turn).unwrap();
    let cut = Cut {
        x: x(),
        plan: launch.plan.clone(),
        old: world.plan.pre.clone(),
        old_set: world.plan.old.set().unwrap(),
        new_instance: id("new-instance"),
        old_proc: death.old.clone(),
        new_proc: death.next.clone(),
        custody: h(&death).unwrap(),
        profile,
        retired_epoch: world.plan.pre.epoch.clone(),
        prior_host_water: world.plan.pre.generation,
    };
    let receipt = briqyard_api::execution::sealed::sig::Sig::sign(
        briqyard_api::execution::sealed::sig::Tag::Retired,
        ReceiptBody::new(cut),
        &Key::hk(),
    )
    .unwrap();
    world.owner.bind_seal_receipt(&receipt).unwrap();
    let (authority_launch, authority_capture): (Launch, _) =
        world.stage_capture(Resource::Authority);
    exit_original(&world, Resource::Authority);
    world.host.0.lock().unwrap().units[1].state = UnitState::Inactive;
    world
        .owner
        .record_exit(Resource::Authority, &world.retained[AUTHORITY])
        .unwrap();
    world.host.0.lock().unwrap().final_io[1] = true;
    world.owner.record_final_io(Resource::Authority).unwrap();
    let grant = world.grant(
        &authority_launch,
        LKind::LaunchA,
        authority_launch.old.clone(),
        &Key::bk(),
    );
    let turn = world.turn(
        world.turn_body(&grant, &authority_launch, &authority_capture),
        &Key::bk(),
    );
    (world, grant, turn)
}

#[test]
fn the_authority_exit_and_handoff_need_the_enrolled_originals_retained_identity() {
    let (world, grant, turn) = authority_ready();
    let before = world.attempt();
    world.retained[AUTHORITY]
        .unknown
        .store(true, Ordering::SeqCst);
    refusal(
        world
            .owner
            .accept_handoff(&grant, &turn, &world.retained[AUTHORITY]),
        "retained",
    );
    world.retained[AUTHORITY]
        .unknown
        .store(false, Ordering::SeqCst);
    let other = Retained {
        proc: measured(&proc(78, 0x34)),
        exit: world.retained[AUTHORITY].exit.clone(),
        unknown: world.retained[AUTHORITY].unknown.clone(),
    };
    refusal(
        world.owner.accept_handoff(&grant, &turn, &other),
        "retained",
    );
    assert_eq!(world.attempt(), before, "no handoff was recorded");
    world
        .owner
        .accept_handoff(&grant, &turn, &world.retained[AUTHORITY])
        .unwrap();
    let _ = (start_guard, Launch::hash);
}

#[test]
#[ignore = "explicit root environment fixture: BRIQYARD_CUSTODY_TEST_REAL_UID=1"]
fn a_reaped_original_keeps_its_stored_identity_on_its_own_retained_pidfd() {
    use crate::execution_custody::tests::ChildGuard;
    use crate::execution_custody::CustodianProcess;

    assert_eq!(
        std::env::var("BRIQYARD_CUSTODY_TEST_REAL_UID").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let child = ChildGuard::sleep();
    let retained = CustodianProcess::open_live(child.pid()).unwrap();
    let stored = MeasuredProc::try_from(retained.process()).unwrap();
    assert_eq!(retained.identity().unwrap(), stored);
    assert!(!retained.has_exited().unwrap());

    child.kill();
    assert!(retained.has_exited().unwrap(), "the pidfd reports the exit");
    assert!(
        retained.verify_unchanged().is_err(),
        "a reread of the reaped process cannot succeed, which is why identity must not use it"
    );
    assert_eq!(
        retained.identity().unwrap(),
        stored,
        "a reaped original answers with the snapshot pinned to its own descriptor"
    );
}
