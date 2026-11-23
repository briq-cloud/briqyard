//! The review of 24fa812: boundaries that a self-consistent but wrong input, or an unchanged
//! stored Attempt over a changed target, used to cross. Each case changes one thing and checks
//! that nothing was recorded.

use super::super::*;
use super::fixtures::*;
use super::flow::{
    daemon_at_guard, exit_original, guard_proc, handed_off, retired_daemon, start_guard,
};
use super::review::authority_ready;
use crate::execution_custody::plan_reader::PlanReadOwner;
use briqyard_api::execution::sealed::{
    canonical::h,
    custody::Resource,
    owner::{FragmentState, UnitState},
    plan_pin::ReadPoint,
    prim::BootId,
    sig::{Sig, Tag},
    transition::{Cut, LKind, ReceiptBody},
};

fn scope(world: &World, resource: Resource) -> ReadScope {
    ReadScope::new(
        x(),
        world.plan.registered.clone(),
        resource,
        ReadPoint::Prearm,
    )
    .unwrap()
}

fn refuses_capture(world: &World, what: &str) {
    for resource in [Resource::Daemon, Resource::Authority] {
        assert!(
            world.owner.capture(&scope(world, resource)).is_err(),
            "{what}: capture"
        );
        assert!(
            world
                .owner
                .lock_and_capture(&scope(world, resource))
                .is_err(),
            "{what}: lock_and_capture"
        );
    }
}

#[test]
fn a_capture_refuses_a_changed_target_over_an_unchanged_attempt_and_changes_nothing() {
    // pids: originals 10 and 12, custodians 20 and 22 (the fixture's own)
    let world = World::new();
    world.install().unwrap();
    let stored = std::fs::read(world.path().join("active.json")).unwrap();
    let control = || {
        world
            .owner
            .capture(&scope(&world, Resource::Daemon))
            .unwrap();
        world
            .owner
            .capture(&scope(&world, Resource::Authority))
            .unwrap();
    };
    control();
    type Change = Box<dyn Fn(&mut HostState)>;
    let mut changes: Vec<(String, Change)> = Vec::new();
    for pid in [10u64, 12, 20, 22] {
        changes.push((
            format!("pid {pid} vanished"),
            Box::new(move |s| {
                s.procs.remove(&pid);
            }),
        ));
        changes.push((
            format!("pid {pid} replaced: other start"),
            Box::new(move |s| s.procs.get_mut(&pid).unwrap().start += 1),
        ));
        changes.push((
            format!("pid {pid} replaced: other image"),
            Box::new(move |s| s.procs.get_mut(&pid).unwrap().exe = digest(0xfd)),
        ));
    }
    changes.push((
        "the target rebooted".into(),
        Box::new(|s| s.boot = BootId::new("00000000-0000-4000-8000-0000000000ff").unwrap()),
    ));
    changes.push((
        "the measurement fails".into(),
        Box::new(|s| s.unreadable = true),
    ));
    for (what, change) in changes {
        let saved = {
            let state = world.host.0.lock().unwrap();
            (state.procs.clone(), state.boot.clone())
        };
        change(&mut world.host.0.lock().unwrap());
        refuses_capture(&world, &what);
        assert_eq!(
            std::fs::read(world.path().join("active.json")).unwrap(),
            stored,
            "{what}: nothing was written"
        );
        {
            let mut state = world.host.0.lock().unwrap();
            state.procs = saved.0;
            state.boot = saved.1;
            state.unreadable = false;
        }
        control();
    }
}

fn unit_field(world: &World, role: usize, field: usize) {
    let mut state = world.host.0.lock().unwrap();
    let unit = &mut state.units[role];
    let other = digest(0xee);
    match field {
        0 => unit.fragment = other,
        1 => unit.argv = other,
        2 => unit.sandbox = other,
        _ => unit.fdstore = other,
    }
}

#[test]
fn the_daemon_handoff_refuses_a_changed_authority_unit_commitment() {
    for field in 0..4 {
        let world = World::new();
        let (launch, capture) = world.enroll();
        let grant = world.grant(&launch, LKind::LaunchD, launch.old.clone(), &Key::bk());
        let turn = world.turn(world.turn_body(&grant, &launch, &capture), &Key::bk());
        let before = world.attempt();
        unit_field(&world, 1, field);
        refused(
            world
                .owner
                .accept_handoff(&grant, &turn, &world.retained[DAEMON]),
            "effective unit differs",
        );
        assert_eq!(world.attempt(), before, "field {field}: nothing recorded");
    }
}

#[test]
fn the_authority_handoff_refuses_a_changed_daemon_unit_commitment() {
    for field in 0..4 {
        let (world, grant, turn) = authority_ready();
        let before = world.attempt();
        unit_field(&world, 0, field);
        refused(
            world
                .owner
                .accept_handoff(&grant, &turn, &world.retained[AUTHORITY]),
            "effective unit differs",
        );
        assert_eq!(world.attempt(), before, "field {field}: nothing recorded");
    }
}

#[test]
fn the_daemon_consume_refuses_a_changed_authority_unit_commitment() {
    for field in 0..4 {
        let (world, ..) = daemon_at_guard();
        let before = world.attempt();
        unit_field(&world, 1, field);
        refused(
            world
                .owner
                .consume(Resource::Daemon, &measured(&guard_proc())),
            "units changed",
        );
        assert_eq!(world.attempt(), before, "field {field}: nothing recorded");
    }
}

#[test]
fn the_authority_consume_refuses_a_changed_daemon_unit_commitment() {
    for field in 0..4 {
        let (world, grant, turn) = authority_ready();
        world
            .owner
            .accept_handoff(&grant, &turn, &world.retained[AUTHORITY])
            .unwrap();
        let guard = proc(50, 0x72);
        world.host.0.lock().unwrap().units[1].state = UnitState::Active;
        start_guard(&world, Resource::Authority, &guard);
        world.owner.record_guard_start(Resource::Authority).unwrap();
        let before = world.attempt();
        unit_field(&world, 0, field);
        refused(
            world.owner.consume(Resource::Authority, &measured(&guard)),
            "units changed",
        );
        assert_eq!(world.attempt(), before, "field {field}: nothing recorded");
    }
}

#[test]
fn a_retirement_of_another_resource_is_refused_even_when_launch_and_death_agree() {
    let (world, launch, _) = daemon_at_guard();
    world
        .owner
        .consume(Resource::Daemon, &measured(&guard_proc()))
        .unwrap();
    let (retired, death, profile) = retired_daemon(&world, &launch);
    world.host.0.lock().unwrap().final_io[0] = true;
    let before = world.attempt();
    let mut wrong_death = death.clone();
    wrong_death.resource = Resource::Authority;
    let mut wrong_launch = retired.clone();
    wrong_launch.resource = Resource::Authority;
    wrong_launch.death = Some(h(&wrong_death).unwrap());
    assert!(
        wrong_launch.check_death(&wrong_death).is_ok(),
        "the pair is coherent on its own"
    );
    refused(
        world
            .owner
            .record_retirement(&wrong_launch, &wrong_death, &profile),
        "retirement is not",
    );
    assert_eq!(world.attempt(), before, "no retirement and no final I/O");
    world
        .owner
        .record_retirement(&retired, &death, &profile)
        .unwrap();
}

#[test]
fn a_signed_seal_receipt_must_be_the_pinned_plans_whole_cut() {
    for (what, change) in [
        (
            "old context",
            Box::new(|cut: &mut Cut, world: &World| {
                cut.old.instance = id("another-instance");
                let _ = world;
            }) as Box<dyn Fn(&mut Cut, &World)>,
        ),
        (
            "old member set",
            Box::new(|cut: &mut Cut, _: &World| cut.old_set = digest(0xa0)),
        ),
    ] {
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
        let mut body = world.turn_body(&seal_grant, &launch, &world.capture(&launch, &Key::rk()));
        body.captured_launch = None;
        body.capture = None;
        world
            .owner
            .accept_seal(&seal_grant, &world.turn(body, &Key::bk()))
            .unwrap();
        let mut cut = Cut {
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
        let sign = |cut: Cut| Sig::sign(Tag::Retired, ReceiptBody::new(cut), &Key::hk()).unwrap();
        let before = world.attempt();
        let good = sign(cut.clone());
        change(&mut cut, &world);
        refused(
            world.owner.bind_seal_receipt(&sign(cut)),
            "not this daemon's sealed cut",
        );
        assert_eq!(world.attempt(), before, "{what}: no receipt bound");
        world.owner.bind_seal_receipt(&good).unwrap();
    }
}

#[test]
fn a_custodian_sharing_its_own_originals_pid_is_refused_at_genesis() {
    for (custodian, original_pid) in [(2usize, 10u64), (3, 12)] {
        let mut world = World::new();
        world.retained[custodian].proc = measured(&proc(original_pid, 0x44));
        refused(
            world.install(),
            "custodians and originals must be distinct processes",
        );
        assert!(
            !world.path().join("active.json").exists(),
            "custodian {custodian}: nothing was written"
        );
    }
}

type Act = Box<dyn Fn(&World) -> Result<(), OwnerError>>;

/// The daemon is retired and its seal and receipt are staged one gate at a time. Each stage
/// returns the world at the gate and the one write that gate authorizes.
fn gate(name: &str) -> (World, Act, &'static str) {
    let custodian = "custodian is not the live enrolled process";
    match name {
        "enrollment" => {
            let world = World::new();
            world.install().unwrap();
            for resource in [Resource::Daemon, Resource::Authority] {
                world.owner.allocate_lease(resource).unwrap();
                world.host.0.lock().unwrap().fragments
                    [usize::from(resource == Resource::Authority)] = FragmentState::Guarded;
                world.owner.install_fragment(resource).unwrap();
            }
            world.stage_capture(Resource::Daemon);
            (world, Box::new(|w| w.owner.commit_enrollment()), custodian)
        }
        "daemon handoff" => {
            let world = World::new();
            let (launch, capture) = world.enroll();
            let grant = world.grant(&launch, LKind::LaunchD, launch.old.clone(), &Key::bk());
            let turn = world.turn(world.turn_body(&grant, &launch, &capture), &Key::bk());
            let act: Act =
                Box::new(move |w| w.owner.accept_handoff(&grant, &turn, &w.retained[DAEMON]));
            (world, act, custodian)
        }
        "daemon exit" => {
            let (world, ..) = handed_off();
            exit_original(&world, Resource::Daemon);
            let act: Act = Box::new(|w| w.owner.record_exit(Resource::Daemon, &w.retained[DAEMON]));
            (world, act, custodian)
        }
        "daemon guard start" => {
            let (world, ..) = handed_off();
            exit_original(&world, Resource::Daemon);
            world
                .owner
                .record_exit(Resource::Daemon, &world.retained[DAEMON])
                .unwrap();
            start_guard(&world, Resource::Daemon, &guard_proc());
            (
                world,
                Box::new(|w| w.owner.record_guard_start(Resource::Daemon)),
                custodian,
            )
        }
        "daemon consume" => {
            let (world, ..) = daemon_at_guard();
            let act: Act = Box::new(|w| {
                w.owner
                    .consume(Resource::Daemon, &measured(&guard_proc()))
                    .map(|_| ())
            });
            (world, act, "processes changed since the handoff")
        }
        "retirement" | "seal" | "receipt" | "authority exit" | "authority final I/O" => {
            let (world, launch, _) = daemon_at_guard();
            world
                .owner
                .consume(Resource::Daemon, &measured(&guard_proc()))
                .unwrap();
            let (retired, death, profile) = retired_daemon(&world, &launch);
            world.host.0.lock().unwrap().final_io[0] = true;
            if name == "retirement" {
                let act: Act =
                    Box::new(move |w| w.owner.record_retirement(&retired, &death, &profile));
                return (world, act, custodian);
            }
            world
                .owner
                .record_retirement(&retired, &death, &profile)
                .unwrap();
            let seal_grant = world.grant(&retired, LKind::Seal, death.next.clone(), &Key::bk());
            let mut body =
                world.turn_body(&seal_grant, &launch, &world.capture(&launch, &Key::rk()));
            body.captured_launch = None;
            body.capture = None;
            let seal_turn = world.turn(body, &Key::bk());
            if name == "seal" {
                let act: Act = Box::new(move |w| w.owner.accept_seal(&seal_grant, &seal_turn));
                return (world, act, custodian);
            }
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
            let receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut), &Key::hk()).unwrap();
            if name == "receipt" {
                let act: Act = Box::new(move |w| w.owner.bind_seal_receipt(&receipt));
                return (world, act, custodian);
            }
            world.owner.bind_seal_receipt(&receipt).unwrap();
            world.stage_capture(Resource::Authority);
            exit_original(&world, Resource::Authority);
            world.host.0.lock().unwrap().units[1].state = UnitState::Inactive;
            if name == "authority exit" {
                let act: Act = Box::new(|w| {
                    w.owner
                        .record_exit(Resource::Authority, &w.retained[AUTHORITY])
                });
                return (world, act, custodian);
            }
            world
                .owner
                .record_exit(Resource::Authority, &world.retained[AUTHORITY])
                .unwrap();
            world.host.0.lock().unwrap().final_io[1] = true;
            (
                world,
                Box::new(|w| w.owner.record_final_io(Resource::Authority)),
                custodian,
            )
        }
        "authority handoff" | "authority guard start" | "authority consume" => {
            let (world, grant, turn) = authority_ready();
            let handoff: Act = Box::new(move |w| {
                w.owner
                    .accept_handoff(&grant, &turn, &w.retained[AUTHORITY])
            });
            if name == "authority handoff" {
                return (world, handoff, custodian);
            }
            handoff(&world).unwrap();
            let guard = proc(50, 0x72);
            world.host.0.lock().unwrap().units[1].state = UnitState::Active;
            start_guard(&world, Resource::Authority, &guard);
            if name == "authority guard start" {
                let act: Act = Box::new(|w| w.owner.record_guard_start(Resource::Authority));
                return (world, act, custodian);
            }
            world.owner.record_guard_start(Resource::Authority).unwrap();
            let act: Act = Box::new(move |w| {
                w.owner
                    .consume(Resource::Authority, &measured(&guard))
                    .map(|_| ())
            });
            (world, act, "processes changed since the handoff")
        }
        _ => unreachable!("{name}"),
    }
}

const GATES: [&str; 13] = [
    "enrollment",
    "daemon handoff",
    "daemon exit",
    "daemon guard start",
    "daemon consume",
    "retirement",
    "seal",
    "receipt",
    "authority handoff",
    "authority exit",
    "authority final I/O",
    "authority guard start",
    "authority consume",
];

#[test]
fn every_authorizing_write_refuses_a_lost_or_replaced_custodian_and_writes_nothing() {
    type Change = (&'static str, fn(&mut HostState, u64));
    let changes: [Change; 3] = [
        ("lost", |s, pid| {
            s.procs.remove(&pid);
        }),
        ("another start", |s, pid| {
            s.procs.get_mut(&pid).unwrap().start += 1
        }),
        ("another image", |s, pid| {
            s.procs.get_mut(&pid).unwrap().exe = digest(0xfd)
        }),
    ];
    let mut failures = Vec::new();
    for name in GATES {
        for pid in [20u64, 22] {
            for (what, change) in &changes {
                let (world, act, why) = gate(name);
                let stored = std::fs::read(world.path().join("active.json")).unwrap();
                let saved = world
                    .host
                    .0
                    .lock()
                    .unwrap()
                    .procs
                    .get(&pid)
                    .cloned()
                    .unwrap();
                change(&mut world.host.0.lock().unwrap(), pid);
                let wanted = format!("{name}: custodian {pid} {what}");
                match act(&world) {
                    Err(OwnerError::Refused(got)) if got.contains(why) => {}
                    other => {
                        failures.push(format!("{wanted}: wanted a refusal, got {other:?}"));
                        continue;
                    }
                }
                assert_eq!(
                    std::fs::read(world.path().join("active.json")).unwrap(),
                    stored,
                    "{wanted}: nothing was written"
                );
                world.host.0.lock().unwrap().procs.insert(pid, saved);
                act(&world).unwrap_or_else(|e| panic!("{wanted}: restored write failed: {e:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_consumed_launch_is_returned_once_and_a_second_use_refuses() {
    let (world, ..) = gate("daemon consume");
    let guard = measured(&guard_proc());
    world.owner.consume(Resource::Daemon, &guard).unwrap();
    refused(
        world.owner.consume(Resource::Daemon, &guard),
        "already consumed",
    );
}

#[test]
fn the_exiting_original_may_be_absent_but_never_another_live_process() {
    let (world, ..) = gate("daemon exit");
    let stored = std::fs::read(world.path().join("active.json")).unwrap();
    {
        let mut state = world.host.0.lock().unwrap();
        let mut other = state.procs.get(&12).cloned().unwrap();
        other.pid = 10.try_into().unwrap_or(other.pid);
        state.procs.insert(10, other);
    }
    refused(
        world
            .owner
            .record_exit(Resource::Daemon, &world.retained[DAEMON]),
        "another process",
    );
    assert_eq!(
        std::fs::read(world.path().join("active.json")).unwrap(),
        stored
    );
    world.host.0.lock().unwrap().procs.remove(&10);
    world
        .owner
        .record_exit(Resource::Daemon, &world.retained[DAEMON])
        .unwrap();
}

#[test]
fn a_peer_original_that_vanished_blocks_an_exit_record() {
    let (world, ..) = gate("daemon exit");
    let stored = std::fs::read(world.path().join("active.json")).unwrap();
    world.host.0.lock().unwrap().procs.remove(&12);
    refused(
        world
            .owner
            .record_exit(Resource::Daemon, &world.retained[DAEMON]),
        "vanished without a witnessed exit",
    );
    assert_eq!(
        std::fs::read(world.path().join("active.json")).unwrap(),
        stored
    );
}
