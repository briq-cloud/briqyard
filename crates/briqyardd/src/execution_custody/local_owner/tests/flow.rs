use super::super::*;
use super::fixtures::*;
use briqyard_api::execution::sealed::prim::{LitBool, LitU};
use briqyard_api::execution::sealed::transition::Cut;
use briqyard_api::execution::sealed::{
    canonical::{decode, encode, h},
    custody::Resource,
    objects::Proc,
    owner::{ExitState, FragmentState, Point, UnitState},
    plan_pin::ReadPoint,
    prim::{HexDigest, Nonce},
    transition::{Death, LKind, Launch, LaunchStage, ReceiptBody},
};
use std::sync::atomic::Ordering;

fn guard_proc() -> Proc {
    proc(30, 0x71)
}

fn exit_original(world: &World, resource: Resource) {
    let (retained, pid) = match resource {
        Resource::Daemon => (&world.retained[DAEMON], 10),
        Resource::Authority => (&world.retained[AUTHORITY], 12),
    };
    retained.exit.store(true, Ordering::SeqCst);
    world.host.0.lock().unwrap().procs.remove(&pid);
}

fn start_guard(world: &World, resource: Resource, guard: &Proc) {
    let index = if resource == Resource::Daemon { 0 } else { 1 };
    world.host.0.lock().unwrap().unit_procs[index] = Some(measured(guard));
}

/// Enroll, then take the launch_d handoff at the current version.
fn handed_off() -> (World, Launch, Capture, LGrant) {
    let world = World::new();
    let (launch, capture) = world.enroll();
    let grant = world.grant(&launch, LKind::LaunchD, launch.old.clone(), &Key::bk());
    let turn = world.turn(world.turn_body(&grant, &launch, &capture), &Key::bk());
    world
        .owner
        .accept_handoff(&grant, &turn, &world.retained[DAEMON])
        .unwrap();
    (world, launch, capture, grant)
}

/// The daemon's authorized lineage: handoff, the original's exit, the enrolled guard's start.
fn daemon_at_guard() -> (World, Launch, Capture) {
    let (world, launch, capture, _) = handed_off();
    exit_original(&world, Resource::Daemon);
    world
        .owner
        .record_exit(Resource::Daemon, &world.retained[DAEMON])
        .unwrap();
    start_guard(&world, Resource::Daemon, &guard_proc());
    world.owner.record_guard_start(Resource::Daemon).unwrap();
    (world, launch, capture)
}

#[test]
fn install_writes_one_private_version_one_attempt_and_never_replaces_it() {
    let world = World::new();
    world.install().unwrap();
    let attempt = world.attempt();
    assert_eq!(attempt.version.get(), 1);
    assert_eq!(attempt.generation.get(), 1);
    assert_eq!(attempt.daemon.original, world.plan.pre_d);
    assert!(attempt.enrolled.is_none() && attempt.daemon.arm.is_none());
    use std::os::unix::fs::MetadataExt;
    let stat = std::fs::metadata(world.path().join("active.json")).unwrap();
    assert_eq!((stat.mode() & 0o777, stat.nlink()), (0o600, 1));
    assert!(!world.path().join("active.json.tmp").exists());
    refused(world.install(), "attempt already exists");
    assert_eq!(world.version(), 1);
}

#[test]
fn install_refuses_inputs_that_are_not_the_plans_own_live_ones() {
    let world = World::new();
    let mut other = world.plan.clone();
    other.rk = Key::attacker().key();
    let foreign = world.trust(&other);
    let build = || briqyard_api::execution::sealed::prim::Build::new("fence-3").unwrap();
    let attempt = |trust: &EnrolledTrust, world: &World, guards: GuardPins| {
        world.owner.install(
            &world.bytes,
            trust,
            id("h15-management"),
            &CustodianInput {
                retained: &world.retained[2],
                build: build(),
            },
            &CustodianInput {
                retained: &world.retained[3],
                build: build(),
            },
            &guards,
        )
    };
    refused(
        attempt(&foreign, &world, world.guards()),
        "not this Plan's enrollment",
    );
    let own = world.trust(&world.plan);
    refused(
        attempt(
            &own,
            &world,
            GuardPins {
                daemon: digest(0x01),
                authority: digest(0x72),
            },
        ),
        "guard image",
    );
    world.host.0.lock().unwrap().procs.get_mut(&10).unwrap().exe = digest(0x99);
    refused(
        attempt(&own, &world, world.guards()),
        "live process the Plan names",
    );
    world.host.0.lock().unwrap().procs.get_mut(&10).unwrap().exe = digest(0x33);
    world.retained[2].exit.store(true, Ordering::SeqCst);
    refused(
        attempt(&own, &world, world.guards()),
        "custodian is not live",
    );
    assert!(
        !world.path().join("active.json").exists(),
        "a refused install writes nothing"
    );
}

#[test]
fn leases_and_fragments_follow_the_resource_order_and_each_bump_one_version() {
    let world = World::new();
    world.install().unwrap();
    refused(
        world.owner.allocate_lease(Resource::Authority),
        "daemon then authority",
    );
    world.owner.allocate_lease(Resource::Daemon).unwrap();
    assert_eq!(world.version(), 2);
    refused(
        world.owner.allocate_lease(Resource::Daemon),
        "already allocated",
    );
    refused(
        world.owner.install_fragment(Resource::Daemon),
        "not on disk",
    );
    world.host.0.lock().unwrap().fragments[0] = FragmentState::Guarded;
    world.owner.install_fragment(Resource::Daemon).unwrap();
    assert_eq!(world.version(), 3);
    refused(
        world.owner.install_fragment(Resource::Authority),
        "needs the resource lease",
    );
    world.owner.allocate_lease(Resource::Authority).unwrap();
    world.host.0.lock().unwrap().fragments[1] = FragmentState::Guarded;
    world.owner.install_fragment(Resource::Authority).unwrap();
    let attempt = world.attempt();
    assert_eq!(attempt.version.get(), 5);
    assert_ne!(attempt.daemon.lease, attempt.authority.lease);
    assert!(attempt.daemon.lease.is_some());
    world.host.0.lock().unwrap().procs.remove(&10);
    refused(world.owner.commit_enrollment(), "preconditions");
}

#[test]
fn enrollment_writes_both_receipts_together_at_one_version_from_verified_units() {
    let world = World::new();
    let (launch, _) = world.enroll();
    let attempt = world.attempt();
    let (daemon, authority) = (
        attempt.daemon.arm.as_ref().unwrap(),
        attempt.authority.arm.as_ref().unwrap(),
    );
    assert_eq!(daemon.version, authority.version);
    assert_eq!(attempt.enrolled, Some(daemon.version));
    assert_eq!(
        attempt.version, daemon.version,
        "the receipts are the latest commit"
    );
    assert_eq!(daemon.fragment, digest(0x50));
    assert_eq!(
        (
            daemon.argv.clone(),
            daemon.sandbox.clone(),
            daemon.fdstore.clone()
        ),
        (digest(0x51), digest(0x52), digest(0x53))
    );
    assert_eq!(authority.fragment, digest(0x60));
    assert_eq!(daemon.lease, attempt.daemon.lease.clone().unwrap());
    assert_eq!(daemon.original, world.plan.pre_d);
    assert_eq!(daemon.custodian, launch.custodian);
    assert_eq!(daemon.target.as_str(), "h15-management");
    assert_eq!(daemon.lockout, attempt.lockout);
    assert_ne!(daemon.hash().unwrap(), authority.hash().unwrap());
    refused(world.owner.commit_enrollment(), "preconditions");
}

#[test]
fn enrollment_refuses_what_is_not_both_effective_guarded_units_with_a_staged_capture() {
    let prepare = |world: &World| {
        world.install().unwrap();
        for resource in [Resource::Daemon, Resource::Authority] {
            world.owner.allocate_lease(resource).unwrap();
            let index = if resource == Resource::Daemon { 0 } else { 1 };
            world.host.0.lock().unwrap().fragments[index] = FragmentState::Guarded;
            world.owner.install_fragment(resource).unwrap();
        }
    };
    let world = World::new();
    prepare(&world);
    refused(world.owner.commit_enrollment(), "preconditions");
    world.stage_capture(Resource::Daemon);
    world.host.0.lock().unwrap().units[1].reloaded = false;
    refused(world.owner.commit_enrollment(), "not effective");
    world.host.0.lock().unwrap().units[1].reloaded = true;
    world.host.0.lock().unwrap().units[0].job =
        briqyard_api::execution::sealed::owner::JobState::Queued;
    refused(world.owner.commit_enrollment(), "not effective");
    world.host.0.lock().unwrap().units[0].job =
        briqyard_api::execution::sealed::owner::JobState::None;
    world.host.0.lock().unwrap().units[0].state = UnitState::Failed;
    refused(world.owner.commit_enrollment(), "not effective");
    world.host.0.lock().unwrap().units[0].state = UnitState::Active;
    world.host.0.lock().unwrap().guards[1] = digest(0x01);
    refused(world.owner.commit_enrollment(), "not effective");
    assert!(
        world.attempt().enrolled.is_none(),
        "every refusal left the attempt unenrolled"
    );
    world.host.0.lock().unwrap().guards[1] = digest(0x72);
    world.owner.commit_enrollment().unwrap();
}

#[test]
fn a_capture_must_be_the_retained_originals_own_signed_pair_and_comes_once() {
    let world = World::new();
    world.install().unwrap();
    world.owner.allocate_lease(Resource::Daemon).unwrap();
    let launch = world.launch(Resource::Daemon, 1);
    let retained = &world.retained[DAEMON];
    let forged = world.capture(&launch, &Key::attacker());
    assert!(matches!(
        world
            .owner
            .record_capture(Resource::Daemon, &launch, &forged, retained),
        Err(OwnerError::Sig(_))
    ));
    let signed = world.capture(&launch, &Key::rk());
    let mut stale_challenge = launch.clone();
    stale_challenge.nonce = Nonce::from_array([9; 32]);
    assert!(matches!(
        world
            .owner
            .record_capture(Resource::Daemon, &stale_challenge, &signed, retained),
        Err(OwnerError::Codec(_))
    ));
    let mut wrong_custodian = launch.clone();
    wrong_custodian.custodian = proc(22, 0x44);
    let for_wrong = world.capture(&wrong_custodian, &Key::rk());
    refused(
        world
            .owner
            .record_capture(Resource::Daemon, &wrong_custodian, &for_wrong, retained),
        "retained original",
    );
    refused(
        world.owner.record_capture(
            Resource::Daemon,
            &launch,
            &signed,
            &world.retained[AUTHORITY],
        ),
        "retained original",
    );
    retained.exit.store(true, Ordering::SeqCst);
    refused(
        world
            .owner
            .record_capture(Resource::Daemon, &launch, &signed, retained),
        "retained original",
    );
    retained.exit.store(false, Ordering::SeqCst);
    assert_eq!(world.version(), 2);
    world
        .owner
        .record_capture(Resource::Daemon, &launch, &signed, retained)
        .unwrap();
    refused(
        world
            .owner
            .record_capture(Resource::Daemon, &launch, &signed, retained),
        "retained original",
    );
    assert_eq!(world.version(), 3);
}

#[test]
fn the_collector_projects_only_what_the_targets_own_state_allows() {
    let world = World::new();
    world.install().unwrap();
    for point in [Point::Launch, Point::Seal] {
        assert!(
            world.observe(Resource::Daemon, point).is_err(),
            "{point:?} before enrollment"
        );
    }
    let before = world.observe(Resource::Daemon, Point::Prearm).unwrap();
    assert!(
        before.arm.is_none()
            && before.launch_capture.is_none()
            && before.daemon_retirement.is_none()
    );
    assert_eq!(before.observation.leases.daemon, None);
    assert_eq!(before.observation.fragments.daemon, FragmentState::Legacy);
    assert_eq!(before.observation.retired.exit, ExitState::Running);
    assert_eq!(before.observation.images.original, world.plan.pre_d.exe);
    let (launch, capture) = {
        world.owner.allocate_lease(Resource::Daemon).unwrap();
        world.owner.allocate_lease(Resource::Authority).unwrap();
        for resource in [Resource::Daemon, Resource::Authority] {
            let index = if resource == Resource::Daemon { 0 } else { 1 };
            world.host.0.lock().unwrap().fragments[index] = FragmentState::Guarded;
            world.owner.install_fragment(resource).unwrap();
        }
        let pair = world.stage_capture(Resource::Daemon);
        world.owner.commit_enrollment().unwrap();
        pair
    };
    assert!(
        world.observe(Resource::Daemon, Point::Prearm).is_err(),
        "prearm after enrollment"
    );
    let daemon = world.observe(Resource::Daemon, Point::Launch).unwrap();
    assert_eq!(daemon.arm.as_ref().unwrap().resource, Resource::Daemon);
    let pair = daemon.launch_capture.as_ref().unwrap();
    assert_eq!((&pair.launch, &pair.capture), (&launch, &capture));
    assert!(daemon.daemon_retirement.is_none());
    assert_eq!(daemon.observation.version, world.attempt().version);
    let authority = world.observe(Resource::Authority, Point::Launch).unwrap();
    assert_eq!(
        authority.arm.as_ref().unwrap().resource,
        Resource::Authority
    );
    assert!(authority.launch_capture.is_none() && authority.daemon_retirement.is_none());
    assert!(
        world.observe(Resource::Daemon, Point::Seal).is_err(),
        "seal before the retirement"
    );
    let mut seal_authority = world.request(Resource::Authority, Point::Launch);
    seal_authority = String::from_utf8(seal_authority)
        .unwrap()
        .replace("\"launch\"", "\"seal\"")
        .into_bytes();
    assert!(matches!(
        world.owner.observe(&seal_authority),
        Err(OwnerError::Codec(_))
    ));
    let mut elsewhere = decode::<briqyard_api::execution::sealed::owner::ObserveRequest>(
        &world.request(Resource::Daemon, Point::Launch),
    )
    .unwrap();
    elsewhere.x.serial = briqyard_api::execution::sealed::prim::PosInt::new(2).unwrap();
    assert!(world.owner.observe(&encode(&elsewhere).unwrap()).is_err());
    assert!(matches!(
        world.owner.observe(b"{}"),
        Err(OwnerError::Codec(_))
    ));
}

#[test]
fn an_observation_refuses_a_changed_unit_a_vanished_original_or_a_rebooted_target() {
    let world = World::new();
    world.enroll();
    world.observe(Resource::Daemon, Point::Launch).unwrap();
    for (what, undo) in [
        ("fragment", 0x50u8),
        ("sandbox", 0x52),
        ("argv", 0x51),
        ("fdstore", 0x53),
    ] {
        let before = world.host.0.lock().unwrap().units[0].clone();
        let mut swapped = before.clone();
        match what {
            "fragment" => swapped.fragment = digest(0xee),
            "sandbox" => swapped.sandbox = digest(0xee),
            "argv" => swapped.argv = digest(0xee),
            _ => swapped.fdstore = digest(0xee),
        }
        world.host.0.lock().unwrap().units[0] = swapped;
        refused(
            world.observe(Resource::Daemon, Point::Launch),
            "differs from its receipt",
        );
        world.host.0.lock().unwrap().units[0] = before;
        let _ = undo;
    }
    world.host.0.lock().unwrap().procs.remove(&10);
    refused(
        world.observe(Resource::Daemon, Point::Launch),
        "vanished without a witnessed exit",
    );
    world
        .host
        .0
        .lock()
        .unwrap()
        .procs
        .insert(10, measured(&world.plan.pre_d));
    world.host.0.lock().unwrap().boot =
        briqyard_api::execution::sealed::prim::BootId::new("00000000-0000-4000-8000-000000000005")
            .unwrap();
    refused(world.observe(Resource::Daemon, Point::Launch), "rebooted");
}

#[test]
fn the_first_handoff_compares_the_exact_version_and_every_binding_before_anything_changes() {
    let world = World::new();
    let (launch, capture) = world.enroll();
    let grant = world.grant(&launch, LKind::LaunchD, launch.old.clone(), &Key::bk());
    let good = world.turn_body(&grant, &launch, &capture);
    let version = world.version();
    let retained = &world.retained[DAEMON];
    let attempt = |turn: Turn, grant: &LGrant| world.owner.accept_handoff(grant, &turn, retained);
    type Mutation = Box<dyn Fn(&mut briqyard_api::execution::sealed::owner::TurnBody)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        (
            "target version ahead",
            Box::new(|t| {
                t.target_version =
                    briqyard_api::execution::sealed::prim::PosInt::new(t.target_version.get() + 1)
                        .unwrap()
            }),
        ),
        (
            "target version behind",
            Box::new(|t| {
                t.target_version =
                    briqyard_api::execution::sealed::prim::PosInt::new(t.target_version.get() - 1)
                        .unwrap()
            }),
        ),
        ("decision", Box::new(|t| t.decision = digest(0x01))),
        (
            "captured launch",
            Box::new(|t| t.captured_launch = Some(digest(0x02))),
        ),
        ("capture", Box::new(|t| t.capture = Some(digest(0x03)))),
        (
            "boot",
            Box::new(|t| {
                t.boot = briqyard_api::execution::sealed::prim::BootId::new(
                    "00000000-0000-4000-8000-000000000009",
                )
                .unwrap()
            }),
        ),
        ("lockout", Box::new(|t| t.lockout = digest(0x04))),
        (
            "owner",
            Box::new(|t| t.owner = Nonce::from_array([0x77; 32])),
        ),
        ("plan", Box::new(|t| t.plan = digest(0x05))),
    ];
    for (what, mutate) in mutations {
        let mut body = good.clone();
        mutate(&mut body);
        let result = attempt(world.turn(body, &Key::bk()), &grant);
        assert!(result.is_err(), "{what} was accepted");
        assert_eq!(world.version(), version, "{what} changed the attempt");
    }
    assert!(
        attempt(world.turn(good.clone(), &Key::rk()), &grant).is_err(),
        "Rk cannot sign owner.turn"
    );
    assert!(attempt(world.turn(good.clone(), &Key::attacker()), &grant).is_err());
    let forged_api = world.grant(
        &launch,
        LKind::LaunchD,
        launch.old.clone(),
        &Key::attacker(),
    );
    assert!(attempt(world.turn(good.clone(), &Key::bk()), &forged_api).is_err());
    let wrong_expected = world.grant(&launch, LKind::LaunchD, proc(11, 0x33), &Key::bk());
    let mut body = good.clone();
    body.decision = h(wrong_expected.decision()).unwrap();
    assert!(attempt(world.turn(body, &Key::bk()), &wrong_expected).is_err());
    assert_eq!(world.version(), version);
    let swapped_unit = world.host.0.lock().unwrap().units[0].clone();
    world.host.0.lock().unwrap().units[0].fragment = digest(0xee);
    refused(
        attempt(world.turn(good.clone(), &Key::bk()), &grant),
        "differs from its receipt",
    );
    world.host.0.lock().unwrap().units[0] = swapped_unit;
    retained.exit.store(true, Ordering::SeqCst);
    refused(
        attempt(world.turn(good.clone(), &Key::bk()), &grant),
        "retained live process",
    );
    retained.exit.store(false, Ordering::SeqCst);
    attempt(world.turn(good.clone(), &Key::bk()), &grant).unwrap();
    assert_eq!(world.version(), version + 1);
    let handoff = world.attempt().daemon.handoff.clone().unwrap();
    assert_eq!(handoff.base.get(), version);
    assert_eq!(handoff.grant, grant.hash().unwrap());
    refused(
        attempt(world.turn(good, &Key::bk()), &grant),
        "target version",
    );
}

#[test]
fn a_turn_minted_at_an_older_version_cannot_ride_an_unrelated_mutation() {
    let world = World::new();
    let (launch, capture) = world.enroll();
    let grant = world.grant(&launch, LKind::LaunchD, launch.old.clone(), &Key::bk());
    let turn = world.turn(world.turn_body(&grant, &launch, &capture), &Key::bk());
    world.stage_capture(Resource::Authority);
    refused(
        world
            .owner
            .accept_handoff(&grant, &turn, &world.retained[DAEMON]),
        "target version",
    );
    assert!(world.attempt().daemon.handoff.is_none());
}

#[test]
fn the_authorized_lineage_is_handoff_then_exit_then_guard_and_only_then_consumes_once() {
    let (world, launch, _) = daemon_at_guard();
    let attempt = world.attempt();
    let base = attempt.daemon.handoff.as_ref().unwrap().base.get();
    let events: Vec<u64> = attempt
        .events
        .iter()
        .map(|event| event.version.get())
        .collect();
    assert_eq!(
        events,
        vec![base + 1, base + 2, base + 3],
        "licensed increments are consecutive"
    );
    assert_eq!(attempt.version.get(), base + 3);
    let consumed = world
        .owner
        .consume(Resource::Daemon, &measured(&guard_proc()))
        .unwrap();
    assert_eq!(consumed.stage, LaunchStage::Consumed);
    assert_eq!(consumed.nonce, launch.nonce);
    launch.check_next(&consumed).unwrap();
    let after = world.attempt();
    let record = after.daemon.consumed.as_ref().unwrap();
    assert_eq!(record.launch, consumed.hash().unwrap());
    assert_eq!(record.grant, after.daemon.handoff.as_ref().unwrap().grant);
    assert_eq!(after.version.get(), base + 4);
    refused(
        world
            .owner
            .consume(Resource::Daemon, &measured(&guard_proc())),
        "already consumed",
    );
}

#[test]
fn consumption_refuses_every_break_in_the_lineage_and_changes_nothing() {
    let guard = measured(&guard_proc());
    type Case = Box<dyn Fn(&World)>;
    let mut cases: Vec<(&str, Case)> = Vec::new();
    cases.push(("another guard pid", Box::new(|_| {})));
    cases.push((
        "a replaced unit",
        Box::new(|w| w.host.0.lock().unwrap().units[0].argv = digest(0xee)),
    ));
    cases.push((
        "a rebooted target",
        Box::new(|w| {
            w.host.0.lock().unwrap().boot = briqyard_api::execution::sealed::prim::BootId::new(
                "00000000-0000-4000-8000-000000000005",
            )
            .unwrap()
        }),
    ));
    for (what, change) in cases {
        let (world, _, _) = daemon_at_guard();
        change(&world);
        let before = world.attempt();
        let who = if what == "another guard pid" {
            measured(&proc(31, 0x71))
        } else {
            guard.clone()
        };
        assert!(
            world.owner.consume(Resource::Daemon, &who).is_err(),
            "{what} consumed"
        );
        assert_eq!(world.attempt(), before, "{what} changed the attempt");
    }
    let (world, _, _) = daemon_at_guard();
    let mut wrong_image = guard.clone();
    wrong_image.exe = digest(0x01);
    assert!(world.owner.consume(Resource::Daemon, &wrong_image).is_err());
    let (world, _, _) = daemon_at_guard();
    world.stage_capture(Resource::Authority);
    refused(
        world.owner.consume(Resource::Daemon, &guard),
        "lineage since the handoff",
    );
}

#[test]
fn the_exit_and_the_guard_must_be_the_enrolled_ones_and_in_order() {
    let (world, _, _, _) = handed_off();
    refused(
        world.owner.record_guard_start(Resource::Daemon),
        "not expected",
    );
    refused(
        world
            .owner
            .record_exit(Resource::Daemon, &world.retained[DAEMON]),
        "does not report this exit",
    );
    world.retained[DAEMON].exit.store(true, Ordering::SeqCst);
    refused(
        world
            .owner
            .record_exit(Resource::Authority, &world.retained[AUTHORITY]),
        "not expected",
    );
    world
        .owner
        .record_exit(Resource::Daemon, &world.retained[DAEMON])
        .unwrap();
    refused(
        world
            .owner
            .record_exit(Resource::Daemon, &world.retained[DAEMON]),
        "not expected",
    );
    for (what, wrong) in [
        ("the original itself", measured(&world.plan.pre_d)),
        ("another image", measured(&proc(30, 0x01))),
    ] {
        start_guard(
            &world,
            Resource::Daemon,
            &Proc {
                boot: world.plan.pre_d.boot.clone(),
                ..{
                    let mut p = proc(wrong.pid(), 0x00);
                    p.exe = wrong.exe().clone();
                    p
                }
            },
        );
        refused(
            world.owner.record_guard_start(Resource::Daemon),
            "enrolled guard",
        );
        let _ = what;
    }
    world.host.0.lock().unwrap().unit_procs[0] = None;
    refused(
        world.owner.record_guard_start(Resource::Daemon),
        "runs no process",
    );
}

fn retired_daemon(world: &World, launch: &Launch) -> (Launch, Death, HexDigest) {
    let profile = digest(0x90);
    let death = Death {
        x: x(),
        plan: launch.plan.clone(),
        resource: Resource::Daemon,
        owner: launch.owner,
        old: launch.old.clone(),
        next: proc(40, 0x81),
        custodian: launch.custodian.clone(),
        challenge: Nonce::from_array([0x80; 32]),
        profile: profile.clone(),
        exited: LitBool,
        external_writers: LitU,
        durable: LitBool,
    };
    let _ = world;
    let mut retired = launch.clone();
    retired.stage = LaunchStage::Retired;
    retired.successor = Some(death.next.clone());
    retired.death = Some(h(&death).unwrap());
    (retired, death, profile)
}

#[test]
fn the_retirement_seal_and_launch_a_join_follow_the_targets_own_records() {
    let (world, launch, _) = daemon_at_guard();
    world
        .owner
        .consume(Resource::Daemon, &measured(&guard_proc()))
        .unwrap();
    let (retired, death, profile) = retired_daemon(&world, &launch);
    refused(
        world
            .owner
            .record_retirement(&retired, &death, &digest(0x91)),
        "retirement is not",
    );
    let mut wrong_death = death.clone();
    wrong_death.challenge = Nonce::from_array([0x81; 32]);
    assert!(world
        .owner
        .record_retirement(&retired, &wrong_death, &profile)
        .is_err());
    let mut wrong_owner = retired.clone();
    wrong_owner.owner = Nonce::from_array([0x99; 32]);
    assert!(world
        .owner
        .record_retirement(&wrong_owner, &death, &profile)
        .is_err());
    world
        .owner
        .record_retirement(&retired, &death, &profile)
        .unwrap();
    refused(
        world.owner.record_retirement(&retired, &death, &profile),
        "retirement is not",
    );

    let seal = world.observe(Resource::Daemon, Point::Seal).unwrap();
    assert!(seal.arm.is_none() && seal.launch_capture.is_none());
    let retirement = seal.daemon_retirement.as_ref().unwrap();
    assert_eq!((&retirement.launch, &retirement.death), (&retired, &death));
    assert!(seal.observation.retired.final_io);
    assert!(world.observe(Resource::Daemon, Point::Launch).is_err());
    assert!(
        world.observe(Resource::Authority, Point::Launch).is_err(),
        "launch_a before the seal"
    );

    let seal_grant = world.grant(&retired, LKind::Seal, death.next.clone(), &Key::bk());
    let mut seal_body = world.turn_body(&seal_grant, &launch, &world.capture(&launch, &Key::rk()));
    seal_body.captured_launch = None;
    seal_body.capture = None;
    let stale = {
        let mut stale = seal_body.clone();
        stale.target_version =
            briqyard_api::execution::sealed::prim::PosInt::new(stale.target_version.get() - 1)
                .unwrap();
        world.turn(stale, &Key::bk())
    };
    assert!(world.owner.accept_seal(&seal_grant, &stale).is_err());
    let with_hashes = {
        let mut hashed = seal_body.clone();
        hashed.capture = Some(digest(1));
        hashed
    };
    assert!(decode::<briqyard_api::execution::sealed::owner::TurnBody>(
        &encode(&with_hashes).unwrap()
    )
    .is_err());
    let seal_turn = world.turn(seal_body.clone(), &Key::bk());
    world.owner.accept_seal(&seal_grant, &seal_turn).unwrap();
    refused(
        world.owner.accept_seal(&seal_grant, &seal_turn),
        "seal turn does not bind",
    );
    assert!(
        world.observe(Resource::Daemon, Point::Seal).is_err(),
        "one seal acceptance"
    );

    let cut = Cut {
        x: x(),
        plan: launch.plan.clone(),
        old: world.plan.pre.clone(),
        old_set: digest(0xa0),
        new_instance: id("new-instance"),
        old_proc: death.old.clone(),
        new_proc: death.next.clone(),
        custody: h(&death).unwrap(),
        profile: profile.clone(),
        retired_epoch: world.plan.pre.epoch.clone(),
        prior_host_water: world.plan.pre.generation,
    };
    let receipt = |signer: &Key, cut: Cut| {
        briqyard_api::execution::sealed::sig::Sig::sign(
            briqyard_api::execution::sealed::sig::Tag::Retired,
            ReceiptBody::new(cut),
            signer,
        )
        .unwrap()
    };
    assert!(world
        .owner
        .bind_seal_receipt(&receipt(&Key::attacker(), cut.clone()))
        .is_err());
    let mut other_cut = cut.clone();
    other_cut.new_proc = proc(41, 0x81);
    assert!(world
        .owner
        .bind_seal_receipt(&receipt(&Key::hk(), other_cut))
        .is_err());
    let mut other_custody = cut.clone();
    other_custody.custody = digest(0xb0);
    assert!(world
        .owner
        .bind_seal_receipt(&receipt(&Key::hk(), other_custody))
        .is_err());
    let signed = receipt(&Key::hk(), cut);
    world.owner.bind_seal_receipt(&signed).unwrap();
    assert_eq!(world.attempt().seal_receipt, Some(h(&signed).unwrap()));

    refused(
        world.owner.record_final_io(Resource::Authority),
        "not expected",
    );
    refused(
        world
            .owner
            .record_exit(Resource::Authority, &world.retained[AUTHORITY]),
        "exit is not expected",
    );
    world.stage_capture(Resource::Authority);
    refused(
        world
            .owner
            .record_exit(Resource::Authority, &world.retained[AUTHORITY]),
        "does not report this exit",
    );
    exit_original(&world, Resource::Authority);
    world.host.0.lock().unwrap().units[1].state = UnitState::Inactive;
    refused(
        world.observe(Resource::Authority, Point::Launch),
        "vanished without a witnessed exit",
    );
    world
        .owner
        .record_exit(Resource::Authority, &world.retained[AUTHORITY])
        .unwrap();
    refused(
        world.observe(Resource::Authority, Point::Launch),
        "exit and final I/O",
    );
    refused(
        world.owner.record_final_io(Resource::Authority),
        "fixture has no final I/O",
    );
    world.host.0.lock().unwrap().final_io[1] = true;
    world.owner.record_final_io(Resource::Authority).unwrap();

    let launch_a = world.observe(Resource::Authority, Point::Launch).unwrap();
    assert!(launch_a.arm.is_none());
    assert_eq!(launch_a.observation.retired.exit, ExitState::Exited);
    assert_eq!(
        launch_a.observation.retired.receipt,
        Some(h(&signed).unwrap())
    );
    assert!(launch_a.observation.retired.final_io);
    assert_eq!(launch_a.observation.unit.state, UnitState::Inactive);
    let authority_pair = launch_a.launch_capture.as_ref().unwrap();
    assert_eq!(authority_pair.launch.resource, Resource::Authority);
    assert_eq!(launch_a.daemon_retirement.as_ref().unwrap().launch, retired);

    let authority_launch = authority_pair.launch.clone();
    let authority_capture = authority_pair.capture.clone();
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
    world
        .owner
        .accept_handoff(&grant, &turn, &world.retained[AUTHORITY])
        .unwrap();
    let guard = proc(50, 0x72);
    world.host.0.lock().unwrap().units[1].state = UnitState::Active;
    start_guard(&world, Resource::Authority, &guard);
    world.owner.record_guard_start(Resource::Authority).unwrap();
    let consumed = world
        .owner
        .consume(Resource::Authority, &measured(&guard))
        .unwrap();
    assert_eq!(consumed.stage, LaunchStage::Consumed);
    assert!(
        world.observe(Resource::Authority, Point::Launch).is_err(),
        "the join closes at the handoff"
    );
}

#[test]
fn launch_a_refuses_until_the_exit_the_final_io_and_the_sealed_receipt_are_recorded() {
    let world = World::new();
    let (launch, capture) = world.enroll();
    let grant = world.grant(&launch, LKind::LaunchA, launch.old.clone(), &Key::bk());
    let turn = world.turn(world.turn_body(&grant, &launch, &capture), &Key::bk());
    assert!(world
        .owner
        .accept_handoff(&grant, &turn, &world.retained[DAEMON])
        .is_err());
}

#[test]
fn the_owner_is_the_plan_read_owner_of_its_own_attempt_and_every_change_alters_its_facts() {
    use crate::execution_custody::plan_reader::PlanReadOwner;
    let world = World::new();
    world.install().unwrap();
    let scope = |resource, point| {
        ReadScope::new(x(), world.plan.registered.clone(), resource, point).unwrap()
    };
    let first = world
        .owner
        .capture(&scope(Resource::Daemon, ReadPoint::Prearm))
        .unwrap();
    let again = world
        .owner
        .capture(&scope(Resource::Daemon, ReadPoint::Prearm))
        .unwrap();
    assert_eq!(first, again);
    assert!(world
        .owner
        .capture(&scope(Resource::Daemon, ReadPoint::Launch))
        .is_err());
    assert!(world
        .owner
        .capture(&scope(Resource::Daemon, ReadPoint::Seal))
        .is_err());
    world.owner.allocate_lease(Resource::Daemon).unwrap();
    let after = world
        .owner
        .capture(&scope(Resource::Daemon, ReadPoint::Prearm))
        .unwrap();
    assert_ne!(
        first, after,
        "a mutation is visible to the reader's comparison"
    );
    let (held, locked) = world
        .owner
        .lock_and_capture(&scope(Resource::Authority, ReadPoint::Prearm))
        .unwrap();
    drop((held, locked));
    let other = ReadScope::new(
        briqyard_api::execution::sealed::objects::X {
            serial: briqyard_api::execution::sealed::prim::PosInt::new(2).unwrap(),
            ..x()
        },
        world.plan.registered.clone(),
        Resource::Daemon,
        ReadPoint::Prearm,
    )
    .unwrap();
    assert!(world.owner.capture(&other).is_err());
}

#[test]
fn the_production_host_measures_processes_and_refuses_what_has_no_decided_preimage() {
    match LiveHost::new() {
        Err(OwnerError::Custody(_)) => assert_ne!(unsafe { libc::geteuid() }, 0),
        Ok(host) => {
            assert!(host
                .process(u64::from(std::process::id()))
                .unwrap()
                .is_some());
            assert!(host.process(u64::from(i32::MAX as u32)).unwrap().is_none());
            assert!(matches!(
                host.unit(Resource::Daemon),
                Err(OwnerError::Unprovisioned(_))
            ));
            assert!(matches!(
                host.fragment(Resource::Daemon),
                Err(OwnerError::Unprovisioned(_))
            ));
            assert!(matches!(
                host.guard_image(Resource::Authority),
                Err(OwnerError::Unprovisioned(_))
            ));
            assert!(matches!(
                host.unit_process(Resource::Authority),
                Err(OwnerError::Unprovisioned(_))
            ));
            assert!(matches!(
                host.final_io(Resource::Authority),
                Err(OwnerError::Unprovisioned(_))
            ));
        }
        Err(other) => panic!("{other:?}"),
    }
}
