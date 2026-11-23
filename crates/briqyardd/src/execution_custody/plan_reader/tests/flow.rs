use super::*;

const _: fn() = || {
    trait AmbiguousIfImpl<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
    impl<T: Clone> AmbiguousIfImpl<u8> for T {}
    impl<T: ?Sized + serde::Serialize> AmbiguousIfImpl<u16> for T {}
    let _ = <VerifiedPlanObservation as AmbiguousIfImpl<_>>::some_item;
};

fn rig(phase: &'static str) -> (World, Arc<SyntheticOwner>, PlanReader) {
    let world = World::new();
    let owner = SyntheticOwner::new(&world, phase);
    let reader = world.reader();
    (world, owner, reader)
}

#[test]
fn an_exact_read_is_observation_only_and_changes_nothing() {
    let (world, owner, reader) = rig("enrolled");
    let _helper = serve(&world.sock_dir(), honest(&world));
    let before = world.tree();
    let trust_before = std::fs::read(world.trust_file()).unwrap();
    {
        let rejoined =
            observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch).unwrap();
        let (observation, held) = rejoined.fresh().unwrap();
        assert_eq!(observation.pin(), &world.local().pin());
        assert_eq!(observation.read().resource, Resource::Daemon);
        assert_eq!(observation.read().point, ReadPoint::Launch);
        assert_eq!(held.facts.floor, 1);
    }
    assert_eq!(world.tree(), before);
    assert_eq!(std::fs::read(world.trust_file()).unwrap(), trust_before);
    let state = owner.state.lock().unwrap();
    assert_eq!(state.facts.floor, 1);
    assert_eq!(state.facts.phase, "enrolled");
    assert_eq!(
        (
            owner.captures.load(Ordering::SeqCst),
            owner.locks.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
}

#[test]
fn every_defined_resource_and_point_reads_and_authority_seal_cannot_be_asked() {
    for (resource, point, phase) in [
        (Resource::Daemon, ReadPoint::Prearm, "preparing"),
        (Resource::Daemon, ReadPoint::Launch, "enrolled"),
        (Resource::Daemon, ReadPoint::Seal, "enrolled"),
        (Resource::Authority, ReadPoint::Prearm, "preparing"),
        (Resource::Authority, ReadPoint::Launch, "enrolled"),
    ] {
        let (world, owner, reader) = rig(phase);
        let _helper = serve(&world.sock_dir(), honest(&world));
        let rejoined = observe(&world, &reader, &owner, resource, point).unwrap();
        let (observation, _) = rejoined.fresh().unwrap();
        assert_eq!(
            (observation.read().resource, observation.read().point),
            (resource, point)
        );
    }
    let world = World::new();
    let error = refused(ReadScope::new(
        world.plan.x.clone(),
        world.plan.registered.clone(),
        Resource::Authority,
        ReadPoint::Seal,
    ));
    says(&error, "seal is daemon-only");
}

#[test]
fn a_point_the_owner_state_does_not_allow_is_refused_before_any_exchange() {
    let (world, owner, reader) = rig("preparing");
    let helper = serve(&world.sock_dir(), honest(&world));
    says(
        &refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "phase does not allow",
    );
    assert_eq!(helper.accepted(), 0);
}

#[test]
fn missing_terminal_or_released_state_is_refused_before_any_exchange() {
    type Change = fn(&mut State);
    let cases: [(&str, Change); 3] = [
        ("no durable operation state", |s| s.missing = true),
        ("operation is terminal", |s| s.terminal = true),
        ("operation hold is gone", |s| s.facts.hold = false),
    ];
    for (text, change) in cases {
        let (world, owner, reader) = rig("enrolled");
        let helper = serve(&world.sock_dir(), honest(&world));
        owner.mutate(change);
        says(
            &refused(observe(
                &world,
                &reader,
                &owner,
                Resource::Daemon,
                ReadPoint::Launch,
            )),
            text,
        );
        assert_eq!(helper.accepted(), 0, "{text}");
    }
}

#[test]
fn an_owner_plan_for_another_operation_is_refused_before_trust_is_read() {
    let (world, owner, reader) = rig("enrolled");
    let helper = serve(&world.sock_dir(), honest(&world));
    let mut other = world.plan.clone();
    other.x.op = digest(0x42);
    other.pre = other.pre_record.ctx(&other.x.host);
    owner.mutate(|s| s.plan = encode(&other).unwrap());
    says(
        &refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "not the requested operation",
    );
    assert_eq!(helper.accepted(), 0);
}

#[test]
fn the_read_runs_outside_the_owners_lock() {
    let (world, owner, reader) = rig("enrolled");
    let local = world.local();
    let probe = Arc::clone(&owner);
    let _helper = serve(&world.sock_dir(), move |request| {
        drop(probe.state.lock().unwrap());
        let read: Read = decode(request).unwrap();
        Reply::Send(framed(&honest_pair(&read, &local)))
    });
    drop(observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch).unwrap());
}

#[test]
fn an_owner_that_changed_during_the_read_is_refused() {
    type Change = fn(&mut State);
    let cases: [(&str, Change); 8] = [
        ("custodian restarted", |s| s.custodian = proc(78)),
        ("owner", |s| s.facts.owner += 1),
        ("boot", |s| s.facts.boot += 1),
        ("serial", |s| s.facts.serial += 1),
        ("floor", |s| s.facts.floor += 1),
        ("plan", |s| {
            let mut changed: Plan = decode(&s.plan).unwrap();
            changed.new = members(9);
            s.plan = encode(&changed).unwrap();
        }),
        ("hold released", |s| s.facts.hold = false),
        ("terminal", |s| s.terminal = true),
    ];
    for (name, change) in cases {
        let (world, owner, reader) = rig("enrolled");
        let local = world.local();
        let mover = Arc::clone(&owner);
        let _helper = serve(&world.sock_dir(), move |request| {
            mover.mutate(change);
            let read: Read = decode(request).unwrap();
            Reply::Send(framed(&honest_pair(&read, &local)))
        });
        let error = refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        ));
        assert!(matches!(error, PlanReadError::Owner(_)), "{name}: {error}");
    }
}

#[test]
fn a_replayed_pair_is_not_a_pin_for_the_next_exchange() {
    let (world, owner, reader) = rig("enrolled");
    let local = world.local();
    let recorded = Arc::new(Mutex::new(None::<Vec<u8>>));
    let slot = Arc::clone(&recorded);
    let _helper = serve(&world.sock_dir(), move |request| {
        let mut recorded = slot.lock().unwrap();
        let reply =
            recorded.get_or_insert_with(|| honest_pair(&decode::<Read>(request).unwrap(), &local));
        Reply::Send(framed(reply))
    });
    drop(observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch).unwrap());
    let error = refused(observe(
        &world,
        &reader,
        &owner,
        Resource::Daemon,
        ReadPoint::Launch,
    ));
    says(&error, "echo is not the outstanding request");
}

#[test]
fn one_read_per_resource_is_outstanding_and_its_nonce_is_released_on_drop() {
    let (world, owner, reader) = rig("enrolled");
    let second = SyntheticOwner::new(&world, "enrolled");
    let _helper = serve(&world.sock_dir(), honest(&world));
    let held = observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch).unwrap();
    says(
        &refused(observe(
            &world,
            &reader,
            &second,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "outstanding",
    );
    drop(
        observe(
            &world,
            &reader,
            &second,
            Resource::Authority,
            ReadPoint::Launch,
        )
        .unwrap(),
    );
    drop(held);
    drop(
        observe(
            &world,
            &reader,
            &second,
            Resource::Daemon,
            ReadPoint::Launch,
        )
        .unwrap(),
    );
}

#[test]
fn a_missing_trust_record_fails_the_read_without_touching_the_peer() {
    let (world, owner, reader) = rig("enrolled");
    let helper = serve(&world.sock_dir(), honest(&world));
    std::fs::remove_file(world.trust_file()).unwrap();
    let error = refused(observe(
        &world,
        &reader,
        &owner,
        Resource::Daemon,
        ReadPoint::Launch,
    ));
    assert!(matches!(error, PlanReadError::Io { .. }), "{error}");
    assert_eq!(helper.accepted(), 0);
    assert_eq!(owner.locks.load(Ordering::SeqCst), 0);
}

#[test]
fn the_production_five_second_bound_is_the_default() {
    assert_eq!(READ_BOUND, Duration::from_secs(5));
}

#[test]
fn an_owner_snapshot_for_another_resource_is_refused_before_any_exchange() {
    let (world, owner, reader) = rig("enrolled");
    let helper = serve(&world.sock_dir(), honest(&world));
    owner.mutate(|s| s.snapshot_resource = Some(Resource::Authority));
    says(
        &refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "another resource",
    );
    assert_eq!(helper.accepted(), 0);
}

#[test]
fn the_original_owner_must_be_the_plans_registered_mapping_and_predecessor() {
    let world = World::new();
    let plan = &world.plan;
    let original = |resource, registered: &str, intrinsic: &str, pre: Proc| {
        OriginalOwner::new(resource, id(registered), id(intrinsic), pre, proc(77))
    };
    let snapshot = |original| OwnerSnapshot::new(&world.plan_bytes, original, ());
    let daemon = original(
        Resource::Daemon,
        "registered.test",
        "host.test",
        plan.pre_d.clone(),
    );
    assert!(snapshot(daemon).is_ok());
    let authority = original(
        Resource::Authority,
        "registered.test",
        "host.test",
        plan.pre_a.clone(),
    );
    assert!(snapshot(authority).is_ok());
    for (name, bad) in [
        (
            "alias",
            original(
                Resource::Daemon,
                "alias.test",
                "host.test",
                plan.pre_d.clone(),
            ),
        ),
        (
            "intrinsic",
            original(
                Resource::Daemon,
                "registered.test",
                "other.test",
                plan.pre_d.clone(),
            ),
        ),
        (
            "authority pre for the daemon",
            original(
                Resource::Daemon,
                "registered.test",
                "host.test",
                plan.pre_a.clone(),
            ),
        ),
        (
            "daemon pre for the authority",
            original(
                Resource::Authority,
                "registered.test",
                "host.test",
                plan.pre_d.clone(),
            ),
        ),
        (
            "another pre",
            original(Resource::Daemon, "registered.test", "host.test", proc(99)),
        ),
    ] {
        let error = refused(snapshot(bad));
        assert!(matches!(error, PlanReadError::Owner(_)), "{name}: {error}");
    }
}
