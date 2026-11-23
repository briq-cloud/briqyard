use super::*;
use std::os::unix::fs::symlink;

fn run(world: &World, behave: impl Fn(&[u8]) -> Reply + Send + 'static) -> PlanReadError {
    let _helper = serve(&world.sock_dir(), behave);
    let owner = SyntheticOwner::new(world, "enrolled");
    refused(observe(
        world,
        &world.reader(),
        &owner,
        Resource::Daemon,
        ReadPoint::Launch,
    ))
}

fn valid(local: &LocalPlan, request: &[u8]) -> Vec<u8> {
    honest_pair(&decode::<Read>(request).unwrap(), local)
}

#[test]
fn frames_are_big_endian_length_then_exactly_that_payload() {
    assert_eq!(
        encode_frame(b"abc").unwrap(),
        [0, 0, 0, 3, b'a', b'b', b'c']
    );
    assert_eq!(encode_frame(&[7; 65536]).unwrap().len(), 4 + 65536);
    assert_eq!(&encode_frame(&[7; 65536]).unwrap()[..4], [0, 1, 0, 0]);
    assert!(matches!(encode_frame(b""), Err(PlanReadError::Frame(_))));
    assert!(matches!(
        encode_frame(&[7; 65537]),
        Err(PlanReadError::Frame(_))
    ));
}

#[test]
fn the_fixed_socket_is_the_one_contract_path() {
    assert_eq!(SOCKET_PATH, "/run/briqyard-sealed/plan-reader.sock");
    assert!(Deadline::start().remaining("start").unwrap() <= Duration::from_secs(5));
    if unsafe { libc::geteuid() } != 0 {
        says(
            &refused(ReaderEndpoint::fixed(own_helper().enrolled())),
            "only root",
        );
    }
}

#[test]
fn the_reader_sends_one_canonical_fresh_read_per_exchange() {
    let world = World::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let local = world.local();
    let _helper = serve(&world.sock_dir(), move |request| {
        let read: Read = decode(request).unwrap();
        assert_eq!(encode(&read).unwrap(), request);
        log.lock().unwrap().push(read.clone());
        Reply::Send(framed(&honest_pair(&read, &local)))
    });
    let reader = world.reader();
    let owner = SyntheticOwner::new(&world, "enrolled");
    drop(observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch).unwrap());
    drop(observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch).unwrap());
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0].nonce, seen[1].nonce);
    assert!(seen.iter().all(|read| read.nonce.as_array() != &[0; 32]));
    assert!(seen.iter().all(|read| read.x == world.plan.x));
}

#[test]
fn a_short_frame_is_refused() {
    let world = World::new();
    let local = world.local();
    let error = run(&world, move |request| {
        let mut bytes = framed(&valid(&local, request));
        bytes.truncate(bytes.len() / 2);
        Reply::Send(bytes)
    });
    says(&error, "ended before its frame");
}

#[test]
fn bytes_after_the_frame_are_refused() {
    let world = World::new();
    let local = world.local();
    let error = run(&world, move |request| {
        let mut bytes = framed(&valid(&local, request));
        bytes.push(b'x');
        Reply::Send(bytes)
    });
    says(&error, "bytes follow the reply frame");
}

#[test]
fn a_second_frame_is_refused() {
    let world = World::new();
    let local = world.local();
    let error = run(&world, move |request| {
        let one = framed(&valid(&local, request));
        Reply::Send([one.clone(), one].concat())
    });
    says(&error, "bytes follow the reply frame");
}

#[test]
fn an_open_stream_after_the_frame_is_not_a_complete_exchange() {
    let world = World::new();
    let local = world.local();
    let _helper = serve(&world.sock_dir(), move |request| {
        Reply::SendThenHold(framed(&valid(&local, request)))
    });
    let owner = SyntheticOwner::new(&world, "enrolled");
    let error = refused(world.reader().observe_within(
        &*owner,
        &world.scope(Resource::Daemon, ReadPoint::Launch),
        Deadline::within(Duration::from_secs(4)),
    ));
    assert!(matches!(error, PlanReadError::Deadline { .. }), "{error}");
}

#[test]
fn zero_oversize_and_missing_lengths_are_refused() {
    for header in [0u32, 65_537, u32::MAX] {
        let world = World::new();
        let error = run(&world, move |_| Reply::Send(header.to_be_bytes().to_vec()));
        says(&error, "reply length is outside 1..65536");
    }
    let world = World::new();
    says(
        &run(&world, |_| Reply::Send(Vec::new())),
        "ended before its frame",
    );
    let world = World::new();
    says(
        &run(&world, |_| Reply::Send(vec![0, 0])),
        "ended before its frame",
    );
}

#[test]
fn a_silent_peer_is_bounded_by_the_deadline() {
    let world = World::new();
    let _helper = serve(&world.sock_dir(), |_| Reply::Silent);
    let owner = SyntheticOwner::new(&world, "enrolled");
    let started = std::time::Instant::now();
    let error = refused(world.reader().observe_within(
        &*owner,
        &world.scope(Resource::Daemon, ReadPoint::Launch),
        Deadline::within(Duration::from_secs(4)),
    ));
    assert!(matches!(error, PlanReadError::Deadline { .. }), "{error}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(owner.locks.load(Ordering::SeqCst), 0);
}

#[test]
fn an_attached_descriptor_is_refused() {
    let world = World::new();
    let local = world.local();
    let error = run(&world, move |request| {
        Reply::Fds(1, framed(&valid(&local, request)))
    });
    says(&error, "ancillary data");
}

#[test]
fn an_already_expired_read_never_connects() {
    let world = World::new();
    let helper = serve(&world.sock_dir(), honest(&world));
    let owner = SyntheticOwner::new(&world, "enrolled");
    let error = refused(world.reader().observe_within(
        &*owner,
        &world.scope(Resource::Daemon, ReadPoint::Launch),
        Deadline::within(Duration::ZERO),
    ));
    assert!(matches!(error, PlanReadError::Deadline { .. }), "{error}");
    assert_eq!(helper.accepted(), 0);
}

#[test]
fn a_peer_that_is_not_the_enrolled_helper_is_refused() {
    let world = World::new();
    let helper = serve(&world.sock_dir(), honest(&world));
    let owner = SyntheticOwner::new(&world, "enrolled");
    let reader = PlanReader::for_test(world.loader(), world.endpoint_for(own(), [0x55; 32]));
    let error = refused(observe(
        &world,
        &reader,
        &owner,
        Resource::Daemon,
        ReadPoint::Launch,
    ));
    says(&error, "not the enrolled helper");
    drop(helper);
    assert_eq!(owner.locks.load(Ordering::SeqCst), 0);
}

#[test]
fn a_peer_with_another_owner_is_refused() {
    let world = World::new();
    let _helper = serve(&world.sock_dir(), honest(&world));
    let owner = SyntheticOwner::new(&world, "enrolled");
    let foreign = Ownership {
        uid: own().uid + 1,
        gid: own().gid,
    };
    let reader = PlanReader::for_test(
        world.loader(),
        world.endpoint_for(foreign, TEST_HELPER_IMAGE),
    );
    let error = refused(observe(
        &world,
        &reader,
        &owner,
        Resource::Daemon,
        ReadPoint::Launch,
    ));
    assert!(matches!(error, PlanReadError::Peer(_)), "{error}");
}

#[test]
fn the_socket_must_be_a_private_socket_node() {
    let world = World::new();
    let helper = serve(&world.sock_dir(), honest(&world));
    let owner = SyntheticOwner::new(&world, "enrolled");
    let socket = world.sock_dir().join("plan-reader.sock");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    let reader = world.reader();
    says(
        &refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "not a private socket",
    );
    drop(helper);
    assert_eq!(owner.locks.load(Ordering::SeqCst), 0);

    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, b"not a socket").unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    says(
        &refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "not a private socket",
    );
}

#[test]
fn a_symlinked_socket_is_not_followed() {
    let world = World::new();
    let real_dir = world.dir.path().join("real");
    mkdir_private(&real_dir);
    let _helper = serve(&real_dir, honest(&world));
    symlink(
        real_dir.join("plan-reader.sock"),
        world.sock_dir().join("plan-reader.sock"),
    )
    .unwrap();
    let owner = SyntheticOwner::new(&world, "enrolled");
    says(
        &refused(observe(
            &world,
            &world.reader(),
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "not a private socket",
    );
}

#[test]
fn a_writable_socket_directory_is_refused() {
    let world = World::new();
    let helper = serve(&world.sock_dir(), honest(&world));
    std::fs::set_permissions(world.sock_dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
    let owner = SyntheticOwner::new(&world, "enrolled");
    says(
        &refused(observe(
            &world,
            &world.reader(),
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "foreign or writable",
    );
    assert_eq!(helper.accepted(), 0);
}

#[test]
fn a_missing_listener_fails_closed() {
    let world = World::new();
    let owner = SyntheticOwner::new(&world, "enrolled");
    let error = refused(observe(
        &world,
        &world.reader(),
        &owner,
        Resource::Daemon,
        ReadPoint::Launch,
    ));
    assert!(matches!(error, PlanReadError::Io { .. }), "{error}");
}

fn restarting_probe(pid: i32) -> Result<ObservedHelper, PlanReadError> {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let mut observed = test_probe(pid)?;
    observed.start_ticks += CALLS.fetch_add(1, Ordering::SeqCst) as u64;
    Ok(observed)
}

#[test]
fn a_helper_whose_start_differs_from_the_enrolled_one_is_refused() {
    let world = World::new();
    let _helper = serve(&world.sock_dir(), honest(&world));
    let endpoint = world.endpoint_with(own(), own_helper().enrolled(), restarting_probe);
    let reader = PlanReader::for_test(world.loader(), endpoint);
    let owner = SyntheticOwner::new(&world, "enrolled");
    says(
        &refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        )),
        "not the enrolled helper",
    );
    assert_eq!(owner.locks.load(Ordering::SeqCst), 0);
}
