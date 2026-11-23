//! The peer's retained pidfd, its liveness around every probe, and the fail-closed path.
//!
//! This machine's kernel (6.1) has no SO_PEERPIDFD (Linux 6.5). Tests here that need only a
//! pidfd use the test-scoped opener in tests.rs; the one test that needs the real socket
//! option is ignored with that reason and is not replaced by a stand-in.

use super::super::wire::kernel_peer_pidfd;
use super::*;
use std::cell::Cell;
use std::ffi::CString;
use std::os::fd::OwnedFd;

/// A real process, forked before the test has any other thread work to protect, that listens
/// itself (so the kernel records it as the peer), replies once, closes the stream and waits to be released. After
/// fork it makes only async-signal-safe calls.
struct ListenerChild {
    pid: i32,
    release: i32,
}

fn spawn_listener(socket: &Path, reply: Vec<u8>) -> ListenerChild {
    let path = CString::new(socket.to_str().unwrap()).unwrap();
    let mut ready = [0 as libc::c_int; 2];
    let mut release = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            let listener = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let mut address: libc::sockaddr_un = std::mem::zeroed();
            address.sun_family = libc::AF_UNIX as _;
            for (slot, byte) in address.sun_path.iter_mut().zip(path.as_bytes()) {
                *slot = *byte as _;
            }
            let size = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            if libc::bind(
                listener,
                (&address as *const libc::sockaddr_un).cast(),
                size,
            ) != 0
                || libc::listen(listener, 1) != 0
            {
                libc::_exit(2);
            }
            libc::write(ready[1], b"r".as_ptr().cast(), 1);
            let connection = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
            let mut buffer = [0u8; 4096];
            libc::read(connection, buffer.as_mut_ptr().cast(), buffer.len());
            libc::write(connection, reply.as_ptr().cast(), reply.len());
            libc::close(connection);
            libc::read(release[0], buffer.as_mut_ptr().cast(), 1);
            libc::_exit(0);
        }
    }
    let mut byte = [0u8; 1];
    assert_eq!(
        unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), 1) },
        1
    );
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    ListenerChild {
        pid,
        release: release[1],
    }
}

impl ListenerChild {
    fn finish(self) {
        unsafe {
            libc::write(self.release, b"x".as_ptr().cast(), 1);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }

    fn helper(&self) -> EnrolledHelper {
        EnrolledHelper::new(
            TEST_HELPER_IMAGE,
            self.pid,
            kernel_start_ticks(self.pid).unwrap(),
            "test".to_string(),
        )
    }
}

thread_local!(static RELEASE: Cell<i32> = const { Cell::new(-1) });

/// On its second call the peer, alive until now, is released and exits during the probe: the
/// stat and executable are still perfectly readable, but only the pidfd says it is dead.
fn dying_probe(pid: i32) -> Result<ObservedHelper, PlanReadError> {
    thread_local!(static CALLS: Cell<usize> = const { Cell::new(0) });
    if CALLS.with(|calls| calls.replace(calls.get() + 1)) >= 1 {
        unsafe { libc::write(RELEASE.with(Cell::get), b"x".as_ptr().cast(), 1) };
        for _ in 0..2_500 {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            if stat.rsplit_once(") ").unwrap().1.starts_with('Z') {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    test_probe(pid)
}

#[test]
fn a_peer_that_died_after_replying_is_refused_though_its_stat_still_reads() {
    let world = World::new();
    let socket = world.sock_dir().join("plan-reader.sock");
    let child = spawn_listener(&socket, framed(b"reply"));
    RELEASE.with(|release| release.set(child.release));
    let endpoint = world.endpoint_with(own(), child.helper(), dying_probe);
    let outcome = endpoint.exchange(b"{}", Deadline::within(GENEROUS));
    unsafe { libc::waitpid(child.pid, std::ptr::null_mut(), 0) };
    says(&refused(outcome), "peer process has exited");
}

#[test]
fn a_live_peer_that_closed_its_stream_is_accepted() {
    let world = World::new();
    let socket = world.sock_dir().join("plan-reader.sock");
    let child = spawn_listener(&socket, framed(b"reply"));
    let endpoint = world.endpoint_with(own(), child.helper(), test_probe);
    let outcome = endpoint.exchange(b"{}", Deadline::within(GENEROUS));
    child.finish();
    assert_eq!(outcome.unwrap(), b"reply");
}

#[test]
fn every_enrolled_process_fact_must_equal_the_peers() {
    let own = own_helper();
    let cases = [
        (
            "pid",
            EnrolledHelper::new(
                own.executable,
                own.pid + 1,
                own.start_ticks,
                own.boot.clone(),
            ),
        ),
        (
            "start",
            EnrolledHelper::new(
                own.executable,
                own.pid,
                own.start_ticks + 1,
                own.boot.clone(),
            ),
        ),
        (
            "boot",
            EnrolledHelper::new(own.executable, own.pid, own.start_ticks, "other".into()),
        ),
        (
            "image",
            EnrolledHelper::new([0x55; 32], own.pid, own.start_ticks, own.boot.clone()),
        ),
    ];
    for (name, helper) in cases {
        let world = World::new();
        let served = serve(&world.sock_dir(), honest(&world));
        let reader = PlanReader::for_test(
            world.loader(),
            world.endpoint_with(super::own(), helper, test_probe),
        );
        let owner = SyntheticOwner::new(&world, "enrolled");
        let error = refused(observe(
            &world,
            &reader,
            &owner,
            Resource::Daemon,
            ReadPoint::Launch,
        ));
        assert!(
            error.to_string().contains("not the enrolled helper"),
            "{name}: {error}"
        );
        assert_eq!(owner.locks.load(Ordering::SeqCst), 0, "{name}");
        drop(served);
    }
}

fn pidfd_of_init(_stream: &OwnedFd, _peer: &PeerIdentity) -> Result<OwnedFd, PlanReadError> {
    use std::os::fd::FromRawFd;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, 1, 0) };
    assert!(raw >= 0);
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

#[test]
fn a_pidfd_for_another_process_is_not_proof_of_the_peer() {
    let world = World::new();
    let helper = serve(&world.sock_dir(), honest(&world));
    let endpoint = ReaderEndpoint::rooted_at(
        &world.sock_dir(),
        own(),
        own_helper().enrolled(),
        test_probe,
        pidfd_of_init,
    );
    let error = refused(endpoint.exchange(b"{}", Deadline::within(GENEROUS)));
    says(&error, "does not name the credentialed process");
    drop(helper);
}

#[test]
fn the_kernel_primitive_names_the_peer_or_the_read_fails_closed() {
    let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
    let left: OwnedFd = left.into();
    let peer = PeerIdentity::from_socket(std::os::fd::AsRawFd::as_raw_fd(&left)).unwrap();
    match kernel_peer_pidfd(&left, &peer) {
        Ok(pidfd) => {
            let pid = super::super::wire::pidfd_pid(&pidfd).unwrap();
            assert_eq!(pid, std::process::id() as i32);
        }
        Err(error) => assert!(
            error.to_string().contains("peer pidfd is unavailable"),
            "{error}"
        ),
    }
    let mut pipe = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let not_a_socket = unsafe { std::os::fd::FromRawFd::from_raw_fd(pipe[0]) };
    let _writer: OwnedFd = unsafe { std::os::fd::FromRawFd::from_raw_fd(pipe[1]) };
    says(
        &refused(kernel_peer_pidfd(&not_a_socket, &peer)),
        "peer pidfd is unavailable",
    );
}

#[test]
#[ignore = "needs SO_PEERPIDFD (Linux >= 6.5); this machine's 6.1 kernel lacks it, so it is not run here"]
fn a_real_kernel_peer_pidfd_exchange_completes() {
    let world = World::new();
    let _helper = serve(&world.sock_dir(), honest(&world));
    let endpoint = ReaderEndpoint::rooted_at(
        &world.sock_dir(),
        own(),
        own_helper().enrolled(),
        test_probe,
        kernel_peer_pidfd,
    );
    let owner = SyntheticOwner::new(&world, "enrolled");
    let reader = PlanReader::for_test(world.loader(), endpoint);
    observe(&world, &reader, &owner, Resource::Daemon, ReadPoint::Launch)
        .unwrap()
        .consume(|_, _| ())
        .unwrap();
}
