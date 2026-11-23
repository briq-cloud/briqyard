use super::super::fd::compare_with;
use super::super::{
    Comparison, CustodianExchange, CustodianProcess, CustodyError, DescriptorFloor, OriginalPidFd,
    PacketListener, StageDeadline,
};
use super::{raw_pidfd, ChildGuard};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

const ROOT_OPT_IN: &str = "BRIQYARD_CUSTODY_TEST_REAL_UID";
const HELPER: &str = "BRIQYARD_CUSTODY_TEST_HELPER";
const NOBODY: u32 = 65_534;
const TWO_SECONDS: Duration = Duration::from_secs(2);

#[test]
#[ignore = "explicit root environment fixture: BRIQYARD_CUSTODY_TEST_REAL_UID=1"]
fn two_process_real_uid_transfer_return_and_independent_exit_poll() {
    assert_eq!(std::env::var(ROOT_OPT_IN).as_deref(), Ok("1"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let helper = std::env::var_os(HELPER).expect("built execution-custody-child path");
    let expect_unavailable = kernel_positive_is_unavailable();
    let predecessor = ChildGuard::sleep();
    let original = CustodianProcess::open_live(predecessor.pid()).unwrap();
    let retained_for_negative_poll = duplicate_original(original.descriptor());

    let path = std::env::temp_dir().join(format!(
        "briqyard-custody-real-uid-{}-{}.sock",
        std::process::id(),
        predecessor.pid()
    ));
    let listener = PacketListener::bind(&path).unwrap();
    nix::unistd::chown(
        &path,
        Some(nix::unistd::Uid::from_raw(NOBODY)),
        Some(nix::unistd::Gid::from_raw(NOBODY)),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut candidate = ChildGuard::spawn(
        Command::new(helper)
            .arg(&path)
            .arg(std::process::id().to_string())
            .arg(if expect_unavailable { "1" } else { "0" })
            .uid(NOBODY)
            .gid(NOBODY)
            .stdin(std::process::Stdio::piped()),
    );
    let expected_candidate = CustodianProcess::identify_peer(candidate.pid()).unwrap();
    candidate.release_stdin();
    let floor = DescriptorFloor::preserving(&[]).unwrap();
    let mut custodian = CustodianExchange::accept_one(
        listener,
        original,
        NOBODY,
        expected_candidate.clone(),
        floor,
        StageDeadline::frame("real UID accept"),
    )
    .unwrap();
    let peer = custodian.peer_identity().unwrap();
    assert_eq!(peer.uid(), NOBODY);
    assert!(peer
        .verify_candidate(NOBODY + 1, &expected_candidate)
        .is_err());

    let request = custodian
        .receive_request(StageDeadline::frame("real UID request"), |bytes| {
            assert_eq!(bytes, b"opaque-request");
            Ok(())
        })
        .unwrap();
    assert_eq!(request, b"opaque-request");
    custodian
        .send_handle(b"opaque-handle", StageDeadline::frame("real UID handle"))
        .unwrap();
    let comparison =
        custodian.receive_echo_and_compare(StageDeadline::frame("real UID echo"), |bytes| {
            assert_eq!(bytes, b"opaque-echo");
            Ok(())
        });

    if expect_unavailable {
        let error = comparison.unwrap_err();
        assert!(matches!(
            error,
            CustodyError::Unsupported { .. } | CustodyError::PermissionDenied { .. }
        ));
        eprintln!("real UID KCMP_FILE unavailable after verified echo: {error}");
        drop(custodian);
        predecessor.kill();
        retained_for_negative_poll
            .wait_exited(StageDeadline::exit("real UID root negative exit", TWO_SECONDS).unwrap())
            .unwrap();
        let output = candidate.wait_bounded();
        assert!(output.status.success(), "candidate failed: {output:?}");
        eprintln!(
            "real UID request/handle/echo verified; root and UID {NOBODY} independently polled exit"
        );
        return;
    }

    comparison.unwrap();
    custodian
        .send_matched(b"opaque-matched", StageDeadline::frame("real UID matched"))
        .unwrap();
    predecessor.kill();
    custodian
        .wait_for_original_exit(StageDeadline::exit("real UID original exit", TWO_SECONDS).unwrap())
        .unwrap();
    let completion = custodian
        .send_exited(b"opaque-exited", StageDeadline::frame("real UID exited"))
        .unwrap();
    assert!(completion.predecessor().descriptor().as_raw_fd() >= 0);
    assert_eq!(completion.matched(), b"opaque-matched");
    assert_eq!(completion.exited(), b"opaque-exited");
    let output = candidate.wait_bounded();
    assert!(output.status.success(), "candidate failed: {output:?}");
}

fn duplicate_original(original: &OriginalPidFd) -> OriginalPidFd {
    let fd = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(fd >= 0);
    OriginalPidFd::from_owned(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn kernel_positive_is_unavailable() -> bool {
    let original = raw_pidfd(std::process::id() as i32);
    let duplicate = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(duplicate >= 0);
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let result = compare_with(original.as_raw_fd(), duplicate.as_raw_fd(), |a, b| {
        let value =
            unsafe { libc::syscall(libc::SYS_kcmp, libc::getpid(), libc::getpid(), 0, a, b) };
        if value < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(value as i32)
        }
    });
    match result {
        Ok(Comparison::SameOpenFileDescription) => false,
        Err(CustodyError::Unsupported { .. } | CustodyError::PermissionDenied { .. }) => true,
        other => panic!("invalid same-description qualification preflight: {other:?}"),
    }
}
