use super::super::fd::compare_with;
use super::super::{
    compare_open_descriptions, CandidatePidFd, Comparison, CustodyError, DescriptorFloor,
    OriginalPidFd, StageDeadline,
};
use super::{raw_pidfd, ChildGuard};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

#[test]
fn independently_opened_pidfd_is_never_a_same_description_match() {
    let child = ChildGuard::sleep();
    let original = raw_pidfd(child.pid());
    let independent = raw_pidfd(child.pid());
    let result = compare_with(
        original.as_raw_fd(),
        independent.as_raw_fd(),
        |original, independent| {
            let value = unsafe {
                libc::syscall(
                    libc::SYS_kcmp,
                    libc::getpid(),
                    libc::getpid(),
                    0,
                    original,
                    independent,
                )
            };
            if value < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(value as i32)
            }
        },
    );
    match result {
        Ok(Comparison::DifferentOpenFileDescription { .. }) => {}
        Err(CustodyError::Unsupported { .. } | CustodyError::PermissionDenied { .. }) => {
            eprintln!("KCMP_FILE nonidentity unavailable: {result:?}");
        }
        other => panic!("independent pidfd unexpectedly qualified: {other:?}"),
    }
}

#[test]
fn kcmp_zero_is_the_only_positive_result() {
    assert_eq!(
        compare_with(10, 11, |_, _| Ok(0)).unwrap(),
        Comparison::SameOpenFileDescription
    );
    assert!(matches!(
        compare_with(10, 11, |_, _| Ok(1)).unwrap(),
        Comparison::DifferentOpenFileDescription { ordering: 1 }
    ));
    for errno in [libc::EPERM, libc::ENOSYS, libc::EBADF] {
        assert!(compare_with(10, 11, move |_, _| {
            Err(std::io::Error::from_raw_os_error(errno))
        })
        .is_err());
    }
}

#[test]
fn non_root_custodian_cannot_claim_a_positive_comparison() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let fd = raw_pidfd(std::process::id() as i32);
    let duplicate = fd.as_fd().try_clone_to_owned().unwrap();
    let floor = DescriptorFloor::preserving(&[]).unwrap();
    let original = OriginalPidFd::from_owned(fd);
    let candidate = CandidatePidFd::from_owned(duplicate, &floor).unwrap();
    assert!(matches!(
        compare_open_descriptions(&original, &candidate),
        Err(CustodyError::PermissionDenied { .. })
    ));
}

#[test]
fn relocation_preserves_listener_and_source_open_description() {
    let (mut listener, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let floor = DescriptorFloor::preserving(&[3, listener.as_raw_fd()]).unwrap();
    let source = raw_pidfd(std::process::id() as i32);
    let source_owner = source.as_fd().try_clone_to_owned().unwrap();
    let relocated = floor.relocate(source).unwrap();
    assert!(relocated.as_raw_fd() > listener.as_raw_fd());
    assert!(relocated.as_raw_fd() > 3);
    assert!(unsafe { libc::fcntl(relocated.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
    assert!(unsafe { libc::fcntl(source_owner.as_raw_fd(), libc::F_GETFD) } >= 0);
    writer.write_all(b"still the original listener").unwrap();
    let mut bytes = [0; 27];
    listener.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"still the original listener");
}

#[test]
fn unsupported_rlimit_is_reported_without_raising_it() {
    let before = unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
        limit
    };
    let minimum = if before.rlim_cur == libc::RLIM_INFINITY {
        i32::MAX
    } else {
        before.rlim_cur as i32
    };
    let result = DescriptorFloor::preserving(&[minimum]);
    assert!(matches!(result, Err(CustodyError::DescriptorLimit { .. })));
    let after = unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
        limit
    };
    assert_eq!(before.rlim_cur, after.rlim_cur);
    assert_eq!(before.rlim_max, after.rlim_max);
}

#[test]
fn candidate_poll_requires_actual_pollin_not_liveness_inference() {
    let child = ChildGuard::sleep();
    let floor = DescriptorFloor::preserving(&[]).unwrap();
    let candidate = CandidatePidFd::from_owned(raw_pidfd(child.pid()), &floor).unwrap();
    assert!(candidate.poll_exited().unwrap().is_none());
    assert!(matches!(
        candidate.wait_exited(StageDeadline::short("live child")),
        Err(CustodyError::Deadline { .. })
    ));
    child.kill();
    let deadline = StageDeadline::exit("child exit", Duration::from_secs(2)).unwrap();
    assert!(candidate.wait_exited(deadline).is_ok());
    assert!(candidate.poll_exited().unwrap().is_some());
}

#[test]
#[ignore = "root qualification: requires a kernel implementing KCMP_FILE and real pidfds"]
fn root_positive_same_description_and_independent_negative_after_exit() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run this qualification as root"
    );
    let child = ChildGuard::sleep();
    let floor = DescriptorFloor::preserving(&[]).unwrap();
    let original = OriginalPidFd::from_owned(raw_pidfd(child.pid()));
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(original.as_raw_fd()) };
    let same = CandidatePidFd::from_owned(borrowed.try_clone_to_owned().unwrap(), &floor).unwrap();
    assert_eq!(
        compare_open_descriptions(&original, &same).unwrap(),
        Comparison::SameOpenFileDescription
    );
    let independent = CandidatePidFd::from_owned(raw_pidfd(child.pid()), &floor).unwrap();
    assert!(matches!(
        compare_open_descriptions(&original, &independent).unwrap(),
        Comparison::DifferentOpenFileDescription { .. }
    ));
    child.kill();
    assert!(original.poll_exited().unwrap().is_some());
    assert!(independent.poll_exited().unwrap().is_some());
    assert!(matches!(
        compare_open_descriptions(&original, &independent).unwrap(),
        Comparison::DifferentOpenFileDescription { .. }
    ));
}

#[test]
fn exited_pidfd_cannot_be_independently_reopened() {
    let child = ChildGuard::sleep();
    let pid = child.pid();
    child.kill();
    let error = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert_eq!(error, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}
