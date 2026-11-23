use super::profile;
use crate::execution::ordinary_key::*;
use nix::libc;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

fn memfd(bytes: &[u8], mode: u32, seals: libc::c_int) -> OwnedFd {
    let fd = unsafe {
        libc::memfd_create(
            c"synthetic-key".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .unwrap();
    if seals != 0 {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    }
    let readonly = File::open(format!("/proc/self/fd/{fd}")).unwrap();
    readonly.into()
}

fn sealed(bytes: &[u8]) -> OwnedFd {
    memfd(bytes, 0o400, SEALS)
}

#[test]
fn a_sealed_profile_error_carries_no_key_bytes() {
    let bytes = profile(9);
    let mut wrong = bytes.clone();
    wrong[60] ^= 1;
    let fd = sealed(&wrong);
    assert_eq!(read_sealed(fd.as_fd()).unwrap_err(), KeyError::Profile);
}

#[test]
fn sealed_read_is_offset_independent_and_does_not_move_the_offset() {
    let bytes = profile(11);
    let fd = sealed(&bytes);
    let mut file = File::from(fd.try_clone().unwrap());
    assert_eq!(file.seek(SeekFrom::Start(40)).unwrap(), 40);
    let key = read_sealed(fd.as_fd()).unwrap();
    assert_eq!(key.public().as_slice(), &bytes[51..]);
    assert_eq!(file.stream_position().unwrap(), 40);
    assert!(read_sealed(fd.as_fd()).is_ok());
    let mut rest = Vec::new();
    file.read_to_end(&mut rest).unwrap();
    assert_eq!(rest.len(), PKCS8_BYTES - 40);
}

#[test]
fn sealed_metadata_requires_the_exact_immutable_read_only_memfd() {
    let bytes = profile(12);
    assert!(check_sealed(sealed(&bytes).as_fd()).is_ok());
    for mode in [0o600, 0o440, 0o444, 0o500, 0o4400] {
        let fd = memfd(&bytes, mode, SEALS);
        assert_eq!(
            check_sealed(fd.as_fd()).unwrap_err(),
            KeyError::Metadata,
            "{mode:o}"
        );
    }
    for missing in [
        libc::F_SEAL_WRITE,
        libc::F_SEAL_GROW,
        libc::F_SEAL_SHRINK,
        libc::F_SEAL_SEAL,
    ] {
        let fd = memfd(&bytes, 0o400, SEALS & !missing);
        assert_eq!(check_sealed(fd.as_fd()).unwrap_err(), KeyError::Metadata);
    }
    assert!(check_sealed(memfd(&bytes, 0o400, 0).as_fd()).is_err());
    for wrong in [&bytes[..82], &[bytes.as_slice(), &[0]].concat()[..]] {
        let fd = sealed(wrong);
        assert_eq!(check_sealed(fd.as_fd()).unwrap_err(), KeyError::Metadata);
        assert!(read_sealed(fd.as_fd()).is_err());
    }
    let writable = unsafe {
        libc::memfd_create(
            c"writable".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    let writable = unsafe { OwnedFd::from_raw_fd(writable) };
    File::from(writable.try_clone().unwrap())
        .write_all(&bytes)
        .unwrap();
    File::from(writable.try_clone().unwrap())
        .set_permissions(std::fs::Permissions::from_mode(0o400))
        .unwrap();
    assert_eq!(
        unsafe { libc::fcntl(writable.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
        0
    );
    assert_eq!(
        check_sealed(writable.as_fd()).unwrap_err(),
        KeyError::Metadata
    );
    let mut path = tempfile::NamedTempFile::new().unwrap();
    path.write_all(&bytes).unwrap();
    path.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o400))
        .unwrap();
    let on_disk = File::open(path.path()).unwrap();
    assert_eq!(
        check_sealed(on_disk.as_fd()).unwrap_err(),
        KeyError::Metadata
    );
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        check_sealed(socket.as_fd()).unwrap_err(),
        KeyError::Metadata
    );
}

#[test]
fn claim_sets_cloexec_first_and_closes_only_the_descriptor_it_was_given() {
    let bytes = profile(13);
    let fd = sealed(&bytes);
    assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    let raw = fd.as_raw_fd();
    let claimed = SealedKeyFd::claim(fd, &[]).unwrap();
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, libc::FD_CLOEXEC);
    assert!(claimed.read().is_ok());
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "closed after the read"
    );

    let fd = sealed(&bytes);
    let raw = fd.as_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(fd, &[raw]).err(),
        Some(KeyError::Descriptor)
    );
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "the given descriptor is closed on refusal"
    );

    let fd = sealed(&bytes);
    let alias = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 500) };
    assert!(alias >= 500);
    let alias = unsafe { OwnedFd::from_raw_fd(alias) };
    let raw = fd.as_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(fd, &[alias.as_raw_fd(), alias.as_raw_fd()]).err(),
        Some(KeyError::Descriptor),
        "same open file under another slot"
    );
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "claimed slot closed on refusal"
    );
    assert_ne!(
        unsafe { libc::fcntl(alias.as_raw_fd(), libc::F_GETFD) },
        -1,
        "the other artifact's slot stays open"
    );

    let wrong = memfd(&bytes, 0o600, SEALS);
    let raw = wrong.as_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(wrong, &[]).err(),
        Some(KeyError::Metadata)
    );
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);

    let mut other = bytes.clone();
    other[60] ^= 1;
    let wrong_key = memfd(&other, 0o400, SEALS);
    let raw = wrong_key.as_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(wrong_key, &[]).unwrap().read().err(),
        Some(KeyError::Profile)
    );
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
}

#[test]
fn a_slot_number_reused_after_a_claim_is_not_closed_by_any_leftover_owner() {
    let owner = sealed(&profile(16));
    let high = unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 50_000) };
    assert!(high >= 50_000);
    drop(owner);
    let owned = unsafe { OwnedFd::from_raw_fd(high) };
    let raw = owned.as_raw_fd();
    SealedKeyFd::claim(owned, &[]).unwrap().read().unwrap();
    let replacement = sealed(&profile(17));
    let reused = unsafe { libc::fcntl(replacement.as_raw_fd(), libc::F_DUPFD_CLOEXEC, raw) };
    assert_eq!(reused, raw, "the freed slot number is reused");
    drop(replacement);
    assert_ne!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "no owner is left to close the replacement"
    );
    drop(unsafe { OwnedFd::from_raw_fd(raw) });
}

#[test]
fn an_inherited_slot_is_cloexec_after_the_claim_so_no_later_process_receives_it() {
    let bytes = profile(14);
    let fd = sealed(&bytes);
    assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    let raw = fd.as_raw_fd();
    let present = |raw| {
        Command::new("/bin/sh")
            .args(["-c", &format!("test -e /proc/self/fd/{raw}")])
            .status()
            .unwrap()
            .success()
    };
    assert!(
        present(raw),
        "fixture proves an inheritable slot does cross exec"
    );
    let claimed = SealedKeyFd::claim(fd, &[]).unwrap();
    assert!(!present(raw), "claimed slot must not reach a helper");
    drop(claimed);
}

#[test]
fn inherited_value_is_one_canonical_decimal_at_any_actual_slot() {
    let bytes = profile(15);
    assert_eq!(
        unsafe { adopt_inherited(None, &[]) }.unwrap_err(),
        KeyError::Descriptor
    );
    let stdio = [0, 1, 2].map(|raw| unsafe { libc::fcntl(raw, libc::F_GETFD) });
    for value in [
        "",
        " 15",
        "15 ",
        "015",
        "+15",
        "-15",
        "0x0f",
        "1e3",
        "15\n",
        "0",
        "1",
        "2",
        "99999",
        "99999999999999999999",
        "٣",
    ] {
        assert_eq!(
            unsafe { adopt_inherited(Some(value), &[]) }.unwrap_err(),
            KeyError::Descriptor,
            "{value:?}"
        );
    }
    assert_eq!(
        [0, 1, 2].map(|raw| unsafe { libc::fcntl(raw, libc::F_GETFD) }),
        stdio,
        "a refused standard descriptor is not closed"
    );
    let fd = sealed(&bytes);
    let high = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 40_000) };
    assert!(high >= 40_000);
    drop(fd);
    assert_ne!(high, 15 + 32768, "an arbitrary slot, not base plus index");
    let key = unsafe { adopt_inherited(Some(&high.to_string()), &[]) }.unwrap();
    assert_eq!(key.public().as_slice(), &bytes[51..]);
    assert_eq!(unsafe { libc::fcntl(high, libc::F_GETFD) }, -1);
}

#[test]
fn adopting_refuses_another_artifacts_slot_before_any_owner_exists() {
    let bytes = profile(18);
    let fd = sealed(&bytes);
    let raw = fd.as_raw_fd();
    assert_eq!(
        unsafe { adopt_inherited(Some(&raw.to_string()), &[3, raw, raw]) }.err(),
        Some(KeyError::Descriptor)
    );
    assert_ne!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "another artifact's slot stays open"
    );
    drop(fd);

    let fd = sealed(&bytes);
    let alias = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 500) };
    assert!(alias >= 500);
    let alias = unsafe { OwnedFd::from_raw_fd(alias) };
    let raw = fd.into_raw_fd();
    assert_eq!(
        unsafe { adopt_inherited(Some(&raw.to_string()), &[alias.as_raw_fd()]) }.err(),
        Some(KeyError::Descriptor),
        "same open file under another slot"
    );
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "the adopted slot, which the claim owned, is closed"
    );
}
