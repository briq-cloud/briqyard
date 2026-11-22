use super::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

fn profile(seed: u8) -> Vec<u8> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let mut bytes = hex::decode("3051020101300506032b657004220420").unwrap();
    bytes.extend([seed; 32]);
    bytes.extend([0x81, 0x21, 0x00]);
    bytes.extend(pair.public_key().as_ref());
    assert_eq!(bytes.len(), PKCS8_BYTES);
    bytes
}

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
fn profile_accepts_exactly_the_canonical_83_byte_v2_form_and_derives_the_public_key() {
    let bytes = profile(7);
    let key = OrdinaryAuthorityKey::from_profile(&bytes).unwrap();
    assert_eq!(key.public().as_slice(), &bytes[51..]);
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    assert_eq!(key.public().as_slice(), pair.public_key().as_ref());
    assert_eq!(format!("{key:?}"), "OrdinaryAuthorityKey(..)");
}

#[test]
fn profile_rejects_every_alternate_or_inconsistent_encoding() {
    let good = profile(7);
    let other = profile(8);
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("seed only", good[16..48].to_vec()),
        ("truncated", good[..82].to_vec()),
        ("trailing byte", [good.clone(), vec![0]].concat()),
        (
            "pem",
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_vec(),
        ),
        (
            "v1 without public",
            [&good[..2], &[0x2e], &good[3..5], &[0], &good[6..48]].concat(),
        ),
        (
            "public of another key",
            [&good[..51], &other[51..]].concat(),
        ),
        ("seed of another key", [&other[..48], &good[48..]].concat()),
    ];
    let mut flipped = good.clone();
    flipped[60] ^= 1;
    cases.push(("flipped embedded public", flipped));
    for index in 0..48 {
        let mut altered = good.clone();
        if index >= 16 {
            continue;
        }
        altered[index] ^= 1;
        cases.push(("altered fixed prefix", altered));
    }
    for index in 48..51 {
        let mut altered = good.clone();
        altered[index] ^= 1;
        cases.push(("altered public wrapper", altered));
    }
    let mut constructed = good[..48].to_vec();
    constructed[1] = 0x53;
    constructed.extend([0xa1, 0x23, 0x03, 0x21, 0x00]);
    constructed.extend(&good[51..]);
    cases.push(("ring legacy constructed public form", constructed));
    let mut encrypted = vec![0x30, 0x81, 0x80, 0x30, 0x1b];
    encrypted.extend(&good[5..]);
    cases.push(("encrypted-looking container", encrypted));
    for (name, bytes) in cases {
        assert_eq!(
            OrdinaryAuthorityKey::from_profile(&bytes).unwrap_err(),
            KeyError::Profile,
            "{name}"
        );
    }
}

#[test]
fn errors_carry_what_failed_and_never_key_bytes() {
    let bytes = profile(9);
    let mut wrong = bytes.clone();
    wrong[60] ^= 1;
    let error = OrdinaryAuthorityKey::from_profile(&wrong).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains(&hex::encode(&bytes[16..48])));
    assert!(!text.contains(&hex::encode(&bytes[51..])));
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
fn claim_sets_cloexec_first_and_refuses_unknown_or_aliased_slots_closing_its_own() {
    let bytes = profile(13);
    let fd = sealed(&bytes);
    assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    let raw = fd.into_raw_fd();
    let claimed = SealedKeyFd::claim(raw, &[]).unwrap();
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, libc::FD_CLOEXEC);
    assert!(claimed.read().is_ok());
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "closed after the read"
    );

    for refused in [0, 1, 2, -1, 99_999] {
        assert_eq!(
            SealedKeyFd::claim(refused, &[]).err(),
            Some(KeyError::Descriptor),
            "{refused}"
        );
    }

    let fd = sealed(&bytes);
    let raw = fd.into_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(raw, &[raw]).err(),
        Some(KeyError::Descriptor)
    );
    assert_ne!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "another artifact's slot stays open"
    );
    drop(unsafe { OwnedFd::from_raw_fd(raw) });

    let fd = sealed(&bytes);
    let alias = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 500) };
    assert!(alias >= 500);
    let alias = unsafe { OwnedFd::from_raw_fd(alias) };
    let raw = fd.into_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(raw, &[alias.as_raw_fd()]).err(),
        Some(KeyError::Descriptor),
        "same open file under another slot"
    );
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        -1,
        "claimed slot closed on refusal"
    );

    let wrong = memfd(&bytes, 0o600, SEALS);
    let raw = wrong.into_raw_fd();
    assert_eq!(SealedKeyFd::claim(raw, &[]).err(), Some(KeyError::Metadata));
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);

    let wrong_key = memfd(
        &{
            let mut b = bytes.clone();
            b[60] ^= 1;
            b
        },
        0o400,
        SEALS,
    );
    let raw = wrong_key.into_raw_fd();
    assert_eq!(
        SealedKeyFd::claim(raw, &[]).unwrap().read().err(),
        Some(KeyError::Profile)
    );
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
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
    let claimed = SealedKeyFd::claim(raw, &[]).unwrap();
    std::mem::forget(fd);
    assert!(!present(raw), "claimed slot must not reach a helper");
    drop(claimed);
}

#[test]
fn inherited_value_is_one_canonical_decimal_at_any_actual_slot() {
    let bytes = profile(15);
    assert_eq!(
        adopt_inherited(None, &[]).unwrap_err(),
        KeyError::Descriptor
    );
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
        "2",
        "99999999999999999999",
        "٣",
    ] {
        assert_eq!(
            adopt_inherited(Some(value), &[]).unwrap_err(),
            KeyError::Descriptor,
            "{value:?}"
        );
    }
    let fd = sealed(&bytes);
    let high = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 40_000) };
    assert!(high >= 40_000);
    drop(fd);
    assert_ne!(high, 15 + 32768, "an arbitrary slot, not base plus index");
    let key = adopt_inherited(Some(&high.to_string()), &[]).unwrap();
    assert_eq!(key.public().as_slice(), &bytes[51..]);
    assert_eq!(unsafe { libc::fcntl(high, libc::F_GETFD) }, -1);
}
