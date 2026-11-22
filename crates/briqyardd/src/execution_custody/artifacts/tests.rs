mod native_image;

use super::*;
use native_image::native_image;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{fs::PermissionsExt, net::UnixStream, process::CommandExt};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const FIXTURE_MODE: &str = "BRIQ_TEST_NATIVE_ASSETS";
const CHILD_TEST: &str = "execution_custody::artifacts::tests::native_asset_child";
const END: &[u8] = b"synthetic post-exec marker\n";

fn source(bytes: &[u8]) -> (tempfile::NamedTempFile, File) {
    let mut temporary = tempfile::NamedTempFile::new().unwrap();
    temporary.write_all(bytes).unwrap();
    let file = File::open(temporary.path()).unwrap();
    (temporary, file)
}

#[test]
fn prepare_is_exact_and_has_no_slot_field() {
    assert_eq!(prepare_packet(), br#"{"format":"native.prepare/v1"}"#);
    assert!(check_prepare(prepare_packet()).is_ok());
    for wrong in [
        br#"{"format":"native.prepare/v1","slot":32768}"#.as_slice(),
        br#"{"format":"native.prepare/v1","format":"native.prepare/v1"}"#,
        b"{\"format\":\"native.prepare/v1\"}\n",
        br#"{"format":"native.assets/v1"}"#,
    ] {
        assert!(check_prepare(wrong).is_err());
    }
}

#[test]
fn exact_snapshot_requires_size_digest_and_a_trusted_read_only_source() {
    let bytes = b"only synthetic immutable fixture data";
    let (_temporary, source) = source(bytes);
    let uid = unsafe { libc::geteuid() };
    let digest = HexDigest::of(bytes);
    let deadline = StageDeadline::frame("artifact test");
    let frozen = FrozenArtifact::freeze(
        &source,
        uid,
        Class::Plan,
        bytes.len() as u64,
        &digest,
        deadline,
    )
    .unwrap();
    assert_eq!(
        access_flags(frozen.as_fd()).unwrap() & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    assert_eq!(frozen.read_small(deadline).unwrap(), bytes);
    for (count, expected) in [
        (0, digest.clone()),
        (MAX_MESSAGE_BYTES as u64 + 1, digest.clone()),
        (bytes.len() as u64 - 1, digest.clone()),
        (bytes.len() as u64 + 1, digest.clone()),
        (bytes.len() as u64, HexDigest::of(b"incorrect digest")),
    ] {
        assert!(
            FrozenArtifact::freeze(&source, uid, Class::Plan, count, &expected, deadline).is_err()
        );
    }
    source
        .set_permissions(std::fs::Permissions::from_mode(0o622))
        .unwrap();
    assert!(FrozenArtifact::freeze(
        &source,
        uid,
        Class::Plan,
        bytes.len() as u64,
        &digest,
        deadline
    )
    .is_err());
    let writable = tempfile::NamedTempFile::new().unwrap();
    assert!(FrozenArtifact::freeze(
        writable.as_file(),
        uid,
        Class::Plan,
        bytes.len() as u64,
        &digest,
        deadline
    )
    .is_err());
}

#[test]
fn readback_is_independent_and_the_kernel_refuses_writes_and_growth() {
    let bytes = b"synthetic readback fixture";
    let (_temporary, source) = source(bytes);
    let deadline = StageDeadline::frame("independent readback");
    let frozen = freeze_fixture_file(&source, Class::Config, bytes, deadline).unwrap();
    let fd = frozen.as_fd().as_raw_fd();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & SEALS, SEALS);
    assert_eq!(
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
        0,
        "all delivered reads start at zero"
    );
    assert!(frozen
        .check_content(Some(&HexDigest::of(b"wrong readback pin")), deadline)
        .is_err());
    for length in [bytes.len() - 1, bytes.len() + 1] {
        assert!(hash_exact(&frozen.file, length as u64, deadline, |_| Ok(())).is_err());
    }
    frozen
        .file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/fd/{fd}"))
        .unwrap();
    for error in [
        writer.write_at(b"x", 0).unwrap_err(),
        writer.set_len(bytes.len() as u64 + 1).unwrap_err(),
        writer.set_len(bytes.len() as u64 - 1).unwrap_err(),
    ] {
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
        -1
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
}

fn freeze_fixture_file(
    file: &File,
    class: Class,
    bytes: &[u8],
    deadline: StageDeadline,
) -> Result<FrozenArtifact, CustodyError> {
    FrozenArtifact::freeze(
        file,
        file.metadata().unwrap().uid(),
        class,
        bytes.len() as u64,
        &HexDigest::of(bytes),
        deadline,
    )
}

fn freeze_fixture(class: Class, bytes: &[u8]) -> FrozenArtifact {
    let (_temporary, file) = source(bytes);
    freeze_fixture_file(&file, class, bytes, StageDeadline::frame("fixture freeze")).unwrap()
}

fn classes(resource: Resource) -> Vec<Class> {
    let mut all = vec![
        Class::Plan,
        Class::Launch,
        Class::Grant,
        Class::Inputs,
        Class::Candidate,
        Class::Config,
        Class::CaptureLoad,
        Class::Member(Member::Hi),
        Class::Member(Member::He),
    ];
    if resource == Resource::Authority {
        all.extend([Class::Member(Member::Ni), Class::Member(Member::Ng)]);
    }
    all.extend([
        Class::Member(Member::Tr),
        Class::Signer(if resource == Resource::Daemon {
            Signer::Hk
        } else {
            Signer::Ak
        }),
        Class::TlsCert,
        Class::TlsKey,
    ]);
    if resource == Resource::Authority {
        all.push(Class::OrdinaryAuthorityKey);
    }
    all
}

const KEY_SEED: u8 = 5;

fn key_profile(seed: u8) -> Vec<u8> {
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let mut bytes = hex::decode("3051020101300506032b657004220420").unwrap();
    bytes.extend([seed; 32]);
    bytes.extend([0x81, 0x21, 0x00]);
    bytes.extend(ring::signature::KeyPair::public_key(&pair).as_ref());
    assert_eq!(bytes.len(), 83);
    bytes
}

fn key_public(seed: u8) -> KeyBytes {
    KeyBytes::from_array(key_profile(seed)[51..].try_into().unwrap())
}

fn payload(class: Class, index: usize) -> Vec<u8> {
    if class == Class::OrdinaryAuthorityKey {
        key_profile(KEY_SEED)
    } else {
        format!("synthetic fixture {index}").into_bytes()
    }
}

fn descriptor_value(class: Class, bytes: &[u8]) -> serde_json::Value {
    let length = bytes.len();
    let digest = HexDigest::of(bytes);
    let literal = match class {
        Class::Plan => "plan",
        Class::Launch => "launch",
        Class::Grant => "grant",
        Class::Inputs => "inputs",
        Class::Candidate => "candidate",
        Class::Config => "config",
        Class::CaptureLoad => "capture-load",
        Class::Member(member) => {
            return serde_json::json!({
                "class": "member", "bytes": length, "digest": digest,
                "member": member, "member_hash": HexDigest::of(b"synthetic member hash"),
            })
        }
        Class::Signer(role) => {
            return serde_json::json!({
                "class": "signer", "bytes": length, "role": role, "public": KeyBytes::from_array([42; 32]),
            })
        }
        Class::TlsCert => "tls-cert",
        Class::TlsKey => "tls-key",
        Class::OrdinaryAuthorityKey => {
            return serde_json::json!({
                "class": "ordinary-authority-key", "bytes": length, "public": key_public(KEY_SEED),
            })
        }
    };
    serde_json::json!({"class": literal, "bytes": length, "digest": digest})
}

fn envelope(assets: Vec<serde_json::Value>) -> Vec<u8> {
    briqyard_api::execution::sealed::encode(&serde_json::json!({
        "format": "native.assets/v1", "assets": assets,
    }))
    .unwrap()
}

#[test]
fn assets_require_every_exact_field_and_resource_array_order() {
    for resource in [Resource::Daemon, Resource::Authority] {
        let fields: Vec<_> = classes(resource)
            .into_iter()
            .map(|class| descriptor_value(class, &payload(class, 0)))
            .collect();
        let wire = envelope(fields.clone());
        let offer = AssetOffer::decode(resource, &wire).unwrap();
        assert_eq!(
            offer
                .descriptors()
                .iter()
                .map(Descriptor::class)
                .collect::<Vec<_>>(),
            classes(resource)
        );
        assert_eq!(AssetOffer::encode(resource, offer.assets).unwrap(), wire);
        let refuses = |alter: fn(&mut Vec<serde_json::Value>)| {
            let mut invalid = fields.clone();
            alter(&mut invalid);
            assert!(AssetOffer::decode(resource, &envelope(invalid)).is_err());
        };
        refuses(|assets| assets[0]["slot"] = 32768.into());
        refuses(|assets| assets[0]["bytes"] = 0.into());
        refuses(|assets| assets[0]["bytes"] = (MAX_MESSAGE_BYTES as u64 + 1).into());
        refuses(|assets| assets[4]["bytes"] = (IMAGE_LIMIT + 1).into());
        refuses(|assets| {
            assets[0].as_object_mut().unwrap().remove("digest");
        });
        refuses(|assets| assets.swap(0, 1));
        refuses(|assets| assets[1] = assets[0].clone());
        refuses(|assets| assets[7]["member"] = "ng".into());
        refuses(|assets| assets[8]["member"] = "hi".into());
        refuses(|assets| {
            assets[7].as_object_mut().unwrap().remove("member_hash");
        });
        refuses(|assets| assets[7]["secret"] = "synthetic".into());
        refuses(|assets| assets[0]["class"] = "opaque.frame".into());
        refuses(|assets| {
            let signer = assets.iter().position(|a| a["class"] == "signer").unwrap();
            assets[signer]["digest"] = serde_json::json!(HexDigest::of(b"synthetic"));
        });
        let mut wrong_signer = fields;
        let signer_index = wrong_signer
            .iter()
            .position(|asset| asset["class"] == "signer")
            .unwrap();
        wrong_signer[signer_index]["role"] = if resource == Resource::Daemon {
            "ak"
        } else {
            "hk"
        }
        .into();
        assert!(AssetOffer::decode(resource, &envelope(wrong_signer)).is_err());
    }
}

fn authority_fields() -> Vec<serde_json::Value> {
    classes(Resource::Authority)
        .into_iter()
        .map(|class| descriptor_value(class, &payload(class, 0)))
        .collect()
}

#[test]
fn authority_slot_fifteen_is_mandatory_last_unique_and_closed() {
    let fields = authority_fields();
    assert_eq!(fields.len(), 16);
    assert_eq!(fields[15]["class"], "ordinary-authority-key");
    let decode =
        |fields: Vec<serde_json::Value>| AssetOffer::decode(Resource::Authority, &envelope(fields));
    let offer = decode(fields.clone()).unwrap();
    assert_eq!(offer.descriptors()[15].class(), Class::OrdinaryAuthorityKey);
    let mutate = |alter: fn(&mut Vec<serde_json::Value>)| {
        let mut invalid = fields.clone();
        alter(&mut invalid);
        decode(invalid)
    };
    assert!(mutate(|a| drop(a.pop())).is_err(), "missing slot 15");
    assert!(mutate(|a| a.swap(14, 15)).is_err(), "misordered");
    assert!(mutate(|a| a.swap(0, 15)).is_err(), "misordered");
    assert!(mutate(|a| a.push(a[15].clone())).is_err(), "duplicate");
    assert!(
        mutate(|a| a[14] = a[15].clone()).is_err(),
        "aliased in place of a TLS key"
    );
    assert!(
        mutate(|a| a[15]["digest"] = serde_json::json!(HexDigest::of(b"private bytes"))).is_err()
    );
    assert!(mutate(|a| a[15]["role"] = "ak".into()).is_err());
    assert!(
        mutate(|a| a[15]["path"] = "/etc/briq-execution/authority/signing.pk8".into()).is_err()
    );
    assert!(mutate(|a| a[15]["name"] = "ordinary".into()).is_err());
    assert!(mutate(|a| a[15]["slot"] = 15.into()).is_err());
    assert!(mutate(|a| drop(a[15].as_object_mut().unwrap().remove("public"))).is_err());
    assert!(mutate(|a| drop(a[15].as_object_mut().unwrap().remove("bytes"))).is_err());
    for bytes in [0, 1, 82, 84, 85, 4096, MAX_MESSAGE_BYTES as u64] {
        assert!(mutate_bytes(&fields, bytes).is_err(), "{bytes}");
    }
    assert!(mutate(|a| a[15]["public"] = "not-a-key".into()).is_err());
}

fn mutate_bytes(fields: &[serde_json::Value], bytes: u64) -> Result<AssetOffer, CodecError> {
    let mut invalid = fields.to_vec();
    invalid[15]["bytes"] = bytes.into();
    AssetOffer::decode(Resource::Authority, &envelope(invalid))
}

#[test]
fn the_daemon_rejects_the_authority_only_right_and_the_authority_requires_it() {
    let authority = authority_fields();
    let daemon: Vec<_> = classes(Resource::Daemon)
        .into_iter()
        .map(|class| descriptor_value(class, &payload(class, 0)))
        .collect();
    assert!(AssetOffer::decode(Resource::Daemon, &envelope(daemon.clone())).is_ok());
    let mut with_key = daemon.clone();
    with_key.push(authority[15].clone());
    assert!(AssetOffer::decode(Resource::Daemon, &envelope(with_key)).is_err());
    let mut hybrid = daemon;
    hybrid.insert(9, authority[15].clone());
    assert!(AssetOffer::decode(Resource::Daemon, &envelope(hybrid)).is_err());
    let mut without_key = authority;
    without_key.pop();
    assert!(AssetOffer::decode(Resource::Authority, &envelope(without_key)).is_err());
}

fn candidate_file() -> (tempfile::NamedTempFile, File, Vec<u8>) {
    let bytes = native_image();
    assert!((1..1024 * 1024).contains(&bytes.len()));
    let (temporary, file) = source(&bytes);
    (temporary, file, bytes)
}

fn delivery(same_bytes: bool) -> (AssetOffer, ReceivedAssetFds) {
    delivery_for(Resource::Daemon, same_bytes)
}

fn delivery_for(resource: Resource, same_bytes: bool) -> (AssetOffer, ReceivedAssetFds) {
    let (_temporary, candidate, image_bytes) = candidate_file();
    let mut assets = Vec::new();
    let mut fds = Vec::new();
    for (index, class) in classes(resource).into_iter().enumerate() {
        let index = if same_bytes { 0 } else { index };
        let (frozen, bytes) = if class == Class::Candidate {
            let frozen = freeze_fixture_file(
                &candidate,
                class,
                &image_bytes,
                StageDeadline::frame("test candidate freeze"),
            )
            .unwrap();
            (frozen, image_bytes.clone())
        } else if class == Class::OrdinaryAuthorityKey {
            let bytes = payload(class, index);
            let frozen = FrozenArtifact::freeze_ordinary_key(
                &bytes,
                &key_public(KEY_SEED),
                StageDeadline::frame("test key stage"),
            )
            .unwrap();
            (frozen, bytes)
        } else {
            let bytes = payload(class, index);
            (freeze_fixture(class, &bytes), bytes)
        };
        assets.push(descriptor_value(class, &bytes));
        fds.push(frozen.file.into());
    }
    let offer = AssetOffer::decode(resource, &envelope(assets)).unwrap();
    (
        offer,
        ReceivedAssetFds {
            fds,
            truncated: false,
            unexpected_control: false,
            queued_packet: false,
        },
    )
}

fn no_listeners() -> ListenerEnv {
    ListenerEnv::verify(&std::process::id().to_string(), "0", "", &[]).unwrap()
}

#[test]
fn delivery_refuses_truncation_queuing_wrong_count_inode_and_transfer_order() {
    let listeners = no_listeners();
    let refuse = |mutation: fn(&mut ReceivedAssetFds), reason| {
        let (offer, mut packet) = delivery(false);
        mutation(&mut packet);
        let result = BoundAssets::bind(
            Resource::Daemon,
            offer,
            packet,
            &listeners,
            StageDeadline::frame("invalid asset delivery"),
        );
        assert!(
            matches!(result, Err(CustodyError::Protocol(got)) if got == reason),
            "{:?}",
            result.err()
        );
    };
    for mutation in [
        (|p: &mut ReceivedAssetFds| p.truncated = true) as fn(&mut ReceivedAssetFds),
        |p| p.unexpected_control = true,
        |p| p.queued_packet = true,
        |p| {
            p.fds.pop();
        },
    ] {
        refuse(mutation, "invalid native asset packet delivery");
    }
    refuse(|p| p.fds.swap(0, 1), "native artifact digest mismatch");
    refuse(
        |p| p.fds[0] = TcpListener::bind("127.0.0.1:0").unwrap().into(),
        "unexpected sealed native artifact metadata",
    );
    refuse(
        |p| {
            assert_eq!(
                unsafe { libc::fcntl(p.fds[0].as_raw_fd(), libc::F_SETFD, 0) },
                0
            )
        },
        "native artifact arrived inheritable",
    );
    let (offer, mut packet) = delivery(true);
    packet.fds[1] = packet.fds[0].try_clone().unwrap();
    let result = BoundAssets::bind(
        Resource::Daemon,
        offer,
        packet,
        &listeners,
        StageDeadline::frame("duplicate native delivery"),
    );
    assert!(matches!(
        result,
        Err(CustodyError::Protocol(
            "duplicate native artifact descriptor"
        ))
    ));
}

#[test]
fn actual_scm_rights_delivery_preserves_asset_order() {
    use nix::sys::socket::{
        recvmsg, socketpair, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    };
    use std::io::IoSliceMut;

    let (sender, receiver) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();
    let (offer, packet) = delivery(false);
    let wire = AssetOffer::encode(Resource::Daemon, offer.assets).unwrap();
    let sending: Vec<_> = packet.fds.iter().map(AsRawFd::as_raw_fd).collect();
    super::super::tests::send_raw(sender.as_raw_fd(), &wire, &sending);
    let mut data = vec![0u8; MAX_MESSAGE_BYTES];
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut control = nix::cmsg_space!([RawFd; 15]);
    let received = recvmsg::<()>(
        receiver.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .unwrap();
    let mut fds = Vec::new();
    for cmsg in received.cmsgs().unwrap() {
        let ControlMessageOwned::ScmRights(raw) = cmsg else {
            panic!("unexpected ancillary fixture data");
        };
        fds.extend(
            raw.into_iter()
                .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
        );
    }
    let truncated = received
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let length = received.bytes;
    let offer = AssetOffer::decode(Resource::Daemon, &data[..length]).unwrap();
    let deadline = StageDeadline::frame("native ordered rights test");
    let bound = BoundAssets::bind(
        Resource::Daemon,
        offer,
        ReceivedAssetFds {
            fds,
            truncated,
            unexpected_control: false,
            queued_packet: false,
        },
        &no_listeners(),
        deadline,
    )
    .unwrap();
    for (index, class) in classes(Resource::Daemon).into_iter().enumerate() {
        if class != Class::Candidate {
            assert_eq!(
                bound.artifact(class).unwrap().read_small(deadline).unwrap(),
                format!("synthetic fixture {index}").as_bytes()
            );
        }
    }
}

#[test]
fn no_script_or_regular_file_can_substitute_for_the_sealed_native_image() {
    let bytes = b"#!/bin/true\n";
    let (_temporary, file) = source(bytes);
    assert!(matches!(
        freeze_fixture_file(
            &file,
            Class::Candidate,
            bytes,
            StageDeadline::frame("reject script")
        ),
        Err(CustodyError::Protocol(
            "native candidate must be an ELF image"
        ))
    ));
    let (offer, mut packet) = delivery(false);
    packet.fds[4] = candidate_file().1.into();
    let result = BoundAssets::bind(
        Resource::Daemon,
        offer,
        packet,
        &no_listeners(),
        StageDeadline::frame("reject mutable image"),
    );
    assert!(matches!(
        result,
        Err(CustodyError::Protocol(
            "unexpected sealed native artifact metadata"
        ))
    ));
}

#[test]
fn isolated_listener_survives_an_allocation_collision_and_low_rlimit_refuses() {
    let mut child = FixtureChild::spawn("listeners", Stdio::null());
    assert!(child.wait().success());
}

#[test]
fn execveat_keeps_pid_and_maps_the_sealed_digest() {
    let (mut output, writer) = UnixStream::pair().unwrap();
    output
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut child = FixtureChild::spawn("exec", Stdio::from(OwnedFd::from(writer)));
    let pid = child.child.id();
    let mut reader = BufReader::new(&mut output);
    let expected_line = format!("synthetic guard pid {pid}\n");
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "native fixture ended before exec"
        );
        if line == expected_line {
            break;
        }
    }
    let (_, _, expected_image) = candidate_file();
    let mut mapped_image = vec![0; expected_image.len()];
    reader.read_exact(&mut mapped_image).unwrap();
    let expected_digest = HexDigest::of(&expected_image);
    assert!(
        HexDigest::of(&mapped_image) == expected_digest,
        "candidate /proc/self/exe digest differs"
    );
    let process_image = std::fs::read(format!("/proc/{pid}/exe")).unwrap();
    assert!(
        HexDigest::of(&process_image) == expected_digest,
        "recorded guard PID has the wrong image"
    );
    let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
    let entries: Vec<_> = env.split(|&byte| byte == 0).collect();
    assert!(entries.contains(&b"PATH=/usr/bin:/bin".as_slice()));
    assert!(entries
        .iter()
        .any(|entry| entry.starts_with(b"BRIQ_SEALED_CAPTURE_FD=")));
    assert!(entries
        .iter()
        .all(|entry| !entry.starts_with(b"LD_LIBRARY_PATH=")
            && !entry.starts_with(b"HTTPS_PROXY=")
            && !entry.starts_with(FIXTURE_MODE.as_bytes())));
    let mut input = child.child.stdin.take().unwrap();
    input.write_all(END).unwrap();
    drop(input);
    let mut marker = [0; END.len()];
    reader.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, END);
    assert!(child.wait().success());
    eprintln!("positive execveat: same PID and SHA-256 of /proc/self/exe and recorded PID's mapped image match");
}

#[test]
fn fixture_child_inherits_no_descriptor_another_test_left_inheritable() {
    let leaked = unsafe { libc::memfd_create(c"synthetic-inheritable".as_ptr(), 0) };
    assert!(leaked >= 0);
    let leaked = unsafe { OwnedFd::from_raw_fd(leaked) };
    assert_eq!(descriptor_flags(leaked.as_raw_fd()).unwrap(), 0);
    let (output, writer) = UnixStream::pair().unwrap();
    let mut child = FixtureChild::spawn("exec", Stdio::from(OwnedFd::from(writer)));
    drop(leaked);
    drop(child.child.stdin.take());
    assert!(child.wait().success());
    drop(output);
}

fn raw_key_memfd(bytes: &[u8], mode: u32, seals: libc::c_int) -> OwnedFd {
    let fd = unsafe {
        libc::memfd_create(
            c"raw-key".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let file = unsafe { File::from_raw_fd(fd) };
    (&file).write_all(bytes).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .unwrap();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    File::open(format!("/proc/self/fd/{fd}")).unwrap().into()
}

fn bind_authority(
    mutation: impl FnOnce(&mut ReceivedAssetFds),
) -> Result<BoundAssets, CustodyError> {
    let (offer, mut packet) = delivery_for(Resource::Authority, false);
    mutation(&mut packet);
    BoundAssets::bind(
        Resource::Authority,
        offer,
        packet,
        &no_listeners(),
        StageDeadline::frame("authority key delivery"),
    )
}

#[test]
fn staging_accepts_only_the_exact_profile_bound_to_the_advertised_public_key() {
    let deadline = StageDeadline::frame("key staging");
    let good = key_profile(KEY_SEED);
    let public = key_public(KEY_SEED);
    let frozen = FrozenArtifact::freeze_ordinary_key(&good, &public, deadline).unwrap();
    assert_eq!(frozen.ordinary_key().unwrap().public(), *public.as_array());
    assert_eq!(frozen.file.metadata().unwrap().mode() & 0o7777, 0o400);
    assert_eq!(
        access_flags(frozen.as_fd()).unwrap() & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    let fd = frozen.as_fd().as_raw_fd();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & SEALS, SEALS);
    assert!(std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/fd/{fd}"))
        .is_err());
    assert_eq!(descriptor_flags(fd).unwrap(), libc::FD_CLOEXEC);
    assert!(
        frozen.read_small(deadline).is_err(),
        "no raw private bytes leave"
    );

    let mut inconsistent = good.clone();
    inconsistent[60] ^= 1;
    let mut other_public = good.clone();
    other_public[51..].copy_from_slice(key_public(KEY_SEED + 1).as_array());
    for (name, bytes, advertised) in [
        ("short", good[..82].to_vec(), &public),
        ("long", [good.clone(), vec![0]].concat(), &public),
        ("seed only", good[16..48].to_vec(), &public),
        ("inconsistent embedded public", inconsistent, &public),
        ("seed with another embedded public", other_public, &public),
        (
            "advertised-but-wrong actual key",
            key_profile(KEY_SEED + 1),
            &public,
        ),
        (
            "advertised public of another key",
            good.clone(),
            &key_public(KEY_SEED + 1),
        ),
    ] {
        assert!(
            FrozenArtifact::freeze_ordinary_key(&bytes, advertised, deadline).is_err(),
            "{name}"
        );
    }
    let (_temporary, file) = source(&good);
    assert!(
        freeze_fixture_file(&file, Class::OrdinaryAuthorityKey, &good, deadline).is_err(),
        "no digest or path route exists for the private key"
    );
}

#[test]
fn staging_closes_every_descriptor_it_opened_on_success_and_on_every_refusal() {
    let mut child = FixtureChild::spawn("stage", Stdio::null());
    assert!(child.wait().success());
}

fn fixture_stage() {
    let deadline = StageDeadline::frame("isolated key staging");
    let good = key_profile(KEY_SEED);
    let public = key_public(KEY_SEED);
    let before = open_descriptors().unwrap().len();
    let frozen = FrozenArtifact::freeze_ordinary_key(&good, &public, deadline).unwrap();
    assert_eq!(
        open_descriptors().unwrap().len(),
        before + 1,
        "the writable staging descriptor is closed"
    );
    drop(frozen);
    assert_eq!(open_descriptors().unwrap().len(), before);
    let mut inconsistent = good.clone();
    inconsistent[60] ^= 1;
    for bytes in [&good[..82], &inconsistent[..], &good[16..48]] {
        assert!(FrozenArtifact::freeze_ordinary_key(bytes, &public, deadline).is_err());
    }
    assert!(
        FrozenArtifact::freeze_ordinary_key(&good, &key_public(KEY_SEED + 1), deadline).is_err()
    );
    assert_eq!(
        open_descriptors().unwrap().len(),
        before,
        "refusals leak nothing"
    );
}

#[test]
fn authority_delivery_binds_slot_fifteen_to_the_actual_descriptor_at_any_slot() {
    let bound = bind_authority(|_| {}).unwrap();
    let key = bound.artifact(Class::OrdinaryAuthorityKey).unwrap();
    let env: Vec<_> = bound.descriptor_env().collect();
    assert_eq!(env.len(), 17);
    assert_eq!(env[16].0, "BRIQ_SEALED_ORDINARY_AUTHORITY_KEY_FD");
    assert_eq!(env[16].1, key.as_fd().as_raw_fd());
    assert_eq!(env.iter().filter(|(name, _)| *name == env[16].0).count(), 1);
    let slots: HashSet<_> = env.iter().skip(1).map(|(_, slot)| *slot).collect();
    assert_eq!(slots.len(), 16, "no two logical indices share a slot");
    assert_eq!(descriptor_flags(env[16].1).unwrap(), libc::FD_CLOEXEC);
    assert_eq!(
        key.ordinary_key().unwrap().public(),
        *key_public(KEY_SEED).as_array()
    );

    let listeners = no_listeners();
    let (offer, packet) = delivery_for(Resource::Authority, false);
    let floor = DescriptorFloor::for_artifacts(0, packet.fds.len()).unwrap();
    let gap = unsafe {
        libc::fcntl(
            packet.fds[0].as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            floor.minimum() + 2,
        )
    };
    assert!(gap >= floor.minimum() + 2);
    let gap = unsafe { OwnedFd::from_raw_fd(gap) };
    let assets = BoundAssets::relocate(
        offer,
        packet.fds,
        floor,
        StageDeadline::frame("shifted slots"),
    )
    .unwrap();
    let env: Vec<_> = assets.descriptor_env().collect();
    let key_slot = env[16].1;
    assert_eq!(
        key_slot,
        assets
            .artifact(Class::OrdinaryAuthorityKey)
            .unwrap()
            .as_fd()
            .as_raw_fd()
    );
    if gap.as_raw_fd() == floor.minimum() + 2 {
        assert_ne!(
            key_slot,
            floor.minimum() + 15,
            "logical index is not the base plus 15"
        );
    }
    drop(listeners);
}

#[test]
fn authority_key_descriptor_must_be_an_exact_immutable_mode_0400_regular_memfd() {
    let good = key_profile(KEY_SEED);
    let refuse = |mutation: fn(&mut ReceivedAssetFds)| {
        assert!(matches!(
            bind_authority(mutation),
            Err(CustodyError::Protocol(
                "unexpected sealed native artifact metadata"
            ))
        ));
    };
    refuse(|p| p.fds[15] = raw_key_memfd(&key_profile(KEY_SEED), 0o600, SEALS));
    refuse(|p| p.fds[15] = raw_key_memfd(&key_profile(KEY_SEED), 0o440, SEALS));
    refuse(|p| {
        p.fds[15] = raw_key_memfd(&key_profile(KEY_SEED), 0o400, SEALS & !libc::F_SEAL_WRITE)
    });
    refuse(|p| p.fds[15] = raw_key_memfd(&key_profile(KEY_SEED)[..82], 0o400, SEALS));
    refuse(|p| p.fds[15] = raw_key_memfd(&[key_profile(KEY_SEED), vec![0]].concat(), 0o400, SEALS));
    refuse(|p| p.fds[15] = TcpListener::bind("127.0.0.1:0").unwrap().into());
    refuse(|p| {
        let (_temporary, file) = source(&key_profile(KEY_SEED));
        file.set_permissions(std::fs::Permissions::from_mode(0o400))
            .unwrap();
        p.fds[15] = file.into();
    });
    assert!(bind_authority(|p| {
        p.fds[15] = raw_key_memfd(&good, 0o400, SEALS);
    })
    .is_ok());
    assert!(matches!(
        bind_authority(|p| {
            assert_eq!(
                unsafe { libc::fcntl(p.fds[15].as_raw_fd(), libc::F_SETFD, 0) },
                0
            )
        }),
        Err(CustodyError::Protocol(
            "native artifact arrived inheritable"
        ))
    ));
}

#[test]
fn authority_delivery_refuses_missing_extra_misordered_and_aliased_key_descriptors() {
    let truncated = |mutation: fn(&mut ReceivedAssetFds)| {
        assert!(matches!(
            bind_authority(mutation),
            Err(CustodyError::Protocol(
                "invalid native asset packet delivery"
            ))
        ));
    };
    truncated(|p| drop(p.fds.pop()));
    truncated(|p| p.fds.push(p.fds[0].try_clone().unwrap()));
    truncated(|p| p.truncated = true);
    truncated(|p| p.unexpected_control = true);
    truncated(|p| p.queued_packet = true);
    assert!(matches!(
        bind_authority(|p| p.fds.swap(14, 15)),
        Err(CustodyError::Protocol(_))
    ));

    let (offer, mut packet) = delivery_for(Resource::Authority, false);
    let mut fields: Vec<_> = serde_json::to_value(&offer.assets)
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    let key = key_profile(KEY_SEED);
    fields[14] =
        serde_json::json!({"class": "tls-key", "bytes": 83, "digest": HexDigest::of(&key)});
    let offer = AssetOffer::decode(Resource::Authority, &envelope(fields)).unwrap();
    packet.fds[14] = packet.fds[15].try_clone().unwrap();
    assert!(matches!(
        BoundAssets::bind(
            Resource::Authority,
            offer,
            packet,
            &no_listeners(),
            StageDeadline::frame("alias")
        ),
        Err(CustodyError::Protocol(
            "duplicate native artifact descriptor"
        ))
    ));
}

#[test]
fn the_daemon_resource_cannot_receive_the_authority_key_at_any_position() {
    let (offer, mut packet) = delivery_for(Resource::Authority, false);
    let extra = packet.fds.pop().unwrap();
    assert!(BoundAssets::bind(
        Resource::Daemon,
        offer,
        ReceivedAssetFds {
            fds: packet.fds,
            truncated: false,
            unexpected_control: false,
            queued_packet: false,
        },
        &no_listeners(),
        StageDeadline::frame("daemon refuses authority offer"),
    )
    .is_err());
    drop(extra);
}

#[test]
fn the_sealed_key_descriptor_crosses_the_one_exec_at_its_actual_slot_without_cloexec() {
    let (mut output, writer) = UnixStream::pair().unwrap();
    output
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut child = FixtureChild::spawn("exec-authority", Stdio::from(OwnedFd::from(writer)));
    let pid = child.child.id();
    let mut reader = BufReader::new(&mut output);
    let expected_line = format!("synthetic guard pid {pid}\n");
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "fixture ended before exec"
        );
        if line == expected_line {
            break;
        }
    }
    let (_, _, image) = candidate_file();
    let mut mapped = vec![0; image.len()];
    reader.read_exact(&mut mapped).unwrap();
    let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
    let slot: i32 = env
        .split(|&byte| byte == 0)
        .find_map(|entry| entry.strip_prefix(b"BRIQ_SEALED_ORDINARY_AUTHORITY_KEY_FD="))
        .map(|value| std::str::from_utf8(value).unwrap().parse().unwrap())
        .expect("the guard names logical index 15 in the environment");
    assert!(slot >= 32768);
    let target = std::fs::read_link(format!("/proc/{pid}/fd/{slot}")).unwrap();
    assert!(target.to_string_lossy().contains("memfd:briq-sealed-asset"));
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{slot}")).unwrap();
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .map(|value| i32::from_str_radix(value.trim(), 8).unwrap())
        .unwrap();
    assert_eq!(
        flags & libc::O_CLOEXEC,
        0,
        "inheritable across this exec only"
    );
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    assert_eq!(
        std::fs::read(format!("/proc/{pid}/fd/{slot}")).unwrap(),
        key_profile(KEY_SEED)
    );
    drop(child.child.stdin.take());
    assert!(child.wait().success());
}

#[test]
fn native_asset_child() {
    let Ok(mode) = std::env::var(FIXTURE_MODE) else {
        return;
    };
    match mode.as_str() {
        "exec" => {
            let (offer, packet) = delivery(false);
            let listeners = no_listeners();
            let assets = BoundAssets::bind(
                Resource::Daemon,
                offer,
                packet,
                &listeners,
                StageDeadline::frame("exec fixture"),
            )
            .unwrap();
            println!("synthetic guard pid {}", std::process::id());
            io::stdout().flush().unwrap();
            let Err(error) = assets.exec(&[c"native-fixture"], &listeners, None, None);
            panic!("real kernel execveat failed: {error}");
        }
        "exec-authority" => {
            let (offer, packet) = delivery_for(Resource::Authority, false);
            let listeners = no_listeners();
            let assets = BoundAssets::bind(
                Resource::Authority,
                offer,
                packet,
                &listeners,
                StageDeadline::frame("authority exec fixture"),
            )
            .unwrap();
            println!("synthetic guard pid {}", std::process::id());
            io::stdout().flush().unwrap();
            let Err(error) = assets.exec(&[c"native-fixture"], &listeners, None, None);
            panic!("real kernel execveat failed: {error}");
        }
        "stage" => fixture_stage(),
        "listeners" => fixture_listeners(),
        _ => panic!("unknown fixture mode"),
    }
}

fn fixture_listeners() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let fd = listener.as_raw_fd();
    if fd != LISTENER_START {
        assert_eq!(unsafe { libc::dup2(fd, LISTENER_START) }, LISTENER_START);
        drop(listener);
    } else {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        std::mem::forget(listener);
    }
    let listener = unsafe { TcpListener::from_raw_fd(LISTENER_START) };
    let pid = std::process::id().to_string();
    let expected = ["fixture".to_owned()];
    assert!(ListenerEnv::verify("0", "1", "fixture", &expected).is_err());
    assert!(ListenerEnv::verify(&pid, "2", "fixture", &expected).is_err());
    assert!(ListenerEnv::verify(&pid, "1", "wrong", &expected).is_err());
    let listeners = ListenerEnv::verify(&pid, "1", "fixture", &expected).unwrap();
    let (offer, packet) = delivery(false);
    let earlier_high = listener.as_fd().try_clone_to_owned().unwrap();
    let earlier_high =
        unsafe { libc::fcntl(earlier_high.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 32770) };
    assert!(earlier_high >= 32770);
    let preserved = unsafe { OwnedFd::from_raw_fd(earlier_high) };
    let floor = DescriptorFloor::for_artifacts(1, packet.fds.len()).unwrap();
    assert_eq!(floor.minimum(), preserved.as_raw_fd() + 1);
    let blocker = unsafe { libc::fcntl(LISTENER_START, libc::F_DUPFD_CLOEXEC, floor.minimum()) };
    assert_eq!(blocker, floor.minimum());
    let blocker = unsafe { OwnedFd::from_raw_fd(blocker) };
    let assets = BoundAssets::relocate(
        offer,
        packet.fds,
        floor,
        StageDeadline::frame("local slot collision"),
    )
    .unwrap();
    let env: Vec<_> = assets.descriptor_env().collect();
    assert_eq!(env[0], ("BRIQ_SEALED_DESCRIPTOR_BASE", floor.minimum()));
    assert_eq!(env[1], ("BRIQ_SEALED_PLAN_FD", blocker.as_raw_fd() + 1));
    assert!(env.iter().any(|(key, _)| *key == "BRIQ_SEALED_CAPTURE_FD"));
    for (index, (name, raw)) in env.into_iter().skip(1).enumerate() {
        let class = classes(Resource::Daemon)[index];
        let actual = assets.artifact(class).unwrap();
        assert_eq!(name, class.env());
        assert_eq!(raw, actual.as_fd().as_raw_fd());
        assert_eq!(descriptor_flags(raw).unwrap(), libc::FD_CLOEXEC);
    }
    assert_eq!(
        descriptor_flags(blocker.as_raw_fd()).unwrap(),
        libc::FD_CLOEXEC
    );
    assert_eq!(listener.local_addr().unwrap(), address);
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_cur = 32768;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let (offer, packet) = delivery(false);
    let result = BoundAssets::bind(
        Resource::Daemon,
        offer,
        packet,
        &listeners,
        StageDeadline::frame("low limit refusal"),
    );
    assert!(matches!(
        result,
        Err(CustodyError::Protocol(
            "open-file limit cannot hold native artifacts"
        ))
    ));
    let mut after: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut after) },
        0
    );
    assert_eq!(
        (after.rlim_cur, after.rlim_max),
        (limit.rlim_cur, limit.rlim_max)
    );
    let _client = TcpStream::connect(address).unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(
        listener.accept().is_ok(),
        "original listener survives allocation and refusal"
    );
}

struct FixtureChild {
    child: Child,
    pidfd: OwnedFd,
}

impl FixtureChild {
    fn spawn(mode: &str, stdout: Stdio) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD_TEST, "--nocapture", "--quiet"])
            .env_clear()
            .env(FIXTURE_MODE, mode)
            .env("LD_LIBRARY_PATH", "/synthetic-must-not-survive")
            .env("HTTPS_PROXY", "synthetic-must-not-survive")
            .stdin(Stdio::piped())
            .stdout(stdout);
        let parent = std::process::id();
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent {
                    return Err(io::Error::from_raw_os_error(libc::ECHILD));
                }
                if libc::syscall(
                    libc::SYS_close_range,
                    3,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            drop(child.stdin.take());
            panic!("fixture pidfd_open failed: {error}");
        }
        Self {
            child,
            pidfd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
        }
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        assert!(self.exited(), "native test child exceeded its bounded wait");
        self.child.wait().unwrap()
    }

    fn exited(&self) -> bool {
        let mut fd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        (unsafe { libc::poll(&mut fd, 1, 5000) }) == 1 && fd.revents & libc::POLLIN != 0
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        if self.exited() {
            let _ = self.child.wait();
        }
    }
}
