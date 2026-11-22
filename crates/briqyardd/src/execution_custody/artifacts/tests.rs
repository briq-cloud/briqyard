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
    all
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
            .map(|class| descriptor_value(class, b"synthetic payload"))
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
            let signer = assets.len() - 3;
            assets[signer]["digest"] = serde_json::json!(HexDigest::of(b"synthetic"));
        });
        let mut wrong_signer = fields;
        let signer_index = wrong_signer.len() - 3;
        wrong_signer[signer_index]["role"] = if resource == Resource::Daemon {
            "ak"
        } else {
            "hk"
        }
        .into();
        assert!(AssetOffer::decode(resource, &envelope(wrong_signer)).is_err());
    }
}

fn candidate_file() -> (tempfile::NamedTempFile, File, Vec<u8>) {
    let bytes = native_image();
    assert!((1..1024 * 1024).contains(&bytes.len()));
    let (temporary, file) = source(&bytes);
    (temporary, file, bytes)
}

fn delivery(same_bytes: bool) -> (AssetOffer, ReceivedAssetFds) {
    let (_temporary, candidate, image_bytes) = candidate_file();
    let mut assets = Vec::new();
    let mut fds = Vec::new();
    for (index, class) in classes(Resource::Daemon).into_iter().enumerate() {
        let fixture = format!("synthetic fixture {}", if same_bytes { 0 } else { index });
        let (frozen, bytes) = if class == Class::Candidate {
            let frozen = freeze_fixture_file(
                &candidate,
                class,
                &image_bytes,
                StageDeadline::frame("test candidate freeze"),
            )
            .unwrap();
            (frozen, image_bytes.as_slice())
        } else {
            (
                freeze_fixture(class, fixture.as_bytes()),
                fixture.as_bytes(),
            )
        };
        assets.push(descriptor_value(class, bytes));
        fds.push(frozen.file.into());
    }
    let offer = AssetOffer::decode(Resource::Daemon, &envelope(assets)).unwrap();
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
