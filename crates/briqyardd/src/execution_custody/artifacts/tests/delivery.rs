//! Delivery of the v3 suffix: field substitution, descriptor metadata, aliases, the 22-right
//! ancillary bound, and descriptor accounting in an isolated child process.

use super::*;
use briqyard_api::execution::private_cert::{Name, Usage};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

struct Part {
    class: Class,
    descriptor: serde_json::Value,
    fd: OwnedFd,
}

type Mutation = Box<dyn Fn(&mut Vec<Part>)>;

fn everything() -> Vec<Requirements> {
    let mut all: Vec<_> = (0..8)
        .map(|bits| Requirements::Daemon {
            admin_tls: bits & 1 != 0,
            backup_s3: bits & 2 != 0,
            file_key: bits & 4 != 0,
        })
        .collect();
    all.push(Requirements::Authority);
    all
}

fn all_daemon() -> Requirements {
    Requirements::Daemon {
        admin_tls: true,
        backup_s3: true,
        file_key: true,
    }
}

fn parts(requirements: Requirements) -> Vec<Part> {
    let (_temporary, candidate, image) = candidate_file();
    requirements
        .classes()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            let (frozen, bytes) = if class == Class::Candidate {
                let deadline = StageDeadline::frame("test candidate freeze");
                (
                    freeze_fixture_file(&candidate, class, &image, deadline).unwrap(),
                    image.clone(),
                )
            } else {
                let bytes = payload(class, index);
                (stage(class, &bytes), bytes)
            };
            Part {
                class,
                descriptor: descriptor_value(class, &bytes),
                fd: frozen.file.into(),
            }
        })
        .collect()
}

fn bind(requirements: Requirements, parts: Vec<Part>) -> Result<BoundAssets, CustodyError> {
    bind_within(requirements, parts, StageDeadline::frame("suffix delivery"))
}

fn bind_within(
    requirements: Requirements,
    parts: Vec<Part>,
    deadline: StageDeadline,
) -> Result<BoundAssets, CustodyError> {
    let wire = envelope(parts.iter().map(|part| part.descriptor.clone()).collect());
    let offer = AssetOffer::decode(requirements, &wire).unwrap();
    BoundAssets::bind(
        requirements,
        offer,
        ReceivedAssetFds {
            fds: parts.into_iter().map(|part| part.fd).collect(),
            truncated: false,
            unexpected_control: false,
            queued_packet: false,
        },
        &no_listeners(),
        deadline,
    )
}

fn refusal(result: Result<BoundAssets, CustodyError>) -> &'static str {
    match result {
        Err(CustodyError::Protocol(reason)) => reason,
        Err(other) => panic!("not a protocol refusal: {other}"),
        Ok(_) => panic!("accepted"),
    }
}

fn at(parts: &mut [Part], class: Class) -> &mut Part {
    parts.iter_mut().find(|part| part.class == class).unwrap()
}

const MISMATCH: &str = "native artifact differs from its advertised descriptor";
const DIGEST: &str = "native artifact digest mismatch";
const METADATA: &str = "unexpected sealed native artifact metadata";

#[test]
fn every_profile_binds_its_exact_suffix_and_the_generic_read_refuses_the_private_ones() {
    let deadline = StageDeadline::frame("typed suffix");
    for requirements in everything() {
        let bound = bind(requirements, parts(requirements)).unwrap();
        assert_eq!(bound.requirements(), requirements);
        for class in requirements.classes() {
            let artifact = bound.artifact(class).unwrap();
            assert_eq!(
                artifact.read_small(deadline).is_err(),
                class.is_secret(),
                "{class:?}"
            );
        }
        assert_eq!(
            bound.descriptor_env().count(),
            requirements.classes().len() + 1
        );
    }
}

#[test]
fn a_correct_looking_secret_behind_a_different_descriptor_is_refused() {
    let identities = identities();
    let other_seed = [0x99; 32];
    let other_pool = PoolKeyId::new(briqyard_api::poolkey::id(&"ab".repeat(32)).unwrap()).unwrap();
    let same_length = |usage: Option<Usage>, length: usize| loop {
        let candidate = issue(&Name::dns(SERVER_NAME).unwrap(), usage);
        if candidate.cert.len() == length {
            break candidate;
        }
    };
    let other_server = same_length(Some(Usage::Server), identities.server.cert.len());
    let other_api = same_length(None, identities.daemon_api.cert.len());
    let deadline = StageDeadline::frame("substitution");
    let cases: Vec<(Class, OwnedFd, &str)> = vec![
        (
            Class::Signer(Signer::Hk),
            stage(Class::Signer(Signer::Hk), &other_seed).file.into(),
            MISMATCH,
        ),
        (
            Class::TransitionServerKey,
            stage(Class::TransitionServerKey, &identities.client.key)
                .file
                .into(),
            MISMATCH,
        ),
        (
            Class::TransitionClientKey,
            stage(Class::TransitionClientKey, &identities.server.key)
                .file
                .into(),
            MISMATCH,
        ),
        (
            Class::DaemonApiKey,
            stage(Class::DaemonApiKey, &identities.server.key)
                .file
                .into(),
            MISMATCH,
        ),
        (
            Class::LocalPoolKey,
            FrozenArtifact::freeze_pool_key("ab".repeat(32).as_bytes(), &other_pool, deadline)
                .unwrap()
                .file
                .into(),
            MISMATCH,
        ),
        (
            Class::VerificationRegistry,
            stage(
                Class::VerificationRegistry,
                &registry_json(("q", "auth", *key_public(KEY_SEED).as_array())),
            )
            .file
            .into(),
            DIGEST,
        ),
        (
            Class::TransitionServerCert,
            stage(Class::TransitionServerCert, &other_server.cert)
                .file
                .into(),
            DIGEST,
        ),
        (
            Class::DaemonApiCert,
            stage(Class::DaemonApiCert, &other_api.cert).file.into(),
            DIGEST,
        ),
        (
            Class::ContinuationBearer,
            stage(
                Class::ContinuationBearer,
                b"continuation~Bearer.0123456789?",
            )
            .file
            .into(),
            DIGEST,
        ),
        (
            Class::BackupS3Pair,
            stage(
                Class::BackupS3Pair,
                format!(
                    r#"{{"access":"{}","secret":"{}"}}"#,
                    b64(b"AKIAFIXTUREACCESZ"),
                    b64(b"fixture/secret+kez")
                )
                .as_bytes(),
            )
            .file
            .into(),
            DIGEST,
        ),
    ];
    for (class, replacement, reason) in cases {
        let requirements = if class == Class::ContinuationBearer {
            Requirements::Authority
        } else {
            all_daemon()
        };
        let mut delivered = parts(requirements);
        at(&mut delivered, class).fd = replacement;
        assert_eq!(refusal(bind(requirements, delivered)), reason, "{class:?}");
    }
}

#[test]
fn certificates_and_keys_must_pair_into_two_distinct_identities() {
    let identities = identities();
    let mut swapped = parts(all_daemon());
    let (server, client) = (
        stage(Class::TransitionServerKey, &identities.client.key),
        stage(Class::TransitionClientKey, &identities.server.key),
    );
    for (class, key, bytes) in [
        (Class::TransitionServerKey, server, &identities.client.key),
        (Class::TransitionClientKey, client, &identities.server.key),
    ] {
        let part = at(&mut swapped, class);
        part.descriptor = descriptor_value(class, bytes);
        part.fd = key.file.into();
    }
    assert_eq!(
        refusal(bind(all_daemon(), swapped)),
        "transition certificate and key do not form distinct identities"
    );
}

fn with_admin(cert: &[u8], key: &[u8]) -> Vec<Part> {
    let mut parts = parts(all_daemon());
    for (class, bytes) in [(Class::DaemonApiCert, cert), (Class::DaemonApiKey, key)] {
        let part = at(&mut parts, class);
        part.descriptor = descriptor_value(class, bytes);
        part.fd = stage(class, bytes).file.into();
    }
    parts
}

#[test]
fn binding_every_profile_refuses_under_the_callers_expired_deadline() {
    let expired = || StageDeadline::new("expired delivery test", std::time::Duration::ZERO);
    for requirements in everything() {
        bind(requirements, parts(requirements)).expect("positive control");
        assert!(
            matches!(
                bind_within(requirements, parts(requirements), expired()),
                Err(CustodyError::Deadline { .. })
            ),
            "{requirements:?}"
        );
    }
}

#[test]
fn the_daemon_admin_certificate_must_be_one_complete_leaf_of_its_actual_key() {
    const DISTINCT: &str = "daemon API certificate and key do not form one distinct identity";
    const INVALID: &str = "invalid daemon API identity";
    let identities = identities();
    let admin = &identities.daemon_api;
    bind(all_daemon(), with_admin(&admin.cert, &admin.key)).expect("positive control");

    let other = issue(&Name::dns("other.host.test").unwrap(), None);
    assert_ne!(spki(&other.key), spki(&admin.key));
    assert_eq!(
        refusal(bind(all_daemon(), with_admin(&admin.cert, &other.key))),
        DISTINCT,
        "K1 leaf, K2 key, digest of the K1 leaf and the SPKI of K2 all advertised consistently"
    );
    assert_eq!(
        refusal(bind(all_daemon(), with_admin(&other.cert, &admin.key))),
        DISTINCT
    );

    for (case, cert) in [
        ("trailing byte", [admin.cert.as_slice(), &[0]].concat()),
        (
            "two certificates",
            [admin.cert.as_slice(), &admin.cert].concat(),
        ),
        ("not DER", b"-----BEGIN CERTIFICATE-----".to_vec()),
        ("truncated", admin.cert[..admin.cert.len() - 1].to_vec()),
    ] {
        assert_eq!(
            refusal(bind(all_daemon(), with_admin(&cert, &admin.key))),
            INVALID,
            "{case}"
        );
    }

    for (case, shared) in [
        ("transition server", &identities.server),
        ("transition client", &identities.client),
    ] {
        assert_eq!(
            refusal(bind(all_daemon(), with_admin(&shared.cert, &shared.key))),
            DISTINCT,
            "admin identity equal to the {case} identity"
        );
    }
}

fn raw_secret_fd(bytes: &[u8], mode: u32, seals: libc::c_int, readonly: bool) -> OwnedFd {
    let fd = unsafe {
        libc::memfd_create(
            c"raw-secret".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let file = unsafe { File::from_raw_fd(fd) };
    (&file).write_all(bytes).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .unwrap();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    if readonly {
        File::open(format!("/proc/self/fd/{fd}")).unwrap().into()
    } else {
        file.into()
    }
}

#[test]
fn every_new_private_class_needs_a_sealed_read_only_mode_0400_memfd() {
    let deadline_error = |bytes: &[u8]| bytes.to_vec();
    let _ = deadline_error;
    let all = SEALS;
    for requirements in [all_daemon(), Requirements::Authority] {
        for class in requirements.classes() {
            let secret_suffix = matches!(
                class,
                Class::VerificationRegistry
                    | Class::TransitionServerCert
                    | Class::TransitionServerKey
                    | Class::TransitionClientCert
                    | Class::TransitionClientKey
                    | Class::ContinuationBearer
                    | Class::DaemonApiCert
                    | Class::DaemonApiKey
                    | Class::BackupS3Pair
                    | Class::LocalPoolKey
                    | Class::Signer(_)
            );
            if !secret_suffix {
                continue;
            }
            let bytes = payload(class, 0);
            let variants: Vec<(&str, OwnedFd)> = vec![
                ("writable mode", raw_secret_fd(&bytes, 0o600, all, true)),
                ("group readable", raw_secret_fd(&bytes, 0o440, all, true)),
                ("unsealed", raw_secret_fd(&bytes, 0o400, 0, true)),
                (
                    "growable",
                    raw_secret_fd(
                        &bytes,
                        0o400,
                        libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
                        true,
                    ),
                ),
                (
                    "read-write description",
                    raw_secret_fd(&bytes, 0o400, all, false),
                ),
                (
                    "socket alias",
                    TcpListener::bind("127.0.0.1:0").unwrap().into(),
                ),
            ];
            for (name, fd) in variants {
                let mut delivered = parts(requirements);
                at(&mut delivered, class).fd = fd;
                let error = bind(requirements, delivered)
                    .err()
                    .unwrap_or_else(|| panic!("{class:?} {name}"));
                assert!(
                    matches!(error, CustodyError::Protocol(reason) if [METADATA, "native artifact is not an immutable memfd"].contains(&reason)),
                    "{class:?} {name}: {error}"
                );
                let text = format!("{error:?}");
                for secret in [
                    hex::encode(&bytes),
                    format!("{bytes:?}"),
                    String::from_utf8_lossy(&bytes).into_owned(),
                ] {
                    assert!(!text.contains(&secret), "{class:?} {name}");
                }
            }
        }
    }
}

#[test]
fn a_suffix_descriptor_that_aliases_another_artifact_is_a_duplicate() {
    for requirements in [all_daemon(), Requirements::Authority] {
        let total = requirements.classes().len();
        let first_suffix = if requirements == Requirements::Authority {
            16
        } else {
            13
        };
        for index in first_suffix..total {
            for earlier in [0, 7, first_suffix - 1] {
                let mut delivered = parts(requirements);
                delivered[index].fd = delivered[earlier].fd.try_clone().unwrap();
                let reason = refusal(bind(requirements, delivered));
                assert!(
                    [
                        "native artifact digest mismatch",
                        "duplicate native artifact descriptor",
                        METADATA,
                        MISMATCH
                    ]
                    .contains(&reason),
                    "{index} over {earlier}: {reason}"
                );
            }
        }
    }
    let mut delivered = parts(all_daemon());
    delivered[14].fd = delivered[13].fd.try_clone().unwrap();
    delivered[14].descriptor = delivered[13].descriptor.clone();
    delivered[14].descriptor["class"] = "transition-server-cert".into();
    assert!(bind(all_daemon(), delivered).is_err());
}

fn receive(requirements: Requirements, extra: usize) -> (Vec<u8>, ReceivedAssetFds) {
    let (sender, receiver) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();
    let delivered = parts(requirements);
    let wire = envelope(
        delivered
            .iter()
            .map(|part| part.descriptor.clone())
            .collect(),
    );
    let spare: Vec<OwnedFd> = (0..extra)
        .map(|_| unsafe {
            OwnedFd::from_raw_fd(libc::memfd_create(c"spare".as_ptr(), libc::MFD_CLOEXEC))
        })
        .collect();
    let sending: Vec<RawFd> = delivered
        .iter()
        .map(|part| part.fd.as_raw_fd())
        .chain(spare.iter().map(AsRawFd::as_raw_fd))
        .collect();
    crate::execution_custody::tests::send_raw(sender.as_raw_fd(), &wire, &sending);
    let mut data = vec![0u8; MAX_MESSAGE_BYTES];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE((MAX_ASSET_RIGHTS * 4) as u32) } as usize];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let length =
        unsafe { libc::recvmsg(receiver.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    assert!(length >= 0);
    let mut fds = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let (level, kind, total) = unsafe {
            (
                (*header).cmsg_level,
                (*header).cmsg_type,
                (*header).cmsg_len,
            )
        };
        assert_eq!((level, kind), (libc::SOL_SOCKET, libc::SCM_RIGHTS));
        let count = (total - unsafe { libc::CMSG_LEN(0) } as usize) / 4;
        for offset in 0..count {
            let raw = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(offset))
            };
            fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    let truncated = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
    (
        data[..length as usize].to_vec(),
        ReceivedAssetFds {
            fds,
            truncated,
            unexpected_control: false,
            queued_packet: false,
        },
    )
}

#[test]
fn all_twenty_two_rights_survive_one_real_packet_and_a_twenty_third_is_truncation() {
    let deadline = StageDeadline::frame("ancillary bound");
    for requirements in [all_daemon(), Requirements::Authority] {
        let (wire, packet) = receive(requirements, 0);
        assert_eq!(packet.fds.len(), 22);
        assert!(!packet.truncated);
        let offer = AssetOffer::decode(requirements, &wire).unwrap();
        let bound =
            BoundAssets::bind(requirements, offer, packet, &no_listeners(), deadline).unwrap();
        for (index, class) in requirements.classes().into_iter().enumerate() {
            assert!(bound.artifact(class).is_some(), "{index} {class:?}");
        }
        let (wire, packet) = receive(requirements, 1);
        assert!(packet.truncated, "a twenty-third right does not fit");
        assert_eq!(packet.fds.len(), 22);
        let offer = AssetOffer::decode(requirements, &wire).unwrap();
        let result = BoundAssets::bind(requirements, offer, packet, &no_listeners(), deadline);
        assert_eq!(refusal(result), "invalid native asset packet delivery");
    }
}

pub(super) fn fixture_suffix_close() {
    let before = open_descriptors().unwrap().len();
    for requirements in [
        all_daemon(),
        Requirements::Authority,
        requirements(Resource::Daemon),
    ] {
        let classes = requirements.classes();
        let first_suffix = classes
            .iter()
            .position(|c| *c == Class::VerificationRegistry)
            .unwrap();
        drop(bind(requirements, parts(requirements)).unwrap());
        assert_eq!(
            open_descriptors().unwrap().len(),
            before,
            "success then drop"
        );
        let mutations: Vec<(&str, Mutation)> = vec![
            ("pop", Box::new(|p| drop(p.pop()))),
            (
                "swap",
                Box::new(|p| {
                    let (low, high) = p.split_at_mut(1);
                    std::mem::swap(&mut low[0].fd, &mut high[0].fd);
                }),
            ),
            (
                "socket alias",
                Box::new(move |p| {
                    p[first_suffix].fd = TcpListener::bind("127.0.0.1:0").unwrap().into()
                }),
            ),
            (
                "bad mode",
                Box::new(move |p| {
                    let class = p[first_suffix + 2].class;
                    p[first_suffix + 2].fd = raw_secret_fd(&payload(class, 0), 0o600, SEALS, true);
                }),
            ),
            (
                "wrong key",
                Box::new(move |p| {
                    p[first_suffix + 2].fd =
                        stage(Class::TransitionServerKey, &identities().client.key)
                            .file
                            .into();
                }),
            ),
            (
                "clone",
                Box::new(move |p| p[first_suffix + 1].fd = p[first_suffix].fd.try_clone().unwrap()),
            ),
        ];
        let identities = identities();
        let mut swapped = parts(requirements);
        for (class, bytes) in [
            (Class::TransitionServerKey, &identities.client.key),
            (Class::TransitionClientKey, &identities.server.key),
        ] {
            let part = at(&mut swapped, class);
            part.descriptor = descriptor_value(class, bytes);
            part.fd = stage(class, bytes).file.into();
        }
        assert!(bind(requirements, swapped).is_err());
        assert_eq!(
            open_descriptors().unwrap().len(),
            before,
            "identity refusal {requirements:?}"
        );
        for (name, mutate) in mutations {
            let mut delivered = parts(requirements);
            let wire = envelope(
                delivered
                    .iter()
                    .map(|part| part.descriptor.clone())
                    .collect(),
            );
            mutate(&mut delivered);
            let offer = AssetOffer::decode(requirements, &wire).unwrap();
            let result = BoundAssets::bind(
                requirements,
                offer,
                ReceivedAssetFds {
                    fds: delivered.into_iter().map(|part| part.fd).collect(),
                    truncated: name == "swap",
                    unexpected_control: false,
                    queued_packet: false,
                },
                &no_listeners(),
                StageDeadline::frame("close on refusal"),
            );
            assert!(result.is_err(), "{name}");
            drop(result);
            assert_eq!(
                open_descriptors().unwrap().len(),
                before,
                "refusal {name} {requirements:?}"
            );
        }
    }
}

#[test]
fn every_received_descriptor_is_closed_on_success_and_on_every_refusal() {
    let mut child = FixtureChild::spawn("suffix", Stdio::null());
    assert!(child.wait().success());
}
