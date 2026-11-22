use super::*;
use crate::execution_custody::artifacts::{
    AssetOffer, Class, Descriptor, FrozenArtifact, ListenerEnv, Member as AssetMember,
    ReceivedAssetFds, Signer as AssetSigner,
};
use briqyard_api::execution::sealed::{
    custody::{CaptureBody, CustodyWire, Slot},
    encode, h,
    objects::{Members, Proc, Reg, X},
    prim::{BootId, Build, Env, Ident, KeyBytes, Nonce, PosInt, SigBytes, Uint},
    sig::{Signer, Tag},
    transition::{Bearer, LDecision, LKind, LaunchStage, Member, Secrets},
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    fs::File, io::Write, os::fd::AsFd, os::fd::OwnedFd, os::unix::fs::MetadataExt, path::PathBuf,
};

const INPUTS: &[u8] = b"synthetic opaque inputs, intentionally not a manifest codec";
const CANDIDATE: &[u8] = b"\x7fELFsynthetic candidate bytes, not an executable";
const CONFIG: &[u8] = b"synthetic config";
const CERT: &[u8] = b"synthetic certificate";
const TLS_KEY: &[u8] = b"synthetic TLS key";

fn ordinary_profile(vector: usize) -> Vec<u8> {
    let signer = FixtureSigner::from_test_vector(vector);
    let seed = [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    ][vector - 1];
    let mut bytes = hex::decode("3051020101300506032b657004220420").unwrap();
    bytes.extend(hex::decode(seed).unwrap());
    bytes.extend([0x81, 0x21, 0x00]);
    bytes.extend(signer.key().as_array());
    bytes
}

fn sealed_key_fd(bytes: &[u8]) -> OwnedFd {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;
    let fd = unsafe {
        libc::memfd_create(
            c"synthetic-ordinary-key".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let file = unsafe { File::from_raw_fd(fd) };
    (&file).write_all(bytes).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o400))
        .unwrap();
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    File::open(format!("/proc/self/fd/{fd}")).unwrap().into()
}

struct FixtureSigner(Ed25519KeyPair);

impl FixtureSigner {
    fn from_test_vector(vector: usize) -> Self {
        let seed = [
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        ][vector - 1];
        Self(Ed25519KeyPair::from_seed_unchecked(&hex::decode(seed).unwrap()).unwrap())
    }

    fn key(&self) -> KeyBytes {
        KeyBytes::from_array(self.public_key())
    }
}

impl Signer for FixtureSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key().as_ref().try_into().unwrap()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).as_ref().try_into().unwrap()
    }
}

fn n(byte: u8) -> Nonce {
    Nonce::from_array([byte; 32])
}

fn proc(pid: u64) -> Proc {
    Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000004").unwrap(),
        pid: PosInt::new(pid).unwrap(),
        start: PosInt::new(912).unwrap(),
        exe: HexDigest::from_raw([0x33; 32]),
        build: Build::new("fence-3").unwrap(),
    }
}

fn bearer(member: Member, offset: u8) -> Bearer {
    let test_byte = match member {
        Member::Hi => 1,
        Member::He => 2,
        Member::Ni => 3,
        Member::Ng => 4,
        Member::Tr => 5,
    };
    Bearer::from_random(&n(test_byte + offset))
}

fn members(offset: u8) -> Members {
    Members {
        hi: bearer(Member::Hi, offset).digest(),
        he: bearer(Member::He, offset).digest(),
        ni: bearer(Member::Ni, offset).digest(),
        ng: bearer(Member::Ng, offset).digest(),
        tr: Some(bearer(Member::Tr, offset).digest()),
    }
}

fn directory_path(resource: Resource, x: &X) -> PathBuf {
    let (base, leaf) = match resource {
        Resource::Daemon => ("/var/lib/briqyard", "daemon"),
        Resource::Authority => ("/var/lib/briq-execution-authority", "authority"),
    };
    format!("{base}/sealed-ops/{}/{}/{leaf}", x.op, x.serial.get()).into()
}

struct Fixture {
    resource: Resource,
    rk: FixtureSigner,
    bk: FixtureSigner,
    plan: Plan,
    launch: Launch,
    decision: LDecision,
    wire: CustodyWire,
    inputs: Vec<u8>,
}

impl Fixture {
    fn new(resource: Resource) -> Self {
        Self::with_predecessor_key(resource, 5)
    }

    fn with_predecessor_key(resource: Resource, vector: usize) -> Self {
        let rk = FixtureSigner::from_test_vector(1);
        let bk = FixtureSigner::from_test_vector(2);
        let ak = FixtureSigner::from_test_vector(3).key();
        let hk = FixtureSigner::from_test_vector(4).key();
        let ordinary_key = FixtureSigner::from_test_vector(5).key();
        let id = |value| Ident::new(value).unwrap();
        let x = X {
            aud: Env::Staging,
            host: id("host.test"),
            op: HexDigest::from_raw([0; 32]),
            serial: PosInt::new(1).unwrap(),
        };
        let pre_record = Reg {
            authority: id("auth"),
            epoch: id("ep"),
            key_id: id("k"),
            public_key: *FixtureSigner::from_test_vector(vector).key().as_array(),
            host_instance: id("hi"),
            generation: PosInt::new(2).unwrap(),
        };
        let (old, action) = match resource {
            Resource::Daemon => (proc(12), LKind::LaunchD),
            Resource::Authority => (proc(13), LKind::LaunchA),
        };
        let (next_d, next_a) = match resource {
            Resource::Daemon => (HexDigest::of(CANDIDATE), HexDigest::of(b"other image")),
            Resource::Authority => (HexDigest::of(b"other image"), HexDigest::of(CANDIDATE)),
        };
        let plan = Plan {
            pre: pre_record.ctx(&x.host),
            x,
            registered: id("hi"),
            pre_record,
            pre_intent: id("original.intent"),
            pre_d: proc(12),
            pre_a: proc(13),
            next_d,
            next_a,
            dbuild: Build::new("next-daemon").unwrap(),
            abuild: Build::new("next-authority").unwrap(),
            old: members(80),
            new: members(0),
            hk,
            ak,
            bk: bk.key(),
            rk: rk.key(),
            ordinary_key,
            exception: HexDigest::of(b"synthetic exception"),
            inputs: HexDigest::of(INPUTS),
        };
        let launch = Launch {
            x: plan.x.clone(),
            plan: h(&plan).unwrap(),
            resource,
            owner: n(27),
            stage: LaunchStage::Consumed,
            old,
            custodian: proc(10),
            successor: None,
            death: None,
            nonce: n(28),
        };
        let decision = LDecision {
            x: launch.x.clone(),
            plan: launch.plan.clone(),
            action,
            owner: launch.owner,
            expected: launch.old.clone(),
            nonce: n(29),
        };
        let wire = CustodyWire {
            x: launch.x.clone(),
            plan: launch.plan.clone(),
            resource,
            owner: launch.owner,
            custodian: launch.custodian.clone(),
            old: launch.old.clone(),
            next: None,
            challenge: launch.nonce,
            slot: Slot::new(27).unwrap(),
        };
        Self {
            resource,
            rk,
            bk,
            plan,
            launch,
            decision,
            wire,
            inputs: INPUTS.to_vec(),
        }
    }

    fn grant(&self) -> LGrant {
        LGrant {
            receiver: Sig::sign(Tag::LaunchReceiver, self.decision.clone(), &self.rk).unwrap(),
            api: Sig::sign(Tag::LaunchApi, self.decision.clone(), &self.bk).unwrap(),
        }
    }

    fn capture_load(&self) -> CaptureLoad {
        let capture = Sig::sign(
            Tag::CustodyCapture,
            CaptureBody {
                wire: self.wire.clone(),
            },
            &self.rk,
        )
        .unwrap();
        let load = LoadBody {
            x: self.launch.x.clone(),
            plan: self.launch.plan.clone(),
            resource: self.launch.resource,
            owner: self.launch.owner,
            launch: h(&self.launch).unwrap(),
            capture: h(&capture).unwrap(),
        };
        CaptureLoad {
            capture,
            load: Sig::sign(Tag::CustodyLoad, load, &self.rk).unwrap(),
        }
    }

    fn directory(&self) -> OperationDirectory {
        OperationDirectory::parse(self.resource, &directory_path(self.resource, &self.plan.x))
            .unwrap()
    }

    fn bind(
        &self,
        grant: &LGrant,
        capture_load: &CaptureLoad,
        tweak: impl FnOnce(&mut Vec<(Descriptor, Vec<u8>)>),
        deadline: StageDeadline,
    ) -> BoundAssets {
        let mut assets = Vec::new();
        let mut add = |parts: fn(Uint, HexDigest) -> Descriptor, bytes: Vec<u8>| {
            assets.push((
                parts(
                    Uint::new(bytes.len() as u64).unwrap(),
                    HexDigest::of(&bytes),
                ),
                bytes,
            ));
        };
        add(
            |bytes, digest| Descriptor::Plan { bytes, digest },
            encode(&self.plan).unwrap(),
        );
        add(
            |bytes, digest| Descriptor::Launch { bytes, digest },
            encode(&self.launch).unwrap(),
        );
        add(
            |bytes, digest| Descriptor::Grant { bytes, digest },
            encode(grant).unwrap(),
        );
        add(
            |bytes, digest| Descriptor::Inputs { bytes, digest },
            self.inputs.clone(),
        );
        add(
            |bytes, digest| Descriptor::Candidate { bytes, digest },
            CANDIDATE.to_vec(),
        );
        add(
            |bytes, digest| Descriptor::Config { bytes, digest },
            CONFIG.to_vec(),
        );
        add(
            |bytes, digest| Descriptor::CaptureLoad { bytes, digest },
            encode(capture_load).unwrap(),
        );
        let mut members = vec![(AssetMember::Hi, Member::Hi), (AssetMember::He, Member::He)];
        if self.resource == Resource::Authority {
            members.extend([(AssetMember::Ni, Member::Ni), (AssetMember::Ng, Member::Ng)]);
        }
        members.push((AssetMember::Tr, Member::Tr));
        for (asset, member) in members {
            let value = bearer(member, 0);
            let member_hash = value.digest();
            let bytes = encode(&Secrets {
                x: self.plan.x.clone(),
                plan: h(&self.plan).unwrap(),
                member,
                value,
            })
            .unwrap();
            let descriptor = Descriptor::Member {
                bytes: Uint::new(bytes.len() as u64).unwrap(),
                digest: HexDigest::of(&bytes),
                member: asset,
                member_hash,
            };
            assets.push((descriptor, bytes));
        }
        let (role, public) = if self.resource == Resource::Daemon {
            (AssetSigner::Hk, self.plan.hk)
        } else {
            (AssetSigner::Ak, self.plan.ak)
        };
        let signer = b"synthetic opaque signer handle";
        assets.push((
            Descriptor::Signer {
                bytes: Uint::new(signer.len() as u64).unwrap(),
                role,
                public,
            },
            signer.to_vec(),
        ));
        for (class, data) in [(Class::TlsCert, CERT), (Class::TlsKey, TLS_KEY)] {
            let bytes = Uint::new(data.len() as u64).unwrap();
            let digest = HexDigest::of(data);
            let desc = if class == Class::TlsCert {
                Descriptor::TlsCert { bytes, digest }
            } else {
                Descriptor::TlsKey { bytes, digest }
            };
            assets.push((desc, data.to_vec()));
        }
        if self.resource == Resource::Authority {
            assets.push((
                Descriptor::OrdinaryAuthorityKey {
                    bytes: Uint::new(83).unwrap(),
                    public: self.plan.ordinary_key,
                },
                ordinary_profile(5),
            ));
        }
        tweak(&mut assets);
        let mut fds = Vec::new();
        let descriptors = assets
            .into_iter()
            .map(|(descriptor, bytes)| {
                if descriptor.class() == Class::OrdinaryAuthorityKey {
                    fds.push(sealed_key_fd(&bytes));
                    return descriptor;
                }
                let mut source = tempfile::NamedTempFile::new().unwrap();
                source.write_all(&bytes).unwrap();
                let file = File::open(source.path()).unwrap();
                let artifact = FrozenArtifact::freeze(
                    &file,
                    file.metadata().unwrap().uid(),
                    descriptor.class(),
                    bytes.len() as u64,
                    &HexDigest::of(&bytes),
                    deadline,
                )
                .unwrap();
                fds.push(artifact.as_fd().try_clone_to_owned().unwrap());
                descriptor
            })
            .collect();
        let packet = AssetOffer::encode(self.resource, descriptors).unwrap();
        let offer = AssetOffer::decode(self.resource, &packet).unwrap();
        let listeners = ListenerEnv::verify(&std::process::id().to_string(), "0", "", &[]).unwrap();
        BoundAssets::bind(
            self.resource,
            offer,
            ReceivedAssetFds {
                fds,
                truncated: false,
                queued_packet: false,
                unexpected_control: false,
            },
            &listeners,
            deadline,
        )
        .unwrap()
    }

    fn decode(
        &self,
        grant: &LGrant,
        capture_load: &CaptureLoad,
    ) -> Result<SealedInput, CustodyError> {
        let deadline = StageDeadline::frame("synthetic startup fixtures");
        let assets = self.bind(grant, capture_load, |_| {}, deadline);
        SealedInput::decode(assets, &self.directory(), &h(&self.plan).unwrap(), deadline)
    }

    fn verify(&self) -> Result<SealedInput, CustodyError> {
        self.decode(&self.grant(), &self.capture_load())
    }
}

fn rejected(result: Result<SealedInput, CustodyError>, why: &'static str) {
    match result {
        Ok(_) => panic!("accepted: {why}"),
        Err(error) => assert!(
            matches!(error, CustodyError::Protocol(reason) if reason == why),
            "{error}"
        ),
    }
}

#[test]
fn exact_daemon_and_authority_bundles_preserve_typed_records_and_opaque_inputs() {
    for resource in [Resource::Daemon, Resource::Authority] {
        let fixture = Fixture::new(resource);
        let decoded = fixture.verify().unwrap();
        assert_eq!(decoded.plan(), &fixture.plan);
        assert_eq!(decoded.launch(), &fixture.launch);
        assert_eq!(decoded.grant(), &fixture.grant());
        assert_eq!(decoded.capture(), &fixture.capture_load().capture);
        assert_eq!(decoded.load(), &fixture.capture_load().load);
        assert!(decoded.inputs_bytes() == INPUTS);
        if resource == Resource::Authority {
            let key = decoded.ordinary_authority_key().unwrap();
            assert_eq!(key.public(), *fixture.plan.ordinary_key.as_array());
            assert_eq!(key.public(), fixture.plan.pre_record.public_key);
            let artifact = decoded.artifact(Class::OrdinaryAuthorityKey).unwrap();
            assert!(artifact
                .read_small(StageDeadline::frame("no raw read"))
                .is_err());
        } else {
            assert!(decoded.artifact(Class::OrdinaryAuthorityKey).is_none());
            assert!(decoded.ordinary_authority_key().is_err());
        }
    }
}

fn decode_with_key(
    fixture: &Fixture,
    change: impl FnOnce(&mut (Descriptor, Vec<u8>)),
) -> Result<SealedInput, CustodyError> {
    let deadline = StageDeadline::frame("synthetic startup fixtures");
    let assets = fixture.bind(
        &fixture.grant(),
        &fixture.capture_load(),
        |assets| change(assets.last_mut().unwrap()),
        deadline,
    );
    SealedInput::decode(
        assets,
        &fixture.directory(),
        &h(&fixture.plan).unwrap(),
        deadline,
    )
}

#[test]
fn the_actual_key_must_derive_the_advertised_and_independently_pinned_public_key() {
    let fixture = Fixture::new(Resource::Authority);
    assert!(decode_with_key(&fixture, |_| {}).is_ok());
    for substitute in [1, 3, 4] {
        rejected(
            decode_with_key(&fixture, |(_, bytes)| *bytes = ordinary_profile(substitute)),
            "startup ordinary key public binding",
        );
    }
    rejected(
        decode_with_key(&fixture, |(_, bytes)| bytes[60] ^= 1),
        "invalid ordinary authority key",
    );
    rejected(
        decode_with_key(&fixture, |(_, bytes)| {
            bytes[16..48].copy_from_slice(&ordinary_profile(4)[16..48])
        }),
        "invalid ordinary authority key",
    );
    rejected(
        decode_with_key(&fixture, |(entry, _)| {
            let Descriptor::OrdinaryAuthorityKey { public, .. } = entry else {
                panic!()
            };
            *public = FixtureSigner::from_test_vector(3).key();
        }),
        "startup asset plan pins",
    );
    rejected(
        decode_with_key(&fixture, |(entry, bytes)| {
            *bytes = ordinary_profile(3);
            let Descriptor::OrdinaryAuthorityKey { public, .. } = entry else {
                panic!()
            };
            *public = FixtureSigner::from_test_vector(3).key();
        }),
        "startup asset plan pins",
    );
    let predecessor = Fixture::with_predecessor_key(Resource::Authority, 4);
    rejected(
        decode_with_key(&predecessor, |_| {}),
        "startup asset plan pins",
    );
}

#[test]
fn the_key_is_not_supplied_before_a_consumed_launch() {
    let mut fixture = Fixture::new(Resource::Authority);
    fixture.launch.stage = LaunchStage::Captured;
    rejected(fixture.verify(), "startup launch scope or stage");
}

#[test]
fn exact_signed_bodies_cannot_select_a_different_action_owner_or_old_process() {
    for action in [LKind::Seal, LKind::LaunchA] {
        let mut fixture = Fixture::new(Resource::Daemon);
        fixture.decision.action = action;
        rejected(fixture.verify(), "startup grant action");
    }
    for mutate in [
        |decision: &mut LDecision| decision.x.aud = Env::Production,
        |decision: &mut LDecision| decision.owner = n(81),
        |decision: &mut LDecision| decision.expected = proc(90),
        |decision: &mut LDecision| decision.plan = HexDigest::of(b"another plan"),
    ] {
        let mut fixture = Fixture::new(Resource::Daemon);
        mutate(&mut fixture.decision);
        rejected(fixture.verify(), "startup grant launch scope");
    }
    let mut fixture = Fixture::new(Resource::Daemon);
    fixture.decision.nonce = fixture.launch.nonce;
    rejected(fixture.verify(), "startup grant reuses capture nonce");
}

#[test]
fn correct_looking_grants_require_both_exact_signatures_and_identical_bodies() {
    let fixture = Fixture::new(Resource::Daemon);
    for first in [false, true] {
        let mut grant = fixture.grant();
        if first {
            grant.receiver.sig = SigBytes::from_array([0; 64]);
        } else {
            grant.api.sig = SigBytes::from_array([0; 64]);
        }
        rejected(
            fixture.decode(&grant, &fixture.capture_load()),
            "startup grant signatures",
        );
    }
    let mut grant = fixture.grant();
    let mut other = fixture.decision.clone();
    other.nonce = n(55);
    grant.api = Sig::sign(Tag::LaunchApi, other, &fixture.bk).unwrap();
    rejected(
        fixture.decode(&grant, &fixture.capture_load()),
        "invalid startup grant record",
    );
    let mut grant = fixture.grant();
    grant.api = Sig::sign(Tag::LaunchApi, fixture.decision.clone(), &fixture.rk).unwrap();
    rejected(
        fixture.decode(&grant, &fixture.capture_load()),
        "startup grant signatures",
    );
}

#[test]
fn unconsumed_launch_or_wrong_selected_resource_is_not_startup_evidence() {
    let mut fixture = Fixture::new(Resource::Authority);
    fixture.launch.stage = LaunchStage::Captured;
    rejected(fixture.verify(), "startup launch scope or stage");
    fixture.launch.stage = LaunchStage::Consumed;
    fixture.launch.resource = Resource::Daemon;
    rejected(fixture.verify(), "startup launch scope or stage");
}

#[test]
fn capture_challenge_and_all_capture_scope_match_launch() {
    for mutate in [
        |wire: &mut CustodyWire| wire.challenge = n(29),
        |wire: &mut CustodyWire| wire.custodian = proc(90),
        |wire: &mut CustodyWire| wire.old = proc(91),
        |wire: &mut CustodyWire| wire.owner = n(90),
        |wire: &mut CustodyWire| wire.plan = HexDigest::of(b"another plan"),
        |wire: &mut CustodyWire| wire.resource = Resource::Authority,
        |wire: &mut CustodyWire| wire.x.host = Ident::new("elsewhere").unwrap(),
    ] {
        let mut fixture = Fixture::new(Resource::Daemon);
        mutate(&mut fixture.wire);
        rejected(fixture.verify(), "startup capture launch scope");
    }
}

#[test]
fn load_binds_the_whole_consumed_snapshot_and_capture_envelope() {
    let fixture = Fixture::new(Resource::Daemon);
    for mutate in [
        |load: &mut LoadBody| load.launch = HexDigest::of(b"another launch"),
        |load: &mut LoadBody| load.capture = HexDigest::of(b"capture body only"),
        |load: &mut LoadBody| load.resource = Resource::Authority,
        |load: &mut LoadBody| load.owner = n(92),
        |load: &mut LoadBody| load.plan = HexDigest::of(b"another plan"),
        |load: &mut LoadBody| load.x.serial = PosInt::new(2).unwrap(),
    ] {
        let mut capture_load = fixture.capture_load();
        let mut load = capture_load.load.body.clone();
        mutate(&mut load);
        capture_load.load = Sig::sign(Tag::CustodyLoad, load, &fixture.rk).unwrap();
        rejected(
            fixture.decode(&fixture.grant(), &capture_load),
            "startup load launch or capture scope",
        );
    }
    let mut capture_load = fixture.capture_load();
    capture_load.capture =
        Sig::sign(Tag::CustodyLoad, capture_load.capture.body, &fixture.rk).unwrap();
    rejected(
        fixture.decode(&fixture.grant(), &capture_load),
        "startup capture signature",
    );
    let mut capture_load = fixture.capture_load();
    capture_load.load =
        Sig::sign(Tag::CustodyCapture, capture_load.load.body, &fixture.rk).unwrap();
    rejected(
        fixture.decode(&fixture.grant(), &capture_load),
        "startup load signature",
    );
    let mut capture_load = fixture.capture_load();
    capture_load.capture.body.wire.next = Some(proc(19));
    rejected(
        fixture.decode(&fixture.grant(), &capture_load),
        "invalid startup capture/load record",
    );
}

#[test]
fn valid_descriptor_integrity_cannot_replace_the_pinned_manifest_bytes() {
    let mut fixture = Fixture::new(Resource::Daemon);
    fixture.inputs = b"substituted exact bytes with their correct offer digest".to_vec();
    rejected(fixture.verify(), "startup asset plan pins");
}

#[test]
fn a_self_consistent_bundle_cannot_replace_an_independent_plan_pin() {
    let fixture = Fixture::new(Resource::Daemon);
    let deadline = StageDeadline::frame("synthetic startup fixtures");
    let assets = fixture.bind(&fixture.grant(), &fixture.capture_load(), |_| {}, deadline);
    rejected(
        SealedInput::decode(
            assets,
            &fixture.directory(),
            &HexDigest::of(b"external plan commitment"),
            deadline,
        ),
        "startup plan commitment",
    );
}

#[test]
fn candidate_signer_and_member_offer_metadata_are_checked_against_the_decoded_plan() {
    let fixture = Fixture::new(Resource::Daemon);
    let grant = fixture.grant();
    let capture_load = fixture.capture_load();
    for change in [
        |(entry, payload): &mut (Descriptor, Vec<u8>)| {
            if let Descriptor::Candidate { bytes, digest } = entry {
                *payload = b"\x7fELFwrong synthetic candidate".to_vec();
                *bytes = Uint::new(payload.len() as u64).unwrap();
                *digest = HexDigest::of(payload);
            }
        },
        |(entry, _): &mut (Descriptor, Vec<u8>)| {
            if let Descriptor::Signer { public, .. } = entry {
                *public = FixtureSigner::from_test_vector(3).key();
            }
        },
        |(entry, _): &mut (Descriptor, Vec<u8>)| {
            if let Descriptor::Member {
                member_hash,
                member: AssetMember::Hi,
                ..
            } = entry
            {
                *member_hash = bearer(Member::He, 0).digest();
            }
        },
    ] {
        let deadline = StageDeadline::frame("synthetic startup fixtures");
        let assets = fixture.bind(
            &grant,
            &capture_load,
            |assets| {
                assets.iter_mut().for_each(change);
            },
            deadline,
        );
        rejected(
            SealedInput::decode(
                assets,
                &fixture.directory(),
                &h(&fixture.plan).unwrap(),
                deadline,
            ),
            "startup asset plan pins",
        );
    }
}

#[test]
fn explicit_config_and_tls_pins_only_match_the_original_bound_descriptors() {
    let fixture = Fixture::new(Resource::Daemon);
    let input = fixture.verify().unwrap();
    let mut pins = ConfigTlsPins {
        config: HexDigest::of(CONFIG),
        cert: HexDigest::of(CERT),
        key: HexDigest::of(TLS_KEY),
    };
    input.check_config_tls_pins(&pins).unwrap();
    std::mem::swap(&mut pins.cert, &mut pins.key);
    assert!(matches!(
        input.check_config_tls_pins(&pins),
        Err(CustodyError::Protocol("startup config or TLS pin"))
    ));
}

#[test]
fn member_envelopes_must_match_the_frozen_descriptor_scope_and_bearer_digest() {
    let fixture = Fixture::new(Resource::Authority);
    let verify = |field: &str, replacement: serde_json::Value| {
        let deadline = StageDeadline::frame("synthetic startup fixtures");
        let assets = fixture.bind(
            &fixture.grant(),
            &fixture.capture_load(),
            |assets| {
                let (Descriptor::Member { bytes, digest, .. }, payload) = &mut assets[9] else {
                    panic!("expected the synthetic ni descriptor");
                };
                let mut secret: serde_json::Value = serde_json::from_slice(payload).unwrap();
                secret[field] = replacement;
                *payload = encode(&secret).unwrap();
                *bytes = Uint::new(payload.len() as u64).unwrap();
                *digest = HexDigest::of(payload);
            },
            deadline,
        );
        SealedInput::decode(
            assets,
            &fixture.directory(),
            &h(&fixture.plan).unwrap(),
            deadline,
        )
    };
    rejected(
        verify("member", serde_json::json!("ng")),
        "startup member role",
    );
    rejected(
        verify("plan", serde_json::json!(HexDigest::of(b"other"))),
        "startup member scope or digest",
    );
    rejected(
        verify("value", serde_json::json!(bearer(Member::Ng, 0))),
        "startup member scope or digest",
    );
    let malformed_secret = "synthetic invalid bearer";
    rejected(
        verify("value", serde_json::json!(malformed_secret)),
        "invalid startup member envelope",
    );
}

#[test]
fn selector_rejects_lexical_aliases_and_requires_the_decoded_operation() {
    let fixture = Fixture::new(Resource::Daemon);
    let valid = directory_path(fixture.resource, &fixture.plan.x);
    let text = valid.to_str().unwrap();
    for bad in [
        String::new(),
        text[1..].to_owned(),
        format!("{text}/"),
        text.replace("/sealed-ops/", "//sealed-ops/"),
        text.replace("/sealed-ops/", "/./sealed-ops/"),
        text.replace("/1/", "/../1/"),
        text.replace("/1/", "/01/"),
        text.replace("/1/", "/+1/"),
        text.replace("/daemon", "/authority"),
    ] {
        assert!(OperationDirectory::parse(fixture.resource, Path::new(&bad)).is_err());
    }
    let deadline = StageDeadline::frame("synthetic startup fixtures");
    let assets = fixture.bind(&fixture.grant(), &fixture.capture_load(), |_| {}, deadline);
    let path = text.replace("/1/", "/2/");
    let other = OperationDirectory::parse(fixture.resource, Path::new(&path)).unwrap();
    rejected(
        SealedInput::decode(assets, &other, &h(&fixture.plan).unwrap(), deadline),
        "startup operation directory scope",
    );
}
