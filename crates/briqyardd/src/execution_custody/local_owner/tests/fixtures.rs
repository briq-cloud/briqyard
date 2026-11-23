use super::super::*;
use crate::execution_custody::plan_reader::{Ownership, TrustLoader};
use briqyard_api::execution::sealed::{
    canonical::{encode, h},
    custody::{CaptureBody, CustodyWire, Slot},
    objects::{Members, Plan, Proc, Reg, X},
    owner::{FragmentState, JobState, TurnBody, UnitState},
    plan_pin::{reg_hash, TrustFormat, TrustRecord},
    prim::{BootId, Build, Env, KeyBytes, Nonce, PosInt},
    sig::{Sig, Signer, Tag},
    transition::{LDecision, LKind, Launch, LaunchStage},
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub(super) const BOOT: &str = "00000000-0000-4000-8000-000000000004";

pub(super) struct Key(Ed25519KeyPair);

impl Key {
    fn vector(hex_seed: &str) -> Self {
        let seed: [u8; 32] = hex::decode(hex_seed).unwrap().try_into().unwrap();
        Self(Ed25519KeyPair::from_seed_unchecked(&seed).unwrap())
    }
    pub(super) fn rk() -> Self {
        Self::vector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    }
    pub(super) fn bk() -> Self {
        Self::vector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    }
    pub(super) fn hk() -> Self {
        Self::vector("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    }
    pub(super) fn attacker() -> Self {
        Self::vector("0707070707070707070707070707070707070707070707070707070707070707")
    }
    pub(super) fn key(&self) -> KeyBytes {
        KeyBytes::from_array(self.public_key())
    }
}

impl Signer for Key {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key().as_ref().try_into().unwrap()
    }
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).as_ref().try_into().unwrap()
    }
}

pub(super) fn id(text: &str) -> Ident {
    Ident::new(text).unwrap()
}

pub(super) fn digest(byte: u8) -> HexDigest {
    HexDigest::from_raw([byte; 32])
}

pub(super) fn proc(pid: u64, exe: u8) -> Proc {
    Proc {
        boot: BootId::new(BOOT).unwrap(),
        pid: PosInt::new(pid).unwrap(),
        start: PosInt::new(900 + pid).unwrap(),
        exe: digest(exe),
        build: Build::new("fence-3").unwrap(),
    }
}

pub(super) fn measured(proc: &Proc) -> MeasuredProc {
    MeasuredProc {
        boot: proc.boot.clone(),
        pid: proc.pid.get(),
        start: proc.start.get(),
        exe: proc.exe.clone(),
    }
}

pub(super) fn x() -> X {
    X {
        aud: Env::Staging,
        host: id("host.test"),
        op: digest(0),
        serial: PosInt::new(1).unwrap(),
    }
}

pub(super) fn plan() -> Plan {
    let record = Reg {
        authority: id("auth"),
        epoch: id("ep"),
        key_id: id("k"),
        public_key: [5; 32],
        host_instance: id("hi"),
        generation: PosInt::new(2).unwrap(),
    };
    let members = |byte: u8| Members {
        hi: digest(byte),
        he: digest(byte + 2),
        ni: digest(byte + 4),
        ng: digest(byte + 6),
        tr: None,
    };
    Plan {
        pre: record.ctx(&x().host),
        x: x(),
        registered: id("registered.test"),
        pre_record: record,
        pre_intent: id("pre"),
        pre_d: proc(10, 0x33),
        pre_a: proc(12, 0x34),
        next_d: digest(0xa),
        next_a: digest(0xb),
        dbuild: Build::new("fence-3").unwrap(),
        abuild: Build::new("fence-3").unwrap(),
        old: members(1),
        new: members(0x21),
        hk: Key::hk().key(),
        ak: KeyBytes::from_array([2; 32]),
        bk: Key::bk().key(),
        rk: Key::rk().key(),
        ordinary_key: KeyBytes::from_array([5; 32]),
        exception: digest(0xc),
        inputs: digest(0xd),
    }
}

pub(super) fn unit(byte: u8) -> UnitMeasure {
    UnitMeasure {
        fragment: digest(byte),
        argv: digest(byte + 1),
        sandbox: digest(byte + 2),
        fdstore: digest(byte + 3),
        job: JobState::None,
        state: UnitState::Active,
        reloaded: true,
    }
}

pub(super) struct HostState {
    pub boot: BootId,
    pub procs: HashMap<u64, MeasuredProc>,
    pub fragments: [FragmentState; 2],
    pub units: [UnitMeasure; 2],
    pub guards: [HexDigest; 2],
    pub unit_procs: [Option<MeasuredProc>; 2],
    pub final_io: [bool; 2],
    /// Process and boot measurement fail, as an unreadable /proc would.
    pub unreadable: bool,
}

pub(super) struct Host(pub Mutex<HostState>);

fn index(resource: Resource) -> usize {
    match resource {
        Resource::Daemon => 0,
        Resource::Authority => 1,
    }
}

impl TargetFacts for Arc<Host> {
    fn boot(&self) -> Result<BootId, OwnerError> {
        let state = self.0.lock().unwrap();
        if state.unreadable {
            return Err(OwnerError::Refused("fixture boot is unreadable"));
        }
        Ok(state.boot.clone())
    }
    fn process(&self, pid: u64) -> Result<Option<MeasuredProc>, OwnerError> {
        let state = self.0.lock().unwrap();
        if state.unreadable {
            return Err(OwnerError::Refused("fixture processes are unreadable"));
        }
        Ok(state.procs.get(&pid).cloned())
    }
    fn fragment(&self, resource: Resource) -> Result<FragmentState, OwnerError> {
        Ok(self.0.lock().unwrap().fragments[index(resource)])
    }
    fn unit(&self, resource: Resource) -> Result<UnitMeasure, OwnerError> {
        Ok(self.0.lock().unwrap().units[index(resource)].clone())
    }
    fn guard_image(&self, resource: Resource) -> Result<HexDigest, OwnerError> {
        Ok(self.0.lock().unwrap().guards[index(resource)].clone())
    }
    fn unit_process(&self, resource: Resource) -> Result<Option<MeasuredProc>, OwnerError> {
        Ok(self.0.lock().unwrap().unit_procs[index(resource)].clone())
    }
    fn final_io(&self, resource: Resource) -> Result<FinalIo, OwnerError> {
        if self.0.lock().unwrap().final_io[index(resource)] {
            Ok(FinalIo::completed())
        } else {
            Err(OwnerError::Unprovisioned("fixture has no final I/O"))
        }
    }
}

/// A retained descriptor stand-in. `exit` is what its pidfd would report.
pub(super) struct Retained {
    pub proc: MeasuredProc,
    pub exit: Arc<AtomicBool>,
    /// The descriptor cannot say whose process it holds (a real one cannot after the exit).
    pub unknown: Arc<AtomicBool>,
}

impl RetainedProcess for Retained {
    fn identity(&self) -> Result<MeasuredProc, OwnerError> {
        if self.unknown.load(Ordering::SeqCst) {
            return Err(OwnerError::Refused("the retained identity is unknown"));
        }
        Ok(self.proc.clone())
    }
    fn has_exited(&self) -> Result<bool, OwnerError> {
        Ok(self.exit.load(Ordering::SeqCst))
    }
}

pub(super) struct World {
    pub dir: tempfile::TempDir,
    pub host: Arc<Host>,
    pub owner: LocalOwner<Arc<Host>>,
    pub plan: Plan,
    pub bytes: Vec<u8>,
    pub retained: [Retained; 4],
}

pub(super) const DAEMON: usize = 0;
pub(super) const AUTHORITY: usize = 1;
const CUSTODIAN_DAEMON: usize = 2;
const CUSTODIAN_AUTHORITY: usize = 3;

fn own() -> Ownership {
    Ownership {
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}

fn mkdir_private(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

impl World {
    pub(super) fn new() -> Self {
        let plan = plan();
        let procs = [
            plan.pre_d.clone(),
            plan.pre_a.clone(),
            proc(20, 0x44),
            proc(22, 0x44),
        ];
        let host = Arc::new(Host(Mutex::new(HostState {
            boot: BootId::new(BOOT).unwrap(),
            procs: procs.iter().map(|p| (p.pid.get(), measured(p))).collect(),
            fragments: [FragmentState::Legacy; 2],
            units: [unit(0x50), unit(0x60)],
            guards: [digest(0x71), digest(0x72)],
            unit_procs: [None, None],
            final_io: [false; 2],
            unreadable: false,
        })));
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("owner");
        mkdir_private(&store);
        let owner =
            LocalOwner::rooted_at(&store, unsafe { libc::geteuid() }, host.clone()).unwrap();
        let retained = procs.map(|p| Retained {
            proc: measured(&p),
            exit: Arc::new(AtomicBool::new(false)),
            unknown: Arc::new(AtomicBool::new(false)),
        });
        Self {
            bytes: encode(&plan).unwrap(),
            dir,
            host,
            owner,
            plan,
            retained,
        }
    }

    pub(super) fn trust(&self, plan: &Plan) -> EnrolledTrust {
        static TREES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = self
            .dir
            .path()
            .join(format!("etc{}", TREES.fetch_add(1, Ordering::SeqCst)));
        let mut leaf = root.clone();
        mkdir_private(&root);
        for name in ["briqyard-sealed", "plan-reader", "v1", "staging"] {
            leaf.push(name);
            mkdir_private(&leaf);
        }
        leaf.push(reg_hash(&plan.registered).as_str());
        mkdir_private(&leaf);
        let record = TrustRecord {
            format: TrustFormat::V1,
            x: plan.x.clone(),
            registered: plan.registered.clone(),
            rk: plan.rk,
            bk: plan.bk,
        };
        let file = leaf.join("1.json");
        std::fs::write(&file, encode(&record).unwrap()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        TrustLoader::rooted_at(&root, own())
            .load(&plan.x, &plan.registered)
            .unwrap()
    }

    pub(super) fn guards(&self) -> GuardPins {
        GuardPins {
            daemon: digest(0x71),
            authority: digest(0x72),
        }
    }

    pub(super) fn install(&self) -> Result<(), OwnerError> {
        let trust = self.trust(&self.plan);
        let build = || Build::new("fence-3").unwrap();
        self.owner.install(
            &self.bytes,
            &trust,
            id("h15-management"),
            &CustodianInput {
                retained: &self.retained[CUSTODIAN_DAEMON],
                build: build(),
            },
            &CustodianInput {
                retained: &self.retained[CUSTODIAN_AUTHORITY],
                build: build(),
            },
            &self.guards(),
        )
    }

    pub(super) fn launch(&self, resource: Resource) -> Launch {
        let (old, custodian) = match resource {
            Resource::Daemon => (self.plan.pre_d.clone(), proc(20, 0x44)),
            Resource::Authority => (self.plan.pre_a.clone(), proc(22, 0x44)),
        };
        Launch {
            x: x(),
            plan: HexDigest::of(&self.bytes),
            resource,
            owner: crate::execution_custody::plan_reader::fresh_nonce().unwrap(),
            stage: LaunchStage::Captured,
            old,
            custodian,
            successor: None,
            death: None,
            nonce: crate::execution_custody::plan_reader::fresh_nonce().unwrap(),
        }
    }

    pub(super) fn capture(&self, launch: &Launch, signer: &Key) -> Capture {
        Sig::sign(
            Tag::CustodyCapture,
            CaptureBody {
                wire: CustodyWire {
                    x: launch.x.clone(),
                    plan: launch.plan.clone(),
                    resource: launch.resource,
                    owner: launch.owner,
                    custodian: launch.custodian.clone(),
                    old: launch.old.clone(),
                    next: None,
                    challenge: launch.nonce,
                    slot: Slot::new(7).unwrap(),
                },
            },
            signer,
        )
        .unwrap()
    }

    pub(super) fn stage_capture(&self, resource: Resource) -> (Launch, Capture) {
        let launch = self.launch(resource);
        let capture = self.capture(&launch, &Key::rk());
        let retained = &self.retained[if resource == Resource::Daemon {
            DAEMON
        } else {
            AUTHORITY
        }];
        self.owner
            .record_capture(resource, &launch, &capture, retained)
            .unwrap();
        (launch, capture)
    }

    /// Install, both leases and fragments, the daemon capture, then the two receipts.
    pub(super) fn enroll(&self) -> (Launch, Capture) {
        self.install().unwrap();
        for resource in [Resource::Daemon, Resource::Authority] {
            self.owner.allocate_lease(resource).unwrap();
            self.host.0.lock().unwrap().fragments[index(resource)] = FragmentState::Guarded;
            self.owner.install_fragment(resource).unwrap();
        }
        let pair = self.stage_capture(Resource::Daemon);
        self.owner.commit_enrollment().unwrap();
        pair
    }

    pub(super) fn attempt(&self) -> Attempt {
        let guard = self.owner.store.lock(false).unwrap();
        self.owner.store.load(&guard).unwrap().unwrap()
    }

    pub(super) fn version(&self) -> u64 {
        self.attempt().version.get()
    }

    pub(super) fn grant(&self, launch: &Launch, action: LKind, expected: Proc, bk: &Key) -> LGrant {
        let decision = LDecision {
            x: launch.x.clone(),
            plan: launch.plan.clone(),
            action,
            owner: launch.owner,
            expected,
            nonce: Nonce::from_array([0x60; 32]),
        };
        LGrant {
            receiver: Sig::sign(Tag::LaunchReceiver, decision.clone(), &Key::rk()).unwrap(),
            api: Sig::sign(Tag::LaunchApi, decision, bk).unwrap(),
        }
    }

    pub(super) fn turn_body(&self, grant: &LGrant, launch: &Launch, capture: &Capture) -> TurnBody {
        let attempt = self.attempt();
        TurnBody {
            x: x(),
            registered: self.plan.registered.clone(),
            plan: HexDigest::of(&self.bytes),
            resource: grant.decision().action.resource(),
            action: grant.decision().action,
            owner: launch.owner,
            decision: h(grant.decision()).unwrap(),
            boot: attempt.boot.clone(),
            generation: attempt.generation,
            lockout: attempt.lockout.clone(),
            target_version: attempt.version,
            captured_launch: Some(h(launch).unwrap()),
            capture: Some(h(capture).unwrap()),
        }
    }

    pub(super) fn turn(&self, body: TurnBody, signer: &Key) -> Turn {
        Sig::sign(Tag::OwnerTurn, body, signer).unwrap()
    }

    pub(super) fn request(&self, resource: Resource, point: Point) -> Vec<u8> {
        let request = ObserveRequest {
            format: briqyard_api::execution::sealed::owner::ObserveFormat::V1,
            x: x(),
            registered: self.plan.registered.clone(),
            resource,
            point,
            verifier: briqyard_api::execution::sealed::owner::Verifier::B,
            nonce: Nonce::from_array([0x70; 32]),
        };
        encode(&request).unwrap()
    }

    pub(super) fn observe(
        &self,
        resource: Resource,
        point: Point,
    ) -> Result<briqyard_api::execution::sealed::owner::Collected, OwnerError> {
        let bytes = self.owner.observe(&self.request(resource, point))?;
        Ok(decode(&bytes).unwrap())
    }

    pub(super) fn path(&self) -> PathBuf {
        self.dir.path().join("owner")
    }
}

pub(super) fn refused<T: std::fmt::Debug>(result: Result<T, OwnerError>, text: &str) {
    match result {
        Err(OwnerError::Refused(reason) | OwnerError::Unprovisioned(reason)) => assert!(
            reason.contains(text),
            "refused for {reason:?}, wanted {text:?}"
        ),
        other => panic!("wanted a refusal containing {text:?}, got {other:?}"),
    }
}
