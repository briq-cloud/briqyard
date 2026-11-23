//! Plan reader tests.
//!
//! **Non-authorizing fixtures.** Every signer below is a synthetic cfg(test) seed, the "owner"
//! is a mutex-guarded stand-in written for these tests, and the trust tree, socket and helper
//! live in a temporary directory owned by the test's own user. None of it is source
//! enrollment, native qualification, a real root peer, or a real operation owner; the
//! ownership policy is test-scoped and production is fixed at root:root.

mod flow;
mod proof;
mod trust;
mod wire;

use super::trust::Ownership;
use super::wire::encode_frame;
use super::wire::ObservedHelper;
use super::*;
use crate::execution_custody::PeerIdentity;
use briqyard_api::execution::sealed::{
    canonical::{decode, encode},
    custody::Resource,
    objects::{Members, Plan, Proc, Reg, X},
    plan_pin::{
        reg_hash, LocalPlan, Read, ReadBody, ReadFormat, ReadPair, ReadPoint, TrustFormat,
        TrustRecord,
    },
    prim::{BootId, Build, Env, HexDigest, Ident, KeyBytes, Nonce, PosInt},
    sig::{Sig, Signer, Tag},
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

const GENEROUS: Duration = Duration::from_secs(60);

struct FixtureSigner(Ed25519KeyPair);

impl FixtureSigner {
    fn seed(seed: [u8; 32]) -> Self {
        Self(Ed25519KeyPair::from_seed_unchecked(&seed).unwrap())
    }

    fn vector(hex_seed: &str) -> Self {
        Self::seed(hex::decode(hex_seed).unwrap().try_into().unwrap())
    }

    fn rk() -> Self {
        Self::vector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    }

    fn bk() -> Self {
        Self::vector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    }

    fn attacker(label: u8) -> Self {
        Self::seed([label; 32])
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

fn id(text: &str) -> Ident {
    Ident::new(text).unwrap()
}

fn digest(byte: u8) -> HexDigest {
    HexDigest::from_raw([byte; 32])
}

fn x(serial: u64) -> X {
    X {
        aud: Env::Staging,
        host: id("host.test"),
        op: digest(0),
        serial: PosInt::new(serial).unwrap(),
    }
}

fn proc(pid: u64) -> Proc {
    Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000004").unwrap(),
        pid: PosInt::new(pid).unwrap(),
        start: PosInt::new(912).unwrap(),
        exe: digest(0x33),
        build: Build::new("fence-3").unwrap(),
    }
}

fn members(byte: u8) -> Members {
    Members {
        hi: digest(byte),
        he: digest(byte),
        ni: digest(byte),
        ng: digest(byte),
        tr: None,
    }
}

fn plan_with(x: X, registered: &str, rk: KeyBytes, bk: KeyBytes, inputs: u8) -> Plan {
    let record = Reg {
        authority: id("auth"),
        epoch: id("ep"),
        key_id: id("k"),
        public_key: [7; 32],
        host_instance: id("hi"),
        generation: PosInt::new(2).unwrap(),
    };
    Plan {
        pre: record.ctx(&x.host),
        x,
        registered: id(registered),
        pre_record: record,
        pre_intent: id("pre"),
        pre_d: proc(10),
        pre_a: proc(12),
        next_d: digest(0xa),
        next_a: digest(0xb),
        dbuild: Build::new("fence-3").unwrap(),
        abuild: Build::new("fence-3").unwrap(),
        old: members(1),
        new: members(2),
        hk: KeyBytes::from_array([1; 32]),
        ak: KeyBytes::from_array([2; 32]),
        bk,
        rk,
        ordinary_key: KeyBytes::from_array([5; 32]),
        exception: digest(0xc),
        inputs: digest(inputs),
    }
}

fn own() -> Ownership {
    Ownership {
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}

fn mkdir_private(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn trust_record(x: X, registered: &str, rk: KeyBytes, bk: KeyBytes) -> TrustRecord {
    TrustRecord {
        format: TrustFormat::V1,
        x,
        registered: id(registered),
        rk,
        bk,
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

type TreeEntry = (PathBuf, u64, u64, i64, u32);

/// A temporary, user-owned stand-in for the root-private tree and the socket directory.
struct World {
    dir: tempfile::TempDir,
    plan: Plan,
    plan_bytes: Vec<u8>,
}

impl World {
    fn new() -> Self {
        Self::with_plan(plan_with(
            x(1),
            "registered.test",
            FixtureSigner::rk().key(),
            FixtureSigner::bk().key(),
            0xd,
        ))
    }

    fn with_plan(plan: Plan) -> Self {
        let world = Self {
            plan_bytes: encode(&plan).unwrap(),
            plan,
            dir: tempfile::tempdir().unwrap(),
        };
        mkdir_private(&world.trust_root());
        let mut leaf = world.trust_root();
        for name in ["briqyard-sealed", "plan-reader", "v1", "staging"] {
            leaf.push(name);
            mkdir_private(&leaf);
        }
        mkdir_private(&world.trust_dir());
        mkdir_private(&world.sock_dir());
        world.install_trust(&trust_record(
            world.plan.x.clone(),
            world.plan.registered.as_str(),
            world.plan.rk,
            world.plan.bk,
        ));
        world
    }

    fn trust_root(&self) -> PathBuf {
        self.dir.path().join("etc")
    }

    fn trust_dir(&self) -> PathBuf {
        self.trust_root()
            .join("briqyard-sealed/plan-reader/v1/staging")
            .join(reg_hash(&self.plan.registered).as_str())
    }

    fn trust_file(&self) -> PathBuf {
        self.trust_dir().join("1.json")
    }

    fn sock_dir(&self) -> PathBuf {
        self.dir.path().join("run")
    }

    fn install_trust(&self, record: &TrustRecord) {
        write_private(&self.trust_file(), &encode(record).unwrap());
    }

    fn loader(&self) -> TrustLoader {
        TrustLoader::rooted_at(&self.trust_root(), own())
    }

    fn trust(&self) -> EnrolledTrust {
        self.loader()
            .load(&self.plan.x, &self.plan.registered)
            .unwrap()
    }

    fn local(&self) -> LocalPlan {
        LocalPlan::decode(&self.plan_bytes).unwrap()
    }

    fn endpoint_for(&self, ownership: Ownership, helper_exe: [u8; 32]) -> ReaderEndpoint {
        ReaderEndpoint::rooted_at(
            &self.sock_dir(),
            ownership,
            EnrolledHelper::new(helper_exe),
            test_probe,
        )
    }

    fn reader(&self) -> PlanReader {
        PlanReader::for_test(self.loader(), self.endpoint_for(own(), TEST_HELPER_IMAGE))
    }

    fn scope(&self, resource: Resource, point: ReadPoint) -> ReadScope {
        ReadScope::new(
            self.plan.x.clone(),
            self.plan.registered.clone(),
            resource,
            point,
        )
        .unwrap()
    }

    fn request(&self, resource: Resource, point: ReadPoint, nonce: u8) -> Read {
        Read {
            format: ReadFormat::V1,
            x: self.plan.x.clone(),
            registered: self.plan.registered.clone(),
            resource,
            point,
            nonce: Nonce::from_array([nonce; 32]),
        }
    }

    fn tree(&self) -> Vec<TreeEntry> {
        fn walk(path: &Path, out: &mut Vec<TreeEntry>) {
            let meta = std::fs::symlink_metadata(path).unwrap();
            out.push((
                path.to_path_buf(),
                meta.ino(),
                meta.size(),
                meta.mtime(),
                meta.mode(),
            ));
            if meta.is_dir() {
                let mut names: Vec<_> = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                names.sort();
                names.iter().for_each(|child| walk(child, out));
            }
        }
        let mut out = Vec::new();
        walk(self.dir.path(), &mut out);
        out
    }
}

/// The "enrolled helper image" of these tests. The helper is a thread of the test process whose
/// mapped binary is larger than the production executable-hash limit, so a test-scoped probe
/// reads the real kernel start ticks of the peer and reports this fixed image digest. The
/// production probe hashes the real mapped executable; qualification uses the real helper.
const TEST_HELPER_IMAGE: [u8; 32] = [0x77; 32];

fn test_probe(peer: &PeerIdentity) -> Result<ObservedHelper, PlanReadError> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", peer.pid()))
        .map_err(|source| io("read test peer stat", source))?;
    let (pid, start_ticks) = crate::execution_custody::process::parse_stat(&stat)?;
    Ok(ObservedHelper {
        pid,
        start_ticks,
        boot: "test".to_string(),
        executable: TEST_HELPER_IMAGE,
    })
}

fn framed(bytes: &[u8]) -> Vec<u8> {
    encode_frame(bytes).unwrap()
}

fn body_for(read: &Read, local: &LocalPlan) -> ReadBody {
    ReadBody {
        read: read.clone(),
        pin: local.pin(),
    }
}

fn sign_pair(
    receiver: (Tag, &FixtureSigner, ReadBody),
    api: (Tag, &FixtureSigner, ReadBody),
) -> Vec<u8> {
    let pair = ReadPair {
        receiver: Sig::sign(receiver.0, receiver.2, receiver.1).unwrap(),
        api: Sig::sign(api.0, api.2, api.1).unwrap(),
    };
    encode(&pair).unwrap()
}

fn honest_pair(read: &Read, local: &LocalPlan) -> Vec<u8> {
    let body = body_for(read, local);
    sign_pair(
        (Tag::PlanReadReceiver, &FixtureSigner::rk(), body.clone()),
        (Tag::PlanReadApi, &FixtureSigner::bk(), body),
    )
}

fn refused<T>(result: Result<T, PlanReadError>) -> PlanReadError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("an invalid read was accepted"),
    }
}

fn says(error: &PlanReadError, text: &str) {
    assert!(error.to_string().contains(text), "{error} lacks {text:?}");
}

enum Reply {
    Send(Vec<u8>),
    SendThenHold(Vec<u8>),
    Fd(Vec<u8>),
    Silent,
}

struct Helper {
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    thread: Option<JoinHandle<()>>,
}

impl Helper {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn serve(sock_dir: &Path, behave: impl Fn(&[u8]) -> Reply + Send + 'static) -> Helper {
    let path = sock_dir.join("plan-reader.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicUsize::new(0));
    let (flag, count) = (Arc::clone(&stop), Arc::clone(&accepted));
    let thread = std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            };
            count.fetch_add(1, Ordering::SeqCst);
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                continue;
            }
            let mut request = vec![0u8; u32::from_be_bytes(header) as usize];
            if stream.read_exact(&mut request).is_err() {
                continue;
            }
            match behave(&request) {
                Reply::Send(bytes) => {
                    let _ = stream.write_all(&bytes);
                }
                Reply::SendThenHold(bytes) => {
                    let _ = stream.write_all(&bytes);
                    while !flag.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
                Reply::Fd(bytes) => {
                    let null = std::fs::File::open("/dev/null").unwrap();
                    let fds = [null.as_raw_fd()];
                    let rights = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
                    nix::sys::socket::sendmsg::<()>(
                        stream.as_raw_fd(),
                        &[std::io::IoSlice::new(&bytes)],
                        &rights,
                        nix::sys::socket::MsgFlags::empty(),
                        None,
                    )
                    .unwrap();
                }
                Reply::Silent => {
                    while !flag.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            }
        }
    });
    Helper {
        stop,
        accepted,
        thread: Some(thread),
    }
}

/// Answers the read it was sent, honestly, for this Plan.
fn honest(world: &World) -> impl Fn(&[u8]) -> Reply + Send + 'static {
    let local = world.local();
    move |request| {
        let read: Read = decode(request).expect("the reader sends one canonical Read");
        Reply::Send(framed(&honest_pair(&read, &local)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Facts {
    owner: u64,
    boot: u64,
    serial: u64,
    floor: u64,
    hold: bool,
    phase: &'static str,
}

struct State {
    plan: Vec<u8>,
    facts: Facts,
    custodian: Proc,
    snapshot_resource: Option<Resource>,
    terminal: bool,
    missing: bool,
}

/// NON-AUTHORIZING stand-in for the operation owner the next package supplies. It proves the
/// reader's capture, out-of-lock read and compare-and-set; it is not a root owner, a lease or
/// any record of a real operation.
struct SyntheticOwner {
    state: Mutex<State>,
    captures: AtomicUsize,
    locks: AtomicUsize,
}

impl SyntheticOwner {
    fn new(world: &World, phase: &'static str) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                plan: world.plan_bytes.clone(),
                facts: Facts {
                    owner: 1,
                    boot: 1,
                    serial: 1,
                    floor: 1,
                    hold: true,
                    phase,
                },
                custodian: proc(77),
                snapshot_resource: None,
                terminal: false,
                missing: false,
            }),
            captures: AtomicUsize::new(0),
            locks: AtomicUsize::new(0),
        })
    }

    fn mutate(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.state.lock().unwrap());
    }

    fn snapshot(state: &State, scope: &ReadScope) -> Result<OwnerSnapshot<Facts>, OwnerRefusal> {
        if state.missing {
            return Err(OwnerRefusal("no durable operation state"));
        }
        if state.terminal {
            return Err(OwnerRefusal("operation is terminal"));
        }
        if !state.facts.hold {
            return Err(OwnerRefusal("operation hold is gone"));
        }
        let wanted = match scope.point() {
            ReadPoint::Prearm => "preparing",
            ReadPoint::Launch | ReadPoint::Seal => "enrolled",
        };
        if state.facts.phase != wanted {
            return Err(OwnerRefusal("phase does not allow this point"));
        }
        let plan: Plan =
            decode(&state.plan).map_err(|_| OwnerRefusal("owner Plan is not canonical"))?;
        let resource = state.snapshot_resource.unwrap_or(scope.resource());
        let pre = match resource {
            Resource::Daemon => plan.pre_d,
            Resource::Authority => plan.pre_a,
        };
        let original = OriginalOwner::new(
            resource,
            plan.registered,
            plan.x.host,
            pre,
            state.custodian.clone(),
        );
        OwnerSnapshot::new(&state.plan, original, state.facts.clone())
            .map_err(|_| OwnerRefusal("owner snapshot is inconsistent"))
    }
}

impl PlanReadOwner for SyntheticOwner {
    type Facts = Facts;
    type Held<'a> = MutexGuard<'a, State>;

    fn capture(&self, scope: &ReadScope) -> Result<OwnerSnapshot<Facts>, OwnerRefusal> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        Self::snapshot(&self.state.lock().unwrap(), scope)
    }

    fn lock_and_capture<'a>(
        &'a self,
        scope: &ReadScope,
    ) -> Result<(MutexGuard<'a, State>, OwnerSnapshot<Facts>), OwnerRefusal> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        let guard = self.state.lock().unwrap();
        let snapshot = Self::snapshot(&guard, scope)?;
        Ok((guard, snapshot))
    }
}

fn observe<'o>(
    world: &World,
    reader: &PlanReader,
    owner: &'o SyntheticOwner,
    resource: Resource,
    point: ReadPoint,
) -> Result<RejoinedObservation<MutexGuard<'o, State>>, PlanReadError> {
    reader.observe_within(
        owner,
        &world.scope(resource, point),
        Deadline::within(GENEROUS),
    )
}
