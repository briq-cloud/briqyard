use super::*;
use briqyard_api::execution::{
    admission::{AuthorityPayload, HostRegistration, Journal},
    channel::InstallationAck,
    sealed::{
        objects::{Dims, HostClockBody, Projection, ProjectionAction, Reg, PROJECTION_ORDER, X},
        prim::{Env, KeyBytes},
        transition::{
            ApiState, ApiViewBody, Cut, Gate, HReadBody, IntentPhase, OwnerCap, ROkBody,
            ReceiptBody, RegDone, Ticket,
        },
    },
    Clock,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::Barrier;

mod custody_boot;
mod review;

const NOW: u64 = 3_000;

struct Key(Ed25519KeyPair);

fn new_key() -> (Key, Vec<u8>) {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    (
        Key(Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()),
        bytes.as_ref().to_vec(),
    )
}

impl Signer for Key {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key().as_ref().try_into().unwrap()
    }
    fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.0.sign(bytes).as_ref().try_into().unwrap()
    }
}

fn id(s: &str) -> Ident {
    Ident::new(s).unwrap()
}
fn pos(n: u64) -> PosInt {
    PosInt::new(n).unwrap()
}
fn uint(n: u64) -> Uint {
    Uint::new(n).unwrap()
}
fn hash(s: &str) -> HexDigest {
    HexDigest::of(s.as_bytes())
}
fn proc(n: u64, build: &str) -> Proc {
    Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000001").unwrap(),
        pid: pos(n),
        start: pos(n * 100),
        exe: hash(build),
        build: Build::new(build).unwrap(),
    }
}
fn members(prefix: &str) -> Members {
    let member = |s| hash(&format!("{prefix}/{s}"));
    Members {
        hi: member("hi"),
        he: member("he"),
        ni: member("ni"),
        ng: member("ng"),
        tr: Some(member("tr")),
    }
}
fn steady_sample() -> ClockSample {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    let monotonic = Instant::now();
    ClockSample {
        wall: Duration::from_secs(NOW) + monotonic.duration_since(origin),
        monotonic,
        uncertainty: Duration::from_millis(1),
    }
}
fn sample() -> Option<ClockSample> {
    review::gate_sample(steady_sample())
}
fn clock() -> Clock {
    steady_sample().interval().unwrap()
}

struct Peer {
    hk: Key,
    bk: Key,
    host_journal: Mutex<Journal>,
    gate: Mutex<Gate>,
    permit: Mutex<Option<t::Permit>>,
    host_reads: Mutex<Option<Arc<Barrier>>>,
    stale_host: AtomicBool,
    stale_api: AtomicBool,
    wrong_clock: AtomicBool,
    signed_clock: AtomicU64,
    wrong_target: AtomicBool,
    sends: AtomicUsize,
}

impl Peer {
    fn read_host(&self, mut q: Q) -> HRead {
        let gate = self.gate.lock().unwrap().clone();
        let basis = gate.hash().unwrap();
        let dims = Dims {
            bytes: uint(1_024),
            counts: [uint(0); 21],
            fits: true,
        };
        let projections = PROJECTION_ORDER[..4]
            .iter()
            .map(|action| {
                let viable =
                    *action == ProjectionAction::HostRegister && gate.phase == GatePhase::Armed;
                Projection {
                    action: *action,
                    basis: basis.clone(),
                    target: viable.then(|| {
                        if self.wrong_target.load(Ordering::SeqCst) {
                            hash("projection")
                        } else {
                            h(&serde_json::json!({ "action": action, "bind": gate.bind.as_ref().unwrap() })).unwrap()
                        }
                    }),
                    next: None,
                    reserve: viable.then(|| dims.clone()),
                    expected_ack: viable.then(|| gate.bind.as_ref().unwrap().record.ack()),
                }
            })
            .collect();
        if self.stale_host.load(Ordering::SeqCst) {
            q.nonce = nonce().unwrap();
        }
        Sig::sign(
            Tag::HostRead,
            HReadBody {
                q,
                plan: gate.plan.clone(),
                proc: gate.committed_cut().new_proc.clone(),
                gate_hash: basis,
                water: uint(gate.implied_water()),
                gate,
                cap: OwnerCap {
                    actual: dims,
                    projections,
                },
            },
            &self.hk,
        )
        .unwrap()
    }
}

impl Peers for Peer {
    fn host_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<HRead, Error>> {
        Box::pin(async move {
            let barrier = self.host_reads.lock().unwrap().clone();
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
            Ok(self.read_host(query.body.q))
        })
    }
    fn api_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ApiView, Error>> {
        Box::pin(async move {
            let mut q = query.body.q;
            if self.stale_api.load(Ordering::SeqCst) {
                q.nonce = nonce()?;
            }
            let permit = self.permit.lock().unwrap();
            let p = permit.as_ref().ok_or(Error::Unavailable)?;
            let ticket = &p.body;
            let n = if ticket.action == ClaimKind::Adopt {
                ticket.bind.prior
            } else {
                ticket.bind.record.generation
            };
            Sig::sign(
                Tag::ApiRead,
                ApiViewBody {
                    q,
                    plan: ticket.plan.clone(),
                    bind: Some(ticket.bind.clone()),
                    step: Some(ticket.action),
                    state: ApiState::Committing,
                    claim: Some(ticket.claim),
                    permit: Some(h(p).unwrap()),
                    api_water: uint(n.get()),
                    row_ack: None,
                    row_intent: None,
                    snapshot: None,
                    pause_owned: true,
                    interlock_owned: true,
                },
                &self.bk,
            )
            .map_err(binding)
        })
    }
    fn host_clock(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<HostClock, Error>> {
        Box::pin(async move {
            let gate = self.gate.lock().unwrap();
            let instance = if self.wrong_clock.load(Ordering::SeqCst) {
                id("foreign-instance")
            } else {
                gate.instance.clone()
            };
            Sig::sign(
                Tag::HostClock,
                HostClockBody {
                    q: query.body.q,
                    plan: gate.plan.clone(),
                    proc: gate.committed_cut().new_proc.clone(),
                    instance,
                    now: uint(match self.signed_clock.load(Ordering::SeqCst) {
                        0 => steady_sample().wall.as_secs(),
                        value => value,
                    }),
                    uncertainty: uint(2),
                },
                &self.hk,
            )
            .map_err(binding)
        })
    }
    fn register_once<'a>(
        &'a self,
        cohort: &'a AdoptedCohort,
        request: RegisterRequest,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.sends.fetch_add(1, Ordering::SeqCst);
            assert_eq!(&cohort.bind, &request.packet.p.body.bind);
            assert_eq!(&cohort.guard, &request.witness.body.guard);
            let mut gate = self.gate.lock().unwrap();
            let record = &cohort.bind.record;
            let native = serde_json::from_slice(&record.native_bytes()).unwrap();
            self.host_journal
                .lock()
                .unwrap()
                .register_host(native, clock())?;
            gate.done = Some(RegDone {
                bind: cohort.bind.clone(),
                claim: request.witness.body.claim,
                permit: h(&request.packet.p).unwrap(),
                witness: h(&request.witness).unwrap(),
                ack: record.ack(),
                host_water: record.generation,
            });
            gate.phase = GatePhase::Registered;
            Err(Error::Unavailable)
        })
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    launch: Launch,
    pkcs8: Vec<u8>,
    rk: Key,
    peer: Arc<Peer>,
    bind: Bind,
    service: Protected,
}

impl Fixture {
    fn new() -> Self {
        let (ordinary, pkcs8) = new_key();
        let rk = new_key().0;
        let hk = new_key().0;
        let bk = new_key().0;
        let ak = Arc::new(new_key().0);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority");
        let host_path = temp.path().join("host");
        let host_role = admission::Role::Host("host-1".into());
        let mut old_host = Journal::open(&host_path, host_role.clone()).unwrap();
        let mut old =
            Journal::open(&path, admission::Role::Authority("authority-1".into())).unwrap();
        let x = X {
            aud: Env::Staging,
            host: id("host-1"),
            op: hash("test-op"),
            serial: pos(1),
        };
        let pre_native = HostRegistration {
            authority: "authority-1".into(),
            epoch: old.instance().into(),
            key_id: "key-1".into(),
            public_key: ordinary.public_key(),
            host_instance: old_host.instance().into(),
            generation: 2,
        };
        old_host.register_host(pre_native.clone(), clock()).unwrap();
        drop(old_host);
        let pre_record = Reg::from_native(&pre_native).unwrap();
        let pre_ack = pre_record.ack();
        old.begin_authority_intent(
            "old-intent",
            x.host.as_str(),
            &pre_native.host_instance.clone(),
            AuthorityPayload::Registration(pre_native),
            clock(),
        )
        .unwrap();
        old.acknowledge_authority_intent(
            "old-intent",
            InstallationAck {
                host_instance: pre_ack.host_instance.to_string(),
                generation: pre_ack.generation.get(),
                digest: pre_ack.digest.to_text(),
            },
            clock(),
        )
        .unwrap();
        drop(old);
        let hp = proc(20, "new-daemon");
        let ap = proc(21, "new-authority");
        let plan = Plan {
            x: x.clone(),
            registered: id("registered"),
            pre: pre_record.ctx(&x.host),
            pre_record,
            pre_intent: id("old-intent"),
            pre_d: proc(10, "old-daemon"),
            pre_a: proc(11, "old-authority"),
            next_d: hp.exe.clone(),
            next_a: ap.exe.clone(),
            dbuild: hp.build.clone(),
            abuild: ap.build.clone(),
            old: members("old"),
            new: members("new"),
            hk: KeyBytes::from_array(hk.public_key()),
            ak: KeyBytes::from_array(ak.public_key()),
            bk: KeyBytes::from_array(bk.public_key()),
            rk: KeyBytes::from_array(rk.public_key()),
            ordinary_key: KeyBytes::from_array(ordinary.public_key()),
            exception: hash("exception"),
            inputs: hash("manifest"),
        };
        let plan_hash = h(&plan).unwrap();
        let launch = Launch {
            x: x.clone(),
            plan: plan_hash.clone(),
            resource: Resource::Authority,
            owner: nonce().unwrap(),
            stage: LaunchStage::Consumed,
            old: plan.pre_a.clone(),
            custodian: proc(7, "custodian"),
            successor: None,
            death: None,
            nonce: nonce().unwrap(),
        };
        let host_journal = Journal::open(&host_path, host_role).unwrap();
        let instance = id(host_journal.instance());
        let cut = Cut {
            x: x.clone(),
            plan: plan_hash.clone(),
            old: plan.pre.clone(),
            old_set: plan.old.set().unwrap(),
            new_instance: instance.clone(),
            old_proc: plan.pre_d.clone(),
            new_proc: hp.clone(),
            custody: hash("custody-evidence"),
            profile: hash("writer-profile"),
            retired_epoch: plan.pre.epoch.clone(),
            prior_host_water: pos(2),
        };
        let receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut.clone()), &hk).unwrap();
        let issuer = DurableIssuer::open_guarded(
            &path,
            &pkcs8,
            "key-1".into(),
            GuardStart {
                plan: &plan,
                plan_hash: &plan_hash,
                launch: &launch,
                proc: &ap,
                receipt: &receipt,
                clock: sample,
            },
            Instant::now() + FRESH,
        )
        .unwrap();
        let record = Reg {
            epoch: id(issuer.instance()),
            host_instance: instance.clone(),
            generation: pos(3),
            ..plan.pre_record.clone()
        };
        let bind = Bind {
            x: x.clone(),
            plan: plan_hash.clone(),
            registered: plan.registered.clone(),
            prior: pos(2),
            intent: id("original-intent"),
            record: record.clone(),
            ctx: record.ctx(&x.host),
            set: plan.new.set().unwrap(),
        };
        let host = HostIdentity {
            proc: hp,
            instance: instance.clone(),
            retirement: h(&receipt).unwrap(),
        };
        let gate = Gate {
            x,
            plan: plan_hash.clone(),
            phase: GatePhase::Armed,
            instance,
            cut: Some(cut),
            receipt: Some(receipt),
            bind: Some(bind.clone()),
            arm: Some(hash("armed")),
            done: None,
            release: None,
        };
        let pins = Pins {
            hk: PinnedKey::new(Role::Hk, hk.public_key()).unwrap(),
            ak: PinnedKey::new(Role::Ak, ak.public_key()).unwrap(),
            bk: PinnedKey::new(Role::Bk, bk.public_key()).unwrap(),
            rk: PinnedKey::new(Role::Rk, rk.public_key()).unwrap(),
        };
        let peer = Arc::new(Peer {
            hk,
            bk,
            host_journal: Mutex::new(host_journal),
            gate: Mutex::new(gate),
            permit: Mutex::new(None),
            host_reads: Mutex::new(None),
            sends: AtomicUsize::new(0),
            stale_host: AtomicBool::new(false),
            stale_api: AtomicBool::new(false),
            wrong_clock: AtomicBool::new(false),
            signed_clock: AtomicU64::new(0),
            wrong_target: AtomicBool::new(false),
        });
        let service = Protected {
            verifier: issuer.authority_verifier().unwrap(),
            issuer: Issuer(tokio::sync::Mutex::new(issuer)),
            plan,
            plan_hash,
            proc: ap,
            host,
            pins,
            ak: ak.clone(),
            peers: peer.clone(),
            cohort: OnceLock::new(),
            reads: Mutex::new(HashMap::new()),
        };
        Self {
            _temp: temp,
            path,
            launch,
            pkcs8,
            rk,
            peer,
            bind,
            service,
        }
    }

    fn query(&self, signer: &Key, preview: Option<Bind>) -> Sig<ProofQuery> {
        challenge(
            signer,
            &self.service.plan,
            &self.service.plan_hash,
            Tag::QueryAuthority,
            preview,
        )
        .unwrap()
    }

    async fn read(&self, preview: Option<Bind>) -> ARead {
        let query = self.query(&self.rk, preview);
        self.service.read(&query, Instant::now()).await.unwrap()
    }

    async fn packet(&self, action: ClaimKind) -> Packet {
        let q = || Q {
            x: self.bind.x.clone(),
            nonce: nonce().unwrap(),
        };
        let bh = self.peer.read_host(q());
        let rh = self.peer.read_host(q());
        let ba = self
            .service
            .read(
                &self.query(&self.peer.bk, Some(self.bind.clone())),
                Instant::now(),
            )
            .await
            .unwrap();
        let ra = self.read(Some(self.bind.clone())).await;
        let ok = Sig::sign(
            Tag::Receiver,
            ROkBody {
                x: self.bind.x.clone(),
                plan: self.bind.plan.clone(),
                action,
                bind: self.bind.clone(),
                owner: nonce().unwrap(),
                claim: nonce().unwrap(),
                nonce: nonce().unwrap(),
                host_proof: h(&rh).unwrap(),
                authority_proof: h(&ra).unwrap(),
                daemon_proc: bh.body.proc.clone(),
                authority_proc: ba.body.proc.clone(),
            },
            &self.rk,
        )
        .unwrap();
        let p = Sig::sign(
            Tag::Decision,
            Ticket {
                x: self.bind.x.clone(),
                plan: self.bind.plan.clone(),
                action,
                bind: self.bind.clone(),
                claim: ok.body.claim,
                owner: ok.body.owner,
                challenge: ok.body.nonce,
                prior_gate: bh.body.gate_hash.clone(),
                auth_guard: Some(ba.body.guard_hash.clone()),
                retired: self.service.host.retirement.clone(),
                authority_proc: ba.body.proc.clone(),
                daemon_proc: bh.body.proc.clone(),
                host_proof: h(&bh).unwrap(),
                authority_proof: h(&ba).unwrap(),
                receiver_ok: h(&ok).unwrap(),
                not_before: uint((clock().now - 2) * 1000),
                expires: pos((clock().now + 12) * 1000),
            },
            &self.peer.bk,
        )
        .unwrap();
        *self.peer.permit.lock().unwrap() = Some(p.clone());
        Packet {
            p,
            ok,
            bh,
            ba,
            rh,
            ra,
        }
    }
}

#[tokio::test]
async fn adoption_competes_on_one_owned_guard_and_publishes_only_after_commit() {
    let f = Fixture::new();
    let before = f.service.snapshot().unwrap();
    let unknown = f.read(None).await.body.cap;
    assert!(unknown
        .projections
        .iter()
        .all(|p| p.target.is_none() && p.reserve.is_none() && p.next.is_none()));
    let packet = f.packet(ClaimKind::Adopt).await;
    let barrier = Arc::new(Barrier::new(3));
    *f.peer.host_reads.lock().unwrap() = Some(barrier.clone());
    let watch = async {
        assert!(f.service.cohort.get().is_none());
        assert!(f.service.snapshot().unwrap().same_snapshot(&before));
        barrier.wait().await;
    };
    let (first, second, ()) = tokio::join!(
        f.service.adopt(&packet, Instant::now()),
        f.service.adopt(&packet, Instant::now()),
        watch,
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let after = f.service.snapshot().unwrap();
    assert_eq!(after.guard().phase, GuardPhase::Adopted);
    assert_eq!(after.guard().bind.as_ref(), Some(&f.bind));
    assert_eq!(
        after.guard().adoption.as_ref(),
        Some(&h(&packet.p).unwrap())
    );
    assert_eq!(
        f.service.cohort.get().unwrap().guard,
        after.guard().hash().unwrap()
    );
    assert_eq!(before.guard().phase, GuardPhase::Started);
    assert!(matches!(
        Journal::open(&f.path, admission::Role::Authority("authority-1".into())),
        Err(admission::Error::Ownership)
    ));
}

#[tokio::test]
async fn lost_registration_reply_preserves_original_and_ack_uses_a_new_read_only_crossing() {
    let f = Fixture::new();
    let adopt = f.packet(ClaimKind::Adopt).await;
    f.service.adopt(&adopt, Instant::now()).await.unwrap();
    let packet = f.packet(ClaimKind::Register).await;
    let foreign = new_key().0;
    let checked = f
        .service
        .crossing(&packet, ClaimKind::Register, Instant::now())
        .await
        .unwrap();
    assert!(checked.prepare_witness(&foreign).is_err());
    drop(checked);
    f.peer.stale_api.store(true, Ordering::SeqCst);
    assert!(f
        .service
        .register(packet.clone(), Instant::now())
        .await
        .is_err());
    f.peer.stale_api.store(false, Ordering::SeqCst);
    assert_eq!(f.peer.sends.load(Ordering::SeqCst), 0);
    assert!(matches!(
        f.service.register(packet.clone(), Instant::now()).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.peer.sends.load(Ordering::SeqCst), 1);
    let pending = f.read(None).await;
    let original = f.service.snapshot().unwrap().origin().unwrap().clone();
    assert_eq!(pending.body.intent.as_ref(), Some(&original));
    assert!(!pending.body.ready);
    assert_eq!(pending.body.native_water.get(), 3);
    assert_eq!(
        pending.body.cap.actual.bytes.get(),
        std::fs::metadata(f.path.join("journal.json"))
            .unwrap()
            .len()
    );
    assert_eq!(pending.body.cap.actual.counts[11].get(), 2);
    assert!(pending.body.cap.projections[0].target.is_none());
    assert_eq!(
        pending.body.cap.projections[1].expected_ack,
        Some(f.bind.record.ack())
    );
    assert!(f.service.register(packet, Instant::now()).await.is_err());
    assert_eq!(f.peer.sends.load(Ordering::SeqCst), 1);

    let ack = f.packet(ClaimKind::RecordAck).await;
    f.peer.stale_host.store(true, Ordering::SeqCst);
    assert!(f.service.record_ack(&ack, Instant::now()).await.is_err());
    f.peer.stale_host.store(false, Ordering::SeqCst);
    assert!(f.service.record_ack(&ack, Instant::now()).await.unwrap());
    let ready = f.read(None).await;
    let intent = ready.body.intent.unwrap();
    assert_eq!(intent.phase, IntentPhase::Ready);
    assert_eq!(intent.ack, Some(f.bind.record.ack()));
    assert!(ready.body.ready && !ready.body.uncertain);
    assert!(ready
        .body
        .cap
        .projections
        .iter()
        .all(|p| p.target.is_none() && p.expected_ack.is_none()));
    assert!(!f.service.record_ack(&ack, Instant::now()).await.unwrap());
    assert_eq!(f.peer.sends.load(Ordering::SeqCst), 1);
    assert_eq!(f.service.snapshot().unwrap().origin().unwrap(), &original);

    let view = f.service.snapshot().unwrap();
    assert!(view.registration_state(None, clock()).unwrap().ready);
    assert!(view
        .registration_state(
            None,
            Clock {
                now: NOW - 1,
                uncertainty: 0
            }
        )
        .is_err());
}

#[tokio::test]
async fn read_refuses_stale_or_unbound_clock_and_foreign_signer() {
    let f = Fixture::new();
    let query = f.query(&f.rk, None);
    assert!(f
        .service
        .read(&query, Instant::now() - FRESH)
        .await
        .is_err());
    f.peer.wrong_clock.store(true, Ordering::SeqCst);
    assert!(f.service.read(&query, Instant::now()).await.is_err());
    f.peer.wrong_clock.store(false, Ordering::SeqCst);
    assert!(f.service.read(&query, Instant::now()).await.is_err());
    let foreign = new_key().0;
    assert!(f
        .service
        .read(&f.query(&foreign, None), Instant::now())
        .await
        .is_err());
    let read = f.read(Some(f.bind.clone())).await;
    assert_eq!(read.body.host_clock.body.proc, f.service.host.proc);
    assert_eq!(read.body.host_clock.body.instance, f.service.host.instance);
    assert_eq!(
        read.body.host_clock.body.q.nonce,
        t::host_challenge_nonce(&read.body.q, &read.body.plan, &read.body.salt,).unwrap()
    );
}

#[tokio::test]
async fn correctly_signed_clock_without_a_local_bracket_is_refused() {
    let f = Fixture::new();
    f.peer.signed_clock.store(NOW - 120, Ordering::SeqCst);
    let query = f.query(&f.rk, None);
    assert!(
        f.service.read(&query, Instant::now()).await.is_err(),
        "signed but stale host time"
    );
}

#[tokio::test]
async fn signed_capacity_for_another_target_does_not_authorize_adoption() {
    let f = Fixture::new();
    f.peer.wrong_target.store(true, Ordering::SeqCst);
    let packet = f.packet(ClaimKind::Adopt).await;
    assert!(
        f.service.adopt(&packet, Instant::now()).await.is_err(),
        "a signed projection for another target authorized an adoption"
    );
}

#[tokio::test]
async fn original_intent_observation_cannot_recover_the_signed_witness() {
    let f = Fixture::new();
    let adopt = f.packet(ClaimKind::Adopt).await;
    f.service.adopt(&adopt, Instant::now()).await.unwrap();
    let register = f.packet(ClaimKind::Register).await;
    assert!(matches!(
        f.service.register(register, Instant::now()).await,
        Err(Error::Unavailable)
    ));
    let expected = f.read(None).await.body.intent.unwrap();
    let view = f.service.snapshot().unwrap();
    let observed = serde_json::to_value(view.origin().unwrap()).unwrap();
    assert!(
        observed["witness"].as_str() == Some(expected.witness.as_str()),
        "observation returned more than the public witness commitment"
    );
}

#[tokio::test]
async fn raw_packet_evidence_cannot_authorize_the_owner_turn() {
    let f = Fixture::new();
    let packet = f.packet(ClaimKind::Adopt).await;
    let before = f.service.snapshot().unwrap();
    let challenge = || {
        f.service
            .verifier
            .challenge(ClaimKind::Adopt, &packet, Instant::now())
            .unwrap()
    };
    let sign = |tag, q: &ProofQuery| Sig::sign(tag, q.clone(), f.service.ak.as_ref()).unwrap();
    let in_flight = challenge();
    let b = f
        .peer
        .api_read(sign(Tag::QueryApi, in_flight.api_query()))
        .await
        .unwrap();
    assert!(in_flight.finish(packet.bh.clone(), &b).is_err());
    let in_flight = challenge();
    let host = f
        .peer
        .host_read(sign(Tag::QueryHost, in_flight.host_query()))
        .await
        .unwrap();
    f.peer.stale_api.store(true, Ordering::SeqCst);
    let b = f
        .peer
        .api_read(sign(Tag::QueryApi, in_flight.api_query()))
        .await
        .unwrap();
    assert!(in_flight.finish(host, &b).is_err());
    f.peer.stale_api.store(false, Ordering::SeqCst);
    let proof = f
        .service
        .crossing(&packet, ClaimKind::Adopt, Instant::now())
        .await
        .unwrap();
    assert!(f
        .service
        .issuer
        .lock()
        .await
        .record_original_ack(proof)
        .is_err());
    assert!(before.same_snapshot(&f.service.snapshot().unwrap()));
    assert!(f.service.adopt(&packet, Instant::now()).await.is_ok());
}

#[tokio::test]
async fn pending_original_survives_without_a_live_reopen_and_dirty_reads_fail() {
    let f = Fixture::new();
    let adopt = f.packet(ClaimKind::Adopt).await;
    f.service.adopt(&adopt, Instant::now()).await.unwrap();
    let packet = f.packet(ClaimKind::Register).await;
    assert!(matches!(
        f.service.register(packet.clone(), Instant::now()).await,
        Err(Error::Unavailable)
    ));
    let live = f.service.snapshot().unwrap();
    let pending = f.read(None).await.body.intent.unwrap();
    assert_eq!(live.origin(), Some(&pending));
    let file = f.path.join("journal.json");
    let bytes = std::fs::read(&file).unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        stored["sealed_authority"]["origin"]["original"],
        serde_json::to_value(&pending).unwrap()
    );
    assert_eq!(
        stored["sealed_authority"]["guard"]["epoch"],
        live.guard().epoch.as_str()
    );
    drop(live);
    let tmp = f.path.join("journal.next");
    std::fs::write(&tmp, b"indeterminate").unwrap();
    assert!(matches!(
        f.service.snapshot(),
        Err(Error::Journal(admission::Error::Persistence))
    ));
    let Fixture {
        _temp,
        path,
        launch,
        pkcs8,
        peer,
        service,
        ..
    } = f;
    let Protected {
        issuer,
        verifier,
        plan,
        plan_hash,
        proc,
        ..
    } = service;
    drop((issuer, verifier));
    let receipt = peer.gate.lock().unwrap().receipt.clone().unwrap();
    let open = || {
        DurableIssuer::open_guarded(
            &path,
            &pkcs8,
            "key-1".into(),
            GuardStart {
                plan: &plan,
                plan_hash: &plan_hash,
                launch: &launch,
                proc: &proc,
                receipt: &receipt,
                clock: sample,
            },
            Instant::now() + FRESH,
        )
    };
    assert!(matches!(open(), Err(admission::Error::Persistence)));
    std::fs::remove_file(tmp).unwrap();
    assert!(matches!(open(), Err(admission::Error::Binding)));
    assert_eq!(std::fs::read(file).unwrap(), bytes);
    assert_eq!(peer.sends.load(Ordering::SeqCst), 1);
}
