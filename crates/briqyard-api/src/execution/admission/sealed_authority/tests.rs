use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sealed::{
    custody::Resource,
    objects::{Members, X},
    prim::{BootId, Build, Env, Ident, KeyBytes},
    sig::Sig,
    transition::{Cut, Launch, LaunchStage, Receipt, ReceiptBody},
};
use std::time::{Duration, Instant};

struct Key(Ed25519KeyPair);

impl Signer for Key {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key().as_ref().try_into().unwrap()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).as_ref().try_into().unwrap()
    }
}

fn keypair() -> (Key, Vec<u8>) {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    (
        Key(Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()),
        bytes.as_ref().to_vec(),
    )
}

fn id(x: &str) -> Ident {
    Ident::new(x).unwrap()
}
fn pos(x: u64) -> PosInt {
    PosInt::new(x).unwrap()
}
fn digest(x: &str) -> HexDigest {
    HexDigest::of(x.as_bytes())
}

fn proc(pid: u64, label: &str) -> Proc {
    Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000001").unwrap(),
        pid: pos(pid),
        start: pos(pid + 100),
        exe: digest(label),
        build: Build::new(label).unwrap(),
    }
}

fn members(scope: &str) -> Members {
    let hash = |name| digest(&format!("{scope}/{name}"));
    Members {
        hi: hash("hi"),
        he: hash("he"),
        ni: hash("ni"),
        ng: hash("ng"),
        tr: Some(hash("tr")),
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    path: PathBuf,
    plan: Plan,
    hash: HexDigest,
    launch: Launch,
    authority: Proc,
    receipt: Receipt,
    ordinary: Vec<u8>,
    ak_pkcs8: Vec<u8>,
    ak: Key,
    bk: Key,
    hk: Key,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("authority");
        let (ordinary, ordinary_bytes) = keypair();
        let (ak, ak_pkcs8) = keypair();
        let bk = keypair().0;
        let hk = keypair().0;
        let rk = keypair().0;
        let mut old = Journal::open(&path, Role::Authority("authority".into())).unwrap();
        let registration = HostRegistration {
            authority: "authority".into(),
            epoch: old.instance().into(),
            key_id: "ordinary".into(),
            public_key: ordinary.public_key(),
            host_instance: "old-host".into(),
            generation: 2,
        };
        let record = Reg::from_native(&registration).unwrap();
        old.begin_authority_intent(
            "predecessor",
            "host",
            "old-host",
            AuthorityPayload::Registration(registration),
            clock(),
        )
        .unwrap();
        old.acknowledge_authority_intent("predecessor", native_ack(&record.ack()), clock())
            .unwrap();
        drop(old);
        let authority = proc(22, "candidate-authority");
        let host = proc(23, "candidate-daemon");
        let x = X {
            aud: Env::Staging,
            host: id("host"),
            op: digest("operation"),
            serial: pos(1),
        };
        let plan = Plan {
            x: x.clone(),
            registered: id("registered"),
            pre: record.ctx(&x.host),
            pre_record: record,
            pre_intent: id("predecessor"),
            pre_d: proc(12, "old-daemon"),
            pre_a: proc(13, "old-authority"),
            next_d: host.exe.clone(),
            next_a: authority.exe.clone(),
            dbuild: host.build.clone(),
            abuild: authority.build.clone(),
            old: members("old"),
            new: members("new"),
            hk: KeyBytes::from_array(hk.public_key()),
            ak: KeyBytes::from_array(ak.public_key()),
            bk: KeyBytes::from_array(bk.public_key()),
            rk: KeyBytes::from_array(rk.public_key()),
            ordinary_key: KeyBytes::from_array(ordinary.public_key()),
            exception: digest("exception"),
            inputs: digest("inputs"),
        };
        let hash = h(&plan).unwrap();
        let launch = Launch {
            x: x.clone(),
            plan: hash.clone(),
            resource: Resource::Authority,
            owner: nonce(),
            stage: LaunchStage::Consumed,
            old: plan.pre_a.clone(),
            custodian: proc(14, "custodian"),
            successor: None,
            death: None,
            nonce: nonce(),
        };
        let cut = Cut {
            x,
            plan: hash.clone(),
            old: plan.pre.clone(),
            old_set: plan.old.set().unwrap(),
            new_instance: id("replacement-host"),
            old_proc: plan.pre_d.clone(),
            new_proc: host,
            custody: digest("custody"),
            profile: digest("profile"),
            retired_epoch: plan.pre.epoch.clone(),
            prior_host_water: plan.pre.generation,
        };
        let receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut), &hk).unwrap();
        Self {
            _tmp: tmp,
            path,
            plan,
            hash,
            launch,
            authority,
            receipt,
            ordinary: ordinary_bytes,
            ak_pkcs8,
            ak,
            bk,
            hk,
        }
    }

    fn started(&self, epoch: &str) -> Guard {
        Guard {
            x: self.plan.x.clone(),
            plan: self.hash.clone(),
            phase: GuardPhase::Started,
            launch: self.launch.hash().unwrap(),
            proc: self.authority.clone(),
            epoch: id(epoch),
            ordinary_kid: id("ordinary"),
            ordinary_key: self.plan.ordinary_key,
            set: self.plan.new.set().unwrap(),
            bind: None,
            armed_gate: None,
            adoption: None,
        }
    }

    fn journal(&self) -> Result<Journal, Error> {
        Journal::open_guarded(
            &self.path,
            Role::Authority("authority".into()),
            clock(),
            &self.plan,
            &|epoch| Ok(self.started(epoch)),
        )
    }

    fn issuer(&self) -> Result<DurableIssuer, Error> {
        self.issuer_with(&self.ordinary)
    }

    fn issuer_with(&self, pkcs8: &[u8]) -> Result<DurableIssuer, Error> {
        DurableIssuer::open_guarded(
            &self.path,
            ordinary_key::OrdinaryAuthorityKey::from_profile(pkcs8).map_err(|_| Error::Binding)?,
            "ordinary".into(),
            GuardStart {
                plan: &self.plan,
                plan_hash: &self.hash,
                launch: &self.launch,
                proc: &self.authority,
                receipt: &self.receipt,
                clock: || {
                    Some(clock::ClockSample {
                        wall: Duration::from_secs(clock().now),
                        monotonic: Instant::now(),
                        uncertainty: Duration::from_millis(1),
                    })
                },
            },
            Instant::now() + Duration::from_secs(5),
        )
    }

    fn pending(&self, journal: &mut Journal) -> Bind {
        let mut state = State::clone(&journal.state);
        let guard = &mut state.sealed_authority.as_mut().unwrap().guard;
        let record = Reg {
            epoch: guard.epoch.clone(),
            host_instance: self.receipt.body.cut.new_instance.clone(),
            generation: pos(3),
            ..self.plan.pre_record.clone()
        };
        let bind = Bind {
            x: guard.x.clone(),
            plan: self.hash.clone(),
            registered: self.plan.registered.clone(),
            prior: pos(2),
            intent: id("registration"),
            ctx: record.ctx(&guard.x.host),
            record,
            set: guard.set.clone(),
        };
        guard.phase = GuardPhase::Adopted;
        guard.bind = Some(bind.clone());
        guard.armed_gate = Some(digest("armed"));
        guard.adoption = Some(digest("adoption"));
        let claim = nonce();
        let p = Sig::sign(
            Tag::Decision,
            Ticket {
                x: bind.x.clone(),
                plan: self.hash.clone(),
                action: ClaimKind::Register,
                claim,
                owner: nonce(),
                challenge: nonce(),
                bind: bind.clone(),
                prior_gate: guard.armed_gate.clone().unwrap(),
                auth_guard: Some(guard.hash().unwrap()),
                retired: h(&self.receipt).unwrap(),
                authority_proc: guard.proc.clone(),
                daemon_proc: self.receipt.body.cut.new_proc.clone(),
                host_proof: digest("host-proof"),
                authority_proof: digest("authority-proof"),
                receiver_ok: digest("receiver-ok"),
                not_before: Uint::new(90_000).unwrap(),
                expires: pos(110_000),
            },
            &self.bk,
        )
        .unwrap();
        let witness = Sig::sign(
            Tag::Intent,
            witness_body(guard, &bind, claim, h(&p).unwrap()).unwrap(),
            &self.ak,
        )
        .unwrap();
        put_origin(&mut state, &bind, make_origin(&p, &witness).unwrap()).unwrap();
        validate_state(&state).unwrap();
        journal.persist(state).unwrap();
        journal.publish();
        bind
    }
}

fn clock() -> Clock {
    Clock {
        now: 100,
        uncertainty: 1,
    }
}

fn nonce() -> Nonce {
    let mut raw = [0_u8; 32];
    SystemRandom::new().fill(&mut raw).unwrap();
    Nonce::from_array(raw)
}

type ChangePlan = fn(&mut Plan);

#[test]
fn guarded_start_does_not_write_a_plan_that_reuses_keys_or_members() {
    let mut legacy = Fixture::new().plan;
    legacy.old.tr = None;
    assert!(validate_authority_plan(&legacy).is_ok());
    let variants: [ChangePlan; 5] = [
        |p| p.ak = p.hk,
        |p| p.new.tr = None,
        |p| p.old.ng = p.old.he.clone(),
        |p| p.new.ng = p.new.hi.clone(),
        |p| p.new.tr = p.old.tr.clone(),
    ];
    for change in variants {
        let mut f = Fixture::new();
        change(&mut f.plan);
        f.hash = h(&f.plan).unwrap();
        f.launch.plan = f.hash.clone();
        let mut cut = f.receipt.body.cut.clone();
        cut.plan = f.hash.clone();
        cut.old_set = f.plan.old.set().unwrap();
        f.receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut), &f.hk).unwrap();
        let file = f.path.join("journal.json");
        let before = std::fs::read(&file).unwrap();
        assert!(
            matches!(f.issuer(), Err(Error::Binding)),
            "invalid matching Plan was accepted"
        );
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
}

#[test]
fn guarded_issuer_accepts_only_the_pinned_actual_ordinary_key_before_any_journal_write() {
    let f = Fixture::new();
    let file = f.path.join("journal.json");
    let before = std::fs::read(&file).unwrap();
    let (_, other) = keypair();
    let mut advertised = other.clone();
    advertised[51..].copy_from_slice(f.plan.ordinary_key.as_array());
    for (name, wrong) in [
        ("transition evidence key", f.ak_pkcs8.clone()),
        ("unrelated key", other.clone()),
        ("seed-only form", other[16..48].to_vec()),
        ("trailing bytes", [f.ordinary.clone(), vec![0]].concat()),
        ("pinned public advertised over another seed", advertised),
    ] {
        assert!(
            matches!(f.issuer_with(&wrong), Err(Error::Binding)),
            "{name} was accepted"
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            before,
            "{name} changed the journal"
        );
    }
    let key = ordinary_key::OrdinaryAuthorityKey::from_profile(&f.ordinary).unwrap();
    let result = DurableIssuer::open_guarded(
        &f.path,
        key,
        "another-key-id".into(),
        GuardStart {
            plan: &f.plan,
            plan_hash: &f.hash,
            launch: &f.launch,
            proc: &f.authority,
            receipt: &f.receipt,
            clock: || None,
        },
        Instant::now() + Duration::from_secs(5),
    );
    assert!(matches!(result, Err(Error::Binding)));
    assert_eq!(std::fs::read(&file).unwrap(), before);
    let issuer = f.issuer().unwrap();
    assert_eq!(issuer.public_key(), f.plan.ordinary_key.as_array());
}

#[test]
fn guarded_issuer_needs_the_actual_key_to_match_both_plan_publics_before_any_journal_write() {
    let variants: [(&str, ChangePlan); 2] = [
        ("plan ordinary key", |p| {
            p.ordinary_key = KeyBytes::from_array([9; 32])
        }),
        ("registered public key", |p| {
            p.pre_record.public_key[0] ^= 1;
            p.pre = p.pre_record.ctx(&p.x.host);
        }),
    ];
    for (name, change) in variants {
        let mut f = Fixture::new();
        change(&mut f.plan);
        f.hash = h(&f.plan).unwrap();
        f.launch.plan = f.hash.clone();
        let mut cut = f.receipt.body.cut.clone();
        cut.plan = f.hash.clone();
        cut.old = f.plan.pre.clone();
        cut.retired_epoch = f.plan.pre.epoch.clone();
        f.receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut), &f.hk).unwrap();
        let file = f.path.join("journal.json");
        let before = std::fs::read(&file).unwrap();
        assert!(
            matches!(f.issuer(), Err(Error::Binding)),
            "{name} differing from the actual key was accepted"
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            before,
            "{name} changed the journal"
        );
    }
}

#[test]
fn ack_after_an_ambiguous_rename_is_not_ready_after_the_journal_owner_is_gone() {
    let f = Fixture::new();
    let mut owner = f.journal().unwrap();
    let bind = f.pending(&mut owner);
    let reader = owner.reader();
    assert!(
        !reader
            .view()
            .authority_transition()
            .unwrap()
            .registration_state(None, clock())
            .unwrap()
            .ready
    );
    let mut next = State::clone(&owner.state);
    ack_candidate(&mut next, &bind).unwrap();
    assert!(matches!(
        owner.persist_inner(next, &mut |stage| stage == "directory_fsync"),
        Err(Error::Persistence)
    ));
    assert!(!f.path.join("journal.next").exists());
    let file = f.path.join("journal.json");
    let before = std::fs::read(&file).unwrap();
    let disk = read_state(&file).unwrap().unwrap();
    assert!(disk.authority_intents[bind.intent.as_str()]
        .acknowledgement
        .is_some());
    assert!(matches!(
        reader.view().authority_transition(),
        Err(Error::Persistence)
    ));
    drop((owner, reader));
    let storage_denied = matches!(f.journal(), Err(Error::Binding));
    let issuer_denied = matches!(f.issuer(), Err(Error::Binding));
    assert!(
        storage_denied && issuer_denied,
        "storage or issuer reattached to an ambiguous ACK"
    );
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

#[test]
fn signed_retirement_on_a_different_boot_does_not_write_guard_or_epoch() {
    let mut f = Fixture::new();
    let mut cut = f.receipt.body.cut.clone();
    cut.new_proc.boot = BootId::new("00000000-0000-4000-8000-000000000002").unwrap();
    f.receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut), &f.hk).unwrap();
    let path = f.path.join("journal.json");
    let before = std::fs::read(&path).unwrap();
    assert!(
        matches!(f.issuer(), Err(Error::Binding)),
        "an otherwise valid mixed-boot chain wrote a Guard"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!f.path.join("journal.next").exists());
}

#[test]
fn consumed_custodian_on_a_different_boot_does_not_write_guard_or_epoch() {
    let mut f = Fixture::new();
    f.launch.custodian.boot = BootId::new("00000000-0000-4000-8000-000000000002").unwrap();
    let path = f.path.join("journal.json");
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(f.issuer(), Err(Error::Binding)));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!f.path.join("journal.next").exists());
}

#[test]
fn ack_bytes_and_original_are_preserved_when_readiness_is_permanently_refused() {
    let f = Fixture::new();
    let mut journal = f.journal().unwrap();
    let bind = f.pending(&mut journal);
    let before = journal.authority_transition().unwrap();
    let original = before.origin().unwrap().clone();
    let ack = bind.record.ack();
    let done = RegDone {
        bind: bind.clone(),
        claim: original.claim,
        permit: original.permit.clone(),
        witness: original.witness.clone(),
        ack: ack.clone(),
        host_water: bind.record.generation,
    };
    let reader = journal.reader();
    assert!(journal.record_origin_ack(&before, &done, clock()).unwrap());
    assert!(
        !reader
            .view()
            .authority_transition()
            .unwrap()
            .registration_state(None, clock())
            .unwrap()
            .ready
    );
    journal.refuse_transition_readiness().unwrap();
    journal.publish();
    let current = reader.view().authority_transition().unwrap();
    let recovered = Clock {
        now: clock().now + 1,
        uncertainty: 1,
    };
    let state = current.registration_state(None, recovered).unwrap();
    assert!(state.uncertain && !state.ready);
    assert_eq!(state.intent, Some(original));
    let disk = read_state(&f.path.join("journal.json")).unwrap().unwrap();
    let native = disk.authority_intents[bind.intent.as_str()]
        .acknowledgement
        .as_ref()
        .unwrap();
    assert!(ack_matches(native, &ack));
    assert!(matches!(
        journal.record_origin_ack(&current, &done, recovered),
        Err(Error::Binding)
    ));
}
