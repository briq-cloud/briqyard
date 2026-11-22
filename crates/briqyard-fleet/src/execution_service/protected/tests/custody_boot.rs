use super::*;
use briqyard_api::execution::sealed::{
    custody::{CaptureBody, ExitBody, MatchBody, Slot},
    prim::LitBool,
    transition::LDecision,
};

struct Startup {
    _tmp: tempfile::TempDir,
    path: PathBuf,
    ordinary: Vec<u8>,
    plan: Plan,
    plan_hash: HexDigest,
    authority: Proc,
    launch: Launch,
    grant: LGrant,
    capture: Capture,
    load: Sig<LoadBody>,
    request: CustodyWire,
    matched: Matched,
    exited: Exited,
    ak: Arc<Key>,
    peer: Arc<Peer>,
}

impl Startup {
    fn new(custodian_boot: BootId) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("authority");
        let host_path = tmp.path().join("host");
        let mut predecessor =
            Journal::open(&path, admission::Role::Authority("authority-1".into())).unwrap();
        let mut old_host =
            Journal::open(&host_path, admission::Role::Host("host-1".into())).unwrap();
        let (ordinary, pkcs8) = new_key();
        let ak = Arc::new(new_key().0);
        let hk = new_key().0;
        let bk = new_key().0;
        let rk = new_key().0;
        let x = X {
            aud: Env::Staging,
            host: id("host-1"),
            op: hash("custodian-boot"),
            serial: pos(1),
        };
        let native = HostRegistration {
            authority: "authority-1".into(),
            epoch: predecessor.instance().into(),
            key_id: "key-1".into(),
            public_key: ordinary.public_key(),
            host_instance: old_host.instance().into(),
            generation: 2,
        };
        let record = Reg::from_native(&native).unwrap();
        old_host.register_host(native.clone(), clock()).unwrap();
        predecessor
            .begin_authority_intent(
                "predecessor",
                x.host.as_str(),
                record.host_instance.as_str(),
                AuthorityPayload::Registration(native),
                clock(),
            )
            .unwrap();
        let ack = record.ack();
        predecessor
            .acknowledge_authority_intent(
                "predecessor",
                InstallationAck {
                    host_instance: ack.host_instance.to_string(),
                    generation: ack.generation.get(),
                    digest: ack.digest.to_text(),
                },
                clock(),
            )
            .unwrap();
        drop((predecessor, old_host));
        let host_journal =
            Journal::open(&host_path, admission::Role::Host(x.host.to_string())).unwrap();
        let host = proc(20, "new-daemon");
        let authority = proc(21, "new-authority");
        let plan = Plan {
            x: x.clone(),
            registered: id("registered"),
            pre: record.ctx(&x.host),
            pre_record: record,
            pre_intent: id("predecessor"),
            pre_d: proc(10, "old-daemon"),
            pre_a: proc(11, "old-authority"),
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
            custodian: Proc {
                boot: custodian_boot,
                ..proc(12, "custodian")
            },
            successor: None,
            death: None,
            nonce: nonce().unwrap(),
        };
        let decision = LDecision {
            x: x.clone(),
            plan: plan_hash.clone(),
            action: LKind::LaunchA,
            owner: launch.owner,
            expected: launch.old.clone(),
            nonce: nonce().unwrap(),
        };
        let grant = LGrant {
            receiver: Sig::sign(Tag::LaunchReceiver, decision.clone(), &rk).unwrap(),
            api: Sig::sign(Tag::LaunchApi, decision, &bk).unwrap(),
        };
        let wire = CustodyWire {
            x: x.clone(),
            plan: plan_hash.clone(),
            resource: Resource::Authority,
            owner: launch.owner,
            custodian: launch.custodian.clone(),
            old: launch.old.clone(),
            next: None,
            challenge: launch.nonce,
            slot: Slot::new(1).unwrap(),
        };
        let request = CustodyWire::request_for(&wire, authority.clone(), nonce().unwrap()).unwrap();
        let capture = Sig::sign(Tag::CustodyCapture, CaptureBody { wire }, &rk).unwrap();
        let capture_hash = h(&capture).unwrap();
        let matched = Sig::sign(
            Tag::CustodyMatch,
            MatchBody {
                wire: request.clone(),
                capture: capture_hash.clone(),
                same: LitBool,
            },
            &rk,
        )
        .unwrap();
        let exited = Sig::sign(
            Tag::CustodyExit,
            ExitBody {
                wire: request.clone(),
                matched: h(&matched).unwrap(),
                exited: LitBool,
            },
            &rk,
        )
        .unwrap();
        let load = Sig::sign(
            Tag::CustodyLoad,
            LoadBody {
                x: x.clone(),
                plan: plan_hash.clone(),
                resource: Resource::Authority,
                owner: launch.owner,
                launch: launch.hash().unwrap(),
                capture: capture_hash,
            },
            &rk,
        )
        .unwrap();
        let instance = id(host_journal.instance());
        let cut = Cut {
            x: x.clone(),
            plan: plan_hash.clone(),
            old: plan.pre.clone(),
            old_set: plan.old.set().unwrap(),
            new_instance: instance.clone(),
            old_proc: plan.pre_d.clone(),
            new_proc: host,
            custody: hash("custody"),
            profile: hash("profile"),
            retired_epoch: plan.pre.epoch.clone(),
            prior_host_water: plan.pre.generation,
        };
        let receipt = Sig::sign(Tag::Retired, ReceiptBody::new(cut.clone()), &hk).unwrap();
        let peer = Arc::new(Peer {
            hk,
            bk,
            host_journal: Mutex::new(host_journal),
            gate: Mutex::new(Gate {
                x,
                plan: plan_hash.clone(),
                instance,
                phase: GatePhase::Sealed,
                cut: Some(cut),
                receipt: Some(receipt),
                bind: None,
                arm: None,
                done: None,
                release: None,
            }),
            permit: Mutex::new(None),
            host_reads: Mutex::new(None),
            stale_host: AtomicBool::new(false),
            stale_api: AtomicBool::new(false),
            wrong_clock: AtomicBool::new(false),
            signed_clock: AtomicU64::new(0),
            wrong_target: AtomicBool::new(false),
            sends: AtomicUsize::new(0),
        });
        Self {
            _tmp: tmp,
            path,
            ordinary: pkcs8,
            plan,
            plan_hash,
            authority,
            launch,
            grant,
            capture,
            load,
            request,
            matched,
            exited,
            ak,
            peer,
        }
    }

    fn custody(&self) -> CustodyStart<'_> {
        CustodyStart {
            plan: self.plan.clone(),
            plan_hash: self.plan_hash.clone(),
            consumed: &self.launch,
            grant: &self.grant,
            launch_claim: self.grant.api.body.nonce,
            capture: &self.capture,
            load: &self.load,
            request: &self.request,
            matched: &self.matched,
            exited: &self.exited,
        }
    }

    async fn start(&self) -> Result<Protected, Error> {
        Protected::from_custody(
            &self.path,
            &self.ordinary,
            "key-1".into(),
            self.custody(),
            self.ak.clone(),
            self.peer.clone(),
            (self.authority.clone(), sample),
        )
        .await
    }

    fn journal_bytes(&self) -> Vec<u8> {
        std::fs::read(self.path.join("journal.json")).unwrap()
    }

    fn assert_preserved(&self, before: &[u8]) {
        assert_eq!(self.journal_bytes(), before);
        assert!(!self.path.join("journal.next").exists());
        let state: serde_json::Value = serde_json::from_slice(before).unwrap();
        assert!(state.get("sealed_authority").is_none());
    }
}

fn other_boot() -> BootId {
    BootId::new("00000000-0000-4000-8000-000000000002").unwrap()
}

#[test]
fn correctly_signed_custody_chain_on_a_different_boot_is_refused() {
    let f = Startup::new(other_boot());
    let before = f.journal_bytes();
    assert!(matches!(
        f.custody().verify(&f.authority, f.ak.as_ref()),
        Err(Error::Binding)
    ));
    f.assert_preserved(&before);
}

#[tokio::test]
async fn full_custody_start_refuses_a_different_custodian_boot_before_writing() {
    let f = Startup::new(other_boot());
    let before = f.journal_bytes();
    assert!(matches!(f.start().await, Err(Error::Binding)));
    f.assert_preserved(&before);

    let same_boot = Startup::new(f.authority.boot.clone());
    let service = same_boot.start().await.unwrap();
    assert_eq!(
        service.snapshot().unwrap().guard().phase,
        GuardPhase::Started
    );
}
