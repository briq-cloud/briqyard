use super::*;
use briqyard_api::execution::admission::JournalReader;
use std::cell::RefCell;

enum After {
    Pending,
    Ack,
}

struct ClockLoss {
    journal: PathBuf,
    published: JournalReader,
    intent: Ident,
    after: After,
    request_deadline: Instant,
    before_write: Option<Instant>,
    after_write: bool,
}

thread_local! {
    static CLOCK_LOSS: RefCell<Option<ClockLoss>> = const { RefCell::new(None) };
}

pub(super) fn gate_sample(sample: ClockSample) -> Option<ClockSample> {
    CLOCK_LOSS.with(|state| {
        if let Some(loss) = state.borrow_mut().as_mut() {
            let persisted = match loss.after {
                After::Pending => {
                    journal_image(&loss.journal)["sealed_authority"]["origin"]["original"]["id"]
                        .as_str()
                        == Some(loss.intent.as_str())
                }
                After::Ack => !retained_ack(&loss.journal, &loss.intent).is_null(),
            };
            if !persisted {
                loss.before_write = Some(sample.monotonic);
            } else {
                assert!(sample.monotonic < loss.request_deadline);
                assert!(sample.monotonic < loss.before_write.unwrap() + Duration::from_secs(1));
                let view = loss.published.view().authority_transition().unwrap();
                if matches!(loss.after, After::Pending) {
                    assert!(view.origin().is_none());
                }
                assert!(
                    !view
                        .registration_state(None, sample.interval().unwrap())
                        .unwrap()
                        .ready
                );
                loss.after_write = true;
                return None;
            }
        }
        Some(sample)
    })
}

fn retained_ack(path: &Path, intent: &Ident) -> serde_json::Value {
    journal_image(path)["authority_intents"][intent.as_str()]["acknowledgement"].clone()
}

fn journal_image(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn qualified_clock_loss_after_pending_fsync_releases_no_witness_or_send() {
    let f = Fixture::new();
    let adopt = f.packet(ClaimKind::Adopt).await;
    f.service.adopt(&adopt, Instant::now()).await.unwrap();
    let file = f.path.join("journal.json");
    let packet = f.packet(ClaimKind::Register).await;
    let received = Instant::now();
    let reader = f.service.issuer.lock().await.reader();
    CLOCK_LOSS.with(|slot| {
        slot.replace(Some(ClockLoss {
            journal: file.clone(),
            published: reader,
            intent: f.bind.intent.clone(),
            after: After::Pending,
            request_deadline: received + FRESH,
            before_write: None,
            after_write: false,
        }))
    });
    let refused = f.service.register(packet.clone(), received).await;
    let loss = CLOCK_LOSS.with(|slot| slot.take().unwrap());
    assert_eq!(
        f.peer.sends.load(Ordering::SeqCst),
        0,
        "send occurred after pending fsync without clock qualification"
    );
    assert!(
        loss.after_write,
        "no local qualification after pending fsync"
    );
    assert!(matches!(
        refused,
        Err(Error::Journal(admission::Error::Persistence))
    ));

    let read = f.read(None).await;
    assert!(!read.body.ready && !read.body.uncertain);
    let intent = read.body.intent.unwrap();
    let bytes = std::fs::read(&file).unwrap();
    let disk = journal_image(&file);
    let origin = &disk["sealed_authority"]["origin"];
    assert_eq!(origin["send_consumed"], true);
    assert_eq!(origin["original"], serde_json::to_value(&intent).unwrap());
    assert_eq!(intent.phase, IntentPhase::Pending);
    assert_eq!(intent.record, f.bind.record);
    assert_eq!(intent.claim, packet.p.body.claim);
    assert_eq!(intent.guard, read.body.guard_hash);
    assert_eq!(intent.permit, h(&packet.p).unwrap());
    assert_eq!(
        intent.permit,
        HexDigest::of(origin["permit"].as_str().unwrap().as_bytes())
    );
    assert_eq!(
        intent.witness,
        HexDigest::of(origin["witness"].as_str().unwrap().as_bytes())
    );
    assert!(intent.ack.is_none());
    assert_eq!(read.body.native_water.get(), f.bind.record.generation.get());
    assert_eq!(f.peer.gate.lock().unwrap().phase, GatePhase::Armed);
    assert!(f.service.register(packet, Instant::now()).await.is_err());
    assert_eq!(f.peer.sends.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(file).unwrap(), bytes);
    let recovered = f.read(None).await;
    assert!(!recovered.body.ready);
    assert_eq!(recovered.body.intent, Some(intent));
}

#[tokio::test]
async fn qualified_clock_loss_after_ack_fsync_permanently_refuses_ready() {
    let f = Fixture::new();
    let adopt = f.packet(ClaimKind::Adopt).await;
    f.service.adopt(&adopt, Instant::now()).await.unwrap();
    assert!(matches!(
        f.service
            .register(f.packet(ClaimKind::Register).await, Instant::now())
            .await,
        Err(Error::Unavailable)
    ));
    let original = f.read(None).await.body.intent.unwrap();
    let file = f.path.join("journal.json");
    let packet = f.packet(ClaimKind::RecordAck).await;
    let received = Instant::now();
    let reader = f.service.issuer.lock().await.reader();
    CLOCK_LOSS.with(|slot| {
        slot.replace(Some(ClockLoss {
            journal: file.clone(),
            published: reader,
            intent: original.id.clone(),
            after: After::Ack,
            request_deadline: received + FRESH,
            before_write: None,
            after_write: false,
        }))
    });
    let refused = f.service.record_ack(&packet, received).await;
    let loss = CLOCK_LOSS.with(|slot| slot.take().unwrap());
    assert!(loss.after_write, "no local qualification after ACK fsync");
    assert!(matches!(
        refused,
        Err(Error::Journal(admission::Error::Persistence))
    ));

    let ack = f.bind.record.ack();
    assert_eq!(
        retained_ack(&file, &original.id),
        serde_json::json!({
            "host_instance": ack.host_instance, "generation": ack.generation, "digest": ack.digest
        })
    );
    let recovered = f.read(None).await;
    assert!(recovered.body.uncertain && !recovered.body.ready);
    assert_eq!(recovered.body.intent, Some(original));
    assert!(f.service.record_ack(&packet, Instant::now()).await.is_err());
    assert_eq!(f.peer.sends.load(Ordering::SeqCst), 1);
}

#[test]
fn pinned_host_proof_on_a_different_boot_is_not_startup_evidence() {
    let f = Fixture::new();
    let q = Q {
        x: f.bind.x.clone(),
        nonce: nonce().unwrap(),
    };
    let mut body = f.peer.read_host(q.clone()).body;
    let mut cut = body.gate.cut.take().unwrap();
    cut.new_proc.boot = BootId::new("00000000-0000-4000-8000-000000000002").unwrap();
    body.proc = cut.new_proc.clone();
    body.gate.receipt =
        Some(Sig::sign(Tag::Retired, ReceiptBody::new(cut.clone()), &f.peer.hk).unwrap());
    body.gate.cut = Some(cut);
    body.gate_hash = body.gate.hash().unwrap();
    for projection in &mut body.cap.projections {
        projection.basis = body.gate_hash.clone();
    }
    let signed = Sig::sign(Tag::HostRead, body, &f.peer.hk).unwrap();
    signed.verify(Tag::HostRead, &f.service.pins.hk).unwrap();
    let query = ProofQuery {
        q,
        plan: f.bind.plan.clone(),
        preview: None,
    };
    let file = f.path.join("journal.json");
    let before = std::fs::read(&file).unwrap();
    assert!(
        verify_host(
            &signed,
            &query,
            &f.service.plan,
            &f.bind.plan,
            &f.service.pins.hk
        )
        .is_err(),
        "a correctly signed host proof from another boot was accepted"
    );
    assert_eq!(std::fs::read(file).unwrap(), before);
}
