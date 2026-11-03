//! Stand-in backend preservation checks, not native process/adoption qualification.
use super::*;
use crate::machine::assignments::tests::fixture;

async fn assigned(stage: templates::CloneStage) -> (Harness, Arc<Entry>) {
    let (h, entry, request) = fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    h.m.commit_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    {
        let mut record = entry.rec.lock().unwrap();
        record.clone_origin.as_mut().unwrap().stage = stage;
        record.state = state::RUNNING.into();
    }
    h.m.save(&entry).unwrap();
    (h, entry)
}

fn preserved(h: &Harness, entry: &Arc<Entry>, before: &Record, trusted: bool) {
    let after = entry.snapshot();
    assert_eq!(
        serde_json::to_value(&after).unwrap(),
        serde_json::to_value(before).unwrap()
    );
    let stored = h.stored(&before.id).unwrap();
    assert_eq!(
        serde_json::to_value(stored).unwrap(),
        serde_json::to_value(before).unwrap()
    );
    assert_eq!(entry.identity_trusted.load(Relaxed), trusted);
    let live = entry.live.lock().unwrap().clone().unwrap();
    assert_eq!(live.pid, before.pid);
    assert_eq!(live.incarnation, before.boot_incarnation);
    assert!(!*live.exited.borrow());
    assert!(h
        .m
        .inner
        .launch_holds
        .lock()
        .unwrap()
        .contains_key(&before.id));
    assert!(h
        .m
        .inner
        .store
        .get::<serde_json::Value>("launch-holds", &before.id)
        .unwrap()
        .is_some());
    assert_eq!(after.root_dataset(), before.root_dataset());
    let calls = h.host_calls();
    assert!(
        !calls.iter().any(|call| [
            "stop ",
            "suspend ",
            "shutdown ",
            "snapshot ",
            "kill ",
            "destroy ",
            "net ",
            "exec "
        ]
        .iter()
        .any(|prefix| call.starts_with(prefix))),
        "{calls:?}"
    );
}

#[tokio::test]
async fn assigned_close_and_handover_preserve_each_stage_without_readiness_authority() {
    for stage in [
        templates::CloneStage::Loading,
        templates::CloneStage::Configuring,
        templates::CloneStage::IdentityDone,
        templates::CloneStage::Active,
    ] {
        for handover in [false, true] {
            let (h, entry) = assigned(stage.clone()).await;
            entry.identity_trusted.store(false, Relaxed);
            entry.probe.lock().unwrap().ready = true;
            let before = entry.snapshot();
            let quota = h.m.quota("destination").unwrap().used;
            h.host_calls();
            if handover {
                let held = h.m.hand_over().await;
                assert!(!h.m.take_handed_ready().contains(&before.id));
                preserved(&h, &entry, &before, false);
                drop(held);
            } else {
                h.m.close().await;
                preserved(&h, &entry, &before, false);
            }
            let after = h.m.quota("destination").unwrap().used;
            assert_eq!(after, quota);
        }
    }
}

#[tokio::test]
async fn assigned_close_keeps_missing_or_corrupt_authority_and_untrusted_process() {
    for corruption in 0..3 {
        let (h, entry) = assigned(templates::CloneStage::Active).await;
        let requests = h.m.inner.store.dir("unbound-requests");
        let receipt = std::fs::read_dir(requests)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        match corruption {
            0 => std::fs::remove_file(receipt).unwrap(),
            1 => std::fs::write(receipt, b"invalid JSON").unwrap(),
            _ => {
                // Missing launch identity is not permission to treat a held assignment
                // as an ordinary machine; its durable/cached allocation remains held.
                entry.rec.lock().unwrap().launch_identity = None;
                h.m.save(&entry).unwrap();
            }
        }
        entry.identity_trusted.store(false, Relaxed);
        let before = entry.snapshot();
        h.host_calls();
        h.m.close().await;
        preserved(&h, &entry, &before, false);
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
    }
}

#[tokio::test]
async fn unreadable_assignment_authority_cannot_authorize_ordinary_close_effects() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let machine =
        h.m.create_made(h.request("unknown-authority"))
            .await
            .unwrap();
    let entry = h.m.entry(&machine.id).unwrap();
    let before = entry.snapshot();
    std::fs::write(
        h.m.inner.store.dir("unbound-requests").join("corrupt.json"),
        b"invalid",
    )
    .unwrap();
    h.host_calls();
    h.m.close().await;
    assert_eq!(entry.snapshot().pid, before.pid);
    assert_eq!(entry.snapshot().state, before.state);
    let calls = h.host_calls();
    assert!(
        !calls.iter().any(|call| call.starts_with("suspend ")
            || call.starts_with("stop ")
            || call.starts_with("shutdown ")
            || call.starts_with("snapshot ")),
        "{calls:?}"
    );
}
