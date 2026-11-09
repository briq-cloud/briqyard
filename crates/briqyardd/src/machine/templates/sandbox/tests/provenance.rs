use super::*;

#[tokio::test]
async fn sandbox_creation_origin_requires_committed_index_and_exact_record_binding() {
    let (h, source, seed) = source().await;
    assert!(h
        .m
        .get(&source.snapshot().id)
        .unwrap()
        .create_origin
        .is_none());
    let request = destination(seed);
    let digest = request_digest(&request).unwrap();
    let (entry, _) = h.m.record(request.clone(), None).await.unwrap();
    let id = entry.snapshot().id;
    let expected = api::CreateOrigin {
        kind: api::CreateOriginKind::SandboxSeed,
        request_id: request.sandbox_seed.as_ref().unwrap().request_id.clone(),
        create_sha256: digest,
    };
    assert_eq!(h.m.get(&id).unwrap().create_origin, Some(expected.clone()));
    assert_eq!(
        h.m.list(Some("destination"), &[])[0].create_origin,
        Some(expected.clone())
    );
    let cache = entry.sandbox_index.lock().unwrap().take();
    assert!(h.m.get(&id).unwrap().create_origin.is_none());
    // Reconstruct through the existing durable recovery path, not from a binding alone.
    h.m.recover_sandbox_assignments().unwrap();
    assert_eq!(h.m.get(&id).unwrap().create_origin, Some(expected.clone()));
    let record = entry.snapshot();
    let mut invalid = record.clone();
    invalid
        .clone_origin
        .as_mut()
        .unwrap()
        .sandbox
        .as_mut()
        .unwrap()
        .create_sha256 = "invalid".into();
    let mut index =
        serde_json::to_value(entry.sandbox_index.lock().unwrap().as_ref().unwrap()).unwrap();
    index["create_sha256"] = "invalid".into();
    let valid_cache = entry
        .sandbox_index
        .lock()
        .unwrap()
        .replace(serde_json::from_value(index).unwrap());
    assert!(
        h.m.create_origin(&entry, &invalid).is_none(),
        "matching malformed evidence is still unknown"
    );
    *entry.sandbox_index.lock().unwrap() = valid_cache;
    for change in [0, 1, 2] {
        let mut changed = record.clone();
        match change {
            0 => changed.namespace = "other".into(),
            1 => {
                changed
                    .clone_origin
                    .as_mut()
                    .unwrap()
                    .sandbox
                    .as_mut()
                    .unwrap()
                    .request_id = "another".into()
            }
            _ => {
                changed
                    .clone_origin
                    .as_mut()
                    .unwrap()
                    .sandbox
                    .as_mut()
                    .unwrap()
                    .create_sha256 = "0".repeat(64)
            }
        }
        assert!(h.m.create_origin(&entry, &changed).is_none());
    }
    // Current boot state is not the accepted creation path.
    let mut later = record;
    later.state = state::STOPPED.into();
    later.suspended = false;
    assert_eq!(h.m.create_origin(&entry, &later), Some(expected.clone()));
    let (same, _) = h.m.record(request, None).await.unwrap();
    assert_eq!(same.snapshot().id, id);
    assert_eq!(h.m.get(&id).unwrap().create_origin, Some(expected));
    drop(cache);
}

#[tokio::test]
async fn warm_creation_origin_survives_replay_and_never_downgrades_conflicting_ownership() {
    let (h, seed, slot) = unbound::bounded(unbound::pool()).await;
    let id = slot.snapshot().id;
    assert!(h.m.get(&id).unwrap().create_origin.is_none());
    let request = destination(seed);
    let expected = api::CreateOrigin {
        kind: api::CreateOriginKind::UnboundWarm,
        request_id: request.sandbox_seed.as_ref().unwrap().request_id.clone(),
        create_sha256: request_digest(&request).unwrap(),
    };
    let accepted = unbound::bounded(h.m.create(request.clone())).await.unwrap();
    assert_eq!(accepted.id, id);
    let running =
        h.m.wait(&id, Until::Ready, Duration::from_secs(10))
            .await
            .unwrap();
    assert_eq!(running.create_origin, Some(expected.clone()));
    assert_eq!(
        unbound::bounded(h.m.create(request))
            .await
            .unwrap()
            .create_origin,
        Some(expected.clone())
    );
    // Even a direct-seed index cannot override an assignment's conflicting record.
    h.m.persist_sandbox_assignment(&slot).unwrap();
    let mut invalid = slot.snapshot();
    invalid.launch_identity = None;
    assert!(h.m.create_origin(&slot, &invalid).is_none());
    invalid = slot.snapshot();
    invalid
        .clone_origin
        .as_mut()
        .unwrap()
        .sandbox
        .as_mut()
        .unwrap()
        .create_sha256 = "0".repeat(64);
    assert!(h.m.create_origin(&slot, &invalid).is_none());
    assert_eq!(h.m.get(&id).unwrap().create_origin, Some(expected));
}
