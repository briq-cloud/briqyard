//! Public updates before the first continuation must retain creation authority.
use super::*;

async fn running() -> (crate::machine::tests::Harness, Arc<Entry>) {
    let (h, entry, request) = super::super::super::tests::fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    h.m.start_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    entry.rec.lock().unwrap().vmm_version = h.m.inner.vmm.version();
    h.m.save(&entry).unwrap();
    let record = entry.snapshot();
    let root_gb = record
        .clone_origin
        .as_ref()
        .unwrap()
        .artifact
        .recipe
        .root_disk_gb;
    h.pool
        .zfs
        .grow(&record.root_dataset(), u64::from(root_gb) << 30)
        .await
        .unwrap();
    h.pool
        .zfs
        .grow(
            &record.data_dataset(),
            u64::from(record.volume.as_ref().unwrap().size_gb) << 30,
        )
        .await
        .unwrap();
    (h, entry)
}

fn grow(size_gb: u32) -> api::UpdateMachineRequest {
    serde_json::from_value(json!({"volume": {"size_gb": size_gb}})).unwrap()
}

#[tokio::test]
async fn initial_running_growth_retries_coalesces_stops_and_consumes_sequence_one() {
    let (h, entry) = Box::pin(running()).await;
    let before = entry.snapshot();
    let id = before.id.clone();
    let live = entry.live.lock().unwrap().clone().unwrap();
    for gb in [3, 3, 4] {
        Box::pin(h.m.update(&id, grow(gb), None)).await.unwrap();
        let now = entry.snapshot();
        assert_eq!(now.pid, before.pid);
        assert_eq!(now.boot_incarnation, before.boot_incarnation);
        assert_eq!(now.launch_identity, before.launch_identity);
        assert!(now.assigned_run.is_none());
        assert!(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().is_none());
        assert_eq!(
            h.pool.zfs.volsize(&now.data_dataset()).await.unwrap(),
            u64::from(gb) << 30
        );
        assert_eq!(entry.live.lock().unwrap().as_ref().unwrap().pid, live.pid);
    }
    Box::pin(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    assert_eq!(entry.snapshot().state, state::STOPPED);
    let image = format!("alpine@sha256:{}", "7".repeat(64));
    h.m.inner
        .images
        .seed(&image, crate::image::ImageConfig::default())
        .await
        .unwrap();
    let files = vec![api::File {
        path: "/app/new".into(),
        base64: "bmV3".into(),
        mode: None,
    }];
    let env = BTreeMap::from([("FRESH".to_string(), "value".to_string())]);
    let size = api::Size {
        vcpus: before.size.vcpus,
        memory_mb: before.size.memory_mb + 128,
        ..before.size
    };
    Box::pin(
        h.m.update(
            &id,
            serde_json::from_value(
                json!({"image": image, "env": env, "files": files, "size": size}),
            )
            .unwrap(),
            None,
        ),
    )
    .await
    .unwrap();
    full_startup(&h).await.unwrap();
    Box::pin(h.m.start(&id, None)).await.unwrap();
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.reference.sequence, 1);
    assert!(current.previous_run_sha256.is_none());
    assert!(matches!(current.mode, Mode::Fresh { .. }));
    let applied = h.m.entry(&id).unwrap().snapshot();
    assert_eq!(applied.image, image);
    assert_eq!(applied.files, files);
    assert_eq!(applied.env, env);
    assert_eq!(applied.size, size);
}

#[tokio::test]
async fn initial_growth_recovery_adopts_same_process_or_settles_changed_boot_without_launch() {
    for changed_boot in [false, true] {
        let (h, entry) = Box::pin(running()).await;
        let before = entry.snapshot();
        Box::pin(h.m.update(&before.id, grow(3), None))
            .await
            .unwrap();
        if changed_boot {
            h.set_host_boot_id(Some("22222222-2222-4222-8222-222222222222"));
        }
        h.host_calls();
        full_startup(&h).await.unwrap();
        let recovered = h.m.entry(&before.id).unwrap();
        let update: UpdateIntent = h.m.inner.store.get(UPDATES, &before.id).unwrap().unwrap();
        assert_eq!(recovered.snapshot().volume.as_ref().unwrap().size_gb, 3);
        assert_eq!(update.creation_settlement.is_some(), changed_boot);
        if changed_boot {
            assert_eq!(recovered.snapshot().pid, 0);
            assert_eq!(recovered.snapshot().state, state::STOPPED);
            assert!(!recovered.identity_trusted.load(Relaxed));
        } else {
            assert_eq!(recovered.snapshot().pid, before.pid);
            assert!(recovered.identity_trusted.load(Relaxed));
        }
        assert!(!h
            .host_calls()
            .iter()
            .any(|call| call.starts_with("launch ")));
        assert!(h
            .m
            .inner
            .store
            .get::<Current>(RUNS, &before.id)
            .unwrap()
            .is_none());
    }
}

#[tokio::test]
async fn initial_growth_failed_machine_write_repairs_before_coalescing_and_settlement() {
    let (h, entry) = Box::pin(running()).await;
    let id = entry.snapshot().id;
    Box::pin(h.m.update(&id, grow(3), None)).await.unwrap();
    let blocked =
        h.m.inner
            .store
            .dir("machines")
            .join(format!("{id}.json.tmp"));
    std::fs::create_dir(&blocked).unwrap();
    assert!(Box::pin(h.m.update(&id, grow(4), None)).await.is_err());
    let outstanding: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert!(Box::pin(h.m.update(&id, grow(5), None)).await.is_err());
    let retained: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(outstanding.digest().unwrap(), retained.digest().unwrap());
    std::fs::remove_dir(blocked).unwrap();
    Box::pin(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    full_startup(&h).await.unwrap();
    assert_eq!(
        h.m.entry(&id).unwrap().snapshot().volume.unwrap().size_gb,
        4
    );
    Box::pin(h.m.start(&id, None)).await.unwrap();
}

#[tokio::test]
async fn initial_growth_refuses_replaced_data_and_uncertain_process_without_fallback() {
    for changed_disk in [false, true] {
        let (h, entry) = Box::pin(running()).await;
        let before = entry.snapshot();
        Box::pin(h.m.update(&before.id, grow(3), None))
            .await
            .unwrap();
        if changed_disk {
            h.pool.zfs.destroy(&before.data_dataset()).await.unwrap();
            h.pool
                .zfs
                .create(&before.data_dataset(), 3 << 30)
                .await
                .unwrap();
            assert!(Box::pin(h.m.update(&before.id, grow(4), None))
                .await
                .is_err());
        } else {
            h.assigned_adoption_profile(fc::UNAVAILABLE_PROFILE);
        }
        let result = full_startup(&h).await;
        if changed_disk {
            assert!(result.is_err());
        } else {
            result.unwrap();
            let recovered = h.m.entry(&before.id).unwrap();
            assert!(!recovered.identity_trusted.load(Relaxed));
            assert!(recovered.live.lock().unwrap().is_none());
            assert!(h.m.ordinary_operation(&recovered.snapshot()).is_err());
        }
        assert!(h
            .m
            .inner
            .store
            .get::<UpdateIntent>(UPDATES, &before.id)
            .unwrap()
            .is_some());
        assert!(h.pool.zfs.exists(&before.root_dataset()).await.unwrap());
    }
}

#[tokio::test]
async fn initial_growth_settles_spontaneous_exit_and_rejects_forged_settlement() {
    let (h, entry) = Box::pin(running()).await;
    let before = entry.snapshot();
    Box::pin(h.m.update(&before.id, grow(3), None))
        .await
        .unwrap();
    let live = entry.live.lock().unwrap().clone().unwrap();
    h.m.inner.vmm.kill(live.pid);
    h.m.settle_exit(&entry, live.pid).await;
    assert_eq!(entry.snapshot().pid, 0);
    assert_eq!(entry.snapshot().state, state::STOPPED);
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &before.id).unwrap().unwrap();
    assert!(update.creation_settlement.is_some());
    for pointer in [
        "/creation_settlement/incarnation/pid",
        "/creation_settlement/stopped_baseline_sha256",
    ] {
        let mut value = serde_json::to_value(&update).unwrap();
        *value.pointer_mut(pointer).unwrap() = if pointer.ends_with("pid") {
            json!(42)
        } else {
            json!("0".repeat(64))
        };
        let forged: UpdateIntent = serde_json::from_value(value).unwrap();
        assert!(forged.check_shape().is_err());
    }
    full_startup(&h).await.unwrap();
    Box::pin(h.m.start(&before.id, None)).await.unwrap();
}

#[tokio::test]
async fn initial_growth_refuses_oversized_backing_shrink_and_running_files() {
    let (h, entry) = Box::pin(running()).await;
    let before = entry.snapshot();
    Box::pin(h.m.update(&before.id, grow(3), None))
        .await
        .unwrap();
    assert!(Box::pin(h.m.update(&before.id, grow(2), None))
        .await
        .is_err());
    assert!(Box::pin(h.m.update(
        &before.id,
        serde_json::from_value(json!({"files": []})).unwrap(),
        None
    ))
    .await
    .is_err());
    h.pool
        .zfs
        .grow(&before.data_dataset(), 5 << 30)
        .await
        .unwrap();
    assert!(Box::pin(h.m.update(&before.id, grow(3), None))
        .await
        .is_err());
    assert!(Box::pin(h.m.update(&before.id, grow(6), None))
        .await
        .is_err());
    assert_eq!(entry.snapshot().volume.unwrap().size_gb, 3);
    assert!(entry.snapshot().assigned_run.is_none());
}

#[tokio::test]
async fn creation_settlement_uncertain_machine_write_repairs_before_retry_publication() {
    let (h, entry) = Box::pin(running()).await;
    let id = entry.snapshot().id;
    Box::pin(h.m.update(&id, grow(3), None)).await.unwrap();
    let guard = entry.lock.lock().await;
    let live = entry.live.lock().unwrap().clone().unwrap();
    let blocked =
        h.m.inner
            .store
            .dir("machines")
            .join(format!("{id}.json.tmp"));
    std::fs::create_dir(&blocked).unwrap();
    h.m.inner.vmm.kill(live.pid);
    assert!(h.m.settle_creation_update(&entry).await.is_err());
    let settlement: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert!(settlement.creation_settlement.is_some());
    std::fs::remove_dir(blocked).unwrap();
    h.m.settle_creation_update(&entry).await.unwrap();
    assert_eq!(entry.snapshot().pid, 0);
    assert!(!entry.snapshot().suspended);
    drop(guard);
    h.m.settle_exit(&entry, live.pid).await;
    full_startup(&h).await.unwrap();
    Box::pin(h.m.start(&id, None)).await.unwrap();
}
