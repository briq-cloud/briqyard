use super::*;

fn request(claim_nonce: &str) -> api::StoppedUpdateRequest {
    api::StoppedUpdateRequest {
        claim_nonce: claim_nonce.into(),
        image: "alpine:3".into(),
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn acceptance_is_durable_current_and_invalidated_by_later_claim() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    e.rec.lock().unwrap().suspended = true;
    let at = e.snapshot().version;
    let receipt =
        h.m.stopped_update("m_receipt", request("n_first"), at)
            .await
            .unwrap();
    assert!(!e.snapshot().suspended);
    assert_eq!(h.stored("m_receipt").unwrap().version, receipt.version);
    assert_eq!(
        h.m.stopped_update_receipt("m_receipt", "n_first")
            .await
            .unwrap(),
        receipt
    );
    let mut conflict = request("n_first");
    conflict.env.insert("KEY".into(), "changed".into());
    assert!(h
        .m
        .stopped_update("m_receipt", conflict, receipt.version)
        .await
        .is_err());
    let later =
        h.m.stopped_update("m_receipt", request("n_second"), receipt.version)
            .await
            .unwrap();
    assert!(later.version > receipt.version);
    assert!(matches!(
        h.m.stopped_update_receipt("m_receipt", "n_first").await,
        Err(MError::NotFound)
    ));
    assert_eq!(
        h.m.stopped_update_receipt("m_receipt", "n_second")
            .await
            .unwrap(),
        later
    );
    h.host
        .host_boot_id
        .lock()
        .unwrap()
        .replace("22222222-2222-4222-8222-222222222222".into());
    assert!(matches!(
        h.m.stopped_update_receipt("m_receipt", "n_second").await,
        Err(MError::NotFound)
    ));
}

#[tokio::test]
async fn unchanged_targets_still_require_exit_and_cas() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    let r = e.snapshot();
    let req = api::StoppedUpdateRequest {
        claim_nonce: "n_noop".into(),
        image: r.image,
        env: r.env,
    };
    h.host
        .unproven_launches
        .lock()
        .unwrap()
        .insert("m_receipt".into());
    assert!(h
        .m
        .stopped_update("m_receipt", req.clone(), r.version)
        .await
        .is_err());
    assert!(e.snapshot().stopped_updates.is_empty());
    h.host.unproven_launches.lock().unwrap().clear();
    e.rec.lock().unwrap().pid = 123;
    assert!(h
        .m
        .stopped_update("m_receipt", req.clone(), r.version)
        .await
        .is_err());
    e.rec.lock().unwrap().pid = 0;
    assert!(matches!(
        h.m.stopped_update("m_receipt", req.clone(), r.version + 1)
            .await,
        Err(MError::Moved(_))
    ));
    let receipt =
        h.m.stopped_update("m_receipt", req, r.version)
            .await
            .unwrap();
    assert!(receipt.version > r.version);
    assert!(e.snapshot().pending.is_none());
}

#[tokio::test]
async fn failed_save_cannot_publish_a_receipt_or_target() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    let before = e.snapshot();
    let tmp = h.m.inner.store.dir("machines").join("m_receipt.json.tmp");
    std::fs::create_dir(&tmp).unwrap();
    assert!(h
        .m
        .stopped_update("m_receipt", request("n_failed"), before.version)
        .await
        .is_err());
    assert_eq!(e.snapshot().version, before.version);
    assert!(e.snapshot().pending.is_none());
    assert!(h
        .m
        .stopped_update_receipt("m_receipt", "n_failed")
        .await
        .is_err());
}

#[tokio::test]
async fn source_lineage_is_refused_before_effects() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    e.rec.lock().unwrap().from_source = true;
    assert!(h
        .m
        .stopped_update("m_receipt", request("n_source"), e.snapshot().version)
        .await
        .is_err());
    assert!(e.snapshot().stopped_updates.is_empty());
}

#[tokio::test]
async fn exact_lookup_never_rolls_back_different_memory() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    let before = e.snapshot();
    let accepted =
        h.m.stopped_update("m_receipt", request("n_recover"), before.version)
            .await
            .unwrap();
    let candidate = e.snapshot();
    // An unexpected older or same-version different memory record must never be
    // replaced just because the persisted receipt has a plausible target.
    *e.rec.lock().unwrap() = before;
    assert!(h
        .m
        .stopped_update_receipt("m_receipt", "n_recover")
        .await
        .is_err());
    *e.rec.lock().unwrap() = candidate.clone();
    e.rec.lock().unwrap().backup_bytes += 1;
    assert!(h
        .m
        .stopped_update_receipt("m_receipt", "n_recover")
        .await
        .is_err());
    assert_eq!(e.snapshot().backup_bytes, candidate.backup_bytes + 1);
    *e.rec.lock().unwrap() = candidate;
    assert_eq!(
        h.m.stopped_update_receipt("m_receipt", "n_recover")
            .await
            .unwrap(),
        accepted
    );
    let mut newer = e.snapshot();
    e.note_locked(&mut newer, Ev::normal(reason::UPDATED, "a later edit"));
    *e.rec.lock().unwrap() = newer;
    assert!(matches!(
        h.m.stopped_update_receipt("m_receipt", "n_recover").await,
        Err(MError::NotFound)
    ));
}

#[tokio::test]
async fn running_handle_refuses_even_when_record_and_launch_tracker_say_stopped() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let e = h.m.own_entry(&m.id).unwrap();
    let mut live = e.live.lock().unwrap().clone().unwrap();
    h.m.stop(&m.id, Duration::from_secs(1), true, None)
        .await
        .unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    live.exited = rx;
    *e.live.lock().unwrap() = Some(live);
    assert!(h
        .m
        .stopped_update(&m.id, request("n_live"), e.snapshot().version)
        .await
        .is_err());
    assert!(e.snapshot().stopped_updates.is_empty());
}

#[tokio::test]
async fn start_and_ownership_changes_invalidate_receipts() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let stopped =
        h.m.stop(&m.id, Duration::from_secs(1), true, None)
            .await
            .unwrap();
    let e = h.m.own_entry(&m.id).unwrap();
    let r = e.snapshot();
    let req = api::StoppedUpdateRequest {
        claim_nonce: "n_start".into(),
        image: r.image,
        env: r.env,
    };
    let accepted =
        h.m.stopped_update(&m.id, req, stopped.version)
            .await
            .unwrap();
    h.m.start(&m.id, Some(accepted.version)).await.unwrap();
    assert!(h.m.stopped_update_receipt(&m.id, "n_start").await.is_err());
    let stopped =
        h.m.stop(&m.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
    let r = e.snapshot();
    let req = api::StoppedUpdateRequest {
        claim_nonce: "n_move".into(),
        image: r.image,
        env: r.env,
    };
    let accepted =
        h.m.stopped_update(&m.id, req, stopped.version)
            .await
            .unwrap();
    h.m.move_machine(&m.id, "new_owner", Some(accepted.version))
        .await
        .unwrap();
    assert!(h.m.stopped_update_receipt(&m.id, "n_move").await.is_err());
}

#[tokio::test]
async fn restore_invalidates_the_current_receipt() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let snap =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let stopped =
        h.m.stop(&m.id, Duration::from_secs(1), true, None)
            .await
            .unwrap();
    let e = h.m.own_entry(&m.id).unwrap();
    let r = e.snapshot();
    let req = api::StoppedUpdateRequest {
        claim_nonce: "n_restore".into(),
        image: r.image,
        env: r.env,
    };
    let accepted =
        h.m.stopped_update(&m.id, req, stopped.version)
            .await
            .unwrap();
    h.m.restore_snapshot(&m.id, &snap.id, Some(accepted.version))
        .await
        .unwrap();
    assert!(h
        .m
        .stopped_update_receipt(&m.id, "n_restore")
        .await
        .is_err());
}

#[tokio::test]
async fn directory_sync_failure_is_recovered_only_after_exact_get_resync() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    let before = e.snapshot();
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h
        .m
        .stopped_update("m_receipt", request("n_sync"), before.version)
        .await
        .is_err());
    assert!(e.snapshot().version > before.version);
    let durable = h.stored("m_receipt").unwrap();
    assert!(durable.version > before.version);
    h.host
        .unproven_launches
        .lock()
        .unwrap()
        .insert("m_receipt".into());
    assert!(h
        .m
        .stopped_update_receipt("m_receipt", "n_sync")
        .await
        .is_err());
    assert!(e.snapshot().version > before.version);
    h.host.unproven_launches.lock().unwrap().clear();
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h
        .m
        .stopped_update_receipt("m_receipt", "n_sync")
        .await
        .is_err());
    assert!(e.snapshot().version > before.version);
    let receipt =
        h.m.stopped_update_receipt("m_receipt", "n_sync")
            .await
            .unwrap();
    assert_eq!(receipt.version, durable.version);
    assert_eq!(e.snapshot().pending, durable.pending);
    assert_eq!(e.snapshot().stopped_updates.len(), 1);
}

#[tokio::test]
async fn uncertain_acceptance_reserves_nonce_and_fences_writers_and_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h
        .m
        .stopped_update("m_receipt", request("n_fence"), e.snapshot().version)
        .await
        .is_err());
    let accepted = e.snapshot();
    let stored = serde_json::to_value(h.stored("m_receipt")).unwrap();
    assert_eq!(serde_json::to_value(&accepted).unwrap(), stored);
    assert!(e.stopped_update_unsynced.load(Relaxed));
    h.host_calls();
    h.pool.calls();
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h.m.start("m_receipt", None).await.is_err());
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h
        .m
        .update(
            "m_receipt",
            spec(|s| s.image = Some("other:1".into())),
            None
        )
        .await
        .is_err());
    assert!(h.host_calls().is_empty());
    assert!(h.pool.calls().is_empty());
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h.m.save(&e).is_err());
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h
        .m
        .save_edit(&e, |r| {
            r.backup_bytes = 999;
            true
        })
        .is_err());
    assert_ne!(e.snapshot().backup_bytes, 999);
    e.unsaved_use.store(true, Relaxed);
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h.m.flush_use(&e).is_err());
    assert_eq!(serde_json::to_value(h.stored("m_receipt")).unwrap(), stored);
    assert!(e.stopped_update_unsynced.load(Relaxed));
    let mut conflict = request("n_fence");
    conflict.image = "other:2".into();
    assert!(h
        .m
        .stopped_update("m_receipt", conflict.clone(), accepted.version)
        .await
        .is_err());
    assert!(!e.stopped_update_unsynced.load(Relaxed));
    let later =
        h.m.stopped_update("m_receipt", request("n_later"), accepted.version)
            .await
            .unwrap();
    assert!(h
        .m
        .stopped_update("m_receipt", conflict, later.version)
        .await
        .is_err());
    assert_eq!(e.snapshot().stopped_updates.len(), 2);
}

#[tokio::test]
async fn a_loaded_acceptance_requires_sync_before_recovery_writes_and_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    let accepted =
        h.m.stopped_update("m_receipt", request("n_reload"), e.snapshot().version)
            .await
            .unwrap();
    let reloaded = Entry::new(h.stored("m_receipt").unwrap(), h.m.inner.events.clone());
    h.m.inner
        .machines
        .lock()
        .unwrap()
        .insert("m_receipt".into(), reloaded.clone());
    assert!(reloaded.stopped_update_unsynced.load(Relaxed));
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h.m.save(&reloaded).is_err());
    h.m.inner.store.fail_next_sync.store(true, Relaxed);
    assert!(h.m.start_entry(&reloaded, true).await.is_err());
    assert!(reloaded.stopped_update_unsynced.load(Relaxed));
    assert_eq!(
        h.m.stopped_update_receipt("m_receipt", "n_reload")
            .await
            .unwrap(),
        accepted
    );
    h.host
        .host_boot_id
        .lock()
        .unwrap()
        .replace("22222222-2222-4222-8222-222222222222".into());
    assert!(h
        .m
        .stopped_update_receipt("m_receipt", "n_reload")
        .await
        .is_err());
    let mut conflict = request("n_reload");
    conflict.image = "other:1".into();
    assert!(h
        .m
        .stopped_update("m_receipt", conflict, accepted.version)
        .await
        .is_err());
}

#[tokio::test]
async fn concurrent_ordinary_save_cannot_land_an_old_record_after_acceptance() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_receipt", state::STOPPED, 256);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let writer = {
        let manager = h.m.clone();
        let entry = e.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            manager.save(&entry).unwrap();
        })
    };
    barrier.wait();
    let accepted =
        h.m.stopped_update("m_receipt", request("n_race"), e.snapshot().version)
            .await
            .unwrap();
    writer.join().unwrap();
    let stored = h.stored("m_receipt").unwrap();
    assert_eq!(stored.version, accepted.version);
    assert!(stored.stopped_updates.contains_key("n_race"));
    assert_eq!(stored.pending, e.snapshot().pending);
}
