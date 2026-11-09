//! Public continuation and update recovery scenarios.
use super::*;

#[tokio::test]
async fn fresh_start_stop_start_publishes_only_current_run_and_coalesces_running_requests() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    let stopped_version = entry.snapshot().version;
    h.host_calls();

    let first = bounded(h.m.start(&id, Some(stopped_version)))
        .await
        .unwrap();
    assert_eq!(first.state, state::RUNNING);
    assert!(entry.identity_trusted.load(Relaxed));
    assert!(entry.live.lock().unwrap().is_some());
    assert!(h.m.ordinary_operation(&entry.snapshot()).is_ok());
    assert!(!h.m.namespace_dns_names("destination").is_empty());
    let first_run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(first_run.reference.phase, Phase::Observed);
    assert_eq!(first_run.reference.sequence, 1);
    h.m.verified_run_publication(&entry.snapshot()).unwrap();
    let first_calls = h.host_calls();
    assert_eq!(
        first_calls
            .iter()
            .filter(|c| c.starts_with("boot "))
            .count(),
        1
    );
    assert_eq!(
        first_calls
            .iter()
            .filter(|c| c.starts_with("activate_quarantined "))
            .count(),
        1
    );

    assert!(matches!(
        bounded(h.m.start(&id, Some(stopped_version))).await,
        Err(MError::Moved(_))
    ));
    let (repeated, wake) =
        bounded(async { tokio::join!(h.m.start(&id, None), h.m.wake(&id, None)) }).await;
    assert_eq!(repeated.unwrap().state, state::RUNNING);
    assert_eq!(wake.unwrap().state, state::RUNNING);
    assert_eq!(
        entry.snapshot().assigned_run.as_ref(),
        Some(&first_run.reference)
    );
    assert!(h.host_calls().iter().all(|c| !c.starts_with("boot ")
        && !c.starts_with("activate_quarantined ")
        && !c.starts_with("count ")));

    let ended = bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    assert_eq!(ended.state, state::STOPPED);
    assert!(!entry.identity_trusted.load(Relaxed));
    assert!(entry.live.lock().unwrap().is_none());
    assert!(h.m.namespace_dns_names("destination").is_empty());
    let terminal: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(terminal.reference.phase, Phase::Settled);
    assert_eq!(terminal.reference.sequence, first_run.reference.sequence);
    h.host_calls();
    assert!(matches!(
        bounded(h.m.wake(&id, None)).await,
        Err(MError::NotRunning(_))
    ));
    assert_eq!(
        bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
            .await
            .unwrap()
            .state,
        state::STOPPED
    );
    assert_eq!(
        entry.snapshot().assigned_run.as_ref(),
        Some(&terminal.reference)
    );
    assert!(h.host_calls().is_empty());

    let next = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(next.state, state::RUNNING);
    let next_run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(next_run.reference.phase, Phase::Observed);
    assert_eq!(
        next_run.reference.sequence,
        first_run.reference.sequence + 1
    );
    assert_ne!(
        next_run.target.boot_incarnation,
        first_run.target.boot_incarnation
    );
    assert!(entry.identity_trusted.load(Relaxed));
    assert!(h.m.ordinary_operation(&entry.snapshot()).is_ok());
    assert!(!h.m.namespace_dns_names("destination").is_empty());
    h.m.verified_run_publication(&entry.snapshot()).unwrap();
    assert_eq!(
        h.host_calls()
            .iter()
            .filter(|c| c.starts_with("boot "))
            .count(),
        1
    );
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
}

#[tokio::test]
async fn checkpoint_suspend_start_preserves_current_files_guest_lineage_and_publication() {
    for initial_checkpoint in [false, true] {
        let (h, entry) = stopped(initial_checkpoint).await;
        let id = entry.snapshot().id;
        bounded(h.m.start(&id, None)).await.unwrap();
        let observed: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        assert_eq!(observed.reference.phase, Phase::Observed);
        assert!(entry.identity_trusted.load(Relaxed));
        h.host_calls();

        let paused = bounded(h.m.stop(&id, Duration::from_secs(1), true, None))
            .await
            .unwrap();
        assert_eq!(paused.state, state::STOPPED);
        assert!(entry.snapshot().suspended);
        assert!(entry.snapshot().suspend_synced);
        assert!(!entry.identity_trusted.load(Relaxed));
        assert!(entry.live.lock().unwrap().is_none());
        assert!(h.m.namespace_dns_names("destination").is_empty());
        let terminal: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        terminal.check().unwrap();
        assert_eq!(terminal.reference.phase, Phase::Settled);
        assert_eq!(terminal.reference.sequence, observed.reference.sequence);
        assert!(terminal.settlement.as_ref().unwrap().checkpoint.is_some());
        let saved =
            h.m.run_checkpoint_paths(&entry.snapshot())
                .map(|path| templates::fingerprint(&path).unwrap());
        let pause_calls = h.host_calls();
        assert_eq!(
            pause_calls
                .iter()
                .filter(|c| c.starts_with("snapshot "))
                .count(),
            1
        );

        let running = bounded(h.m.start(&id, None)).await.unwrap();
        assert_eq!(running.state, state::RUNNING);
        let resumed: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        resumed.check().unwrap();
        assert_eq!(resumed.reference.phase, Phase::Observed);
        assert_eq!(resumed.reference.sequence, observed.reference.sequence + 1);
        assert_eq!(
            resumed.previous_run_sha256,
            Some(terminal.authority_sha256().unwrap())
        );
        assert_eq!(resumed.root, terminal.root);
        assert_eq!(resumed.data, terminal.data);
        assert_eq!(
            resumed.expected_boot_identity,
            observed.expected_boot_identity
        );
        let Mode::Checkpoint {
            state: saved_state,
            memory,
            config,
            saved_generation,
            assigned_lineage,
            ..
        } = &resumed.mode
        else {
            panic!("public start must resume the CURRENT checkpoint rather than launch Fresh");
        };
        assert_eq!([saved_state, memory, config], saved.each_ref());
        assert_eq!(
            assigned_lineage.as_deref(),
            observed.observed_guest.as_ref()
        );
        assert_eq!(resumed.observed_guest, observed.observed_guest);
        if let Some(proof) = &observed.observed_guest {
            assert_eq!(saved_generation, &proof.generation);
            assert!(resumed.observed_checkpoint.is_none());
        } else {
            let before = observed.observed_checkpoint.as_ref().unwrap();
            let after = resumed.observed_checkpoint.as_ref().unwrap();
            assert_eq!(
                saved_generation,
                &observed
                    .prior
                    .clone_origin
                    .as_ref()
                    .unwrap()
                    .configure
                    .generation
            );
            assert_eq!(before.sha256, after.sha256);
            assert_eq!(before.init_sha256, after.init_sha256);
            assert_eq!(
                serde_json::to_value(&before.clone_status).unwrap(),
                serde_json::to_value(&after.clone_status).unwrap()
            );
        }
        assert!(entry.identity_trusted.load(Relaxed));
        assert!(entry.live.lock().unwrap().is_some());
        assert!(h.m.ordinary_operation(&entry.snapshot()).is_ok());
        assert!(!h.m.namespace_dns_names("destination").is_empty());
        h.m.verified_run_publication(&entry.snapshot()).unwrap();
        let resumed_calls = h.host_calls();
        // CURRENT restore boots from its saved snapshot, rather than resuming a parked pool slot.
        assert_eq!(
            resumed_calls
                .iter()
                .filter(|c| c.starts_with("boot ") && c.ends_with("resume=true"))
                .count(),
            1
        );
        assert!(!resumed_calls
            .iter()
            .any(|c| c.starts_with("boot ") && c.ends_with("resume=false")));
        assert_eq!(
            resumed_calls
                .iter()
                .filter(|c| c.starts_with("activate_quarantined "))
                .count(),
            1
        );
        bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn volume_free_assigned_run_starts_stops_and_starts_again_without_a_data_disk() {
    for checkpoint in [false, true] {
        let (h, entry) = stopped_with(checkpoint, None).await;
        let id = entry.snapshot().id;
        assert!(entry.snapshot().volume.is_none());
        h.host_calls();
        let first = bounded(h.m.start(&id, None)).await.unwrap();
        assert_eq!(first.state, state::RUNNING);
        let run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        assert_eq!(run.reference.phase, Phase::Observed);
        assert!(run.data.is_none());
        assert!(run.root.guid > 0);
        h.m.verified_run_publication(&entry.snapshot()).unwrap();
        bounded(h.m.stop(&id, Duration::from_secs(1), checkpoint, None))
            .await
            .unwrap();
        let settled: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        assert_eq!(settled.reference.phase, Phase::Settled);
        assert!(settled.data.is_none());
        restart(&h).unwrap();
        let again = bounded(h.m.start(&id, None)).await.unwrap();
        assert_eq!(again.state, state::RUNNING);
        let next: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        assert_eq!(next.reference.sequence, run.reference.sequence + 1);
        assert!(next.data.is_none());
        assert!(next.reader().unwrap().data.is_none());
        bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn coalesced_growth_interrupted_before_record_write_recovers_from_predecessor() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let first_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
    let second_gb = first_gb + 1;
    bounded(h.m.update(&id, volume_patch(first_gb), None))
        .await
        .unwrap();
    let after_first = entry.snapshot();
    bounded(h.m.update(&id, volume_patch(second_gb), None))
        .await
        .unwrap();

    // The second intent replaced the first, then the daemon died before the record write.
    h.m.inner
        .store
        .put_durable("machines", &id, &after_first)
        .unwrap();
    restart(&h).expect("the machine at the immediate predecessor of the intent recovers");
    let entry = h.m.entry(&id).unwrap();
    assert_eq!(entry.snapshot().volume.as_ref().unwrap().size_gb, second_gb);
    h.m.recover_assigned_update_backing().await.unwrap();
    let data = entry.snapshot().data_dataset();
    assert_eq!(
        h.pool.zfs.volsize(&data).await.unwrap(),
        u64::from(second_gb) << 30
    );
}

#[tokio::test]
async fn identical_stopped_growth_retry_finishes_the_unfinished_grow() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let source_gb = entry.snapshot().volume.as_ref().unwrap().size_gb;
    let target_gb = source_gb + 1;
    bounded(h.m.update(&id, volume_patch(target_gb), None))
        .await
        .unwrap();

    // The target was persisted but the grow did not happen.
    let data = entry.snapshot().data_dataset();
    std::fs::write(
        h.pool.dev().join("byard").join(&data),
        (u64::from(source_gb) << 30).to_string(),
    )
    .unwrap();
    bounded(h.m.update(&id, volume_patch(target_gb), None))
        .await
        .unwrap();
    assert_eq!(
        h.pool.zfs.volsize(&data).await.unwrap(),
        u64::from(target_gb) << 30,
        "the retry completes the growth instead of acknowledging it"
    );
}

#[tokio::test]
async fn stopped_resize_with_unchanged_image_is_accepted() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let current = entry.snapshot();
    let larger = api::Size {
        vcpus: current.size.vcpus + 1,
        memory_mb: current.size.memory_mb + 256,
        cpu_millis: None,
    };
    let updated = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(larger),
                image: Some(current.image.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .expect("an image equal to the current one is not a change");
    let pending = updated.pending.expect("the size waits for the next start");
    assert_eq!(pending.size, Some(larger));
    assert!(pending.image.is_none());
}

#[tokio::test]
async fn failed_machine_write_then_coalesce_and_crash_retains_recoverable_authority() {
    for running in [false, true] {
        let (h, entry) = stopped(false).await;
        let id = entry.snapshot().id;
        bounded(h.m.start(&id, None)).await.unwrap();
        if !running {
            bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
                .await
                .unwrap();
        }
        let first_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
        bounded(h.m.update(&id, volume_patch(first_gb), None))
            .await
            .unwrap();
        // Fail the real atomic machine write, retaining its previous durable record.
        let blocked =
            h.m.inner
                .store
                .dir("machines")
                .join(format!("{id}.json.tmp"));
        std::fs::create_dir(&blocked).unwrap();
        assert!(bounded(h.m.update(&id, volume_patch(first_gb + 1), None))
            .await
            .is_err());
        assert_eq!(
            entry.snapshot().volume.as_ref().unwrap().size_gb,
            first_gb + 1
        );
        let durable: Record = h.m.inner.store.get("machines", &id).unwrap().unwrap();
        assert_eq!(durable.volume.as_ref().unwrap().size_gb, first_gb);
        let outstanding: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        assert!(bounded(h.m.update(&id, volume_patch(first_gb + 2), None))
            .await
            .is_err());
        let retained: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        // Crash now: discard memory, unblock storage, and run normal startup recovery.
        std::fs::remove_dir(blocked).unwrap();
        restart(&h).expect("the last durable machine must still match the retained journal");
        assert_eq!(
            retained.digest().unwrap(),
            outstanding.digest().unwrap(),
            "failed reconciliation must not replace the outstanding authority"
        );
        let recovered = h.m.entry(&id).unwrap().snapshot();
        assert_eq!(recovered.volume.as_ref().unwrap().size_gb, first_gb + 1);
        h.m.recover_assigned_update_backing().await.unwrap();
    }
}

/// A coalesced update whose machine write failed: memory and the journal hold the newest
/// target, the machine file still holds the predecessor. Leaves the storage unblocked.
async fn stale_machine_after_failed_coalesced_write(
    h: &crate::machine::tests::Harness,
    id: &str,
    running: bool,
) -> u32 {
    let entry = h.m.entry(id).unwrap();
    bounded(h.m.start(id, None)).await.unwrap();
    if !running {
        bounded(h.m.stop(id, Duration::from_secs(1), false, None))
            .await
            .unwrap();
    }
    let first_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
    bounded(h.m.update(id, volume_patch(first_gb), None))
        .await
        .unwrap();
    let blocked =
        h.m.inner
            .store
            .dir("machines")
            .join(format!("{id}.json.tmp"));
    std::fs::create_dir(&blocked).unwrap();
    assert!(bounded(h.m.update(id, volume_patch(first_gb + 1), None))
        .await
        .is_err());
    std::fs::remove_dir(blocked).unwrap();
    let durable: Record = h.m.inner.store.get("machines", id).unwrap().unwrap();
    assert_eq!(durable.volume.as_ref().unwrap().size_gb, first_gb);
    assert_eq!(
        entry.snapshot().volume.as_ref().unwrap().size_gb,
        first_gb + 1
    );
    first_gb + 1
}

fn assert_no_run_intent_and_clean_load(h: &crate::machine::tests::Harness, id: &str, gb: u32) {
    assert!(
        h.m.inner
            .store
            .get::<Intent>(INTENTS, id)
            .unwrap()
            .is_none(),
        "no run intent is left behind"
    );
    let durable: Record = h.m.inner.store.get("machines", id).unwrap().unwrap();
    assert_eq!(durable.volume.as_ref().unwrap().size_gb, gb);
    restart(h).expect("the next daemon start loads the repaired machine");
    assert_eq!(
        h.m.entry(id)
            .unwrap()
            .snapshot()
            .volume
            .as_ref()
            .unwrap()
            .size_gb,
        gb
    );
}

#[tokio::test]
async fn start_after_failed_coalesced_machine_write_repairs_the_record_first() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    let gb = stale_machine_after_failed_coalesced_write(&h, &id, false).await;
    let started = bounded(h.m.start(&id, None))
        .await
        .expect("start repairs the machine record before reserving the run");
    assert_eq!(started.state, state::RUNNING);
    assert_eq!(started.volume.as_ref().unwrap().size_gb, gb);
    assert_no_run_intent_and_clean_load(&h, &id, gb);
}

#[tokio::test]
async fn guest_exit_after_failed_coalesced_machine_write_settles_and_restarts_clean() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    let gb = stale_machine_after_failed_coalesced_write(&h, &id, true).await;
    let live = entry.live.lock().unwrap().clone().unwrap();
    h.m.inner.vmm.kill(live.pid);
    h.m.settle_assigned_run(&entry, Disposition::Stopped)
        .await
        .expect("settlement repairs the machine record before journaling the transition");
    let settled: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(settled.reference.phase, Phase::Settled);
    assert_no_run_intent_and_clean_load(&h, &id, gb);
}

#[tokio::test]
async fn update_shape_rejects_tampered_predecessor_bindings() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let first_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
    bounded(h.m.update(&id, volume_patch(first_gb), None))
        .await
        .unwrap();
    bounded(h.m.update(&id, volume_patch(first_gb + 1), None))
        .await
        .unwrap();
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    update.check_shape().unwrap();
    let earlier = serde_json::to_value(update.predecessor_target.as_ref().unwrap()).unwrap();
    let mutations = [
        ("id", serde_json::json!("m_other")),
        ("namespace", serde_json::json!("other")),
        ("root_key", serde_json::json!("other-root")),
        ("image", serde_json::json!("other:latest")),
        ("created_at", serde_json::json!("2000-01-01T00:00:00Z")),
        ("env", serde_json::json!({"INJECTED": "value"})),
        ("clone_origin", serde_json::Value::Null),
        (
            "volume",
            serde_json::json!({"size_gb": first_gb, "mount": "/other"}),
        ),
        (
            "volume",
            serde_json::json!({"size_gb": first_gb - 2, "mount": earlier["volume"]["mount"]}),
        ),
        (
            "volume",
            serde_json::json!({"size_gb": first_gb + 2, "mount": earlier["volume"]["mount"]}),
        ),
        ("volume", serde_json::Value::Null),
        ("pending", serde_json::json!({"cmd": ["injected"]})),
        (
            "pending",
            serde_json::json!({"size": {"vcpus": 0, "memory_mb": 0}}),
        ),
    ];
    for (field, value) in mutations {
        let mut tampered = update.clone();
        let mut record = earlier.clone();
        record[field] = value;
        tampered.predecessor_target = Some(Box::new(serde_json::from_value(record).unwrap()));
        assert!(
            tampered.check_shape().is_err(),
            "tampered predecessor {field} accepted"
        );
    }
    let mut tampered = update.clone();
    tampered.target.volume.as_mut().unwrap().mount = "/other".into();
    assert!(
        tampered.check_shape().is_err(),
        "target volume mount changed"
    );
}

#[tokio::test]
async fn assigned_pending_unavailable_image_does_not_resolve_or_swap_at_full_startup() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let root = entry.snapshot().root_dataset();
    let source_guid = h.pool.zfs.guid(&root).await.unwrap();
    let original = entry.snapshot().image;
    bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                image: Some("127.0.0.1:1/unavailable:deleted".into()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    let before: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    let calls = h.m.inner.images.ensure_calls.load(Relaxed);
    let result = full_startup(&h).await;
    assert_eq!(
        h.m.inner.images.ensure_calls.load(Relaxed),
        calls,
        "startup must never resolve a pending image"
    );
    result.unwrap();
    assert_eq!(
        h.m.entry(&id).unwrap().snapshot().stopped_at,
        before.target.stopped_at
    );
    assert_eq!(h.pool.zfs.guid(&root).await.unwrap(), source_guid);
    let pending: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(pending.digest().unwrap(), before.digest().unwrap());
    assert!(pending.root_swap.is_none());
    assert!(bounded(h.m.start(&id, None)).await.is_err());
    assert_eq!(h.pool.zfs.guid(&root).await.unwrap(), source_guid);
    let failed: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(failed.digest().unwrap(), before.digest().unwrap());
    // Returning to the current image durably cancels the unavailable replacement.
    let canceled = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                image: Some(original.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    assert!(canceled.pending.is_none());
    let cancellation: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert!(cancellation.change.image.is_none());
    assert!(cancellation.root_swap.is_none());
    let mut unbound = cancellation.clone();
    unbound.predecessor_target = None;
    assert!(
        unbound.check_shape().is_err(),
        "an empty update needs a canceled-image predecessor"
    );
    // Crash after the cancellation journal, before its machine write: replay that predecessor.
    h.m.inner
        .store
        .put_durable("machines", &id, &*before.target)
        .unwrap();
    full_startup(&h).await.unwrap();
    let started = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(started.image, original);
    assert_eq!(h.pool.zfs.guid(&root).await.unwrap(), source_guid);
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn assigned_running_volume_patch_then_suspend_request_settles_and_starts_cold() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    let size_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
    bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                volume: Some(api::VolumeSize { size_gb }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    h.host_calls();
    bounded(h.m.stop(&id, Duration::from_secs(1), true, None))
        .await
        .unwrap();
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.reference.phase, Phase::Settled);
    let settlement = current.settlement.as_ref().unwrap();
    assert!(settlement.checkpoint.is_none());
    assert!(settlement.update.is_some());
    assert!(!entry.snapshot().suspended);
    assert!(!h
        .host_calls()
        .iter()
        .any(|call| call.starts_with("snapshot ")));
    full_startup(&h).await.unwrap();
    let started = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(started.volume.as_ref().unwrap().size_gb, size_gb);
    let next: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert!(matches!(next.mode, Mode::Fresh { .. }));
    assert_eq!(next.reference.sequence, current.reference.sequence + 1);
    assert!(next.consumed_update.is_some());
}

#[tokio::test]
async fn assigned_unreadable_update_journal_defers_backing_cleanup() {
    let (h, entry) = stopped(false).await;
    let record = entry.snapshot();
    let next = format!("{}.next", record.root_dataset());
    let cached =
        h.m.inner
            .images
            .seed(
                &format!("alpine@sha256:{}", "9".repeat(64)),
                crate::image::ImageConfig::default(),
            )
            .await
            .unwrap();
    h.pool.zfs.create(&next, 1 << 20).await.unwrap();
    h.m.inner
        .store
        .put_durable(
            UPDATES,
            &record.id,
            &serde_json::json!({"schema": 3, "unknown": true}),
        )
        .unwrap();
    assert!(h.m.tidy(&entry).await.is_err());
    assert!(h.m.finish_swap(&record, "root").await.is_err());
    assert!(h.m.sweep_orphans().await.is_err());
    assert!(h.m.delete_image(&cached.key).await.is_err());
    assert_eq!(h.m.gc_images(chrono::Duration::zero()).await, 0);
    let gb = 1u64 << 30;
    h.pool
        .answer("used,available", &format!("{}\n{}\n", 92 * gb, 8 * gb));
    h.pool.answer("used", &format!("{gb}\n"));
    h.m.assess(Utc::now()).await;
    assert!(h.pool.zfs.exists(&cached.dataset()).await.unwrap());
    assert!(h.pool.zfs.exists(&next).await.unwrap());
    assert!(h.pool.zfs.exists(&record.root_dataset()).await.unwrap());
}
