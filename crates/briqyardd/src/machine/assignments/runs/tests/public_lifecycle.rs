//! Public Manager callers must compose private run authority without duplicate launches.
use super::*;

fn bounded<T>(
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    // Keep several large Manager futures out of this multi-operation test's stack frame.
    let future = Box::pin(future);
    async move {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("public assigned lifecycle operation must complete")
    }
}

#[tokio::test]
async fn assigned_provider_resize_remains_fail_closed_without_update_journal() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    let before = entry.snapshot();
    let current_before: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    let volume_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
    let running_volume_patch = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                volume: Some(api::VolumeSize { size_gb: volume_gb }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await;
    assert!(matches!(running_volume_patch, Err(MError::Conflict(_))));
    assert_eq!(entry.snapshot().volume, before.volume);
    assert_eq!(
        serde_json::to_value(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().unwrap()).unwrap(),
        serde_json::to_value(current_before).unwrap(),
        "a refused live volume update must not change current-run evidence"
    );

    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let first: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(first.reference.phase, Phase::Settled);

    let stopped_size_patch = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(api::Size {
                    vcpus: 1,
                    memory_mb: 512,
                    cpu_millis: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await;
    assert!(matches!(stopped_size_patch, Err(MError::Conflict(_))));

    let stopped_image_patch = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                image: Some("alpine:3.20".into()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await;
    assert!(matches!(stopped_image_patch, Err(MError::Conflict(_))));
    assert_eq!(
        serde_json::to_value(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().unwrap()).unwrap(),
        serde_json::to_value(first.clone()).unwrap(),
        "refused stopped resize patches must not rewrite settled run evidence"
    );

    restart(&h).unwrap();
    let recovered = h.m.entry(&id).unwrap();
    assert!(recovered.snapshot().pending.is_none());
    let next = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(next.state, state::RUNNING);
    assert_eq!(next.size, before.size);
    assert_eq!(next.volume, before.volume);
    assert!(next.pending.is_none());
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.reference.phase, Phase::Observed);
    assert_eq!(current.reference.sequence, first.reference.sequence + 1);
    assert_eq!(current.target.image, before.image);
}

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
