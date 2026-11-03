//! Public Manager callers must compose private run authority without duplicate launches.
use super::*;
use crate::machine::assignments::runs::recovery::RunRecovery;

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
async fn assigned_combined_provider_resize_is_durable_and_consumed_on_cold_start() {
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
    .await
    .unwrap();
    assert_eq!(
        running_volume_patch.volume.as_ref().unwrap().size_gb,
        volume_gb
    );
    let live_update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    live_update
        .check(&current_before)
        .expect("live volume update must bind the observed run");
    let data = entry.snapshot().data_dataset();
    assert_eq!(
        h.pool.zfs.volsize(&data).await.unwrap(),
        u64::from(volume_gb) << 30
    );
    assert_eq!(
        serde_json::to_value(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().unwrap()).unwrap(),
        serde_json::to_value(current_before).unwrap(),
        "a live volume update must not rewrite observed-run evidence"
    );

    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let first: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(first.reference.phase, Phase::Settled);
    let settled_update = first
        .settlement
        .as_ref()
        .and_then(|settlement| settlement.update.as_deref())
        .expect("the settled run must retain the consumed volume update");
    assert_eq!(
        settled_update.digest().unwrap(),
        live_update.digest().unwrap()
    );
    let settled_intent: UpdateIntent =
        h.m.inner
            .store
            .get::<UpdateIntent>(UPDATES, &id)
            .unwrap()
            .expect("pending volume update remains authoritative until the next run");
    assert_eq!(
        settled_intent.digest().unwrap(),
        live_update.digest().unwrap()
    );
    let settled_record = entry.snapshot();
    let settled_actual = projection::authority(&settled_record).unwrap();
    let settled_target = projection::authority(&first.target).unwrap();
    let differing_fields: Vec<_> = settled_actual
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(key, value)| (settled_target.get(key) != Some(value)).then_some(key))
        .collect();
    assert!(
        differing_fields.is_empty(),
        "settled record differs in {differing_fields:?}"
    );
    let root_dataset = settled_record.root_dataset();
    let old_root_guid = h.pool.zfs.guid(&root_dataset).await.unwrap();

    let requested_size = api::Size {
        vcpus: 1,
        memory_mb: 512,
        cpu_millis: None,
    };
    let image = format!("alpine@sha256:{}", "2".repeat(64));
    h.m.inner
        .images
        .seed(&image, crate::image::ImageConfig::default())
        .await
        .unwrap();
    let requested_volume_gb = volume_gb + 1;
    let requested_disk_limits = api::DiskLimits {
        bandwidth_mb: Some(10),
        iops: Some(500),
        burst_sec: Some(2),
    };
    let stopped_resize_patch = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(requested_size),
                image: Some(image.clone()),
                volume: Some(api::VolumeSize {
                    size_gb: requested_volume_gb,
                }),
                ..Default::default()
            },
            disk_limits: Some(requested_disk_limits.clone()),
            ..Default::default()
        },
        None,
    ))
    .await;
    let pending = stopped_resize_patch.unwrap();
    assert_eq!(pending.size, before.size);
    let pending_spec = pending.pending.as_ref().unwrap();
    assert_eq!(pending_spec.size, Some(requested_size));
    assert_eq!(pending_spec.image.as_deref(), Some(image.as_str()));
    assert_eq!(
        pending_spec.volume.as_ref().map(|volume| volume.size_gb),
        Some(requested_volume_gb)
    );
    assert_eq!(
        pending.volume.as_ref().unwrap().size_gb,
        requested_volume_gb
    );
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    update
        .check(&first)
        .expect("pending size update must bind the settled run");
    let retry = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(requested_size),
                image: Some(image.clone()),
                volume: Some(api::VolumeSize {
                    size_gb: requested_volume_gb,
                }),
                ..Default::default()
            },
            disk_limits: Some(requested_disk_limits.clone()),
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    assert_eq!(retry.pending.as_ref().unwrap().size, Some(requested_size));
    assert_eq!(
        retry.pending.as_ref().unwrap().image.as_deref(),
        Some(image.as_str())
    );
    assert_eq!(retry.disk_limits, requested_disk_limits);
    assert_eq!(
        serde_json::to_value(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().unwrap()).unwrap(),
        serde_json::to_value(first.clone()).unwrap(),
        "a pending spec update must not rewrite settled run evidence"
    );

    // Model a crash after the update intent reached durable storage but before the machine
    // record did. Startup must finish exactly that target from the saved source/target pair.
    h.m.inner
        .store
        .put_durable("machines", &id, &*update.source_record)
        .unwrap();
    restart(&h).unwrap();
    let recovered = h.m.entry(&id).unwrap();
    assert_eq!(
        recovered
            .snapshot()
            .pending
            .as_ref()
            .and_then(|pending| pending.size),
        Some(requested_size)
    );
    // A second restart covers the already-reconciled target as well.
    restart(&h).unwrap();
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    h.m.ensure_assigned_root_update(&update)
        .await
        .expect("the image root swap must finish from its durable intent");
    // Restart after the external root swap but before the next assigned run is reserved.
    restart(&h).unwrap();
    h.m.recover_assigned_update_backing()
        .await
        .expect("startup must accept the exact completed root swap");
    let next = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(next.state, state::RUNNING);
    assert_eq!(next.size, requested_size);
    assert_eq!(next.image, image);
    assert_eq!(next.volume.as_ref().unwrap().size_gb, requested_volume_gb);
    assert!(next.pending.is_none());
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.reference.phase, Phase::Observed);
    assert_eq!(current.reference.sequence, first.reference.sequence + 1);
    assert_eq!(current.target.image, image);
    assert_eq!(current.target.root_key, current.target.image_key);
    assert_eq!(current.root.dataset, root_dataset);
    assert_ne!(current.root.guid, old_root_guid);
    let consumed = current.consumed_update.as_deref().unwrap();
    let swap = consumed.root_swap.as_ref().unwrap();
    assert_eq!(swap.source_guid, old_root_guid);
    assert_eq!(swap.target_guid, Some(current.root.guid));
    let retired_root = swap.retired_dataset.clone();
    h.m.tidy_at_start().await;
    assert!(
        !h.pool.zfs.exists(&retired_root).await.unwrap(),
        "the previous root is retired after the new run authority is durable"
    );
}

#[tokio::test]
async fn assigned_volume_update_repairs_exact_zvol_after_restart() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let source_gb = entry.snapshot().volume.as_ref().unwrap().size_gb;
    let target_gb = source_gb + 1;
    let updated = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                volume: Some(api::VolumeSize { size_gb: target_gb }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    assert_eq!(updated.volume.as_ref().unwrap().size_gb, target_gb);
    let intent: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    let data = entry.snapshot().data_dataset();

    // The durable target exists, but the external grow did not complete before the crash.
    std::fs::write(
        h.pool.dev().join("byard").join(&data),
        (u64::from(source_gb) << 30).to_string(),
    )
    .unwrap();
    restart(&h).unwrap();
    let entry = h.m.entry(&id).unwrap();
    assert_eq!(entry.snapshot().volume.as_ref().unwrap().size_gb, target_gb);
    h.m.recover_assigned_update_backing().await.unwrap();
    assert_eq!(
        h.pool.zfs.volsize(&data).await.unwrap(),
        u64::from(target_gb) << 30
    );

    let started = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(started.state, state::RUNNING);
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.reference.phase, Phase::Observed);
    assert_eq!(current.prior.volume.as_ref().unwrap().size_gb, target_gb);
    assert_eq!(
        current
            .consumed_update
            .as_deref()
            .unwrap()
            .digest()
            .unwrap(),
        intent.digest().unwrap()
    );
}

#[tokio::test]
async fn assigned_stopped_volume_growth_is_refused_by_namespace_disk_quota() {
    let (h, entry) = stopped(false).await;
    let before = entry.snapshot();
    let id = before.id.clone();
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let volume_gb = before.volume.as_ref().unwrap().size_gb;
    let held = h.m.quota("destination").unwrap().used.disk_gb;
    h.m.set_quota(
        "destination",
        api::Quota {
            disk_gb: Some(held),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let result = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                volume: Some(api::VolumeSize {
                    size_gb: volume_gb + 1,
                }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await;
    assert!(matches!(result, Err(MError::Quota(_))));
    assert_eq!(entry.snapshot().volume.unwrap().size_gb, volume_gb);
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn assigned_running_volume_growth_is_refused_by_namespace_disk_quota() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    let current = entry.snapshot();
    let volume_gb = current.volume.as_ref().unwrap().size_gb;
    let held = h.m.quota("destination").unwrap().used.disk_gb;
    h.m.set_quota(
        "destination",
        api::Quota {
            disk_gb: Some(held),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let result = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                volume: Some(api::VolumeSize {
                    size_gb: volume_gb + 1,
                }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await;
    assert!(matches!(result, Err(MError::Quota(_))));
    assert_eq!(entry.snapshot().volume.unwrap().size_gb, volume_gb);
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn concurrent_assigned_volume_growths_reserve_namespace_quota_atomically() {
    let (h, _, _) = super::super::super::tests::fixture().await;
    let namespace = "destination";
    let mut entries = Vec::new();
    for id in ["m_resize_a", "m_resize_b"] {
        let mut record = crate::machine::tests::record();
        record.id = id.into();
        record.namespace = namespace.into();
        record.volume = Some(api::VolumeSpec {
            size_gb: 1,
            mount: "/work".into(),
        });
        let entry = Entry::new(record.clone(), h.m.inner.events.clone());
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .insert(id.into(), entry.clone());
        entries.push((entry, record));
    }
    h.m.set_quota(
        namespace,
        api::Quota {
            disk_gb: Some(3),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let gate = Arc::new(std::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for (entry, source) in entries {
        let manager = h.m.clone();
        let gate = gate.clone();
        let mut target = source.clone();
        target.volume.as_mut().unwrap().size_gb = 2;
        let intent = UpdateIntent {
            schema: 1,
            machine: source.id.clone(),
            source_current_sha256: "a".repeat(64),
            source_record: Box::new(source),
            change: api::SpecChange {
                volume: Some(api::VolumeSize { size_gb: 2 }),
                ..Default::default()
            },
            disk_limits: None,
            target: Box::new(target.clone()),
            resolved_image: None,
            root_swap: None,
        };
        tasks.push(tokio::task::spawn_blocking(move || {
            gate.wait();
            manager.persist_assigned_update(&entry, &target, &intent, Some(1))
        }));
    }
    gate.wait();
    let results = futures::future::join_all(tasks).await;
    let successes = results
        .into_iter()
        .map(|result| result.unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1, "only one growth fits the remaining quota");
    assert_eq!(h.m.quota(namespace).unwrap().used.disk_gb, 3);
}

#[tokio::test]
async fn assigned_stopped_resize_back_to_current_size_cancels_pending_change() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let current_size = entry.snapshot().size;
    let larger = api::Size {
        vcpus: current_size.vcpus + 1,
        memory_mb: current_size.memory_mb + 256,
        cpu_millis: None,
    };
    bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(larger),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    assert_eq!(
        entry.snapshot().pending.as_ref().unwrap().size,
        Some(larger)
    );

    let canceled = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(current_size),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    assert!(canceled.pending.is_none());
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert!(update.target.pending.is_none());

    restart(&h).expect("the cancellation transition is durable across startup");
    let started = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(started.state, state::RUNNING);
    assert_eq!(started.size, current_size);
    assert!(started.pending.is_none());
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn running_volume_update_settles_and_recovers_before_next_resize() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    let target_gb = entry.snapshot().volume.as_ref().unwrap().size_gb + 1;
    bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                volume: Some(api::VolumeSize { size_gb: target_gb }),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();

    let settled: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(settled.reference.phase, Phase::Settled);
    assert_eq!(
        settled
            .settlement
            .as_deref()
            .unwrap()
            .update_sha256
            .as_deref(),
        Some(update.digest().unwrap().as_str())
    );

    restart(&h).expect("startup accepts the settlement-authorized volume update");
    let recovered = h.m.entry(&id).unwrap();
    assert_eq!(
        recovered.snapshot().volume.as_ref().unwrap().size_gb,
        target_gb
    );
    h.m.ensure_entry_assigned_update_backing(&recovered)
        .await
        .expect("the settled record and retained update agree after recovery");

    let started = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(started.state, state::RUNNING);
    assert_eq!(started.volume.as_ref().unwrap().size_gb, target_gb);
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert!(current.consumed_update.is_some());
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn assigned_image_root_swap_recovers_each_zfs_rename_boundary() {
    for boundary in 0..4 {
        let (h, entry) = stopped(false).await;
        let id = entry.snapshot().id;
        bounded(h.m.start(&id, None)).await.unwrap();
        bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
            .await
            .unwrap();
        let image = format!("alpine@sha256:{}", (boundary + 3).to_string().repeat(64));
        h.m.inner
            .images
            .seed(&image, crate::image::ImageConfig::default())
            .await
            .unwrap();
        bounded(h.m.update(
            &id,
            api::UpdateMachineRequest {
                spec: api::SpecChange {
                    image: Some(image.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            None,
        ))
        .await
        .unwrap();
        h.m.ensure_entry_assigned_update_backing(&entry)
            .await
            .unwrap();
        let mut update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        assert!(update.resolved_image.is_none());
        assert!(update.root_swap.is_none());
        let root = update.target.root_dataset();
        let next = format!("{root}.next");
        let resolved_image = h.m.inner.images.ensure(&image).await.unwrap();
        let source_guid = h.pool.zfs.guid(&root).await.unwrap();
        let suffix = sha(format!(
            "{}:{}:{}",
            update.source_current_sha256, resolved_image.key, source_guid
        )
        .as_bytes());
        let retired = format!(
            "{}/root.u_{}",
            update.source_record.dataset(),
            &suffix[..24]
        );
        update.resolved_image = Some(resolved_image.clone());
        update.root_swap = Some(RootSwap {
            source_guid,
            target_guid: None,
            retired_dataset: retired.clone(),
        });
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        update.check(&current).unwrap();
        h.m.inner.store.put_durable(UPDATES, &id, &update).unwrap();
        let base = resolved_image.dataset();
        h.pool
            .zfs
            .clone_snapshot(&base, crate::image::SNAP, &next)
            .await
            .unwrap();
        let target_guid = h.pool.zfs.guid(&next).await.unwrap();
        if boundary >= 1 {
            update.root_swap.as_mut().unwrap().target_guid = Some(target_guid);
            h.m.inner.store.put_durable(UPDATES, &id, &update).unwrap();
        }
        if boundary >= 2 {
            h.pool.zfs.rename(&root, &retired).await.unwrap();
        }
        if boundary >= 3 {
            h.pool.zfs.rename(&next, &root).await.unwrap();
        }

        restart(&h).unwrap();
        h.m.recover_assigned_update_backing().await.unwrap();
        let recovered: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        let recovered_swap = recovered.root_swap.as_ref().unwrap();
        assert_eq!(recovered_swap.source_guid, source_guid);
        assert_eq!(recovered_swap.target_guid, Some(target_guid));
        assert_eq!(h.pool.zfs.guid(&root).await.unwrap(), target_guid);
        assert!(!h.pool.zfs.exists(&next).await.unwrap());
        assert_eq!(h.pool.zfs.guid(&retired).await.unwrap(), source_guid);
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        assert_eq!(
            h.m.classify_run_recovery(&current).await.unwrap(),
            RunRecovery::Settled
        );
    }
}

#[tokio::test]
async fn assigned_provider_same_size_resize_journals_disk_limits_without_pending_spec() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    bounded(h.m.start(&id, None)).await.unwrap();
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    let before = entry.snapshot();
    let size = before.size;
    let bump = |value: Option<u32>, max: u32| match value {
        Some(value) if value >= max => Some(max - 1),
        Some(value) => Some(value + 1),
        None => Some(1),
    };
    let limits = api::DiskLimits {
        bandwidth_mb: bump(before.disk_limits.bandwidth_mb, api::DiskLimits::MAX_MB),
        iops: bump(before.disk_limits.iops, api::DiskLimits::MAX_IOPS),
        burst_sec: bump(before.disk_limits.burst_sec, api::DiskLimits::MAX_BURST_SEC),
    };
    let updated = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(size),
                ..Default::default()
            },
            disk_limits: Some(limits.clone()),
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    assert_eq!(updated.size, size);
    assert_eq!(updated.pending, None);
    assert_eq!(updated.disk_limits, limits);
    let coalesced_limits = api::DiskLimits {
        iops: Some(limits.iops.unwrap_or(0).saturating_add(1)),
        ..Default::default()
    };
    let updated = bounded(h.m.update(
        &id,
        api::UpdateMachineRequest {
            spec: api::SpecChange {
                size: Some(size),
                ..Default::default()
            },
            disk_limits: Some(coalesced_limits.clone()),
            ..Default::default()
        },
        None,
    ))
    .await
    .unwrap();
    let expected_limits = coalesced_limits.over(&limits);
    assert_eq!(updated.size, size);
    assert_eq!(updated.pending, None);
    assert_eq!(updated.disk_limits, expected_limits);
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert!(update.target.pending.is_none());
    assert_eq!(update.disk_limits, Some(expected_limits.clone()));
    restart(&h).unwrap();
    let started = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(started.state, state::RUNNING);
    assert_eq!(started.disk_limits, expected_limits);
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.target.disk_limits, expected_limits);
    assert!(current.consumed_update.is_some());
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
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
