use super::*;

async fn pool(desired: u16) -> (Harness, api::Machine) {
    let (h, builder) = reviewed_builder_with_warm(true).await;
    let snapshot =
        h.m.snapshot(
            &builder.id,
            api::SnapshotRequest {
                memory: true,
                template: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let view =
        h.m.put_warm_pool(
            "t1",
            "tools",
            api::PutWarmPoolRequest {
                source_machine: builder.id.clone(),
                snapshot: snapshot.id,
                desired,
            },
        )
        .await
        .unwrap();
    assert_eq!(view.profile, guest::INIT_READY_V1);
    (h, builder)
}

async fn fill(h: &Harness) -> Arc<Entry> {
    h.m.warm_step().await;
    let e =
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .find(|e| {
                e.snapshot()
                    .warm_slot
                    .as_ref()
                    .is_some_and(|s| s.claimed.is_none())
            })
            .cloned()
            .expect("slot recorded");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let changed = e.changed.notified();
            let r = e.snapshot();
            if crate::machine::warm::ready_slot(&r) {
                break;
            }
            assert_ne!(r.state, state::ERROR, "{}", r.error);
            changed.await;
        }
    })
    .await
    .unwrap();
    e
}

fn claim(name: &str, request_id: &str) -> api::ClaimWarmPoolRequest {
    api::ClaimWarmPoolRequest {
        name: name.into(),
        request_id: request_id.into(),
        fail_fast: true,
    }
}

#[tokio::test]
async fn slot_is_identity_configured_paused_and_fully_reserved_before_claim() {
    let (h, _) = pool(1).await;
    h.host_calls();
    let e = fill(&h).await;
    let before = e.snapshot();
    let identity = before
        .clone_origin
        .as_ref()
        .unwrap()
        .identity
        .clone()
        .unwrap();
    assert_eq!(
        before.clone_origin.as_ref().unwrap().stage,
        CloneStage::Paused
    );
    assert!(!h.m.view(&e).ready);
    assert!(commits_memory(&before));
    assert_eq!(quota_need(&before, false).memory_mb, 256);
    assert!(!h
        .host_calls()
        .iter()
        .any(|c| c.starts_with("clone-activate")));
    let made =
        h.m.claim_warm_pool("t1", "tools", claim("worker", "request1"))
            .await
            .unwrap();
    assert_eq!(made.id, before.id);
    assert!(made.ready);
    let after = e.snapshot();
    assert_eq!(after.ip, before.ip);
    assert_eq!(after.clone_origin.unwrap().identity.unwrap(), identity);
    assert_eq!(after.name, "worker");
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 512);
    h.host_calls();
    let retry =
        h.m.claim_warm_pool("t1", "tools", claim("worker", "request1"))
            .await
            .unwrap();
    assert_eq!(retry.id, made.id);
    assert!(!h.host_calls().iter().any(|c| c.starts_with("boot ")
        || c.starts_with("resume")
        || c.starts_with("clone-activate")));
}

#[tokio::test]
async fn one_slot_concurrent_claims_and_empty_fail_fast_never_start_another_vm() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    h.host_calls();
    let (a, b) = tokio::join!(
        h.m.claim_warm_pool("t1", "tools", claim("worker-a", "request-a")),
        h.m.claim_warm_pool("t1", "tools", claim("worker-b", "request-b"))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a, Err(MError::PoolEmpty)) || matches!(b, Err(MError::PoolEmpty)));
    assert_eq!(h.m.warm_pools("t1").unwrap()[0].claimed, 1);
    assert!(!h.host_calls().iter().any(|c| c.starts_with("boot ")));
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert!(e.snapshot().warm_slot.unwrap().claimed.is_some());
}

#[tokio::test]
async fn paused_adoption_keeps_identity_and_claim_retry_survives_restart_and_destroy() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    let before = e.snapshot();
    *e.live.lock().unwrap() = None;
    h.host_calls();
    h.m.recover().await;
    assert_eq!(e.snapshot().pid, before.pid);
    assert_eq!(
        e.snapshot().clone_origin.unwrap().identity,
        before.clone_origin.unwrap().identity
    );
    assert!(e.live.lock().unwrap().is_some());
    let made =
        h.m.claim_warm_pool("t1", "tools", claim("worker", "stable-id"))
            .await
            .unwrap();
    h.m.recover_warm_names().unwrap();
    h.m.recover().await;
    assert_eq!(
        h.m.claim_warm_pool("t1", "tools", claim("worker", "stable-id"))
            .await
            .unwrap()
            .id,
        made.id
    );
    h.m.destroy(&made.id, None).await.unwrap();
    assert!(matches!(
        h.m.claim_warm_pool("t1", "tools", claim("worker", "stable-id"))
            .await,
        Err(MError::Conflict(_))
    ));
}

#[tokio::test]
async fn quota_refusal_and_drain_keep_full_reservations_without_cold_fallback() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    h.m.set_quota(
        "t1",
        api::Quota {
            machines: Some(2),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let made =
        h.m.claim_warm_pool("t1", "tools", claim("worker", "request"))
            .await
            .unwrap();
    h.m.warm_step().await;
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert!(h.m.warm_pools("t1").unwrap()[0].error.contains("quota"));
    assert!(commits_memory(&e.snapshot()));
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    assert!(h.m.get(&made.id).unwrap().ready); // Claimed guests are never recycled.
}

#[tokio::test]
async fn concurrent_identical_claims_and_busy_turn_retry_reach_the_same_vm() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    let (first, retry) = tokio::join!(
        h.m.claim_warm_pool("t1", "tools", claim("worker", "same-key")),
        h.m.claim_warm_pool("t1", "tools", claim("worker", "same-key"))
    );
    assert_eq!(first.unwrap().id, retry.unwrap().id);
    let busy = h.m.inner.warm_lock.lock().await;
    assert_eq!(
        h.m.claim_warm_pool("t1", "tools", claim("worker", "same-key"))
            .await
            .unwrap()
            .id,
        e.snapshot().id
    );
    assert!(matches!(
        h.m.claim_warm_pool("t1", "tools", claim("another", "new-key"))
            .await,
        Err(MError::PoolEmpty)
    ));
    drop(busy);
}

#[tokio::test]
async fn unconfirmed_paused_ownership_retains_quota_and_blocks_refill() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    *e.live.lock().unwrap() = None;
    e.rec.lock().unwrap().boot_incarnation = None;
    h.m.recover().await;
    assert_eq!(e.snapshot().state, state::ERROR);
    assert!(!e.snapshot().clone_origin.unwrap().mapping_exited);
    assert!(commits_memory(&e.snapshot()));
    h.m.warm_step().await;
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 512);
    assert!(matches!(
        h.m.claim_warm_pool("t1", "tools", claim("worker", "key"))
            .await,
        Err(MError::PoolEmpty)
    ));
}

#[tokio::test]
async fn draining_unused_slots_releases_capacity_and_readers() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    let id = e.snapshot().id;
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    assert!(h.m.entry(&id).is_err());
    assert!(h.m.clone_readers().unwrap().is_empty());
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 256);
}

#[tokio::test]
async fn warm_root_disk_charge_is_admitted_before_record_and_survives_claim_and_destroy() {
    let (h, _) = pool(2).await;
    let root = h.m.inner.cfg.root_disk_gb;
    h.m.set_quota(
        "t1",
        api::Quota {
            disk_gb: Some(root),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let e = fill(&h).await;
    let before = quota_need(&e.snapshot(), false);
    assert_eq!(
        (before.memory_mb, before.cpu_millis(), before.disk_gb),
        (256, 1000, root)
    );
    h.m.warm_step().await;
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert!(h.m.warm_pools("t1").unwrap()[0].error.contains("disk_gb"));
    let made =
        h.m.claim_warm_pool("t1", "tools", claim("worker", "disk-key"))
            .await
            .unwrap();
    assert_eq!(quota_need(&e.snapshot(), false), before);
    h.refuse_clone_exit(true);
    // Lost live observer plus exact registered exit unavailable: destruction retains all charges.
    *e.live.lock().unwrap() = None;
    assert!(h.m.destroy(&made.id, None).await.is_err());
    assert_eq!(quota_need(&e.snapshot(), false), before);
    h.refuse_clone_exit(false);
    h.m.destroy(&made.id, None).await.unwrap();
    assert_eq!(h.m.quota("t1").unwrap().used.disk_gb, 0);
}

#[tokio::test]
async fn handover_keeps_confirmed_paused_slot_and_closes_new_claim_admission() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    assert_eq!(e.snapshot().state, state::STARTING);
    assert_eq!(h.m.view(&e).state, state::WARM);
    h.host_calls();
    let held = tokio::time::timeout(Duration::from_secs(3), h.m.hand_over())
        .await
        .unwrap();
    assert!(commits_memory(&e.snapshot()));
    assert_eq!(e.snapshot().clone_origin.unwrap().stage, CloneStage::Paused);
    assert!(!h
        .host_calls()
        .iter()
        .any(|c| c.starts_with("resume") || c.starts_with("kill ")));
    assert!(h
        .m
        .claim_warm_pool("t1", "tools", claim("worker", "closed-key"))
        .await
        .is_err());
    drop(held);
}

#[tokio::test]
async fn claim_cannot_mutate_a_paused_slot_until_fill_releases_its_lifecycle_lock() {
    let (h, _) = pool(1).await;
    h.pause_warm_barrier("warm_parked");
    h.m.warm_step().await;
    h.wait_warm_barrier().await;
    let e =
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .find(|e| e.snapshot().warm_slot.is_some())
            .cloned()
            .unwrap();
    assert!(crate::machine::warm::ready_slot(&e.snapshot()));
    assert!(e.lock.try_lock().is_err());
    let fast = tokio::time::timeout(
        Duration::from_secs(1),
        h.m.claim_warm_pool("t1", "tools", claim("worker", "parked-key")),
    )
    .await
    .unwrap();
    assert!(matches!(fast, Err(MError::PoolEmpty)));
    assert!(e.snapshot().warm_slot.unwrap().claimed.is_none());
    assert_eq!(h.m.warm_pools("t1").unwrap()[0].claim_receipts, 0);
    let manager = h.m.clone();
    let waiting = tokio::spawn(async move {
        let mut request = claim("worker", "parked-key");
        request.fail_fast = false;
        manager.claim_warm_pool("t1", "tools", request).await
    });
    h.release_warm_barriers();
    let made = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(made.ready);
    assert_eq!(made.id, e.snapshot().id);
    assert_eq!(e.snapshot().clone_origin.unwrap().stage, CloneStage::Active);
}

#[tokio::test]
async fn queued_namespace_writer_cannot_deadlock_refill_and_claim_lock_order() {
    let (h, _) = pool(1).await;
    h.pause_warm_barrier("warm_admission");
    let manager = h.m.clone();
    let refill = tokio::spawn(async move { manager.warm_step().await });
    h.wait_warm_barrier().await; // Refill owns warm_lock, before namespace admission.
    h.pause_warm_barrier("warm_claim_lock");
    let manager = h.m.clone();
    let claiming = tokio::spawn(async move {
        let mut request = claim("worker", "writer-key");
        request.fail_fast = false;
        manager.claim_warm_pool("t1", "tools", request).await
    });
    h.wait_warm_barrier().await; // Claim is just before warm_lock, without a namespace reader.
    let began = Arc::new(Notify::new());
    let acquired = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let manager = h.m.clone();
    let (writer_began, writer_acquired, writer_release) =
        (began.clone(), acquired.clone(), release.clone());
    let writer = tokio::spawn(async move {
        writer_began.notify_one();
        let _namespace_delete = manager.inner.namespace_lifecycle.write().await;
        writer_acquired.notify_one();
        writer_release.notified().await;
    });
    began.notified().await;
    h.release_warm_barriers();
    tokio::time::timeout(Duration::from_secs(3), acquired.notified())
        .await
        .unwrap();
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), refill)
        .await
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), claiming)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok() || matches!(result, Err(MError::PoolEmpty)));
    if result.is_err() {
        fill(&h).await;
    } // Settle the existing fill before fixture teardown.
}

#[tokio::test]
async fn paused_resident_stats_report_physical_use_and_warm_state_without_resuming() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    let r = e.snapshot();
    let reserved = h.m.usage().0.memory_mb;
    let quota = h.m.quota("t1").unwrap().used.memory_mb;
    h.set_cgroup(
        &r.id,
        Some(fc::CgroupUse {
            cpu_usec: 1234,
            memory_bytes: 5754880,
            memory_anon_bytes: Some(4096),
            memory_file_bytes: Some(8192),
        }),
    );
    h.host_calls();
    h.m.measure(Utc::now()).await;
    let stats = h.m.stats(&r.id).await.unwrap();
    assert_eq!(stats.state, state::WARM);
    assert_eq!(stats.memory_status, "available");
    assert_eq!((stats.cpu_usec, stats.memory_bytes), (1234, 5754880));
    assert_eq!(
        (stats.memory_anon_bytes, stats.memory_file_bytes),
        (Some(4096), Some(8192))
    );
    assert!(stats.memory_read_at.is_some());
    assert!(stats.balloon.is_none(), "legacy profile has no balloon");
    let metrics = h.m.metrics();
    for (name, value) in [
        ("memory_bytes", 5754880),
        ("memory_anon_bytes", 4096),
        ("memory_file_bytes", 8192),
    ] {
        assert!(
            metrics.lines().any(|line| line
                .starts_with(&format!("briqyard_machine_{name}{{machine=\"{}\"", r.id))
                && line.ends_with(&format!(" {value}"))),
            "{metrics}"
        );
    }
    assert!(metrics.lines().any(|line| line
        .starts_with(&format!("briqyard_machine_state{{machine=\"{}\"", r.id))
        && line.ends_with("state=\"warm\"} 1")));
    assert!(metrics.contains("briqyard_machines{state=\"warm\"} 1"));
    assert_eq!(h.m.usage().0.memory_mb, reserved);
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, quota);
    assert_eq!(e.snapshot().pid, r.pid);
    assert_eq!(e.snapshot().clone_origin.unwrap().stage, CloneStage::Paused);
    assert!(!h
        .host_calls()
        .iter()
        .any(|c| c.starts_with("resume") || c.starts_with("clone-activate")));
    // A failed read is unavailable, never a successful zero or configured-RAM sample.
    h.set_cgroup(&r.id, None);
    h.m.measure(Utc::now()).await;
    let stats = h.m.stats(&r.id).await.unwrap();
    assert_eq!(stats.memory_status, "unavailable");
    assert_eq!(stats.memory_bytes, 0);
    assert!(stats.memory_read_at.is_none());
    assert!(stats.memory_anon_bytes.is_none());
    assert!(!h.m.metrics().lines().any(|line| line.starts_with(&format!(
        "briqyard_machine_memory_bytes{{machine=\"{}\"",
        r.id
    ))));
}

#[tokio::test]
async fn paused_resident_telemetry_requires_bound_live_incarnation_and_paused_stage() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    let original = e.snapshot();
    h.set_cgroup(
        &original.id,
        Some(fc::CgroupUse {
            memory_bytes: 99,
            ..Default::default()
        }),
    );
    for case in 0..5 {
        *e.rec.lock().unwrap() = original.clone();
        let saved_live = e.live.lock().unwrap().clone();
        match case {
            0 => e.rec.lock().unwrap().boot_incarnation = None,
            1 => {
                e.rec
                    .lock()
                    .unwrap()
                    .boot_incarnation
                    .as_mut()
                    .unwrap()
                    .start_ticks += 1
            }
            2 => *e.live.lock().unwrap() = None,
            3 => {
                e.rec.lock().unwrap().clone_origin.as_mut().unwrap().stage =
                    CloneStage::IdentityDone
            }
            _ => {
                e.live.lock().unwrap().as_mut().unwrap().exited =
                    tokio::sync::watch::channel(true).1
            }
        }
        h.m.measure(Utc::now()).await;
        let stats = h.m.stats(&original.id).await.unwrap();
        assert_ne!(stats.memory_status, "available", "case {case}");
        assert_eq!(stats.memory_bytes, 0);
        assert!(stats.memory_read_at.is_none());
        assert!(!e.meter.lock().unwrap().memory_available);
        assert!(!h.m.metrics().lines().any(|line| line.starts_with(&format!(
            "briqyard_machine_memory_bytes{{machine=\"{}\"",
            original.id
        ))));
        *e.live.lock().unwrap() = saved_live;
    }
}

#[tokio::test]
async fn paused_resident_balloon_read_preserves_unknown_guest_sample_time() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    // Exercise reporting-device telemetry using the same mock as the balloon tests.
    e.rec
        .lock()
        .unwrap()
        .boot_identity
        .as_mut()
        .unwrap()
        .device_profile = fc::REPORTING_PROFILE.into();
    h.m.measure(Utc::now()).await;
    let stats = h.m.stats(&e.snapshot().id).await.unwrap();
    let balloon = stats.balloon.unwrap();
    assert_eq!(balloon.actual_bytes, Some(3 * 4096));
    assert!(!balloon.guest_sample_time_known);
    assert!(balloon.last_stats_update_observed_at.is_none());
    assert!(h.host_calls().iter().any(|c| c == "balloon-statistics"));
    assert!(h.m.metrics().lines().any(|line| line.starts_with(&format!(
        "briqyard_machine_balloon_actual_bytes{{machine=\"{}\"",
        e.snapshot().id
    ))));
}
