use super::*;

async fn settle(h: &Harness) {
    tokio::task::yield_now().await;
    let _turn = h.m.inner.warm_lock.write().await;
}

#[tokio::test]
async fn a_sample_keeps_fill_liability_after_completion_or_claim_until_a_fresh_measurement() {
    for began_before_fill in [false, true] {
        let (h, _) = pool(0).await;
        h.m.inner.warm_policy.lock().unwrap().max_fills = 1;
        let initial_boundary = if began_before_fill {
            Some(h.m.warm_probe_boundary().unwrap())
        } else {
            None
        };
        h.pause_warm_barrier("warm_parked");
        desired(&h, 1).await;
        h.wait_warm_barrier().await;
        let boundary = initial_boundary.unwrap_or_else(|| h.m.warm_probe_boundary().unwrap());
        let sample = crate::machine::warm::Sample {
            at: std::time::Instant::now(),
            memory_mb: 1280,
            pool: crate::zfs::Pool {
                used: 1 << 30,
                free: 1024 << 30,
            },
            boundary,
        };
        // The asynchronous pool probe returns after this fill has completed. Its memory
        // measurement still predates that completion, regardless of the current fill count.
        h.release_warm_barriers();
        let entry = fill(&h).await;
        {
            let _completed = tokio::time::timeout(Duration::from_secs(3), entry.lock.lock())
                .await
                .unwrap();
        }
        if began_before_fill {
            h.m.claim_warm_pool("t1", "tools", claim("owned", "sample-claim"))
                .await
                .unwrap();
        }
        *h.m.inner.warm_probe_override.lock().unwrap() = Some(Some(sample));
        desired(&h, 2).await;
        settle(&h).await;
        let status = h.m.warm_catalog("t1").await.unwrap();
        assert_eq!(status.fills, 0);
        assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
        assert!(status.pools[0].error.contains("MemAvailable"));
        assert!(status.blocked.iter().any(|b| b.reason == "pressure"));

        // A replacement measurement includes the completed allocation. It may release
        // the old conservative liability, but cannot admit more than one fill at a time.
        *h.m.inner.warm_probe_override.lock().unwrap() = Some(Some(crate::machine::warm::Sample {
            at: std::time::Instant::now(),
            memory_mb: 1280,
            pool: crate::zfs::Pool {
                used: 1 << 30,
                free: 1024 << 30,
            },
            boundary: h.m.warm_probe_boundary().unwrap(),
        }));
        h.m.warm_step().await;
        assert_eq!(h.m.inner.machines.lock().unwrap().len(), 3);
        h.wait_warm_barrier().await;
        h.release_warm_barriers();
        let entries =
            h.m.inner
                .machines
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>();
        for entry in entries {
            let _completed = tokio::time::timeout(Duration::from_secs(3), entry.lock.lock())
                .await
                .unwrap();
        }
        h.m.delete_warm_pool("t1", "tools").await.unwrap();
        h.m.warm_step().await;
    }
}

#[tokio::test]
async fn durable_paused_claim_can_finish_after_catalog_removal_and_pool_drain() {
    use sha2::Digest;
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    {
        let _completed = e.lock.lock().await;
    }
    // Crash boundary: receipt is durable, but the machine marker/name are still paused.
    let mut saved =
        h.m.inner
            .store
            .list::<serde_json::Value>("warm-pools")
            .unwrap()
            .remove(0);
    saved["claims"] = json!({"pending": {"machine": e.snapshot().id, "name": "owned"}});
    let pool_key = hex::encode(sha2::Sha256::digest(b"t1\0tools"));
    h.m.inner
        .store
        .put_durable("warm-pools", &pool_key, &saved)
        .unwrap();
    h.m.recover_warm_names().unwrap();
    h.m.inner.warm_policy.lock().unwrap().catalog.clear();
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    assert!(h.m.entry(&e.snapshot().id).is_ok());
    let before = h.m.quota("t1").unwrap().used;
    let made =
        h.m.claim_warm_pool("t1", "tools", claim("owned", "pending"))
            .await
            .unwrap();
    assert!(made.ready);
    assert_eq!(made.id, e.snapshot().id);
    assert_eq!(h.m.quota("t1").unwrap().used, before);
}

#[tokio::test]
async fn configured_target_above_32_is_accepted_but_operator_ceiling_is_authoritative() {
    let (h, _) = pool(0).await;
    h.m.inner.warm_policy.lock().unwrap().catalog[0].max_ready = 64;
    let accepted =
        h.m.put_warm_catalog("t1", "shell-small", api::WarmDesiredRequest { desired: 64 })
            .await
            .unwrap();
    assert_eq!(accepted.desired, 64);
    assert!(h
        .m
        .put_warm_catalog("t1", "shell-small", api::WarmDesiredRequest { desired: 65 })
        .await
        .is_err());
    assert_eq!(
        h.m.warm_pools("t1")
            .unwrap()
            .iter()
            .find(|p| p.name == "shell-small")
            .unwrap()
            .desired,
        64
    );
    h.m.delete_warm_pool("t1", "shell-small").await.unwrap();
    h.m.warm_step().await;
}

#[tokio::test]
async fn configured_catalog_fill_claim_and_zero_desired_leave_claimed_machine_owned() {
    let (h, _) = pool(0).await;
    let view =
        h.m.put_warm_catalog("t1", "shell-small", api::WarmDesiredRequest { desired: 1 })
            .await
            .unwrap();
    assert_eq!(view.name, "shell-small");
    let e = fill(&h).await;
    {
        let _completed = e.lock.lock().await;
    }
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert_eq!(
        (
            status.charged.memory_mb,
            status.charged.cpu_millis,
            status.charged.root_disk_gb
        ),
        (256, 1000, h.m.inner.cfg.root_disk_gb)
    );
    let made =
        h.m.claim_warm_pool("t1", "shell-small", claim("owned", "catalog-claim"))
            .await
            .unwrap();
    h.m.put_warm_catalog("t1", "shell-small", api::WarmDesiredRequest { desired: 0 })
        .await
        .unwrap();
    h.m.warm_step().await;
    assert!(h.m.get(&made.id).unwrap().ready);
    assert_eq!(
        h.m.warm_catalog("t1").await.unwrap().charged,
        api::WarmResources::default()
    );
    h.m.destroy(&made.id, None).await.unwrap();
}

#[tokio::test]
async fn policy_drain_racing_a_durable_claim_never_stops_its_winner() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    {
        let _completed = e.lock.lock().await;
    }
    h.m.inner.warm_policy.lock().unwrap().budget.memory_mb = 1;
    let (claim, ()) = tokio::join!(
        h.m.claim_warm_pool("t1", "tools", claim("owned", "drain-race")),
        h.m.warm_step()
    );
    match claim {
        Ok(machine) => {
            assert!(h.m.get(&machine.id).unwrap().ready);
            assert!(e.snapshot().warm_slot.unwrap().claimed.is_some());
        }
        Err(MError::PoolEmpty) => assert!(h.m.entry(&e.snapshot().id).is_err()),
        Err(error) => panic!("unexpected claim outcome: {error}"),
    }
}

#[tokio::test]
async fn each_host_budget_is_full_recipe_charge_and_cannot_be_raised_by_desired() {
    for resource in ["memory", "cpu", "disk"] {
        let (h, _) = pool(0).await;
        {
            let mut policy = h.m.inner.warm_policy.lock().unwrap();
            match resource {
                "memory" => policy.budget.memory_mb = 255,
                "cpu" => policy.budget.cpu_millis = 999,
                "disk" => policy.budget.root_disk_gb = h.m.inner.cfg.root_disk_gb - 1,
                _ => unreachable!(),
            }
        }
        desired(&h, 1).await;
        settle(&h).await;
        let status = h.m.warm_catalog("t1").await.unwrap();
        assert_eq!(
            status.pools[0].creating + status.pools[0].ready,
            0,
            "{resource}"
        );
        assert!(status.pools[0].error.contains("budget"), "{resource}");
        assert_eq!(status.charged, api::WarmResources::default());
    }
}

#[tokio::test]
async fn catalog_binds_namespace_generation_and_exact_size_and_caps_aggregate_across_pools() {
    let (h, _) = pool(0).await;
    h.m.inner.warm_policy.lock().unwrap().catalog[0].max_ready = 1;
    let view = h.m.warm_pools("t1").unwrap().remove(0);
    let request = |desired| api::PutWarmPoolRequest {
        source_machine: view.source_machine.clone(),
        snapshot: view.snapshot.clone(),
        desired,
    };
    assert!(h.m.put_warm_pool("t1", "tools", request(2)).await.is_err());
    desired(&h, 1).await;
    let e = fill(&h).await;
    {
        let _completed = e.lock.lock().await;
    }
    h.m.put_warm_pool("t1", "other", request(1)).await.unwrap();
    settle(&h).await;
    let pools = h.m.warm_pools("t1").unwrap();
    assert_eq!(pools.iter().map(|p| p.ready + p.creating).sum::<usize>(), 1);
    assert!(pools.iter().any(|p| p.error.contains("catalog")));
    assert!(h
        .m
        .put_warm_catalog(
            "other",
            "shell-small",
            api::WarmDesiredRequest { desired: 1 }
        )
        .await
        .is_err());
    for mismatch in ["generation", "size"] {
        let old = h.m.inner.warm_policy.lock().unwrap().clone();
        {
            let mut p = h.m.inner.warm_policy.lock().unwrap();
            if mismatch == "generation" {
                p.catalog[0].generation = "g_changed".into();
            } else {
                p.catalog[0].size.memory_mb += 128;
            }
        }
        assert!(h
            .m
            .put_warm_pool("t1", "mismatch", request(1))
            .await
            .is_err());
        *h.m.inner.warm_policy.lock().unwrap() = old;
    }
}

#[tokio::test]
async fn stale_failed_and_low_measurements_stop_refill_and_drain_only_unused_slots() {
    for pressure in ["stale", "failed", "memory", "disk"] {
        let (h, _) = pool(1).await;
        let e = fill(&h).await;
        {
            let _completed = e.lock.lock().await;
        }
        let mut sample =
            h.m.inner
                .warm_probe_override
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .unwrap();
        match pressure {
            "stale" => sample.at -= Duration::from_secs(6),
            "memory" => sample.memory_mb = 512,
            "disk" => sample.pool.free = 8 << 30,
            _ => {}
        }
        *h.m.inner.warm_probe_override.lock().unwrap() = Some(if pressure == "failed" {
            None
        } else {
            Some(sample)
        });
        h.m.warm_step().await;
        assert!(h.m.entry(&e.snapshot().id).is_err(), "{pressure}");
        assert_eq!(
            h.m.inner.machines.lock().unwrap().len(),
            1,
            "source survives {pressure}"
        );
        assert!(
            h.m.warm_pools("t1").unwrap()[0].error.contains("pressure"),
            "{pressure}"
        );
    }
}

#[tokio::test]
async fn lowered_budget_and_catalog_removal_never_drain_claimed_slots() {
    for remove in [false, true] {
        let (h, _) = pool(1).await;
        let e = fill(&h).await;
        {
            let _completed = e.lock.lock().await;
        }
        h.m.claim_warm_pool("t1", "tools", claim("worker", "policy-claim"))
            .await
            .unwrap();
        {
            let mut p = h.m.inner.warm_policy.lock().unwrap();
            if remove {
                p.catalog.clear();
            } else {
                p.budget.memory_mb = 1;
            }
        }
        h.m.warm_step().await;
        assert!(h.m.get(&e.snapshot().id).unwrap().ready);
        assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 512);
    }
}

#[tokio::test]
async fn pending_durable_receipt_reconstructs_ordinary_classification_without_releasing_charge() {
    let (h, _) = pool(1).await;
    let e = fill(&h).await;
    {
        let _completed = e.lock.lock().await;
    }
    h.m.claim_warm_pool("t1", "tools", claim("worker", "intent"))
        .await
        .unwrap();
    let full = h.m.quota("t1").unwrap().used;
    {
        let mut r = e.rec.lock().unwrap();
        r.warm_slot.as_mut().unwrap().claimed = None;
        r.name = "warm-before-rename".into();
        r.state = state::STARTING.into();
        r.clone_origin.as_mut().unwrap().stage = CloneStage::Paused;
    }
    h.m.inner.warm_names.lock().unwrap().clear();
    h.m.recover_warm_names().unwrap();
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert_eq!(status.charged, api::WarmResources::default());
    assert_eq!(status.pools[0].claimed, 1);
    assert_eq!(h.m.quota("t1").unwrap().used, full);
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    assert!(h.m.entry(&e.snapshot().id).is_ok());
}

#[tokio::test]
async fn fills_across_pools_share_maximum_including_parked_worker_until_completion() {
    let (h, _) = pool(0).await;
    h.m.inner.warm_policy.lock().unwrap().max_fills = 1;
    h.pause_warm_barrier("warm_parked");
    desired(&h, 1).await;
    h.wait_warm_barrier().await;
    let view = h.m.warm_pools("t1").unwrap().remove(0);
    h.m.put_warm_pool(
        "t1",
        "other",
        api::PutWarmPoolRequest {
            source_machine: view.source_machine,
            snapshot: view.snapshot,
            desired: 1,
        },
    )
    .await
    .unwrap();
    settle(&h).await;
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert!(h
        .m
        .warm_pools("t1")
        .unwrap()
        .iter()
        .any(|p| p.error.contains("concurrent")));
    h.release_warm_barriers();
    let e = fill(&h).await;
    let _completed = e.lock.lock().await;
}

#[tokio::test]
async fn ordinary_admission_racing_fill_can_consume_headroom_and_refill_rechecks_under_map_lock() {
    let (h, _) = pool(0).await;
    h.pause_warm_barrier("warm_admission");
    desired(&h, 1).await;
    h.wait_warm_barrier().await;
    let mut request = h.request("ordinary");
    request.image = ALPINE.into();
    // Source: 512 MiB physical; ordinary: 3072 + 256 MiB. Both fit the host,
    // but the remaining 256 MiB cannot cover a fill plus its reserved headroom.
    request.size.memory_mb = 3072;
    let ordinary = h.m.create_made(request).await.unwrap();
    assert_eq!(h.m.usage().0.memory_mb, 3840);
    h.release_warm_barriers();
    settle(&h).await;
    let view = h.m.warm_pools("t1").unwrap().remove(0);
    assert_eq!(view.creating + view.ready, 0);
    assert!(view.error.contains("headroom"));
    assert!(h.m.get(&ordinary.id).unwrap().ready);
}

#[tokio::test]
async fn data_volumes_are_fully_budgeted_and_subtracted_from_disk_floor() {
    let (h, _) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _completed = entry.lock.lock().await;
    }
    entry.rec.lock().unwrap().volume = Some(api::VolumeSpec {
        size_gb: 2,
        mount: "/work".into(),
    });
    h.m.inner.warm_policy.lock().unwrap().budget.data_disk_gb = 2;
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert_eq!(status.charged.data_disk_gb, 2);
    assert_eq!(
        status.charged.root_disk_gb,
        entry
            .snapshot()
            .clone_origin
            .unwrap()
            .artifact
            .recipe
            .root_disk_gb
    );
    assert!(status.blocked.is_empty());
    h.m.inner.warm_policy.lock().unwrap().budget.data_disk_gb = 1;
    assert!(h
        .m
        .warm_catalog("t1")
        .await
        .unwrap()
        .blocked
        .iter()
        .any(|reason| reason.reason == "budget"));
    h.m.inner.warm_policy.lock().unwrap().budget.data_disk_gb = 2;
    let root = u64::from(status.charged.root_disk_gb);
    // Roots alone would leave 17 GiB above a 16 GiB floor; full data leaves 15 GiB.
    h.m.inner
        .warm_probe_override
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .pool
        .free = (root + 17) << 30;
    assert!(h
        .m
        .warm_catalog("t1")
        .await
        .unwrap()
        .blocked
        .iter()
        .any(|reason| reason.reason == "pressure"));
    entry.rec.lock().unwrap().state = state::ERROR.into();
    assert_eq!(
        h.m.warm_metrics().charged.data_disk_gb,
        2,
        "failed/unknown cleanup retains its full data reservation"
    );
    assert!(
        matches!(h.m.warm_catalog("t1").await, Err(MError::Capacity(_))),
        "the still-live VMM in error state must also block protected admission"
    );
}

#[tokio::test]
async fn a_claim_cannot_erase_root_and_data_liability_from_a_usable_sample() {
    let (h, _) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _completed = entry.lock.lock().await;
    }
    entry.rec.lock().unwrap().volume = Some(api::VolumeSpec {
        size_gb: 2,
        mount: "/work".into(),
    });
    h.m.inner.warm_policy.lock().unwrap().budget.data_disk_gb = 2;
    let boundary = h.m.warm_probe_boundary().unwrap();
    let root = u64::from(
        entry
            .snapshot()
            .clone_origin
            .unwrap()
            .artifact
            .recipe
            .root_disk_gb,
    );
    let mut sample = crate::machine::warm::Sample {
        at: std::time::Instant::now(),
        memory_mb: 32768,
        pool: crate::zfs::Pool {
            used: 1 << 30,
            free: (16 + root + 1) << 30,
        },
        boundary,
    };
    // Record-level accounting boundary only: native claim/volume behavior is not exercised.
    entry
        .rec
        .lock()
        .unwrap()
        .warm_slot
        .as_mut()
        .unwrap()
        .claimed = Some("accounting-claim".into());
    *h.m.inner.warm_probe_override.lock().unwrap() = Some(Some(sample.clone()));
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert_eq!(status.charged.data_disk_gb, 0);
    assert!(status
        .blocked
        .iter()
        .any(|reason| reason.reason == "pressure"));
    sample.boundary = h.m.warm_probe_boundary().unwrap();
    *h.m.inner.warm_probe_override.lock().unwrap() = Some(Some(sample));
    assert!(h.m.warm_catalog("t1").await.unwrap().blocked.is_empty());
}

// These tests exercise accounting records, not a qualified volume-bearing clone.
// The public init-ready pool lifecycle continues to reject data-volume recipes.
#[tokio::test]
async fn data_volume_budget_is_independent_and_retained_through_uncertain_cleanup() {
    let (h, _) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _completed = entry.lock.lock().await;
    }
    entry.rec.lock().unwrap().volume = Some(api::VolumeSpec {
        size_gb: 12,
        mount: "/work".into(),
    });
    let before = h.m.quota("t1").unwrap().used;
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert_eq!(status.budget.data_disk_gb, 0);
    assert_eq!(status.charged.data_disk_gb, 12);
    assert!(status.blocked.iter().any(|b| b.reason == "budget"));
    {
        let mut policy = h.m.inner.warm_policy.lock().unwrap();
        policy.budget.data_disk_gb = 12;
    }
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert!(status.blocked.is_empty());
    // An additional fill must fit the independent data budget, even with ample roots,
    // memory, CPU and physical free space. No admission state moves on refusal.
    let candidate = entry.snapshot();
    {
        let machines = h.m.inner.machines.lock().unwrap();
        assert!(matches!(
            h.m.admit_warm_policy(&machines, &candidate),
            Err(MError::Capacity(message)) if message.starts_with("budget:")
        ));
    }
    assert_eq!(h.m.quota("t1").unwrap().used, before);

    // Lowering the budget or demand cannot release a data liability before exit proof.
    h.m.inner.warm_policy.lock().unwrap().budget.data_disk_gb = 11;
    h.refuse_clone_exit(true);
    *entry.live.lock().unwrap() = None;
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    let status = h.m.warm_catalog("t1").await.unwrap();
    assert_eq!(status.draining, 1);
    assert_eq!(status.charged.data_disk_gb, 12);
    assert_eq!(h.m.quota("t1").unwrap().used, before);
    assert!(h
        .m
        .metrics()
        .contains("briqyard_warm_data_disk_bytes{kind=\"reserved\"} 12884901888\n"));
    h.refuse_clone_exit(false);
    h.m.warm_step().await;
    assert_eq!(
        h.m.warm_catalog("t1").await.unwrap().charged.data_disk_gb,
        0
    );
    assert!(h.m.entry(&entry.snapshot().id).is_err());
}

#[tokio::test]
async fn pool_space_floor_subtracts_both_full_root_and_data_liabilities() {
    let (h, _) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _completed = entry.lock.lock().await;
    }
    entry.rec.lock().unwrap().volume = Some(api::VolumeSpec {
        size_gb: 12,
        mount: "/work".into(),
    });
    h.m.inner.warm_policy.lock().unwrap().budget.data_disk_gb = 12;
    let root = h.m.inner.cfg.root_disk_gb;
    let floor = h.m.inner.warm_policy.lock().unwrap().headroom.disk_free_gb;
    let free = u64::from(root + 12 + floor) << 30;
    for (extra, pressure) in [(0, true), (1, false)] {
        *h.m.inner.warm_probe_override.lock().unwrap() = Some(Some(crate::machine::warm::Sample {
            at: std::time::Instant::now(),
            memory_mb: 32768,
            boundary: h.m.warm_probe_boundary().unwrap(),
            pool: crate::zfs::Pool {
                used: 0,
                free: free + extra,
            },
        }));
        let status = h.m.warm_catalog("t1").await.unwrap();
        assert_eq!(status.charged.root_disk_gb, root);
        assert_eq!(status.charged.data_disk_gb, 12);
        assert_eq!(
            status
                .blocked
                .iter()
                .any(|b| b.reason == "pressure" && b.message.contains("pool free-space")),
            pressure
        );
    }
}

#[tokio::test]
async fn durable_claim_transfers_data_charge_to_ordinary_without_releasing_namespace_charge() {
    let (h, _) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _completed = entry.lock.lock().await;
    }
    entry.rec.lock().unwrap().volume = Some(api::VolumeSpec {
        size_gb: 12,
        mount: "/work".into(),
    });
    let before = h.m.quota("t1").unwrap().used;
    // Existing durable claim receipt boundary, before the in-memory claimed marker.
    // This exercises accounting transfer only; no volume-bearing guest is resumed.
    let key = hex::encode(sha2::Sha256::digest(b"t1\0tools"));
    let mut pool =
        h.m.inner
            .store
            .get::<serde_json::Value>("warm-pools", &key)
            .unwrap()
            .unwrap();
    pool["claims"] = json!({"data-transfer": {"machine": entry.snapshot().id, "name": "owned"}});
    h.m.inner
        .store
        .put_durable("warm-pools", &key, &pool)
        .unwrap();
    h.m.recover_warm_names().unwrap();
    assert_eq!(
        h.m.warm_catalog("t1").await.unwrap().charged.data_disk_gb,
        0
    );
    assert_eq!(h.m.quota("t1").unwrap().used, before);
    assert!(h
        .m
        .metrics()
        .contains("briqyard_warm_data_disk_bytes{kind=\"reserved\"} 0\n"));
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    assert!(h.m.entry(&entry.snapshot().id).is_ok());
    assert_eq!(h.m.quota("t1").unwrap().used, before);
}
