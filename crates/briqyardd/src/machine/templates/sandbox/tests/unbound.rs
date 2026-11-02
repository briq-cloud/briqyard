//! Factory-record and ordinary-create integration with existing mocked disks/lifecycle.
use super::*;

fn bounded<T>(
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    let future = Box::pin(future);
    async move {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("unbound integration operation completes")
    }
}

async fn pool() -> (Harness, api::SandboxSeed, Arc<Entry>) {
    let (h, source, seed) = bounded(source_with_unbound(true)).await;
    let artifact = source
        .snapshot()
        .snapshots
        .iter()
        .find(|s| s.id == seed.snapshot)
        .unwrap()
        .clone_artifact
        .clone()
        .unwrap();
    *h.m.inner.warm_policy.lock().unwrap() = crate::config::WarmPolicy {
        budget: api::WarmResources {
            memory_mb: 2048,
            cpu_millis: 6000,
            root_disk_gb: 64,
            data_disk_gb: 8,
        },
        headroom: crate::config::WarmHeadroom {
            memory_mb: 512,
            cpu_millis: 1000,
            disk_free_gb: 16,
        },
        min_mem_available_mb: 512,
        max_fills: 2,
        catalog: vec![api::WarmCatalogEntry {
            id: "pristine-small".into(),
            namespace: "operator".into(),
            kind: "sandbox".into(),
            source_machine: seed.machine_id.clone(),
            snapshot: seed.snapshot.clone(),
            generation: seed.generation.clone(),
            size: artifact.recipe.size,
            max_ready: 2,
        }],
    };
    // Use the same deterministic capacity observation as the configured-pool fixtures.
    *h.m.inner.warm_probe_override.lock().unwrap() = Some(Some(crate::machine::warm::Sample {
        at: std::time::Instant::now(),
        memory_mb: 32768,
        boundary: Default::default(),
        pool: crate::zfs::Pool {
            used: 1 << 30,
            free: 1024 << 30,
        },
    }));
    h.m.put_warm_pool(
        "operator",
        "pristine",
        api::PutWarmPoolRequest {
            source_machine: seed.machine_id.clone(),
            snapshot: seed.snapshot.clone(),
            desired: 1,
        },
    )
    .await
    .unwrap();
    // PUT queues refill without yielding after releasing admission. Take that same lock
    // before yielding to its worker, so the fixture supplies the mocked disks first.
    let turn = h.m.inner.warm_lock.lock().await;
    let pool =
        h.m.inner
            .store
            .list::<crate::machine::warm::Pool>("warm-pools")
            .unwrap()
            .pop()
            .unwrap();
    h.m.warm_probe().await.unwrap();
    let (entry, how) = bounded(h.m.allocate_warm_slot(&pool, "warm-fixture".into(), None))
        .await
        .unwrap();
    assert!(matches!(how, Make::Fork(_, _)));
    // The factory's record/artifact/reader/launch admission is real. Native formatting
    // and device geometry are outside this existing fake-backend test harness.
    h.disks(&entry).await;
    {
        let _entry = entry.lock.lock().await;
        bounded(h.m.start_entry(&entry, true)).await.unwrap();
    }
    assert_eq!(
        entry.snapshot().clone_origin.as_ref().unwrap().stage,
        CloneStage::UnboundPaused
    );
    drop(turn);
    (h, seed, entry)
}

#[tokio::test]
async fn ordinary_create_transfers_unbound_slot_and_replays_without_another_worker() {
    // Omitted CPU millis and the equivalent explicit budget identify the same resource recipe.
    for explicit_cpu in [false, true] {
        let (h, seed, slot) = bounded(pool()).await;
        let before = slot.snapshot();
        assert!(!crate::machine::warm::ready_slot(&before));
        assert!(before.env.is_empty() && before.files.is_empty() && before.ports.is_empty());
        assert!(before.clone_origin.as_ref().unwrap().sandbox.is_none());
        let names = h.m.namespace_dns_names("operator");
        assert!(!names.contains_key(&before.hostname()));
        assert!(!names.contains_key(&before.machine_host()));
        h.host_calls();
        let mut request = destination(seed);
        if explicit_cpu {
            request.size.cpu_millis = Some(1000);
        }
        let count = h.m.inner.machines.lock().unwrap().len();
        let accepted = bounded(h.m.create(request.clone())).await.unwrap();
        assert_eq!(accepted.id, before.id);
        assert_eq!(accepted.state, state::STARTING);
        assert_eq!(h.m.inner.machines.lock().unwrap().len(), count);
        let current = slot.snapshot();
        assert_eq!(current.namespace, request.namespace);
        assert_eq!(current.launch_identity, before.launch_identity);
        assert_eq!(current.boot_incarnation, before.boot_incarnation);
        assert_eq!(current.root_dataset(), before.root_dataset());
        assert_eq!(current.data_dataset(), before.data_dataset());
        assert_eq!(
            bounded(h.m.create(request.clone())).await.unwrap().id,
            accepted.id
        );
        let running =
            h.m.wait(&accepted.id, Until::Ready, Duration::from_secs(10))
                .await
                .unwrap();
        assert_eq!(running.state, state::RUNNING);
        assert!(slot.identity_trusted.load(Relaxed));
        assert!(!h.m.namespace_dns_names("destination").is_empty());
        assert_eq!(bounded(h.m.create(request)).await.unwrap().id, accepted.id);
        let calls = h.host_calls();
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("boot ") || c.starts_with("snapshot ")));
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("assigned_resume "))
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("activate_quarantined "))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn desired_zero_falls_back_to_the_same_seed_restore() {
    let (h, seed, slot) = bounded(pool()).await;
    h.m.put_warm_pool(
        "operator",
        "pristine",
        api::PutWarmPoolRequest {
            source_machine: seed.machine_id.clone(),
            snapshot: seed.snapshot.clone(),
            desired: 0,
        },
    )
    .await
    .unwrap();
    let request = destination(seed);
    let (entry, make) = bounded(h.m.record(request.clone(), None)).await.unwrap();
    assert_ne!(entry.snapshot().id, slot.snapshot().id);
    assert!(matches!(make, Make::Fork(_, _)));
    let binding = entry.snapshot().clone_origin.unwrap().sandbox.unwrap();
    assert_eq!(binding.create_sha256, request_digest(&request).unwrap());
    assert_eq!(
        bounded(h.m.record(request, None))
            .await
            .unwrap()
            .0
            .snapshot()
            .id,
        entry.snapshot().id
    );
}

#[tokio::test]
async fn invalid_resources_and_uncertain_intent_never_consume_another_destination() {
    let (h, seed, slot) = bounded(pool()).await;
    let mut request = destination(seed);
    let count = h.m.inner.machines.lock().unwrap().len();
    for size in [
        api::Size::default(),
        api::Size {
            cpu_millis: Some(500),
            ..request.size
        },
    ] {
        let mut invalid = request.clone();
        invalid.size = size;
        assert!(bounded(h.m.create(invalid)).await.is_err());
        assert_eq!(h.m.inner.machines.lock().unwrap().len(), count);
        assert!(slot.snapshot().warm_slot.unwrap().claimed.is_none());
    }
    // Fail the intent write after the existing writer has installed its in-memory reservation.
    let key = hex::encode(Sha256::digest(
        serde_json::to_vec(&(
            &request.namespace,
            &request.sandbox_seed.as_ref().unwrap().request_id,
        ))
        .unwrap(),
    ));
    let blocked =
        h.m.inner
            .store
            .dir("unbound-assignments")
            .join(format!("{key}.json.tmp"));
    std::fs::create_dir(&blocked).unwrap();
    let error = bounded(h.m.create(request.clone())).await.unwrap_err();
    let MError::Other(error) = error else {
        panic!("intent write must fail after reservation: {error}");
    };
    assert_eq!(error.to_string(), format!("write {}", blocked.display()));
    assert!(error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::IsADirectory));
    assert!(bounded(h.m.create(request.clone())).await.is_err());
    request.name = "changed-after-consumption".into();
    assert!(bounded(h.m.create(request)).await.is_err());
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), count);
    let retained = slot.snapshot();
    assert!(!h
        .m
        .assignment_publication_allowed(&retained, slot.identity_trusted.load(Relaxed)));
    let origin = retained.clone_origin.as_ref().unwrap();
    assert_eq!(origin.stage, CloneStage::UnboundPaused);
    assert!(origin.sandbox.is_none());
    assert!(h.m.namespace_dns_names("destination").is_empty());
    assert!(h
        .m
        .destination_assignment_owns(&slot.snapshot().id)
        .unwrap());
}

#[tokio::test]
async fn busy_unused_slot_is_a_seed_restore_miss_without_transferring_the_slot() {
    let (h, seed, slot) = bounded(pool()).await;
    let guard = slot.lock.lock().await;
    let request = destination(seed);
    let (entry, how) = bounded(h.m.record(request.clone(), None)).await.unwrap();
    assert_ne!(entry.snapshot().id, slot.snapshot().id);
    assert!(matches!(how, Make::Fork(_, _)));
    assert_eq!(
        entry
            .snapshot()
            .clone_origin
            .unwrap()
            .sandbox
            .unwrap()
            .create_sha256,
        request_digest(&request).unwrap()
    );
    assert!(slot.snapshot().warm_slot.unwrap().claimed.is_none());
    drop(guard);
}
