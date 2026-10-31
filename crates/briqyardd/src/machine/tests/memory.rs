//! Host memory is a physical reservation; namespace size remains guest memory.
use super::*;

#[tokio::test]
async fn host_and_namespace_memory_are_different_domains() {
    let h = harness("10.64.0.0/22", 512).await;
    h.ready().await;
    h.m.set_quota(
        "t1",
        api::Quota {
            memory_mb: Some(256),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let machine = h.m.create_made(h.request("one")).await.unwrap();
    assert_eq!(machine.size.memory_mb, 256);
    assert_eq!(h.m.usage().0.memory_mb, 512);
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 256);
    assert!(matches!(
        h.m.create_made(h.request("two")).await,
        Err(MError::Quota(_))
    ));
    h.m.stop(&machine.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(h.m.usage().0.memory_mb, 0);
}

#[tokio::test]
async fn every_committing_record_reserves_overhead_once() {
    let h = harness("10.64.0.0/22", 4096).await;
    for (i, state) in [
        state::CREATING,
        state::STARTING,
        state::RUNNING,
        state::STOPPING,
    ]
    .into_iter()
    .enumerate()
    {
        let entry = h.add(&format!("m_{i}"), state, 256);
        entry.rec.lock().unwrap().start = true;
        assert_eq!(h.m.usage().0.memory_mb, (i as u32 + 1) * 512);
    }
    let stopped = h.add("m_stopped", state::STOPPED, 256);
    stopped.rec.lock().unwrap().suspended = true;
    let created = h.add("m_created", state::CREATING, 256);
    created.rec.lock().unwrap().start = false;
    assert_eq!(h.m.usage().0.memory_mb, 2048);
    assert_eq!(api::vmm_memory_mb(u32::MAX), None);
}

#[tokio::test]
async fn the_last_physical_slot_is_reserved_under_the_existing_lock() {
    let h = harness("10.64.0.0/22", 1024).await;
    let entries: Vec<_> = (0..8)
        .map(|i| h.add(&format!("m_{i}"), state::STOPPED, 256))
        .collect();
    let admitted = std::thread::scope(|scope| {
        let tasks: Vec<_> = entries
            .iter()
            .map(|e| scope.spawn(|| h.m.reserve(e, None).is_ok()))
            .collect();
        tasks
            .into_iter()
            .map(|task| usize::from(task.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(admitted, 2);
    assert_eq!(h.m.usage().0.memory_mb, 1024);
}

#[tokio::test]
async fn positive_adoption_survives_policy_failure_and_blocks_new_admission() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let ours = h.add("m_ours", state::RUNNING, 256);
    let pid = h
        .host
        .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
    ours.rec.lock().unwrap().pid = pid;
    *h.host.memory_policy.lock().unwrap() = Some(fc::MemoryProtection {
        charge_mb: 1024,
        degraded: Some("policy_write_denied"),
        contained: false,
    });
    h.m.recover().await.unwrap();
    h.m.resume_recovery_workers();
    assert_eq!(ours.snapshot().state, state::RUNNING);
    assert_eq!(ours.snapshot().pid, pid);
    assert!(ours.live.lock().unwrap().is_some());
    assert_eq!(h.m.usage().0.memory_mb, 1024);
    assert!(h
        .m
        .conditions()
        .iter()
        .any(|c| c.kind == "memory_protection" && c.status));
    assert!(matches!(
        h.m.create_made(h.request("refused")).await,
        Err(MError::Capacity(_))
    ));
    assert!(!h
        .host
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("kill ")));
    let condition = || {
        h.m.conditions()
            .into_iter()
            .find(|c| c.kind == "memory_protection")
            .unwrap()
    };
    let first = condition();
    assert_eq!(condition().since, first.since);
    // The live guest is managed normally; stopping it releases its physical reservation.
    h.m.stop("m_ours", Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(h.m.usage().0.memory_mb, 0);
    assert!(!h
        .m
        .conditions()
        .iter()
        .any(|c| c.kind == "memory_protection" && c.status));
}

#[test]
fn only_the_runtime_record_role_selects_gateway_preference() {
    use briqyard_api::host_process::OomClass;
    let mut r = record();
    r.name = "gateway".into();
    r.metadata.insert("oom_score_adj".into(), "-1000".into());
    r.metadata.insert("role".into(), "gateway".into());
    assert_eq!(r.oom_class(), OomClass::Machine);
    r.role = Some(Role::Gateway);
    assert_eq!(r.oom_class(), OomClass::Gateway);
}
