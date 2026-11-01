use super::*;

async fn pending() -> (Harness, Arc<Entry>, String) {
    let (h, builder) = reviewed_builder().await;
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
    let request = api::CreateMachineRequest {
        namespace: "t1".into(),
        name: "interrupted".into(),
        fork: Some(api::ForkSpec {
            machine_id: builder.id,
            copy: String::new(),
            snapshot: Some(snapshot.id.clone()),
        }),
        ..Default::default()
    };
    let (e, _) = h.m.record(request, None).await.unwrap();
    h.m.clone_stage(&e, CloneStage::Loading).unwrap();
    e.set_state(state::STARTING, |_| None);
    h.m.save(&e).unwrap();
    (h, e, snapshot.id)
}

#[tokio::test]
async fn pid_zero_and_unknown_launch_retain_full_quota_and_reader_during_destroy() {
    let (h, e, _) = pending().await;
    let id = e.snapshot().id;
    assert_eq!(e.snapshot().pid, 0);
    assert!(commits_memory(&e.snapshot()));
    h.m.recover_incomplete_clone(&e).await;
    assert!(!e.snapshot().clone_origin.unwrap().mapping_exited);
    assert!(matches!(
        h.m.destroy(&id, None).await,
        Err(MError::Conflict(_))
    ));
    assert_eq!(e.snapshot().state, state::DESTROYING);
    assert!(commits_memory(&e.snapshot()));
    let need = quota_need(&e.snapshot(), false);
    assert_eq!(need.memory_mb, 256);
    assert_eq!(need.cpu_millis(), 1000);
    assert_eq!(h.m.clone_readers().unwrap().len(), 1);
    assert!(!h
        .host_calls()
        .iter()
        .any(|call| call.starts_with("settle-clone") || call.starts_with("kill ")));
    // Missing/malformed boot information is not a reboot proof either.
    for boot in [None, Some("invalid")] {
        h.set_host_boot_id(boot);
        assert!(!h.m.reconcile_clone_exit(&e).await.unwrap());
        assert!(commits_memory(&e.snapshot()));
    }
}

#[tokio::test]
async fn persisted_launch_boot_boundary_confirms_death_and_allows_explicit_cleanup() {
    let (h, e, _) = pending().await;
    let id = e.snapshot().id;
    let saved: Record = h.m.inner.store.get("machines", &id).unwrap().unwrap();
    assert_eq!(
        saved.clone_origin.unwrap().launch_host_boot_id.as_deref(),
        Some("11111111-1111-4111-8111-111111111111")
    );
    h.set_host_boot_id(Some("22222222-2222-4222-8222-222222222222"));
    h.m.recover_incomplete_clone(&e).await;
    assert!(e.snapshot().clone_origin.unwrap().mapping_exited);
    assert_eq!(e.snapshot().state, state::ERROR);
    assert!(commits_memory(&e.snapshot())); // cleanup has not released the reserved slot yet
    h.m.destroy(&id, None).await.unwrap();
    assert!(h.m.entry(&id).is_err());
    assert!(h.m.clone_readers().unwrap().is_empty());
}

#[tokio::test]
async fn exact_registered_incarnation_is_settled_without_guest_activation() {
    let (h, builder) = reviewed_builder().await;
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
    let made =
        h.m.create_made(api::CreateMachineRequest {
            namespace: "t1".into(),
            name: "interrupted".into(),
            fork: Some(api::ForkSpec {
                machine_id: builder.id.clone(),
                copy: String::new(),
                snapshot: Some(snapshot.id),
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let e = h.m.entry(&made.id).unwrap();
    let pid = e.snapshot().pid;
    {
        let mut record = e.rec.lock().unwrap();
        record.state = state::STARTING.into();
        record.clone_origin.as_mut().unwrap().stage = CloneStage::Loading;
    }
    *e.live.lock().unwrap() = None;
    h.host_calls();
    h.refuse_clone_exit(true);
    h.m.recover_incomplete_clone(&e).await;
    assert!(!e.snapshot().clone_origin.unwrap().mapping_exited);
    assert!(commits_memory(&e.snapshot()));
    h.refuse_clone_exit(false);
    h.m.recover_incomplete_clone(&e).await;
    assert!(e.snapshot().clone_origin.unwrap().mapping_exited);
    let calls = h.host_calls();
    assert!(calls.contains(&format!("kill {pid}")));
    assert!(!calls.iter().any(|c| c.starts_with("resume ")
        || c.starts_with("clone-activate")
        || c.starts_with("clone-configure")));
    assert!(h
        .m
        .entry(&builder.id)
        .unwrap()
        .live
        .lock()
        .unwrap()
        .is_some());
    h.m.destroy(&made.id, None).await.unwrap();
    assert!(h.m.clone_readers().unwrap().is_empty());
}

#[tokio::test]
async fn launch_without_valid_boot_fence_is_refused_before_a_vmm_starts() {
    let (h, e, _) = pending().await;
    e.rec.lock().unwrap().clone_origin.as_mut().unwrap().stage = CloneStage::Reserved;
    h.set_host_boot_id(None);
    h.host_calls();
    assert!(h.m.clone_stage(&e, CloneStage::Loading).is_err());
    assert_eq!(
        e.snapshot().clone_origin.unwrap().stage,
        CloneStage::Reserved
    );
    assert!(!h.host_calls().iter().any(|c| c.starts_with("boot ")));
}
