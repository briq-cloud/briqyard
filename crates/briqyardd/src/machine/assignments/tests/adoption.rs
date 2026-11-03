use super::*;

async fn staged(
    phase: u8,
) -> (
    crate::machine::tests::Harness,
    String,
    api::CreateMachineRequest,
) {
    let (h, entry, request) = fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    h.m.commit_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    if phase == 1 {
        h.lose_destination_ack();
    }
    if phase == 2 {
        h.assigned_first_exec_code(7);
    }
    if phase != 0 {
        let result =
            h.m.start_destination_assignment("destination", "assignment-one", &digest)
                .await;
        assert_eq!(result.is_ok(), phase == 3);
    }
    (h, entry.snapshot().id, request)
}

fn no_cleanup_or_cold_launch(calls: &[String]) {
    assert!(!calls.iter().any(|call| [
        "kill ",
        "settle-clone ",
        "spawn ",
        "snapshot ",
        "destination_bind_v1",
        "clone_activate_v1",
        "exec "
    ]
    .iter()
    .any(|prefix| call.starts_with(prefix))));
}

#[tokio::test]
async fn assigned_stage_adoption_proves_continuity_before_trust_or_active_publication() {
    for phase in 0..4 {
        let (h, id, request) = staged(phase).await;
        let before = h.m.entry(&id).unwrap().snapshot();
        let host = committed(&h.m.inner.machines.lock().unwrap()).0;
        restart_load(&h.m).unwrap();
        h.m.inner.policies.lock().unwrap().clear();
        h.host_calls();
        let entry = h.m.entry(&id).unwrap();
        assert!(!entry.identity_trusted.load(Relaxed));
        let (adopted, _, _) = h.m.recover().await.unwrap();
        assert_eq!(adopted, 1);
        assert!(entry.identity_trusted.load(Relaxed));
        assert_eq!(entry.live.lock().unwrap().as_ref().unwrap().pid, before.pid);
        assert_eq!(entry.snapshot().launch_identity, before.launch_identity);
        assert_eq!(entry.snapshot().boot_incarnation, before.boot_incarnation);
        assert_eq!(
            committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
            host.memory_mb
        );
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
        let calls = h.host_calls();
        no_cleanup_or_cold_launch(&calls);
        let quarantine = calls
            .iter()
            .position(|call| call.starts_with("quarantine "))
            .unwrap();
        let ping = calls
            .iter()
            .position(|call| call.starts_with("ping "))
            .unwrap();
        assert!(quarantine < ping);
        if phase == 3 {
            let network = calls
                .iter()
                .position(|call| call.starts_with("activate_quarantined "))
                .unwrap();
            assert!(ping < network);
            assert!(h
                .m
                .namespace_dns_names("destination")
                .contains_key(&entry.snapshot().hostname()));
            assert!(h.m.ordinary_operation(&entry.snapshot()).is_ok());
        } else {
            assert!(!calls
                .iter()
                .any(|call| call.starts_with("activate_quarantined ")));
            assert!(h.m.namespace_dns_names("destination").is_empty());
            assert!(h.m.ordinary_operation(&entry.snapshot()).is_err());
            // Recovered incomplete stages are still quarantined. Only the exact private
            // caller can replay the already frozen payload and finish normal barriers.
            h.assigned_first_exec_code(0);
            h.m.start_destination_assignment(
                "destination",
                "assignment-one",
                &templates::sandbox::request_digest(&request).unwrap(),
            )
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn assigned_recovery_refuses_fresh_init_marker_protocol_identity_and_device_mismatches() {
    for fault in 0..6 {
        let (h, id, _) = staged(3).await;
        let original = h.m.entry(&id).unwrap();
        let live = original.live.lock().unwrap().clone().unwrap();
        let mut status =
            h.m.inner
                .guest
                .ping(&live.vsock)
                .await
                .unwrap()
                .clone_status
                .unwrap();
        match fault {
            0 => status.ram_marker = "f".repeat(32),
            1 => status.protocol = 2,
            2 => status.identity.as_mut().unwrap().hostname = "different".into(),
            3 => h.assigned_guest_init(&live.vsock, &"0".repeat(64)),
            4 => h.assigned_adoption_profile(fc::UNAVAILABLE_PROFILE),
            _ => h.assigned_adoption_profile(fc::REPORTING_PROFILE),
        }
        h.assigned_guest_status(&live.vsock, status);
        let before = original.snapshot();
        restart_load(&h.m).unwrap();
        h.m.inner.policies.lock().unwrap().clear();
        h.host_calls();
        h.m.recover().await.unwrap();
        let entry = h.m.entry(&id).unwrap();
        assert!(!entry.identity_trusted.load(Relaxed));
        assert!(entry.live.lock().unwrap().is_none());
        assert!(h.m.namespace_dns_names("destination").is_empty());
        assert!(h.m.ordinary_operation(&entry.snapshot()).is_err());
        let calls = h.host_calls();
        no_cleanup_or_cold_launch(&calls);
        assert!(!calls
            .iter()
            .any(|call| call.starts_with("activate_quarantined ")));
        assert!(h.pool.zfs.exists(&before.root_dataset()).await.unwrap());
        assert!(commits_memory(&entry.snapshot()));
    }
}

#[tokio::test]
async fn uncertain_assigned_resume_is_retained_and_explicit_recovery_queries_the_same_process() {
    let (h, id, request) = staged(0).await;
    let before = h.m.entry(&id).unwrap().snapshot();
    h.lose_assigned_resume();
    restart_load(&h.m).unwrap();
    h.host_calls();
    let entry = h.m.entry(&id).unwrap();
    assert!(!h.m.recover_assigned_launch(&entry).await);
    assert!(!entry.identity_trusted.load(Relaxed));
    assert!(entry.live.lock().unwrap().is_none());
    let frozen = entry
        .snapshot()
        .clone_origin
        .unwrap()
        .sandbox
        .unwrap()
        .bind
        .unwrap()
        .fingerprint_bytes()
        .unwrap();
    no_cleanup_or_cold_launch(&h.host_calls());
    assert!(h.m.recover_assigned_launch(&entry).await);
    assert_eq!(entry.live.lock().unwrap().as_ref().unwrap().pid, before.pid);
    assert_eq!(
        entry
            .snapshot()
            .clone_origin
            .unwrap()
            .sandbox
            .unwrap()
            .bind
            .unwrap()
            .fingerprint_bytes()
            .unwrap(),
        frozen
    );
    assert!(h.m.namespace_dns_names("destination").is_empty());
    h.m.start_destination_assignment(
        "destination",
        "assignment-one",
        &templates::sandbox::request_digest(&request).unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn assigned_stopped_loading_and_unknown_incarnation_never_enter_legacy_cleanup_or_cold_restart(
) {
    for fault in 0..3 {
        let (h, id, _) = staged(3).await;
        let entry = h.m.entry(&id).unwrap();
        {
            let mut record = entry.rec.lock().unwrap();
            match fault {
                0 => {
                    record.state = state::STOPPED.into();
                    record.stopped_reason = stop::HOST.into();
                }
                1 => {
                    record.clone_origin.as_mut().unwrap().stage = templates::CloneStage::Loading;
                }
                _ => {
                    record.boot_incarnation.as_mut().unwrap().start_ticks += 1;
                }
            }
        }
        h.m.save(&entry).unwrap();
        if fault == 1 {
            let mut reader: templates::CloneReader =
                h.m.inner
                    .store
                    .get(templates::READERS, &id)
                    .unwrap()
                    .unwrap();
            reader.stage = templates::CloneStage::Loading;
            h.m.inner
                .store
                .put_durable(templates::READERS, &id, &reader)
                .unwrap();
        }
        restart_load(&h.m).unwrap();
        h.host_calls();
        let recovered = h.m.entry(&id).unwrap();
        h.m.recover().await.unwrap();
        h.m.start_stopped_by_host();
        assert!(h.m.start_entry(&recovered, false).await.is_err());
        no_cleanup_or_cold_launch(&h.host_calls());
        assert!(!recovered.identity_trusted.load(Relaxed));
        assert!(recovered.live.lock().unwrap().is_none());
        assert!(commits_memory(&recovered.snapshot()));
    }
}

#[tokio::test]
async fn assigned_adoption_requires_durable_receipt_and_post_resume_credentials() {
    for missing_receipt in [true, false] {
        let (h, id, _) = staged(0).await;
        let record = h.m.entry(&id).unwrap().snapshot();
        if missing_receipt {
            let receipt =
                h.m.destination_receipt("destination", "assignment-one")
                    .unwrap()
                    .unwrap();
            std::fs::remove_file(
                h.m.inner
                    .store
                    .dir(REQUESTS)
                    .join(format!("{}.json", receipt.key())),
            )
            .unwrap();
        } else {
            h.change_assigned_credentials_on_resume();
        }
        restart_load(&h.m).unwrap();
        h.host_calls();
        let entry = h.m.entry(&id).unwrap();
        assert!(!h.m.recover_assigned_launch(&entry).await);
        assert!(!entry.identity_trusted.load(Relaxed));
        assert!(entry.live.lock().unwrap().is_none());
        let calls = h.host_calls();
        no_cleanup_or_cold_launch(&calls);
        assert!(!calls
            .iter()
            .any(|call| call.starts_with("activate_quarantined ")));
        if missing_receipt {
            assert!(!calls.iter().any(|call| call.starts_with("adopt-state ")));
        } else {
            assert!(calls
                .iter()
                .any(|call| call.starts_with("assigned_resume paused")));
            assert!(!calls.iter().any(|call| call.starts_with("ping ")));
        }
        assert!(h.pool.zfs.exists(&record.root_dataset()).await.unwrap());
        assert_eq!(
            h.m.quota("destination").unwrap().used.memory_mb,
            record.size.memory_mb
        );
    }
}

#[tokio::test]
async fn active_adoption_cannot_publish_a_via_dependency_before_its_own_verification() {
    let (h, id, _) = staged(3).await;
    let original = h.m.entry(&id).unwrap();
    original.rec.lock().unwrap().egress = api::Egress {
        mode: "via".into(),
        via: Some("m_unverified".into()),
        siblings: false,
    };
    h.m.save(&original).unwrap();
    restart_load(&h.m).unwrap();
    let source = h.m.entry(&id).unwrap();
    let mut target = source.snapshot();
    target.id = "m_unverified".into();
    target.name = "unverified".into();
    target.host_num = 3;
    target.ip = "10.64.2.3".into();
    h.m.inner.machines.lock().unwrap().insert(
        target.id.clone(),
        Entry::new(target, h.m.inner.events.clone()),
    );
    h.m.inner.policies.lock().unwrap().clear();
    h.host_calls();
    assert!(!h.m.recover_assigned_launch(&source).await);
    assert!(!source.identity_trusted.load(Relaxed));
    assert!(source.live.lock().unwrap().is_none());
    assert!(!h
        .host_calls()
        .iter()
        .any(|call| call.starts_with("activate_quarantined ")));
    assert!(h.m.namespace_dns_names("destination").is_empty());
}
