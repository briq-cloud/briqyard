use super::*;

fn binding(entry: &Entry) -> templates::sandbox::Binding {
    entry.snapshot().clone_origin.unwrap().sandbox.unwrap()
}
fn digest(request: &api::CreateMachineRequest) -> String {
    templates::sandbox::request_digest(request).unwrap()
}
fn no_activation(calls: &[String]) {
    assert!(!calls.iter().any(|call| [
        "activate_quarantined",
        "clone_activate",
        "exec ",
        "session ",
        "probe_"
    ]
    .iter()
    .any(|prefix| call.starts_with(prefix))));
}

#[tokio::test]
async fn invalid_complete_frame_never_reserves_or_consumes_a_pristine_slot() {
    for invalid in 0..3 {
        let (h, entry, mut request) = fixture().await;
        match invalid {
            0 => request.cmd = None,
            1 => {
                request
                    .env
                    .insert("OVERSIZED".into(), "x".repeat(guest::MAX_FRAME));
            }
            _ => request.files.push(api::File {
                path: "/etc/machine-id".into(),
                base64: guest::base64_encode(b"forbidden"),
                mode: None,
            }),
        }
        assert!(h
            .m
            .stage_destination_assignment(request, &entry, 2)
            .await
            .is_err());
        assert!(h
            .m
            .inner
            .store
            .list::<model::Intent>(INTENTS)
            .unwrap()
            .is_empty());
        assert!(!h
            .m
            .destination_assignment_owns(&entry.snapshot().id)
            .unwrap());
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 0);
        assert!(model::eligible(&entry.snapshot()));
    }
}

#[tokio::test]
async fn private_bind_reuses_owned_process_and_full_config_before_network_main_exec_and_probes() {
    let (h, entry, mut request) = fixture().await;
    request.files.push(api::File {
        path: "/usr/local/share/ca-certificates/destination.crt".into(),
        base64: guest::base64_encode(b"destination CA bytes"),
        mode: Some("644".into()),
    });
    request.probes = Some(api::Probes {
        readiness: Some(api::Probe {
            exec: None,
            tcp: Some(8080),
            http: None,
            period_sec: 1,
            timeout_sec: 1,
            failure_threshold: 1,
            success_threshold: 1,
            initial_delay_sec: 0,
        }),
        ..Default::default()
    });
    let before = entry.snapshot();
    let live = entry.live.lock().unwrap().clone().unwrap();
    let host_use = committed(&h.m.inner.machines.lock().unwrap()).0;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    h.host_calls();
    let created =
        h.m.start_destination_assignment("destination", "assignment-one", &digest(&request))
            .await
            .unwrap();
    assert_eq!(created.state, state::RUNNING);
    assert_eq!(created.id, before.id);
    assert_eq!(entry.snapshot().pid, live.pid);
    assert_eq!(entry.snapshot().boot_incarnation, before.boot_incarnation);
    assert_eq!(entry.snapshot().launch_identity, before.launch_identity);
    assert_eq!(entry.snapshot().root_dataset(), before.root_dataset());
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        host_use.memory_mb
    );
    let saved = binding(&entry);
    let payload = saved.bind.as_ref().unwrap();
    assert_eq!(payload.config.env.get("DESTINATION_ONLY").unwrap(), "value");
    assert_eq!(payload.config.cmd, request.cmd.clone().unwrap());
    assert_eq!(payload.files[0].data, b"destination CA bytes");
    assert_eq!(
        saved.ack_sha256,
        Some(templates::sandbox::binding_hash(payload).unwrap())
    );
    assert!(h
        .m
        .namespace_dns_names("destination")
        .contains_key(&entry.snapshot().hostname()));
    assert!(entry.prober.lock().unwrap().is_some());
    let calls = h.host_calls();
    let position = |prefix: &str| {
        calls
            .iter()
            .position(|call| call.starts_with(prefix))
            .unwrap()
    };
    assert!(position("assigned_resume paused") < position("destination_bind_v1"));
    assert!(position("destination_bind_v1") < position("activate_quarantined"));
    assert!(position("activate_quarantined") < position("clone_activate_v1"));
    assert!(position("clone_activate_v1") < position("exec "));
    assert!(!calls
        .iter()
        .any(|call| call.starts_with("spawn ") || call.starts_with("clone_configure_v1")));
    let replay =
        h.m.start_destination_assignment("destination", "assignment-one", &digest(&request))
            .await
            .unwrap();
    assert_eq!(replay.id, created.id);
    assert!(h
        .m
        .start_destination_assignment("destination", "assignment-one", &"0".repeat(64))
        .await
        .is_err());
    if let Some(task) = entry.prober.lock().unwrap().take() {
        task.abort();
    };
}

#[tokio::test]
async fn lost_resume_or_full_bind_ack_replays_identical_frozen_payload_on_the_same_process() {
    for loss in 0..3 {
        let (h, entry, request) = fixture().await;
        let before = entry.snapshot();
        h.m.stage_destination_assignment(request.clone(), &entry, 2)
            .await
            .unwrap();
        if loss == 0 {
            h.lose_assigned_resume();
        }
        if loss == 1 {
            h.lose_destination_ack();
        }
        if loss == 2 {
            h.refuse_destination(false, true);
        }
        h.host_calls();
        assert!(h
            .m
            .start_destination_assignment("destination", "assignment-one", &digest(&request))
            .await
            .is_err());
        assert_eq!(
            entry.snapshot().clone_origin.unwrap().stage,
            templates::CloneStage::Configuring
        );
        assert!(entry.prober.lock().unwrap().is_none());
        assert!(h.m.namespace_dns_names("destination").is_empty());
        no_activation(&h.host_calls());
        let frozen = binding(&entry).bind.unwrap().fingerprint_bytes().unwrap();
        h.refuse_destination(false, false);
        let made =
            h.m.start_destination_assignment("destination", "assignment-one", &digest(&request))
                .await
                .unwrap();
        assert_eq!(made.id, before.id);
        assert_eq!(entry.snapshot().pid, before.pid);
        assert_eq!(
            binding(&entry).bind.unwrap().fingerprint_bytes().unwrap(),
            frozen
        );
        let calls = h.host_calls();
        assert!(calls
            .iter()
            .any(|call| call.starts_with("assigned_resume running")));
        assert!(!calls
            .iter()
            .any(|call| call.starts_with("assigned_resume paused")));
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
    }
}

#[tokio::test]
async fn uncertain_configuring_reader_write_keeps_stage_journal_and_cannot_resume_before_recovery()
{
    let (h, entry, request) = fixture().await;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    h.m.commit_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .unwrap();
    let source = entry.snapshot();
    let blocked =
        h.m.inner
            .store
            .dir(templates::READERS)
            .join(format!("{}.json.tmp", source.id));
    std::fs::create_dir(&blocked).unwrap();
    h.host_calls();
    assert!(h
        .m
        .start_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .is_err());
    assert!(h
        .m
        .inner
        .store
        .get::<serde_json::Value>("launch-transitions", &source.id)
        .unwrap()
        .is_some());
    assert!(
        !h.host_calls()
            .iter()
            .any(|call| call.starts_with("assigned_resume")
                || call.starts_with("destination_bind_v1"))
    );
    assert!(h.pool.zfs.exists(&source.root_dataset()).await.unwrap());
    std::fs::remove_dir(blocked).unwrap();
    restart_load(&h.m).unwrap();
    let recovered = h.m.entry(&source.id).unwrap();
    assert_eq!(
        recovered.snapshot().clone_origin.unwrap().stage,
        templates::CloneStage::Configuring
    );
    assert!(h
        .m
        .inner
        .store
        .get::<serde_json::Value>("launch-transitions", &source.id)
        .unwrap()
        .is_none());
    h.host_calls();
    assert!(h
        .m
        .start_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .is_err());
    assert!(
        h.host_calls().is_empty(),
        "restart has no fresh original owned handle"
    );
    assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
}

#[tokio::test]
async fn running_vmm_and_configuring_never_authorize_an_already_active_guest() {
    let (h, entry, request) = fixture().await;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    h.lose_destination_ack();
    assert!(h
        .m
        .start_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .is_err());
    let live = entry.live.lock().unwrap().clone().unwrap();
    // Simulate a contradictory active guest without any durable IdentityDone authority.
    let generation = entry.snapshot().clone_origin.unwrap().configure.generation;
    h.m.inner
        .guest
        .destination_control(
            &live.vsock,
            guest::Request {
                op: "clone_activate_v1".into(),
                clone_generation: generation,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    h.host_calls();
    assert!(h
        .m
        .start_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .is_err());
    no_activation(&h.host_calls());
    assert_eq!(
        entry.snapshot().clone_origin.unwrap().stage,
        templates::CloneStage::Configuring
    );
}

#[tokio::test]
async fn exact_process_proof_is_required_before_and_after_assigned_api_operation() {
    for after_api in [false, true] {
        let (h, entry, request) = fixture().await;
        h.m.stage_destination_assignment(request.clone(), &entry, 2)
            .await
            .unwrap();
        if after_api {
            h.change_assigned_credentials_on_resume();
        } else {
            entry.identity_trusted.store(false, Relaxed);
        }
        h.host_calls();
        assert!(h
            .m
            .start_destination_assignment("destination", "assignment-one", &digest(&request))
            .await
            .is_err());
        let calls = h.host_calls();
        assert_eq!(
            calls.iter().any(|call| call.starts_with("assigned_resume")),
            after_api
        );
        assert!(!calls
            .iter()
            .any(|call| call.starts_with("destination_bind_v1")));
        no_activation(&calls);
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
        assert!(h
            .pool
            .zfs
            .exists(&entry.snapshot().root_dataset())
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn first_exec_failure_cannot_publish_dns_or_probes_and_active_checkpoint_finishes_without_reexec(
) {
    let (h, entry, request) = fixture().await;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    h.assigned_first_exec_code(7);
    assert!(h
        .m
        .start_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .is_err());
    assert_eq!(
        entry.snapshot().clone_origin.unwrap().stage,
        templates::CloneStage::IdentityDone
    );
    assert!(h.m.namespace_dns_names("destination").is_empty());
    assert!(entry.prober.lock().unwrap().is_none());
    let frozen = binding(&entry).bind.unwrap().fingerprint_bytes().unwrap();
    h.assigned_first_exec_code(0);
    h.m.start_destination_assignment("destination", "assignment-one", &digest(&request))
        .await
        .unwrap();
    assert_eq!(
        binding(&entry).bind.unwrap().fingerprint_bytes().unwrap(),
        frozen
    );
    // Active is durable before RUNNING/probes. Finish this interrupted boundary without
    // another bind, network activation, main activation or first exec.
    entry.rec.lock().unwrap().state = state::STARTING.into();
    h.m.save(&entry).unwrap();
    h.host_calls();
    let made =
        h.m.start_destination_assignment("destination", "assignment-one", &digest(&request))
            .await
            .unwrap();
    assert_eq!(made.state, state::RUNNING);
    no_activation(&h.host_calls());
}
