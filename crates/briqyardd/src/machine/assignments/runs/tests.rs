//! Private continuation tests use synthetic records, processes and backing; no native qualification.
use super::*;
mod legacy545;
mod recovery;
mod terminal;

#[test]
fn run_reference_is_explicit_and_rejects_unknown_fields() {
    let reference = RunRef {
        schema: 1,
        sequence: 1,
        phase: Phase::Reserved,
    };
    let mut value = serde_json::to_value(reference).unwrap();
    assert_eq!(value["phase"], "reserved");
    value["unknown"] = true.into();
    assert!(serde_json::from_value::<RunRef>(value).is_err());
}

async fn stopped(checkpoint: bool) -> (crate::machine::tests::Harness, Arc<Entry>) {
    let (h, entry, request) = super::super::tests::fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    h.m.start_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    entry.rec.lock().unwrap().vmm_version = h.m.inner.vmm.version();
    h.m.save(&entry).unwrap();
    h.m.stop(
        &entry.snapshot().id,
        Duration::from_secs(1),
        checkpoint,
        None,
    )
    .await
    .unwrap();
    assert_eq!(entry.snapshot().state, state::STOPPED);
    assert!(
        entry
            .snapshot()
            .clone_origin
            .as_ref()
            .unwrap()
            .mapping_exited
    );
    (h, entry)
}
fn restart(h: &crate::machine::tests::Harness) -> Result<()> {
    h.m.inner.machines.lock().unwrap().clear();
    h.m.inner.namespaces.lock().unwrap().clear();
    h.m.inner.launch_holds.lock().unwrap().clear();
    *h.m.inner.assignments.lock().unwrap() = State::default();
    h.m.load()
}

#[tokio::test]
async fn run_reservation_freezes_exact_current_bundle_and_reserves_once_without_launch() {
    let (h, entry) = stopped(false).await;
    let before = entry.snapshot();
    let creation =
        h.m.inner
            .store
            .get::<serde_json::Value>(templates::READERS, &before.id)
            .unwrap();
    h.host_calls();
    let reference = h.m.reserve_assigned_run(&entry, false).await.unwrap();
    assert_eq!(reference.phase, Phase::Reserved);
    assert!(entry.live.lock().unwrap().is_none());
    assert!(!entry.identity_trusted.load(Relaxed));
    assert_eq!(
        h.m.quota("destination").unwrap().used.memory_mb,
        before.size.memory_mb
    );
    let current: Current = h.m.inner.store.get(RUNS, &before.id).unwrap().unwrap();
    current.check().unwrap();
    let Mode::Fresh {
        guest_generation,
        drive_base64,
        expected_bundle_sha256,
        ..
    } = &current.mode
    else {
        panic!("fresh expected")
    };
    let (config, files) = model::parse_drive(&guest::base64_decode(drive_base64).unwrap()).unwrap();
    assert_eq!(
        config.assigned_run_generation.as_ref(),
        Some(guest_generation)
    );
    assert_eq!(config.env.get("DESTINATION_ONLY").unwrap(), "value");
    assert_ne!(guest_generation, &current.host_generation);
    assert_eq!(
        sha(&guest::boot_bundle_fingerprint_bytes(&config, &files).unwrap()),
        *expected_bundle_sha256
    );
    assert!(
        current.observed_guest.is_none(),
        "expected config is not observed guest evidence"
    );
    assert_eq!(
        h.m.inner
            .store
            .get::<serde_json::Value>(templates::READERS, &before.id)
            .unwrap(),
        creation
    );
    assert!(h.m.reserve_assigned_run(&entry, false).await.is_err());
    assert_eq!(entry.snapshot().assigned_run.as_ref(), Some(&reference));
    assert!(
        h.host_calls().is_empty(),
        "journal reservation performs no VMM/guest/network work"
    );
    assert!(h.m.inner.store.list::<Intent>(INTENTS).unwrap().is_empty());
    assert!(!h.m.assignment_publication_allowed(&entry.snapshot(), true));
    h.m.verify_assigned_run_backing().await.unwrap();
    restart(&h).unwrap();
    assert_eq!(
        h.m.quota("destination").unwrap().used.memory_mb,
        before.size.memory_mb
    );
}

#[tokio::test]
async fn run_intent_current_machine_reader_interruption_boundaries_recover_exactly() {
    for boundary in 0..4 {
        let (h, entry) = stopped(false).await;
        let intent = h.m.plan_assigned_run(&entry, false).await.unwrap();
        let id = &intent.current.machine;
        h.m.inner.store.put_durable(INTENTS, id, &intent).unwrap();
        if boundary >= 1 {
            h.m.inner
                .store
                .put_durable(RUNS, id, &intent.current)
                .unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable("machines", id, &intent.current.target)
                .unwrap();
        }
        if boundary >= 3 {
            h.m.inner
                .store
                .put_durable(READERS, id, &intent.reader)
                .unwrap();
        }
        h.host_calls();
        restart(&h).unwrap();
        let current: Current = h.m.inner.store.get(RUNS, id).unwrap().unwrap();
        assert_eq!(current.host_generation, intent.current.host_generation);
        assert_eq!(current.reference, intent.current.reference);
        assert!(h.m.inner.store.list::<Intent>(INTENTS).unwrap().is_empty());
        assert_eq!(
            h.m.entry(id).unwrap().snapshot().launch_identity,
            intent.current.prior.launch_identity
        );
        assert!(h.host_calls().is_empty());
        h.m.verify_assigned_run_backing().await.unwrap();
    }
}

#[tokio::test]
async fn run_reader_first_missing_authority_and_control_mismatches_retain_backing() {
    for fault in 0..4 {
        let (h, entry) = stopped(false).await;
        let intent = h.m.plan_assigned_run(&entry, false).await.unwrap();
        let id = &intent.current.machine;
        h.m.inner.store.put_durable(INTENTS, id, &intent).unwrap();
        match fault {
            0 => {
                h.m.inner
                    .store
                    .put_durable(READERS, id, &intent.reader)
                    .unwrap()
            }
            1 => h.m.inner.store.delete_durable("machines", id).unwrap(),
            2 => {
                let mut changed = intent.current.prior.clone();
                changed.env.insert("changed".into(), "control".into());
                h.m.inner
                    .store
                    .put_durable("machines", id, &changed)
                    .unwrap();
            }
            _ => std::fs::remove_file(
                h.m.inner
                    .store
                    .dir(super::super::REQUESTS)
                    .join(format!("{}.json", intent.current.receipt.key())),
            )
            .unwrap(),
        }
        h.host_calls();
        assert!(restart(&h).is_err());
        assert!(h
            .m
            .inner
            .store
            .get::<Intent>(INTENTS, id)
            .unwrap()
            .is_some());
        assert!(h
            .pool
            .zfs
            .exists(&intent.current.prior.root_dataset())
            .await
            .unwrap());
        assert!(h.host_calls().is_empty());
    }
}

#[tokio::test]
async fn uncertain_first_run_write_keeps_reservation_and_forbids_replanning() {
    let (h, entry) = stopped(false).await;
    let memory = entry.snapshot().size.memory_mb;
    let directory = h.m.inner.store.dir(INTENTS);
    std::fs::remove_dir(&directory).unwrap();
    assert!(h.m.reserve_assigned_run(&entry, false).await.is_err());
    assert!(entry.snapshot().assigned_run.is_some());
    assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, memory);
    std::fs::create_dir(directory).unwrap();
    assert!(h.m.reserve_assigned_run(&entry, false).await.is_err());
    assert!(entry.live.lock().unwrap().is_none());
}

#[tokio::test]
async fn current_dataset_guid_and_current_checkpoint_lineage_are_not_pristine_template_ram() {
    let (h, entry) = stopped(true).await;
    let prior = entry.snapshot();
    let intent = h.m.plan_assigned_run(&entry, true).await.unwrap();
    let Mode::Checkpoint {
        saved_generation,
        saved_marker,
        state,
        ..
    } = &intent.current.mode
    else {
        panic!("checkpoint expected")
    };
    let origin = prior.clone_origin.as_ref().unwrap();
    assert_eq!(saved_generation, &origin.configure.generation);
    assert_eq!(saved_marker, &origin.artifact.ram_marker);
    assert_ne!(saved_generation, &intent.current.host_generation);
    assert_ne!(
        state.inode, origin.artifact.state.inode,
        "current checkpoint must not be pristine artifact"
    );
    h.m.reserve_assigned_run(&entry, true).await.unwrap();
    h.m.verify_assigned_run_backing().await.unwrap();
    let root = prior.root_dataset();
    h.pool.zfs.destroy(&root).await.unwrap();
    h.pool.zfs.create(&root, 1 << 20).await.unwrap();
    assert!(h.m.verify_assigned_run_backing().await.is_err());
    assert!(entry.snapshot().assigned_run.is_some());
}

#[tokio::test]
async fn unknown_exit_pending_update_and_invalid_bundle_never_gain_run_authority() {
    let (h, entry, request) = super::super::tests::fixture().await;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    h.m.start_destination_assignment(
        "destination",
        "assignment-one",
        &templates::sandbox::request_digest(&request).unwrap(),
    )
    .await
    .unwrap();
    assert!(h.m.plan_assigned_run(&entry, false).await.is_err());
    assert!(h.m.launch_assigned_run(&entry, false).await.is_err());
    let (h, entry) = stopped(false).await;
    entry.rec.lock().unwrap().pending = Some(api::SpecChange {
        cmd: Some(vec!["pending".into()]),
        ..Default::default()
    });
    assert!(h.m.plan_assigned_run(&entry, false).await.is_err());
    assert!(entry.snapshot().pending.is_some());
    entry.rec.lock().unwrap().pending = None;
    let mut intent = h.m.plan_assigned_run(&entry, false).await.unwrap();
    if let Mode::Fresh { drive_base64, .. } = &mut intent.current.mode {
        drive_base64.push('x');
    }
    assert!(intent.current.check().is_err());
    assert!(h.m.inner.store.list::<Intent>(INTENTS).unwrap().is_empty());
}

#[tokio::test]
async fn private_fresh_and_current_checkpoint_observe_exact_process_without_publication() {
    for checkpoint in [false, true] {
        let (h, entry) = stopped(checkpoint).await;
        let old = entry.snapshot();
        h.host_calls();
        let reference = h.m.launch_assigned_run(&entry, checkpoint).await.unwrap();
        assert_eq!(reference.phase, Phase::Observed);
        let current: Current = h.m.inner.store.get(RUNS, &old.id).unwrap().unwrap();
        current.check().unwrap();
        let live = entry.live.lock().unwrap().clone().unwrap();
        h.m.verify_run_process(&current, &live).unwrap();
        assert_ne!(live.incarnation, old.boot_incarnation);
        assert_eq!(entry.snapshot().launch_identity, old.launch_identity);
        assert_eq!(
            serde_json::to_value(entry.snapshot().clone_origin).unwrap(),
            serde_json::to_value(old.clone_origin).unwrap()
        );
        assert_eq!(entry.snapshot().state, state::STARTING);
        assert!(!entry.identity_trusted.load(Relaxed));
        assert!(h.m.verified_run_publication(&entry.snapshot()).is_ok());
        assert!(!h.m.assignment_publication_allowed(
            &entry.snapshot(),
            entry.identity_trusted.load(Relaxed)
        ));
        assert!(h.m.ordinary_operation(&entry.snapshot()).is_err());
        assert!(h.m.namespace_dns_names("destination").is_empty());
        assert_eq!(current.observed_guest.is_some(), !checkpoint);
        assert_eq!(current.observed_checkpoint.is_some(), checkpoint);
        assert!(h.m.launch_assigned_run(&entry, checkpoint).await.is_err());
        let calls = h.host_calls();
        assert_eq!(calls.iter().filter(|c| c.starts_with("boot ")).count(), 1);
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("activate_quarantined ") || c.starts_with("exec ")));
        assert!(
            calls
                .iter()
                .position(|c| c.starts_with("quarantine "))
                .unwrap()
                < calls.iter().position(|c| c.starts_with("boot ")).unwrap()
        );
    }
}

#[tokio::test]
async fn run_wrong_digest_marker_init_process_lost_response_and_launch_retain_without_retry() {
    for (checkpoint, fault) in [
        (false, 1),
        (false, 2),
        (false, 3),
        (false, 4),
        (false, 5),
        (false, 6),
        (true, 6),
        (true, 7),
    ] {
        let (h, entry) = stopped(checkpoint).await;
        let before = entry.snapshot();
        h.assigned_run_fault(fault);
        h.host_calls();
        assert!(h.m.launch_assigned_run(&entry, checkpoint).await.is_err());
        let current: Current = h.m.inner.store.get(RUNS, &before.id).unwrap().unwrap();
        assert!(current.launch_started);
        assert_eq!(current.reference.phase, Phase::Reserved);
        assert!(current.observed_guest.is_none() && current.observed_checkpoint.is_none());
        assert!(!entry.identity_trusted.load(Relaxed));
        h.assigned_run_fault(0);
        assert!(h.m.launch_assigned_run(&entry, checkpoint).await.is_err());
        assert_eq!(
            h.host_calls()
                .iter()
                .filter(|c| c.starts_with("boot "))
                .count(),
            1
        );
        assert!(h.pool.zfs.exists(&before.root_dataset()).await.unwrap());
        assert_eq!(
            h.m.quota("destination").unwrap().used.memory_mb,
            before.size.memory_mb
        );
    }
}

#[tokio::test]
async fn interrupted_observation_intent_repairs_exact_generation_without_launching_again() {
    for boundary in 0..4 {
        let (h, entry) = stopped(false).await;
        h.m.launch_assigned_run(&entry, false).await.unwrap();
        let observed: Current =
            h.m.inner
                .store
                .get(RUNS, &entry.snapshot().id)
                .unwrap()
                .unwrap();
        let mut attempted = observed.clone();
        attempted.reference.phase = Phase::Reserved;
        attempted.target = attempted.prior.clone();
        attempted.target.assigned_run = Some(attempted.reference.clone());
        attempted.target.state = state::STARTING.into();
        attempted.target.suspended = false;
        attempted.observed_guest = None;
        attempted.observed_main_pid = 0;
        attempted.check().unwrap();
        let intent = Intent {
            schema: observed.schema,
            reader: observed.reader().unwrap(),
            current: observed.clone(),
            predecessor: Some(attempted.clone()),
        };
        intent.check().unwrap();
        let id = &observed.machine;
        h.m.inner.store.put_durable(RUNS, id, &attempted).unwrap();
        h.m.inner
            .store
            .put_durable("machines", id, &attempted.target)
            .unwrap();
        h.m.inner
            .store
            .put_durable(READERS, id, &attempted.reader().unwrap())
            .unwrap();
        h.m.inner.store.put_durable(INTENTS, id, &intent).unwrap();
        if boundary >= 1 {
            h.m.inner.store.put_durable(RUNS, id, &observed).unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable("machines", id, &observed.target)
                .unwrap();
        }
        if boundary >= 3 {
            h.m.inner
                .store
                .put_durable(READERS, id, &intent.reader)
                .unwrap();
        }
        h.host_calls();
        restart(&h).unwrap();
        let repaired: Current = h.m.inner.store.get(RUNS, id).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(repaired).unwrap(),
            serde_json::to_value(&observed).unwrap()
        );
        assert!(h.m.inner.store.list::<Intent>(INTENTS).unwrap().is_empty());
        let recovered = h.m.entry(id).unwrap();
        assert!(!recovered.identity_trusted.load(Relaxed));
        assert!(h.m.launch_assigned_run(&recovered, false).await.is_err());
        assert!(h.host_calls().is_empty());
    }
}

#[tokio::test]
async fn assigned_early_pong_waits_for_main_and_rejects_marker_change() {
    for fault in [8, 9] {
        let (h, entry) = stopped(false).await;
        h.assigned_run_fault(fault);
        h.host_calls();
        assert_eq!(
            h.m.launch_assigned_run(&entry, false).await.is_ok(),
            fault == 8
        );
        let calls = h.host_calls();
        assert_eq!(calls.iter().filter(|c| c.starts_with("boot ")).count(), 1);
        assert_eq!(calls.iter().filter(|c| c.starts_with("ping ")).count(), 2);
        assert!(!entry.identity_trusted.load(Relaxed));
    }
}
