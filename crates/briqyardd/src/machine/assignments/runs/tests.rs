//! Private journal tests use synthetic records/backing; no continuation launcher exists.
use super::*;

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
