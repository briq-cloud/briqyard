//! Offline record/reader proof tests; these do not qualify a live unbound VMM.
use super::*;

async fn reserved() -> (Harness, Arc<Entry>) {
    let (h, source, snapshot, _) = source().await;
    h.namespace("t1");
    let mut record = crate::machine::tests::record();
    record.id = "m_unbound".into();
    record.name = "unbound".into();
    record.host_num = 3;
    record.ip = "10.64.1.3".into();
    record.pid = 0;
    record.boot_incarnation = None;
    let request = api::CreateMachineRequest {
        namespace: "t1".into(),
        name: "unbound".into(),
        ..Default::default()
    };
    let fork = api::ForkSpec {
        machine_id: source.snapshot().id.clone(),
        snapshot: Some(snapshot),
        copy: String::new(),
    };
    h.m.named_clone_spec(&request, &mut record, &source.snapshot(), &fork)
        .unwrap();
    record.clone_origin.as_mut().unwrap().artifact.profile = guest::SANDBOX_READY_V1.into();
    record.warm_slot = Some(crate::machine::warm::Slot {
        pool: "unbound-test".into(),
        fingerprint: "test".into(),
        claimed: None,
    });
    let origin = record.clone_origin.as_ref().unwrap();
    h.m.inner
        .store
        .put_durable(
            READERS,
            &record.id,
            &CloneReader {
                source_machine: origin.source_machine.clone(),
                snapshot: origin.snapshot.clone(),
                generation: origin.artifact.generation.clone(),
                destination: record.id.clone(),
                namespace: record.namespace.clone(),
                stage: CloneStage::Reserved,
            },
        )
        .unwrap();
    let entry = Entry::new(record, h.m.inner.events.clone());
    h.m.pin_launch_identity(&entry).unwrap();
    (h, entry)
}

#[tokio::test]
async fn immutable_template_provenance_rejects_origin_artifact_and_reader_changes() {
    let (h, entry) = reserved().await;
    let saved = entry.snapshot();
    h.m.validate_launch_record(&saved).unwrap();
    for field in 0..3 {
        let mut changed = saved.clone();
        let origin = changed.clone_origin.as_mut().unwrap();
        match field {
            0 => origin.source_machine = "m_other".into(),
            1 => origin.snapshot = "s_other".into(),
            _ => origin.artifact.init_sha256 = "b".repeat(64),
        }
        assert!(h.m.validate_launch_record(&changed).is_err());
    }
    let mut reader: CloneReader = h.m.inner.store.get(READERS, &saved.id).unwrap().unwrap();
    reader.namespace = "other".into();
    h.m.inner
        .store
        .put_durable(READERS, &saved.id, &reader)
        .unwrap();
    assert!(h.m.validate_launch_record(&saved).is_err());
    h.m.inner.store.delete_durable(READERS, &saved.id).unwrap();
    assert!(h.m.validate_launch_record(&saved).is_err());
}

#[tokio::test]
async fn launch_proof_requires_exact_boot_incarnation_and_reader_stage() {
    let (h, entry) = reserved().await;
    let mut saved = entry.snapshot();
    let boot = "a".repeat(32);
    // Valid boot IDs use their canonical UUID form.
    let boot = format!(
        "{}-{}-{}-{}-{}",
        &boot[..8],
        &boot[8..12],
        &boot[12..16],
        &boot[16..20],
        &boot[20..]
    );
    saved.pid = 1234;
    saved.boot_incarnation = Some(fc::Incarnation {
        pid: 1234,
        start_ticks: 77,
        host_boot_id: boot.clone(),
    });
    let origin = saved.clone_origin.as_mut().unwrap();
    origin.stage = CloneStage::Loading;
    origin.launch_host_boot_id = Some(boot);
    let mut reader: CloneReader = h.m.inner.store.get(READERS, &saved.id).unwrap().unwrap();
    assert!(h.m.validate_launch_record(&saved).is_err());
    reader.stage = CloneStage::Loading;
    h.m.inner
        .store
        .put_durable(READERS, &saved.id, &reader)
        .unwrap();
    h.m.validate_launch_record(&saved).unwrap();
    for field in 0..4 {
        let mut changed = saved.clone();
        match field {
            0 => changed.boot_incarnation = None,
            1 => changed.boot_incarnation.as_mut().unwrap().pid += 1,
            2 => changed.boot_identity = None,
            _ => changed.clone_origin.as_mut().unwrap().launch_host_boot_id = Some("other".into()),
        }
        assert!(h.m.validate_launch_record(&changed).is_err());
    }
}

#[tokio::test]
async fn settled_paused_exit_can_finish_cleanup_but_unknown_exit_cannot() {
    let (h, entry) = reserved().await;
    let mut saved = entry.snapshot();
    saved.state = state::ERROR.into();
    saved.clone_origin.as_mut().unwrap().stage = CloneStage::Paused;
    let mut reader: CloneReader = h.m.inner.store.get(READERS, &saved.id).unwrap().unwrap();
    reader.stage = CloneStage::Paused;
    h.m.inner
        .store
        .put_durable(READERS, &saved.id, &reader)
        .unwrap();
    assert!(h.m.validate_launch_record(&saved).is_err());
    saved.clone_origin.as_mut().unwrap().mapping_exited = true;
    h.m.validate_launch_record(&saved).unwrap();
    h.m.inner.store.delete_durable(READERS, &saved.id).unwrap();
    assert!(h.m.validate_launch_record(&saved).is_err());
    saved.state = state::DESTROYING.into();
    h.m.validate_launch_record(&saved).unwrap();
}
