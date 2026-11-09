//! Offline record/reader proof tests; these do not qualify a live unbound VMM.
use super::*;

pub(in crate::machine) async fn reserved() -> (Harness, Arc<Entry>) {
    reserved_with(Some(2)).await
}
/// A reserved unbound slot whose sealed topology has this `/work` volume (none: two drives).
pub(in crate::machine) async fn reserved_with(volume: Option<u32>) -> (Harness, Arc<Entry>) {
    eprintln!("stopped-fixture stage=reserved-enter");
    let (h, source, snapshot, _) = source().await;
    eprintln!("stopped-fixture stage=source-ready");
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
        consistency: None,
        machine_id: source.snapshot().id.clone(),
        snapshot: Some(snapshot),
        copy: String::new(),
    };
    h.m.named_clone_spec(&request, &mut record, &source.snapshot(), &fork)
        .unwrap();
    record.clone_origin.as_mut().unwrap().artifact.profile = guest::SANDBOX_READY_V1.into();
    record.clone_origin.as_mut().unwrap().artifact.recipe.config =
        crate::machine::templates::sandbox::builder_config(volume.map(guest::SandboxDevice::of_gb));
    record.volume = volume.map(|size_gb| api::VolumeSpec {
        size_gb,
        mount: "/work".into(),
    });
    record.state = state::CREATING.into();
    record.env.clear();
    record.files.clear();
    record.ports.clear();
    record.entrypoint = None;
    record.cmd = None;

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

pub(in crate::machine) async fn prepared_with(volume: Option<u32>) -> (Harness, Arc<Entry>) {
    eprintln!("stopped-fixture stage=prepared-enter");
    let (h, entry) = reserved_with(volume).await;
    eprintln!("stopped-fixture stage=reserved-ready");
    h.m.inner
        .machines
        .lock()
        .unwrap()
        .insert(entry.snapshot().id, entry.clone());
    h.disks(&entry).await;
    eprintln!("stopped-fixture stage=disks-ready");
    {
        let _turn = entry.lock.lock().await;
        h.m.start_entry(&entry, true).await.unwrap();
    }
    (h, entry)
}

#[tokio::test]
async fn internal_unbound_preparation_stays_at_builder_without_bind_network_or_activation() {
    let (h, entry) = reserved().await;
    let id = entry.snapshot().id;
    h.m.inner
        .machines
        .lock()
        .unwrap()
        .insert(id.clone(), entry.clone());
    h.disks(&entry).await;
    let _turn = entry.lock.lock().await;
    h.host_calls();
    h.m.start_entry(&entry, true).await.unwrap();
    let saved = entry.snapshot();
    assert_eq!(
        saved.clone_origin.as_ref().unwrap().stage,
        CloneStage::UnboundPaused
    );
    assert!(saved.clone_origin.as_ref().unwrap().identity.is_none());
    assert!(saved.clone_origin.as_ref().unwrap().sandbox.is_none());
    assert!(
        !crate::machine::warm::ready_slot(&saved),
        "public configured-slot recovery stays unreachable"
    );
    assert!(!h
        .m
        .warm_pool_profiles()
        .iter()
        .any(|profile| profile == guest::SANDBOX_READY_V1));
    let live = entry.live.lock().unwrap().clone().unwrap();
    h.m.verify_live_launch(&entry, &live).unwrap();
    assert!(h.m.activate_memory_clone(&entry, &live).await.is_err());
    assert!(h.m.configure_memory_clone(&entry, &live).await.is_err());
    let calls = h.host_calls();
    assert!(calls.iter().any(|call| call == &format!("quarantine {id}")));
    assert!(!calls.iter().any(|call| [
        "clone_configure_v1",
        "destination_bind_v1",
        "clone_activate_v1",
        "activate_quarantined",
        "exec ",
        "session "
    ]
    .iter()
    .any(|prefix| call.starts_with(prefix))));
    // Stand-in VMM/guest only: no native disk geometry or isolation qualification.
    let pong = h.m.inner.guest.ping(&live.vsock).await.unwrap();
    assert_eq!(pong.main_pid, 0);
    assert_eq!(pong.clone_status.unwrap().stage, "builder");
    assert!(h
        .m
        .inner
        .store
        .list::<serde_json::Value>("launch-transitions")
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn saved_fields_alone_cannot_authorize_unbound_activation() {
    let (h, entry) = reserved().await;
    let mut record = entry.snapshot();
    let (exited, exit_receiver) = tokio::sync::watch::channel(false);
    let (_, report) = tokio::sync::watch::channel(None);
    record.pid = 1234;
    record.boot_incarnation = Some(fc::Incarnation {
        pid: 1234,
        start_ticks: 77,
        host_boot_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
    });
    record.clone_origin.as_mut().unwrap().stage = CloneStage::Loading;
    record.clone_origin.as_mut().unwrap().launch_host_boot_id =
        Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into());
    let mut reader: CloneReader = h.m.inner.store.get(READERS, &record.id).unwrap().unwrap();
    reader.stage = CloneStage::Loading;
    h.m.inner
        .store
        .put_durable(READERS, &record.id, &reader)
        .unwrap();
    *entry.rec.lock().unwrap() = record.clone();
    h.m.validate_launch_record(&record).unwrap();
    let live = fc::Vm {
        #[cfg(target_os = "linux")]
        identity: None,
        pid: record.pid,
        api: PathBuf::new(),
        vsock: PathBuf::new(),
        dir: PathBuf::new(),
        chroot: None,
        resumed: true,
        boot_identity: record.boot_identity.clone(),
        incarnation: record.boot_incarnation.clone(),
        exited: exit_receiver,
        exit: report,
        vmm_oom: Default::default(),
    };
    assert!(h.m.verify_live_launch(&entry, &live).is_err());
    assert!(h.m.activate_memory_clone(&entry, &live).await.is_err());
    drop(exited);
}
