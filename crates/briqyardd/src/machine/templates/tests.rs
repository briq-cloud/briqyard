use super::*;
use crate::machine::tests::{harness, Harness};

async fn source() -> (Harness, Arc<Entry>, String, CloneArtifact) {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_template", state::CREATED, 256);
    h.disks(&e).await;
    let snapshot =
        h.m.snapshot("m_template", api::SnapshotRequest::default())
            .await
            .unwrap();
    let files =
        h.m.artifact_files("m_template", &snapshot.id, "g_one")
            .unwrap();
    std::fs::create_dir_all(files[0].parent().unwrap()).unwrap();
    for (path, bytes) in files
        .iter()
        .zip([b"state".as_slice(), b"memory marker".as_slice()])
    {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let r = e.snapshot();
    let a = CloneArtifact {
        schema: 1,
        generation: "g_one".into(),
        profile: guest::INIT_READY_V1.into(),
        ram_marker: "0123456789abcdef0123456789abcdef".into(),
        namespace: r.namespace.clone(),
        source_host: "h_test".into(),
        init_sha256: h.m.inner.images.init_sha256().into(),
        init_protocol: 1,
        cpu_fingerprint: "test_cpu".into(),
        boot_identity: h.m.inner.vmm.boot_identity(false).unwrap(),
        recipe: CloneRecipe {
            image: r.image.clone(),
            image_digest: r.image_digest.clone(),
            image_key: r.image_key.clone(),
            size: r.size,
            root_disk_gb: h.m.inner.cfg.root_disk_gb,
            config: guest::Config {
                template_profile: Some(guest::INIT_READY_V1.into()),
                ..Default::default()
            },
        },
        state: fingerprint(&files[0]).unwrap(),
        memory: fingerprint(&files[1]).unwrap(),
    };
    {
        let mut r = e.rec.lock().unwrap();
        let s = r
            .snapshots
            .iter_mut()
            .find(|s| s.id == snapshot.id)
            .unwrap();
        s.memory = Some("memory-spec".into());
        s.clone_artifact = Some(a.clone());
    }
    h.m.inner
        .store
        .put_durable("machines", &r.id, &e.snapshot())
        .unwrap();
    (h, e, snapshot.id, a)
}

#[tokio::test]
async fn exact_shared_inode_and_durable_reader_fence_deletion_until_confirmed_exit() {
    let (h, e, snapshot, a) = source().await;
    let namespace = e.snapshot().namespace;
    assert!(h
        .m
        .reserve_named_clone("m_template", &snapshot, "m_clone", &namespace)
        .await
        .is_err());
    h.m.verify_clone_artifacts();
    let (_, files) =
        h.m.reserve_named_clone("m_template", &snapshot, "m_clone", &namespace)
            .await
            .unwrap();
    // Staging is a hard link to the exact immutable inode; no owner/mode mutation or copy.
    let backing = h.m.inner.cfg.run_dir().join("m_clone");
    std::fs::create_dir_all(&backing).unwrap();
    std::fs::hard_link(&files[1], backing.join("mem")).unwrap();
    assert_eq!(
        std::fs::metadata(backing.join("mem")).unwrap().ino(),
        a.memory.inode
    );
    let durable: CloneReader = h.m.inner.store.get(READERS, "m_clone").unwrap().unwrap();
    assert_eq!(durable.generation, "g_one");
    assert_eq!(durable.stage, CloneStage::Reserved);
    // Same destination retry does not create another read reference.
    h.m.reserve_named_clone("m_template", &snapshot, "m_clone", &namespace)
        .await
        .unwrap();
    assert_eq!(h.m.clone_readers().unwrap().len(), 1);
    assert!(matches!(
        h.m.delete_snapshot("m_template", &snapshot).await,
        Err(MError::Conflict(_))
    ));
    assert!(matches!(
        h.m.destroy("m_template", None).await,
        Err(MError::Conflict(_))
    ));
    assert!(matches!(
        h.m.restore_snapshot("m_template", &snapshot, None).await,
        Err(MError::Conflict(_))
    ));
    let (tx, exited) = tokio::sync::watch::channel(false);
    assert!(h.m.release_clone_reader("m_clone", &exited).is_err());
    drop(tx); // Closed channel is still not exit evidence.
    assert!(h.m.release_clone_reader("m_clone", &exited).is_err());
    let (_, exited) = tokio::sync::watch::channel(true);
    std::fs::remove_dir_all(backing).unwrap();
    h.m.release_clone_reader("m_clone", &exited).unwrap();
    h.m.delete_snapshot("m_template", &snapshot).await.unwrap();
}

#[tokio::test]
async fn changed_inode_and_foreign_namespace_are_refused_without_new_reference() {
    let (h, e, snapshot, _) = source().await;
    h.m.verify_clone_artifacts();
    assert!(h
        .m
        .reserve_named_clone("m_template", &snapshot, "m_foreign", "foreign")
        .await
        .is_err());
    let files =
        h.m.artifact_files("m_template", &snapshot, "g_one")
            .unwrap();
    let replacement = files[1].with_extension("new");
    std::fs::write(&replacement, b"memory marker").unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::rename(replacement, &files[1]).unwrap();
    assert!(h
        .m
        .reserve_named_clone("m_template", &snapshot, "m_clone", &e.snapshot().namespace)
        .await
        .is_err());
    assert!(h.m.clone_readers().unwrap().is_empty());
}

#[tokio::test]
async fn recovery_retains_recordless_destinations_and_corrupt_references_block_cleanup() {
    let (h, e, snapshot, _) = source().await;
    h.m.verify_clone_artifacts();
    h.m.reserve_named_clone(
        "m_template",
        &snapshot,
        "m_missing",
        &e.snapshot().namespace,
    )
    .await
    .unwrap();
    let run = h.m.inner.cfg.run_dir().join("m_missing");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("backing"), b"retain").unwrap();
    h.m.sweep_orphans().await;
    assert!(run.join("backing").exists());
    std::fs::write(
        h.m.inner.store.dir(READERS).join("m_bad.json"),
        b"incomplete",
    )
    .unwrap();
    assert!(h.m.check_clone_readers("m_other", None).is_err());
    assert_eq!(h.m.sweep_orphans().await, 0);
}

async fn reviewed_builder() -> (Harness, api::Machine) {
    use crate::machine::tests::harness_config;
    use sha2::Digest;
    let h = harness_config(|cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.capacity.memory_mb = 4096;
        cfg.jailer = "/mock/jailer".into();
        cfg.templates.init_ready_init_sha256 = hex::encode(sha2::Sha256::digest(b"init"));
    })
    .await;
    h.namespace("t1");
    let mut config = ImageConfig::default();
    config.cmd = vec!["/bin/sh".into()];
    config.workdir = "/".into();
    config.env = builder_config().env;
    h.m.inner.images.seed(ALPINE, config).await.unwrap();
    let mut req = h.request("template");
    req.image = ALPINE.into();
    req.sleep = "never".into();
    req.template_build = Some(guest::INIT_READY_V1.into());
    let machine = h.m.create_made(req).await.unwrap();
    (h, machine)
}

#[tokio::test]
async fn reviewed_builder_seals_and_named_clone_crosses_identity_before_network_and_work() {
    let (h, builder) = reviewed_builder().await;
    assert_eq!(builder.state, state::RUNNING);
    assert!(!builder.ready);
    assert!(h
        .m
        .exec(
            &builder.id,
            api::ExecRequest {
                cmd: vec!["/bin/true".into()],
                ..Default::default()
            }
        )
        .await
        .is_err());
    assert!(h
        .m
        .update(&builder.id, api::UpdateMachineRequest::default(), None)
        .await
        .is_err());
    assert!(h.m.start(&builder.id, None).await.is_err());
    assert!(h
        .m
        .snapshot(
            &builder.id,
            api::SnapshotRequest {
                memory: true,
                ..Default::default()
            }
        )
        .await
        .is_err());
    let snapshot =
        h.m.snapshot(
            &builder.id,
            api::SnapshotRequest {
                name: Some("ready".into()),
                memory: true,
                template: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        snapshot.clone_profile.as_deref(),
        Some(guest::INIT_READY_V1)
    );
    let mut req = api::CreateMachineRequest {
        namespace: "t1".into(),
        name: "clone".into(),
        fork: Some(api::ForkSpec {
            machine_id: builder.id.clone(),
            copy: String::new(),
            snapshot: Some("ready".into()),
        }),
        ..Default::default()
    };
    req.env.insert("SECRET".into(), "forbidden".into());
    assert!(h.m.create_made(req.clone()).await.is_err());
    req.env.clear();
    h.host_calls();
    let clone = h.m.create_made(req).await.unwrap();
    assert_eq!(clone.state, state::RUNNING);
    let origin = clone.memory_origin.unwrap();
    assert_eq!(origin.stage, "active");
    assert_eq!(origin.snapshot, snapshot.id);
    assert_eq!(origin.identity.unwrap().ip, format!("{}/24", clone.ip));
    assert_eq!(h.m.usage().0.memory_mb, 512);
    let calls = h.host_calls();
    let configured = calls
        .iter()
        .position(|s| s.starts_with("clone_configure_v1"))
        .unwrap();
    let network = calls
        .iter()
        .position(|s| s.starts_with("activate_quarantined"))
        .unwrap();
    let activated = calls
        .iter()
        .position(|s| s.starts_with("clone_activate_v1"))
        .unwrap();
    assert!(configured < network && network < activated, "{calls:?}");
    assert!(matches!(
        h.m.delete_snapshot(&builder.id, &snapshot.id).await,
        Err(MError::Conflict(_))
    ));
    h.m.destroy(&clone.id, None).await.unwrap();
    assert!(h.m.clone_readers().unwrap().is_empty());
    h.m.delete_snapshot(&builder.id, &snapshot.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn clone_never_boots_cold_when_backing_disappears_after_reservation() {
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
    let req = api::CreateMachineRequest {
        namespace: "t1".into(),
        name: "broken".into(),
        fork: Some(api::ForkSpec {
            machine_id: builder.id,
            copy: String::new(),
            snapshot: Some(snapshot.id.clone()),
        }),
        ..Default::default()
    };
    let (e, how) = h.m.record(req, None).await.unwrap();
    let origin = e.snapshot().clone_origin.unwrap();
    let files =
        h.m.artifact_files(
            &origin.source_machine,
            &origin.snapshot,
            &origin.artifact.generation,
        )
        .unwrap();
    std::fs::remove_file(&files[1]).unwrap();
    h.host_calls();
    let scope = h.m.inner.zfs.io_scope().unwrap();
    assert!(h.m.make_admitted(scope, &e, how).await.is_err());
    assert!(!h.host_calls().iter().any(|s| s.starts_with("boot ")));
    assert_eq!(e.snapshot().state, state::ERROR);
}

#[tokio::test]
async fn actual_guest_init_digest_mismatch_refuses_seal_before_snapshot() {
    let (h, builder) = reviewed_builder().await;
    h.report_guest_init_digest(&builder.id, &"0".repeat(64));
    h.host_calls();
    let error =
        h.m.snapshot(
            &builder.id,
            api::SnapshotRequest {
                memory: true,
                template: true,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("actual guest init executable"));
    assert!(!h.host_calls().iter().any(|s| s.starts_with("snapshot ")));
}
