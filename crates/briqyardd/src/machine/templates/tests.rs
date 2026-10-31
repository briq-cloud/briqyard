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
        namespace: r.namespace.clone(),
        source_host: "h_test".into(),
        init_sha256: "a".repeat(64),
        init_protocol: 1,
        cpu_fingerprint: "test_cpu".into(),
        boot_identity: h.m.inner.vmm.boot_identity(false).unwrap(),
        recipe: CloneRecipe {
            image: r.image.clone(),
            image_digest: r.image_digest.clone(),
            image_key: r.image_key.clone(),
            size: r.size,
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
