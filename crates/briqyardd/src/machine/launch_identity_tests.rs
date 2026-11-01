use super::*;
use crate::machine::tests::{harness, harness_config, record};

async fn held() -> (crate::machine::tests::Harness, Record, LaunchIdentity) {
    let h = harness_config(|cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.jailer = "/mock/jailer".into();
    })
    .await;
    h.namespace("t1");
    let mut r = record();
    let identity =
        LaunchIdentity::new(&h.m.inner.cfg, &r.namespace, r.subnet_index, r.host_num).unwrap();
    r.launch_identity = Some(identity.clone());
    h.m.inner
        .store
        .put_durable(
            HOLDS,
            &r.id,
            &Hold {
                machine: r.id.clone(),
                identity: identity.clone(),
            },
        )
        .unwrap();
    h.m.recover_launch_holds(&[r.clone()]).unwrap();
    (h, r, identity)
}

#[tokio::test]
async fn launch_identity_survives_destination_assignment_and_legacy_stays_address_based() {
    let (h, mut r, identity) = held().await;
    let before = h.m.jail_for(&r).unwrap();
    r.namespace = "tenant".into();
    r.subnet_index = 2;
    r.host_num = 43;
    let after = h.m.jail_for(&r).unwrap();
    assert_eq!((after.uid, after.gid), (before.uid, before.gid));
    assert_eq!((after.uid, after.gid), (identity.uid, identity.gid));
    h.m.recover_launch_holds(&[r.clone()]).unwrap();
    assert!(h.m.held_addresses(1).contains(&2));
    r.launch_identity = None;
    assert_eq!(
        h.m.jail_for(&r).unwrap().uid,
        start::jail_uid(h.m.inner.cfg.jail_uid_base, 2, 43)
    );
}

#[tokio::test]
async fn source_namespace_cannot_be_deleted_or_reused_until_cleanup_releases_hold() {
    let (h, _r, _) = held().await;
    assert!(matches!(
        h.m.delete_namespace("t1").await,
        Err(MError::NamespaceInUse)
    ));
    // Simulate a partial namespace-record loss: allocation must still avoid the held subnet.
    let mut first = h.m.inner.namespaces.lock().unwrap().remove("t1").unwrap();
    let mut namespaces = h.m.inner.namespaces.lock().unwrap();
    assert_eq!(h.m.free_namespace_subnet(&namespaces).unwrap(), 0);
    first.rec.id = "fresh-a".into();
    first.rec.subnet_index = 0;
    namespaces.insert("fresh-a".into(), first);
    assert_eq!(h.m.free_namespace_subnet(&namespaces).unwrap(), 2);
    h.m.release_launch_hold("m_abc123").unwrap();
    assert!(!h.m.held_addresses(1).contains(&2));
    assert_eq!(h.m.free_namespace_subnet(&namespaces).unwrap(), 1);
}

#[tokio::test]
async fn recovery_fails_closed_on_journal_only_missing_or_conflicting_identity() {
    let (h, mut r, _) = held().await;
    assert!(h.m.recover_launch_holds(&[]).is_err());
    assert!(h.m.held_addresses(1).contains(&2));
    r.launch_identity = None;
    assert!(h.m.recover_launch_holds(&[r.clone()]).is_err());
    r.launch_identity = Some(LaunchIdentity::new(&h.m.inner.cfg, "t1", 1, 3).unwrap());
    assert!(h.m.recover_launch_holds(&[r]).is_err());
    assert!(h.m.held_addresses(1).contains(&2));
}

#[tokio::test]
async fn recovery_rejects_source_reuse_missing_namespace_and_changed_jail_configuration() {
    let (h, r, identity) = held().await;
    let mut reused = record();
    reused.id = "m_other".into();
    assert!(h.m.recover_launch_holds(&[r.clone(), reused]).is_err());
    h.m.inner.namespaces.lock().unwrap().remove("t1");
    assert!(h.m.recover_launch_holds(&[r]).is_err());
    for field in 0..4 {
        let mut cfg = h.m.inner.cfg.clone();
        match field {
            0 => cfg.jail_uid_base += 1,
            1 => cfg.jailer = PathBuf::new(),
            2 => cfg.jail_dir = "/changed".into(),
            _ => cfg.jailer = "/changed/jailer".into(),
        }
        assert!(identity.check(&cfg).is_err());
    }
}

#[tokio::test]
async fn failed_hold_deletion_retains_allocation() {
    let (h, _, _) = held().await;
    let path = h.m.inner.store.dir(HOLDS).join("m_abc123.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(h.m.release_launch_hold("m_abc123").is_err());
    assert!(h.m.held_addresses(1).contains(&2));
}

#[tokio::test]
async fn handover_rejects_incompatible_target_with_holds_and_releases_admission_on_failure() {
    let (h, _, _) = held().await;
    assert!(h
        .m
        .handover_admission(Path::new("/usr/bin/true"))
        .await
        .is_err());
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());
    assert!(h.m.held_addresses(1).contains(&2));
    h.m.release_launch_hold("m_abc123").unwrap();
    let admission =
        h.m.handover_admission(Path::new("/usr/bin/true"))
            .await
            .unwrap();
    assert!(h.m.inner.namespace_lifecycle.try_read().is_err());
    drop(admission);
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());
}

#[test]
fn launch_identity_checks_source_range_version_and_uid_overflow() {
    let cfg = Config {
        jailer: "/mock/jailer".into(),
        ..Default::default()
    };
    assert!(LaunchIdentity::new(
        &Config {
            jailer: "/jailer".into(),
            jail_uid_base: u32::MAX,
            ..cfg.clone()
        },
        "source",
        1,
        2
    )
    .is_err());
    let mut identity = LaunchIdentity::new(&cfg, "source", 1, 2).unwrap();
    identity.host_num = 1;
    assert!(identity.check(&cfg).is_err());
    identity.host_num = 2;
    identity.version = 2;
    assert!(identity.check(&cfg).is_err());
}

#[tokio::test]
async fn legacy_records_need_no_launch_holds() {
    let h = harness("10.64.0.0/22", 4096).await;
    let record = record();
    h.m.recover_launch_holds(std::slice::from_ref(&record))
        .unwrap();
    h.m.validate_launch_record(&record).unwrap();
    assert!(h.m.inner.launch_holds.lock().unwrap().is_empty());
}

#[tokio::test]
async fn compatible_handover_fences_new_admission_through_target_check() {
    use std::os::unix::fs::PermissionsExt;
    let (h, _, _) = held().await;
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("replacement");
    std::fs::write(
        &executable,
        b"#!/bin/sh\n[ \"$1\" = state-capabilities ] || exit 1\nprintf 'launch-identity-v1\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let admission = h.m.handover_admission(&executable).await.unwrap();
    assert!(h.m.inner.namespace_lifecycle.try_read().is_err());
    assert!(h.m.held_addresses(1).contains(&2));
    drop(admission);
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());
}

#[tokio::test]
async fn destruction_releases_source_allocation_only_after_cleanup_succeeds() {
    let (h, r, _) = held().await;
    let e = Entry::new(r.clone(), h.m.inner.events.clone());
    h.m.inner.machines.lock().unwrap().insert(r.id.clone(), e);
    let run = h.m.inner.cfg.run_dir().join(&r.id);
    std::fs::create_dir_all(run.parent().unwrap()).unwrap();
    std::fs::write(&run, b"incomplete cleanup").unwrap();
    assert!(h.m.destroy_machine(&r.id, None).await.is_err());
    assert!(h.m.held_addresses(1).contains(&2));
    assert!(h.m.entry(&r.id).is_ok());
    std::fs::remove_file(&run).unwrap();
    h.m.destroy_machine(&r.id, None).await.unwrap();
    assert!(!h.m.held_addresses(1).contains(&2));
    assert!(h.m.inner.store.get::<Hold>(HOLDS, &r.id).unwrap().is_none());
    assert!(h.m.entry(&r.id).is_err());
}

#[tokio::test]
async fn handover_admission_deadline_and_cancellation_release_queued_writer() {
    // No launch holds: even an ordinary host can have an admission reader stuck.
    let h = harness("10.64.0.0/22", 4096).await;
    let reader = h.m.inner.namespace_lifecycle.read().await;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let result =
        h.m.handover_admission_until(Path::new("/usr/bin/true"), deadline)
            .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("handover deadline"));
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());

    let mut pending = Box::pin(h.m.handover_admission(Path::new("/usr/bin/true")));
    assert!(matches!(
        futures::poll!(&mut pending),
        std::task::Poll::Pending
    ));
    // A stop signal/server completion drops the pending acquisition in main's select.
    drop(pending);
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());
    drop(reader);
    assert!(h.m.inner.namespace_lifecycle.try_write().is_ok());
}

#[tokio::test]
async fn launch_hold_retry_is_idempotent_and_conflicting_retry_cannot_replace_it() {
    let (h, r, identity) = held().await;
    h.m.persist_launch_hold(&r.id, &identity).unwrap();
    let mut changed = identity.clone();
    changed.host_num += 1;
    assert!(h.m.persist_launch_hold(&r.id, &changed).is_err());
    assert_eq!(
        h.m.inner.launch_holds.lock().unwrap().get(&r.id),
        Some(&identity)
    );
    assert_eq!(
        h.m.inner
            .store
            .get::<Hold>(HOLDS, &r.id)
            .unwrap()
            .unwrap()
            .identity,
        identity
    );
    // A restart/cache loss must still consult the existing durable identity.
    h.m.inner.launch_holds.lock().unwrap().clear();
    assert!(h.m.persist_launch_hold(&r.id, &changed).is_err());
    h.m.persist_launch_hold(&r.id, &identity).unwrap();
}

#[tokio::test]
async fn uncertain_first_launch_hold_write_keeps_immutable_cached_identity() {
    let h = harness_config(|cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.jailer = "/mock/jailer".into();
    })
    .await;
    let identity = LaunchIdentity::new(&h.m.inner.cfg, "t1", 1, 2).unwrap();
    let directory = h.m.inner.store.dir(HOLDS);
    std::fs::remove_dir(&directory).unwrap();
    assert!(h.m.persist_launch_hold("m_retry", &identity).is_err());
    let mut changed = identity.clone();
    changed.host_num = 3;
    assert!(h.m.persist_launch_hold("m_retry", &changed).is_err());
    assert_eq!(
        h.m.inner.launch_holds.lock().unwrap().get("m_retry"),
        Some(&identity)
    );
    std::fs::create_dir(&directory).unwrap();
    h.m.persist_launch_hold("m_retry", &identity).unwrap();
    assert_eq!(
        h.m.inner
            .store
            .get::<Hold>(HOLDS, "m_retry")
            .unwrap()
            .unwrap()
            .identity,
        identity
    );
}

#[tokio::test]
async fn durable_machine_forget_precedes_hold_release_and_excludes_late_writes() {
    let (h, r, _) = held().await;
    let e = Entry::new(r.clone(), h.m.inner.events.clone());
    h.m.inner.store.put_durable("machines", &r.id, &r).unwrap();
    h.m.forget(&e).unwrap();
    assert!(*e.removed.lock().unwrap());
    h.m.save(&e).unwrap();
    assert!(h
        .m
        .inner
        .store
        .get::<Record>("machines", &r.id)
        .unwrap()
        .is_none());
    // Crash after the durable record unlink, before the durable hold unlink:
    // the source remains held and startup conservatively refuses the orphaned hold.
    assert!(h.m.recover_launch_holds(&[]).is_err());
    assert!(h.m.held_addresses(1).contains(&2));
    h.m.release_launch_hold(&r.id).unwrap();
    h.m.recover_launch_holds(&[]).unwrap();
    assert!(!h.m.held_addresses(1).contains(&2));
}

#[tokio::test]
async fn failed_machine_directory_sync_does_not_release_hold_or_mark_record_removed() {
    let (h, r, _) = held().await;
    let e = Entry::new(r.clone(), h.m.inner.events.clone());
    h.m.inner.store.put_durable("machines", &r.id, &r).unwrap();
    let directory = h.m.inner.store.dir("machines");
    let retained = directory.with_extension("retained");
    std::fs::rename(&directory, &retained).unwrap();
    // delete sees absence, but the mandatory directory fsync cannot complete.
    assert!(h.m.forget(&e).is_err());
    assert!(!*e.removed.lock().unwrap());
    assert!(h.m.held_addresses(1).contains(&2));
    assert!(h.m.inner.store.get::<Hold>(HOLDS, &r.id).unwrap().is_some());
    std::fs::rename(&retained, &directory).unwrap();
    h.m.recover_launch_holds(&[r]).unwrap();
}

#[test]
fn unjailed_launch_identity_is_refused_instead_of_assuming_root_credentials() {
    assert!(LaunchIdentity::new(&Config::default(), "operator", 1, 2).is_err());
}

#[tokio::test]
async fn assignment_state_appearing_after_preflight_is_checked_inside_admission_fence() {
    let h = harness("10.64.0.0/22", 4096).await;
    let reader = h.m.inner.namespace_lifecycle.read().await;
    // A preflight with no assignment state accepts an old executable.
    assert!(!crate::assignment_compatibility::required(&h.m.inner.cfg.state_dir()).unwrap());
    let mut pending = Box::pin(h.m.handover_admission(Path::new("/usr/bin/true")));
    assert!(matches!(
        futures::poll!(&mut pending),
        std::task::Poll::Pending
    ));
    h.m.inner
        .store
        .put(
            "unbound-requests",
            "consumed",
            &serde_json::json!({"schema": 1}),
        )
        .unwrap();
    drop(reader);
    assert!(pending.await.is_err());
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());
}

#[tokio::test]
async fn machine_destruction_keeps_assignment_consumption_and_compatibility_floor() {
    let (h, r, _) = held().await;
    let e = Entry::new(r.clone(), h.m.inner.events.clone());
    h.m.inner.machines.lock().unwrap().insert(r.id.clone(), e);
    h.m.inner
        .store
        .put_durable(
            "unbound-requests",
            "consumed",
            &serde_json::json!({"schema": 1, "machine": r.id, "namespace": r.namespace, "request_id": "req1", "create_sha256": "a".repeat(64)}),
        )
        .unwrap();
    let run = h.m.inner.cfg.run_dir().join(&r.id);
    std::fs::create_dir_all(run.parent().unwrap()).unwrap();
    std::fs::write(&run, b"incomplete cleanup").unwrap();
    assert!(h.m.destroy_machine(&r.id, None).await.is_err());
    std::fs::remove_file(&run).unwrap();
    h.m.destroy_machine(&r.id, None).await.unwrap();
    assert!(h
        .m
        .inner
        .store
        .get::<serde_json::Value>("unbound-requests", "consumed")
        .unwrap()
        .is_some());
    assert!(crate::assignment_compatibility::required(&h.m.inner.cfg.state_dir()).unwrap());
    assert!(h
        .m
        .inner
        .store
        .delete_durable("unbound-requests", "consumed")
        .is_err());
}

#[tokio::test]
async fn late_lifecycle_writer_rechecks_schema2_only_candidate_inside_handover_fence() {
    use std::os::unix::fs::PermissionsExt;
    let h = harness("10.64.0.0/22", 4096).await;
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("schema2-only");
    std::fs::write(&executable, b"#!/bin/sh\ncase \"$1\" in\nassignment-capabilities) printf 'destination-assignment-v1\\n';;\nassigned-run-capabilities) printf 'assigned-run-v1\\n';;\n*) exit 1;;\nesac\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    h.m.inner
        .store
        .put("assigned-runs", "before", &serde_json::json!({"schema":1}))
        .unwrap();
    crate::assignment_compatibility::check_required_candidate(
        &h.m.inner.cfg.state_dir(),
        &executable,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    let admission = h.m.inner.namespace_lifecycle.read().await;
    let mut pending = Box::pin(h.m.handover_admission(&executable));
    assert!(matches!(
        futures::poll!(&mut pending),
        std::task::Poll::Pending
    ));
    // Models the terminal writer already admitted under this read fence: floor first,
    // then incompatible intent. The queued handover must observe it after admission.
    h.m.inner
        .store
        .ensure_assigned_run_lifecycle_floor()
        .unwrap();
    h.m.inner
        .store
        .put_durable(
            "assigned-run-intents",
            "late",
            &serde_json::json!({"schema":3}),
        )
        .unwrap();
    drop(admission);
    assert!(pending.await.is_err());
    assert!(h.m.inner.namespace_lifecycle.try_read().is_ok());
}
