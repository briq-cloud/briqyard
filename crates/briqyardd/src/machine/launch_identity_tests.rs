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
    let cfg = Config::default();
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
