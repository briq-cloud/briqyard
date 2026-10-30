//! Chains across restores and growth, sealing, retention and forks.

use super::*;

fn restore_of(machine_id: &str, backup: &str, name: &str) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        namespace: "t1".into(),
        name: name.into(),
        restore: Some(api::RestoreSpec {
            machine_id: machine_id.into(),
            backup: backup.into(),
        }),
        start: Some(false),
        ..Default::default()
    }
}

/// A growth between two backups: the chain goes on (a stream carries the volume's size),
/// and a restore asks for the backup's volume size or more (ADR 0040).
#[tokio::test]
async fn a_chain_goes_on_across_a_growth_and_a_restore_never_shrinks_the_volume() {
    let h = harness(|_| {}).await;
    with_volume(&h, "m_v", state::STOPPED, 2).await;
    let b1 = h.m.backup("m_v").await.unwrap();
    h.m.update("m_v", grow_to(5), None).await.unwrap();
    let b2 = h.m.backup("m_v").await.unwrap();
    let data = b2.disks.iter().find(|d| d.disk == "data").unwrap();
    assert_eq!(data.from.as_deref(), Some(b1.id.as_str()));
    let r =
        h.m.create_made(restore_of("m_v", &b2.id, "r2"))
            .await
            .unwrap();
    assert_eq!(
        (r.volume.map(|v| v.size_gb), h.volsize_gb(&r.id).await),
        (Some(5), 5)
    );
    let with = |gb: u32, name: &str| api::CreateMachineRequest {
        volume: Some(api::VolumeSpec {
            size_gb: gb,
            mount: "/data".into(),
        }),
        ..restore_of("m_v", &b1.id, name)
    };
    let err = h.m.create_made(with(1, "small")).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid request: volume: 1 GB asked, 2 GB held: a volume never shrinks"
    );
    let r = h.m.create_made(with(8, "big")).await.unwrap();
    assert_eq!(
        (r.volume.map(|v| v.size_gb), h.volsize_gb(&r.id).await),
        (Some(8), 8)
    );
}

/// A backup is sent raw and its record says the id of the pool's key, never the key; a
/// restore opens the received streams with the key of that id and gives them the pool's
/// (ADR 0035).
#[tokio::test]
async fn a_backup_is_raw_and_its_restore_takes_the_pools_key() {
    let h = harness(|_| {}).await;
    let mut req = h.request("db");
    req.env.insert("PASSWORD".into(), "s3cret".into());
    let m = h.m.create_made(req).await.unwrap();
    h.pool.calls();
    let b = h.m.backup(&m.id).await.unwrap();
    let key = "0123456789abcdef".repeat(4);
    assert_eq!(b.key_id, briqyard_api::poolkey::id(&key));
    let calls = h.pool.calls();
    assert!(calls.iter().any(|c| c.starts_with("send -w ")), "{calls:?}");
    assert!(
        calls.contains(&"load-key -n -L prompt byard".to_string()),
        "the key checked on the pool's encryption root: {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("send -c ")),
        "{calls:?}"
    );
    let store = h.m.backup_store().unwrap();
    let record = store
        .get_bytes(&format!("backups/{}/{}.json", m.id, b.id))
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&record);
    assert!(!text.contains(&key));
    let record: api::Backup = serde_json::from_slice(&record).unwrap();
    assert!(
        record.machine.is_none() && record.sealed.is_some(),
        "{text}"
    );
    assert!(
        !text.contains("s3cret"),
        "the machine's env is sealed: {text}"
    );
    let spec = spec_of(&record, Some(&key)).unwrap();
    assert_eq!(spec["env"]["PASSWORD"], "s3cret");
    // Sealed for its place: moved to another backup's record, it does not open.
    let mut moved = record.clone();
    moved.id = "20991231T000000.000Z".into();
    assert!(spec_of(&moved, Some(&key)).is_err());
    let r =
        h.m.create_made(restore_of(&m.id, &b.id, "r"))
            .await
            .unwrap();
    let env = h.m.entry(&r.id).unwrap().snapshot().env;
    assert_eq!(env["PASSWORD"], "s3cret", "the spec opened");
    let calls = h.pool.calls();
    let load = calls
        .iter()
        .position(|c| c.starts_with("load-key -L prompt ") && c.contains(&r.id))
        .unwrap_or_else(|| panic!("{calls:?}"));
    let ds = calls[load].rsplit(' ').next().unwrap();
    assert!(
        calls[load..].contains(&format!("change-key -i {ds}")),
        "{calls:?}"
    );
    // A key the host does not have, with no fleet to ask: the restore is refused.
    let mut other = b.clone();
    other.id = "20991231T000000.000Z".into();
    other.key_id = briqyard_api::poolkey::id(&"fedcba9876543210".repeat(4));
    store
        .put_bytes(
            &format!("backups/{}/{}.json", m.id, other.id),
            &serde_json::to_vec(&other).unwrap(),
        )
        .await
        .unwrap();
    let err = h.m.create_made(restore_of(&m.id, &other.id, "r2")).await;
    let msg = match err {
        Ok(r) => h.m.get(&r.id).unwrap().error,
        Err(e) => format!("{e:#}"),
    };
    assert!(msg.contains("no fleet to ask"), "{msg}");
}

/// A key from the source that is not the pool's (a key file replaced, a registry restored
/// to an older key) makes no backup: its record would name a key its streams are not under.
#[tokio::test]
async fn a_backup_is_refused_under_a_key_that_is_not_the_pools() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", None, true).await;
    let file =
        h.m.inner
            .cfg
            .storage
            .key
            .trim_start_matches("file:")
            .to_string();
    std::fs::write(&file, "fedcba9876543210".repeat(4)).unwrap();
    let err = h.m.backup(&m.id).await.unwrap_err();
    assert!(format!("{err:#}").contains("not the pool's"), "{err:#}");
    assert!(h.objects(&m.id).await.is_empty());
    assert!(!h.pool.calls().iter().any(|c| c.starts_with("send ")));
}

/// A backup made before ADR 0035, its streams in clear, restores as it did, with no key;
/// the next backup is whole: a raw increment never continues a stream in clear.
#[tokio::test]
async fn a_backup_in_clear_restores_and_the_next_one_is_whole() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", None, true).await;
    let b = h.m.backup(&m.id).await.unwrap();
    // Its record as a backup in clear had it: the machine open, no key.
    let place = format!("backups/{}/{}.json", m.id, b.id);
    let store = h.m.backup_store().unwrap();
    let mut record: api::Backup =
        serde_json::from_slice(&store.get_bytes(&place).await.unwrap()).unwrap();
    let key = "0123456789abcdef".repeat(4);
    record.machine = Some(spec_of(&record, Some(&key)).unwrap());
    (record.key_id, record.sealed) = (None, None);
    store
        .put_bytes(&place, &serde_json::to_vec(&record).unwrap())
        .await
        .unwrap();
    h.pool.calls();
    let r =
        h.m.create_made(restore_of(&m.id, &b.id, "r"))
            .await
            .unwrap();
    assert_eq!(r.state, state::CREATED);
    let calls = h.pool.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("load-key") || c.starts_with("change-key")),
        "{calls:?}"
    );
    let next = h.m.backup(&m.id).await.unwrap();
    assert!(!next.incremental, "{next:?}");
}

#[tokio::test]
async fn retention_keeps_keep_restorable_points_and_their_bases() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", every("1h", 2), true).await;
    let mut made = Vec::new();
    for _ in 0..3 {
        made.push(h.m.backup(&m.id).await.unwrap().id);
    }
    // Whole, from it, whole: the second is kept and needs the first.
    let all = h.listed(&m.id).await;
    assert_eq!(h.ids(&all), made);
    assert_eq!(
        all.iter().map(|b| b.incremental).collect::<Vec<_>>(),
        [false, true, false]
    );
    // The oldest kept point restores from its chain.
    let restore = |name: &str, backup: &str| api::CreateMachineRequest {
        namespace: "t1".into(),
        name: name.into(),
        restore: Some(api::RestoreSpec {
            machine_id: m.id.clone(),
            backup: backup.into(),
        }),
        start: Some(false),
        ..Default::default()
    };
    let r = h.m.create_made(restore("r2", &made[1])).await.unwrap();
    assert_eq!(r.state, state::CREATED);
    // Its own backups start a chain of their own, whole.
    let rb = h.m.backup(&r.id).await.unwrap();
    assert!(!rb.incremental, "{rb:?}");
    // The fourth continues from the third: the first chain goes, streams and records.
    made.push(h.m.backup(&m.id).await.unwrap().id);
    let all = h.listed(&m.id).await;
    assert_eq!(h.ids(&all), made[2..].to_vec());
    assert!(all[1].incremental);
    let mut want: Vec<String> = made[2..]
        .iter()
        .flat_map(|id| {
            [
                format!("backups/{}/{id}.json", m.id),
                format!("backups/{}/root/{id}.zfs", m.id),
            ]
        })
        .collect();
    want.sort();
    assert_eq!(h.objects(&m.id).await, want);
    let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
    assert_eq!(ev["reason"], "retention");
    assert_eq!(ev["backups"], json!([made[1], made[0]]), "newest first");
    assert_eq!(
        h.stored(&m.id).unwrap().backup_bytes,
        all.iter().map(|b| b.bytes).sum::<u64>()
    );
    // Both kept points restore.
    h.m.create_made(restore("r3", &made[2])).await.unwrap();
    h.m.create_made(restore("r4", &made[3])).await.unwrap();
}

#[tokio::test]
async fn a_promoted_fork_backs_up_whole_from_its_own_snapshots_only() {
    let h = harness(|_| {}).await;
    let src = h.machine("src", Some(None), true).await;
    let sb = h.m.backup(&src.id).await.unwrap();
    let mut req = h.request("fork");
    req.fork = Some(api::ForkSpec {
        machine_id: src.id.clone(),
        copy: String::new(),
    });
    let fork = h.m.create_made(req).await.unwrap();
    // Destroyed under its fork: the fork's root disk takes the source's older snapshots
    // over, its backup snapshot among them, as ZFS's promote does.
    h.m.destroy(&src.id, None).await.unwrap();
    let taken = h
        .pool
        .dev()
        .join(format!("byard/m/{}/root@bk-{}", fork.id, sb.id));
    assert!(taken.exists(), "{}", taken.display());
    // That snapshot is not a backup of the fork: its first backup is whole.
    let first = h.m.backup(&fork.id).await.unwrap();
    assert!(!first.incremental, "{first:?}");
    assert!(first.disks.iter().all(|d| d.from.is_none()));
    let second = h.m.backup(&fork.id).await.unwrap();
    assert_eq!(second.disks[0].from.as_deref(), Some(first.id.as_str()));
    // And its chain restores.
    let r =
        h.m.create_made(api::CreateMachineRequest {
            namespace: "t1".into(),
            name: "back".into(),
            restore: Some(api::RestoreSpec {
                machine_id: fork.id.clone(),
                backup: second.id.clone(),
            }),
            start: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(r.state, state::CREATED);
}

#[tokio::test]
async fn a_base_is_deleted_only_with_what_continues_from_it() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", Some(None), true).await;
    let mut made = Vec::new();
    for _ in 0..3 {
        made.push(h.m.backup(&m.id).await.unwrap().id);
    }
    match h.m.delete_backup(&m.id, &made[0], false).await {
        Err(MError::Conflict(e)) => {
            assert!(e.contains(&made[1]) && e.contains(&made[2]), "{e}");
            assert!(e.contains("?chain=true"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        h.m.delete_backup(&m.id, "20990101T000000.000Z", false)
            .await,
        Err(MError::NoBackup(_))
    ));
    assert!(matches!(
        h.m.delete_backup("m_none", &made[0], false).await,
        Err(MError::NotFound)
    ));
    // The newest goes alone; the record's newest is the one before.
    h.m.delete_backup(&m.id, &made[2], false).await.unwrap();
    assert_eq!(h.ids(&h.listed(&m.id).await), made[..2].to_vec());
    assert_eq!(
        h.stored(&m.id).unwrap().backup.last.as_ref(),
        Some(&made[1])
    );
    let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
    assert_eq!(
        (ev["reason"].clone(), ev["backups"].clone()),
        (json!("request"), json!([made[2]]))
    );
    // Its snapshot was the base on the host, and it is gone from the store: whole.
    let next = h.m.backup(&m.id).await.unwrap();
    assert!(!next.incremental);
    h.m.delete_backup(&m.id, &made[0], true).await.unwrap();
    assert_eq!(h.ids(&h.listed(&m.id).await), vec![next.id.clone()]);
    let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
    assert_eq!(ev["backups"], json!([made[1], made[0]]));
    assert_eq!(h.stored(&m.id).unwrap().backup_bytes, next.bytes);
}
