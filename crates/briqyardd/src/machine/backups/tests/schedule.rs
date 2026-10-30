//! Policies, the schedule and the one-at-a-time rule.

use super::*;

#[tokio::test]
async fn a_policy_is_checked_by_field_and_a_patch_sets_or_removes_it() {
    let h = harness(|_| {}).await;
    for (backup, why) in [
        (every("30m", 2), r#"backup.every "30m": at least 1h"#),
        (every("6h", 0), "backup.keep: at least 1"),
    ] {
        let mut req = h.request("bad");
        req.backup = backup;
        match h.m.create_made(req).await {
            Err(MError::Invalid(e)) => assert_eq!(e, why),
            other => panic!("{other:?}"),
        }
    }
    // None by default on this host.
    let m = h.machine("db", None, false).await;
    assert_eq!((m.backup, m.next_backup_at), (None, None));
    let patch = |backup| api::UpdateMachineRequest {
        backup,
        ..Default::default()
    };
    let before = Utc::now();
    let m =
        h.m.update(&m.id, patch(every("1d", 5)), None)
            .await
            .unwrap();
    assert_eq!(m.backup.as_ref().map(|p| p.keep), Some(5));
    let next = m.next_backup_at.unwrap();
    assert!(
        next >= before + chrono::Duration::days(1)
            && next <= Utc::now() + chrono::Duration::days(1)
    );
    let ev = h.last_of(&m.id, reason::UPDATED);
    assert_eq!(ev.data.unwrap()["fields"], json!(["backup"]));
    // The same policy again is no change: no event, the same next time.
    let again =
        h.m.update(&m.id, patch(every("1d", 5)), None)
            .await
            .unwrap();
    assert_eq!(
        (again.version, again.next_backup_at),
        (m.version, m.next_backup_at)
    );
    let err = h.m.update(&m.id, patch(every("1d", 0)), None).await;
    assert!(matches!(err, Err(MError::Invalid(e)) if e == "backup.keep: at least 1"));
    // null removes it.
    let m = h.m.update(&m.id, patch(Some(None)), None).await.unwrap();
    assert_eq!((m.backup, m.next_backup_at), (None, None));
    assert!(h.stored(&m.id).unwrap().backup.policy.is_none());

    // A host's default is what a create without one gets; null is none.
    let h = harness(|b| {
        b.default_every = "1d".into();
        b.default_keep = 5;
    })
    .await;
    let m = h.machine("db", None, false).await;
    assert_eq!(m.backup.map(|p| (p.every, p.keep)), Some(("1d".into(), 5)));
    assert_eq!(
        m.next_backup_at,
        Some(m.created_at + chrono::Duration::days(1))
    );
    let m = h.machine("scratch", Some(None), false).await;
    assert_eq!(m.backup, None);
}

#[tokio::test]
async fn the_schedule_fires_when_due_and_not_before() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", every("1h", 3), true).await;
    let t = m.next_backup_at.unwrap();
    assert_eq!(t, m.created_at + chrono::Duration::hours(1));
    assert_eq!(m.last_backup_at, None);
    assert_eq!(
        run(h.m.backup_step(t - chrono::Duration::seconds(1))).await,
        0
    );
    assert!(h.listed(&m.id).await.is_empty());
    assert_eq!(run(h.m.backup_step(t)).await, 1);
    let all = h.listed(&m.id).await;
    assert_eq!(all.len(), 1);
    assert!(!all[0].incremental);
    let v = h.m.get(&m.id).unwrap();
    assert_eq!(v.last_backup_at, Some(all[0].created_at));
    assert_eq!(v.next_backup_at, Some(t + chrono::Duration::hours(1)));
    let ev = h.last_of(&m.id, reason::BACKED_UP);
    assert_eq!(ev.data.unwrap()["bytes"], json!(all[0].bytes));
    // Done for this hour: the same tick, or one a minute short of the next, starts none.
    assert_eq!(run(h.m.backup_step(t)).await, 0);
    assert_eq!(
        run(h.m.backup_step(t + chrono::Duration::minutes(59))).await,
        0
    );
    assert_eq!(
        run(h.m.backup_step(t + chrono::Duration::hours(1))).await,
        1
    );
    let all = h.listed(&m.id).await;
    assert_eq!(all.len(), 2);
    assert!(all[1].incremental, "from the first");
    // Written to the record: a daemon that starts again goes on from it.
    assert_eq!(
        h.stored(&m.id).unwrap().backup.next_at,
        Some(t + chrono::Duration::hours(2))
    );
    assert_eq!(
        h.stored(&m.id).unwrap().backup_bytes,
        all.iter().map(|b| b.bytes).sum::<u64>()
    );
}

/// A destroy while a backup sends (the chaos run of 2026-10-28): the backup answers the
/// destroy, 404, never a 500 about a dataset that is gone.
#[tokio::test]
async fn a_backup_racing_a_destroy_answers_not_found() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", every("1h", 3), true).await;
    let hold = h.pool.dev().join("hold.snapshot");
    std::fs::write(&hold, "").unwrap();
    let (mm, id) = (h.m.clone(), m.id.clone());
    let backup = tokio::spawn(async move { mm.backup(&id).await });
    while h.pool.zfs.stalled(Duration::ZERO).is_none() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (mm, id) = (h.m.clone(), m.id.clone());
    let destroy = tokio::spawn(async move { mm.destroy(&id, None).await });
    // Gone from the manager, not only its disks: the backup's failure then reads the
    // destroy, whatever the destroy still had to do after its disks.
    while h.m.entry(&m.id).is_ok() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::remove_file(&hold).unwrap();
    destroy.await.unwrap().unwrap();
    let err = backup.await.unwrap().unwrap_err();
    assert!(matches!(err, MError::NotFound), "{err:?}");
}

#[tokio::test]
async fn at_most_at_once_and_never_two_for_one_machine() {
    let h = harness(|b| b.at_once = 2).await;
    let mut ms = Vec::new();
    for name in ["a", "b", "c"] {
        ms.push(h.machine(name, every("1h", 3), true).await);
    }
    let t = ms.iter().filter_map(|m| m.next_backup_at).max().unwrap();
    let hold = h.pool.dev().join("hold.send");
    std::fs::write(&hold, "").unwrap();
    h.pool.calls();
    let tasks = h.m.backup_step(t);
    assert_eq!(tasks.len(), 3);
    tokio::time::timeout(Duration::from_secs(10), async {
        while h.sends() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("two sends start");
    assert_eq!(h.sends(), 2, "the third waits for the gate");
    assert_eq!(h.m.inner.backups.gate.available_permits(), 0);
    // Every turn is held, the waiting one's too: a tick meanwhile starts nothing more.
    assert!(h.m.backup_step(t).is_empty());
    std::fs::remove_file(&hold).unwrap();
    assert_eq!(run(tasks).await, 3);
    assert_eq!(h.sends(), 3);
    for m in &ms {
        assert_eq!(h.listed(&m.id).await.len(), 1, "{}", m.name);
    }
    assert_eq!(h.m.inner.backups.gate.available_permits(), 2);
}

#[tokio::test]
async fn a_machine_with_no_process_is_backed_up_only_when_its_disks_changed() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", every("1h", 3), false).await;
    assert_eq!(m.state, state::CREATED);
    let t = m.next_backup_at.unwrap();
    // Its first backup: there is none to compare with.
    run(h.m.backup_step(t)).await;
    let first = h.listed(&m.id).await;
    assert_eq!(first.len(), 1);
    let version = h.m.get(&m.id).unwrap().version;
    h.pool.answer(&format!("written@bk-{}", first[0].id), "0\n");
    let t = t + chrono::Duration::hours(1);
    assert_eq!(run(h.m.backup_step(t)).await, 1);
    assert_eq!(h.listed(&m.id).await.len(), 1, "unchanged: skipped");
    let v = h.m.get(&m.id).unwrap();
    assert_eq!(v.next_backup_at, Some(t + chrono::Duration::hours(1)));
    assert_eq!(v.version, version, "a skip is no event");
    h.pool
        .answer(&format!("written@bk-{}", first[0].id), "4096\n");
    run(h.m.backup_step(t + chrono::Duration::hours(1))).await;
    let all = h.listed(&m.id).await;
    assert_eq!(all.len(), 2, "written: backed up");
    assert!(all[1].incremental);
}
