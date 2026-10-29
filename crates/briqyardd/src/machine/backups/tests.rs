//! Tests of backups.

use super::super::tests::{at, grow_to, harness_config, with_volume, Harness};
use super::*;
use tokio::task::JoinHandle;

fn disk(name: &str, id: &str, from: Option<&str>) -> api::BackupDisk {
    api::BackupDisk {
        disk: name.into(),
        key: format!("k-{name}-{id}"),
        bytes: 1,
        from: from.map(String::from),
    }
}

/// A backup of the root disk, whole or from another.
fn b(id: &str, from: Option<&str>) -> api::Backup {
    api::Backup {
        id: id.into(),
        machine_id: "m_1".into(),
        tenant: "t".into(),
        name: "n".into(),
        created_at: Utc::now(),
        bytes: 1,
        incremental: from.is_some(),
        disks: vec![disk("root", id, from)],
        key_id: Some("k1".into()),
        machine: None,
        sealed: None,
        deletes_at: None,
    }
}

fn ids(bs: &[&api::Backup]) -> Vec<String> {
    bs.iter().map(|b| b.id.clone()).collect()
}

#[test]
fn backup_chains() {
    let all = vec![
        b("a", None),
        b("b", Some("a")),
        b("c", Some("b")),
        b("d", None),
    ];
    let keys = |t: &api::Backup| -> Vec<String> {
        backup_chain(&all, t, "root")
            .iter()
            .map(|d| d.key.clone())
            .collect()
    };
    assert_eq!(keys(&all[2]), vec!["k-root-a", "k-root-b", "k-root-c"]);
    assert_eq!(keys(&all[0]), vec!["k-root-a"]);
    assert_eq!(keys(&all[3]), vec!["k-root-d"]);
    assert!(backup_chain(&all, &all[2], "data").is_empty());
    // A base that is not in the store ends the chain where it is.
    let orphan = b("e", Some("zz"));
    assert_eq!(keys(&orphan), vec!["k-root-e"]);
    assert_eq!(
        newest_backup_snapshot(&[
            "fork-x".into(),
            "bk-20260101T000000.000Z".into(),
            "bk-20260102T000000.000Z".into()
        ]),
        Some("bk-20260102T000000.000Z".into())
    );
    assert_eq!(newest_backup_snapshot(&["fork-x".into()]), None);
    // A base is a snapshot of one of the machine's backups that holds that disk.
    assert!(in_store(&all, "bk-b", "root", "k1"));
    assert!(!in_store(&all, "bk-b", "data", "k1"));
    assert!(!in_store(&all, "bk-zz", "root", "k1"));
    // And sent raw under this pool's key: never over a stream in clear or another key's.
    assert!(!in_store(&all, "bk-b", "root", "k2"));
    let mut clear = all.clone();
    clear[1].key_id = None;
    assert!(!in_store(&clear, "bk-b", "root", "k1"));
}

#[test]
fn retention_keeps_the_newest_and_what_they_continue_from() {
    // keep 2: whole every second backup, the store between 2 and 3.
    let mut all = vec![b("1", None)];
    assert!(prune(&all, 2).is_empty());
    assert_eq!(chain_length(&all), 1);
    all.push(b("2", Some("1")));
    assert!(prune(&all, 2).is_empty());
    assert_eq!(chain_length(&all), 2, "the next one is whole");
    all.push(b("3", None));
    assert!(prune(&all, 2).is_empty(), "2 is kept and needs 1");
    assert_eq!(chain_length(&all), 1);
    all.push(b("4", Some("3")));
    assert_eq!(ids(&prune(&all, 2)), vec!["1", "2"]);
    // keep 1: every backup whole, the store holds one.
    let all = vec![b("1", None), b("2", None)];
    assert_eq!(ids(&prune(&all, 1)), vec!["1"]);
    // A base of either disk is kept.
    let mut two = b("2", None);
    two.disks.push(disk("data", "2", Some("1")));
    let all = vec![b("1", None), two, b("3", None)];
    assert!(prune(&all, 2).is_empty());
    assert_eq!(ids(&prune(&all, 1)), vec!["1", "2"]);
    // A chain with no whole backup (before schedules) counts whole.
    let all = vec![b("1", Some("0")), b("2", Some("1"))];
    assert_eq!(chain_length(&all), 2);
    assert_eq!(chain_length(&[]), 0);
}

#[test]
fn what_continues_from_a_backup() {
    let all = vec![
        b("1", None),
        b("2", Some("1")),
        b("3", Some("2")),
        b("4", None),
        b("5", Some("4")),
    ];
    assert_eq!(dependents(&all, 0), vec![1, 2]);
    assert_eq!(dependents(&all, 1), vec![2]);
    assert_eq!(dependents(&all, 3), vec![4]);
    assert!(dependents(&all, 4).is_empty());
}

/// A harness whose host backs up to a directory, after `f`; tenant `t1` and the image in
/// place.
async fn harness(f: impl FnOnce(&mut config::Backup)) -> Harness {
    let h = harness_config(|cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.capacity = config::Capacity {
            memory_mb: 4096,
            vcpus: 1000,
            ..Default::default()
        };
        cfg.egress_limits = config::EgressLimits {
            blocked_ports: vec![],
            new_connections_per_minute: 0,
            bandwidth_mbit: 0,
        };
        cfg.backup.store = format!("file://{}", cfg.data_dir.join("store").display());
        f(&mut cfg.backup);
    })
    .await;
    h.ready().await;
    h
}

fn every(e: &str, keep: u32) -> Option<Option<api::BackupPolicy>> {
    Some(Some(api::BackupPolicy {
        every: e.into(),
        keep,
    }))
}

impl Harness {
    /// A machine of `t1` with this schedule, running or only created.
    async fn machine(
        &self,
        name: &str,
        backup: Option<Option<api::BackupPolicy>>,
        start: bool,
    ) -> api::Machine {
        let mut req = self.request(name);
        req.backup = backup;
        req.start = Some(start);
        self.m.create_made(req).await.unwrap()
    }

    async fn volsize_gb(&self, id: &str) -> u64 {
        let ds = format!("m/{id}/data");
        self.pool.zfs.volsize(&ds).await.unwrap() >> 30
    }

    fn ids(&self, bs: &[api::Backup]) -> Vec<String> {
        bs.iter().map(|b| b.id.clone()).collect()
    }

    async fn listed(&self, id: &str) -> Vec<api::Backup> {
        self.m.backups(id).await.unwrap()
    }

    /// The store's objects of a machine.
    async fn objects(&self, id: &str) -> Vec<String> {
        let store = self.m.backup_store().unwrap();
        store.list(&format!("backups/{id}/")).await.unwrap()
    }

    fn last_of(&self, id: &str, reason: &str) -> api::Event {
        self.events_of(id)
            .into_iter()
            .rev()
            .find(|e| e.reason == reason)
            .unwrap_or_else(|| panic!("{id}: no {reason} in {:?}", self.reasons(id)))
    }

    /// The sends the fake `zfs` started, read without taking the calls, which other
    /// processes are still appending to.
    fn sends(&self) -> usize {
        let calls = self.pool.dev().parent().unwrap().join("calls");
        std::fs::read_to_string(calls)
            .unwrap_or_default()
            .lines()
            .filter(|c| c.starts_with("send "))
            .count()
    }
}

/// Waits for the tasks a step started; how many there were.
async fn run(tasks: Vec<JoinHandle<()>>) -> usize {
    let n = tasks.len();
    for t in tasks {
        t.await.unwrap();
    }
    n
}

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

fn restore_of(machine_id: &str, backup: &str, name: &str) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        tenant: "t1".into(),
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
        tenant: "t1".into(),
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
            tenant: "t1".into(),
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

#[tokio::test]
async fn a_failed_backup_is_a_warning_and_is_tried_again_after_the_backoff() {
    let h = harness(|_| {}).await;
    // The fake's `zfs` refuses any name with "boom" in it.
    let e = h.add("m_boom", state::STOPPED, 256);
    let t = at("2026-10-21T10:00:00Z");
    {
        let mut r = e.rec.lock().unwrap();
        r.backup.policy = every("1h", 3).flatten();
        r.backup.next_at = Some(t);
    }
    assert_eq!(run(h.m.backup_step(t)).await, 1);
    let ev = h.last_of("m_boom", reason::BACKUP_FAILED);
    assert_eq!(ev.kind, api::event::WARNING);
    assert!(ev.message.contains("permission denied"), "{}", ev.message);
    assert!(ev.data.unwrap()["error"]
        .as_str()
        .unwrap()
        .contains("permission denied"));
    assert_eq!(
        h.m.get("m_boom").unwrap().next_backup_at,
        Some(t + RETRY_AFTER)
    );
    assert_eq!(
        run(h.m.backup_step(t + chrono::Duration::minutes(14))).await,
        0
    );
    assert_eq!(run(h.m.backup_step(t + RETRY_AFTER)).await, 1);
    let failed = h
        .reasons("m_boom")
        .iter()
        .filter(|r| *r == reason::BACKUP_FAILED)
        .count();
    assert_eq!(failed, 2);
    assert!(h.listed("m_boom").await.is_empty());
}

#[tokio::test]
async fn a_backup_the_store_refuses_leaves_nothing_behind() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", Some(None), false).await;
    // A file where the root disk's streams go: the store cannot write there.
    let store = h.m.inner.cfg.data_dir.join("store");
    std::fs::create_dir_all(store.join(format!("backups/{}", m.id))).unwrap();
    std::fs::write(store.join(format!("backups/{}/root", m.id)), "").unwrap();
    assert!(h.m.backup(&m.id).await.is_err());
    assert_eq!(
        h.last_of(&m.id, reason::BACKUP_FAILED).kind,
        api::event::WARNING
    );
    let root = h.m.get(&m.id).map(|_| format!("m/{}/root", m.id)).unwrap();
    let snaps = h.pool.zfs.snapshots(&root).await.unwrap();
    assert!(!snaps.iter().any(|s| s.starts_with("bk-")), "{snaps:?}");
    assert!(h.listed(&m.id).await.is_empty());
}

/// A destroy that finds no disks holds what the store lists, not what the record says:
/// a record written back after its destroy names backups deleted since (the upgrade of
/// 2026-10-28 held them again), and a destroy cut short after its disks may hold more.
#[tokio::test]
async fn a_destroy_without_disks_holds_what_the_store_lists() {
    let h = harness(|_| {}).await;
    let mut records = Vec::new();
    for name in ["gone", "kept"] {
        let m = h.machine(name, every("1h", 3), false).await;
        h.m.backup(&m.id).await.unwrap();
        let mut r = h.stored(&m.id).unwrap();
        h.m.destroy(&m.id, None).await.unwrap();
        assert!(h.m.holder(&m.id).is_some());
        r.state = state::DESTROYING.into();
        records.push(r);
    }
    let (gone, kept) = (&records[0], &records[1]);
    // One's backups deleted since: its holder went with them.
    let b = &h.listed(&gone.id).await[0];
    h.m.delete_backup(&gone.id, &b.id, false).await.unwrap();
    assert!(h.m.holder(&gone.id).is_none());
    // The other's destroy cut short before its holder, its record a step behind.
    h.m.inner.backups.holders.lock().unwrap().remove(&kept.id);
    let listed: u64 = h.listed(&kept.id).await.iter().map(|b| b.bytes).sum();
    let mut kept = kept.clone();
    kept.backup_bytes = listed + 1;
    for r in [gone, &kept] {
        h.m.inner.store.put("machines", &r.id, r).unwrap();
    }
    h.m.load().unwrap();
    h.m.tick().await;
    for r in [gone, &kept] {
        assert!(h.stored(&r.id).is_none());
    }
    assert!(
        h.m.holder(&gone.id).is_none(),
        "no holder for deleted backups"
    );
    let held = h.m.holder(&kept.id).unwrap().rec.lock().unwrap().bytes;
    assert_eq!(held, listed);
}

/// A store that never answers fails a destroy without disks within [`LIST_AT_DESTROY`],
/// rather than after its own retries: the machine stays `destroying`, its lock free again,
/// for the tick to try again.
#[tokio::test(start_paused = true)]
async fn a_store_that_does_not_answer_fails_a_destroy_without_disks_in_time() {
    let mut h = harness(|_| {}).await;
    // Takes connections, never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", silent.local_addr().unwrap());
    let store = ObjectStore::open("s3://b", &endpoint, "", "key", "secret").unwrap();
    Arc::get_mut(&mut h.m.inner).unwrap().backups.store = Some(store);
    let e = h.add("m_s", state::DESTROYING, 256);
    {
        let mut r = e.rec.lock().unwrap();
        r.backup_bytes = 1 << 20;
        r.backup.last = Some("20261028T183459.168Z".into());
    }
    let started = tokio::time::Instant::now();
    let err = h.m.destroy("m_s", None).await.unwrap_err();
    assert!(err.to_string().contains("not listed"), "{err}");
    assert!(started.elapsed() < LIST_AT_DESTROY * 2);
    assert_eq!(h.stored("m_s").unwrap().state, state::DESTROYING);
    assert!(e.lock.try_lock().is_ok());
    assert!(h.m.holder("m_s").is_none());
}

#[tokio::test]
async fn a_destroyed_machine_s_backups_are_listed_counted_then_deleted() {
    let h = harness(|_| {}).await;
    let mut req = h.request("db");
    req.backup = every("1h", 3);
    req.metadata = BTreeMap::from([("briq".to_string(), "bq_1".to_string())]);
    let m = h.m.create_made(req).await.unwrap();
    let first = h.m.backup(&m.id).await.unwrap();
    let second = h.m.backup(&m.id).await.unwrap();
    let bytes = first.bytes + second.bytes;
    let gone = Utc::now();
    h.m.destroy(&m.id, None).await.unwrap();
    assert!(matches!(h.m.get(&m.id), Err(MError::NotFound)));
    // Listed with the tenant's, each saying when it goes.
    let all = h.m.all_backups(Some("t1"), None).await.unwrap();
    assert_eq!(h.ids(&all), vec![first.id.clone(), second.id.clone()]);
    let deletes_at = all[0].deletes_at.unwrap();
    assert!(deletes_at >= gone + chrono::Duration::days(30));
    assert!(deletes_at <= Utc::now() + chrono::Duration::days(30));
    assert_eq!(
        h.m.backups(&m.id).await.unwrap()[1].deletes_at,
        Some(deletes_at)
    );
    assert!(h.m.all_backups(Some("t2"), None).await.unwrap().is_empty());
    assert_eq!(h.m.all_backups(None, None).await.unwrap().len(), 2);
    // Counted in its own buckets, as it was: what its backups take, nothing else.
    let now = Utc::now();
    h.m.measure(now + chrono::Duration::hours(1)).await;
    let from = usage::hour_of(gone).to_rfc3339();
    let to = (usage::hour_of(now) + chrono::Duration::hours(2)).to_rfc3339();
    let mine: Vec<api::UsageBucket> = h
        .buckets(&from, &to)
        .await
        .into_iter()
        .filter(|b| b.machine_id == m.id)
        .collect();
    let gb_hours: f64 = mine.iter().map(|b| b.usage.backup_gb_hours).sum();
    let hour = bytes as f64 / (1u64 << 30) as f64;
    assert!(
        gb_hours >= hour && gb_hours < hour * 1.01,
        "{gb_hours} {hour}"
    );
    let last = mine.last().unwrap();
    assert_eq!(
        (
            last.role.as_deref(),
            last.metadata.get("briq").map(String::as_str)
        ),
        (None, Some("bq_1"))
    );
    assert_eq!(last.usage.root_gb_hours, 0.0);
    // Deleted by request too, and held across a restart of the daemon.
    h.m.delete_backup(&m.id, &second.id, false).await.unwrap();
    assert_eq!(
        h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap()["reason"],
        "request"
    );
    let again = Backups::open(&h.m.inner.cfg.backup, &h.m.inner.store).unwrap();
    let held = again
        .holders
        .lock()
        .unwrap()
        .get(&m.id)
        .map(|x| x.rec.lock().unwrap().bytes);
    assert_eq!(held, Some(first.bytes));
    // `keep_destroyed_days` later, the rest goes, then the holder.
    let days = |n| gone + chrono::Duration::days(n);
    assert_eq!(run(h.m.backup_step(days(29))).await, 0);
    assert_eq!(run(h.m.backup_step(days(31))).await, 1);
    assert!(h.m.all_backups(Some("t1"), None).await.unwrap().is_empty());
    assert!(h.objects(&m.id).await.is_empty());
    assert!(h.m.holder(&m.id).is_none());
    assert!(h
        .m
        .inner
        .store
        .get::<HolderRec>(HOLDERS, &m.id)
        .unwrap()
        .is_none());
    let ev = h.last_of(&m.id, reason::BACKUP_DELETED).data.unwrap();
    assert_eq!(
        (ev["reason"].clone(), ev["backups"].clone()),
        (json!("expired"), json!([first.id]))
    );
    assert!(matches!(
        h.m.delete_backup(&m.id, &first.id, false).await,
        Err(MError::NotFound)
    ));
}

#[tokio::test]
async fn the_routes_delete_and_list() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", Some(None), true).await;
    let first = h.m.backup(&m.id).await.unwrap();
    let second = h.m.backup(&m.id).await.unwrap();
    let st = Arc::new(crate::api::AppState {
        mgr: h.m.clone(),
        token: String::new(),
        metrics_token: String::new(),
        loopback: true,
        openapi: "",
        tls_fingerprint: String::new(),
    });
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1", ln.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
    let http = reqwest::Client::new();
    let list: Vec<api::Backup> = http
        .get(format!("{url}/backups?tenant=t1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 2);
    let delete = |q: &str| {
        http.delete(format!("{url}/machines/{}/backups/{q}", m.id))
            .send()
    };
    let r = delete(&first.id).await.unwrap();
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<api::ApiError>().await.unwrap().code, "conflict");
    let r = delete("20990101T000000.000Z").await.unwrap();
    assert_eq!(r.status(), 404);
    assert!(r
        .json::<api::ApiError>()
        .await
        .unwrap()
        .error
        .contains("20990101T000000.000Z"));
    let of = |q: String| {
        let http = http.clone();
        async move {
            let r = http.get(q).send().await.unwrap();
            assert_eq!(r.status(), 200);
            r.json::<Vec<api::Backup>>().await.unwrap().len()
        }
    };
    assert_eq!(of(format!("{url}/backups?machine={}", m.id)).await, 2);
    assert_eq!(
        of(format!("{url}/backups?tenant=t1&machine=m_other")).await,
        0
    );
    // Two deletes of one chain sent together run one after the other (the machine's turn):
    // the second finds nothing left and answers 404, never 500. A record deleted under a
    // listing is `a_listing_by_machine_reads_that_machine_s_backups_alone`.
    let chain = format!("{}?chain=true", first.id);
    let (a, b) = tokio::join!(delete(&chain), delete(&chain));
    let mut codes = [a.unwrap().status(), b.unwrap().status()];
    codes.sort();
    assert_eq!(codes, [204, 404]);
    assert!(
        h.listed(&m.id).await.is_empty(),
        "{second:?} went with its base"
    );
    for q in ["tenant=../x", "machine=../x"] {
        let r = http.get(format!("{url}/backups?{q}")).send().await.unwrap();
        assert_eq!(r.status(), 400, "{q}");
    }
}

#[tokio::test]
async fn a_listing_by_machine_reads_that_machine_s_backups_alone() {
    let h = harness(|_| {}).await;
    let m = h.machine("db", Some(None), false).await;
    let other = h.machine("web", Some(None), false).await;
    let made = h.m.backup(&m.id).await.unwrap();
    h.m.backup(&other.id).await.unwrap();
    let store = h.m.backup_store().unwrap();
    // A record of a machine this host neither has nor holds: not this host's to list.
    let elsewhere = format!("backups/m_elsewhere/{}.json", made.id);
    let record = serde_json::to_vec(&made).unwrap();
    store.put_bytes(&elsewhere, &record).await.unwrap();
    let mine = h.m.all_backups(None, Some(&m.id)).await.unwrap();
    assert_eq!(h.ids(&mine), vec![made.id.clone()]);
    assert_eq!(h.m.all_backups(None, None).await.unwrap().len(), 2);
    assert!(h
        .m
        .all_backups(None, Some("m_elsewhere"))
        .await
        .unwrap()
        .is_empty());
    assert!(h
        .m
        .all_backups(Some("t2"), Some(&m.id))
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        h.m.all_backups(None, Some("../x")).await,
        Err(MError::Invalid(_))
    ));
    // A record deleted between the list and its read (a deletion under way) is skipped,
    // not a failure of the whole listing.
    let listed = vec![
        format!("backups/{}/{}.json", m.id, made.id),
        format!("backups/{}/20990101T000000.000Z.json", m.id),
    ];
    let read = h.m.read_backups(store, listed).await.unwrap();
    assert_eq!(h.ids(&read), vec![made.id]);
}
