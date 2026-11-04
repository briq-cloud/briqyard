//! Deterministic census boundaries; job integration uses the existing fake-host harness.
use super::*;

const A: &str = "20261103T010000.000Z";
const B: &str = "20261103T020000.000Z";
const C: &str = "20261103T030000.000Z";
fn record(id: &str, from: Option<&str>) -> api::Backup {
    api::Backup {
        copy_consistency: Default::default(),
        id: id.into(),
        machine_id: "m_1".into(),
        namespace: "ns".into(),
        name: "n".into(),
        created_at: Utc::now(),
        bytes: 3,
        incremental: from.is_some(),
        size: None,
        runtime_class: String::new(),
        disks: vec![api::BackupDisk {
            disk: "root".into(),
            key: format!("backups/m_1/root/{id}.zfs"),
            bytes: 3,
            from: from.map(str::to_owned),
        }],
        key_id: None,
        machine: Some(json!({"env": {"PRIVATE": "never-export"}})),
        sealed: None,
        deletes_at: None,
    }
}
fn key(b: &api::Backup) -> String {
    format!("backups/{}/{}.json", b.machine_id, b.id)
}
fn bytes(b: &api::Backup) -> Vec<u8> {
    serde_json::to_vec(b).unwrap()
}
async fn store() -> (tempfile::TempDir, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let store =
        ObjectStore::open(&format!("file://{}", dir.path().display()), "", "", "", "").unwrap();
    (dir, store)
}
async fn put(store: &ObjectStore, b: &api::Backup) {
    store.put_bytes(&b.disks[0].key, b"zfs").await.unwrap();
    store.put_bytes(&key(b), &bytes(b)).await.unwrap();
}
async fn scan(store: &ObjectStore, complete: bool, owner: bool) -> Snapshot {
    let mut list = store.list_bounded("backups", OBJECTS).await.unwrap();
    list.complete &= complete;
    let mut scan = Scan::new(list);
    let objects: Vec<_> = scan.objects.values().cloned().collect();
    for o in objects {
        if matches!(path(&o.key), Some(Path::Record(..))) {
            match store.get_bytes_bounded(&o, RECORD_BYTES).await {
                Ok(data) => scan.record(&o.key, &data, |_, _| owner),
                Err(_) => scan.snapshot.read_failures += 1,
            }
        }
    }
    scan.finish()
}

#[test]
fn strict_paths_records_and_references() {
    let b = record(B, Some(A));
    assert!(parse(&key(&b), &bytes(&b)).is_some());
    for k in [
        "backups//x.json",
        "fleet/registry.json.age",
        "backups/m_1/root/bad.zfs",
        "backups/m_1/../x.json",
        "backups/m_1/20260230T010000.000Z.json",
    ] {
        assert!(path(k).is_none(), "{k}");
    }
    let mutations: [fn(&mut api::Backup); 10] = [
        |b: &mut api::Backup| b.machine_id = "m_foreign".into(),
        |b: &mut api::Backup| b.disks[0].key = "backups/m_foreign/root/x.zfs".into(),
        |b: &mut api::Backup| b.disks[0].disk = "other".into(),
        |b: &mut api::Backup| b.disks[0].from = Some(B.into()),
        |b: &mut api::Backup| b.disks[0].from = Some("../../bad".into()),
        |b: &mut api::Backup| b.disks.push(b.disks[0].clone()),
        |b: &mut api::Backup| b.bytes = u64::MAX,
        |b: &mut api::Backup| b.incremental = false,
        |b: &mut api::Backup| b.key_id = Some("invalid".into()),
        |b: &mut api::Backup| b.sealed = Some("corrupt".into()),
    ];
    for mutate in mutations {
        let mut bad = b.clone();
        mutate(&mut bad);
        assert!(parse(&key(&b), &bytes(&bad)).is_none());
    }
    assert!(parse(&key(&b), b"{broken}").is_none());
    let mut unknown = serde_json::to_value(&b).unwrap();
    unknown["future_authority"] = json!(true);
    assert!(parse(&key(&b), &serde_json::to_vec(&unknown).unwrap()).is_none());
    let duplicate =
        String::from_utf8(bytes(&b))
            .unwrap()
            .replacen("{", "{\"id\":\"duplicate\",", 1);
    assert!(parse(&key(&b), duplicate.as_bytes()).is_none());
}

#[test]
fn records_written_with_the_old_consistency_value_are_valid_and_read_as_unsynced() {
    let b = record(B, Some(A));
    let mut old = serde_json::to_value(&b).unwrap();
    old["consistency"] = json!("crash");
    let parsed = parse(&key(&b), &serde_json::to_vec(&old).unwrap()).expect("old record is valid");
    assert_eq!(parsed.copy_consistency.consistency, "unsynced");
    old["consistency"] = json!("torn");
    assert!(parse(&key(&b), &serde_json::to_vec(&old).unwrap()).is_none());
}

#[tokio::test]
async fn transitive_bases_and_key_or_namespace_mismatches_remain_unresolved() {
    let (_dir, store) = store().await;
    for b in [record(A, None), record(B, Some(A)), record(C, Some(B))] {
        put(&store, &b).await;
    }
    assert_eq!(scan(&store, true, true).await.unresolved_chains, 0);
    // A missing root propagates across both incremental generations.
    store.delete(&record(A, None).disks[0].key).await.unwrap();
    let s = scan(&store, true, true).await;
    assert_eq!(s.missing_streams, 1);
    assert_eq!(s.unresolved_chains, 2);
    put(&store, &record(A, None)).await;
    let mut foreign = record(A, None);
    foreign.namespace = "foreign".into();
    put(&store, &foreign).await;
    assert_eq!(scan(&store, true, true).await.unresolved_chains, 2);
    // A raw base cannot continue as a clear chain, even when both records parse.
    foreign.namespace = "ns".into();
    foreign.machine = None;
    foreign.key_id = Some("0123456789abcdef0123456789abcdef".into());
    use base64::Engine;
    foreign.sealed = Some(base64::engine::general_purpose::STANDARD.encode([0u8; 28]));
    put(&store, &foreign).await;
    assert_eq!(scan(&store, true, true).await.unresolved_chains, 2);
}

#[tokio::test]
async fn publication_foreign_owners_truncation_corruption_and_repeats() {
    let (_dir, store) = store().await;
    let b = record(A, None);
    // Streams precede the record. This is unresolved publication, never an orphan.
    store.put_bytes(&b.disks[0].key, b"zfs").await.unwrap();
    let pending = scan(&store, true, false).await;
    assert_eq!(pending.unreferenced_streams, 1);
    assert_eq!(pending.unresolved_owners, 0);
    put(&store, &b).await;
    let foreign = scan(&store, true, false).await;
    assert_eq!(foreign.unresolved_owners, 1);
    assert_eq!(scan(&store, true, false).await, foreign); // gauges replace; never accumulate
    let local = scan(&store, true, true).await;
    assert_eq!(local.local_owners, 1);
    assert_eq!(local.unresolved_owners, 0);
    assert!(!scan(&store, false, true).await.metadata_complete);
    store
        .put_bytes(&b.disks[0].key, b"shorter-or-longer")
        .await
        .unwrap();
    assert_eq!(scan(&store, true, true).await.size_mismatches, 1);
    store.put_bytes(&key(&b), b"invalid-json").await.unwrap();
    let corrupt = scan(&store, true, true).await;
    assert_eq!(corrupt.malformed, 1);
    assert!(!corrupt.metadata_complete);
    let mut out = String::new();
    crate::metrics::backup_census::render(&mut out, &local);
    assert!(out.contains("briqyard_backup_census_global_ownership_qualified 0"));
    assert!(out.contains("briqyard_backup_census_deletion_qualified 0"));
    for secret in [
        "never-export",
        "m_1",
        "PRIVATE",
        "backups/",
        "key_id=",
        "namespace=",
    ] {
        assert!(
            !out.contains(secret),
            "census metrics must omit sensitive fixture values"
        );
    }
}

#[test]
fn periods_unsettled_attempts_and_stale_cache_never_imply_completeness() {
    let now = Instant::now();
    let mut c = Cache {
        next: Some(now + PERIOD),
        observation: Snapshot::default(),
    };
    assert!(!c.reserve(now)); // no startup burst
    assert!(c.reserve(now + PERIOD));
    assert!(!c.reserve(now + PERIOD));
    assert!(!c.observation.metadata_complete); // cancellation/unsettled remains unknown
    assert!(c.reserve(now + 2 * PERIOD));
    let s = Snapshot {
        finished_at: 1,
        metadata_complete: true,
        enumeration_complete: true,
        ..Snapshot::default()
    };
    assert!(fresh(s, 1).metadata_complete);
    assert!(!fresh(s, 0).metadata_complete);
    assert!(!fresh(s, 2 + (2 * PERIOD.as_secs()) as i64).metadata_complete);
}

#[test]
fn aggregate_metadata_budget_includes_failed_and_empty_reads() {
    let mut budget = MetadataBudget(2 * (RECORD_BYTES + 1));
    assert_eq!(budget.reserve(RECORD_BYTES as u64 + 1), None);
    for _ in 0..2 {
        assert_eq!(budget.reserve(RECORD_BYTES as u64), Some(RECORD_BYTES));
    }
    assert_eq!(budget.reserve(1), None);
    assert_eq!(budget.reserve(0), None);
    let mut empty = MetadataBudget(2);
    assert_eq!(empty.reserve(0), Some(1));
    assert_eq!(empty.reserve(0), None);
}

#[tokio::test]
async fn admitted_census_outlives_waiter_and_participates_in_shutdown_until_timeout() {
    use super::super::tests::harness;
    let h = harness(|b| b.at_once = 1).await;
    let backups = &h.m.inner.backups;
    {
        let _cache = backups.census.state.lock().unwrap();
        assert_eq!(h.m.backup_census_observation(), Snapshot::default());
    }
    let reads = backups
        .reads
        .acquire_many(READS_AT_ONCE as u32)
        .await
        .unwrap();
    let turn = backups.census.turn.clone().lock_owned().await;
    let admission = backups.jobs.try_reserve().unwrap();
    tokio::time::pause();
    let ticket = backups
        .jobs
        .start(h.m.clone(), jobs::Work::Census, turn, admission)
        .unwrap();
    // Losing its observer must not cancel the retained census.
    drop(ticket);
    tokio::task::yield_now().await;
    assert_eq!(backups.jobs.pending(), 1);
    assert!(backups.census.turn.clone().try_lock_owned().is_err());
    h.m.close_backup_admission();
    assert!(backups.jobs.try_reserve().is_none());
    assert!(tokio::time::timeout(Duration::ZERO, h.m.drain_backups())
        .await
        .is_err());
    tokio::time::advance(RUNTIME + Duration::from_secs(1)).await;
    tokio::time::timeout(Duration::from_secs(1), h.m.drain_backups())
        .await
        .unwrap();
    assert_eq!(backups.jobs.pending(), 0);
    assert!(backups.census.turn.clone().try_lock_owned().is_ok());
    let s = h.m.backup_census_observation();
    assert!(s.failed);
    assert!(!s.enumeration_complete && !s.metadata_complete);
    assert!(s.finished_at > 0);
    drop(reads);
    tokio::time::resume();
}

#[tokio::test]
async fn retained_holder_and_disconnected_job_are_positive_local_observations_only() {
    use super::super::tests::harness;
    let h = harness(|b| b.at_once = 2).await;
    let machine = h.machine("owner", None, false).await;
    let entry = h.m.entry(&machine.id).unwrap();
    let rec = entry.snapshot();
    assert!(h.m.observed_backup_owner(&machine.id, &rec.namespace));
    assert!(!h.m.observed_backup_owner(&machine.id, "foreign"));
    h.m.hold(&rec, 3, entry.backup_turn.clone()).unwrap();
    // Remove only this test's in-memory active entry; the durable retained holder owns it.
    h.m.inner.machines.lock().unwrap().remove(&machine.id);
    assert!(h.m.observed_backup_owner(&machine.id, &rec.namespace));
    let backups = &h.m.inner.backups;
    let active = backups.gate.clone().acquire_many_owned(2).await.unwrap();
    let holder = h.m.holder(&machine.id).unwrap();
    let turn = holder.turn.clone().lock_owned().await;
    let admission = backups.jobs.try_reserve().unwrap();
    let ticket = backups
        .jobs
        .start(h.m.clone(), jobs::Work::Expire(holder), turn, admission)
        .unwrap();
    drop(ticket);
    backups.holders.lock().unwrap().remove(&machine.id);
    assert!(backups.jobs.has_owner(&machine.id, &rec.namespace));
    assert!(h.m.observed_backup_owner(&machine.id, &rec.namespace));
    assert!(!h.m.observed_backup_owner(&machine.id, "foreign"));
    h.m.close_backup_admission();
    drop(active);
    tokio::time::timeout(Duration::from_secs(15), h.m.drain_backups())
        .await
        .unwrap();
    assert!(!backups.jobs.has_owner(&machine.id, &rec.namespace));
    assert!(!h.m.observed_backup_owner(&machine.id, &rec.namespace));
}

#[tokio::test]
async fn busy_backup_gate_skips_census_without_waiting_or_claiming_coverage() {
    use super::super::tests::harness;
    let h = harness(|b| b.at_once = 1).await;
    let backups = &h.m.inner.backups;
    let _gate = backups.gate.clone().acquire_owned().await.unwrap();
    let turn = backups.census.turn.clone().lock_owned().await;
    let admission = backups.jobs.try_reserve().unwrap();
    let ticket = backups
        .jobs
        .start(h.m.clone(), jobs::Work::Census, turn, admission)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), ticket.finished())
        .await
        .unwrap();
    assert_eq!(backups.jobs.pending(), 0);
    assert_eq!(h.m.backup_census_observation(), Snapshot::default());
    assert!(backups.census.turn.clone().try_lock_owned().is_ok());
}

#[tokio::test]
async fn repeated_listing_keys_never_qualify_exhaustion() {
    let (_dir, store) = store().await;
    put(&store, &record(A, None)).await;
    let mut list = store.list_bounded("backups", OBJECTS).await.unwrap();
    list.objects.push(list.objects[0].clone());
    let s = Scan::new(list).finish();
    assert!(!s.enumeration_complete && !s.metadata_complete);
    assert_eq!(s.malformed, 1);
}

#[tokio::test]
async fn overlapping_retained_job_invalidates_coverage_even_for_an_empty_store() {
    use super::super::tests::harness;
    let h = harness(|b| b.at_once = 2).await;
    let machine = h.machine("overlap", None, false).await;
    let entry = h.m.entry(&machine.id).unwrap();
    h.m.hold(&entry.snapshot(), 0, entry.backup_turn.clone())
        .unwrap();
    let holder = h.m.holder(&machine.id).unwrap();
    let backups = &h.m.inner.backups;
    let reads = backups
        .reads
        .acquire_many(READS_AT_ONCE as u32)
        .await
        .unwrap();
    let census = backups
        .jobs
        .start(
            h.m.clone(),
            jobs::Work::Census,
            backups.census.turn.clone().lock_owned().await,
            backups.jobs.try_reserve().unwrap(),
        )
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(backups.gate.available_permits(), 1);
    let turn = holder.turn.clone().lock_owned().await;
    let expiry = backups
        .jobs
        .start(
            h.m.clone(),
            jobs::Work::Expire(holder),
            turn,
            backups.jobs.try_reserve().unwrap(),
        )
        .unwrap();
    drop(census);
    drop(expiry);
    h.m.close_backup_admission();
    drop(reads);
    tokio::time::timeout(Duration::from_secs(15), h.m.drain_backups())
        .await
        .unwrap();
    let s = h.m.backup_census_observation();
    assert!(s.local_activity);
    assert!(!s.enumeration_complete && !s.metadata_complete);
}
