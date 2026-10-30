//! Failed backups, destroyed machines' holders and the routes.

use super::*;

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
    // Listed with the namespace's, each saying when it goes.
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
        .get(format!("{url}/backups?namespace=t1"))
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
        of(format!("{url}/backups?namespace=t1&machine=m_other")).await,
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
    for q in ["namespace=../x", "machine=../x"] {
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

#[tokio::test]
async fn listings_report_the_backups_size_without_exposing_its_machine() {
    let h = harness(|_| {}).await;
    let m = h.machine("sized", Some(None), false).await;
    let made = h.m.backup(&m.id).await.unwrap();
    assert_eq!(made.size, Some(m.size));
    let listed = h.m.backups(&m.id).await.unwrap();
    assert_eq!(listed[0].size, Some(m.size));
    assert!(listed[0].machine.is_none() && listed[0].sealed.is_none());
    let store = h.m.backup_store().unwrap();
    let path = format!("backups/{}/{}.json", m.id, made.id);
    let mut record: api::Backup =
        serde_json::from_slice(&store.get_bytes(&path).await.unwrap()).unwrap();
    // An older clear record can supply its captured size. Never substitute the live size.
    record.size = None;
    record.sealed = None;
    record.key_id = None;
    record.machine = Some(
        serde_json::json!({"size":{"vcpus":1,"memory_mb":128,"cpu_millis":250},"env":{"TOKEN":"private"}}),
    );
    store
        .put_bytes(&path, &serde_json::to_vec(&record).unwrap())
        .await
        .unwrap();
    let listed = h.m.backups(&m.id).await.unwrap();
    assert_eq!(listed[0].size.as_ref().unwrap().cpu_millis(), 250);
    assert!(listed[0].machine.is_none());
    // Older sealed records need an explicit restore size through the fleet.
    record.machine = None;
    record.sealed = Some("unopened".into());
    store
        .put_bytes(&path, &serde_json::to_vec(&record).unwrap())
        .await
        .unwrap();
    let listed = h.m.backups(&m.id).await.unwrap();
    assert!(listed[0].size.is_none() && listed[0].sealed.is_none());
}
