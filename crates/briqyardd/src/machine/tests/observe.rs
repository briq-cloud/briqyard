//! Tests of what the manager reports: metrics, conditions, storage, top, logs.

use super::*;

// --- metrics, conditions, top (ADR 0021) ---

#[tokio::test]
async fn metrics_hold_every_machine_by_its_labels_from_the_last_measure() {
    let h = harness("10.64.0.0/22", 4096).await;
    let run = h.metered("m_run", state::RUNNING, "2026-10-21T10:00:00Z");
    let gw = h.metered("m_gw", state::RUNNING, "2026-10-21T10:00:00Z");
    let _stopped = h.metered("m_stop", state::STOPPED, "2026-10-21T10:00:00Z");
    let _broken = h.metered("m_err", state::ERROR, "2026-10-21T10:00:00Z");
    for (e, name, ip) in [(&run, "db", "10.64.1.2"), (&gw, "gateway", "10.64.1.3")] {
        let mut r = e.rec.lock().unwrap();
        r.name = name.into();
        r.ip = ip.into();
    }
    gw.rec.lock().unwrap().role = Some(Role::Gateway);
    h.m.inner.net.count("10.64.1.2").await.unwrap();
    h.pool.answer(
        "space",
        "byard/m/m_run\t-\t4096\t0\nbyard/m/m_run/root\t8589934592\t52428800\t1048576\n",
    );
    h.pool.answer("used,available", "950\n50\n");
    h.host.cpu("m_run", 2_000_000);
    h.m.measure(at("2026-10-21T10:00:15Z")).await;
    h.host.cpu("m_run", 4_500_000);
    h.host.memory("m_run", 100 << 20);
    h.host.internet("10.64.1.2", 1000, 10);
    h.m.traffic("m_run").unwrap().sent(300);
    h.m.measure(at("2026-10-21T10:00:30Z")).await;
    h.m.assess(at("2026-10-21T10:00:30Z")).await;
    // A start's time is measured from `starting` to `running`.
    run.set_state(state::STARTING, |_| None);
    run.set_state(state::RUNNING, |_| None);
    let text = h.m.metrics();
    briqyard_api::metrics::check_exposition(&text);
    let lines: Vec<&str> = text.lines().collect();
    let db = r#"machine="m_run",namespace="t1",name="db""#;
    for want in [
        format!("briqyard_machine_cpu_seconds_total{{{db}}} 2.5"),
        format!("briqyard_machine_memory_bytes{{{db}}} 104857600"),
        format!("briqyard_machine_memory_limit_bytes{{{db}}} 536870912"),
        format!("briqyard_machine_disk_used_bytes{{{db}}} 53481472"),
        format!("briqyard_machine_internet_in_bytes_total{{{db}}} 1000"),
        format!("briqyard_machine_internet_out_bytes_total{{{db}}} 10"),
        format!("briqyard_machine_ingress_out_bytes_total{{{db}}} 300"),
        format!("briqyard_machine_egress_dropped_packets_total{{{db}}} 0"),
        format!("briqyard_machine_restarts_total{{{db}}} 0"),
        format!("briqyard_machine_state{{{db},state=\"running\"}} 1"),
        r#"briqyard_machine_state{machine="m_gw",namespace="t1",name="gateway",role="gateway",state="running"} 1"#.into(),
        r#"briqyard_machine_state{machine="m_err",namespace="t1",name="db",state="error"} 1"#.into(),
        r#"briqyard_machine_state{machine="m_stop",namespace="t1",name="db",state="stopped"} 1"#.into(),
        // The host's, the names from before included.
        r#"briqyard_machines{state="running"} 2"#.into(),
        "briqyard_machines_total 4".into(),
        r#"briqyard_memory_mb{kind="used"} 1536"#.into(),
        r#"briqyard_pool_bytes{kind="size"} 1000"#.into(),
        r#"briqyard_pool_bytes{kind="free"} 50"#.into(),
        r#"briqyard_host_condition{condition="memory_pressure"} 0"#.into(),
        r#"briqyard_host_condition{condition="disk_pressure"} 1"#.into(),
        r#"briqyard_events_total{type="warning",reason="host_condition"} 1"#.into(),
        "briqyard_boots_total 0".into(),
    ] {
        assert!(lines.contains(&want.as_str()), "{want}\n{text}");
    }
    // One state series per machine; a boot time only once a start was measured.
    let states = lines
        .iter()
        .filter(|l| l.starts_with(r#"briqyard_machine_state{machine="m_run""#))
        .count();
    assert_eq!(states, 1);
    let boots: Vec<&&str> = lines
        .iter()
        .filter(|l| l.starts_with("briqyard_machine_boot_seconds{"))
        .collect();
    assert_eq!(boots.len(), 1, "{boots:?}");
    assert!(boots[0].starts_with(&format!("briqyard_machine_boot_seconds{{{db}}} ")));
    // A scrape asks nothing of the host: no zfs call, no cgroup read.
    h.pool.calls();
    h.host.cgroups.lock().unwrap().clear();
    let again = h.m.metrics();
    assert!(h.pool.calls().is_empty());
    assert!(again.contains(&format!("briqyard_machine_memory_bytes{{{db}}} 104857600")));
}

impl Harness {
    /// The host's events of a reason, oldest first.
    fn host_events(&self, reason: &str) -> Vec<api::Event> {
        let all = self.m.inner.events.read(0, &Default::default(), 5000);
        all.unwrap()
            .events
            .into_iter()
            .filter(|e| e.reason == reason)
            .collect()
    }
}

#[tokio::test]
async fn conditions_turn_true_and_clear_with_their_events() {
    let h = harness("10.64.0.0/22", 1000).await;
    h.pool.answer("used,available", "100\n900\n");
    let e = h.add("m_a", state::RUNNING, 960);
    let t0 = at("2026-10-21T10:00:00Z");
    h.m.assess(t0).await;
    let c = h.m.conditions();
    assert_eq!(
        (c[0].kind.as_str(), c[0].status, c[0].since),
        ("memory_pressure", true, t0)
    );
    assert_eq!(c[0].message, "1216 MB of 1000 committed (121%), over 95%");
    assert!(!c[1].status, "{:?}", c[1]);
    let evs = h.host_events(reason::HOST_CONDITION);
    assert_eq!(evs.len(), 1, "only a change is an event: {evs:?}");
    assert_eq!(
        (evs[0].kind.as_str(), evs[0].message.as_str()),
        (
            "warning",
            "memory_pressure: 1216 MB of 1000 committed (121%), over 95%"
        )
    );
    assert_eq!(
        evs[0].data,
        Some(json!({"condition": "memory_pressure", "status": true}))
    );
    // Still true at the next tick: no event, the time it turned kept.
    h.m.assess(t0 + chrono::Duration::seconds(15)).await;
    assert_eq!(h.host_events(reason::HOST_CONDITION).len(), 1);
    assert_eq!(h.m.conditions()[0].since, t0);
    // The machine stops: cleared, a normal event.
    e.set_state(state::STOPPED, |_| None);
    let t1 = t0 + chrono::Duration::seconds(30);
    h.m.assess(t1).await;
    let evs = h.host_events(reason::HOST_CONDITION);
    assert_eq!(
        (evs[1].kind.as_str(), evs[1].message.as_str()),
        (
            "normal",
            "memory_pressure cleared: 0 MB of 1000 committed (0%)"
        )
    );
    assert_eq!(h.m.conditions()[0].since, t1);
    // The pool fills: disk pressure; a pool that cannot be read leaves it as it was.
    h.pool.answer("used,available", "950\n50\n");
    h.m.assess(t1).await;
    assert!(h.m.conditions()[1].status);
    assert_eq!(
        h.host_events(reason::HOST_CONDITION)[2].message,
        "disk_pressure: pool 0.0 GB free of 0.0 (5%), under 10%"
    );
    h.pool.answer("used,available", "-\n");
    h.m.assess(t1).await;
    assert!(h.m.conditions()[1].status, "kept");
    assert_eq!(h.host_events(reason::HOST_CONDITION).len(), 3);
}

/// An exec as the guest exits (a fork whose command ends at once): Firecracker's socket
/// refuses, which is a machine not running, 409, not an internal error.
#[test]
fn a_guest_that_cannot_be_reached_is_not_running() {
    let refused = guestc::Unreachable("vsock /x/vsock.sock: Connection refused".into());
    let err = not_running_if_unreachable(refused.into());
    assert!(
        matches!(&err, MError::NotRunning(m) if m.ends_with("Connection refused")),
        "{err:?}"
    );
    let other = not_running_if_unreachable(anyhow!("frame too large"));
    assert!(matches!(other, MError::Other(_)));
}

/// A `zfs` command that does not come back (ADR 0046): `storage_stalled` while it runs,
/// decided apart from the tick it holds, and cleared once it exits.
#[tokio::test]
async fn a_stuck_zfs_command_is_storage_stalled_until_it_exits() {
    let h = harness("10.64.0.0/22", 1000).await;
    let t0 = at("2026-10-28T18:44:47Z");
    h.m.assess_storage(Duration::ZERO, t0);
    assert!(!h.m.conditions()[2].status);
    let hold = h.pool.dev().join("hold.snapshot");
    std::fs::write(&hold, "").unwrap();
    let z = h.pool.zfs.clone();
    let snap = tokio::spawn(async move { z.snapshot("m/x/root", "fork-y").await });
    while h.pool.zfs.stalled(Duration::ZERO).is_none() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.m.assess_storage(Duration::ZERO, t0);
    let c = &h.m.conditions()[2];
    assert_eq!(
        (c.kind.as_str(), c.status, c.since),
        ("storage_stalled", true, t0)
    );
    assert!(
        c.message
            .starts_with("zfs snapshot byard/m/x/root@fork-y running for "),
        "{}",
        c.message
    );
    let evs = h.host_events(reason::HOST_CONDITION);
    assert_eq!(evs.len(), 1);
    assert!(evs[0].message.starts_with("storage_stalled: zfs snapshot"));
    std::fs::remove_file(&hold).unwrap();
    let _ = snap.await.unwrap();
    let t1 = t0 + chrono::Duration::seconds(15);
    h.m.assess_storage(Duration::ZERO, t1);
    let c = &h.m.conditions()[2];
    assert_eq!((c.status, c.since), (false, t1));
    assert_eq!(c.message, "no zfs command running for over 60 s");
}

#[tokio::test]
async fn under_disk_pressure_the_oldest_unused_images_go_until_the_pool_is_back() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // The seeded image is cloned by a machine; then four more, oldest first.
    h.m.create_made(h.request("web")).await.unwrap();
    let mut keys = vec![];
    for n in 2..=5 {
        let r = format!("alpine@sha256:{n:064}");
        let im =
            h.m.inner
                .images
                .seed(&r, ImageConfig::default())
                .await
                .unwrap();
        keys.push(im.key);
    }
    // The oldest of them is named by a record whose disk is not made yet.
    h.add("m_new", state::CREATED, 256)
        .rec
        .lock()
        .unwrap()
        .image_key = keys[0].clone();
    // 8 GB free of 100: 2 GB short of 10%; each image takes 1 GB.
    let gb = 1u64 << 30;
    h.pool
        .answer("used,available", &format!("{}\n{}\n", 92 * gb, 8 * gb));
    h.pool.answer("used", &format!("{gb}\n"));
    h.m.assess(Utc::now()).await;
    let left: Vec<String> =
        h.m.images()
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.key)
            .collect();
    assert_eq!(left.len(), 3, "{left:?}");
    assert!(
        left.contains(&keys[0]) && left.contains(&keys[3]),
        "{left:?}"
    );
    assert!(
        !left.contains(&keys[1]) && !left.contains(&keys[2]),
        "{left:?}"
    );
    let gone: Vec<(String, String)> = h
        .host_events(reason::IMAGE_REMOVED)
        .into_iter()
        .map(|e| {
            let d = e.data.unwrap();
            (
                d["key"].as_str().unwrap().into(),
                d["reason"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        gone,
        [
            (keys[1].clone(), "disk_pressure".into()),
            (keys[2].clone(), "disk_pressure".into())
        ]
    );
    // Back over the threshold: nothing more goes.
    h.pool
        .answer("used,available", &format!("{}\n{}\n", 80 * gb, 20 * gb));
    h.m.assess(Utc::now()).await;
    assert_eq!(h.m.images().await.unwrap().len(), 3);
    // The age rule says so too, and a removal on request.
    assert_eq!(h.m.gc_images(chrono::Duration::zero()).await, 2);
    let reasons: Vec<String> = h
        .host_events(reason::IMAGE_REMOVED)
        .into_iter()
        .map(|e| e.data.unwrap()["reason"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(reasons[2..], ["unused", "unused"]);
}

#[tokio::test]
async fn top_takes_its_rates_from_the_last_two_ticks() {
    let h = harness("10.64.0.0/22", 4096).await;
    let a = h.metered("m_a", state::RUNNING, "2026-10-21T10:00:00Z");
    let b = h.metered("m_b", state::STOPPED, "2026-10-21T10:00:00Z");
    b.rec.lock().unwrap().ip = "10.64.1.3".into();
    h.m.inner.net.count("10.64.1.2").await.unwrap();
    h.host.cpu("m_a", 1_000_000);
    h.host.memory("m_a", 64 << 20);
    h.host.internet("10.64.1.2", 100, 10);
    h.m.measure(at("2026-10-21T10:00:00Z")).await;
    // One measure: no window yet.
    let t = h.m.top(None);
    assert_eq!((t.len(), t[0].window_sec, t[0].cpu_percent), (1, 0.0, 0.0));
    h.host.cpu("m_a", 4_000_000);
    h.host.internet("10.64.1.2", 1500, 30);
    let tr = h.m.traffic("m_a").unwrap();
    tr.received(30);
    tr.sent(300);
    h.m.measure(at("2026-10-21T10:00:15Z")).await;
    let t = h.m.top(None);
    assert_eq!(
        t,
        vec![api::TopMachine {
            machine_id: "m_a".into(),
            namespace: "t1".into(),
            name: "db".into(),
            role: None,
            cpu_percent: 20.0,
            memory_bytes: 64 << 20,
            memory_limit_bytes: 512 << 20,
            disk_used_bytes: 0,
            internet_in_bytes_per_sec: 100.0,
            internet_out_bytes_per_sec: 2.0,
            ingress_in_bytes_per_sec: 2.0,
            ingress_out_bytes_per_sec: 20.0,
            window_sec: 15.0,
            host: String::new(),
        }],
        "running machines only"
    );
    assert!(h.m.top(Some("t2")).is_empty());
    assert_eq!(h.m.top(Some("t1")).len(), 1);
    drop(a);
}

#[tokio::test]
async fn logs_read_across_the_rotated_console() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.add("m_a", state::RUNNING, 256);
    let dir = h.m.inner.cfg.run_dir().join("m_a");
    std::fs::create_dir_all(&dir).unwrap();
    let line = |s: &str| format!("2026-10-21T10:00:00.000000Z {s}\n");
    let (one, two) = (line("one"), line("two"));
    // `two` rotated away once: the previous file starts at 1000 in the console.
    std::fs::write(dir.join("console.1000.log"), &one).unwrap();
    std::fs::write(dir.join("console.log"), &two).unwrap();
    let page = h.m.logs("m_a", "", 10).unwrap();
    let got: Vec<&str> = page.lines.iter().map(|l| l.line.as_str()).collect();
    assert_eq!(got, ["one", "two"]);
    let end = 1000 + (one.len() + two.len()) as u64;
    assert_eq!(page.next, end.to_string());
    // A cursor in the current file, and one past the end.
    let mid = (1000 + one.len()).to_string();
    assert_eq!(h.m.logs("m_a", &mid, 10).unwrap().lines.len(), 1);
    let after = h.m.logs("m_a", &end.to_string(), 10).unwrap();
    assert_eq!((after.lines.len(), after.next), (0, end.to_string()));
}

// --- labels, quotas and logs follow (ADR 0025) ---

#[tokio::test]
async fn a_listing_selects_by_labels_all_of_them() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let labelled = |name: &str, labels: &[(&str, &str)]| {
        let mut req = h.request(name);
        req.start = Some(false);
        req.metadata = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        req
    };
    let web =
        h.m.create_made(labelled("web", &[("app", "web"), ("tier", "front")]))
            .await
            .unwrap();
    let db =
        h.m.create_made(labelled("db", &[("app", "db")]))
            .await
            .unwrap();
    h.m.create_made(labelled("bare", &[])).await.unwrap();
    let ids = |namespace: Option<&str>, sel: &[&str]| -> Vec<String> {
        let sel: Vec<api::Label> = sel.iter().map(|s| api::Label::parse(s).unwrap()).collect();
        h.m.list(namespace, &sel)
            .into_iter()
            .map(|m| m.id)
            .collect()
    };
    assert_eq!(ids(None, &["app=web"]), [web.id.as_str()]);
    assert_eq!(ids(Some("t1"), &["app"]), [web.id.clone(), db.id.clone()]);
    assert_eq!(ids(None, &["app=web", "tier=front"]), [web.id.as_str()]);
    assert!(
        ids(None, &["app=db", "tier"]).is_empty(),
        "every one must match"
    );
    assert!(ids(Some("t2"), &["app"]).is_empty());
    assert_eq!(ids(None, &[]).len(), 3);
}

/// The next line of a follow, as JSON, within five seconds.
async fn followed(rx: &mut tokio::sync::mpsc::Receiver<String>) -> serde_json::Value {
    let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("a line in time")
        .expect("the follow is open");
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn logs_follow_sends_what_is_there_then_each_line_across_a_rotation_until_destroyed() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let dir = h.m.inner.cfg.run_dir().join(&m.id);
    // The daemon's writer of the console, rotating every two lines.
    let mut w = console::Writer::open(&dir, 64).await.unwrap();
    let ts = "2026-10-21T10:00:00.000000Z";
    w.line(ts, b"before").await.unwrap();
    let from = h.m.logs(&m.id, "", 500).unwrap();
    assert!(matches!(
        h.m.follow_logs("m_nope", "", tokio::sync::mpsc::channel(1).0),
        Err(MError::NotFound)
    ));
    assert!(matches!(
        h.m.follow_logs(&m.id, "x", tokio::sync::mpsc::channel(1).0),
        Err(MError::Invalid(_))
    ));
    // From the start: the lines there, the last one written before the follow.
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    h.m.follow_logs(&m.id, "", tx).unwrap();
    let mut got = vec![];
    for _ in 0..from.lines.len() {
        got.push(
            followed(&mut rx).await["line"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    assert_eq!(got.last().map(String::as_str), Some("before"));
    // From a cursor: only what comes after it, each line as the writer writes it, in the
    // paged answer's shape, across the rotations.
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    h.m.follow_logs(&m.id, &from.next, tx).unwrap();
    for i in 0..5 {
        w.line(ts, format!("line {i}").as_bytes()).await.unwrap();
        let l = followed(&mut rx).await;
        assert_eq!(
            l,
            json!({"ts": "2026-10-21T10:00:00Z", "line": format!("line {i}")})
        );
    }
    let rotated = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name().to_string_lossy().starts_with("console.")
                && e.file_name() != "console.log"
        });
    assert!(rotated, "the console rotated under the follow");
    // Destroyed: a last line says so, and the stream ends.
    drop(w);
    h.m.destroy(&m.id, None).await.unwrap();
    let last = followed(&mut rx).await;
    assert_eq!(last["code"], "destroyed");
    assert_eq!(
        last["error"],
        format!("machine {} was destroyed; its console went with it", m.id)
    );
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn a_quiet_follow_sends_a_heartbeat_and_ends_with_the_daemon() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.add("m_a", state::CREATED, 256);
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    // No console yet: nothing to send until a line is written.
    h.m.follow_logs("m_a", "", tx).unwrap();
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(events::HEARTBEAT + Duration::from_secs(1)).await;
    assert_eq!(followed(&mut rx).await, json!({}));
    h.m.inner.events.close();
    let last = followed(&mut rx).await;
    assert_eq!(last["code"], "shutdown");
    assert!(last["error"]
        .as_str()
        .unwrap()
        .ends_with("follow again from since=0"));
    assert!(rx.recv().await.is_none());
}
