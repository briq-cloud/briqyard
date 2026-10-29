//! Tests of the usage buckets and the metrics' access.

use super::*;

pub(in crate::machine) const GB: f64 = (1u64 << 30) as f64;

impl Harness {
    /// A machine as `add` makes it (512 MB), its usage accrued up to `since`.
    pub(super) fn metered(&self, id: &str, state: &str, since: &str) -> Arc<Entry> {
        let e = self.add(id, state, 512);
        e.meter.lock().unwrap().at = at(since);
        e
    }

    /// The buckets of `[from, to)`.
    pub(in crate::machine) async fn buckets(&self, from: &str, to: &str) -> Vec<api::UsageBucket> {
        self.m.usage_buckets(at(from), at(to), None).await.unwrap()
    }

    /// The bucket of a machine in an hour.
    pub(super) async fn bucket(&self, id: &str, hour: &str) -> api::UsageBucket {
        let next = (at(hour) + chrono::Duration::hours(1)).to_rfc3339();
        let all = self.buckets(hour, &next).await;
        all.into_iter()
            .find(|b| b.machine_id == id)
            .unwrap_or_else(|| panic!("no bucket of {id} at {hour}"))
    }
}

#[tokio::test]
async fn a_machine_running_across_an_hour_has_two_buckets_that_split_its_seconds() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.metered("m_a", state::RUNNING, "2026-10-20T13:59:50Z");
    h.m.measure(at("2026-10-20T14:00:20Z")).await;
    let bs = h
        .buckets("2026-10-20T13:00:00Z", "2026-10-20T15:00:00Z")
        .await;
    let got: Vec<(DateTime<Utc>, f64, bool)> = bs
        .iter()
        .map(|b| (b.hour, b.usage.running_seconds, b.closed))
        .collect();
    assert_eq!(
        got,
        [
            (at("2026-10-20T13:00:00Z"), 10.0, true),
            (at("2026-10-20T14:00:00Z"), 20.0, false)
        ]
    );
    assert_eq!(bs[1].usage.memory_mb_seconds, 512.0 * 20.0);
    let b = &bs[0];
    assert_eq!(
        (
            b.machine_id.as_str(),
            b.namespace.as_str(),
            &b.role,
            b.size.memory_mb
        ),
        ("m_a", "t1", &None, 512)
    );
    // The hour that is over is on disk, closed; the open one is written too.
    let closed: Vec<api::UsageBucket> =
        h.m.inner
            .store
            .get("usage", "2026-10-20T13")
            .unwrap()
            .unwrap();
    assert!(closed[0].closed);
    let open: Vec<api::UsageBucket> =
        h.m.inner
            .store
            .get("usage", "2026-10-20T14")
            .unwrap()
            .unwrap();
    assert!(!open[0].closed);
}

#[tokio::test]
async fn a_state_change_accrues_the_time_in_the_old_state() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_a", state::RUNNING, 512);
    let t0 = Utc::now() - chrono::Duration::seconds(30);
    e.meter.lock().unwrap().at = t0;
    e.set_state(state::STOPPED, |_| None);
    // A minute later, the tick finds it stopped: the 30 s before the stop ran, the
    // minute after did not.
    h.m.measure(Utc::now() + chrono::Duration::seconds(60))
        .await;
    let (from, to) = (
        usage::hour_of(t0),
        usage::hour_of(Utc::now()) + chrono::Duration::hours(2),
    );
    let ran: f64 =
        h.m.usage_buckets(from, to, None)
            .await
            .unwrap()
            .iter()
            .map(|b| b.usage.running_seconds)
            .sum();
    assert!((30.0..31.0).contains(&ran), "{ran}");
}

#[tokio::test]
async fn cpu_counts_what_the_cgroup_grew_by_and_a_reset_adds_all() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
    // Running before this daemon: its first reading is where the count starts.
    h.host.cpu("m_a", 50_000_000);
    h.m.measure(at("2026-10-20T14:00:15Z")).await;
    h.host.cpu("m_a", 52_500_000);
    h.m.measure(at("2026-10-20T14:00:30Z")).await;
    // A new cgroup reads smaller: all of it is new.
    h.host.cpu("m_a", 1_000_000);
    h.m.measure(at("2026-10-20T14:00:45Z")).await;
    let b = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
    assert_eq!(b.usage.cpu_seconds, 3.5);
}

#[tokio::test]
async fn a_suspended_machine_counts_suspended_seconds_and_its_memory_snapshot() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.metered("m_s", state::STOPPED, "2026-10-20T14:00:00Z");
    e.rec.lock().unwrap().suspended = true;
    let dir = h.m.inner.cfg.run_dir().join("m_s");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("snap.mem"), vec![1u8; 1 << 20]).unwrap();
    h.m.measure(at("2026-10-20T14:10:00Z")).await;
    let u = h.bucket("m_s", "2026-10-20T14:00:00Z").await.usage;
    assert_eq!(
        (u.suspended_seconds, u.running_seconds, u.memory_mb_seconds),
        (600.0, 0.0, 0.0)
    );
    let bytes = usage::file_bytes(&[dir.join("snap.mem")]);
    assert!(bytes >= 1 << 20, "{bytes}");
    assert_eq!(u.snapshot_gb_hours, bytes as f64 / GB * 600.0 / 3600.0);
    // Resumed, the snapshot is gone: running, and nothing suspended any more.
    std::fs::remove_file(dir.join("snap.mem")).unwrap();
    {
        let mut r = e.rec.lock().unwrap();
        (r.state, r.suspended) = (state::RUNNING.into(), false);
    }
    h.m.measure(at("2026-10-20T14:11:00Z")).await;
    let u = h.bucket("m_s", "2026-10-20T14:00:00Z").await.usage;
    assert_eq!((u.suspended_seconds, u.running_seconds), (600.0, 60.0));
}

#[tokio::test]
async fn a_stopped_machine_counts_its_disks_and_no_compute() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.metered("m_d", state::STOPPED, "2026-10-20T14:00:00Z");
    e.rec.lock().unwrap().backup_bytes = 3 << 30;
    h.host.cpu("m_d", 9_000_000);
    // The pool's listing: the machine's datasets, and another machine's that is not its.
    h.pool.answer(
        "space",
        "byard/m\t-\t24576\t0\n\
             byard/m/m_d\t-\t0\t0\n\
             byard/m/m_d/root\t8589934592\t1073741824\t536870912\n\
             byard/m/m_d/data\t2147483648\t1073741824\t0\n\
             byard/m/m_x/root\t8589934592\t5\t5\n",
    );
    h.m.measure(at("2026-10-20T15:00:00Z")).await;
    let u = h.bucket("m_d", "2026-10-20T14:00:00Z").await.usage;
    assert_eq!(
        (u.root_gb_hours, u.volume_gb_hours, u.disk_used_gb_hours),
        (8.0, 2.0, 2.0)
    );
    assert_eq!((u.snapshot_gb_hours, u.backup_gb_hours), (0.5, 3.0));
    assert_eq!(
        (u.running_seconds, u.memory_mb_seconds, u.cpu_seconds),
        (0.0, 0.0, 0.0)
    );
    // One call for the whole pool, whatever the number of machines.
    let calls = h.pool.calls();
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("list -H -p")).count(),
        1,
        "{calls:?}"
    );
}

#[tokio::test]
async fn internet_and_ingress_bytes_land_on_their_machine() {
    let h = harness("10.64.0.0/22", 4096).await;
    let a = h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
    let b = h.metered("m_b", state::RUNNING, "2026-10-20T14:00:00Z");
    b.rec.lock().unwrap().ip = "10.64.1.3".into();
    b.rec.lock().unwrap().role = Some(Role::Gateway);
    for ip in ["10.64.1.2", "10.64.1.3"] {
        h.m.inner.net.count(ip).await.unwrap();
    }
    h.host.internet("10.64.1.2", 1000, 100);
    let tr = h.m.traffic("m_b").unwrap();
    tr.received(7);
    tr.sent(70);
    h.m.measure(at("2026-10-20T14:00:15Z")).await;
    // Only what grew since: the counters are read again, not added again.
    h.host.internet("10.64.1.2", 1, 0);
    h.m.measure(at("2026-10-20T14:00:30Z")).await;
    let (ua, ub) = (
        h.bucket("m_a", "2026-10-20T14:00:00Z").await,
        h.bucket("m_b", "2026-10-20T14:00:00Z").await,
    );
    let net = |u: &api::Usage| {
        (
            u.internet_in_bytes,
            u.internet_out_bytes,
            u.ingress_in_bytes,
            u.ingress_out_bytes,
        )
    };
    assert_eq!(net(&ua.usage), (1001, 100, 0, 0));
    assert_eq!(net(&ub.usage), (0, 0, 7, 70));
    // The namespace's gateway is a machine of the daemon: its bucket says so.
    assert_eq!(ub.role.as_deref(), Some("gateway"));
    assert_eq!(ua.role, None);
    drop(a);
}

#[tokio::test]
async fn a_closed_hour_is_never_written_again() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.metered("m_a", state::RUNNING, "2026-10-20T14:59:50Z");
    h.m.measure(at("2026-10-20T15:00:10Z")).await;
    let file = h.m.inner.cfg.state_dir().join("usage/2026-10-20T14.json");
    let before = std::fs::read(&file).unwrap();
    // A meter behind the closed hour (its last 5 s) adds them to the open one.
    h.metered("m_late", state::RUNNING, "2026-10-20T14:59:55Z");
    h.m.measure(at("2026-10-20T15:00:20Z")).await;
    assert_eq!(std::fs::read(&file).unwrap(), before);
    let in14 = h
        .buckets("2026-10-20T14:00:00Z", "2026-10-20T15:00:00Z")
        .await;
    assert_eq!(in14.len(), 1);
    assert_eq!(
        (in14[0].machine_id.as_str(), in14[0].usage.running_seconds),
        ("m_a", 10.0)
    );
    let late = h.bucket("m_late", "2026-10-20T15:00:00Z").await;
    assert_eq!(late.usage.running_seconds, 25.0);
    assert_eq!(
        h.bucket("m_a", "2026-10-20T15:00:00Z")
            .await
            .usage
            .running_seconds,
        20.0
    );
}

#[tokio::test]
async fn a_restart_reads_the_open_hour_back_and_closes_one_left_open() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
    h.m.measure(at("2026-10-20T14:10:00Z")).await;
    // An hour a crashed daemon left open, before it.
    let left = api::UsageBucket {
        hour: at("2026-10-20T12:00:00Z"),
        machine_id: "m_old".into(),
        namespace: "t1".into(),
        ..Default::default()
    };
    h.m.inner
        .store
        .put("usage", "2026-10-20T12", &vec![left])
        .unwrap();
    // The daemon starts again at 14:20; what it measures goes on from 14:20.
    let loaded = Ledger::load(&h.m.inner.store, at("2026-10-20T14:20:00Z")).unwrap();
    *h.m.inner.usage.lock().unwrap() = loaded;
    e.meter.lock().unwrap().at = at("2026-10-20T14:20:00Z");
    h.m.measure(at("2026-10-20T14:30:00Z")).await;
    let b = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
    assert_eq!((b.usage.running_seconds, b.closed), (1200.0, false));
    let old: Vec<api::UsageBucket> =
        h.m.inner
            .store
            .get("usage", "2026-10-20T12")
            .unwrap()
            .unwrap();
    assert!(old[0].closed, "closed at the start");
}

#[tokio::test]
async fn retention_removes_hours_past_usage_keep_days_once_an_hour() {
    let h = harness("10.64.0.0/22", 4096).await;
    let put = |key: &str| {
        let b = api::UsageBucket {
            hour: at(&format!("{key}:00:00Z")),
            closed: true,
            ..Default::default()
        };
        h.m.inner.store.put("usage", key, &vec![b]).unwrap();
    };
    put("2026-07-01T00");
    put("2026-10-10T00");
    h.m.measure(at("2026-10-20T14:00:00Z")).await;
    assert_eq!(h.m.inner.store.keys("usage").unwrap(), ["2026-10-10T00"]);
    // Once an hour: an old file found later in the same hour waits for the next one.
    put("2026-07-02T00");
    h.m.measure(at("2026-10-20T14:30:00Z")).await;
    assert!(h
        .m
        .inner
        .store
        .get::<Vec<api::UsageBucket>>("usage", "2026-07-02T00")
        .unwrap()
        .is_some());
    h.m.measure(at("2026-10-20T15:00:00Z")).await;
    assert_eq!(h.m.inner.store.keys("usage").unwrap(), ["2026-10-10T00"]);
}

#[tokio::test]
async fn a_destroyed_machine_keeps_its_buckets_and_its_counters_go() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let t0 = Utc::now();
    let m = h.m.create_made(h.request("web")).await.unwrap();
    assert!(
        h.host.counted.lock().unwrap().contains_key(&m.ip),
        "counted from its create"
    );
    // Booted by this daemon: its CPU counts from the boot, so the first reading counts.
    h.host.cpu(&m.id, 3_000_000);
    h.host.internet(&m.ip, 500, 50);
    h.m.destroy(&m.id, None).await.unwrap();
    assert!(!h.host.counted.lock().unwrap().contains_key(&m.ip));
    // Measured by the destroy itself: no tick ran.
    let mine: Vec<api::UsageBucket> =
        h.m.usage_buckets(
            usage::hour_of(t0),
            usage::hour_of(Utc::now()) + chrono::Duration::hours(1),
            None,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|b| b.machine_id == m.id)
        .collect();
    let sum = |f: fn(&api::Usage) -> f64| mine.iter().map(|b| f(&b.usage)).sum::<f64>();
    assert!(sum(|u| u.running_seconds) > 0.0, "{mine:?}");
    assert_eq!(sum(|u| u.cpu_seconds), 3.0);
    assert_eq!(sum(|u| u.internet_in_bytes as f64), 500.0);
    // Counters that cannot be removed keep the destroy from finishing: the address would
    // be handed out again with the old count. The tick tries again.
    let m = h.m.create_made(h.request("web2")).await.unwrap();
    h.host.refuse_uncount.store(true, Relaxed);
    let err = h.m.destroy(&m.id, None).await.unwrap_err();
    assert!(format!("{err:#}").contains("usage counters"), "{err:#}");
    assert_eq!(h.m.get(&m.id).unwrap().state, state::DESTROYING);
    h.host.refuse_uncount.store(false, Relaxed);
    h.m.tick().await;
    assert!(matches!(h.m.get(&m.id), Err(MError::NotFound)));
    assert!(!h.host.counted.lock().unwrap().contains_key(&m.ip));
    // A create that fails once counted (a fork of a source whose disks are gone) is kept
    // in `error` for a read (ADR 0048); its destroy takes its counters back.
    h.add("m_src", state::STOPPED, 256);
    let mut fork = h.request("fork");
    fork.image.clear();
    fork.fork = Some(api::ForkSpec {
        machine_id: "m_src".into(),
        copy: String::new(),
    });
    let err = h.m.create_made(fork).await.unwrap_err();
    let MError::CreateFailed(f) = err else {
        panic!("{err:?}")
    };
    assert!(f.error.contains("zfs"), "{}", f.error);
    assert_eq!(f.error_reason, reason::CREATE_FAILED);
    h.m.destroy(&f.id, None).await.unwrap();
    assert!(h.host.counted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_usage_route_checks_its_range() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
    h.m.measure(at("2026-10-20T14:10:00Z")).await;
    let st = Arc::new(crate::api::AppState {
        mgr: h.m.clone(),
        token: String::new(),
        metrics_token: String::new(),
        loopback: true,
        openapi: "",
        tls_fingerprint: String::new(),
    });
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1/usage", ln.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
    let get = |q: &str| reqwest::get(format!("{url}{q}"));
    let r = get("?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z")
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let bs: Vec<api::UsageBucket> = r.json().await.unwrap();
    assert_eq!(bs.len(), 1);
    assert_eq!(bs[0].usage.running_seconds, 600.0);
    let r = get("?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z&namespace=t2")
        .await
        .unwrap();
    assert_eq!(r.json::<Vec<api::UsageBucket>>().await.unwrap().len(), 0);
    for (q, why) in [
        ("", "from is required"),
        ("?from=2026-10-20T14:00:00Z", "to is required"),
        (
            "?from=2026-10-20T14:30:00Z&to=2026-10-20T15:00:00Z",
            "not on the hour",
        ),
        (
            "?from=2026-10-20T15:00:00Z&to=2026-10-20T14:00:00Z",
            "to must be after from",
        ),
        (
            "?from=2026-10-20T14:00:00Z&to=2026-12-20T14:00:00Z",
            "at most 31 days",
        ),
    ] {
        let r = get(q).await.unwrap();
        assert_eq!(r.status(), 400, "{q}");
        let e: api::ApiError = r.json().await.unwrap();
        assert_eq!(e.code, "invalid", "{q}");
        assert!(e.error.contains(why), "{q}: {}", e.error);
    }
}

#[tokio::test]
async fn metrics_open_to_the_metrics_token_or_the_apis_and_nothing_else_to_the_first() {
    let h = harness("10.64.0.0/22", 4096).await;
    let st = Arc::new(crate::api::AppState {
        mgr: h.m.clone(),
        token: "api".into(),
        metrics_token: "scrape".into(),
        loopback: false,
        openapi: "",
        tls_fingerprint: String::new(),
    });
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", ln.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
    let client = reqwest::Client::new();
    let get = |path: &str, token: &str| {
        let mut r = client.get(format!("{base}{path}"));
        if !token.is_empty() {
            r = r.bearer_auth(token);
        }
        r.send()
    };
    // The fleet relays a host's metrics with the API token it holds (ADR 0054).
    for token in ["scrape", "api"] {
        let r = get("/metrics", token).await.unwrap();
        assert_eq!(r.status(), 200, "{token}");
        assert!(r.text().await.unwrap().contains("briqyard_machines_total"));
    }
    for token in ["", "other"] {
        assert_eq!(
            get("/metrics", token).await.unwrap().status(),
            401,
            "{token:?}"
        );
    }
    assert_eq!(get("/v1/status", "scrape").await.unwrap().status(), 401);
    assert_eq!(get("/v1/status", "api").await.unwrap().status(), 200);
}
