//! Tests of the event log and the versions.

use super::*;

// --- events and versions (ADR 0019) ---

impl Harness {
    /// The events about a machine, oldest first.
    pub(in crate::machine) fn events_of(&self, id: &str) -> Vec<api::Event> {
        let f = events::Filter {
            machine: Some(id.into()),
            ..Default::default()
        };
        self.m.inner.events.read(0, &f, 5000).unwrap().events
    }

    pub(in crate::machine) fn reasons(&self, id: &str) -> Vec<String> {
        self.events_of(id).into_iter().map(|e| e.reason).collect()
    }

    /// Waits until the machine's events hold `n` of `reason`, within ten minutes: on a
    /// paused clock, which a restart's backoff needs.
    pub(super) async fn events_reach(&self, id: &str, reason: &str, n: usize) {
        let count = || self.reasons(id).iter().filter(|r| *r == reason).count();
        tokio::time::timeout(Duration::from_secs(600), async {
            while count() < n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{id}: {:?}", self.reasons(id)));
    }
}

#[tokio::test]
async fn each_transition_is_an_event_and_moves_the_version() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    let running = h.m.start(&m.id, None).await.unwrap();
    // The version is the seq of the last event, in memory and on disk.
    let evs = h.events_of(&m.id);
    assert_eq!(running.version, evs.last().unwrap().seq);
    assert_eq!(h.stored(&m.id).unwrap().version, running.version);
    h.m.destroy(&m.id, None).await.unwrap();
    assert_eq!(
        h.reasons(&m.id),
        [
            "created",
            "starting",
            "started",
            "stopping",
            "stopped",
            "starting",
            "started",
            "destroyed"
        ]
    );
    let evs = h.events_of(&m.id);
    assert!(evs.windows(2).all(|w| w[0].seq < w[1].seq));
    assert!(evs
        .iter()
        .all(|e| e.namespace == "t1" && e.kind == api::event::NORMAL));
    let data = |i: usize| evs[i].data.clone().unwrap_or_default();
    assert_eq!(data(0)["image"], IMAGE);
    assert_eq!(data(1)["resume"], false);
    assert_eq!(data(2)["pid"], 1000);
    assert_eq!(
        (data(3)["reason"].clone(), data(4)["reason"].clone()),
        ("user".into(), "user".into())
    );
    assert_eq!(evs[4].message, "stopped (user)");
}

#[tokio::test]
async fn a_failed_start_is_a_warning_that_says_whose_fault() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // The image's: the guest exited booting; its console's tail is in the message.
    h.host.boots(Boots::Exits(1, ""));
    let m = match h.m.create_made(h.request("bad")).await {
        Err(MError::BootFailed(m)) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(h.reasons(&m.id), ["created", "starting", "boot_failed"]);
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(e.kind, api::event::WARNING);
    assert!(
        e.message.starts_with("the machine exited during boot"),
        "{}",
        e.message
    );
    assert!(
        e.message.contains("[briqyard] exit code=1"),
        "{}",
        e.message
    );
    assert_eq!(m.version, e.seq);
    // The host's: a policy the tables refuse.
    h.host.boots(Boots::Ready(Duration::ZERO));
    h.host.refuse_policies.store(true, Relaxed);
    let err =
        h.m.create_made(h.request_egress("walled", "none", None))
            .await
            .unwrap_err();
    assert!(matches!(err, MError::Other(_)), "{err:?}");
    let id =
        h.m.list(Some("t1"), &[])
            .into_iter()
            .find(|x| x.name == "walled")
            .unwrap()
            .id;
    assert_eq!(h.reasons(&id), ["created", "starting", "start_failed"]);
    let e = h.events_of(&id).pop().unwrap();
    assert_eq!(e.kind, api::event::WARNING);
    assert!(e.message.contains("nft: refused"), "{}", e.message);
}

#[tokio::test(start_paused = true)]
async fn an_exit_and_its_restart_are_events() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("job")).await.unwrap();
    h.host.exit(1000, 7, false);
    // The default policy, on-failure with 3 retries: the first comes after 10 s.
    h.events_reach(&m.id, reason::STARTED, 2).await;
    assert_eq!(
        h.reasons(&m.id),
        [
            "created",
            "starting",
            "started",
            "exited",
            "restarting",
            "starting",
            "started"
        ]
    );
    let evs = h.events_of(&m.id);
    let (exited, restarting) = (&evs[3], &evs[4]);
    assert_eq!(
        (exited.kind.as_str(), exited.message.as_str()),
        ("warning", "exited with code 7")
    );
    assert_eq!(
        exited.data,
        Some(json!({"code": 7, "oom": false, "restarting": true}))
    );
    assert_eq!(restarting.message, "restart 1 in 10 s (at most 3)");
    assert_eq!(restarting.data.as_ref().unwrap()["delay_sec"], 10);
    assert_eq!(restarting.data.as_ref().unwrap()["attempt"], 1);
    // Counted for `/metrics`, and a start's time measured.
    let e = h.m.entry(&m.id).unwrap();
    assert_eq!(e.meter.lock().unwrap().restarts, 1);
    assert!(e.meter.lock().unwrap().boot_seconds.is_some());
    // An exit with nothing to restart says so, and a clean exit is no warning.
    let mut req = h.request("once");
    req.restart = Some(api::RestartPolicy {
        policy: "no".into(),
        max_retries: 0,
    });
    let m = h.m.create_made(req).await.unwrap();
    h.host.exit(1002, 0, false);
    h.events_reach(&m.id, reason::EXITED, 1).await;
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (e.kind.as_str(), e.message.as_str()),
        ("normal", "exited with code 0")
    );
    assert_eq!(e.data.unwrap()["restarting"], false);
}

#[tokio::test]
async fn a_suspend_and_its_resume_are_events() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.m.stop(&m.id, Duration::from_secs(1), true, None)
        .await
        .unwrap();
    h.m.start(&m.id, None).await.unwrap();
    let evs = h.events_of(&m.id);
    let got: Vec<(&str, &str)> = evs[3..]
        .iter()
        .map(|e| (e.reason.as_str(), e.message.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("stopping", "stopping (user)"),
            ("suspended", "suspended (user): its memory snapshot kept"),
            ("starting", "resuming from its memory snapshot"),
            ("resumed", "resumed from its memory snapshot, pid 1001"),
        ]
    );
    assert_eq!(evs[3].data.as_ref().unwrap()["suspend"], true);
    // A sleeping machine stopped on request: that changes it, so it is an event.
    let m = h.m.create_made(h.request("nap")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    let last = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (last.reason.as_str(), last.message.as_str()),
        ("stopped", "stopped on request (it was idle)")
    );
}

#[tokio::test]
async fn the_gateway_says_when_it_serves_and_when_it_sleeps() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    assert_eq!(h.reasons(&gw), ["created"]);
    let c = h.m.create_made(h.consumer("c")).await.unwrap();
    assert_eq!(
        h.reasons(&gw),
        ["created", "starting", "started", "gateway_started"]
    );
    let started = h.events_of(&gw).pop().unwrap();
    assert_eq!(
        started.message,
        "the namespace's gateway answers on 10.64.1.2:3128"
    );
    // Its consumer's start came after the gateway answered.
    let consumer = h.events_of(&c.id);
    assert!(consumer[1].seq > started.seq);
    // A start that finds it running says nothing more.
    h.m.create_made(h.consumer("d")).await.unwrap();
    assert_eq!(h.reasons(&gw).len(), 4);
    for id in [
        c.id.clone(),
        h.m.list(Some("t1"), &[])
            .into_iter()
            .find(|m| m.name == "d")
            .unwrap()
            .id,
    ] {
        h.m.stop(&id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
    }
    h.m.tick().await;
    assert_eq!(
        h.reasons(&gw)[4..],
        ["stopping", "stopped", "gateway_stopped"]
    );
    assert_eq!(
        h.m.get(&gw).unwrap().version,
        h.events_of(&gw).pop().unwrap().seq
    );
    // A new spec is an update of the gateway.
    let mut spec = gateway_spec(3128);
    spec.env.insert("MORE".into(), "1".into());
    h.m.set_gateway("t1", spec).await.unwrap();
    let e = h.events_of(&gw).pop().unwrap();
    assert_eq!(
        (e.reason.as_str(), e.message.as_str()),
        ("updated", "the gateway's env replaced")
    );
}

#[tokio::test]
async fn a_patch_is_an_event_only_when_it_changes_something() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let changed =
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap();
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (e.reason.as_str(), e.message.as_str()),
        ("egress_changed", "egress open -> none")
    );
    let data = e.data.unwrap();
    assert_eq!(
        (&data["fields"], &data["from"], &data["to"]),
        (&json!(["egress"]), &json!("open"), &json!("none"))
    );
    assert_eq!(changed.version, e.seq);
    // The limits are what the tables hold for its internet traffic too: an egress change.
    let limits = api::UpdateMachineRequest {
        limits: Some(api::EgressLimits {
            bandwidth_mbit: Some(5),
            ..Default::default()
        }),
        ..Default::default()
    };
    let limited = h.m.update(&m.id, limits.clone(), None).await.unwrap();
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (e.reason.as_str(), e.message.as_str()),
        ("egress_changed", "egress limits changed")
    );
    let data = e.data.unwrap();
    assert_eq!(data["fields"], json!(["limits"]));
    assert_eq!(data["limits"]["bandwidth_mbit"], 5);
    assert_eq!(limited.version, e.seq);
    // The same limits again change nothing.
    let same = h.m.update(&m.id, limits, None).await.unwrap();
    assert_eq!(same.version, limited.version);
    let sleep = |s: &str| api::UpdateMachineRequest {
        sleep: Some(s.into()),
        ..Default::default()
    };
    let three = h.m.update(&m.id, sleep("3h"), None).await.unwrap();
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (e.reason.as_str(), e.message.as_str()),
        ("updated", "sleep changed")
    );
    assert_eq!(three.version, e.seq);
    // The same value again: no event, the version stays.
    let same = h.m.update(&m.id, sleep("3h"), None).await.unwrap();
    assert_eq!(same.version, three.version);
    let both = api::UpdateMachineRequest {
        sleep: Some("never".into()),
        metadata: Some(BTreeMap::from([(
            "briq_id".to_string(),
            "bq_1".to_string(),
        )])),
        ..Default::default()
    };
    h.m.update(&m.id, both, None).await.unwrap();
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(e.data, Some(json!({"fields": ["sleep", "metadata"]})));
}

#[tokio::test]
async fn a_stale_if_match_is_refused_with_the_machine_as_it_is() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let stale = m.version - 1;
    let moved = |r: Result<api::Machine, MError>| match r {
        Err(MError::Moved(now)) => now.version,
        other => panic!("{other:?}"),
    };
    let sleep = api::UpdateMachineRequest {
        sleep: Some("3h".into()),
        ..Default::default()
    };
    assert_eq!(
        moved(h.m.update(&m.id, sleep.clone(), Some(stale)).await),
        m.version
    );
    assert_eq!(h.m.get(&m.id).unwrap().sleep, "30m", "nothing changed");
    assert_eq!(
        moved(
            h.m.stop(&m.id, Duration::from_secs(1), false, Some(stale))
                .await
        ),
        m.version
    );
    assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
    assert_eq!(moved(h.m.start(&m.id, Some(stale)).await), m.version);
    assert_eq!(moved(h.m.wake(&m.id, Some(stale)).await), m.version);
    assert!(matches!(
        h.m.destroy(&m.id, Some(stale)).await,
        Err(MError::Moved(_))
    ));
    assert!(h.m.get(&m.id).is_ok());
    // The version read passes, once: the change moves it.
    let patched =
        h.m.update(&m.id, sleep.clone(), Some(m.version))
            .await
            .unwrap();
    assert_eq!(patched.sleep, "3h");
    assert_eq!(
        moved(h.m.update(&m.id, sleep, Some(m.version)).await),
        patched.version
    );
    let stopped =
        h.m.stop(&m.id, Duration::from_secs(1), false, Some(patched.version))
            .await
            .unwrap();
    h.m.destroy(&m.id, Some(stopped.version)).await.unwrap();
    assert!(h.m.get(&m.id).is_err());
}

#[tokio::test]
async fn the_seq_goes_on_past_every_records_version_at_load() {
    let h = harness("10.64.0.0/22", 4096).await;
    // A record written at version 500 by a daemon whose log was lost after it.
    let mut r = record();
    r.version = 500;
    h.m.inner.store.put("machines", &r.id, &r).unwrap();
    h.m.load().unwrap();
    assert_eq!(h.m.get(&r.id).unwrap().version, 500);
    assert_eq!(
        h.m.inner.events.emit(Ev::normal(reason::HOST_STARTED, "")),
        Some(501)
    );
}

#[tokio::test]
async fn recovery_says_what_it_adopted_and_what_it_stopped() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let ours = h.add("m_ours", state::RUNNING, 256);
    let pid = h
        .host
        .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
    ours.set_state(state::RUNNING, |r| {
        r.pid = pid;
        None
    });
    // Its process gone: it exited while no daemon ran.
    h.add("m_lost", state::STARTING, 256);
    // Its process there, but mid-start: not one to take over, ended (what fails an upgrade).
    let cut = h.add("m_cut", state::STARTING, 256);
    let cut_pid = h
        .host
        .left_running("m_cut", &h.m.inner.cfg.run_dir().join("m_cut"));
    cut.set_state(state::STARTING, |r| {
        r.pid = cut_pid;
        None
    });
    h.host.calls();
    assert_eq!(h.m.recover().await, (1, 1, 1));
    assert!(h.host.calls().contains(&format!("kill {cut_pid}")));
    let cut = h.events_of("m_cut").pop().unwrap();
    assert_eq!(
        cut.message,
        "left running by a previous daemon that could not hand it over: stopped"
    );
    let adopted = h.events_of("m_ours").pop().unwrap();
    assert_eq!(adopted.reason, "adopted");
    assert_eq!(adopted.data, Some(json!({"pid": pid})));
    assert_eq!(h.stored("m_ours").unwrap().version, adopted.seq);
    let lost = h.events_of("m_lost").pop().unwrap();
    assert_eq!(
        (lost.reason.as_str(), lost.kind.as_str()),
        ("stopped", "warning")
    );
    assert_eq!(lost.data, Some(json!({"reason": "host"})));
    assert_eq!(
        lost.message,
        "its process ended while no daemon ran: stopped"
    );
}

/// The next line of a streamed answer, as JSON, within five seconds.
async fn next_line(w: &mut reqwest::Response, buf: &mut String) -> serde_json::Value {
    loop {
        if let Some(i) = buf.find('\n') {
            let l = serde_json::from_str(&buf[..i]).unwrap();
            buf.drain(..=i);
            return l;
        }
        let chunk = tokio::time::timeout(Duration::from_secs(5), w.chunk())
            .await
            .expect("a line in time")
            .unwrap()
            .expect("the stream is open");
        buf.push_str(std::str::from_utf8(&chunk).unwrap());
    }
}

#[tokio::test]
async fn the_events_route_pages_watches_and_checks_if_match() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let st = Arc::new(crate::api::AppState {
        mgr: h.m.clone(),
        token: String::new(),
        metrics_token: String::new(),
        loopback: true,
        openapi: "",
        tls_fingerprint: String::new(),
    });
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", ln.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(ln, crate::api::router(st)).await.unwrap() });
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let http = reqwest::Client::new();
    let get = |q: String| http.get(format!("{base}/v1/events{q}")).send();
    let r = get(format!("?machine={}", m.id)).await.unwrap();
    assert_eq!(r.status(), 200);
    let page: api::EventsPage = r.json().await.unwrap();
    let reasons: Vec<&str> = page.events.iter().map(|e| e.reason.as_str()).collect();
    assert_eq!(reasons, ["created", "starting", "started"]);
    assert_eq!(page.next, m.version.to_string());
    // A cursor the log cannot answer, and queries that make no sense.
    let r = get("?since=99".into()).await.unwrap();
    assert_eq!(r.status(), 410);
    let e: api::ApiError = r.json().await.unwrap();
    assert_eq!((e.code.as_str(), e.oldest), ("gone", Some(1)));
    for q in ["?since=x", "?type=fatal", "?machine=../x", "?watch=yes"] {
        let r = get(q.into()).await.unwrap();
        assert_eq!(r.status(), 400, "{q}");
    }
    // A watch from the first event: the rest of the log, then what happens next.
    let mut w = get(format!("?watch=true&since=1&machine={}", m.id))
        .await
        .unwrap();
    assert_eq!(w.headers()["content-type"], "application/x-ndjson");
    let mut buf = String::new();
    assert_eq!(next_line(&mut w, &mut buf).await["reason"], "starting");
    assert_eq!(next_line(&mut w, &mut buf).await["reason"], "started");
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(next_line(&mut w, &mut buf).await["reason"], "stopping");
    assert_eq!(next_line(&mut w, &mut buf).await["reason"], "stopped");
    // If-Match on a PATCH: stale is 409 with the machine, current passes, garbage is 400.
    let now = h.m.get(&m.id).unwrap().version;
    let patch = |v: String| {
        http.patch(format!("{base}/v1/machines/{}", m.id))
            .header("if-match", v)
            .json(&json!({"sleep": "3h"}))
            .send()
    };
    let r = patch((now - 1).to_string()).await.unwrap();
    assert_eq!(r.status(), 409);
    let e: api::ApiError = r.json().await.unwrap();
    assert_eq!(e.code, "conflict");
    assert_eq!(e.machine.map(|m| m.version), Some(now));
    let r = patch(format!("\"{now}\"")).await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.json::<api::Machine>().await.unwrap().version > now);
    let r = patch("soon".into()).await.unwrap();
    assert_eq!(r.status(), 400);
    // A lifecycle POST takes it too.
    let r = http
        .post(format!("{base}/v1/machines/{}/start", m.id))
        .header("if-match", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
}
