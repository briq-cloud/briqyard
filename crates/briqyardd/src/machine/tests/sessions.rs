//! Tests of exec sessions, the ingress and waking a machine.

use super::*;

#[tokio::test]
async fn the_ingress_resyncs_when_it_missed_endpoint_events() {
    let h = harness_config(|c| c.ingress.tcp_ports = "39100-39199".into()).await;
    h.namespace("t1");
    h.add("m_abc123", state::RUNNING, 256);
    let ing = crate::ingress::Ingress::new(
        h.m.clone(),
        "127.0.0.1",
        "",
        Duration::from_secs(1),
        std::sync::Arc::new(briqyard_api::listeners::Listeners::none()),
    );
    ing.start().await.unwrap();
    let tcp = |port| api::CreateEndpointRequest {
        port,
        protocol: "tcp".into(),
        host: String::new(),
    };
    let ep = h.m.create_endpoint("m_abc123", tcp(8080)).unwrap();
    let port = ep.host_port.unwrap();
    while !listening(port).await {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // More events than the channel holds, sent while the ingress cannot read (one thread,
    // no await): it misses the removal of the first.
    h.m.delete_endpoint(&ep.id).unwrap();
    for p in 0..70 {
        let x = h.m.create_endpoint("m_abc123", tcp(9000 + p)).unwrap();
        h.m.delete_endpoint(&x.id).unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while listening(port).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "port {port} of a removed endpoint still listening"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn the_ingress_opens_no_listener_for_an_endpoint_gone() {
    let h = harness_config(|c| c.ingress.tcp_ports = "39200-39299".into()).await;
    h.namespace("t1");
    h.add("m_abc123", state::RUNNING, 256);
    let ing = crate::ingress::Ingress::new(
        h.m.clone(),
        "127.0.0.1",
        "",
        Duration::from_secs(1),
        std::sync::Arc::new(briqyard_api::listeners::Listeners::none()),
    );
    let req = api::CreateEndpointRequest {
        port: 8080,
        protocol: "tcp".into(),
        host: String::new(),
    };
    let ep = h.m.create_endpoint("m_abc123", req).unwrap();
    let rec = h.m.endpoint(&ep.id).unwrap();
    // The delete's event first, then the create's.
    h.m.delete_endpoint(&ep.id).unwrap();
    ing.add(rec).await.unwrap();
    assert!(!listening(ep.host_port.unwrap()).await);
}

// --- exec sessions (ADR 0029) ---

fn session_req(cmd: &[&str], tty: bool) -> api::session::ExecSession {
    api::session::ExecSession {
        cmd: cmd.iter().map(|c| c.to_string()).collect(),
        tty,
        cols: 100,
        rows: 30,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_session_streams_both_ways_and_is_an_event_not_a_version() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("sbx")).await.unwrap();
    h.host.answers("sh", 3);
    let mut s =
        h.m.open_session(&m.id, session_req(&["sh"], true))
            .await
            .unwrap();
    assert_eq!(s.machine, m.id);
    let pid = h
        .host
        .calls()
        .into_iter()
        .find(|c| c.starts_with("session "))
        .unwrap();
    assert!(pid.ends_with(" sh tty=true"), "{pid}");
    // Input goes in, the command's answer comes back, the code ends it.
    for f in [
        guest::Request {
            op: "stdin".into(),
            data: b"ls\n".to_vec(),
            ..Default::default()
        },
        guest::Request {
            op: "resize".into(),
            cols: 120,
            rows: 40,
            ..Default::default()
        },
        guest::Request {
            op: "close_stdin".into(),
            ..Default::default()
        },
    ] {
        guestc::write_request(&mut s.conn, &f).await.unwrap();
    }
    let out = guestc::collect(&mut s.conn).await.unwrap();
    assert_eq!(out.stdout, b"ls\n120x40\n");
    assert_eq!(out.code, 3);
    // An event says someone came in; the machine's version did not move.
    let ev =
        h.m.inner
            .events
            .read(0, &events::Filter::default(), 1000)
            .unwrap();
    let opened = ev
        .events
        .iter()
        .find(|e| e.reason == reason::SESSION_OPENED)
        .unwrap();
    assert_eq!(
        (opened.machine_id.as_str(), opened.message.as_str()),
        (m.id.as_str(), "sh on a terminal")
    );
    assert_eq!(opened.data, Some(json!({"command": "sh", "tty": true})));
    assert_eq!(h.m.get(&m.id).unwrap().version, m.version);
}

#[tokio::test]
async fn an_open_session_keeps_the_machine_awake() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("sbx")).await.unwrap();
    let s =
        h.m.open_session(&m.id, session_req(&["sh"], true))
            .await
            .unwrap();
    let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
    let idle = || h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
    idle();
    assert_eq!(
        h.m.get(&m.id).unwrap().sleeps_at,
        None,
        "no sleep while in use"
    );
    h.m.tick().await;
    assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
    // The session's end is a use: the window starts again from it.
    drop(s);
    let after = h.m.get(&m.id).unwrap();
    assert!(after.last_used_at > long_ago);
    assert!(after.sleeps_at.is_some());
    h.m.tick().await;
    assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
    idle();
    h.m.tick().await;
    let slept = h.m.get(&m.id).unwrap();
    assert_eq!(
        (slept.state.as_str(), slept.stopped_reason.as_str()),
        (state::STOPPED, stop::IDLE)
    );
}

#[tokio::test]
async fn a_command_in_flight_keeps_the_machine_awake() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("job")).await.unwrap();
    *h.host.exec_takes.lock().unwrap() = Duration::from_secs(3);
    let mgr = h.m.clone();
    let id = m.id.clone();
    let job = tokio::spawn(async move {
        mgr.exec(
            &id,
            api::ExecRequest {
                cmd: vec!["migrate".into()],
                ..Default::default()
            },
        )
        .await
    });
    eventually("the command runs", || {
        h.host.execs_now.load(std::sync::atomic::Ordering::SeqCst) == 1
    })
    .await;
    // Its window ran out while it runs: it is in use, it does not sleep under it.
    h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at =
        Some(Utc::now() - chrono::Duration::hours(1));
    h.m.tick().await;
    assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
    let out = job.await.unwrap().unwrap();
    assert_eq!((out.exit_code, out.stdout.as_str()), (0, "ok\n"));
    assert!(h.m.get(&m.id).unwrap().last_used_at > Some(Utc::now() - chrono::Duration::minutes(1)));
}

/// The ingress and a TCP endpoint to port 1 of `machine`, which nothing serves at the
/// harness's addresses: a dial waits on it until the machine stops.
fn ingress_to(h: &Harness, machine: &str) -> (crate::ingress::Ingress, EndpointRec) {
    let req = api::CreateEndpointRequest {
        port: 1,
        protocol: "tcp".into(),
        ..Default::default()
    };
    let ep = h.m.create_endpoint(machine, req).unwrap();
    let ingress = crate::ingress::Ingress::new(
        h.m.clone(),
        "127.0.0.1",
        "",
        Duration::from_secs(5),
        std::sync::Arc::new(briqyard_api::listeners::Listeners::none()),
    );
    (ingress, h.m.endpoint(&ep.id).unwrap())
}

#[tokio::test]
async fn a_connection_that_wakes_its_machine_keeps_it_awake_until_delivered() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let idle = || {
        h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at =
            Some(Utc::now() - chrono::Duration::hours(1))
    };
    idle();
    h.m.tick().await;
    assert_eq!(h.m.get(&m.id).unwrap().stopped_reason, stop::IDLE);
    let (ingress, ep) = ingress_to(&h, &m.id);
    let dial = tokio::spawn(async move { ingress.dial(&ep).await });
    eventually("the connection woke it", || {
        h.m.get(&m.id).unwrap().state == state::RUNNING
    })
    .await;
    // Its window runs out before the program listens: the connection still waits for the
    // port, and the machine does not go back to sleep under it.
    idle();
    h.m.tick().await;
    let up = h.m.get(&m.id).unwrap();
    assert_eq!(up.state, state::RUNNING);
    assert_eq!(up.sleeps_at, None, "in use");
    // A stop ends the wait, and the use with it.
    h.m.stop(&m.id, Duration::ZERO, false, None).await.unwrap();
    let err = dial.await.unwrap().unwrap_err().to_string();
    assert!(err.ends_with("the machine stopped"), "{err}");
    assert_eq!(h.m.entry(&m.id).unwrap().in_flight.load(Relaxed), 0);
    assert!(h.m.get(&m.id).unwrap().last_used_at > Some(Utc::now() - chrono::Duration::minutes(1)));
}

#[tokio::test]
async fn a_session_wakes_a_sleeping_machine_or_says_why_not() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("sbx")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    let mut asleep = session_req(&["sh"], false);
    asleep.wake = false;
    match h.m.open_session(&m.id, asleep).await {
        Err(MError::NotRunning(why)) => assert_eq!(why, "stopped (idle)"),
        other => panic!("{:?}", other.err()),
    }
    assert!(matches!(
        h.m.open_session(&m.id, session_req(&[], false)).await.err(),
        Some(MError::Invalid(_))
    ));
    let s =
        h.m.open_session(&m.id, session_req(&["sh"], false))
            .await
            .unwrap();
    assert_eq!(h.m.get(&s.machine).unwrap().state, state::RUNNING);
    assert!(matches!(
        h.m.open_session("m_none", session_req(&["sh"], false))
            .await
            .err(),
        Some(MError::NotFound)
    ));
}

#[tokio::test]
async fn a_session_on_an_init_older_than_sessions_is_refused_naming_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // An init older than the version report: it would run the command as a plain exec,
    // no input, no terminal.
    *h.host.init_version.lock().unwrap() = String::new();
    let m = h.m.create_made(h.request("old")).await.unwrap();
    h.host.calls();
    match h.m.open_session(&m.id, session_req(&["sh"], true)).await {
        Err(MError::Conflict(why)) => assert_eq!(
            why,
            "the machine's init (older than the version report) does not know `session`: it is older than this daemon; the machine gets this daemon's init when its root disk is made again (an image change)"
        ),
        other => panic!("{:?}", other.err()),
    }
    assert!(
        !h.host.calls().iter().any(|c| c.starts_with("session ")),
        "nothing reached the guest"
    );
    // An exec is the old way in: it runs.
    let exec = api::ExecRequest {
        cmd: vec!["true".into()],
        wake: true,
        ..Default::default()
    };
    let out = h.m.exec(&m.id, exec).await.unwrap();
    assert_eq!(out.exit_code, 0);
    // One of a release before sessions, named.
    *h.host.init_version.lock().unwrap() = "0.0.9+a".into();
    let m = h.m.create_made(h.request("older")).await.unwrap();
    match h.m.open_session(&m.id, session_req(&["sh"], false)).await {
        Err(MError::Conflict(why)) => assert!(
            why.starts_with("the machine's init (0.0.9+a) does not know `session`"),
            "{why}"
        ),
        other => panic!("{:?}", other.err()),
    }
    // This release's: a session.
    *h.host.init_version.lock().unwrap() = api::VERSION.into();
    let m = h.m.create_made(h.request("new")).await.unwrap();
    assert!(h
        .m
        .open_session(&m.id, session_req(&["sh"], false))
        .await
        .is_ok());
}

/// Moves the current run's start back, as if it had run that long.
pub(super) fn e_started_minutes_ago(h: &Harness, id: &str, minutes: i64) {
    let e = h.m.entry(id).unwrap();
    e.rec.lock().unwrap().started_at = Some(Utc::now() - chrono::Duration::minutes(minutes));
}

#[tokio::test(start_paused = true)]
async fn the_ingress_waits_for_a_woken_machine_to_be_ready() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m =
        h.m.create_made(h.probed("web", readiness(http_probe(8080))))
            .await
            .unwrap();
    eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
    let e = h.m.entry(&m.id).unwrap();
    h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    // A connection wakes it; its program is not serving yet: the proxy waits.
    h.host.http(&m.ip, 8080, 503);
    let mgr = h.m.clone();
    let id = m.id.clone();
    let dial = tokio::spawn(async move { mgr.ready_addr(&id, Duration::from_secs(120)).await });
    eventually("woken", || h.m.get(&m.id).unwrap().state == state::RUNNING).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!dial.is_finished());
    h.host.http(&m.ip, 8080, 200);
    let ip = dial.await.unwrap().unwrap();
    assert_eq!(ip.to_string(), m.ip);
    assert!(h.m.get(&m.id).unwrap().ready);
    // Running and not ready: readiness gates every connection, not only a wake's.
    h.host.http(&m.ip, 8080, 500);
    eventually("not ready", || !h.m.get(&m.id).unwrap().ready).await;
    match h.m.ready_addr(&m.id, Duration::from_secs(5)).await {
        Err(MError::NotReady(_)) => {}
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn an_exec_that_wakes_a_machine_runs_once_it_is_ready() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m =
        h.m.create_made(h.probed("db", readiness(http_probe(8080))))
            .await
            .unwrap();
    eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
    let e = h.m.entry(&m.id).unwrap();
    h.m.stop_entry(&e, stop::IDLE, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    // The command wakes it; its program is not serving yet: the command waits.
    h.host.http(&m.ip, 8080, 503);
    let mgr = h.m.clone();
    let id = m.id.clone();
    let run = tokio::spawn(async move { mgr.running_vsock(&id, true).await });
    eventually("woken", || h.m.get(&m.id).unwrap().state == state::RUNNING).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!run.is_finished());
    h.host.http(&m.ip, 8080, 200);
    run.await.unwrap().unwrap();
    assert!(h.m.get(&m.id).unwrap().ready);
    // Running and not ready, no wake: the command runs at once, as in a pod.
    h.host.http(&m.ip, 8080, 500);
    eventually("not ready", || !h.m.get(&m.id).unwrap().ready).await;
    h.m.running_vsock(&m.id, true).await.unwrap();
}

#[tokio::test]
async fn file_capabilities_are_live_even_when_versions_are_identical() {
    let h = harness("10.64.0.0/16", 4096).await;
    h.ready().await;
    *h.host.init_version.lock().unwrap() = "0.1.7".into();
    let machine = h.m.create_made(h.request("files")).await.unwrap();
    let old = h.m.file_capabilities(&machine.id).await.unwrap();
    h.host.file_stream_v1.store(true, Relaxed);
    let new = h.m.file_capabilities(&machine.id).await.unwrap();
    assert_eq!(old.init_version, new.init_version);
    assert!(!old.file_stream_v1);
    assert!(new.file_stream_v1);
    assert_eq!(new.legacy_max_bytes, 1 << 20);
    assert_eq!(new.native_max_bytes, 1 << 30);
    assert!(matches!(
        h.m.file_capabilities("m_missing").await,
        Err(MError::NotFound)
    ));
    h.m.stop(&machine.id, Duration::ZERO, false, None)
        .await
        .unwrap();
    assert!(h.m.file_capabilities(&machine.id).await.is_err());
}
