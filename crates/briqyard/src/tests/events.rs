//! Events and describe (ADR 0019).

use super::*;

fn ev(seq: u64, reason: &str, machine: &str, message: &str) -> api::Event {
    api::Event {
        seq,
        at: ts() + chrono::Duration::seconds(seq as i64),
        kind: if reason == "exited" {
            "warning"
        } else {
            "normal"
        }
        .into(),
        reason: reason.into(),
        message: message.into(),
        machine_id: machine.into(),
        namespace: "t1".into(),
        host: String::new(),
        data: None,
        count: 1,
        first_at: None,
    }
}

#[test]
fn events_and_describe_parse() {
    match parse(&[
        "events",
        "--namespace",
        "t1",
        "--machine",
        "m1",
        "--since",
        "d1:3,d2:9",
        "--watch",
    ])
    .cmd
    {
        Cmd::Events {
            namespace,
            machine,
            since,
            watch,
        } => {
            assert_eq!(
                (namespace.as_deref(), machine.as_deref(), since.as_deref()),
                (Some("t1"), Some("m1"), Some("d1:3,d2:9"))
            );
            assert!(watch);
        }
        _ => panic!("not events"),
    }
    match parse(&["events"]).cmd {
        Cmd::Events {
            namespace: None,
            machine: None,
            since: None,
            watch: false,
        } => {}
        _ => panic!("not plain events"),
    }
    match machine(parse(&["machine", "describe", "m1"])) {
        MachineCmd::Describe { id } => assert_eq!(id, "m1"),
        _ => panic!("not a describe"),
    }
    assert_eq!(
        fails(&["machine", "describe"]),
        ErrorKind::MissingRequiredArgument
    );
    // The paths, and a cursor added to either.
    assert_eq!(events_path(None, None, false), "/v1/events");
    assert_eq!(
        events_path(Some("t1"), Some("m1"), true),
        "/v1/events?namespace=t1&machine=m1&watch=true"
    );
    assert_eq!(with_since("/v1/events", "4"), "/v1/events?since=4");
    assert_eq!(
        with_since("/v1/events?namespace=t1", "d1:3"),
        "/v1/events?namespace=t1&since=d1:3"
    );
    assert_eq!(with_since("/v1/events", ""), "/v1/events");
    assert_eq!(backups_path(None, None), "/v1/backups");
    assert_eq!(backups_path(None, Some("m1")), "/v1/backups?machine=m1");
    assert_eq!(
        backups_path(Some("t1"), Some("m1")),
        "/v1/backups?namespace=t1&machine=m1"
    );
}

#[test]
fn the_events_table() {
    let folded = api::Event {
        count: 4,
        first_at: Some(ts()),
        ..ev(3, "session_opened", "m_0123456789ab", "sh")
    };
    let out = events_table(&[
        ev(1, "host_started", "", "daemon started"),
        ev(2, "exited", "m_0123456789ab", "exited with code 7"),
        folded,
    ]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "TIME                 TYPE     REASON           MACHINE         COUNT  MESSAGE",
            "2026-10-19 08:30:01  normal   host_started     -                   1  daemon started",
            "2026-10-19 08:30:02  warning  exited           m_0123456789ab      1  exited with code 7",
            "2026-10-19 08:30:03  normal   session_opened   m_0123456789ab      4  sh (x4 since 08:30:00)",
        ]
    );
}

#[test]
fn probes_from_the_command_line() {
    let p = probe_arg("http:8080").unwrap();
    assert_eq!(
        p.http,
        Some(api::HttpProbe {
            port: 8080,
            path: "/".into()
        })
    );
    assert_eq!(p.period_sec, 10, "the API's timings");
    let p = probe_arg("http:8080/healthz?x=1").unwrap();
    assert_eq!(p.http.unwrap().path, "/healthz?x=1");
    assert_eq!(probe_arg("tcp:5432").unwrap().tcp, Some(5432));
    assert_eq!(
        probe_arg("exec:test -f /tmp/alive").unwrap().exec,
        Some(vec!["test".into(), "-f".into(), "/tmp/alive".into()])
    );
    for bad in ["http", "tcp:x", "ftp:21", "tcp:0", "exec:", "http:70000/"] {
        assert!(probe_arg(bad).is_err(), "{bad}");
    }
    assert_eq!(
        probe_arg("tcp:0").unwrap_err(),
        "probe.tcp: 0 is not a port"
    );
}

#[test]
fn describe_shows_the_machine_then_its_events() {
    let m = api::Machine {
        id: "m_0123456789ab".into(),
        namespace: "t1".into(),
        name: "web".into(),
        image: "nginx:1.27".into(),
        state: "stopped".into(),
        stopped_reason: "exit".into(),
        exit: Some(api::Exit {
            code: 137,
            oom_killed: true,
            at: ts(),
            restarting: true,
        }),
        ip: "10.64.1.2".into(),
        size: api::Size {
            vcpus: 1,
            memory_mb: 256,
            cpu_millis: None,
        },
        volume: Some(api::VolumeSpec {
            size_gb: 2,
            mount: "/data".into(),
        }),
        sleep: "30m".into(),
        backup: Some(api::BackupPolicy {
            every: "6h".into(),
            keep: 4,
        }),
        last_backup_at: Some(ts()),
        next_backup_at: Some(ts() + chrono::Duration::hours(6)),
        egress: api::Egress {
            mode: "via".into(),
            via: Some("gateway".into()),
        },
        endpoints: vec![
            api::Endpoint {
                id: "ep_1".into(),
                machine_id: "m_0123456789ab".into(),
                port: 80,
                protocol: "http".into(),
                host_port: None,
                host: "web-ab12.byard.localhost".into(),
                address: "http://web-ab12.byard.localhost".into(),
                created_at: ts(),
            },
            api::Endpoint {
                id: "ep_2".into(),
                machine_id: "m_0123456789ab".into(),
                port: 5432,
                protocol: "tcp".into(),
                host_port: Some(20001),
                host: String::new(),
                address: "10.0.0.5:20001".into(),
                created_at: ts(),
            },
        ],
        created_at: ts(),
        version: 12,
        pending: Some(api::Pending {
            fields: vec!["image".into(), "env".into(), "size".into(), "volume".into()],
            image: Some("nginx:1.28".into()),
            size: Some(api::Size {
                vcpus: 2,
                memory_mb: 512,
                cpu_millis: None,
            }),
            volume: Some(api::VolumeSize { size_gb: 20 }),
            ..Default::default()
        }),
        pending_since: Some(ts()),
        init_version: "0.1.0+fdad892eeefa".into(),
        host: "d1".into(),
        restarts: 2,
        restarting_at: Some(ts() + chrono::Duration::seconds(20)),
        probes: api::Probes {
            readiness: Some(api::Probe {
                http: Some(api::HttpProbe {
                    port: 80,
                    path: "/healthz".into(),
                }),
                ..Default::default()
            }),
            liveness: Some(api::Probe {
                exec: Some(vec!["test".into(), "-f".into(), "/tmp/alive".into()]),
                ..Default::default()
            }),
            startup: Some(api::Probe {
                tcp: Some(80),
                period_sec: 2,
                ..Default::default()
            }),
        },
        disk_limits: api::DiskLimits {
            bandwidth_mb: Some(32),
            iops: Some(4000),
            burst_sec: Some(10),
        },
        probes_status: api::ProbesStatus {
            startup: Some(api::ProbeStatus {
                passed: true,
                message: "10.64.1.2:80 accepted".into(),
                failures: 0,
                at: ts(),
            }),
            readiness: Some(api::ProbeStatus {
                passed: false,
                message: "HTTP 503".into(),
                failures: 2,
                at: ts(),
            }),
            liveness: None,
        },
        ..Default::default()
    };
    let out = describe(
        &m,
        &[ev(11, "exited", "m_0123456789ab", "killed: out of memory")],
    );
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "Name:          web",
            "ID:            m_0123456789ab",
            "Namespace:     t1",
            "Host:          d1",
            "Image:         nginx:1.27",
            "State:         stopped",
            "Ready:         no",
            "Reason:        exit",
            "Exit:          code 137 at 2026-10-19 08:30:00, out of memory, restarting",
            "Restarts:      2, next at 2026-10-19 08:30:20",
            "Probes:        startup tcp :80, every 2 s: passed (10.64.1.2:80 accepted)",
            "               readiness http :80/healthz, every 10 s: failed 2 in a row (HTTP 503)",
            "               liveness exec test -f /tmp/alive, every 10 s: not run yet",
            "IP:            10.64.1.2",
            "Size:          1 vCPU, 256 MB",
            "CPU limit:     1000m",
            "Volume:        2 GB at /data",
            "Disk limits:   32MB/s 4000io each, 10s burst",
            "Egress:        via:gateway",
            "Runs on:       init 0.1.0+fdad892eeefa, vmm unknown",
            "Endpoints:     ep_1 http 80 -> http://web-ab12.byard.localhost",
            "               ep_2 tcp 5432 -> 10.0.0.5:20001",
            "Sleep:         30m",
            "Backup:        every 6h, keep 4; last 2026-10-19 08:30:00, next 2026-10-19 14:30:00",
            "Pending:       image nginx:1.28, env, size 2 vCPU, 512 MB, volume's filesystem to 20 GB, at the next start (since 2026-10-19 08:30:00)",
            "Version:       12",
            "Created:       2026-10-19 08:30:00",
            "Events:",
            "  2026-10-19 08:30:11  warning  exited           killed: out of memory",
        ]
    );
    // A machine with nothing to say says so.
    let plain = api::Machine {
        state: "created".into(),
        ..m.clone()
    };
    let out = describe(
        &api::Machine {
            exit: None,
            stopped_reason: String::new(),
            endpoints: vec![],
            volume: None,
            host: String::new(),
            backup: None,
            last_backup_at: None,
            restarts: 0,
            restarting_at: None,
            probes: api::Probes::default(),
            pending: None,
            init_version: String::new(),
            ..plain
        },
        &[],
    );
    assert!(out.contains("Endpoints:     none\n"), "{out}");
    assert!(out.contains("Backup:        none\n"), "{out}");
    assert!(out.ends_with("Events:\n  none\n"), "{out}");
    for absent in [
        "Host:",
        "Exit:",
        "Restarts:",
        "Probes:",
        "Pending:",
        "Runs on:",
    ] {
        assert!(!out.contains(absent), "{absent} {out}");
    }
}

#[test]
fn a_watch_line_is_an_event_a_heartbeat_or_the_end() {
    let line = serde_json::to_string(&ev(3, "started", "m1", "running, pid 9")).unwrap();
    assert_eq!(watch_line(&line).unwrap().map(|e| e.seq), Some(3));
    assert!(watch_line("{}\n").unwrap().is_none());
    // A bookmark is not an event: a client that keeps no cursor skips it.
    assert!(watch_line("{\"bookmark\":812}\n").unwrap().is_none());
    let err =
        watch_line(r#"{"error":"the watch fell 9 events behind","code":"lagged"}"#).unwrap_err();
    assert_eq!(err.to_string(), "the watch fell 9 events behind (lagged)");
    assert!(watch_line("not json").is_err());
}

#[tokio::test]
async fn events_are_read_page_after_page_and_a_watch_line_by_line() {
    // A full page, then the rest: the second read starts from the first one's cursor.
    let full = api::EventsPage {
        events: (1..=500).map(|n| ev(n, "created", "m1", "")).collect(),
        next: "500".into(),
    };
    let rest = api::EventsPage {
        events: vec![ev(501, "started", "m1", "")],
        next: "501".into(),
    };
    let ndjson = format!(
        "{}\n{{}}\n{}\n{}\n",
        serde_json::to_string(&ev(7, "stopping", "m1", "")).unwrap(),
        serde_json::to_string(&ev(8, "stopped", "m1", "")).unwrap(),
        r#"{"error":"the daemon is going down: watch again from since=8","code":"shutdown"}"#
    );
    let (url, stub) = stub(vec![
        (
            StatusCode::OK,
            JSON.to_vec(),
            &serde_json::to_string(&full).unwrap(),
        ),
        (
            StatusCode::OK,
            JSON.to_vec(),
            &serde_json::to_string(&rest).unwrap(),
        ),
        (
            StatusCode::OK,
            vec![("content-type", "application/x-ndjson")],
            &ndjson,
        ),
    ])
    .await;
    let c = client(&url, None);
    let (evs, next) = c
        .events("/v1/events?machine=m1", Some("0".into()))
        .await
        .unwrap();
    assert_eq!((evs.len(), next.as_str()), (501, "501"));
    let seen = stub.seen.lock().unwrap().clone();
    assert_eq!(seen[0].path, "/v1/events?machine=m1&since=0");
    assert_eq!(seen[1].path, "/v1/events?machine=m1&since=500");
    // A watch hands over each event and ends with the server's reason.
    let mut got = Vec::new();
    let err = c
        .watch("/v1/events?machine=m1&watch=true", |e| {
            got.push(e.reason.clone())
        })
        .await
        .unwrap_err();
    assert_eq!(got, ["stopping", "stopped"]);
    assert!(err.to_string().ends_with("(shutdown)"), "{err}");
}
