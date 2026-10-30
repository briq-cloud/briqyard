//! Labels, regions, quotas and logs follow (ADR 0025).

use super::*;

#[test]
fn labels_regions_and_quotas_from_the_command_line() {
    match machine(parse(&[
        "machine",
        "ls",
        "--namespace",
        "t1",
        "-l",
        "app=web",
        "--label",
        "tier",
    ])) {
        MachineCmd::Ls { namespace, labels } => {
            assert_eq!(namespace.as_deref(), Some("t1"));
            assert_eq!(labels, ["app=web", "tier"]);
            assert_eq!(
                machines_path(namespace.as_deref(), &labels),
                "/v1/machines?namespace=t1&label=app%3Dweb&label=tier"
            );
        }
        _ => panic!("not a ls"),
    }
    assert_eq!(machines_path(None, &[]), "/v1/machines");
    let MachineCmd::Run(a) = machine(parse(&[
        "m", "run", "--image", "x", "--region", "gra", "-l", "app=web", "-l", "tier=",
    ])) else {
        panic!("not a run")
    };
    assert_eq!(a.region, "gra");
    let labels = label_args(&a.labels).unwrap();
    assert_eq!(labels["app"], "web");
    assert_eq!(labels["tier"], "");
    let MachineCmd::Run(a) = machine(parse(&["m", "run", "--image", "x"])) else {
        panic!("not a run")
    };
    assert_eq!(a.region, "", "any region");
    let err = label_args(&["app".into()]).unwrap_err();
    assert_eq!(err.to_string(), "--label \"app\": want K=V");
    assert!(label_args(&["-app=x".into()]).is_err());
    match machine(parse(&["machine", "logs", "-f", "m1"])) {
        MachineCmd::Logs { follow, id, .. } => assert!(follow && id == "m1"),
        _ => panic!("not logs"),
    }
    match parse(&[
        "namespace",
        "quota",
        "t1",
        "--machines",
        "1",
        "--memory-mb",
        "2048",
        "--region",
        "vin",
    ])
    .cmd
    {
        Cmd::Namespace(NamespaceCmd::Quota {
            id,
            machines,
            memory_mb,
            vcpus,
            disk_gb,
            region,
            cpu_millis: None,
        }) => {
            assert_eq!(id, "t1");
            assert_eq!(
                (machines, memory_mb, vcpus, disk_gb),
                (Some(1), Some(2048), None, None)
            );
            assert_eq!(
                namespace_put_path(&id, "quota", region.as_deref()),
                "/v1/namespaces/t1/quota?region=vin"
            );
        }
        _ => panic!("not a quota"),
    }
    assert_eq!(
        fails(&["namespace", "quota", "t1", "--machines", "-1"]),
        ErrorKind::UnknownArgument
    );
    match parse(&[
        "namespace",
        "gateway",
        "set",
        "t1",
        "--image",
        "i",
        "--port",
        "1",
        "--region",
        "gra",
    ])
    .cmd
    {
        Cmd::Namespace(NamespaceCmd::Gateway(GatewayCmd::Set(a))) => {
            let region = a.region;
            assert_eq!(region.as_deref(), Some("gra"))
        }
        _ => panic!("not a gateway set"),
    }
    assert_eq!(
        namespace_put_path("t1", "gateway", None),
        "/v1/namespaces/t1/gateway"
    );
}

#[test]
fn a_follow_line_is_a_console_line_a_heartbeat_or_the_end() {
    let l = follow_line(r#"{"ts":"2026-10-21T10:00:00Z","line":"hello"}"#).unwrap();
    assert!(matches!(l, ControlFlow::Continue(Some(ref l)) if l.line == "hello"));
    assert!(matches!(
        follow_line("{}\n").unwrap(),
        ControlFlow::Continue(None)
    ));
    // A destroyed machine ends it, not as an error.
    let end = follow_line(r#"{"error":"machine m1 was destroyed","code":"destroyed"}"#).unwrap();
    assert!(matches!(end, ControlFlow::Break(ref why) if why == "machine m1 was destroyed"));
    let err = follow_line(r#"{"error":"the daemon is going down","code":"shutdown"}"#).unwrap_err();
    assert_eq!(err.to_string(), "the daemon is going down (shutdown)");
    assert!(follow_line("not json").is_err());
}

#[tokio::test]
async fn a_follow_prints_until_the_machine_is_destroyed() {
    let ndjson = concat!(
        r#"{"ts":"2026-10-21T10:00:00Z","line":"one"}"#,
        "\n",
        "{}\n",
        r#"{"ts":"2026-10-21T10:00:01Z","line":"two"}"#,
        "\n",
        r#"{"error":"machine m1 was destroyed","code":"destroyed"}"#,
        "\n",
    );
    let (url, stub) = stub(vec![(
        StatusCode::OK,
        vec![("content-type", "application/x-ndjson")],
        ndjson,
    )])
    .await;
    let c = client(&url, None);
    let mut got = vec![];
    c.stream("/v1/machines/m1/logs?since=&follow=true", |line| {
        Ok(match follow_line(line)? {
            ControlFlow::Continue(l) => {
                got.extend(l.map(|l| l.line));
                ControlFlow::Continue(())
            }
            ControlFlow::Break(_) => ControlFlow::Break(()),
        })
    })
    .await
    .unwrap();
    assert_eq!(got, ["one", "two"]);
    assert_eq!(
        stub.seen.lock().unwrap()[0].path,
        "/v1/machines/m1/logs?since=&follow=true"
    );
}
