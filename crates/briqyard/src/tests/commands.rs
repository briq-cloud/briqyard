//! The commands' arguments, one family after another.

use super::*;

#[test]
fn machine_lifecycle_commands() {
    match machine(parse(&["machine", "stop", "--suspend", "m1"])) {
        MachineCmd::Stop { suspend, id } => assert!(suspend && id == "m1"),
        _ => panic!("not a stop"),
    }
    match machine(parse(&["machine", "stop", "m1"])) {
        MachineCmd::Stop { suspend, .. } => assert!(!suspend),
        _ => panic!("not a stop"),
    }
    for (args, want) in [
        (vec!["machine", "get", "m1"], "get"),
        (vec!["machine", "start", "m1"], "start"),
        (vec!["machine", "wake", "m1"], "wake"),
        (vec!["machine", "touch", "m1"], "touch"),
        (vec!["machine", "wait", "m1"], "wait"),
        (vec!["machine", "rm", "m1"], "rm"),
        (vec!["machine", "destroy", "m1"], "rm"),
        (vec!["machine", "stats", "m1"], "stats"),
        (vec!["machine", "restart", "m1"], "restart"),
    ] {
        let got = match machine(parse(&args)) {
            MachineCmd::Get { id } if id == "m1" => "get",
            MachineCmd::Start { id } if id == "m1" => "start",
            MachineCmd::Wake { id } if id == "m1" => "wake",
            MachineCmd::Touch { id } if id == "m1" => "touch",
            MachineCmd::Wait { id, until } if id == "m1" && until == "ready" => "wait",
            MachineCmd::Rm { id } if id == "m1" => "rm",
            MachineCmd::Stats { id } if id == "m1" => "stats",
            MachineCmd::Restart { id } if id == "m1" => "restart",
            _ => "?",
        };
        assert_eq!(got, want, "{args:?}");
    }
    match machine(parse(&["machine", "wait", "--for", "running", "m1"])) {
        MachineCmd::Wait { until, .. } => assert_eq!(until, "running"),
        _ => panic!("not a wait"),
    }
    assert_eq!(
        fails(&["machine", "wait", "--for", "up", "m1"]),
        ErrorKind::InvalidValue
    );
    let MachineCmd::Run(a) = machine(parse(&[
        "m",
        "run",
        "--image",
        "x",
        "--readiness",
        "http:8080/",
        "--liveness",
        "exec:test -f /tmp/alive",
    ])) else {
        panic!("not a run")
    };
    assert_eq!(a.readiness.and_then(|p| p.http).map(|h| h.port), Some(8080));
    assert_eq!(a.liveness.and_then(|p| p.exec).map(|c| c.len()), Some(3));
    assert!(a.startup.is_none());
    assert_eq!(
        fails(&["m", "run", "--image", "x", "--startup", "udp:53"]),
        ErrorKind::ValueValidation
    );
    for sub in [
        "get", "start", "stop", "wake", "touch", "wait", "rm", "stats", "fork", "logs",
    ] {
        assert_eq!(
            fails(&["machine", sub]),
            ErrorKind::MissingRequiredArgument,
            "{sub} needs an id"
        );
    }
    // Snapshots: create (named, with memory), ls, restore and rm, each on a machine; restore
    // and rm name the snapshot too.
    for (args, want) in [
        (vec!["machine", "snapshot", "create", "m1"], "create"),
        (
            vec![
                "machine", "snapshot", "create", "--name", "before", "--memory", "m1",
            ],
            "create before with memory",
        ),
        (vec!["machine", "snapshot", "ls", "m1"], "ls"),
        (
            vec!["machine", "snapshot", "restore", "m1", "before"],
            "restore",
        ),
        (vec!["machine", "snapshot", "rm", "m1", "s_1"], "rm"),
    ] {
        let got = match machine(parse(&args)) {
            MachineCmd::Snapshot(SnapshotCmd::Create {
                name, memory, id, ..
            }) if id == "m1" => match (name, memory) {
                (None, false) => "create",
                (Some(n), true) if n == "before" => "create before with memory",
                _ => "?",
            },
            MachineCmd::Snapshot(SnapshotCmd::Ls { id }) if id == "m1" => "ls",
            MachineCmd::Snapshot(SnapshotCmd::Restore { id, snap })
                if id == "m1" && snap == "before" =>
            {
                "restore"
            }
            MachineCmd::Snapshot(SnapshotCmd::Rm { id, snap }) if id == "m1" && snap == "s_1" => {
                "rm"
            }
            _ => "?",
        };
        assert_eq!(got, want, "{args:?}");
    }
    for args in [
        vec!["machine", "snapshot", "create"],
        vec!["machine", "snapshot", "restore", "m1"],
        vec!["machine", "snapshot", "rm", "m1"],
    ] {
        assert_eq!(fails(&args), ErrorKind::MissingRequiredArgument, "{args:?}");
    }
    match machine(parse(&["machine", "ls", "--namespace", "t1"])) {
        MachineCmd::Ls { namespace, labels } => {
            assert_eq!(namespace.as_deref(), Some("t1"));
            assert!(labels.is_empty());
        }
        _ => panic!("not an ls"),
    }
    match machine(parse(&["m", "ls"])) {
        MachineCmd::Ls { namespace, .. } => assert_eq!(namespace, None),
        _ => panic!("not an ls"),
    }
    match machine(parse(&[
        "machine", "logs", "-f", "--since", "c9", "--limit", "10", "m1",
    ])) {
        MachineCmd::Logs {
            since,
            limit,
            follow,
            id,
        } => {
            assert_eq!(since.as_deref(), Some("c9"));
            assert_eq!(limit, 10);
            assert!(follow);
            assert_eq!(id, "m1");
        }
        _ => panic!("not logs"),
    }
    match machine(parse(&["machine", "logs", "m1"])) {
        MachineCmd::Logs {
            since,
            limit,
            follow,
            ..
        } => assert!(since.is_none() && limit == 500 && !follow),
        _ => panic!("not logs"),
    }
    match machine(parse(&["machine", "fork", "--name", "copy", "m1"])) {
        MachineCmd::Fork {
            name,
            namespace,
            id,
            ..
        } => assert_eq!(
            (name.as_deref(), namespace, id.as_str()),
            (Some("copy"), None, "m1")
        ),
        _ => panic!("not a fork"),
    }
    match machine(parse(&["machine", "fork", "m1", "--namespace", "t2"])) {
        MachineCmd::Fork { namespace, .. } => assert_eq!(namespace.as_deref(), Some("t2")),
        _ => panic!("not a fork"),
    }
    match machine(parse(&["machine", "move", "m1", "--namespace", "t2"])) {
        MachineCmd::Move { namespace, id } => {
            assert_eq!((namespace.as_str(), id.as_str()), ("t2", "m1"))
        }
        _ => panic!("not a move"),
    }
    assert_eq!(
        fails(&["machine", "move", "m1"]),
        ErrorKind::MissingRequiredArgument
    );
    match machine(parse(&[
        "machine",
        "put",
        "m1",
        "./local.txt",
        "/etc/remote.txt",
    ])) {
        MachineCmd::Put {
            id,
            local,
            guest_path,
        } => assert_eq!(
            (id.as_str(), local.as_str(), guest_path.as_str()),
            ("m1", "./local.txt", "/etc/remote.txt")
        ),
        _ => panic!("not a put"),
    }
    match machine(parse(&["machine", "get-file", "m1", "/etc/remote.txt"])) {
        MachineCmd::GetFile { id, guest_path } => {
            assert_eq!(
                (id.as_str(), guest_path.as_str()),
                ("m1", "/etc/remote.txt")
            )
        }
        _ => panic!("not a get-file"),
    }
    assert_eq!(
        fails(&["machine", "put", "m1", "./only"]),
        ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn endpoint_namespace_and_image_commands() {
    match parse(&["endpoint", "add", "--http", "--host", "web", "m1", "8080"]).cmd {
        Cmd::Endpoint(EndpointCmd::Add {
            http,
            host,
            id,
            port,
        }) => {
            assert!(http);
            assert_eq!(host.as_deref(), Some("web"));
            assert_eq!((id.as_str(), port), ("m1", 8080));
        }
        _ => panic!("not an endpoint add"),
    }
    match parse(&["ep", "add", "m1", "5432"]).cmd {
        Cmd::Endpoint(EndpointCmd::Add {
            http, host, port, ..
        }) => assert!(!http && host.is_none() && port == 5432),
        _ => panic!("not an endpoint add"),
    }
    assert_eq!(
        fails(&["endpoint", "add", "m1"]),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        fails(&["endpoint", "add", "m1", "http"]),
        ErrorKind::ValueValidation
    );
    assert_eq!(
        fails(&["endpoint", "add", "m1", "70000"]),
        ErrorKind::ValueValidation
    );
    assert!(matches!(
        parse(&["endpoint", "ls"]).cmd,
        Cmd::Endpoint(EndpointCmd::Ls)
    ));
    match parse(&["endpoint", "rm", "e1"]).cmd {
        Cmd::Endpoint(EndpointCmd::Rm { id }) => assert_eq!(id, "e1"),
        _ => panic!("not an endpoint rm"),
    }
    assert!(matches!(
        parse(&["namespace", "ls"]).cmd,
        Cmd::Namespace(NamespaceCmd::Ls)
    ));
    match parse(&["namespace", "rm", "t1"]).cmd {
        Cmd::Namespace(NamespaceCmd::Rm { id }) => assert_eq!(id, "t1"),
        _ => panic!("not a namespace rm"),
    }
    assert_eq!(
        fails(&["namespace", "rm"]),
        ErrorKind::MissingRequiredArgument
    );
    match parse(&["namespace", "get", "t1"]).cmd {
        Cmd::Namespace(NamespaceCmd::Get { id }) => assert_eq!(id, "t1"),
        _ => panic!("not a namespace get"),
    }
    match parse(&[
        "namespace",
        "gateway",
        "set",
        "t1",
        "--image",
        "proxy:1",
        "--port",
        "3128",
        "-e",
        "TOKEN=a=b",
        "--file",
        "/etc/proxy.yaml=proxy.yaml",
        "--",
        "proxy",
        "-v",
    ])
    .cmd
    {
        Cmd::Namespace(NamespaceCmd::Gateway(GatewayCmd::Set(a))) => {
            let GatewaySetArgs {
                namespace,
                region,
                start,
                image,
                port,
                readiness,
                envs,
                files,
                cmd,
                ..
            } = *a;
            assert_eq!(files, ["/etc/proxy.yaml=proxy.yaml"]);
            assert_eq!(
                (namespace.as_str(), image.as_str(), port),
                ("t1", "proxy:1", 3128)
            );
            assert!(readiness.is_none(), "its port, unless a probe is named");
            assert!(!start, "made, not started, unless asked");
            assert!(region.is_none());
            assert_eq!(env_args(&envs).unwrap()["TOKEN"], "a=b");
            assert_eq!(cmd, ["proxy", "-v"]);
        }
        _ => panic!("not a gateway set"),
    }
    match parse(&[
        "namespace",
        "gateway",
        "set",
        "t1",
        "--image",
        "proxy:1",
        "--port",
        "3128",
        "--start",
    ])
    .cmd
    {
        Cmd::Namespace(NamespaceCmd::Gateway(GatewayCmd::Set(a))) => {
            assert!(a.start && a.cmd.is_empty())
        }
        _ => panic!("not a gateway set"),
    }
    // An image and a port are what a gateway needs.
    assert_eq!(
        fails(&["namespace", "gateway", "set", "t1", "--image", "proxy:1"]),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        fails(&["namespace", "gateway", "set", "t1", "--port", "3128"]),
        ErrorKind::MissingRequiredArgument
    );
    match parse(&["namespace", "gateway", "rm", "t1"]).cmd {
        Cmd::Namespace(NamespaceCmd::Gateway(GatewayCmd::Rm { namespace })) => {
            assert_eq!(namespace, "t1")
        }
        _ => panic!("not a gateway rm"),
    }
    assert!(env_args(&["NOEQUALS".into()]).is_err());
    match parse(&["namespace", "unpin", "t1"]).cmd {
        Cmd::Namespace(NamespaceCmd::Unpin { id }) => assert_eq!(id, "t1"),
        _ => panic!("not a namespace unpin"),
    }
    assert!(matches!(
        parse(&["image", "ls"]).cmd,
        Cmd::Image(ImageCmd::Ls)
    ));
    match parse(&["image", "rm", "k1"]).cmd {
        Cmd::Image(ImageCmd::Rm { key }) => assert_eq!(key, "k1"),
        _ => panic!("not an image rm"),
    }
}

#[test]
fn host_commands() {
    assert!(matches!(parse(&["host", "ls"]).cmd, Cmd::Host(HostCmd::Ls)));
    // The fleet buys no server (ADR 0042).
    assert_eq!(fails(&["host", "order"]), ErrorKind::InvalidSubcommand);
    match parse(&["host", "retire", "h_1"]).cmd {
        Cmd::Host(HostCmd::Retire { id }) => assert_eq!(id, "h_1"),
        _ => panic!("not a retire"),
    }
    match parse(&["host", "drain", "h_1"]).cmd {
        Cmd::Host(HostCmd::Drain { id }) => assert_eq!(id, "h_1"),
        _ => panic!("not a drain"),
    }
    match parse(&["host", "rm", "h_1"]).cmd {
        Cmd::Host(HostCmd::Rm { id, force }) => assert!(id == "h_1" && !force),
        _ => panic!("not a rm"),
    }
    match parse(&["host", "rm", "h_1", "--force"]).cmd {
        Cmd::Host(HostCmd::Rm { force, .. }) => assert!(force),
        _ => panic!("not a rm"),
    }
    match parse(&[
        "host",
        "add",
        "51.68.1.2",
        "--address",
        "10.42.0.11",
        "--region",
        "gra",
    ])
    .cmd
    {
        Cmd::Host(HostCmd::Add {
            ssh,
            address,
            region,
            id,
            ..
        }) => assert_eq!(
            (ssh.as_str(), address.as_str(), region.as_str(), id.as_str()),
            ("51.68.1.2", "10.42.0.11", "gra", ""),
            "the fleet names it"
        ),
        _ => panic!("not an add"),
    }
    for sub in ["add", "retire", "drain", "rm"] {
        assert_eq!(
            fails(&["host", sub]),
            ErrorKind::MissingRequiredArgument,
            "{sub}"
        );
    }
}

#[test]
fn usage_takes_a_range_of_hours() {
    let utc = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    match parse(&[
        "usage",
        "--from",
        "2026-10-20T16:00:00+02:00",
        "--to",
        "2026-10-20T15:00:00Z",
        "--namespace",
        "t1",
        "--json",
    ])
    .cmd
    {
        Cmd::Usage {
            from,
            to,
            namespace,
            json,
        } => {
            assert_eq!(from, utc("2026-10-20T14:00:00Z"), "read as UTC");
            assert_eq!(to, utc("2026-10-20T15:00:00Z"));
            assert_eq!(namespace.as_deref(), Some("t1"));
            assert!(json);
            // In UTC, the query needs no escaping.
            assert_eq!(
                usage_path(from, to, namespace.as_deref()),
                "/v1/usage?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z&namespace=t1"
            );
            assert_eq!(
                usage_path(from, to, None),
                "/v1/usage?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z"
            );
        }
        _ => panic!("not a usage"),
    }
    assert_eq!(
        fails(&["usage", "--to", "2026-10-20T15:00:00Z"]),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        fails(&["usage", "--from", "today", "--to", "2026-10-20T15:00:00Z"]),
        ErrorKind::ValueValidation
    );
}

#[test]
fn backup_schedules_and_backup_commands() {
    let run = |extra: &[&str]| -> Result<Option<Option<api::BackupPolicy>>> {
        let args: Vec<&str> = ["machine", "run", "--image", "x"]
            .iter()
            .chain(extra)
            .copied()
            .collect();
        let MachineCmd::Run(a) = machine(parse(&args)) else {
            panic!("not a run");
        };
        a.backup.request()
    };
    assert_eq!(run(&[]).unwrap(), None, "the host's default");
    assert_eq!(
        run(&["--backup-every", "6h", "--backup-keep", "4"]).unwrap(),
        Some(Some(api::BackupPolicy {
            every: "6h".into(),
            keep: 4
        }))
    );
    assert_eq!(run(&["--no-backup"]).unwrap(), Some(None));
    // Checked as the daemon checks it, before any request.
    let err = run(&["--backup-every", "30m", "--backup-keep", "4"]).unwrap_err();
    assert_eq!(err.to_string(), r#"backup.every "30m": at least 1h"#);
    for bad in [
        vec!["machine", "run", "--image", "x", "--backup-every", "6h"],
        vec!["machine", "run", "--image", "x", "--backup-keep", "4"],
    ] {
        assert_eq!(fails(&bad), ErrorKind::MissingRequiredArgument, "{bad:?}");
    }
    assert_eq!(
        fails(&[
            "machine",
            "run",
            "--image",
            "x",
            "--no-backup",
            "--backup-every",
            "6h",
            "--backup-keep",
            "1"
        ]),
        ErrorKind::ArgumentConflict
    );
    match machine(parse(&[
        "machine",
        "set-backup",
        "m1",
        "--every",
        "1d",
        "--keep",
        "5",
    ])) {
        MachineCmd::SetBackup {
            id,
            every,
            keep,
            off,
        } => {
            assert_eq!(
                (id.as_str(), every.as_deref(), keep, off),
                ("m1", Some("1d"), Some(5), false)
            )
        }
        _ => panic!("not set-backup"),
    }
    match machine(parse(&["machine", "set-backup", "m1", "--off"])) {
        MachineCmd::SetBackup { off, every, .. } => assert!(off && every.is_none()),
        _ => panic!("not set-backup"),
    }
    assert_eq!(
        fails(&["machine", "set-backup", "m1"]),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        fails(&[
            "machine",
            "set-backup",
            "m1",
            "--off",
            "--every",
            "1d",
            "--keep",
            "1"
        ]),
        ErrorKind::ArgumentConflict
    );
    match parse(&["backup", "rm", "m1", "b1", "--chain"]).cmd {
        Cmd::Backup(BackupCmd::Rm {
            machine,
            backup,
            chain,
            namespace,
        }) => {
            assert_eq!(
                backup_rm_path(&machine, &backup, chain, namespace.as_deref()),
                "/v1/machines/m1/backups/b1?chain=true"
            )
        }
        _ => panic!("not backup rm"),
    }
    assert_eq!(
        backup_rm_path("m1", "b1", false, None),
        "/v1/machines/m1/backups/b1"
    );
    assert_eq!(
        backup_rm_path("m1", "b1", true, Some("t1")),
        "/v1/machines/m1/backups/b1?chain=true&namespace=t1"
    );
    match parse(&["backups", "--namespace", "t1", "--machine", "m1"]).cmd {
        Cmd::Backups { namespace, machine } => {
            assert_eq!(
                (namespace.as_deref(), machine.as_deref()),
                (Some("t1"), Some("m1"))
            )
        }
        _ => panic!("not backups"),
    }
    assert!(matches!(
        parse(&["backups"]).cmd,
        Cmd::Backups {
            namespace: None,
            machine: None
        }
    ));
    assert_eq!(
        fails(&["backup", "rm", "m1"]),
        ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn template_commands_keep_seal_and_named_memory_selection_explicit() {
    match machine(parse(&[
        "machine",
        "fork",
        "m1",
        "--snapshot",
        "ready",
        "--name",
        "clone",
    ])) {
        MachineCmd::Fork { snapshot, name, .. } => {
            assert_eq!(snapshot.as_deref(), Some("ready"));
            assert_eq!(name.as_deref(), Some("clone"));
        }
        _ => panic!("not a fork"),
    }
    match machine(parse(&[
        "machine",
        "snapshot",
        "create",
        "m1",
        "--memory",
        "--template",
    ])) {
        MachineCmd::Snapshot(SnapshotCmd::Create {
            memory, template, ..
        }) => assert!(memory && template),
        _ => panic!("not a seal"),
    }
    match machine(parse(&[
        "machine",
        "run",
        "--image",
        "docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f",
        "--memory",
        "256",
        "--template-build",
        "init-ready-v1",
    ])) {
        MachineCmd::Run(a) => assert_eq!(a.template_build.as_deref(), Some("init-ready-v1")),
        _ => panic!("not a builder"),
    }
}
