//! Argument parsing.

use super::*;

#[test]
fn global_flags_go_before_or_after_the_command() {
    let cli = parse(&["--url", "http://fleet:7430/", "--token", "t", "status"]);
    assert_eq!(cli.url, "http://fleet:7430/");
    assert_eq!(cli.token.as_deref(), Some("t"));
    assert!(matches!(cli.cmd, Cmd::Status));
    let cli = parse(&["status", "--url", "http://fleet:7430", "--token", "t"]);
    assert_eq!(cli.url, "http://fleet:7430");
    assert!(matches!(parse(&["openapi"]).cmd, Cmd::Openapi));
    assert!(matches!(parse(&["doctor"]).cmd, Cmd::Doctor));
    assert_eq!(
        fails(&[]),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
        "no command: the help"
    );
    assert_eq!(fails(&["--help"]), ErrorKind::DisplayHelp);
    assert_eq!(fails(&["--version"]), ErrorKind::DisplayVersion);
    assert_eq!(fails(&["nope"]), ErrorKind::InvalidSubcommand);
}

#[test]
fn a_daemon_is_pinned_by_its_certificate() {
    let fp = "ab".repeat(32);
    let cli = parse(&[
        "--url",
        "https://10.0.0.5:7420",
        "--tls-fingerprint",
        &fp,
        "status",
    ]);
    assert_eq!(cli.tls_fingerprint.as_deref(), Some(fp.as_str()));
    // As openssl prints it.
    let colons = vec!["AB"; 32].join(":");
    let cli = parse(&["status", "--tls-fingerprint", &colons]);
    assert_eq!(cli.tls_fingerprint.as_deref(), Some(fp.as_str()));
    assert_eq!(
        parse(&["status"]).tls_fingerprint,
        None,
        "a fleet: the web PKI"
    );
    assert_eq!(
        fails(&["--tls-fingerprint", "abc", "status"]),
        ErrorKind::ValueValidation
    );
    http_client(Some(&fp)).unwrap();
    http_client(None).unwrap();
}

#[test]
fn machine_run_takes_every_setting() {
    let cli = parse(&[
        "machine",
        "run",
        "--image",
        "ghcr.io/x/nginx:1.27",
        "--name",
        "web",
        "--namespace",
        "t1",
        "--vcpus",
        "2",
        "--memory",
        "1024",
        "--sleep",
        "2h",
        "--volume",
        "10G:/data",
        "-e",
        "A=1",
        "--env",
        "B=x=y",
        "-p",
        "80",
        "--port",
        "443",
        "--file",
        "/etc/app.conf=./app.conf",
        "--entrypoint",
        "/bin/sh",
        // A value starting with a dash goes with its flag, as clap reads it.
        "--entrypoint=-c",
        "--no-start",
        "--",
        "nginx",
        "-g",
        "daemon off;",
    ]);
    let MachineCmd::Run(a) = machine(cli) else {
        panic!("not a run");
    };
    assert_eq!(a.image, "ghcr.io/x/nginx:1.27");
    assert_eq!(a.name.as_deref(), Some("web"));
    assert_eq!(a.namespace, "t1");
    assert_eq!((a.vcpus, a.memory), (2, 1024));
    assert_eq!(a.sleep, "2h");
    assert_eq!(a.volume.as_deref(), Some("10G:/data"));
    assert_eq!(a.envs, ["A=1", "B=x=y"]);
    assert_eq!(a.ports, [80, 443]);
    assert_eq!(a.files, ["/etc/app.conf=./app.conf"]);
    assert_eq!(a.entrypoint, ["/bin/sh", "-c"]);
    assert!(a.no_start);
    assert_eq!(a.cmd, ["nginx", "-g", "daemon off;"]);
}

#[test]
fn machine_run_defaults() {
    let MachineCmd::Run(a) = machine(parse(&["m", "run", "--image", "nginx"])) else {
        panic!("not a run");
    };
    assert_eq!(a.name, None);
    assert_eq!(a.namespace, "default");
    assert_eq!((a.vcpus, a.memory), (1, 512));
    assert_eq!(a.sleep, "", "the daemon's default window");
    assert_eq!(a.volume, None);
    assert!(a.envs.is_empty() && a.ports.is_empty() && a.files.is_empty());
    assert!(a.entrypoint.is_empty() && a.cmd.is_empty());
    assert!(!a.no_start);
    assert_eq!(
        fails(&["machine", "run"]),
        ErrorKind::MissingRequiredArgument,
        "an image is required"
    );
    assert_eq!(
        fails(&["machine", "run", "--image", "nginx", "--port", "http"]),
        ErrorKind::ValueValidation
    );
}

#[test]
fn a_bad_sleep_window_is_refused_before_any_request() {
    for ok in ["30m", "2h", "7d", "never", ""] {
        let MachineCmd::Run(a) = machine(parse(&["machine", "run", "--image", "x", "--sleep", ok]))
        else {
            panic!("not a run");
        };
        assert_eq!(a.sleep, ok);
    }
    for bad in ["1y", "0m", "soon", "30"] {
        assert_eq!(
            fails(&["machine", "run", "--image", "x", "--sleep", bad]),
            ErrorKind::ValueValidation,
            "{bad}"
        );
        assert_eq!(
            fails(&["machine", "set-sleep", "m1", bad]),
            ErrorKind::ValueValidation,
            "{bad}"
        );
    }
    let err = match Cli::try_parse_from([
        "briqyard", "machine", "run", "--image", "x", "--sleep", "1y",
    ]) {
        Ok(_) => panic!("parsed"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("want \"30m\", \"2h\", \"7d\" or \"never\""),
        "{err}"
    );
    match machine(parse(&["machine", "set-sleep", "m1", "never"])) {
        MachineCmd::SetSleep { id, sleep } => {
            assert_eq!((id.as_str(), sleep.as_str()), ("m1", "never"))
        }
        _ => panic!("not set-sleep"),
    }
}

#[test]
fn an_egress_policy_is_read_as_the_daemon_checks_it() {
    let egress = |mode: &str, via: Option<&str>| api::Egress {
        mode: mode.into(),
        via: via.map(String::from),
    };
    for (arg, want) in [
        ("open", egress("open", None)),
        ("none", egress("none", None)),
        ("via:m_0123456789ab", egress("via", Some("m_0123456789ab"))),
        ("via:gateway", egress("via", Some("gateway"))),
    ] {
        let MachineCmd::Run(a) = machine(parse(&["m", "run", "--image", "x", "--egress", arg]))
        else {
            panic!("not a run");
        };
        assert_eq!(a.egress.as_ref(), Some(&want), "{arg}");
        assert_eq!(egress_label(&want), arg, "shown as it is written");
        match machine(parse(&["machine", "set-egress", "m1", arg])) {
            MachineCmd::SetEgress { id, egress } => assert_eq!((id, egress), ("m1".into(), want)),
            _ => panic!("not set-egress"),
        }
    }
    let MachineCmd::Run(a) = machine(parse(&["m", "run", "--image", "x"])) else {
        panic!("not a run");
    };
    assert_eq!(a.egress, None, "the daemon's default: open");
    for bad in ["all", "via", "via:", "via:../x", "open:m_1", ""] {
        assert_eq!(
            fails(&["machine", "run", "--image", "x", "--egress", bad]),
            ErrorKind::ValueValidation,
            "{bad}"
        );
        assert_eq!(
            fails(&["machine", "set-egress", "m1", bad]),
            ErrorKind::ValueValidation,
            "{bad}"
        );
    }
    assert_eq!(
        fails(&["machine", "set-egress", "m1"]),
        ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn disk_limits_are_read_as_the_daemon_checks_them() {
    let run = |extra: &[&str]| {
        let args = [&["machine", "run", "--image", "x"][..], extra].concat();
        let MachineCmd::Run(a) = machine(parse(&args)) else {
            panic!("not a run");
        };
        a.disk.request()
    };
    // Nothing named: none sent, the host's for its size apply.
    assert_eq!(run(&[]).unwrap(), None);
    assert_eq!(
        run(&["--disk-bw", "8", "--disk-iops", "500", "--disk-burst", "0"]).unwrap(),
        Some(api::DiskLimits {
            bandwidth_mb: Some(8),
            iops: Some(500),
            burst_sec: Some(0),
        })
    );
    let MachineCmd::SetDiskLimits { id, limits } = machine(parse(&[
        "machine",
        "set-disk-limits",
        "m1",
        "--disk-bw",
        "0",
    ])) else {
        panic!("not set-disk-limits");
    };
    assert_eq!(id, "m1");
    assert_eq!(
        limits.request().unwrap(),
        Some(api::DiskLimits {
            bandwidth_mb: Some(0),
            ..Default::default()
        })
    );
    assert_eq!(
        run(&["--disk-iops", "20000000"]).unwrap_err().to_string(),
        "disk_limits.iops: at most 10000000"
    );
}

#[test]
fn limits_are_read_as_the_daemon_checks_them() {
    let run = |extra: &[&str]| {
        let args = [&["machine", "run", "--image", "x"][..], extra].concat();
        let MachineCmd::Run(a) = machine(parse(&args)) else {
            panic!("not a run");
        };
        a.limits.request()
    };
    // Nothing named: none sent, the host's apply.
    assert_eq!(run(&[]).unwrap(), None);
    assert_eq!(
        run(&[
            "--block-port",
            "25",
            "--block-port",
            "465",
            "--conn-per-min",
            "600",
            "--bandwidth",
            "100"
        ])
        .unwrap(),
        Some(api::EgressLimits {
            blocked_ports: Some(vec![25, 465]),
            new_connections_per_minute: Some(600),
            bandwidth_mbit: Some(100),
        })
    );
    // set-limits sends the ones it names; 0 lifts one.
    let MachineCmd::SetLimits { id, limits } = machine(parse(&[
        "machine",
        "set-limits",
        "m1",
        "--conn-per-min",
        "0",
    ])) else {
        panic!("not set-limits");
    };
    assert_eq!(id, "m1");
    assert_eq!(
        limits.request().unwrap(),
        Some(api::EgressLimits {
            new_connections_per_minute: Some(0),
            ..Default::default()
        })
    );
    // Refused before the request, as the daemon would.
    assert_eq!(
        run(&["--block-port", "0"]).unwrap_err().to_string(),
        "limits.blocked_ports: 0 is not a port"
    );
    assert_eq!(
        run(&["--bandwidth", "200000"]).unwrap_err().to_string(),
        "limits.bandwidth_mbit: at most 100000"
    );
    assert_eq!(
        fails(&["machine", "run", "--image", "x", "--block-port", "smtp"]),
        ErrorKind::ValueValidation
    );
    assert_eq!(
        fails(&["machine", "set-limits"]),
        ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn machine_exec_takes_the_command_after_the_dashes() {
    match machine(parse(&[
        "machine",
        "exec",
        "--no-wake",
        "--timeout",
        "10s",
        "-it",
        "m1",
        "--",
        "sh",
        "-c",
        "ls -la",
    ])) {
        MachineCmd::Exec {
            no_wake,
            timeout,
            interactive,
            tty,
            id,
            cmd,
        } => {
            assert!(no_wake);
            assert_eq!(timeout.map(Duration::from), Some(Duration::from_secs(10)));
            assert!(interactive && tty);
            assert_eq!(id, "m1");
            assert_eq!(cmd, ["sh", "-c", "ls -la"]);
        }
        _ => panic!("not an exec"),
    }
    match machine(parse(&["machine", "exec", "m1", "--", "true"])) {
        MachineCmd::Exec {
            no_wake,
            timeout,
            interactive,
            tty,
            cmd,
            ..
        } => {
            assert!(!no_wake, "wakes by default");
            assert_eq!(timeout, None, "the daemon's default");
            assert!(!interactive && !tty);
            assert_eq!(cmd, ["true"]);
        }
        _ => panic!("not an exec"),
    }
    match machine(parse(&[
        "machine",
        "exec",
        "--interactive",
        "m1",
        "--",
        "cat",
    ])) {
        MachineCmd::Exec {
            interactive, tty, ..
        } => assert!(interactive && !tty),
        _ => panic!("not an exec"),
    }
    assert_eq!(
        fails(&["machine", "exec", "m1"]),
        ErrorKind::MissingRequiredArgument,
        "a command is required"
    );
    assert_eq!(
        fails(&["machine", "exec", "--timeout", "5x", "m1", "--", "true"]),
        ErrorKind::ValueValidation
    );
}

#[test]
fn machine_set_changes_what_it_runs() {
    let set = |args: &[&str]| match machine(parse(args)) {
        MachineCmd::Set(a) => a,
        _ => panic!("not a set"),
    };
    let a = set(&[
        "machine",
        "set",
        "m1",
        "--image",
        "python:3.13-alpine",
        "-e",
        "V=2",
        "-e",
        "W=a=b",
        "--memory",
        "1024",
        "--vcpus",
        "2",
        "-p",
        "8080",
        "--restart",
        "on-failure:5",
        "--volume-gb",
        "20",
        "--",
        "python3",
        "-m",
        "http.server",
    ]);
    assert_eq!(a.id, "m1");
    let req = a.request(None).unwrap();
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::json!({
            "image": "python:3.13-alpine",
            "cmd": ["python3", "-m", "http.server"],
            "env": {"V": "2", "W": "a=b"},
            "size": {"vcpus": 2, "memory_mb": 1024},
            "ports": [8080],
            "restart": {"policy": "on-failure", "max_retries": 5},
            "volume": {"size_gb": 20}
        }),
        "only what was named; the size whole"
    );
    // Half a size takes the other half from the machine.
    let half = set(&["m", "set", "m1", "--memory", "2048"]);
    let now = api::Size {
        vcpus: 4,
        memory_mb: 512,
    };
    assert_eq!(
        half.request(Some(now)).unwrap().spec.size,
        Some(api::Size {
            vcpus: 4,
            memory_mb: 2048
        })
    );
    assert!(half.request(None).is_err());
    // Nothing named, or what the daemon would refuse, is refused before any request.
    let err = set(&["m", "set", "m1"]).request(None).unwrap_err();
    assert!(err.to_string().starts_with("name a change"), "{err}");
    let err = set(&["m", "set", "m1", "--image", ""])
        .request(None)
        .unwrap_err();
    assert_eq!(err.to_string(), "image must not be empty");
    let err = set(&["m", "set", "m1", "-p", "0"])
        .request(None)
        .unwrap_err();
    assert_eq!(err.to_string(), "ports: 0 is not a port");
    let err = set(&["m", "set", "m1", "--volume-gb", "0"])
        .request(None)
        .unwrap_err();
    assert_eq!(err.to_string(), "volume.size_gb must be 1 or more");
    // A restart policy, Docker's way.
    assert_eq!(restart_arg("always").unwrap().policy, "always");
    assert_eq!(restart_arg("on-failure").unwrap().max_retries, 3);
    assert_eq!(
        restart_arg("on-failure:0").unwrap(),
        api::RestartPolicy {
            policy: "on-failure".into(),
            max_retries: 0
        }
    );
    for bad in ["sometimes", "always:3", "on-failure:x"] {
        assert!(restart_arg(bad).is_err(), "{bad}");
    }
    assert_eq!(
        fails(&["m", "set", "m1", "--restart", "sometimes"]),
        ErrorKind::ValueValidation
    );
}
