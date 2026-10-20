//! Argument parsing, the tables, and the client against a stub API on loopback.

use super::*;
use clap::error::ErrorKind;
use clap::Parser;

// --- parsing ---

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("briqyard").chain(args.iter().copied()))
        .unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

fn fails(args: &[&str]) -> ErrorKind {
    match Cli::try_parse_from(std::iter::once("briqyard").chain(args.iter().copied())) {
        Ok(_) => panic!("{args:?} parsed"),
        Err(e) => e.kind(),
    }
}

fn machine(cli: Cli) -> MachineCmd {
    match cli.cmd {
        Cmd::Machine(m) => *m,
        _ => panic!("not a machine command"),
    }
}

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
fn machine_run_takes_every_setting() {
    let cli = parse(&[
        "machine",
        "run",
        "--image",
        "ghcr.io/x/nginx:1.27",
        "--name",
        "web",
        "--tenant",
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
    assert_eq!(a.tenant, "t1");
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
    assert_eq!(a.tenant, "default");
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
fn machine_exec_takes_the_command_after_the_dashes() {
    match machine(parse(&[
        "machine",
        "exec",
        "--no-wake",
        "--timeout",
        "10s",
        "--stdin",
        "m1",
        "--",
        "sh",
        "-c",
        "ls -la",
    ])) {
        MachineCmd::Exec {
            no_wake,
            timeout,
            stdin,
            id,
            cmd,
        } => {
            assert!(no_wake);
            assert_eq!(Duration::from(timeout), Duration::from_secs(10));
            assert!(stdin);
            assert_eq!(id, "m1");
            assert_eq!(cmd, ["sh", "-c", "ls -la"]);
        }
        _ => panic!("not an exec"),
    }
    match machine(parse(&["machine", "exec", "m1", "--", "true"])) {
        MachineCmd::Exec {
            no_wake,
            timeout,
            stdin,
            cmd,
            ..
        } => {
            assert!(!no_wake, "wakes by default");
            assert_eq!(Duration::from(timeout), Duration::from_secs(300));
            assert!(!stdin);
            assert_eq!(cmd, ["true"]);
        }
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
    ] {
        let got = match machine(parse(&args)) {
            MachineCmd::Get { id } if id == "m1" => "get",
            MachineCmd::Start { id } if id == "m1" => "start",
            MachineCmd::Wake { id } if id == "m1" => "wake",
            MachineCmd::Touch { id } if id == "m1" => "touch",
            MachineCmd::Wait { id } if id == "m1" => "wait",
            MachineCmd::Rm { id } if id == "m1" => "rm",
            MachineCmd::Stats { id } if id == "m1" => "stats",
            _ => "?",
        };
        assert_eq!(got, want, "{args:?}");
    }
    for sub in [
        "get", "start", "stop", "wake", "touch", "wait", "rm", "stats", "fork", "logs",
    ] {
        assert_eq!(
            fails(&["machine", sub]),
            ErrorKind::MissingRequiredArgument,
            "{sub} needs an id"
        );
    }
    // Snapshots: create, ls and rm, each on a machine; rm names the snapshot too.
    for (args, want) in [
        (vec!["machine", "snapshot", "create", "m1"], "create"),
        (vec!["machine", "snapshot", "ls", "m1"], "ls"),
        (vec!["machine", "snapshot", "rm", "m1", "s_1"], "rm"),
    ] {
        let got = match machine(parse(&args)) {
            MachineCmd::Snapshot(SnapshotCmd::Create { id }) if id == "m1" => "create",
            MachineCmd::Snapshot(SnapshotCmd::Ls { id }) if id == "m1" => "ls",
            MachineCmd::Snapshot(SnapshotCmd::Rm { id, snap }) if id == "m1" && snap == "s_1" => {
                "rm"
            }
            _ => "?",
        };
        assert_eq!(got, want, "{args:?}");
    }
    for args in [
        vec!["machine", "snapshot", "create"],
        vec!["machine", "snapshot", "rm", "m1"],
    ] {
        assert_eq!(fails(&args), ErrorKind::MissingRequiredArgument, "{args:?}");
    }
    match machine(parse(&["machine", "ls", "--tenant", "t1"])) {
        MachineCmd::Ls { tenant } => assert_eq!(tenant.as_deref(), Some("t1")),
        _ => panic!("not an ls"),
    }
    match machine(parse(&["m", "ls"])) {
        MachineCmd::Ls { tenant } => assert_eq!(tenant, None),
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
        MachineCmd::Fork { name, id } => {
            assert_eq!((name.as_deref(), id.as_str()), (Some("copy"), "m1"))
        }
        _ => panic!("not a fork"),
    }
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
fn endpoint_tenant_and_image_commands() {
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
        parse(&["tenant", "ls"]).cmd,
        Cmd::Tenant(TenantCmd::Ls)
    ));
    match parse(&["tenant", "rm", "t1"]).cmd {
        Cmd::Tenant(TenantCmd::Rm { id }) => assert_eq!(id, "t1"),
        _ => panic!("not a tenant rm"),
    }
    assert_eq!(fails(&["tenant", "rm"]), ErrorKind::MissingRequiredArgument);
    match parse(&["tenant", "get", "t1"]).cmd {
        Cmd::Tenant(TenantCmd::Get { id }) => assert_eq!(id, "t1"),
        _ => panic!("not a tenant get"),
    }
    match parse(&[
        "tenant",
        "gateway",
        "set",
        "t1",
        "--image",
        "proxy:1",
        "--port",
        "3128",
        "-e",
        "TOKEN=a=b",
        "--",
        "proxy",
        "-v",
    ])
    .cmd
    {
        Cmd::Tenant(TenantCmd::Gateway(GatewayCmd::Set {
            tenant,
            start,
            image,
            port,
            envs,
            cmd,
        })) => {
            assert_eq!(
                (tenant.as_str(), image.as_str(), port),
                ("t1", "proxy:1", 3128)
            );
            assert!(!start, "made, not started, unless asked");
            assert_eq!(env_args(&envs).unwrap()["TOKEN"], "a=b");
            assert_eq!(cmd, ["proxy", "-v"]);
        }
        _ => panic!("not a gateway set"),
    }
    match parse(&[
        "tenant", "gateway", "set", "t1", "--image", "proxy:1", "--port", "3128", "--start",
    ])
    .cmd
    {
        Cmd::Tenant(TenantCmd::Gateway(GatewayCmd::Set { start, cmd, .. })) => {
            assert!(start && cmd.is_empty())
        }
        _ => panic!("not a gateway set"),
    }
    // An image and a port are what a gateway needs.
    assert_eq!(
        fails(&["tenant", "gateway", "set", "t1", "--image", "proxy:1"]),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        fails(&["tenant", "gateway", "set", "t1", "--port", "3128"]),
        ErrorKind::MissingRequiredArgument
    );
    match parse(&["tenant", "gateway", "rm", "t1"]).cmd {
        Cmd::Tenant(TenantCmd::Gateway(GatewayCmd::Rm { tenant })) => assert_eq!(tenant, "t1"),
        _ => panic!("not a gateway rm"),
    }
    assert!(env_args(&["NOEQUALS".into()]).is_err());
    match parse(&["tenant", "unpin", "t1"]).cmd {
        Cmd::Tenant(TenantCmd::Unpin { id }) => assert_eq!(id, "t1"),
        _ => panic!("not a tenant unpin"),
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
    match parse(&["host", "order", "--reason", "launch week"]).cmd {
        Cmd::Host(HostCmd::Order { reason }) => assert_eq!(reason, "launch week"),
        _ => panic!("not an order"),
    }
    match parse(&["host", "order"]).cmd {
        Cmd::Host(HostCmd::Order { reason }) => {
            assert_eq!(reason, "", "the fleet writes a default")
        }
        _ => panic!("not an order"),
    }
    match parse(&["host", "retire", "h_1"]).cmd {
        Cmd::Host(HostCmd::Retire { id }) => assert_eq!(id, "h_1"),
        _ => panic!("not a retire"),
    }
    match parse(&["host", "drain", "h_1"]).cmd {
        Cmd::Host(HostCmd::Drain { id }) => assert_eq!(id, "h_1"),
        _ => panic!("not a drain"),
    }
    match parse(&["host", "rm", "h_1"]).cmd {
        Cmd::Host(HostCmd::Rm { id }) => assert_eq!(id, "h_1"),
        _ => panic!("not a rm"),
    }
    for sub in ["retire", "drain", "rm"] {
        assert_eq!(
            fails(&["host", sub]),
            ErrorKind::MissingRequiredArgument,
            "{sub}"
        );
    }
}

// --- tables ---

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-19T08:30:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// The text of a column, by the character offset the header puts it at.
fn col(line: &str, at: usize, width: usize) -> String {
    line.chars()
        .skip(at)
        .take(width)
        .collect::<String>()
        .trim_end()
        .to_string()
}

#[test]
fn the_machine_table() {
    let a = api::Machine {
        id: "m_01HZX".into(),
        tenant: "t1".into(),
        name: "web".into(),
        image: "nginx:1.27".into(),
        state: "running".into(),
        ip: "10.1.0.2".into(),
        size: api::Size {
            vcpus: 2,
            memory_mb: 1024,
        },
        sleep: "30m".into(),
        host: "d1".into(),
        created_at: ts(),
        updated_at: ts(),
        ..Default::default()
    };
    let mut b = a.clone();
    b.id = "m_02".into();
    b.name = "db".into();
    b.state = "stopped".into();
    b.stopped_reason = "idle".into();
    b.ip.clear();
    b.host.clear();
    b.sleep = "never".into();
    b.egress = api::Egress {
        mode: "via".into(),
        via: Some("m_0123456789ab".into()),
    };
    let mut long = a.clone();
    long.id = "m_03".into();
    long.name = "a-rather-long-name-indeed".into();
    long.image = "ghcr.io/org/some-image:v1.2.3".into();
    let out = machine_table(&[a, b, long]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4);
    assert!(out.ends_with('\n'));
    assert_eq!(
        lines[0],
        "ID               TENANT     NAME           IMAGE                    STATE              IP           SIZE      SLEEP  EGRESS             HOST"
    );
    // Every column starts where its header does.
    let cols = [
        (0, 16),
        (17, 10),
        (28, 14),
        (43, 24),
        (68, 18),
        (87, 12),
        (100, 9),
        (110, 6),
        (117, 18),
    ];
    let heads: Vec<String> = cols.iter().map(|(at, w)| col(lines[0], *at, *w)).collect();
    assert_eq!(
        heads,
        ["ID", "TENANT", "NAME", "IMAGE", "STATE", "IP", "SIZE", "SLEEP", "EGRESS"]
    );
    let row: Vec<String> = cols.iter().map(|(at, w)| col(lines[2], *at, *w)).collect();
    assert_eq!(
        row,
        [
            "m_02",
            "t1",
            "db",
            "nginx:1.27",
            "stopped (idle)",
            "",
            "2c/1024M",
            "never",
            "via:m_0123456789ab"
        ],
        "the stop reason is shown with the state; an empty ip is an empty column; \
         a via policy in the form set-egress takes"
    );
    assert!(
        lines[2].ends_with("via:m_0123456789ab "),
        "no host: nothing after the egress"
    );
    assert_eq!(col(lines[1], 117, 18), "open");
    // A value wider than its column is not cut: the rest of that row moves right.
    assert!(
        lines[3].contains("a-rather-long-name-indeed ghcr.io/org/some-image:v1.2.3 "),
        "{}",
        lines[3]
    );
    assert_eq!(col(lines[1], 0, 16), "m_01HZX");
    assert_eq!(col(lines[1], 68, 18), "running");
    assert_eq!(col(lines[1], 87, 12), "10.1.0.2");
    assert!(lines[1].ends_with(" d1"));
    assert_eq!(col(lines[1], 43, 24), "nginx:1.27");
    assert_eq!(machine_table(&[]).lines().count(), 1, "the header alone");
}

#[test]
fn the_host_table() {
    let ready = api::Host {
        id: "h_byard-1".into(),
        url: "http://10.0.0.9:7420".into(),
        region: "par".into(),
        provider: "scaleway".into(),
        state: "ready".into(),
        capacity: api::Capacity {
            memory_mb: 64000,
            vcpus: 32,
        },
        used: api::Capacity {
            memory_mb: 8192,
            vcpus: 6,
        },
        machines: 3,
        tenants: vec!["t1".into(), "t2".into()],
        last_seen: ts(),
        version: "0.1.0".into(),
        note: String::new(),
    };
    let ordered = api::Host {
        id: "h_srv-9".into(),
        url: String::new(),
        state: "provisioning".into(),
        capacity: api::Capacity::default(),
        used: api::Capacity::default(),
        machines: 0,
        tenants: vec![],
        note: "bootstrap attempt 2: ssh: connect to host 10.0.0.9 port 22: Connection refused"
            .into(),
        ..ready.clone()
    };
    let out = host_table(&[ready, ordered]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "a note takes a line of its own");
    assert_eq!(
        lines[0],
        "ID               URL                          STATE        MEMORY MB      VCPUS      MACHINES  TENANTS  LAST SEEN"
    );
    assert_eq!(
        lines[1],
        "h_byard-1        http://10.0.0.9:7420         ready        8192/64000     6/32       3         2        2026-10-19T08:30:00+00:00"
    );
    assert_eq!(
        lines[2],
        "h_srv-9          -                            provisioning 0/0            0/0        0         0        2026-10-19T08:30:00+00:00",
        "no address yet shows as -"
    );
    assert_eq!(
        lines[3],
        "                 note: bootstrap attempt 2: ssh: connect to host 10.0.0.9 port 22: Connection refused"
    );
    assert!(out.ends_with('\n'));
}

#[test]
fn the_endpoint_and_image_tables() {
    let eps = [
        api::Endpoint {
            id: "ep_01".into(),
            machine_id: "m_01".into(),
            port: 5432,
            protocol: "tcp".into(),
            host_port: Some(30432),
            host: String::new(),
            address: "203.0.113.5:30432".into(),
            created_at: ts(),
        },
        api::Endpoint {
            id: "ep_02".into(),
            machine_id: "m_02".into(),
            port: 80,
            protocol: "http".into(),
            host_port: None,
            host: "web".into(),
            address: "http://web.example".into(),
            created_at: ts(),
        },
    ];
    let out = endpoint_table(&eps);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "ID                 MACHINE          PORT   PROTOCOL  ADDRESS"
    );
    assert_eq!(
        lines[1],
        "ep_01              m_01             5432   tcp       203.0.113.5:30432"
    );
    assert_eq!(
        lines[2],
        "ep_02              m_02             80     http      http://web.example"
    );
    assert_eq!(lines.len(), 3);

    let ims = [
        api::Image {
            key: "nginx-1.27".into(),
            reference: "docker.io/library/nginx:1.27".into(),
            digest: "sha256:0123456789abcdef0123456789abcdef".into(),
            size_gb: 1,
            built_at: ts(),
            machines: 2,
        },
        api::Image {
            key: "short".into(),
            reference: "x".into(),
            digest: "sha256:ab".into(),
            size_gb: 1,
            built_at: ts(),
            machines: 0,
        },
    ];
    let out = image_table(&ims);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "KEY                    REF                                      MACHINES  BUILT                 DIGEST"
    );
    assert_eq!(
        lines[1],
        "nginx-1.27             docker.io/library/nginx:1.27             2         2026-10-19 08:30:00   sha256:0123456789ab",
        "the digest is cut to 19 characters"
    );
    assert!(
        lines[2].ends_with("sha256:ab"),
        "a short digest is whole: {}",
        lines[2]
    );
}

// --- the client ---

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: String,
}

/// Response headers of a canned reply.
type Headers = Vec<(&'static str, &'static str)>;

/// An API on loopback: records every request and answers the next canned reply (status,
/// headers, body); 500 when none is left.
struct Stub {
    seen: Mutex<Vec<Seen>>,
    replies: Mutex<VecDeque<(StatusCode, Headers, String)>>,
}

/// A header's value. A function, not a closure: a closure keeping `&req` while the body is
/// read would hold a `!Sync` body across the await and the handler would not be `Send`.
fn header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

async fn answer(State(stub): State<Arc<Stub>>, req: Request) -> axum::response::Response {
    let mut seen = Seen {
        method: req.method().to_string(),
        path: req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default(),
        authorization: header(&req, "authorization"),
        content_type: header(&req, "content-type"),
        body: String::new(),
    };
    let data = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap();
    seen.body = String::from_utf8_lossy(&data).into_owned();
    stub.seen.lock().unwrap().push(seen);
    let next = stub.replies.lock().unwrap().pop_front();
    match next {
        Some((status, headers, body)) => {
            let mut resp = (status, body).into_response();
            for (k, v) in headers {
                resp.headers_mut().insert(k, v.parse().unwrap());
            }
            resp
        }
        None => (StatusCode::INTERNAL_SERVER_ERROR, "no canned reply").into_response(),
    }
}

async fn stub(replies: Vec<(StatusCode, Headers, &str)>) -> (String, Arc<Stub>) {
    let stub = Arc::new(Stub {
        seen: Mutex::new(vec![]),
        replies: Mutex::new(
            replies
                .into_iter()
                .map(|(s, h, b)| (s, h, b.to_string()))
                .collect(),
        ),
    });
    let app = axum::Router::new()
        .fallback(answer)
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, stub)
}

fn client(base: &str, token: Option<&str>) -> Client {
    Client {
        base: base.trim_end_matches('/').to_string(),
        token: token.map(|t| t.to_string()),
        http: reqwest::Client::new(),
    }
}

const JSON: &[(&str, &str)] = &[("content-type", "application/json")];

#[tokio::test]
async fn the_client_sends_the_token_and_the_body() {
    let (url, stub) = stub(vec![
        (
            StatusCode::OK,
            JSON.to_vec(),
            r#"{"id":"m1","state":"running"}"#,
        ),
        (StatusCode::NO_CONTENT, vec![], ""),
        (StatusCode::OK, JSON.to_vec(), r#"[]"#),
    ])
    .await;
    let c = client(&format!("{url}/"), Some("t0k"));
    assert_eq!(c.base, url, "a trailing slash is dropped");
    let v: serde_json::Value = c
        .call(
            reqwest::Method::POST,
            "/v1/machines/m1/stop",
            Some(&api::StopRequest {
                suspend: true,
                timeout_sec: 0,
            }),
        )
        .await
        .unwrap();
    assert_eq!(v["id"], "m1");
    let text = c
        .raw(reqwest::Method::DELETE, "/v1/machines/m1", NONE)
        .await
        .unwrap();
    assert_eq!(text, "");
    let open = client(&url, None);
    let v: Vec<api::Machine> = open
        .call(reqwest::Method::GET, "/v1/machines?tenant=t1", NONE)
        .await
        .unwrap();
    assert!(v.is_empty());
    let seen = stub.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v1/machines/m1/stop");
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer t0k"));
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(seen[0].body, r#"{"suspend":true,"timeout_sec":0}"#);
    assert_eq!(seen[1].method, "DELETE");
    assert_eq!(seen[1].content_type, None, "no body, no content type");
    assert_eq!(seen[1].body, "");
    assert_eq!(
        seen[2].path, "/v1/machines?tenant=t1",
        "the query goes along"
    );
    assert_eq!(seen[2].authorization, None, "no token, no header");
}

#[tokio::test]
async fn an_empty_answer_is_only_fine_when_nothing_is_expected() {
    let (url, _stub) = stub(vec![
        (StatusCode::OK, vec![], ""),
        (StatusCode::OK, vec![], ""),
    ])
    .await;
    let c = client(&url, None);
    c.call::<()>(reqwest::Method::POST, "/v1/machines/m1/touch", NONE)
        .await
        .unwrap();
    let err = c
        .call::<api::Machine>(reqwest::Method::GET, "/v1/machines/m1", NONE)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "empty response");
}

#[tokio::test]
async fn errors_name_the_code_and_the_request() {
    let (url, _stub) = stub(vec![
        (
            StatusCode::NOT_FOUND,
            vec![("content-type", "application/json"), ("x-request-id", "r-1")],
            r#"{"error":"machine not found","code":"not_found","request_id":"r-1"}"#,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            JSON.to_vec(),
            r#"{"error":"host d1 is down: its machines answer again once it does","code":"host_down"}"#,
        ),
        (StatusCode::BAD_GATEWAY, vec![], "  <html>upstream timed out</html>\n"),
        (StatusCode::OK, JSON.to_vec(), r#"{"id":"m1""#),
    ])
    .await;
    let c = client(&url, Some("t"));
    let get = |path: &'static str| c.call::<api::Machine>(reqwest::Method::GET, path, NONE);
    assert_eq!(
        get("/v1/machines/m9").await.unwrap_err().to_string(),
        "machine not found (not_found, request r-1)",
        "the request id from the daemon's body, for a support ticket"
    );
    assert_eq!(
        get("/v1/machines/m1").await.unwrap_err().to_string(),
        "host d1 is down: its machines answer again once it does (host_down)",
        "the fleet's own errors have no request id"
    );
    assert_eq!(
        get("/v1/machines/m1").await.unwrap_err().to_string(),
        "502 Bad Gateway: <html>upstream timed out</html>",
        "a body that is not an API error is shown as is, trimmed"
    );
    let err = get("/v1/machines/m1").await.unwrap_err().to_string();
    assert!(
        err.contains("EOF") || err.contains("expected"),
        "a broken JSON answer: {err}"
    );
    // Nothing listens: the error names the base URL.
    let dead = client("http://127.0.0.1:1", None);
    let err = format!(
        "{:#}",
        dead.call::<api::Status>(reqwest::Method::GET, "/v1/status", NONE)
            .await
            .unwrap_err()
    );
    assert!(err.starts_with("request http://127.0.0.1:1: "), "{err}");
}
