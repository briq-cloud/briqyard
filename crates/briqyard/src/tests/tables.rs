//! The tables, and the host commands that print or order them.

use super::*;

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
        namespace: "t1".into(),
        name: "web".into(),
        image: "nginx:1.27".into(),
        state: "running".into(),
        ip: "10.1.0.2".into(),
        size: api::Size {
            vcpus: 2,
            memory_mb: 1024,
            cpu_millis: None,
        },
        sleep: "30m".into(),
        host: "d1".into(),
        created_at: ts(),
        updated_at: ts(),
        ready: true,
        ..Default::default()
    };
    let mut b = a.clone();
    b.ready = false;
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
        siblings: false,
    };
    b.limits = api::EgressLimits {
        blocked_ports: Some(vec![25, 465]),
        new_connections_per_minute: Some(600),
        bandwidth_mbit: Some(100),
    };
    b.disk_limits = api::DiskLimits {
        bandwidth_mb: Some(64),
        iops: Some(8000),
        burst_sec: Some(10),
    };
    b.backup = Some(api::BackupPolicy {
        every: "6h".into(),
        keep: 4,
    });
    b.pending = Some(api::Pending {
        fields: vec!["image".into(), "env".into()],
        image: Some("nginx:1.28".into()),
        ..Default::default()
    });
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
        "ID               NAMESPACE    NAME           IMAGE                    STATE              READY IP           SIZE      CPU m   SLEEP  EGRESS             LIMITS                   DISK             BACKUP   PENDING      HOST"
    );
    // Every column starts where its header does.
    let cols = [
        (0, 16),
        (17, 12),
        (30, 14),
        (45, 24),
        (70, 18),
        (89, 5),
        (95, 12),
        (108, 9),
        (118, 7),
        (126, 6),
        (133, 18),
        (152, 24),
        (177, 16),
        (194, 8),
        (203, 12),
    ];
    let heads: Vec<String> = cols.iter().map(|(at, w)| col(lines[0], *at, *w)).collect();
    assert_eq!(
        heads,
        [
            "ID",
            "NAMESPACE",
            "NAME",
            "IMAGE",
            "STATE",
            "READY",
            "IP",
            "SIZE",
            "CPU m",
            "SLEEP",
            "EGRESS",
            "LIMITS",
            "DISK",
            "BACKUP",
            "PENDING"
        ]
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
            "no",
            "",
            "2c/1024M",
            "2000",
            "never",
            "via:m_0123456789ab",
            "25,465 600/min 100Mbit",
            "64MB/s 8000io",
            "6h/4",
            "image,env"
        ],
        "the stop reason is shown with the state; an empty ip is an empty column; \
         a via policy in the form set-egress takes; the limits and the disk's short; the schedule as \
         every/keep; what changes at the next start"
    );
    assert_eq!(
        lines[2].len(),
        203 + 12 + 1,
        "no host: nothing after the pending fields"
    );
    assert_eq!(col(lines[1], 177, 16), "-", "no disk limit");
    assert_eq!(col(lines[1], 194, 8), "-", "no schedule");
    assert_eq!(col(lines[1], 203, 12), "-", "nothing pending");
    assert_eq!(col(lines[1], 89, 5), "yes");
    assert_eq!(col(lines[1], 133, 18), "open");
    assert_eq!(col(lines[1], 152, 24), "-", "nothing limited");
    // A value wider than its column is not cut: the rest of that row moves right.
    assert!(
        lines[3].contains("a-rather-long-name-indeed ghcr.io/org/some-image:v1.2.3 "),
        "{}",
        lines[3]
    );
    assert_eq!(col(lines[1], 0, 16), "m_01HZX");
    assert_eq!(col(lines[1], 70, 18), "running");
    assert_eq!(col(lines[1], 95, 12), "10.1.0.2");
    assert!(lines[1].ends_with(" d1"));
    assert_eq!(col(lines[1], 45, 24), "nginx:1.27");
    assert_eq!(machine_table(&[]).lines().count(), 1, "the header alone");
}

#[test]
fn the_region_table() {
    assert_eq!(region_table(&[]), "", "a daemon has no regions");
    let gra = api::RegionRoom {
        region: "gra".into(),
        free: Some(api::Room {
            memory_mb: 120_000,
            disk_mb: 800_000,
        }),
        largest_slot: Some(api::Room {
            memory_mb: 60_000,
            disk_mb: 400_000,
        }),
        unschedulable: api::Unschedulable {
            memory: 3,
            disk: 0,
            pressure: 1,
            cpu: 0,
        },
    };
    // Refusals of creates that asked for no region, while every host has one: no room.
    let any = api::RegionRoom {
        region: String::new(),
        unschedulable: api::Unschedulable {
            memory: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let out = region_table(&[gra, any]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "",
            "REGION   FREE MB MEM/DISK     LARGEST MB MEM/DISK  UNSCHEDULABLE MEM/DISK/PRESSURE",
            "gra      120000/800000        60000/400000         3/0/1",
            "-        -                    -                    1/0/0",
        ]
    );
}

#[test]
fn the_host_table() {
    let ready = api::Host {
        egress_siblings_v1: false,
        id: "h_byard-1".into(),
        url: "https://10.0.0.9:7420".into(),
        ssh: String::new(),
        region: "par".into(),
        provider: "static".into(),
        state: "ready".into(),
        capacity: api::Capacity {
            memory_mb: 64000,
            vcpus: 32,
            cpu_millis: None,
        },
        used: api::Capacity {
            memory_mb: 8192,
            vcpus: 6,
            cpu_millis: None,
        },
        machines: 3,
        namespaces: vec!["t1".into(), "t2".into()],
        last_seen: ts(),
        version: "0.1.0".into(),
        note: String::new(),
        tls_fingerprint: "ab".repeat(32),
        labels: Default::default(),
        public_tcp_ports: vec![],
        conditions: vec![
            api::Condition {
                kind: "memory_pressure".into(),
                status: false,
                since: ts(),
                message: "8192 MB of 64000 committed (12%)".into(),
            },
            api::Condition {
                kind: "disk_pressure".into(),
                status: true,
                since: ts(),
                message: "pool 4.0 GB free of 100.0 (4%), under 10%".into(),
            },
        ],
        started: Default::default(),
    };
    let pending = api::Host {
        id: "h_srv-9".into(),
        url: String::new(),
        state: "provisioning".into(),
        capacity: api::Capacity::default(),
        used: api::Capacity::default(),
        machines: 0,
        namespaces: vec![],
        note: "bootstrap attempt 2: ssh: connect to host 10.0.0.9 port 22: Connection refused"
            .into(),
        tls_fingerprint: String::new(),
        conditions: vec![],
        region: String::new(),
        version: String::new(),
        ..ready.clone()
    };
    let added = api::Host {
        id: "h_10-42-0-11".into(),
        url: "https://10.42.0.11:7420".into(),
        ssh: "51.68.1.2".into(),
        region: "gra".into(),
        note: String::new(),
        labels: Default::default(),
        public_tcp_ports: vec![80, 443, 5432],
        ..pending.clone()
    };
    let out = host_table(&[ready, pending, added]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines.len(),
        9,
        "an SSH address, a pin, public ports, a true condition and a note take a line each"
    );
    assert_eq!(
        lines[0],
        "ID               URL                          STATE        REGION   MEMORY MB      CPU m      MACHINES  NAMESPACES VERSION              LAST SEEN"
    );
    assert_eq!(
        lines[1],
        "h_byard-1        https://10.0.0.9:7420        ready        par      8192/64000     6000/32000 3         2          0.1.0                2026-10-19T08:30:00+00:00"
    );
    assert_eq!(
        lines[2],
        format!("                 tls: {}", "ab".repeat(32))
    );
    assert_eq!(
        lines[3],
        "                 disk_pressure since 2026-10-19 08:30:00: pool 4.0 GB free of 100.0 (4%), under 10%",
        "a false condition takes no line"
    );
    assert_eq!(
        lines[4],
        "h_srv-9          -                            provisioning -        0/0            0/0        0         0          -                    2026-10-19T08:30:00+00:00",
        "no address, region nor version yet shows as -"
    );
    assert_eq!(
        lines[5],
        "                 note: bootstrap attempt 2: ssh: connect to host 10.0.0.9 port 22: Connection refused"
    );
    assert_eq!(
        lines[6],
        "h_10-42-0-11     https://10.42.0.11:7420      provisioning gra      0/0            0/0        0         0          -                    2026-10-19T08:30:00+00:00"
    );
    assert_eq!(
        lines[7], "                 ssh: 51.68.1.2",
        "the SSH address when it is not the API's"
    );
    assert_eq!(lines[8], "                 public tcp: 80,443,5432");
    assert!(out.ends_with('\n'));
}

#[test]
fn host_add_takes_its_public_ports() {
    for (arg, want) in [
        (None, None),
        (Some("80,443,5432"), Some(vec![80, 443, 5432])),
        (Some("none"), Some(vec![])),
    ] {
        let mut args = vec!["host", "add", "51.68.1.2"];
        if let Some(a) = arg {
            args.extend(["--public-tcp-ports", a]);
        }
        match parse(&args).cmd {
            Cmd::Host(HostCmd::Add {
                public_tcp_ports, ..
            }) => assert_eq!(
                public_tcp_ports
                    .as_deref()
                    .map(port_list)
                    .transpose()
                    .unwrap(),
                want
            ),
            _ => panic!("not a host add"),
        }
    }
    for bad in ["", "80,", "0", "http"] {
        assert!(port_list(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn host_upgrade_takes_a_host_or_all() {
    match parse(&["host", "upgrade", "h_a", "--release", "0.2.0"]).cmd {
        Cmd::Host(HostCmd::Upgrade { id, all, release }) => assert_eq!(
            (id.as_deref(), all, release.as_str()),
            (Some("h_a"), false, "0.2.0")
        ),
        _ => panic!("not an upgrade"),
    }
    assert!(matches!(
        parse(&["host", "upgrade", "--all", "--release", "0.2.0"]).cmd,
        Cmd::Host(HostCmd::Upgrade {
            id: None,
            all: true,
            ..
        })
    ));
    match parse(&["host", "undrain", "h_1"]).cmd {
        Cmd::Host(HostCmd::Undrain { id }) => assert_eq!(id, "h_1"),
        _ => panic!("not an undrain"),
    }
    // A host or --all, never both nor neither, and always a release.
    fails(&["host", "upgrade", "--release", "0.2.0"]);
    fails(&["host", "upgrade", "h_a", "--all", "--release", "0.2.0"]);
    fails(&["host", "upgrade", "h_a"]);
}

#[test]
fn a_rolling_upgrade_goes_host_by_host_over_those_in_service() {
    let host = |id: &str, state: &str| api::Host {
        egress_siblings_v1: false,
        id: id.into(),
        url: String::new(),
        ssh: String::new(),
        region: String::new(),
        provider: String::new(),
        state: state.into(),
        capacity: api::Capacity::default(),
        used: api::Capacity::default(),
        machines: 0,
        namespaces: vec![],
        last_seen: ts(),
        version: String::new(),
        note: String::new(),
        tls_fingerprint: String::new(),
        labels: Default::default(),
        public_tcp_ports: vec![],
        conditions: vec![],
        started: Default::default(),
    };
    let hs = [
        host("h_c", "ready"),
        host("h_a", "draining"),
        host("h_d", "down"),
        host("h_b", "ready"),
        host("h_e", "retiring"),
    ];
    let (up, left) = upgrade_order(&hs);
    assert_eq!(up, ["h_a", "h_b", "h_c"]);
    assert_eq!(
        left,
        [
            ("h_d".to_string(), "down".to_string()),
            ("h_e".to_string(), "retiring".to_string())
        ]
    );
}

#[test]
fn top_takes_a_namespace() {
    match parse(&["top", "--namespace", "t1"]).cmd {
        Cmd::Top { namespace, json } => {
            assert_eq!((namespace.as_deref(), json), (Some("t1"), false))
        }
        _ => panic!("not a top"),
    }
    assert!(matches!(
        parse(&["top", "--json"]).cmd,
        Cmd::Top {
            namespace: None,
            json: true
        }
    ));
}

#[test]
fn the_top_table_puts_the_busiest_first() {
    let m = |id: &str, name: &str, cpu: f64| api::TopMachine {
        machine_id: id.into(),
        namespace: "t1".into(),
        name: name.into(),
        cpu_percent: cpu,
        memory_bytes: 100 << 20,
        memory_limit_bytes: 512 << 20,
        disk_used_bytes: 2048 << 20,
        internet_in_bytes_per_sec: 2048.0,
        internet_out_bytes_per_sec: 512.0,
        ingress_in_bytes_per_sec: 0.0,
        ingress_out_bytes_per_sec: 10240.0,
        window_sec: 15.0,
        host: "h1".into(),
        ..Default::default()
    };
    let out = top_table(vec![m("m_1", "idle", 0.5), m("m_2", "busy", 87.25)]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "MACHINE          NAMESPACE    NAME            CPU %     MEMORY MB   DISK MB   INTERNET IN/OUT    INGRESS IN/OUT HOST",
            "m_2              t1           busy             87.2       100/512      2048           2.0/0.5          0.0/10.0 h1",
            "m_1              t1           idle              0.5       100/512      2048           2.0/0.5          0.0/10.0 h1",
        ]
    );
    assert_eq!(top_table(vec![]).lines().count(), 1, "the header alone");
}

#[test]
fn the_usage_table() {
    let b = api::UsageBucket {
        hour: chrono::DateTime::parse_from_rfc3339("2026-10-20T14:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        machine_id: "m_0123456789ab".into(),
        namespace: "t1".into(),
        size: api::Size {
            vcpus: 1,
            memory_mb: 512,
            cpu_millis: None,
        },
        usage: api::Usage {
            running_seconds: 1800.0,
            cpu_seconds: 12.34,
            memory_mb_seconds: 512.0 * 1800.0,
            root_gb_hours: 4.0,
            volume_gb_hours: 1.0,
            backup_gb_hours: 0.5,
            internet_out_bytes: 1200,
            internet_in_bytes: 34000,
            ingress_out_bytes: 5600,
            ingress_in_bytes: 78,
            ..Default::default()
        },
        closed: true,
        host: "h1".into(),
        ..Default::default()
    };
    let out = usage_table(&[b]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "HOUR              MACHINE          NAMESPACE      RUN H    CPU S  MEM GB·H  DISK GB·H  BACKUP GB·H       INTERNET OUT/IN        INGRESS OUT/IN HOST",
            "2026-10-20 14:00  m_0123456789ab   t1              0.50     12.3      0.25       5.00         0.50            1200/34000               5600/78 h1",
        ]
    );
    assert_eq!(usage_table(&[]).lines().count(), 1, "the header alone");
}

#[test]
fn the_snapshot_table() {
    let ss = [
        api::Snapshot {
            id: "s_0123456789ab".into(),
            machine_id: "m_01".into(),
            name: Some("before-migration".into()),
            created_at: ts(),
            disks: vec!["root".into(), "data".into()],
            memory: true,
        },
        api::Snapshot {
            id: "s_ba9876543210".into(),
            machine_id: "m_01".into(),
            name: None,
            created_at: ts(),
            disks: vec!["data".into()],
            memory: false,
        },
    ];
    let out = snapshot_table(&ss);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "ID               NAME                 CREATED               DISKS      MEMORY",
            "s_0123456789ab   before-migration     2026-10-19 08:30:00   root,data  yes",
            "s_ba9876543210   -                    2026-10-19 08:30:00   data       no",
        ]
    );
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
