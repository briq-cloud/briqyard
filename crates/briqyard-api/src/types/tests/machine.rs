use super::*;

#[test]
fn size_and_capacity() {
    let s: Size = same(json!({"vcpus": 2, "memory_mb": 1024}));
    assert_eq!(s.vcpus, 2);
    assert_eq!(s.memory_mb, 1024);
    // Both fields are required: a size with no memory is refused.
    assert!(serde_json::from_value::<Size>(json!({"vcpus": 2})).is_err());
    let c: Capacity = same(json!({"memory_mb": 65536, "vcpus": 16}));
    assert_eq!(
        c,
        Capacity {
            memory_mb: 65536,
            vcpus: 16,
            cpu_millis: None,
        }
    );
    assert_eq!(
        Capacity::default(),
        Capacity {
            memory_mb: 0,
            vcpus: 0,
            cpu_millis: None,
        }
    );
}

#[test]
fn volume_spec() {
    let v: VolumeSpec = same(json!({"size_gb": 10, "mount": "/data"}));
    assert_eq!(v.mount, "/data");
    assert!(serde_json::from_value::<VolumeSpec>(json!({"size_gb": 10})).is_err());
}

#[test]
fn file() {
    // The mode is optional and absent from the output when not given.
    let f: File = same(json!({"path": "/etc/app.conf", "base64": "aGk="}));
    assert_eq!(f.mode, None);
    let f: File = same(json!({"path": "/bin/run", "base64": "", "mode": "0755"}));
    assert_eq!(f.mode.as_deref(), Some("0755"));
    assert!(serde_json::from_value::<File>(json!({"path": "/x"})).is_err());
}

#[test]
fn restart_policy_defaults() {
    // The description promises on-failure with 3 retries for whatever is left out.
    let r: RestartPolicy = round_trip(
        json!({"policy": "always"}),
        json!({"policy": "always", "max_retries": 3}),
    );
    assert_eq!(r.max_retries, 3);
    let r: RestartPolicy = round_trip(
        json!({"max_retries": 0}),
        json!({"policy": "on-failure", "max_retries": 0}),
    );
    assert_eq!(r.policy, "on-failure");
    let r: RestartPolicy = round_trip(json!({}), json!({"policy": "on-failure", "max_retries": 3}));
    assert_eq!(r, RestartPolicy::default());
    let r: RestartPolicy = same(json!({"policy": "no", "max_retries": 5}));
    assert_eq!(r.max_retries, 5);
}

#[test]
fn fork_spec() {
    let f: ForkSpec = round_trip(
        json!({"machine_id": "m1"}),
        json!({"machine_id": "m1", "copy": ""}),
    );
    assert_eq!(f.copy, "");
    let f: ForkSpec = same(json!({"machine_id": "m1", "copy": "config"}));
    assert_eq!(f.copy, "config");
    assert!(serde_json::from_value::<ForkSpec>(json!({"copy": "disk"})).is_err());
}

#[test]
fn exit() {
    let e: Exit = same(json!({
        "code": 137, "oom_killed": true, "at": "2026-01-02T03:04:05Z", "restarting": false
    }));
    assert_eq!(e.code, 137);
    assert!(e.oom_killed);
    assert_eq!(e.at, ts());
}

#[test]
fn create_machine_request_minimal() {
    // namespace, name and size are enough; the collections come back empty and the
    // optional parts stay out of the output.
    let r: CreateMachineRequest = round_trip(
        json!({"namespace": "t1", "name": "db", "size": {"vcpus": 1, "memory_mb": 256}}),
        json!({
            "namespace": "t1", "name": "db", "image": "",
            "env": {}, "files": [], "size": {"vcpus": 1, "memory_mb": 256},
            "ports": [], "sleep": "", "metadata": {}
        }),
    );
    assert_eq!(r.entrypoint, None);
    assert_eq!(r.cmd, None);
    assert_eq!(r.volume, None);
    assert_eq!(r.restart, None);
    assert_eq!(r.start, None);
    assert!(r.fork.is_none());
    for missing in [
        json!({"name": "db", "size": {"vcpus": 1, "memory_mb": 256}}),
        json!({"namespace": "t1", "size": {"vcpus": 1, "memory_mb": 256}}),
        json!({"namespace": "t1", "name": "db"}),
    ] {
        assert!(
            serde_json::from_value::<CreateMachineRequest>(missing.clone()).is_err(),
            "{missing}"
        );
    }
}

#[test]
fn create_machine_request_full() {
    let input = json!({
        "namespace": "t1", "name": "web", "image": "docker.io/library/nginx:1.27",
        "entrypoint": ["/docker-entrypoint.sh"], "cmd": ["nginx", "-g", "daemon off;"],
        "env": {"A": "1", "B": "2"},
        "files": [{"path": "/etc/motd", "base64": "aGk=", "mode": "0600"}],
        "size": {"vcpus": 2, "memory_mb": 1024},
        "volume": {"size_gb": 5, "mount": "/data"},
        "ports": [80, 443], "sleep": "30m",
        "restart": {"policy": "always", "max_retries": 0},
        "metadata": {"briq": "bq_1"}, "region": "gra", "egress": {"mode": "via", "via": "m_gw"},
        "limits": {"blocked_ports": [25, 465], "new_connections_per_minute": 600},
        "start": false,
        "fork": {"machine_id": "m0", "copy": "disk"}
    });
    let r: CreateMachineRequest = same(input);
    assert_eq!(
        r.egress.as_ref().and_then(|e| e.via.as_deref()),
        Some("m_gw")
    );
    let l = r.limits.as_ref().unwrap();
    assert_eq!(l.blocked_ports.as_deref(), Some(&[25, 465][..]));
    assert_eq!(l.bandwidth_mbit, None, "absent: the host's");
    assert_eq!(
        r.cmd.as_deref(),
        Some(&["nginx", "-g", "daemon off;"].map(String::from)[..])
    );
    assert_eq!(r.env.get("B").map(String::as_str), Some("2"));
    assert_eq!(r.files[0].mode.as_deref(), Some("0600"));
    assert_eq!(r.ports, vec![80, 443]);
    assert_eq!(r.start, Some(false));
    assert_eq!(r.fork.as_ref().map(|f| f.machine_id.as_str()), Some("m0"));
    assert_eq!(r.region, "gra");
}

#[test]
fn machine_minimal() {
    let input = json!({
        "id": "m1", "namespace": "t1", "name": "db", "image": "postgres:17",
        "state": "running", "hostname": "db.internal", "machine_host": "m1.vm.internal",
        "size": {"vcpus": 1, "memory_mb": 512}, "sleep": "never",
        "restart": {"policy": "no", "max_retries": 0},
        "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z",
        "state_changed_at": "2026-01-02T03:04:05Z"
    });
    let mut expected = input.clone();
    // What a reader always gets, even when nothing was set.
    expected["ports"] = json!([]);
    expected["metadata"] = json!({});
    expected["endpoints"] = json!([]);
    expected["suspended"] = json!(false);
    expected["egress"] = json!({"mode": "open"});
    expected["version"] = json!(0);
    expected["limits"] = json!({});
    expected["egress_drops"] = json!({"blocked_port": 0, "rate": 0, "bandwidth": 0});
    expected["restarts"] = json!(0);
    expected["ready"] = json!(false);
    let m: Machine = round_trip(input, expected);
    assert!(m.probes.is_empty() && m.probes_status.is_empty());
    assert_eq!(m.restarting_at, None);
    assert_eq!(m.state, state::RUNNING);
    assert_eq!(m.egress, Egress::default());
    assert_eq!(m.image_digest, "");
    assert!(m.exit.is_none());
    assert_eq!(m.started_at, None);
    assert_eq!(m.sleeps_at, None);
    assert_eq!(m.host, "");
    assert_eq!((m.init_version.as_str(), m.vmm_version.as_str()), ("", ""));
}

#[test]
fn machine_full() {
    let input = json!({
        "id": "m1", "namespace": "t1", "name": "db", "image": "postgres:17",
        "image_digest": "sha256:abc", "state": "stopped", "stopped_reason": "exit",
        "exit": {"code": 1, "oom_killed": false, "at": "2026-01-02T03:04:05Z", "restarting": true},
        "error": "boom", "ip": "10.64.0.2",
        "hostname": "db.internal", "machine_host": "m1.vm.internal",
        "size": {"vcpus": 1, "memory_mb": 512},
        "volume": {"size_gb": 5, "mount": "/var/lib/postgresql/data"},
        "ports": [5432], "sleep": "30m",
        "restart": {"policy": "on-failure", "max_retries": 3},
        "egress": {"mode": "none"},
        "limits": {"blocked_ports": [25], "new_connections_per_minute": 0, "bandwidth_mbit": 100},
        "egress_drops": {"blocked_port": 3, "rate": 0, "bandwidth": 12},
        "metadata": {"stack": "s1"},
        "endpoints": [{
            "id": "e1", "machine_id": "m1", "port": 5432, "protocol": "tcp",
            "host_port": 20001, "address": "1.2.3.4:20001", "created_at": "2026-01-02T03:04:05Z"
        }],
        "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z",
        "state_changed_at": "2026-01-02T03:04:05Z",
        "started_at": "2026-01-02T03:04:05Z", "stopped_at": "2026-01-02T03:04:05Z",
        "last_used_at": "2026-01-02T03:04:05Z", "sleeps_at": "2026-01-02T03:34:05Z",
        "suspended": true, "backup": {"every": "6h", "keep": 4},
        "last_backup_at": "2026-01-02T03:04:05Z", "next_backup_at": "2026-01-02T09:04:05Z",
        "version": 812, "host": "h1",
        "init_version": "0.1.0+fdad892eeefa", "vmm_version": "v1.17.0/6.8.0-45-generic",
        "restarts": 2, "restarting_at": "2026-01-02T03:04:25Z", "ready": false
    });
    let mut input = input;
    input["probes"] = json!({"readiness": {"http": {"port": 8080, "path": "/"},
            "period_sec": 10, "timeout_sec": 5, "failure_threshold": 3, "success_threshold": 1,
            "initial_delay_sec": 0}});
    input["probes_status"] = json!({"readiness": {"passed": false, "message": "HTTP 503",
            "failures": 2, "at": "2026-01-02T03:04:05Z"}});
    input["pending"] = json!({"fields": ["image", "env", "size"], "image": "postgres:18",
            "size": {"vcpus": 2, "memory_mb": 1024}});
    input["pending_since"] = json!("2026-01-02T03:04:05Z");
    // ADR 0048: why it is in `error`; absent from a machine of before, it reads empty.
    let mut failed = input.clone();
    failed["state"] = json!(state::ERROR);
    failed["error_reason"] = json!(reason::PULL_FAILED);
    assert_eq!(same::<Machine>(failed).error_reason, "pull_failed");
    let m: Machine = same(input);
    assert_eq!(m.error_reason, "");
    let p = m.pending.as_ref().unwrap();
    assert_eq!(
        (p.fields.len(), p.image.as_deref()),
        (3, Some("postgres:18"))
    );
    assert_eq!(m.pending_since, Some(ts()));
    assert_eq!(m.backup.as_ref().map(|b| b.keep), Some(4));
    assert_eq!(
        m.next_backup_at
            .zip(m.last_backup_at)
            .map(|(n, l)| (n - l).num_hours()),
        Some(6)
    );
    assert_eq!(m.restarts, 2);
    assert_eq!(
        m.probes_status.readiness.as_ref().map(|s| s.failures),
        Some(2)
    );
    assert_eq!(m.version, 812);
    assert_eq!(m.stopped_reason, stop::EXIT);
    assert_eq!(m.egress.mode, egress::NONE);
    assert_eq!(m.limits.bandwidth_mbit, Some(100));
    assert_eq!(m.egress_drops.total(), 15);
    assert_eq!(m.exit.as_ref().map(|e| e.code), Some(1));
    assert_eq!(m.endpoints[0].host_port, Some(20001));
    assert_eq!(m.sleeps_at.map(|t| (t - ts()).num_minutes()), Some(30));
    assert!(m.suspended);
    assert_eq!(m.init_version, "0.1.0+fdad892eeefa");
}

#[test]
fn endpoint() {
    // A TCP endpoint carries host_port and no host; an HTTP one the reverse.
    let e: Endpoint = same(json!({
        "id": "e1", "machine_id": "m1", "port": 5432, "protocol": "tcp",
        "host_port": 20001, "address": "1.2.3.4:20001", "created_at": "2026-01-02T03:04:05Z"
    }));
    assert_eq!(e.host, "");
    let e: Endpoint = same(json!({
        "id": "e2", "machine_id": "m1", "port": 8080, "protocol": "http",
        "host": "app-ab12.example.test", "address": "http://app-ab12.example.test",
        "created_at": "2026-01-02T03:04:05Z"
    }));
    assert_eq!(e.host_port, None);
}

#[test]
fn create_endpoint_request() {
    let r: CreateEndpointRequest = round_trip(
        json!({"port": 80}),
        json!({"port": 80, "protocol": "", "host": ""}),
    );
    assert_eq!(r.port, 80);
    let r: CreateEndpointRequest = same(json!({"port": 80, "protocol": "http", "host": "app"}));
    assert_eq!(r.host, "app");
    assert!(serde_json::from_value::<CreateEndpointRequest>(json!({"protocol": "tcp"})).is_err());
    // A port is 16 bits.
    assert!(serde_json::from_value::<CreateEndpointRequest>(json!({"port": 70000})).is_err());
}

#[test]
fn exec_request_defaults() {
    let r: ExecRequest = round_trip(
        json!({"cmd": ["ls", "-l"]}),
        json!({
            "cmd": ["ls", "-l"], "env": {}, "cwd": "", "stdin": "",
            "timeout_ms": 0, "wake": true
        }),
    );
    assert!(r.wake, "wake defaults to true");
    assert_eq!(r.timeout_ms, 0);
    let r: ExecRequest = same(json!({
        "cmd": ["cat"], "env": {"X": "1"}, "cwd": "/tmp", "stdin": "hi",
        "timeout_ms": 5000, "wake": false
    }));
    assert!(!r.wake);
    assert_eq!(r.stdin, "hi");
    assert!(serde_json::from_value::<ExecRequest>(json!({"wake": true})).is_err());
    // ExecRequest::default() is not what the wire gives: the derive leaves wake false, so
    // code that builds one by hand must set it.
    assert!(!ExecRequest::default().wake);
}

#[test]
fn exec_result() {
    let r: ExecResult = same(json!({
        "stdout": "ok\n", "stderr": "", "exit_code": 0, "timed_out": false
    }));
    assert_eq!(r.exit_code, 0);
    assert!(serde_json::from_value::<ExecResult>(json!({"stdout": "x"})).is_err());
}

#[test]
fn files() {
    let p: PutFileRequest = same(json!({"path": "/etc/x", "base64": "aGk="}));
    assert_eq!(p.mode, None);
    let p: PutFileRequest = same(json!({"path": "/etc/x", "base64": "aGk=", "mode": "0600"}));
    assert_eq!(p.mode.as_deref(), Some("0600"));
    let f: FileResponse = same(json!({"path": "/etc/x", "base64": "aGk="}));
    assert_eq!(f.base64, "aGk=");
}

#[test]
fn logs() {
    let l: LogsResponse = round_trip(
        json!({"lines": [{"ts": "2026-01-02T03:04:05Z", "line": "[briqyard] started pid=1"}]}),
        json!({"lines": [{"ts": "2026-01-02T03:04:05Z", "line": "[briqyard] started pid=1"}]}),
    );
    assert_eq!(l.next, "");
    assert_eq!(l.lines[0].ts, ts());
    let l: LogsResponse = same(json!({"lines": [], "next": "42"}));
    assert_eq!(l.next, "42");
}

#[test]
fn update_machine_request() {
    // Absent keeps the current value, so absent must stay absent on the wire.
    let u: UpdateMachineRequest = same(json!({}));
    assert_eq!(u.sleep, None);
    assert_eq!(u.metadata, None);
    let u: UpdateMachineRequest = same(json!({"sleep": "3h"}));
    assert_eq!(u.sleep.as_deref(), Some("3h"));
    assert_eq!(u.metadata, None);
    let u: UpdateMachineRequest = same(json!({"metadata": {}}));
    assert_eq!(u.metadata, Some(BTreeMap::new()));
    let u: UpdateMachineRequest = same(json!({"egress": {"mode": "via", "via": "m_gw"}}));
    assert_eq!(
        u.egress.as_ref().and_then(|e| e.via.as_deref()),
        Some("m_gw")
    );
    assert_eq!(u.limits, None);
    // Only the limits it names change: 0 lifts one.
    let u: UpdateMachineRequest = same(json!({"limits": {"new_connections_per_minute": 0}}));
    assert_eq!(
        u.limits,
        Some(EgressLimits {
            new_connections_per_minute: Some(0),
            ..Default::default()
        })
    );
    assert!(u.spec.is_empty());
    // What it runs sits beside the rest, under create's names.
    let u: UpdateMachineRequest = same(json!({
        "sleep": "1h", "image": "python:3.13-alpine", "entrypoint": ["/bin/sh"],
        "cmd": ["-c", "x"], "env": {"V": "2"},
        "files": [{"path": "/a", "base64": "aGk="}],
        "size": {"vcpus": 2, "memory_mb": 1024}, "ports": [8080],
        "restart": {"policy": "always", "max_retries": 3}, "volume": {"size_gb": 20}
    }));
    assert_eq!(u.sleep.as_deref(), Some("1h"));
    assert_eq!(
        u.spec.fields(),
        [
            "image",
            "entrypoint",
            "cmd",
            "env",
            "files",
            "size",
            "ports",
            "restart",
            "volume"
        ]
    );
    assert_eq!(u.spec.ports, Some(vec![8080]));
    assert_eq!(u.spec.volume, Some(VolumeSize { size_gb: 20 }));
    // A volume's mount is fixed: a PATCH that names one is refused, not ignored.
    let err = serde_json::from_value::<UpdateMachineRequest>(
        json!({"volume": {"size_gb": 20, "mount": "/other"}}),
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown field `mount`"), "{err}");
}
