use super::*;

#[test]
fn host() {
    let input = json!({
        "id": "h1", "url": "http://10.0.0.5:7420", "state": "ready",
        "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 1024, "vcpus": 2},
        "machines": 2, "last_seen": "2026-01-02T03:04:05Z"
    });
    let mut expected = input.clone();
    expected["region"] = json!("");
    expected["provider"] = json!("");
    expected["namespaces"] = json!([]);
    expected["version"] = json!("");
    expected["tls_fingerprint"] = json!("");
    expected["conditions"] = json!([]);
    let h: Host = round_trip(input, expected);
    assert_eq!(h.note, "");
    let h: Host = same(json!({
        "id": "h1", "url": "http://10.0.0.5:7420", "region": "fsn1", "provider": "manual",
        "state": "draining", "capacity": {"memory_mb": 65536, "vcpus": 16},
        "used": {"memory_mb": 1024, "vcpus": 2}, "machines": 2, "namespaces": ["t1", "t2"],
        "last_seen": "2026-01-02T03:04:05Z", "version": "0.1.0", "note": "bootstrapped",
        "tls_fingerprint": "ab01",
        "conditions": [{"type": "disk_pressure", "status": true,
            "since": "2026-01-02T03:04:05Z", "message": "pool 4% free"}],
        "started": {"at": "2026-01-02T03:04:05Z", "adopted": 2, "stopped": 0, "gone": 1}
    }));
    assert_eq!(h.namespaces, vec!["t1", "t2"]);
    assert_eq!(h.started.map(|s| (s.adopted, s.gone)), Some((2, 1)));
    assert_eq!(
        under_pressure(&h.conditions).map(|c| c.kind.as_str()),
        Some(condition::DISK_PRESSURE)
    );
}

#[test]
fn host_requests() {
    let r: RegisterHostRequest = round_trip(
        json!({
            "id": "h1", "url": "http://10.0.0.5:7420",
            "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
            "machines": 0
        }),
        json!({
            "id": "h1", "url": "http://10.0.0.5:7420", "region": "",
            "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
            "machines": 0, "namespaces": [], "version": "", "disk_free_mb": 0,
            "tls_fingerprint": "", "conditions": []
        }),
    );
    assert_eq!(r.region, "");
    let r: RegisterHostRequest = same(json!({
        "id": "h1", "url": "http://10.0.0.5:7420", "region": "fsn1",
        "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 512, "vcpus": 1},
        "machines": 1, "namespaces": ["t1"], "version": "0.1.0", "disk_free_mb": 100000,
        "tls_fingerprint": "ab01",
        "conditions": [{"type": "memory_pressure", "status": false,
            "since": "2026-01-02T03:04:05Z", "message": "512 MB of 65536 committed (0%)"}],
        "started": {"at": "2026-01-02T03:04:05Z", "adopted": 2, "stopped": 0, "gone": 1}
    }));
    assert_eq!(r.disk_free_mb, 100000);
    assert_eq!(r.tls_fingerprint, "ab01");
    assert!(serde_json::from_value::<RegisterHostRequest>(json!({"id": "h1"})).is_err());
}

#[test]
fn status() {
    let s: Status = round_trip(
        json!({
            "version": "0.1.0", "host_id": "h1",
            "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
            "machines": 3, "running": 1
        }),
        json!({
            "version": "0.1.0", "host_id": "h1",
            "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
            "machines": 3, "running": 1, "disk_free_mb": 0, "tls_fingerprint": "",
            "conditions": [], "vmm_version": ""
        }),
    );
    assert_eq!(s.running, 1);
    let s: Status = same(json!({
        "version": "0.1.0", "host_id": "h1",
        "capacity": {"memory_mb": 1000, "vcpus": 16}, "used": {"memory_mb": 990, "vcpus": 2},
        "machines": 3, "running": 3, "disk_free_mb": 10, "tls_fingerprint": "",
        "conditions": [
            {"type": "memory_pressure", "status": true, "since": "2026-01-02T03:04:05Z",
             "message": "990 MB of 1000 committed (99%), over 95%"},
            {"type": "disk_pressure", "status": false, "since": "2026-01-02T03:04:05Z",
             "message": "pool 50% free"}
        ],
        "started": {"at": "2026-01-02T03:04:05Z", "adopted": 2, "stopped": 0, "gone": 1}, "vmm_version": "v1.17.0/6.8.0-45-generic"
    }));
    assert_eq!(
        under_pressure(&s.conditions).map(|c| c.kind.as_str()),
        Some(condition::MEMORY_PRESSURE)
    );
    // A condition without its status or time is refused, not read as fine.
    assert!(
        serde_json::from_value::<Condition>(json!({"type": "disk_pressure", "message": ""}))
            .is_err()
    );
    assert_eq!(
        condition::ALL,
        ["memory_pressure", "disk_pressure", "storage_stalled"]
    );
}

#[test]
fn upgrade_request() {
    let r: UpgradeHostRequest = same(json!({"release": "0.2.0"}));
    assert_eq!(r.release, "0.2.0");
    assert!(serde_json::from_value::<UpgradeHostRequest>(json!({})).is_err());
}

#[test]
fn top_machine() {
    let t: TopMachine = same(json!({
        "machine_id": "m_1", "namespace": "t1", "name": "db", "cpu_percent": 12.5,
        "memory_bytes": 104857600, "memory_limit_bytes": 536870912,
        "disk_used_bytes": 2147483648u64, "internet_in_bytes_per_sec": 10.0,
        "internet_out_bytes_per_sec": 2.5, "ingress_in_bytes_per_sec": 0.0,
        "ingress_out_bytes_per_sec": 1000.0, "window_sec": 15.0
    }));
    assert_eq!((t.role, t.host.as_str()), (None, ""));
    let g: TopMachine = same(json!({
        "machine_id": "m_2", "namespace": "t1", "name": "gateway", "role": "gateway",
        "cpu_percent": 0.0, "memory_bytes": 0, "memory_limit_bytes": 268435456,
        "disk_used_bytes": 0, "internet_in_bytes_per_sec": 0.0,
        "internet_out_bytes_per_sec": 0.0, "ingress_in_bytes_per_sec": 0.0,
        "ingress_out_bytes_per_sec": 0.0, "window_sec": 0.0, "host": "h1"
    }));
    assert_eq!(g.role.as_deref(), Some("gateway"));
}

#[test]
fn usage_bucket() {
    // Flat: the identity, every measure by its ADR name, `closed`; no role for a namespace's
    // own machine, no host from a daemon.
    let b: UsageBucket = same(json!({
        "hour": "2026-10-20T14:00:00Z", "machine_id": "m_1", "namespace": "t1",
        "metadata": {"briq_id": "bq_1"}, "size": {"vcpus": 1, "memory_mb": 512},
        "running_seconds": 3600.0, "suspended_seconds": 0.0, "cpu_seconds": 12.5,
        "memory_mb_seconds": 1843200.0, "root_gb_hours": 8.0, "volume_gb_hours": 2.0,
        "disk_used_gb_hours": 0.5, "snapshot_gb_hours": 0.25, "backup_gb_hours": 0.75,
        "internet_out_bytes": 100, "internet_in_bytes": 2000,
        "ingress_out_bytes": 300, "ingress_in_bytes": 40, "egress_dropped_packets": 7,
        "closed": true
    }));
    assert_eq!(b.usage.cpu_seconds, 12.5);
    assert_eq!(b.usage.ingress_in_bytes, 40);
    assert_eq!(b.role, None);
    let g: UsageBucket = same(json!({
        "hour": "2026-10-20T15:00:00Z", "machine_id": "m_2", "namespace": "t1",
        "role": "gateway", "metadata": {}, "size": {"vcpus": 1, "memory_mb": 256},
        "running_seconds": 1.5, "suspended_seconds": 0.0, "cpu_seconds": 0.0,
        "memory_mb_seconds": 384.0, "root_gb_hours": 0.0, "volume_gb_hours": 0.0,
        "disk_used_gb_hours": 0.0, "snapshot_gb_hours": 0.0, "backup_gb_hours": 0.0,
        "internet_out_bytes": 0, "internet_in_bytes": 0,
        "ingress_out_bytes": 0, "ingress_in_bytes": 0, "egress_dropped_packets": 2,
        "closed": false, "host": "h1"
    }));
    assert_eq!(
        (g.role.as_deref(), g.host.as_str()),
        (Some("gateway"), "h1")
    );
    // A measure left out is refused, not read as zero.
    assert!(serde_json::from_value::<UsageBucket>(json!({
        "hour": "2026-10-20T15:00:00Z", "machine_id": "m_2", "namespace": "t1",
        "size": {"vcpus": 1, "memory_mb": 256}, "closed": false
    }))
    .is_err());
    // Except the drops: an hour stored before ADR 0018 has none, read as zero.
    let mut old = serde_json::to_value(&b).unwrap();
    old.as_object_mut()
        .unwrap()
        .remove("egress_dropped_packets");
    let old: UsageBucket = serde_json::from_value(old).unwrap();
    assert_eq!(old.usage.egress_dropped_packets, 0);
    // Two measures of a machine's hour add up, field by field.
    let mut u = b.usage;
    u.add(&g.usage);
    assert_eq!(u.running_seconds, 3601.5);
    assert_eq!(u.memory_mb_seconds, 1843584.0);
    assert_eq!(u.internet_in_bytes, 2000);
    assert_eq!(u.egress_dropped_packets, 9);
}

#[test]
fn api_error() {
    // request_id is left out when the error has none.
    let e: ApiError = same(json!({"error": "no such machine", "code": "not_found"}));
    assert_eq!(e.request_id, "");
    let e: ApiError = same(json!({"error": "boom", "code": "internal", "request_id": "r1"}));
    assert_eq!(e.request_id, "r1");
    // A boot failure carries the machine it left in `error`.
    let e: ApiError = same(json!({
        "error": "the guest did not come up", "code": "boot_failed",
        "machine": {
            "id": "m1", "namespace": "t1", "name": "db", "image": "postgres:17",
            "state": "error", "error": "the guest did not come up",
            "hostname": "db.internal", "machine_host": "m1.vm.internal",
            "size": {"vcpus": 1, "memory_mb": 512}, "ports": [], "sleep": "never",
            "restart": {"policy": "no", "max_retries": 0}, "egress": {"mode": "open"},
            "limits": {}, "egress_drops": {"blocked_port": 0, "rate": 0, "bandwidth": 0},
            "metadata": {}, "endpoints": [],
            "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z",
            "state_changed_at": "2026-01-02T03:04:05Z", "suspended": false, "version": 3,
            "restarts": 0, "ready": false
        }
    }));
    assert_eq!(e.machine.as_ref().map(|m| m.state.as_str()), Some("error"));
    // A cursor too old for the log names the oldest seq kept.
    let e: ApiError = same(json!({"error": "since 3 is gone", "code": "gone", "oldest": 120}));
    assert_eq!(e.oldest, Some(120));
}
