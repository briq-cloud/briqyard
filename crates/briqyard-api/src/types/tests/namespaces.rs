use super::*;

#[test]
fn stop_request() {
    let s: StopRequest = round_trip(json!({}), json!({"suspend": false, "timeout_sec": 0}));
    assert!(!s.suspend);
    let s: StopRequest = same(json!({"suspend": true, "timeout_sec": 30}));
    assert_eq!(s.timeout_sec, 30);
}

#[test]
fn snapshot_and_namespace() {
    let s: Snapshot = round_trip(
        json!({"id": "snap1", "machine_id": "m1", "created_at": "2026-01-02T03:04:05Z"}),
        json!({
            "id": "snap1", "machine_id": "m1", "created_at": "2026-01-02T03:04:05Z",
            "disks": [], "memory": false
        }),
    );
    assert_eq!(s.machine_id, "m1");
    let s: Snapshot = same(json!({
        "id": "s_1", "machine_id": "m1", "name": "before-migration",
        "created_at": "2026-01-02T03:04:05Z", "disks": ["root", "data"], "memory": true
    }));
    assert_eq!(s.name.as_deref(), Some("before-migration"));
    let r: SnapshotRequest = round_trip(json!({}), json!({"memory": false}));
    assert!(r.name.is_none() && !r.memory);
    let r: SnapshotRequest = same(json!({"name": "x", "memory": true}));
    assert!(r.memory);
    for ok in ["before-migration", "a", "s1", "snap_2"] {
        assert!(check_snapshot_name(ok).is_ok(), "{ok}");
    }
    for bad in ["", "s_abc", "Before", "a/b", "..", &"x".repeat(65)] {
        assert!(check_snapshot_name(bad).is_err(), "{bad}");
    }
    let t: Namespace = round_trip(
        json!({"id": "t1", "created_at": "2026-01-02T03:04:05Z"}),
        json!({
            "id": "t1", "subnet": "", "router": "", "machines": 0,
            "created_at": "2026-01-02T03:04:05Z"
        }),
    );
    assert_eq!(t.host, "");
    assert!(t.gateway.is_none(), "no gateway: none on the wire");
    let t: Namespace = same(json!({
        "id": "t1", "subnet": "10.64.1.0/24", "router": "10.64.1.1", "machines": 2,
        "created_at": "2026-01-02T03:04:05Z", "host": "h1", "region": "gra",
        "gateway": {"state": "running", "ip": "10.64.1.2", "port": 3128, "machine_id": "m_1"}
    }));
    assert_eq!(t.machines, 2);
    assert_eq!(t.region, "gra");
    assert_eq!(t.gateway.as_ref().map(|g| g.port), Some(3128));
    let g: GatewayView = same(json!({
        "state": "error", "ip": "10.64.1.2", "port": 3128, "machine_id": "m_1",
        "error": "port 3128 did not answer"
    }));
    assert_eq!(g.error, "port 3128 did not answer");
}

#[test]
fn quota() {
    // A limit left out is no limit, and stays out on the wire.
    let q: Quota = same(json!({}));
    assert_eq!(q, Quota::default());
    let q: Quota = same(json!({"machines": 1, "memory_mb": 2048, "vcpus": 4, "disk_gb": 20}));
    assert_eq!((q.machines, q.disk_gb), (Some(1), Some(20)));
    let q: Quota = same(json!({"memory_mb": 0}));
    assert_eq!(q.memory_mb, Some(0), "zero is a limit, nothing allowed");
    let t: NamespaceQuota = same(json!({
        "namespace": "t1", "quota": {"machines": 2},
        "used": {"machines": 1, "memory_mb": 512, "vcpus": 1, "disk_gb": 0}
    }));
    assert_eq!(t.used.memory_mb, 512);
    assert!(serde_json::from_value::<Quota>(json!({"machines": -1})).is_err());
}

#[test]
fn label_selectors() {
    let l = |s: &str| Label::parse(s).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        l("app=web"),
        Label {
            key: "app".into(),
            value: Some("web".into())
        }
    );
    assert_eq!(l("app").value, None, "present");
    assert_eq!(l("app=").value.as_deref(), Some(""), "equal to empty");
    assert_eq!(l("briq_id=bq_1").key, "briq_id");
    assert_eq!(l("briq.cloud/stack=main").key, "briq.cloud/stack");
    assert_eq!(l("a.b-c_d=V.1-x").value.as_deref(), Some("V.1-x"));
    let refused = |s: &str| Label::parse(s).unwrap_err();
    for s in ["app!=web", "!app", "app in (a,b)", "app notin (a)"] {
        assert!(refused(s).contains("only key=value and key"), "{s}");
    }
    for s in [
        "",
        "=web",
        "-app=x",
        "app-=x",
        "Prefix.Upper/app",
        "/app",
        &"k".repeat(64),
    ] {
        assert!(refused(s).contains("the key is"), "{s:?}");
    }
    for s in [
        "app=-x",
        "app=a=b",
        "app=a/b",
        &format!("app={}", "v".repeat(64)),
    ] {
        assert!(refused(s).contains("the value is"), "{s:?}");
    }
    let labels: BTreeMap<String, String> = [("app", "web"), ("tier", "")]
        .map(|(k, v)| (k.into(), v.into()))
        .into();
    assert!(l("app=web").matches(&labels));
    assert!(!l("app=db").matches(&labels));
    assert!(l("app").matches(&labels));
    assert!(l("tier=").matches(&labels));
    assert!(!l("zone").matches(&labels));
}

#[test]
fn gateway_spec() {
    // An image and a port are enough; env comes back empty, not started, the rest out.
    let s: GatewaySpec = round_trip(
        json!({"image": "ghcr.io/x/proxy:1", "port": 3128}),
        json!({"image": "ghcr.io/x/proxy:1", "env": {}, "port": 3128, "start": false}),
    );
    assert!(s.size.is_none() && s.volume_gb.is_none() && s.cmd.is_none());
    assert_eq!(
        s.size(),
        Size {
            vcpus: 1,
            memory_mb: 256
        }
    );
    let s: GatewaySpec = same(json!({
        "image": "ghcr.io/x/proxy:1", "cmd": ["proxy", "-v"], "env": {"TOKEN": "t"},
        "size": {"vcpus": 1, "memory_mb": 512}, "port": 3128, "volume_gb": 1, "start": true
    }));
    assert_eq!(s.env["TOKEN"], "t");
    assert_eq!(s.size().memory_mb, 512);
    assert!(s.start);
    for missing in [json!({"image": "x"}), json!({"port": 3128})] {
        assert!(
            serde_json::from_value::<GatewaySpec>(missing.clone()).is_err(),
            "{missing}"
        );
    }
}

#[test]
fn machine_stats() {
    let s: MachineStats = same(json!({
        "state": "running", "cpu_usec": 123456, "memory_bytes": 104857600,
        "uptime_sec": 60, "disk_bytes": 2147483648u64
    }));
    assert_eq!(s.disk_bytes, 2 << 30);
}

#[test]
fn image_ref_field() {
    // The reference is `ref` on the wire (a keyword in Rust, hence the rename).
    let i: Image = same(json!({
        "key": "k", "ref": "docker.io/library/postgres:17", "digest": "sha256:abc",
        "size_gb": 2, "built_at": "2026-01-02T03:04:05Z", "machines": 1
    }));
    assert_eq!(i.reference, "docker.io/library/postgres:17");
    assert!(serde_json::from_value::<Image>(json!({
        "key": "k", "reference": "x", "digest": "d", "size_gb": 2,
        "built_at": "2026-01-02T03:04:05Z", "machines": 1
    }))
    .is_err());
}
