use super::*;

#[test]
fn a_spec_change_and_its_check() {
    let s = |v: Value| -> SpecChange { serde_json::from_value(v).unwrap() };
    for (v, want) in [
        (json!({"image": ""}), "image must not be empty"),
        (
            json!({"env": {"": "x"}}),
            "env \"\": a name is not empty and holds no \"=\"",
        ),
        (
            json!({"env": {"A=B": "x"}}),
            "env \"A=B\": a name is not empty and holds no \"=\"",
        ),
        (
            json!({"files": [{"path": "a", "base64": ""}]}),
            "file \"a\": path must be absolute",
        ),
        (
            json!({"files": [{"path": "/a", "base64": "", "mode": "08"}]}),
            "file \"/a\": mode \"08\": want octal digits",
        ),
        (
            json!({"size": {"vcpus": 33, "memory_mb": 512}}),
            "size.vcpus must be 1..32",
        ),
        (
            json!({"size": {"vcpus": 1, "memory_mb": 64}}),
            "size.memory_mb must be 128..262144",
        ),
        (json!({"ports": [80, 0]}), "ports: 0 is not a port"),
        (
            json!({"restart": {"policy": "sometimes"}}),
            "restart.policy must be no, on-failure or always",
        ),
        (
            json!({"volume": {"size_gb": 0}}),
            "volume.size_gb must be 1 or more",
        ),
    ] {
        assert_eq!(s(v.clone()).check(), Err(want.to_string()), "{v}");
    }
    let bad_b64 = s(json!({"files": [{"path": "/a", "base64": "!!"}]})).check();
    assert!(bad_b64.unwrap_err().starts_with("file \"/a\": "));
    let fine = s(json!({"image": "x", "env": {"A": "a=b"}, "cmd": [],
            "files": [{"path": "/a", "base64": "aGk=", "mode": "0755"}, {"path": "/b", "base64": "", "mode": ""}],
            "size": {"vcpus": 1, "memory_mb": 128}, "ports": [1], "restart": {"policy": "no"}}));
    assert_eq!(fine.check(), Ok(()));
    // What changed from another, set or unset; what a memory snapshot holds.
    let was = s(json!({"image": "x", "ports": [1]}));
    let now = s(json!({"image": "x", "env": {}}));
    assert_eq!(now.changed_from(&was), ["env", "ports"]);
    assert!(now.touches_snapshot());
    assert!(!s(json!({"ports": [1], "restart": {}})).touches_snapshot());
    assert!(s(json!({"volume": {"size_gb": 2}})).touches_snapshot());
    assert!(SpecChange::default().is_empty() && SpecChange::default().fields().is_empty());
    // As the view shows it: env and files by name only.
    let v = s(json!({"image": "y", "env": {"SECRET": "s"},
            "size": {"vcpus": 1, "memory_mb": 256}, "volume": {"size_gb": 20}}))
    .view();
    assert_eq!(
        serde_json::to_value(&v).unwrap(),
        json!({"fields": ["image", "env", "size", "volume"], "image": "y",
                "size": {"vcpus": 1, "memory_mb": 256}, "volume": {"size_gb": 20}})
    );
    // A create is checked as the same spec: its image only when it names one.
    let c = CreateMachineRequest {
        size: Size {
            vcpus: 1,
            memory_mb: 256,
            cpu_millis: None,
        },
        ..Default::default()
    };
    assert_eq!(c.spec().image, None);
    assert_eq!(c.spec().fields(), ["env", "files", "size", "ports"]);
}

#[test]
fn egress_policy() {
    // Absent fields are the default: open, no gateway; `via` stays off the wire then.
    let e: Egress = round_trip(json!({}), json!({"mode": "open"}));
    assert_eq!(e, Egress::default());
    assert_eq!(e.check(), Ok(()));
    let e: Egress = same(json!({"mode": "none"}));
    assert_eq!(e.check(), Ok(()));
    let e: Egress = same(json!({"mode": "via", "via": "m_gw"}));
    assert_eq!(e.check(), Ok(()));
    assert!(!e.via_gateway());
    // The namespace's gateway, by the word that names it.
    let e: Egress = same(json!({"mode": "via", "via": "gateway"}));
    assert_eq!(e.check(), Ok(()));
    assert!(e.via_gateway());
    assert!(!Egress::default().via_gateway());
    // The checks name the field and what it wants.
    let bad = |v: serde_json::Value| serde_json::from_value::<Egress>(v).unwrap().check();
    assert_eq!(
        bad(json!({"mode": "all"})).unwrap_err(),
        "egress.mode \"all\": want \"open\", \"via\" or \"none\""
    );
    assert_eq!(
        bad(json!({"mode": "open", "via": "m_gw"})).unwrap_err(),
        "egress.via goes with mode \"via\" only"
    );
    for v in [
        json!({"mode": "via"}),
        json!({"mode": "via", "via": "../x"}),
    ] {
        assert_eq!(
            bad(v).unwrap_err(),
            "egress.via must name a machine of the namespace"
        );
    }
}

#[test]
fn egress_limits() {
    // Absent fields stay absent: a request that names none changes none.
    let l: EgressLimits = same(json!({}));
    assert_eq!(l, EgressLimits::default());
    assert_eq!(l.check(), Ok(()));
    let own: EgressLimits = same(json!({"blocked_ports": [], "bandwidth_mbit": 100}));
    assert_eq!(own.check(), Ok(()));
    // A machine's own fields over the host's, one by one; `[]` and 0 are values.
    let host: EgressLimits = same(json!({
        "blocked_ports": [25], "new_connections_per_minute": 0, "bandwidth_mbit": 0
    }));
    assert_eq!(
        own.over(&host),
        EgressLimits {
            blocked_ports: Some(vec![]),
            new_connections_per_minute: Some(0),
            bandwidth_mbit: Some(100),
        }
    );
    assert_eq!(EgressLimits::default().over(&host), host);
    // The checks name the field under `limits` and what it wants.
    let bad = |v: serde_json::Value| serde_json::from_value::<EgressLimits>(v).unwrap().check();
    assert_eq!(
        bad(json!({"blocked_ports": [25, 0]})).unwrap_err(),
        "blocked_ports: 0 is not a port"
    );
    assert_eq!(
        bad(json!({"bandwidth_mbit": 100_001})).unwrap_err(),
        "bandwidth_mbit: at most 100000"
    );
    assert_eq!(bad(json!({"bandwidth_mbit": 100_000})), Ok(()));
    assert!(serde_json::from_value::<EgressLimits>(json!({"blocked_ports": [70000]})).is_err());
    let d: EgressDrops = same(json!({"blocked_port": 1, "rate": 2, "bandwidth": 3}));
    assert_eq!(d.total(), 6);
}

#[test]
fn disk_limits() {
    let l: DiskLimits = same(json!({}));
    assert_eq!(l, DiskLimits::default());
    let own: DiskLimits = same(json!({"bandwidth_mb": 0, "iops": 500}));
    let host: DiskLimits = same(json!({"bandwidth_mb": 64, "iops": 4000, "burst_sec": 10}));
    // Its own fields over the host's, one by one; 0 is a value (no limit).
    assert_eq!(
        own.over(&host),
        DiskLimits {
            bandwidth_mb: Some(0),
            iops: Some(500),
            burst_sec: Some(10),
        }
    );
    let bad = |v: serde_json::Value| serde_json::from_value::<DiskLimits>(v).unwrap().check();
    assert_eq!(
        bad(json!({"bandwidth_mb": 100_000, "iops": 10_000_000})),
        Ok(())
    );
    assert_eq!(
        bad(json!({"bandwidth_mb": 100_001})).unwrap_err(),
        "bandwidth_mb: at most 100000"
    );
    assert_eq!(
        bad(json!({"iops": 10_000_001})).unwrap_err(),
        "iops: at most 10000000"
    );
    assert_eq!(
        bad(json!({"burst_sec": 3601})).unwrap_err(),
        "burst_sec: at most 3600"
    );
}

#[test]
fn probes_round_trip_with_their_defaults() {
    // An action alone takes Kubernetes's timings; `path` defaults to `/`.
    let p: Probes = round_trip(
        json!({"readiness": {"http": {"port": 8080}}, "liveness": {"exec": ["true"]}}),
        json!({
            "readiness": {"http": {"port": 8080, "path": "/"}, "period_sec": 10,
                "timeout_sec": 5, "failure_threshold": 3, "success_threshold": 1,
                "initial_delay_sec": 0},
            "liveness": {"exec": ["true"], "period_sec": 10, "timeout_sec": 5,
                "failure_threshold": 3, "success_threshold": 1, "initial_delay_sec": 0}
        }),
    );
    assert!(p.startup.is_none());
    assert_eq!(p.check(), Ok(()));
    let full = json!({"startup": {"tcp": 5432, "period_sec": 2, "timeout_sec": 1,
            "failure_threshold": 30, "success_threshold": 1, "initial_delay_sec": 4}});
    let p: Probes = same(full);
    assert_eq!(p.startup.as_ref().unwrap().target(), "tcp :5432");
    assert!(same::<Probes>(json!({})).is_empty());
    // In a request and a gateway's spec: absent stays absent.
    let u: UpdateMachineRequest = same(json!({"probes": {}}));
    assert_eq!(u.probes, Some(Probes::default()));
    let r: CreateMachineRequest = serde_json::from_value(json!({
        "namespace": "t1", "name": "web", "size": {"vcpus": 1, "memory_mb": 256},
        "probes": {"readiness": {"tcp": 80}}
    }))
    .unwrap();
    assert_eq!(
        r.probes.and_then(|p| p.readiness).and_then(|p| p.tcp),
        Some(80)
    );
    let s: GatewaySpec = serde_json::from_value(json!({
        "image": "proxy", "port": 3128, "probes": {"readiness": {"tcp": 3128}}
    }))
    .unwrap();
    assert!(s.probes.readiness.is_some());
    let st: ProbeStatus = same(json!({
        "passed": true, "message": "HTTP 200", "failures": 0, "at": "2026-01-02T03:04:05Z"
    }));
    assert!(st.passed);
}

#[test]
fn probes_are_checked_with_the_field_named() {
    let bad = |v: Value| {
        serde_json::from_value::<Probes>(v)
            .unwrap()
            .check()
            .unwrap_err()
    };
    assert_eq!(
        bad(json!({"readiness": {}})),
        "probes.readiness: exactly one of exec, tcp and http"
    );
    assert_eq!(
        bad(json!({"liveness": {"exec": ["true"], "tcp": 80}})),
        "probes.liveness: exactly one of exec, tcp and http"
    );
    assert_eq!(
        bad(json!({"startup": {"exec": []}})),
        "probes.startup.exec: an empty command"
    );
    assert_eq!(
        bad(json!({"readiness": {"tcp": 0}})),
        "probes.readiness.tcp: 0 is not a port"
    );
    assert_eq!(
        bad(json!({"readiness": {"http": {"port": 0}}})),
        "probes.readiness.http.port: 0 is not a port"
    );
    for path in ["healthz", "/a b", "/a\r\nX: y", ""] {
        assert!(
            bad(json!({"readiness": {"http": {"port": 80, "path": path}}}))
                .starts_with("probes.readiness.http.path: "),
            "{path:?}"
        );
    }
    for field in [
        "period_sec",
        "timeout_sec",
        "failure_threshold",
        "success_threshold",
    ] {
        let mut p = json!({"readiness": {"tcp": 80}});
        p["readiness"][field] = json!(0);
        assert_eq!(bad(p), format!("probes.readiness.{field}: at least 1"));
    }
    // Readiness may want several passes; startup and liveness pass on one, as Kubernetes.
    let three = |kind: &str| json!({ kind: {"tcp": 80, "success_threshold": 3} });
    assert!(serde_json::from_value::<Probes>(three("readiness"))
        .unwrap()
        .check()
        .is_ok());
    assert_eq!(
        bad(three("liveness")),
        "probes.liveness.success_threshold: must be 1"
    );
    assert_eq!(
        bad(three("startup")),
        "probes.startup.success_threshold: must be 1"
    );
    // A negative or fractional timing is refused by the parse itself.
    assert!(serde_json::from_value::<Probe>(json!({"tcp": 80, "period_sec": -1})).is_err());
    assert!(serde_json::from_value::<Probe>(json!({"tcp": 70000})).is_err());
}

#[test]
fn cpu_limits_are_precise_and_legacy_values_stay_valid() {
    let mut size: Size = serde_json::from_value(json!({"vcpus": 1, "memory_mb": 128})).unwrap();
    assert_eq!(size.cpu_millis(), 1000);
    assert!(serde_json::to_value(size)
        .unwrap()
        .get("cpu_millis")
        .is_none());
    for millis in [1, 250, 1000] {
        size.cpu_millis = Some(millis);
        assert!(size.check().is_ok());
        assert_eq!(size.cpu_millis(), millis);
    }
    for millis in [0, 1001] {
        size.cpu_millis = Some(millis);
        assert!(size.check().is_err());
    }
    let quota = Quota {
        vcpus: Some(1),
        cpu_millis: Some(1500),
        ..Default::default()
    };
    assert_eq!(quota.cpu_millis(), Some(1000));
    let legacy = Capacity {
        memory_mb: 1024,
        vcpus: 4,
        cpu_millis: None,
    };
    assert_eq!(legacy.cpu_millis(), 4000);
}

#[test]
fn sibling_access_is_explicit_and_only_valid_through_a_gateway() {
    let strict: Egress = serde_json::from_value(json!({"mode":"via","via":"m_gateway"})).unwrap();
    assert_eq!(serde_json::to_value(&strict).unwrap().get("siblings"), None);
    let allowed: Egress =
        serde_json::from_value(json!({"mode":"via","via":"m_gateway","siblings":true})).unwrap();
    assert!(allowed.check().is_ok());
    assert_eq!(serde_json::to_value(&allowed).unwrap()["siblings"], true);
    for mode in ["open", "none"] {
        let invalid: Egress = serde_json::from_value(json!({"mode":mode,"siblings":true})).unwrap();
        assert!(invalid.check().is_err(), "siblings cannot widen {mode}");
    }
}
