use super::*;

#[test]
fn sleep_windows() {
    assert_eq!(parse_sleep("").unwrap(), None);
    assert_eq!(parse_sleep("   ").unwrap(), None);
    assert_eq!(parse_sleep("never").unwrap(), None);
    assert_eq!(parse_sleep(" never ").unwrap(), None);
    let secs = |s: &str| parse_sleep(s).unwrap().unwrap().as_secs();
    assert_eq!(secs("45s"), 45);
    assert_eq!(secs("30m"), 1800);
    assert_eq!(secs("2h"), 7200);
    assert_eq!(secs("7d"), 7 * 86400);
    assert_eq!(secs(" 1m "), 60);
    for bad in [
        "0m", "0s", "0d", "x", "m", "1", "1y", "-1h", "1.5h", "30 m", "1h30m", "NEVER", "1M",
    ] {
        assert!(parse_sleep(bad).is_err(), "{bad}");
    }
    assert!(parse_sleep("0m").unwrap_err().contains("positive"));
    assert!(parse_sleep("1y").unwrap_err().contains("\"30m\""));
}

#[test]
fn sleep_windows_do_not_panic() {
    // A unit that is not one byte long used to split the string inside a character.
    for bad in ["1é", "é", "30\u{200b}", "1時"] {
        assert!(parse_sleep(bad).is_err(), "{bad}");
    }
    // A count past u64 is refused; one whose seconds would overflow too, instead of
    // wrapping to a short window in release builds.
    assert!(parse_sleep("99999999999999999999s").is_err());
    assert_eq!(
        parse_sleep(&format!("{}s", u64::MAX))
            .unwrap()
            .unwrap()
            .as_secs(),
        u64::MAX
    );
    assert!(parse_sleep(&format!("{}m", u64::MAX))
        .unwrap_err()
        .contains("too long"));
    assert!(parse_sleep(&format!("{}d", u64::MAX / 86400 + 1)).is_err());
    assert_eq!(
        secs_of(&format!("{}d", u64::MAX / 86400)),
        (u64::MAX / 86400) * 86400
    );
}

fn secs_of(s: &str) -> u64 {
    parse_sleep(s).unwrap().unwrap().as_secs()
}

#[test]
fn names() {
    for ok in [
        "db",
        "my-app",
        "a1",
        "x",
        "0",
        "a-b-c",
        "a--b",
        &"a".repeat(63),
    ] {
        assert!(valid_name(ok), "{ok}");
    }
    for bad in [
        "",
        "-a",
        "a-",
        "-",
        "A",
        "aB",
        "a.b",
        "a_b",
        "a b",
        "é",
        "a/b",
        &"a".repeat(64),
    ] {
        assert!(!valid_name(bad), "{bad}");
    }
}

#[test]
fn ids() {
    for ok in [
        "t1",
        "m_abcdef123456",
        "team-x",
        "_",
        "-",
        "0",
        &"a".repeat(64),
    ] {
        assert!(valid_id(ok), "{ok}");
    }
    // What would leave the state directory, or name a file nothing expects.
    for bad in [
        "",
        "../../etc/cron.d/x",
        "a/b",
        "..",
        ".hidden",
        "a.b",
        "A",
        "a b",
        "é",
        "a\0b",
        &"a".repeat(65),
    ] {
        assert!(!valid_id(bad), "{bad}");
    }
}
/// ADR 0055: `tenant` is the former name of `namespace` and still read, in a body, a record
/// or a heartbeat; what is written carries `namespace` only.
#[test]
fn tenant_is_read_as_namespace() {
    let size = json!({"vcpus": 1, "memory_mb": 256});
    let r: CreateMachineRequest =
        serde_json::from_value(json!({"tenant": "t1", "name": "db", "size": size})).unwrap();
    assert_eq!(r.namespace, "t1");
    let out = serde_json::to_value(&r).unwrap();
    assert_eq!(out["namespace"], "t1");
    assert!(out.get("tenant").is_none());
    let e: Event = serde_json::from_value(json!({
        "seq": 1, "at": "2026-10-20T14:00:00Z", "type": "normal", "reason": "created",
        "message": "", "machine_id": "m_1", "tenant": "t1"
    }))
    .unwrap();
    assert_eq!(e.namespace, "t1");
    let q: NamespaceQuota = serde_json::from_value(json!({
        "tenant": "t1", "quota": {"machines": 2},
        "used": {"machines": 0, "memory_mb": 0, "vcpus": 0, "disk_gb": 0}
    }))
    .unwrap();
    assert_eq!(q.namespace, "t1");
    let h: RegisterHostRequest = serde_json::from_value(json!({
        "id": "h1", "url": "https://h1:7420", "capacity": {"memory_mb": 1, "vcpus": 1},
        "used": {"memory_mb": 0, "vcpus": 0}, "machines": 1, "tenants": ["t1"]
    }))
    .unwrap();
    assert_eq!(h.namespaces, ["t1"]);
}
