use super::*;

#[test]
fn backup_policies() {
    let p: BackupPolicy = same(json!({"every": "6h", "keep": 4}));
    assert_eq!(p.check(), Ok(std::time::Duration::from_secs(6 * 3600)));
    let every = |e: &str| BackupPolicy {
        every: e.into(),
        keep: 1,
    };
    assert_eq!(every("1d").check().unwrap().as_secs(), 86400);
    assert_eq!(every(" 1h ").check().unwrap().as_secs(), 3600);
    // Each refusal names its field, for the caller to put `backup.` before.
    assert_eq!(
        every("59m").check().unwrap_err(),
        r#"every "59m": at least 1h"#
    );
    assert_eq!(
        every("never").check().unwrap_err(),
        r#"every "never": want "6h", "1d""#
    );
    assert_eq!(
        every("0h").check().unwrap_err(),
        r#"every "0h": must be positive"#
    );
    assert!(every("").check().unwrap_err().starts_with("every "));
    let none = BackupPolicy {
        every: "6h".into(),
        keep: 0,
    };
    assert_eq!(none.check().unwrap_err(), "keep: at least 1");
    // Both fields are required.
    assert!(serde_json::from_value::<BackupPolicy>(json!({"every": "6h"})).is_err());
}

#[test]
fn a_backup_policy_absent_is_kept_and_null_removes_it() {
    let c: CreateMachineRequest = serde_json::from_value(json!({
        "namespace": "t1", "name": "db", "size": {"vcpus": 1, "memory_mb": 256}
    }))
    .unwrap();
    assert_eq!(c.backup, None, "absent: the host's default");
    let c: CreateMachineRequest = serde_json::from_value(json!({
        "namespace": "t1", "name": "db", "size": {"vcpus": 1, "memory_mb": 256}, "backup": null
    }))
    .unwrap();
    assert_eq!(c.backup, Some(None), "null: none");
    assert_eq!(serde_json::to_value(&c).unwrap()["backup"], Value::Null);
    let u: UpdateMachineRequest = same(json!({"backup": {"every": "1d", "keep": 5}}));
    assert_eq!(u.backup.flatten().map(|p| p.keep), Some(5));
    let u: UpdateMachineRequest = same(json!({"backup": null}));
    assert_eq!(u.backup, Some(None));
    let u: UpdateMachineRequest = same(json!({}));
    assert_eq!(u.backup, None);
}

#[test]
fn backups() {
    let b: Backup = same(json!({
        "id": "20261021T101500.123Z", "machine_id": "m1", "namespace": "t1", "name": "db",
        "created_at": "2026-01-02T03:04:05Z", "bytes": 30, "incremental": true,
        "disks": [
            {"disk": "root", "key": "backups/m1/root/20261021T101500.123Z.zfs", "bytes": 10,
             "from": "20261021T091500.001Z"},
            {"disk": "data", "key": "backups/m1/data/20261021T101500.123Z.zfs", "bytes": 20}
        ],
        "deletes_at": "2026-01-02T03:04:05Z"
    }));
    assert_eq!(b.disks[0].from.as_deref(), Some("20261021T091500.001Z"));
    assert_eq!(b.disks[1].from, None);
    assert_eq!(b.deletes_at, Some(ts()));
    // A stored record carries the machine and no deletion time.
    let r: Backup = same(json!({
        "id": "a", "machine_id": "m1", "namespace": "t1", "name": "db",
        "created_at": "2026-01-02T03:04:05Z", "bytes": 0, "incremental": false,
        "disks": [], "machine": {"id": "m1"}
    }));
    assert_eq!(r.deletes_at, None);
    let rs: RestoreSpec = round_trip(
        json!({"machine_id": "m1"}),
        json!({"machine_id": "m1", "backup": ""}),
    );
    assert_eq!(rs.backup, "");
}
