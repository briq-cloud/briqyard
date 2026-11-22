use std::os::unix::fs::PermissionsExt;

#[test]
fn projection_failures_leave_stdout_empty() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    let mut initial: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../briqyard-api/tests/fixtures/authority-compacted-v1.json"
    ))
    .unwrap();
    initial["v"] = serde_json::json!(2);
    let bytes = serde_json::to_vec(&initial).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_briqyard-fleet"))
        .arg("authority")
        .arg("journal-project")
        .arg(&path)
        .arg("1999000")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
