use super::*;
use serde_json::Value;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

fn only_static_keys_and_numbers(value: &Value) {
    match value {
        Value::Object(map) => map.values().for_each(only_static_keys_and_numbers),
        Value::Array(values) => values.iter().for_each(only_static_keys_and_numbers),
        Value::Number(_) | Value::Bool(_) => {}
        _ => panic!("projection contains a value other than a number"),
    }
}

#[test]
fn projection_measures_reclaimable_raw_credentials() {
    let mut initial: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/authority-compacted-v1.json"
    ))
    .unwrap();
    let signed: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/execution-v1.json")).unwrap();
    initial["delegation_intents"]["legacy"]["request"]["grant"] = signed["grant_token"].clone();
    initial["delegation_intents"]["legacy"]["request"]["allocations"] =
        serde_json::json!([signed["allocation_token"].as_str().unwrap()]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    let before = serde_json::to_vec(&initial).unwrap();
    std::fs::write(&path, &before).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let report = project_capacity(&path, 2_000_000).unwrap();
    assert_eq!(report.bytes_reclaimed, 1734);
    assert_eq!(report.retained_bytes["delegation_credentials"], 0);
    assert!(report.fits_capacity);
    for projection in report.collections.values() {
        assert_eq!(projection.before, projection.after);
    }
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(signed["grant_token"].as_str().unwrap()));
    assert!(!serialized.contains(signed["allocation_token"].as_str().unwrap()));

    let pretty = serde_json::to_vec_pretty(&initial).unwrap();
    assert!(pretty.len() > before.len());
    std::fs::write(&path, &pretty).unwrap();
    let pretty_report = project_capacity(&path, 2_000_000).unwrap();
    assert_eq!(pretty_report.bytes_before, pretty.len());
    assert_eq!(pretty_report.bytes_after, report.bytes_after);
    assert_eq!(pretty_report.bytes_reclaimed, report.bytes_reclaimed);
}

#[test]
fn projection_is_read_only_and_reports_only_aggregates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    let bytes = include_bytes!("../../../tests/fixtures/authority-compacted-v1.json");
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let lock_path = directory.path().join("writer.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .unwrap();
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    lock.try_lock().unwrap();
    let before = std::fs::metadata(&path).unwrap();
    let mtime = (before.mtime(), before.mtime_nsec());
    let entries = || {
        std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>()
    };
    let before_entries = entries();
    let report = project_capacity(&path, 1_999_000).unwrap();
    assert_eq!(report.qualified_lower_bound_ms, 1_999_000);
    assert_eq!(report.bytes_before as u64, before.len());
    assert!(report.fits_capacity);
    assert_eq!(report.bytes_reclaimed, 0);
    assert_eq!(report.retained_bytes["delegation_credentials"], 0);
    assert_eq!(
        report.retained_bytes.values().sum::<usize>(),
        report.bytes_after
    );
    for projection in report.collections.values() {
        assert_eq!(projection.before, projection.after);
    }
    let text = serde_json::to_string_pretty(&report).unwrap();
    let serialized: Value = serde_json::from_str(&text).unwrap();
    only_static_keys_and_numbers(&serialized);
    let execution: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/execution-v1.json")).unwrap();
    assert!(!text.contains(execution["grant_token"].as_str().unwrap()));
    assert!(!text.contains(execution["allocation_token"].as_str().unwrap()));
    assert!(!text.contains("key:credential-1"));
    assert!(!text.contains("grant-1"));
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((after.mtime(), after.mtime_nsec()), mtime);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(entries(), before_entries);
    assert!(!directory.path().join("journal.next").exists());
    assert!(matches!(
        Journal::open(directory.path(), Role::Authority("authority".into())),
        Err(Error::Ownership)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn projection_uses_the_exact_qualified_lower_bound() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    let mut initial: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/authority-compacted-v1.json"
    ))
    .unwrap();
    initial["clock_floor"] = serde_json::json!(100);
    std::fs::write(&path, serde_json::to_vec(&initial).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (state, _) = read_state_size(&path).unwrap().unwrap();
    let (writer_projection, _) = compact_authority(
        &state,
        Clock {
            now: 100,
            uncertainty: 3,
        },
    )
    .unwrap();
    let report = project_capacity(&path, 97_000).unwrap();
    assert_eq!(report.bytes_reclaimed, 0);
    assert_eq!(
        report.bytes_after,
        serde_json::to_vec(&writer_projection).unwrap().len()
    );
}

#[test]
fn projection_rejects_an_unsafe_lower_bound() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    std::fs::write(
        &path,
        include_bytes!("../../../tests/fixtures/authority-compacted-v1.json"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        project_capacity(&path, MAX_SAFE_INTEGER + 1),
        Err(Error::Binding)
    ));
}

#[test]
fn projection_rejects_unsupported_journal_versions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    let mut initial: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/authority-compacted-v1.json"
    ))
    .unwrap();
    initial["v"] = serde_json::json!(2);
    let bytes = serde_json::to_vec(&initial).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        project_capacity(&path, 1_999_000),
        Err(Error::Binding)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
