//! Read-only downgrade inspection and a permanent, crash-durable assignment floor.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

pub const CAPABILITY: &[u8] = b"destination-assignment-v1\n";
const FLOOR: &str = "required-assignment-protocol.json";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    schema: u8,
    protocol: String,
}
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                std::fs::symlink_metadata(path).is_err(),
                "dangling assignment state path"
            );
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}
fn floor(root: &Path) -> Result<bool> {
    let Some(bytes) = read(&root.join("meta").join(FLOOR))? else {
        return Ok(false);
    };
    let value: Floor =
        serde_json::from_slice(&bytes).context("invalid assignment compatibility floor")?;
    anyhow::ensure!(
        value.schema == 1 && value.protocol == "destination-assignment-v1",
        "unsupported assignment compatibility floor"
    );
    Ok(true)
}
pub fn assigned(record: &Value) -> bool {
    record.get("launch_identity").is_some_and(|v| !v.is_null())
        && record
            .pointer("/warm_slot/claimed")
            .is_some_and(|v| !v.is_null())
}
/// Never opens Store or changes permissions. Missing state is safe; unreadable or
/// malformed state is not equivalent to empty state, including when a floor exists.
pub fn required(root: &Path) -> Result<bool> {
    let mut required = floor(root)?;
    for kind in ["unbound-assignments", "unbound-requests", "machines"] {
        let entries = match std::fs::read_dir(root.join(kind)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                anyhow::ensure!(
                    std::fs::symlink_metadata(root.join(kind)).is_err(),
                    "dangling assignment state directory"
                );
                continue;
            }
            Err(error) => return Err(error).context("inspect assignment state directory"),
        };
        for entry in entries {
            let entry = entry?;
            // Atomic store temporary files are not committed records.
            if entry.path().extension().is_none_or(|s| s != "json") {
                continue;
            }
            let bytes = std::fs::read(entry.path())?;
            let value: Value =
                serde_json::from_slice(&bytes).context("invalid assignment state JSON")?;
            anyhow::ensure!(value.is_object(), "invalid assignment state record");
            if kind == "machines" {
                required |= assigned(&value);
            } else {
                required = true;
            }
        }
    }
    Ok(required)
}
/// Must complete before any intent, receipt or assigned machine becomes visible.
/// The lock also prevents concurrent writers sharing the store's temporary path.
pub fn ensure_floor(root: &Path) -> Result<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = LOCK.lock().unwrap();
    let meta = root.join("meta");
    if !floor(root)? {
        crate::store::private_dir(&meta)?;
        crate::store::write_private(
            &meta.join(FLOOR),
            &serde_json::to_vec(&Floor {
                schema: 1,
                protocol: "destination-assignment-v1".into(),
            })?,
        )?;
    }
    std::fs::File::open(meta.join(FLOOR))?.sync_all()?;
    std::fs::File::open(&meta)?.sync_all()?;
    std::fs::File::open(root)?.sync_all()?;
    if let Some(parent) = root.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
/// Bounded output and lifetime even for an unknown/hostile candidate command.
pub async fn check_candidate(executable: &Path, deadline: tokio::time::Instant) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut child = tokio::process::Command::new(executable)
        .arg("assignment-capabilities")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .context("candidate stdout missing")?
        .take(128);
    let probe = async {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await?;
        anyhow::ensure!(
            bytes == CAPABILITY,
            "replacement cannot preserve destination assignments"
        );
        anyhow::ensure!(
            child.wait().await?.success(),
            "assignment compatibility command failed"
        );
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout_at(deadline, probe)
        .await
        .context("assignment compatibility probe timed out")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn candidate_must_exit_successfully_with_exact_bounded_capability() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("candidate");
        for (body, accepted) in [
            ("printf 'destination-assignment-v1\\n'", true),
            ("printf 'destination-assignment-v1\\n'; exit 1", false),
            ("printf 'destination-assignment-v1\\nextra'", false),
            ("exit 2", false),
            ("while :; do printf 0123456789; done", false),
        ] {
            std::fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let result = check_candidate(
                &executable,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.is_ok(), accepted, "{body}: {result:?}");
        }
    }
    #[test]
    fn migration_is_monotonic_and_inspection_is_pure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state");
        assert!(!required(&root).unwrap());
        assert!(!root.exists());
        let store = crate::store::Store::open(&root).unwrap();
        store
            .put(
                "unbound-requests",
                "request",
                &serde_json::json!({"schema":1}),
            )
            .unwrap();
        assert!(required(&root).unwrap());
        // Machine destruction and journal settlement cannot unconsume a request.
        assert!(store.delete_durable("unbound-requests", "request").is_err());
        assert!(store
            .delete("meta", "required-assignment-protocol")
            .is_err());
        store
            .put(
                "machines",
                "assigned",
                &serde_json::json!({
                    "launch_identity": {}, "warm_slot": {"claimed": "request"}
                }),
            )
            .unwrap();
        store.delete_durable("machines", "assigned").unwrap();
        assert!(store.dir("unbound-requests").join("request.json").exists());
        assert!(required(&root).unwrap());
    }
    #[test]
    fn corrupt_or_unwritable_floor_prevents_first_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        let floor = dir.path().join("meta").join(FLOOR);
        std::fs::write(&floor, b"{\"schema\":1}").unwrap();
        assert!(store
            .put("unbound-assignments", "intent", &serde_json::json!({}))
            .is_err());
        assert!(!store
            .dir("unbound-assignments")
            .join("intent.json")
            .exists());
        assert!(required(dir.path()).is_err());
        std::fs::remove_file(&floor).unwrap();
        std::fs::create_dir(&floor).unwrap();
        assert!(store
            .put("unbound-requests", "receipt", &serde_json::json!({}))
            .is_err());
        assert!(!store.dir("unbound-requests").join("receipt.json").exists());
    }
    #[test]
    fn startup_migrates_evidence_before_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("unbound-requests")).unwrap();
        std::fs::write(
            dir.path().join("unbound-requests/r.json"),
            b"{\"schema\":1}",
        )
        .unwrap();
        crate::store::Store::open(dir.path()).unwrap();
        assert!(dir.path().join("meta").join(FLOOR).is_file());
    }
}
