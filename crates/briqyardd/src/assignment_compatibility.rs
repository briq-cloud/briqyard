//! Read-only downgrade inspection and a permanent, crash-durable assignment floor.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

pub const EXECUTION_CAPABILITY: &[u8] = b"scoped-execution-v1\n";
pub const CAPABILITY: &[u8] = b"destination-assignment-v1\n";
pub const RUN_CAPABILITY: &[u8] = b"assigned-run-v1\n";
pub const UPDATE_CAPABILITY: &[u8] = b"assigned-update-v3\n";
pub const LIFECYCLE_CAPABILITY: &[u8] = b"assigned-run-lifecycle-v1\n";
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Requirement {
    None,
    Assignment,
    AssignedRun,
    AssignedRunLifecycle,
    AssignedUpdates,
    ScopedExecution,
}
pub const RUN_COLLECTIONS: [&str; 3] = [
    "assigned-run-intents",
    "assigned-runs",
    "assigned-run-readers",
];
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
fn floor(root: &Path) -> Result<Requirement> {
    let Some(bytes) = read(&root.join("meta").join(FLOOR))? else {
        return Ok(Requirement::None);
    };
    let value: Floor =
        serde_json::from_slice(&bytes).context("invalid assignment compatibility floor")?;
    match (value.schema, value.protocol.as_str()) {
        (1, "destination-assignment-v1") => Ok(Requirement::Assignment),
        (2, "assigned-run-v1") => Ok(Requirement::AssignedRun),
        (3, "assigned-run-lifecycle-v1") => Ok(Requirement::AssignedRunLifecycle),
        (4, "assigned-update-v3") => Ok(Requirement::AssignedUpdates),
        (5, "scoped-execution-v1") => Ok(Requirement::ScopedExecution),
        _ => anyhow::bail!("unsupported assignment compatibility floor"),
    }
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
    Ok(requirement(root)? != Requirement::None)
}
pub fn requirement(root: &Path) -> Result<Requirement> {
    let mut required = floor(root)?;
    for kind in ["unbound-assignments", "unbound-requests", "machines"]
        .into_iter()
        .chain(RUN_COLLECTIONS)
        .chain([
            "assigned-run-updates",
            "execution-idle-protection",
            "execution-namespace-fence",
        ])
    {
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
            required = required.max(record_requirement(kind, &value)?);
        }
    }
    Ok(required)
}
/// Inspect both committed evidence and a pending write using the same exact schemas.
pub fn record_requirement(kind: &str, value: &Value) -> Result<Requirement> {
    if matches!(
        kind,
        "execution-idle-protection" | "execution-namespace-fence"
    ) {
        return Ok(Requirement::ScopedExecution);
    }
    if kind == "machines" {
        if let Some(run) = value.get("assigned_run").filter(|v| !v.is_null()) {
            let requirement = run_schema(run)?;
            anyhow::ensure!(
                run.as_object().is_some_and(|fields| fields.len() == 3)
                    && run["sequence"].as_u64().is_some_and(|value| value > 0)
                    && (matches!(run["phase"].as_str(), Some("reserved" | "observed"))
                        || (requirement == Requirement::AssignedRunLifecycle
                            && run["phase"].as_str() == Some("settled"))),
                "unsupported assigned run record link"
            );
            return Ok(requirement);
        }
        return Ok(if assigned(value) {
            Requirement::Assignment
        } else {
            Requirement::None
        });
    }
    if kind == "assigned-run-updates" {
        return match value["schema"].as_u64() {
            Some(1 | 2) => Ok(Requirement::AssignedRunLifecycle),
            Some(3) => Ok(Requirement::AssignedUpdates),
            _ => anyhow::bail!("unsupported assigned update evidence schema"),
        };
    }
    if RUN_COLLECTIONS.contains(&kind) {
        return run_schema(value);
    }
    Ok(
        if matches!(kind, "unbound-assignments" | "unbound-requests") {
            Requirement::Assignment
        } else {
            Requirement::None
        },
    )
}
fn run_schema(value: &Value) -> Result<Requirement> {
    match value["schema"].as_u64() {
        Some(1) => Ok(Requirement::AssignedRun),
        Some(3) => Ok(Requirement::AssignedRunLifecycle),
        _ => anyhow::bail!("unsupported assigned run evidence schema"),
    }
}
/// Must complete before any intent, receipt or assigned machine becomes visible.
/// The lock also prevents concurrent writers sharing the store's temporary path.
pub fn ensure_floor(root: &Path) -> Result<()> {
    ensure_floor_at(root, Requirement::Assignment)
}
pub fn ensure_run_floor(root: &Path) -> Result<()> {
    ensure_floor_at(root, Requirement::AssignedRun)
}
pub fn ensure_assigned_run_lifecycle_floor(root: &Path) -> Result<()> {
    ensure_floor_at(root, Requirement::AssignedRunLifecycle)
}
pub fn ensure_floor_at(root: &Path, minimum: Requirement) -> Result<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = LOCK.lock().unwrap();
    let meta = root.join("meta");
    let existing = floor(root)?;
    // A missing marker is not a downgrade when durable run evidence survived it.
    let minimum = if existing == Requirement::None {
        minimum.max(requirement(root)?)
    } else {
        minimum
    };
    if existing < minimum {
        crate::store::private_dir(&meta)?;
        crate::store::write_private(
            &meta.join(FLOOR),
            &serde_json::to_vec(&Floor {
                schema: match minimum {
                    Requirement::ScopedExecution => 5,
                    Requirement::AssignedUpdates => 4,
                    Requirement::AssignedRunLifecycle => 3,
                    Requirement::AssignedRun => 2,
                    _ => 1,
                },
                protocol: match minimum {
                    Requirement::ScopedExecution => "scoped-execution-v1",
                    Requirement::AssignedUpdates => "assigned-update-v3",
                    Requirement::AssignedRunLifecycle => "assigned-run-lifecycle-v1",
                    Requirement::AssignedRun => "assigned-run-v1",
                    _ => "destination-assignment-v1",
                }
                .into(),
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
    probe(executable, "assignment-capabilities", CAPABILITY, deadline).await
}
pub async fn check_required_candidate(
    root: &Path,
    executable: &Path,
    deadline: tokio::time::Instant,
) -> Result<()> {
    // Inspection still fails closed, but a sample cannot authorize a weaker binary:
    // an admitted writer or a daemon restart may raise the floor before replacement.
    requirement(root)?;
    check_candidate(executable, deadline).await?;
    probe(
        executable,
        "assigned-run-capabilities",
        RUN_CAPABILITY,
        deadline,
    )
    .await?;
    probe(
        executable,
        "assigned-run-lifecycle-capabilities",
        LIFECYCLE_CAPABILITY,
        deadline,
    )
    .await?;
    probe(
        executable,
        "assigned-update-capabilities",
        UPDATE_CAPABILITY,
        deadline,
    )
    .await?;
    probe(
        executable,
        "scoped-execution-capabilities",
        EXECUTION_CAPABILITY,
        deadline,
    )
    .await?;
    Ok(())
}
async fn probe(
    executable: &Path,
    command: &str,
    expected: &[u8],
    deadline: tokio::time::Instant,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut child = tokio::process::Command::new(executable)
        .arg(command)
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
            bytes == expected,
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
    #[test]
    fn scoped_floor_precedes_protection_and_reconstructs_without_config() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        store
            .put_durable(
                "execution-idle-protection",
                "accepted",
                &serde_json::json!({"admission":"accepted"}),
            )
            .unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::ScopedExecution);
        let bytes = std::fs::read(dir.path().join("meta").join(FLOOR)).unwrap();
        let old: Floor = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(old.schema, 5);
        // Previous binaries' exhaustive schemas 1..4 refuse this same marker.
        assert!(!(1..=4).contains(&old.schema));
        std::fs::remove_file(dir.path().join("meta").join(FLOOR)).unwrap();
        assert_eq!(
            requirement(dir.path()).unwrap(),
            Requirement::ScopedExecution
        );
        drop(store);
        crate::store::Store::open(dir.path()).unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::ScopedExecution);
    }
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
    #[tokio::test]
    async fn assigned_run_floor_is_durable_monotonic_and_rejects_old_candidate() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        store
            .put(
                "unbound-requests",
                "consumed",
                &serde_json::json!({"schema":1}),
            )
            .unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::Assignment);
        store
            .put_durable(
                "assigned-run-intents",
                "run",
                &serde_json::json!({"schema":1}),
            )
            .unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::AssignedRun);
        store
            .put(
                "unbound-requests",
                "again",
                &serde_json::json!({"schema":1}),
            )
            .unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::AssignedRun);
        let executable = dir.path().join("old-candidate");
        std::fs::write(&executable, "#!/bin/sh\n[ \"$1\" = assignment-capabilities ] || exit 2\nprintf 'destination-assignment-v1\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = check_required_candidate(
            dir.path(),
            &executable,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
        // The exact schema1 reader rejects schema2, rather than treating it as v1.
        let old: Floor =
            serde_json::from_slice(&std::fs::read(dir.path().join("meta").join(FLOOR)).unwrap())
                .unwrap();
        assert!(!(old.schema == 1 && old.protocol == "destination-assignment-v1"));
        std::fs::remove_file(dir.path().join("meta").join(FLOOR)).unwrap();
        assert_eq!(requirement(dir.path()).unwrap(), Requirement::AssignedRun);
        store
            .put(
                "unbound-requests",
                "after-marker-loss",
                &serde_json::json!({"schema":1}),
            )
            .unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::AssignedRun);
        crate::store::Store::open(dir.path()).unwrap();
        assert_eq!(floor(dir.path()).unwrap(), Requirement::AssignedRun);
    }
    #[test]
    fn lifecycle_floor_survives_marker_loss_deletion_and_ordinary_writes() {
        for kind in RUN_COLLECTIONS.into_iter().chain(["machines"]) {
            let dir = tempfile::tempdir().unwrap();
            let store = crate::store::Store::open(dir.path()).unwrap();
            let value = if kind == "machines" {
                serde_json::json!({"assigned_run":{"schema":3,"sequence":1,"phase":"settled"}})
            } else {
                serde_json::json!({"schema":3})
            };
            store.put_durable(kind, "terminal", &value).unwrap();
            assert_eq!(
                floor(dir.path()).unwrap(),
                Requirement::AssignedRunLifecycle
            );
            store
                .put(
                    "unbound-requests",
                    "ordinary",
                    &serde_json::json!({"schema":1}),
                )
                .unwrap();
            assert_eq!(
                floor(dir.path()).unwrap(),
                Requirement::AssignedRunLifecycle
            );
            std::fs::remove_file(dir.path().join("meta").join(FLOOR)).unwrap();
            assert_eq!(
                requirement(dir.path()).unwrap(),
                Requirement::AssignedRunLifecycle
            );
            store.delete_durable(kind, "terminal").unwrap();
            assert_eq!(
                requirement(dir.path()).unwrap(),
                Requirement::AssignedRunLifecycle
            );
            crate::store::Store::open(dir.path()).unwrap();
            assert_eq!(
                floor(dir.path()).unwrap(),
                Requirement::AssignedRunLifecycle
            );
        }
    }
    #[test]
    fn replacing_last_lifecycle_machine_link_restores_lost_floor_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        store
            .put(
                "machines",
                "terminal",
                &serde_json::json!({
                    "assigned_run":{"schema":3,"sequence":1,"phase":"settled"}
                }),
            )
            .unwrap();
        std::fs::remove_file(dir.path().join("meta").join(FLOOR)).unwrap();
        store
            .put(
                "machines",
                "terminal",
                &serde_json::json!({"assigned_run":null}),
            )
            .unwrap();
        assert_eq!(
            requirement(dir.path()).unwrap(),
            Requirement::AssignedRunLifecycle
        );
    }
    #[test]
    fn lifecycle_inspection_never_downgrades_and_unknown_evidence_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        store.ensure_assigned_run_lifecycle_floor().unwrap();
        store
            .put(
                "machines",
                "old",
                &serde_json::json!({
                    "assigned_run":{"schema":1,"sequence":1,"phase":"observed"}
                }),
            )
            .unwrap();
        assert_eq!(
            requirement(dir.path()).unwrap(),
            Requirement::AssignedRunLifecycle
        );
        for kind in RUN_COLLECTIONS.into_iter().chain(["machines"]) {
            let path = store.dir(kind).join("unknown.json");
            let value = if kind == "machines" {
                serde_json::json!({"assigned_run":{"schema":9,"sequence":1,"phase":"settled"}})
            } else {
                serde_json::json!({"schema":9})
            };
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(requirement(dir.path()).is_err());
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn schema_three_update_floor_survives_journal_deletion_and_marker_loss() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        store
            .put_durable(
                "assigned-run-updates",
                "machine",
                &serde_json::json!({"schema":3}),
            )
            .unwrap();
        assert_eq!(
            requirement(dir.path()).unwrap(),
            Requirement::AssignedUpdates
        );
        std::fs::remove_file(dir.path().join("meta").join(FLOOR)).unwrap();
        assert_eq!(
            requirement(dir.path()).unwrap(),
            Requirement::AssignedUpdates
        );
        store
            .delete_durable("assigned-run-updates", "machine")
            .unwrap();
        assert_eq!(
            requirement(dir.path()).unwrap(),
            Requirement::AssignedUpdates
        );
    }

    #[test]
    fn lifecycle_floor_failure_forbids_first_incompatible_intent() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        std::fs::create_dir(dir.path().join("meta").join(FLOOR)).unwrap();
        assert!(store.ensure_assigned_run_lifecycle_floor().is_err());
        assert!(store
            .put_durable(
                "assigned-run-intents",
                "first",
                &serde_json::json!({"schema":3})
            )
            .is_err());
        assert!(!store
            .dir("assigned-run-intents")
            .join("first.json")
            .exists());
    }
    #[tokio::test]
    async fn empty_state_requires_all_four_exact_successful_bounded_probes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("candidate");
        for (body, accepted) in [
            ("exit 2", false),
            ("printf 'assigned-run-lifecycle-v1\\nextra'", false),
            ("printf 'assigned-run-lifecycle-v1\\n'; exit 1", false),
            ("sleep 2", false),
            ("printf 'assigned-run-lifecycle-v1\\n'", true),
        ] {
            std::fs::write(&executable, format!("#!/bin/sh\ncase $1 in\nassignment-capabilities) printf 'destination-assignment-v1\\n';;\nassigned-run-capabilities) printf 'assigned-run-v1\\n';;\nassigned-run-lifecycle-capabilities) {body};;\nassigned-update-capabilities) printf 'assigned-update-v3\\n';;\nscoped-execution-capabilities) printf 'scoped-execution-v1\\n';;\n*) exit 2;;\nesac\n")).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let result = check_required_candidate(
                dir.path(),
                &executable,
                tokio::time::Instant::now() + std::time::Duration::from_millis(150),
            )
            .await;
            assert_eq!(result.is_ok(), accepted, "{body}: {result:?}");
        }
        // A lifecycle-only answer also cannot bypass either prior protocol.
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'assigned-run-lifecycle-v1\\n'\n",
        )
        .unwrap();
        assert!(check_required_candidate(
            dir.path(),
            &executable,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1)
        )
        .await
        .is_err());
    }
    #[test]
    fn corrupt_floor_prevents_any_run_publication() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        std::fs::write(
            dir.path().join("meta").join(FLOOR),
            b"{\"schema\":3,\"protocol\":\"assigned-run-v1\"}",
        )
        .unwrap();
        assert!(store
            .put("assigned-runs", "machine", &serde_json::json!({"schema":1}))
            .is_err());
        assert!(!store.dir("assigned-runs").join("machine.json").exists());
        std::fs::remove_file(dir.path().join("meta").join(FLOOR)).unwrap();
        std::fs::write(
            store.dir("assigned-runs").join("unknown.json"),
            b"{\"schema\":2}",
        )
        .unwrap();
        assert!(requirement(dir.path()).is_err());
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
