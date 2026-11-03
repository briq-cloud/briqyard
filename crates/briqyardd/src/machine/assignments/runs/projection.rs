//! Assigned-run authority is independent of advisory machine observations.
//! This does not change the creation/stage transition fingerprint contract.
use super::*;

const ADVISORY: &[&str] = &[
    "state",
    "stopped_reason",
    "exit",
    "error",
    "error_reason",
    "restarts",
    "recent_restarts",
    "restarting_at",
    "boots",
    "updated_at",
    "state_changed_at",
    "started_at",
    "stopped_at",
    "last_used_at",
    "console_offset",
    "version",
    "backup_bytes",
    "init_version",
    "pending_since",
];

pub(super) fn authority(record: &Record) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(record)?;
    let object = value
        .as_object_mut()
        .context("run record must be an object")?;
    for name in ADVISORY {
        object.remove(*name);
    }
    Ok(value)
}

pub(super) fn fingerprint(record: &Record) -> Result<String> {
    Ok(sha(&serde_json::to_vec(&authority(record)?)?))
}

/// Target owns all authority; latest owns only the explicitly advisory observations.
/// The caller must separately match latest authority to the journal's predecessor/target.
pub(super) fn preserve_advisory(target: &Record, latest: &Record) -> Result<Record> {
    let mut value = serde_json::to_value(target)?;
    let latest = serde_json::to_value(latest)?;
    let object = value
        .as_object_mut()
        .context("run record must be an object")?;
    for name in ADVISORY {
        match latest.get(*name) {
            Some(observation) => {
                object.insert((*name).into(), observation.clone());
            }
            None => {
                object.remove(*name);
            }
        }
    }
    let merged = serde_json::from_value(value)?;
    anyhow::ensure!(
        authority(&merged)? == authority(target)?,
        "advisory merge changed run authority"
    );
    Ok(merged)
}

impl Current {
    pub(super) fn record_fingerprint(&self, record: &Record) -> Result<String> {
        if self.schema == 1 {
            launch_identity::record_fingerprint(record)
        } else {
            fingerprint(record)
        }
    }
    pub(super) fn authority_sha256(&self) -> Result<String> {
        // Schema1 persisted struct field-order bytes at 545db521, not Value's sorted map.
        // Box wrappers are serde-transparent; later optional fields omit absent values.
        if self.schema == 1 {
            return Ok(sha(&serde_json::to_vec(self)?));
        }
        let mut value = serde_json::to_value(self)?;
        if self.schema == 3 {
            value["prior"] = authority(&self.prior)?;
            value["target"] = authority(&self.target)?;
        }
        Ok(sha(&serde_json::to_vec(&value)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_authority_includes_pid_sequence_workload_and_backing_lineage() {
        let record = crate::machine::tests::record();
        let before = fingerprint(&record).unwrap();
        let mut changed = record.clone();
        changed.pid += 1;
        assert_ne!(before, fingerprint(&changed).unwrap());
        assert_eq!(
            launch_identity::record_fingerprint(&record).unwrap(),
            launch_identity::record_fingerprint(&changed).unwrap(),
            "creation fingerprint contract is unchanged"
        );
        changed = record.clone();
        changed.assigned_run = Some(RunRef {
            schema: 1,
            sequence: 2,
            phase: Phase::Reserved,
        });
        assert_ne!(before, fingerprint(&changed).unwrap());
        changed = record.clone();
        changed.env.insert("control".into(), "changed".into());
        assert_ne!(before, fingerprint(&changed).unwrap());
        changed = record.clone();
        changed.suspended = !changed.suspended;
        assert_ne!(before, fingerprint(&changed).unwrap());
        changed = record.clone();
        changed.rest.insert("future_authority".into(), true.into());
        assert_ne!(
            before,
            fingerprint(&changed).unwrap(),
            "unknown future controls fail closed"
        );
    }

    #[test]
    fn advisory_observations_do_not_change_authority_and_latest_values_survive_projection() {
        let record = crate::machine::tests::record();
        let mut latest = record.clone();
        latest.state = state::RUNNING.into();
        latest.error = "latest observation".into();
        latest.boots += 1;
        latest.version += 1;
        latest.updated_at += chrono::Duration::seconds(3);
        latest.init_version = "new observed init version".into();
        assert_eq!(fingerprint(&record).unwrap(), fingerprint(&latest).unwrap());
        let mut target = record.clone();
        target.pid += 1;
        let merged = preserve_advisory(&target, &latest).unwrap();
        assert_eq!(merged.pid, target.pid);
        assert_eq!(merged.state, latest.state);
        assert_eq!(merged.error, latest.error);
        assert_eq!(merged.boots, latest.boots);
        assert_eq!(merged.version, latest.version);
        assert_eq!(merged.updated_at, latest.updated_at);
        assert_eq!(merged.init_version, latest.init_version);
        assert_eq!(fingerprint(&merged).unwrap(), fingerprint(&target).unwrap());
    }
}
