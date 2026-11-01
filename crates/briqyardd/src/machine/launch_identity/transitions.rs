//! Write-ahead evidence for one record-first/reader-second launch transition.
//! Assignment and public unbound recovery remain separate, disabled integration gates.
use super::*;
use sha2::{Digest, Sha256};
const TRANSITIONS: &str = "launch-transitions";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    schema: u8,
    machine: String,
    identity: LaunchIdentity,
    before_record: String,
    after_record: String,
    after_origin: templates::CloneOrigin,
    before_reader: templates::CloneReader,
    after_reader: templates::CloneReader,
}

// Error/exit/accounting observations may complete after a failed persistence step.
// Ownership, workload, boot evidence and complete binding remain in the fingerprint.
fn record_fingerprint(record: &Record) -> Result<String> {
    let mut value = serde_json::to_value(record)?;
    let object = value
        .as_object_mut()
        .context("launch record must be an object")?;
    for name in [
        "state",
        "stopped_reason",
        "exit",
        "error",
        "error_reason",
        "pid",
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
    ] {
        object.remove(name);
    }
    if let Some(origin) = object
        .get_mut("clone_origin")
        .and_then(|origin| origin.as_object_mut())
    {
        origin.remove("mapping_exited");
    }
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
}

impl Transition {
    fn new(
        manager: &Manager,
        target: &Record,
        before_reader: templates::CloneReader,
        next: templates::CloneStage,
    ) -> Result<Self> {
        let before = manager
            .inner
            .store
            .get::<Record>("machines", &target.id)?
            .context("launch transition source record missing")?;
        let identity = target
            .launch_identity
            .clone()
            .context("launch identity missing")?;
        anyhow::ensure!(
            before.launch_identity.as_ref() == Some(&identity),
            "launch transition cannot change host identity"
        );
        manager.validate_launch_record(&before)?;
        provenance::check_pair(&before, Some(&before_reader))?;
        let after_origin = target
            .clone_origin
            .clone()
            .context("launch origin missing")?;
        anyhow::ensure!(
            after_origin.stage == next,
            "launch transition target stage differs"
        );
        let mut after_reader = before_reader.clone();
        after_reader.stage = next;
        provenance::check_pair(target, Some(&after_reader))?;
        let after_record = record_fingerprint(target)?;
        let mut projected = before.clone();
        projected.clone_origin = Some(after_origin.clone());
        anyhow::ensure!(
            record_fingerprint(&projected)? == after_record,
            "stage transition cannot change ownership, workload or boot evidence"
        );
        Ok(Self {
            schema: 1,
            machine: target.id.clone(),
            identity,
            before_record: record_fingerprint(&before)?,
            after_record,
            after_origin,
            before_reader,
            after_reader,
        })
    }

    fn publish(&self, manager: &Manager) -> Result<()> {
        anyhow::ensure!(
            manager
                .inner
                .store
                .get::<Transition>(TRANSITIONS, &self.machine)?
                .is_none(),
            "unsettled launch transition requires reconciliation"
        );
        manager
            .inner
            .store
            .put_durable(TRANSITIONS, &self.machine, self)
    }

    fn reconcile(&self, manager: &Manager) -> Result<()> {
        anyhow::ensure!(
            self.schema == 1 && api::valid_id(&self.machine),
            "unsupported launch transition identity"
        );
        let hold = manager
            .inner
            .store
            .get::<Hold>(HOLDS, &self.machine)?
            .context("launch transition source hold missing")?;
        anyhow::ensure!(
            hold.machine == self.machine && hold.identity == self.identity,
            "launch transition disagrees with source allocation"
        );
        self.identity.check(&manager.inner.cfg)?;
        let mut current = manager
            .inner
            .store
            .get::<Record>("machines", &self.machine)?
            .context("launch transition has no record; source allocation and backing retained")?;
        anyhow::ensure!(
            current.id == self.machine && current.launch_identity.as_ref() == Some(&self.identity),
            "launch transition record identity conflict"
        );
        let fingerprint = record_fingerprint(&current)?;
        let before = fingerprint == self.before_record;
        anyhow::ensure!(
            before || fingerprint == self.after_record,
            "launch transition record differs from durable evidence"
        );
        let reader = manager
            .inner
            .store
            .get::<templates::CloneReader>(templates::READERS, &self.machine)?
            .context("launch transition reader missing; backing retained")?;
        anyhow::ensure!(
            reader == self.before_reader || reader == self.after_reader,
            "launch transition reader differs from durable evidence"
        );
        anyhow::ensure!(
            !before || reader == self.before_reader,
            "reader advanced before its owning record"
        );
        if before {
            let exited = current
                .clone_origin
                .as_ref()
                .is_some_and(|origin| origin.mapping_exited);
            let mut origin = self.after_origin.clone();
            origin.mapping_exited |= exited;
            current.clone_origin = Some(origin);
            anyhow::ensure!(
                record_fingerprint(&current)? == self.after_record,
                "launch transition cannot reconstruct exact target control state"
            );
            provenance::check_pair(&current, Some(&self.after_reader))?;
            manager
                .inner
                .store
                .put_durable("machines", &self.machine, &current)?;
        }
        let mut expected_origin = self.after_origin.clone();
        expected_origin.mapping_exited = current
            .clone_origin
            .as_ref()
            .context("launch transition current origin missing")?
            .mapping_exited;
        anyhow::ensure!(
            serde_json::to_value(&expected_origin)? == serde_json::to_value(&current.clone_origin)?,
            "launch transition target origin differs from durable evidence"
        );
        provenance::check_pair(&current, Some(&self.after_reader))?;
        manager
            .inner
            .store
            .put_durable(templates::READERS, &self.machine, &self.after_reader)?;
        manager
            .inner
            .store
            .delete_durable(TRANSITIONS, &self.machine)
    }
}

impl Manager {
    pub(in crate::machine) fn persist_launch_transition(
        &self,
        entry: &Entry,
        reader: templates::CloneReader,
        next: templates::CloneStage,
    ) -> Result<()> {
        let removed = entry.removed.lock().unwrap();
        anyhow::ensure!(!*removed, "launch transition record was removed");
        let target = entry.snapshot();
        let transition = Transition::new(self, &target, reader, next)?;
        transition.publish(self)?;
        self.inner
            .store
            .put_durable("machines", &target.id, &target)?;
        self.inner
            .store
            .put_durable(templates::READERS, &target.id, &transition.after_reader)?;
        self.inner.store.delete_durable(TRANSITIONS, &target.id)
    }

    /// Called before exact hold/provenance validation and all external startup effects.
    pub(in crate::machine) fn recover_launch_transitions(&self) -> Result<()> {
        for transition in self.inner.store.list::<Transition>(TRANSITIONS)? {
            transition.reconcile(self)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
