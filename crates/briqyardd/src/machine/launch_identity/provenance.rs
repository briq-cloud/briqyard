//! Frozen template provenance is independent of mutable tenant ownership.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TemplateLaunch {
    source_machine: String,
    snapshot: String,
    artifact_sha256: String,
}

impl TemplateLaunch {
    pub(super) fn from_origin(origin: &templates::CloneOrigin) -> Result<Self> {
        anyhow::ensure!(
            origin.artifact.profile == guest::SANDBOX_READY_V1,
            "launch provenance requires the pristine sandbox profile"
        );
        Ok(Self {
            source_machine: origin.source_machine.clone(),
            snapshot: origin.snapshot.clone(),
            artifact_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&origin.artifact)?)),
        })
    }
}

impl Manager {
    pub(super) fn validate_launch_provenance(&self, record: &Record) -> Result<()> {
        if record.launch_identity.is_none() {
            return Ok(());
        }
        let reader = self
            .inner
            .store
            .get::<templates::CloneReader>(templates::READERS, &record.id)?;
        check_pair(record, reader.as_ref())
    }

    pub(in crate::machine) fn verify_live_launch(
        &self,
        entry: &Entry,
        live: &fc::Vm,
    ) -> Result<()> {
        let record = entry.snapshot();
        let Some(identity) = &record.launch_identity else {
            return Ok(());
        };
        self.validate_launch_record(&record)?;
        let saved = record
            .boot_incarnation
            .as_ref()
            .context("live launch incarnation missing")?;
        anyhow::ensure!(
            !*live.exited.borrow()
                && live.pid == record.pid
                && live.incarnation.as_ref() == Some(saved)
                && live.boot_identity == record.boot_identity
                && self
                    .inner
                    .vmm
                    .verify_process(&record.id, saved, identity.uid, identity.gid),
            "actual launch process, incarnation or credentials are unconfirmed"
        );
        Ok(())
    }

    /// Called before guest configuration, network publication or readiness. Failure is
    /// handled by the normal owned launch failure path, which settles the VMM first.
    pub(in crate::machine) fn persist_launch_provenance(
        &self,
        e: &Entry,
        live: &fc::Vm,
    ) -> Result<()> {
        let record = e.snapshot();
        if record.launch_identity.is_none() {
            return Ok(());
        }
        anyhow::ensure!(
            live.resumed
                && e.identity_trusted.load(Relaxed)
                && live.incarnation.is_some()
                && live.incarnation == record.boot_incarnation
                && live.pid == record.pid
                && live.boot_identity == record.boot_identity,
            "launch process provenance is unconfirmed"
        );
        self.verify_live_launch(e, live)?;
        self.inner
            .store
            .put_durable("machines", &record.id, &record)
    }
}

pub(in crate::machine) fn check_pair(
    record: &Record,
    reader: Option<&templates::CloneReader>,
) -> Result<()> {
    let Some(identity) = &record.launch_identity else {
        return Ok(());
    };
    let Some(expected) = &identity.template else {
        anyhow::ensure!(
            !requires_identity(record),
            "pristine slot launch template binding missing"
        );
        return Ok(());
    };
    let origin = record
        .clone_origin
        .as_ref()
        .context("launch clone origin missing")?;
    anyhow::ensure!(
        &TemplateLaunch::from_origin(origin)? == expected,
        "launch template provenance changed"
    );
    if let Some(reader) = reader {
        anyhow::ensure!(
            reader.destination == record.id
                && reader.namespace == record.namespace
                && reader.source_machine == origin.source_machine
                && reader.snapshot == origin.snapshot
                && reader.generation == origin.artifact.generation
                && reader.stage == origin.stage,
            "launch reader and record provenance disagree"
        );
    } else {
        anyhow::ensure!(
            record.state == state::DESTROYING && origin.mapping_exited,
            "launch clone reader missing; backing and source allocation retained"
        );
    }
    if record.pid > 0 {
        let incarnation = record
            .boot_incarnation
            .as_ref()
            .context("launch incarnation missing")?;
        anyhow::ensure!(
            incarnation.pid == record.pid
                && incarnation.start_ticks > 0
                && fc::valid_host_boot_id(&incarnation.host_boot_id)
                && origin.launch_host_boot_id.as_deref() == Some(incarnation.host_boot_id.as_str())
                && record.boot_identity.as_ref() == Some(&origin.artifact.boot_identity),
            "launch process or boot identity disagrees with frozen template"
        );
    } else {
        anyhow::ensure!(
            !matches!(
                origin.stage,
                templates::CloneStage::Paused | templates::CloneStage::UnboundPaused
            ) || origin.mapping_exited,
            "paused launch is missing its bound process"
        );
    }
    Ok(())
}
