//! Private continuation authority. Observation never authorizes ordinary publication.
use super::*;
use rand::RngCore;
mod adoption;
mod launch;
mod lifecycle;
mod model;
#[allow(dead_code)]
// Pure projection; durable run transitions are wired with the terminal capability floor.
mod projection;
mod publication;
mod recovery;
mod startup;
mod terminal;
#[cfg(test)]
mod tests;
mod updates;
const INTENTS: &str = "assigned-run-intents";
const RUNS: &str = "assigned-runs";
const READERS: &str = "assigned-run-readers";
const UPDATES: &str = "assigned-run-updates";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRef {
    pub schema: u8,
    pub sequence: u64,
    pub phase: Phase,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Reserved,
    Observed,
    Settled,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    dataset: String,
    guid: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Mode {
    Fresh {
        guest_generation: String,
        drive_base64: String,
        drive_sha256: String,
        expected_bundle_sha256: String,
    },
    Checkpoint {
        state: templates::ArtifactFile,
        memory: templates::ArtifactFile,
        config: templates::ArtifactFile,
        saved_generation: String,
        saved_init_sha256: String,
        saved_marker: String,
        saved_bind_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assigned_lineage: Option<Box<guest::AssignedRunProof>>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    schema: u8,
    machine: String,
    host_generation: String,
    reference: RunRef,
    receipt: Receipt,
    prior_control_sha256: String,
    prior: Box<Record>,
    target: Box<Record>,
    creation_reader: templates::CloneReader,
    root: Disk,
    /// None for a machine without a data volume.
    data: Option<Disk>,
    host_boot_id: String,
    expected_boot_identity: fc::BootIdentity,
    mode: Mode,
    /// Expected host bundle is NOT observed guest/config proof. This slice grants no trust.
    observed_guest: Option<guest::AssignedRunProof>,
    #[serde(default)]
    launch_started: bool,
    #[serde(default)]
    observed_main_pid: i32,
    #[serde(default)]
    observed_checkpoint: Option<guest::Response>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_run_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement: Option<Box<terminal::Settlement>>,
    /// The exact stopped-run spec patch consumed to create this run, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_update: Option<Box<UpdateIntent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_update_sha256: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reader {
    schema: u8,
    machine: String,
    host_generation: String,
    reference: RunRef,
    current_sha256: String,
    root: Disk,
    data: Option<Disk>,
    backing: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: u8,
    current: Current,
    reader: Reader,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor: Option<Current>,
}

/// A pending spec update is separate from the immutable run record until a new run
/// transition consumes it. The intent authorizes only the `pending` projection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateIntent {
    schema: u8,
    machine: String,
    source_current_sha256: String,
    source_record: Box<Record>,
    change: api::SpecChange,
    disk_limits: Option<api::DiskLimits>,
    target: Box<Record>,
    /// The target of the intent this one replaced, while that intent was outstanding. A crash
    /// between writing this intent and its target leaves the machine at that earlier target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_target: Option<Box<Record>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_image: Option<crate::image::Image>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_swap: Option<RootSwap>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSwap {
    source_guid: u64,
    target_guid: Option<u64>,
    retired_dataset: String,
}

impl UpdateIntent {
    fn digest(&self) -> Result<String> {
        Ok(sha(&serde_json::to_vec(self)?))
    }

    fn check_shape(&self) -> Result<()> {
        let source_run = self.source_record.assigned_run.as_ref();
        let source_phase_allowed = source_run.is_some_and(|run| {
            run.phase == Phase::Settled
                || (run.phase == Phase::Observed
                    && self.change.volume.is_some()
                    && self.change.size.is_none()
                    && self.change.image.is_none()
                    && self.change.entrypoint.is_none()
                    && self.change.cmd.is_none()
                    && self.change.env.is_none()
                    && self.change.files.is_none()
                    && self.change.ports.is_none()
                    && self.change.restart.is_none())
        });
        anyhow::ensure!(
            self.schema == 1
                && self.machine == self.source_record.id
                && self.machine == self.target.id
                && self.source_record.assigned_run == self.target.assigned_run
                && self.predecessor_target.as_ref().is_none_or(|earlier| {
                    earlier.id == self.machine && earlier.assigned_run == self.target.assigned_run
                })
                && source_phase_allowed,
            "assigned update source or target differs"
        );
        self.check_record_changes(&self.target)?;
        if let Some(earlier) = self.predecessor_target.as_deref() {
            self.check_record_changes(earlier)?;
        }
        let pending = self.target.pending.as_ref();
        let expected_pending =
            crate::machine::update::pending_after(&self.source_record, self.change.clone());
        let pending_size = self.change.size.is_some();
        let volume_change = self.change.volume.is_some();
        // Canceling an unresolved image leaves no image change to consume. The immediate
        // predecessor retains the canceled pending image through the durable record write.
        let canceled_image = self.change.image.is_none()
            && self
                .source_record
                .pending
                .as_ref()
                .is_none_or(|p| p.image.is_none())
            && self
                .target
                .pending
                .as_ref()
                .is_none_or(|p| p.image.is_none())
            && self
                .predecessor_target
                .as_ref()
                .is_some_and(|earlier| earlier.pending.as_ref().is_some_and(|p| p.image.is_some()));
        anyhow::ensure!(
            (pending_size || volume_change || self.change.image.is_some() || canceled_image)
                && self.change.entrypoint.is_none()
                && self.change.cmd.is_none()
                && self.change.env.is_none()
                && self.change.files.is_none()
                && self.change.ports.is_none()
                && self.change.restart.is_none()
                && self.target.disk_limits
                    == self.disk_limits.as_ref().map_or_else(
                        || self.source_record.disk_limits.clone(),
                        |limits| limits.over(&self.source_record.disk_limits)
                    )
                && (!volume_change
                    || self.target.volume.as_ref().is_some_and(|target| {
                        self.change.volume.as_ref().is_some_and(|change| {
                            target.size_gb == change.size_gb
                                && self
                                    .source_record
                                    .volume
                                    .as_ref()
                                    .is_some_and(|source| target.size_gb > source.size_gb)
                        })
                    }))
                && (volume_change || self.target.volume == self.source_record.volume)
                && (!self.change.image.is_some() || pending.is_some_and(|p| p.image.is_some()))
                && pending == expected_pending.as_ref()
                && self.target.pending_since.is_some() == self.target.pending.is_some(),
            "assigned update contains an unsupported field"
        );
        match (&self.resolved_image, &self.root_swap, &self.change.image) {
            (None, None, _) => {}
            (Some(image), Some(swap), Some(reference)) => {
                let suffix = sha(format!(
                    "{}:{}:{}",
                    self.source_current_sha256, image.key, swap.source_guid
                )
                .as_bytes());
                anyhow::ensure!(
                    image.r#ref == *reference
                        && swap.source_guid > 0
                        && swap.target_guid.is_none_or(|guid| guid > 0)
                        && swap.retired_dataset
                            == format!("{}/root.u_{}", self.source_record.dataset(), &suffix[..24]),
                    "assigned image update root identity differs"
                );
            }
            _ => anyhow::bail!("assigned image update lacks exact root-swap authority"),
        }
        Ok(())
    }

    /// Every recoverable record preserves the source bindings. Only the same bounded
    /// resize projection is allowed for the target and its immediate predecessor.
    fn check_record_changes(&self, record: &Record) -> Result<()> {
        if let Some(pending) = &record.pending {
            pending.check().map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                pending.entrypoint.is_none()
                    && pending.cmd.is_none()
                    && pending.env.is_none()
                    && pending.files.is_none()
                    && pending.ports.is_none()
                    && pending.restart.is_none()
                    && pending.volume.as_ref().is_none_or(|pending| {
                        record
                            .volume
                            .as_ref()
                            .is_some_and(|volume| pending.size_gb == volume.size_gb)
                    }),
                "assigned update record contains unsupported pending fields"
            );
        }
        anyhow::ensure!(
            record.pending_since.is_some() == record.pending.is_some(),
            "assigned update record pending timestamp differs"
        );
        let mut projected = record.clone();
        match (
            &mut projected.volume,
            &self.source_record.volume,
            &self.target.volume,
        ) {
            (Some(volume), Some(source), Some(target)) => {
                anyhow::ensure!(
                    volume.size_gb >= source.size_gb && volume.size_gb <= target.size_gb,
                    "assigned update record volume is outside source and target"
                );
                volume.size_gb = source.size_gb;
            }
            (None, None, None) => {}
            _ => anyhow::bail!("assigned update record changes volume presence"),
        }
        projected.pending = self.source_record.pending.clone();
        projected.pending_since = self.source_record.pending_since;
        projected.version = self.source_record.version;
        projected.updated_at = self.source_record.updated_at;
        projected.last_used_at = self.source_record.last_used_at;
        projected.disk_limits = self.source_record.disk_limits.clone();
        anyhow::ensure!(
            serde_json::to_value(projected)? == serde_json::to_value(&*self.source_record)?,
            "assigned update changes fields outside pending spec and event version"
        );
        Ok(())
    }

    pub(super) fn check(&self, current: &Current) -> Result<()> {
        current.check()?;
        let digest = self.digest()?;
        let settled_authority = current.settlement.as_deref().is_some_and(|settlement| {
            settlement.update_sha256.as_deref() == Some(digest.as_str())
                && settlement
                    .update
                    .as_deref()
                    .is_some_and(|update| update.digest().ok().as_ref() == Some(&digest))
        });
        let phase_allowed = current.reference.phase == Phase::Settled
            || (current.reference.phase == Phase::Observed
                && self.change.volume.is_some()
                && self.change.size.is_none());
        anyhow::ensure!(
            self.machine == current.machine
                && phase_allowed
                && (self.source_current_sha256 == current.authority_sha256()? || settled_authority)
                && hex_id(&self.source_current_sha256, 64)
                && (settled_authority
                    || current.record_fingerprint(&self.source_record)?
                        == current.record_fingerprint(&current.target)?),
            "assigned update source or target differs"
        );
        self.check_shape()?;
        if let Some(swap) = &self.root_swap {
            anyhow::ensure!(
                current.root.dataset == self.source_record.root_dataset()
                    && current.root.guid == swap.source_guid,
                "assigned image update does not bind the settled root"
            );
        }
        Ok(())
    }
}

fn sha(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
fn hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
}
fn generation() -> Result<String> {
    let mut bytes = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow!("run entropy unavailable"))?;
    Ok(hex::encode(bytes))
}

impl Manager {
    /// Private first-continuation reservation; this method performs no launch/config/disk mutation.
    #[allow(dead_code)]
    pub(in crate::machine) async fn reserve_assigned_run(
        &self,
        entry: &Arc<Entry>,
        checkpoint: bool,
    ) -> Result<RunRef> {
        self.reserve_assigned_run_version(entry, checkpoint, None)
            .await
    }

    pub(super) async fn reserve_assigned_run_version(
        &self,
        entry: &Arc<Entry>,
        checkpoint: bool,
        at: Option<u64>,
    ) -> Result<RunRef> {
        self.ensure_entry_assigned_update_backing(entry).await?;
        let _warm = self.inner.warm_lock.lock().await;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _sandbox = self.inner.sandbox_create_lock.lock().await;
        let _entry = entry.lock.lock().await;
        self.check_version(entry, at)?;
        if let Some(update) = self
            .inner
            .store
            .get::<UpdateIntent>(UPDATES, &entry.snapshot().id)?
            .filter(|update| update.change.image.is_some())
        {
            // Root replacement shares the source entry lock with named-clone reservation.
            self.ensure_assigned_root_update(&update).await?;
        }
        let intent = self.plan_assigned_run(entry, checkpoint).await?;
        let machines = self.inner.machines.lock().unwrap();
        anyhow::ensure!(
            machines
                .get(&intent.current.machine)
                .is_some_and(|other| Arc::ptr_eq(other, entry)),
            "run source left admission"
        );
        anyhow::ensure!(
            intent.current.record_fingerprint(&entry.snapshot())?
                == intent.current.prior_control_sha256,
            "run source controls changed before admission"
        );
        let quota = self
            .namespace_of(&intent.current.target.namespace)
            .context("run namespace missing")?;
        let mut held = self.namespace_use(&machines, &quota.rec.id);
        let prior_charge = quota_need(&intent.current.prior, false);
        held.memory_mb = held.memory_mb.saturating_sub(prior_charge.memory_mb);
        held.cpu_millis = Some(held.cpu_millis().saturating_sub(prior_charge.cpu_millis()));
        let need = api::QuotaUse {
            memory_mb: intent.current.target.size.memory_mb,
            cpu_millis: Some(intent.current.target.size.cpu_millis()),
            ..Default::default()
        };
        if let Some(error) = over_quota(&quota.rec.id, &quota.rec.quota, &held, &need) {
            return Err(anyhow!(MError::Quota(error.to_string())));
        }
        self.memory_admission(&machines)?;
        let prior_memory = if entry.commits_memory(&intent.current.prior) {
            entry.memory_charge(&intent.current.prior)
        } else {
            0
        };
        let (physical, _) = committed(&machines);
        admit(
            physical.memory_mb.saturating_sub(prior_memory),
            self.capacity().memory_mb,
            host_memory(need.memory_mb)?,
        )?;
        admit_cpu(
            physical
                .cpu_millis()
                .saturating_sub(prior_charge.cpu_millis()),
            self.capacity().cpu_millis(),
            need.cpu_millis(),
        )?;
        self.inner.store.ensure_assigned_run_lifecycle_floor()?;
        // The intent is checked against the machine file at once: repair a file a failed
        // update write left at its predecessor target first.
        self.repair_outstanding_update_record(&intent.current.machine)?;
        // Cache reservation before uncertain persistence: even the first failed write
        // cannot turn this process into a second run or a second physical allocation.
        let _writes = entry.removed.lock().unwrap();
        anyhow::ensure!(!*_writes, "run source removed");
        entry.identity_trusted.store(false, Relaxed);
        *entry.live.lock().unwrap() = None;
        *entry.rec.lock().unwrap() = intent.current.target.as_ref().clone();
        self.inner
            .store
            .put_durable(INTENTS, &intent.current.machine, &intent)?;
        self.reconcile_assigned_run(&intent)?;
        Ok(intent.current.reference)
    }
}

#[cfg(test)]
pub(in crate::machine) use model::parse_drive as parse_drive_for_test;
