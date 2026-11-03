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
const INTENTS: &str = "assigned-run-intents";
const RUNS: &str = "assigned-runs";
const READERS: &str = "assigned-run-readers";

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
    data: Disk,
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
    data: Disk,
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
        let _warm = self.inner.warm_lock.lock().await;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _sandbox = self.inner.sandbox_create_lock.lock().await;
        let _entry = entry.lock.lock().await;
        self.check_version(entry, at)?;
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
        let (physical, _) = committed(&machines);
        admit(
            physical.memory_mb.saturating_sub(prior_charge.memory_mb),
            self.capacity().memory_mb,
            need.memory_mb,
        )?;
        admit_cpu(
            physical
                .cpu_millis()
                .saturating_sub(prior_charge.cpu_millis()),
            self.capacity().cpu_millis(),
            need.cpu_millis(),
        )?;
        self.inner.store.ensure_assigned_run_lifecycle_floor()?;
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
