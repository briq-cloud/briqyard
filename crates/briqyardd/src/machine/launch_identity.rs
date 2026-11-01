//! Immutable host identity and source allocation for future cross-namespace warm claims.
//! The hold is independent of the tenant record and is released after destruction, last.
use super::*;

mod provenance;
use provenance::TemplateLaunch;

const HOLDS: &str = "launch-holds";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchIdentity {
    version: u8,
    pub(super) namespace: String,
    pub(super) subnet_index: u32,
    pub(super) host_num: u8,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) jailed: bool,
    pub(super) jailer: PathBuf,
    pub(super) jail_base: PathBuf,
    uid_base: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    template: Option<TemplateLaunch>,
}

#[derive(Serialize, Deserialize)]
struct Hold {
    machine: String,
    identity: LaunchIdentity,
}

impl LaunchIdentity {
    fn new(cfg: &Config, namespace: &str, subnet_index: u32, host_num: u8) -> Result<Self> {
        let jailed = !cfg.jailer.as_os_str().is_empty();
        anyhow::ensure!(
            jailed,
            "unbound slot launch requires the jailer; unjailed credentials are not qualified"
        );
        let uid = if jailed {
            cfg.jail_uid_base
                .checked_add(
                    subnet_index
                        .checked_mul(256)
                        .context("launch subnet identity overflow")?,
                )
                .and_then(|n| n.checked_add(u32::from(host_num)))
                .context("launch UID overflow")?
        } else {
            0
        };
        Ok(Self {
            version: 1,
            namespace: namespace.into(),
            subnet_index,
            host_num,
            uid,
            gid: uid,
            jailed,
            jailer: cfg.jailer.clone(),
            jail_base: cfg.jail_base(),
            uid_base: cfg.jail_uid_base,
            template: None,
        })
    }

    fn check(&self, cfg: &Config) -> Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported launch identity version");
        check_namespace_id(&self.namespace)?;
        anyhow::ensure!(
            (2..=254).contains(&self.host_num),
            "invalid source launch address"
        );
        // Recompute only from immutable source coordinates, never tenant ownership.
        let mut expected = Self::new(cfg, &self.namespace, self.subnet_index, self.host_num)?;
        expected.template.clone_from(&self.template);
        anyhow::ensure!(
            self == &expected,
            "launch identity conflicts with jail configuration"
        );
        Ok(())
    }
}

impl Manager {
    /// Called while the new slot still owns its operator address, before any launch.
    pub(super) fn pin_launch_identity(&self, e: &Entry) -> Result<()> {
        let mut record = e.rec.lock().unwrap();
        anyhow::ensure!(
            record.boot_incarnation.is_none() && record.pid == 0,
            "cannot assign launch identity to an existing process"
        );
        anyhow::ensure!(
            record
                .warm_slot
                .as_ref()
                .is_some_and(|slot| slot.claimed.is_none())
                && record
                    .clone_origin
                    .as_ref()
                    .is_some_and(|origin| origin.stage == templates::CloneStage::Reserved
                        && origin.artifact.profile == guest::SANDBOX_READY_V1),
            "launch identity requires a newly reserved pristine sandbox slot"
        );
        let mut identity = LaunchIdentity::new(
            &self.inner.cfg,
            &record.namespace,
            record.subnet_index,
            record.host_num,
        )?;
        identity.template = Some(TemplateLaunch::from_origin(
            record.clone_origin.as_ref().unwrap(),
        )?);
        identity.check(&self.inner.cfg)?;
        if let Some(previous) = &record.launch_identity {
            anyhow::ensure!(previous == &identity, "launch identity is immutable");
        }
        self.persist_launch_hold(&record.id, &identity)?;
        record.launch_identity = Some(identity);
        self.inner
            .store
            .put_durable("machines", &record.id, &*record)
    }

    fn persist_launch_hold(&self, machine: &str, identity: &LaunchIdentity) -> Result<()> {
        let mut holds = self.inner.launch_holds.lock().unwrap();
        if let Some(previous) = holds.get(machine) {
            anyhow::ensure!(previous == identity, "launch hold identity is immutable");
        }
        if let Some(previous) = self.inner.store.get::<Hold>(HOLDS, machine)? {
            anyhow::ensure!(
                previous.machine == machine && &previous.identity == identity,
                "durable launch hold identity is immutable"
            );
        }
        anyhow::ensure!(
            holds
                .iter()
                .all(|(other_machine, other)| other_machine == machine
                    || (other.subnet_index, other.host_num)
                        != (identity.subnet_index, identity.host_num)),
            "source launch allocation is already held"
        );
        // Cache before the uncertain persistence boundary. An identical retry may
        // finish persistence; a conflicting retry cannot replace this reservation.
        holds.insert(machine.into(), identity.clone());
        self.inner.store.put_durable(
            HOLDS,
            machine,
            &Hold {
                machine: machine.into(),
                identity: identity.clone(),
            },
        )
    }

    /// Reconcile before stale-record deletion, plumbing, orphan sweep or admission.
    /// A journal-only hold blocks startup; it is never proof of process absence.
    pub(super) fn recover_launch_holds(&self, records: &[Record]) -> Result<()> {
        let mut holds = BTreeMap::new();
        for hold in self.inner.store.list::<Hold>(HOLDS)? {
            anyhow::ensure!(
                api::valid_id(&hold.machine),
                "invalid launch hold machine ID"
            );
            hold.identity.check(&self.inner.cfg)?;
            anyhow::ensure!(
                holds.insert(hold.machine, hold.identity).is_none(),
                "duplicate launch hold"
            );
        }
        // Publish all persisted holds even when reconciliation subsequently fails.
        *self.inner.launch_holds.lock().unwrap() = holds.clone();
        for record in records {
            anyhow::ensure!(
                !requires_identity(record) || record.launch_identity.is_some(),
                "pristine warm slot is missing its immutable launch identity"
            );
            if let Some(identity) = &record.launch_identity {
                identity.check(&self.inner.cfg)?;
                anyhow::ensure!(
                    holds.get(&record.id) == Some(identity),
                    "machine {} has missing or inconsistent durable launch hold",
                    record.id
                );
            }
        }
        for record in records {
            self.validate_launch_provenance(record)?;
        }
        let mut sources = std::collections::HashSet::new();
        let namespaces = self.inner.namespaces.lock().unwrap();
        for (id, identity) in &holds {
            let record = records
                .iter()
                .find(|r| &r.id == id)
                .context("launch hold has no machine record; allocation and backing retained")?;
            anyhow::ensure!(
                record.launch_identity.as_ref() == Some(identity),
                "launch hold disagrees with machine identity"
            );
            anyhow::ensure!(
                sources.insert((identity.subnet_index, identity.host_num)),
                "conflicting source launch allocations"
            );
            anyhow::ensure!(
                namespaces
                    .values()
                    .filter(|namespace| namespace.rec.subnet_index == identity.subnet_index)
                    .count()
                    == 1,
                "source launch subnet has conflicting namespace owners"
            );
            anyhow::ensure!(
                namespaces
                    .get(&identity.namespace)
                    .is_some_and(|ns| ns.rec.subnet_index == identity.subnet_index),
                "source launch namespace allocation is missing or changed"
            );
            anyhow::ensure!(
                records.iter().all(|other| other.id == *id
                    || (other.subnet_index, other.host_num)
                        != (identity.subnet_index, identity.host_num)),
                "another machine reuses a source launch allocation"
            );
        }
        Ok(())
    }

    pub(super) fn validate_launch_record(&self, record: &Record) -> Result<()> {
        anyhow::ensure!(
            !requires_identity(record) || record.launch_identity.is_some(),
            "pristine warm slot is missing its immutable launch identity"
        );
        if let Some(identity) = &record.launch_identity {
            identity.check(&self.inner.cfg)?;
            anyhow::ensure!(
                self.inner.launch_holds.lock().unwrap().get(&record.id) == Some(identity),
                "launch allocation is not durably held"
            );
        }
        self.validate_launch_provenance(record)?;
        Ok(())
    }

    /// The current daemon enforces compatibility even if the installer is older.
    /// Hold namespace admission closed from this check through process handover.
    pub async fn handover_admission(
        &self,
        executable: &Path,
    ) -> Result<tokio::sync::RwLockWriteGuard<'_, ()>> {
        self.handover_admission_until(
            executable,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
    }

    async fn handover_admission_until(
        &self,
        executable: &Path,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::RwLockWriteGuard<'_, ()>> {
        let admission = tokio::time::timeout_at(deadline, self.inner.namespace_lifecycle.write())
            .await
            .context("namespace admission did not settle before handover deadline")?;
        if !self.inner.launch_holds.lock().unwrap().is_empty() {
            let probe = tokio::process::Command::new(executable)
                .arg("state-capabilities")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .output();
            let output = tokio::time::timeout_at(deadline, probe)
                .await
                .context("replacement daemon compatibility probe timed out")??;
            anyhow::ensure!(
                output.status.success() && output.stdout == b"launch-identity-v1\n",
                "replacement daemon cannot preserve launch allocations; handover refused"
            );
        }
        Ok(admission)
    }

    pub(super) fn release_launch_hold(&self, id: &str) -> Result<()> {
        self.inner.store.delete_durable(HOLDS, id)?;
        self.inner.launch_holds.lock().unwrap().remove(id);
        Ok(())
    }
}

pub(super) async fn remove_dir(path: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).context("launch backing cleanup incomplete; source allocation retained")
        }
    }
}

fn requires_identity(record: &Record) -> bool {
    record.warm_slot.is_some()
        && record
            .clone_origin
            .as_ref()
            .is_some_and(|origin| origin.artifact.profile == guest::SANDBOX_READY_V1)
}

#[cfg(test)]
#[path = "launch_identity_tests.rs"]
mod tests;
