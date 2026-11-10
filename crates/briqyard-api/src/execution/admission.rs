//! Durable reservation and one-shot host consumption. A permit must not leave its
//! trusted issuer before `reserve` succeeds. Dispatch must not begin before `consume`.
//! Opening rotates the service instance and clears installed authority. Reinstallation
//! requires the trusted control channel's acknowledgement of this exact new instance.
use super::*;
mod authority_install;
mod delegation_install;
mod installation_flow;
mod operation;
mod projection;
pub use authority_install::{AuthorityIntent, AuthorityPayload};
pub use delegation_install::DelegationIntent;
pub use installation_flow::{
    validate_discovery_receipt, DiscoveryIntent, OwnershipControl, ProtectionIntent,
};
use nix::libc;
pub use operation::{OperationIntent, OperationPhase};
pub use projection::{Projection, ProjectionEvidence, MAX_PROJECTION_BYTES};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 16_384;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "identity",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Role {
    Authority(String),
    Host(String),
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Reserved,
    Consumed,
    Finished,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    permit: Permit,
    status: Status,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    allocation: Allocation,
    digest: String,
    used: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    v: u8,
    role: Role,
    instance: String,
    clock_floor: u64,
    allocations: BTreeMap<String, Installed>,
    fences: BTreeMap<String, String>,
    retired: BTreeMap<String, Vec<String>>,
    admissions: BTreeMap<String, Admission>,
    #[serde(default)]
    registration: Option<HostRegistration>,
    #[serde(default)]
    registration_highwater: u64,
    #[serde(default)]
    ownership: BTreeMap<String, HostOwnership>,
    #[serde(default)]
    ownership_highwater: BTreeMap<String, u64>,
    #[serde(default)]
    delegations: BTreeMap<String, HostDelegation>,
    #[serde(default)]
    delegation_versions: BTreeMap<String, Vec<HostDelegation>>,
    #[serde(default)]
    delegation_tombstones: BTreeMap<String, u64>,
    #[serde(default)]
    prepared: BTreeMap<String, PreparedAdmission>,
    #[serde(default)]
    protections: BTreeMap<String, InstalledProtection>,
    #[serde(default)]
    authority_intents: BTreeMap<String, AuthorityIntent>,
    #[serde(default)]
    authority_highwater: BTreeMap<String, u64>,
    #[serde(default)]
    discovery_intents: BTreeMap<String, DiscoveryIntent>,
    #[serde(default)]
    protection_intents: BTreeMap<String, ProtectionIntent>,
    #[serde(default)]
    delegation_intents: BTreeMap<String, DelegationIntent>,
    #[serde(default)]
    operation_intents: BTreeMap<String, OperationIntent>,
    #[serde(default)]
    uncertain_installations: BTreeSet<String>,
}

/// Authenticated installer input. These records are never constructed from a grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostRegistration {
    pub authority: String,
    pub epoch: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub host_instance: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostOwnership {
    pub installation: String,
    pub generation: u64,
    pub team: String,
    pub subject: String,
    pub metadata_revision: String,
    pub primary: Target,
    pub public_seeds: Vec<Target>,
    pub public_resources: Vec<PublicResource>,
    pub resource_set: ResourceSet,
    pub host_instance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostDelegation {
    pub id: String,
    pub version: u64,
    pub ownership: String,
    pub ownership_generation: u64,
    pub grant_digest: String,
    pub allocation_digests: Vec<String>,
    pub principal: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedAdmission {
    pub admission: String,
    pub delegation: String,
    pub grant_digest: String,
    pub permit_digest: String,
    pub request_digest: String,
    pub allocation_refs: Vec<AllocationRef>,
    pub ownership: String,
    pub ownership_generation: u64,
    pub host_instance: String,
    pub expires_at: u64,
    pub dispatched: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledProtection {
    pub installation: String,
    pub generation: u64,
    pub admission: String,
    pub expires_at_ms: u64,
    pub resources: Vec<Target>,
    pub resource_revision: String,
}

/// Fixed errors contain no submitted claims or credential material.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("execution journal persistence unavailable; reconciliation required")]
    Persistence,
    #[error("execution journal is already owned or its files changed")]
    Ownership,
    #[error("execution admission is stale or mismatched")]
    Binding,
    #[error("execution allocation has no remaining capacity")]
    Exhausted,
    #[error("execution admission already exists; query status instead of dispatching")]
    AlreadyAdmitted,
    #[error("execution journal capacity reached")]
    Full,
}

/// One exclusive writer for a bounded private journal. Keep this alive for the service
/// lifetime. Never copy a live journal or restore it under an acknowledged old instance.
/// An instance change must be fenced at every dispatch host before capacity is reused.
pub struct Journal {
    root: PathBuf,
    directory: File,
    lock: File,
    state: State,
    poisoned: bool,
}
impl Journal {
    /// Clock loss after a durable host ACK must never promote that uncertain
    /// intent again. Retain its full evidence and a permanent bounded refusal.
    pub fn refuse_installation_readiness(&mut self, kind: &str, id: &str) -> Result<(), Error> {
        self.ownership()?;
        if !valid_id(id)
            || !matches!(
                kind,
                "authority" | "discovery" | "protection" | "delegation"
            )
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.uncertain_installations.insert(format!("{kind}:{id}"));
        let result = self.commit(next);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn installation_uncertain(&self, kind: &str, id: &str) -> bool {
        self.state
            .uncertain_installations
            .contains(&format!("{kind}:{id}"))
    }
    /// Retained ordering evidence for explicit revocation/removal only. This is
    /// never qualified time and must not authorize admission or release protection.
    pub fn revocation_order(&self) -> Clock {
        Clock {
            now: self.state.clock_floor,
            uncertainty: 0,
        }
    }

    pub fn open(root: &Path, role: Role) -> Result<Self, Error> {
        if !valid_id(match &role {
            Role::Authority(id) | Role::Host(id) => id,
        }) {
            return Err(Error::Binding);
        }
        match std::fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => File::open(root.parent().ok_or(Error::Ownership)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| Error::Persistence)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Persistence),
        }
        if std::fs::symlink_metadata(root)
            .map_err(|_| Error::Ownership)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Ownership);
        }
        let root = root.canonicalize().map_err(|_| Error::Persistence)?;
        let metadata = root.metadata().map_err(|_| Error::Persistence)?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(Error::Ownership);
        }
        let directory = File::open(&root).map_err(|_| Error::Persistence)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("writer.lock"))
            .map_err(|_| Error::Ownership)?;
        let lm = lock.metadata().map_err(|_| Error::Ownership)?;
        if !lm.is_file()
            || lm.uid() != metadata.uid()
            || lm.mode() & 0o777 != 0o600
            || lm.nlink() != 1
        {
            return Err(Error::Ownership);
        }
        lock.try_lock().map_err(|_| Error::Ownership)?;
        let mut state = match read_state(&root.join("journal.json"))? {
            Some(state) if state.v == 1 && state.role == role => state,
            Some(_) => return Err(Error::Binding),
            None => State {
                v: 1,
                role,
                instance: String::new(),
                clock_floor: 0,
                allocations: BTreeMap::new(),
                fences: BTreeMap::new(),
                retired: BTreeMap::new(),
                admissions: BTreeMap::new(),
                registration: None,
                registration_highwater: 0,
                ownership: BTreeMap::new(),
                ownership_highwater: BTreeMap::new(),
                delegations: BTreeMap::new(),
                delegation_versions: BTreeMap::new(),
                delegation_tombstones: BTreeMap::new(),
                prepared: BTreeMap::new(),
                protections: BTreeMap::new(),
                authority_intents: BTreeMap::new(),
                authority_highwater: BTreeMap::new(),
                discovery_intents: BTreeMap::new(),
                protection_intents: BTreeMap::new(),
                delegation_intents: BTreeMap::new(),
                operation_intents: BTreeMap::new(),
                uncertain_installations: BTreeSet::new(),
            },
        };
        if state
            .delegation_versions
            .values()
            .map(Vec::len)
            .sum::<usize>()
            > MAX_RECORDS
            || state.admissions.len() > MAX_RECORDS
            || state.allocations.len() > MAX_RECORDS
            || state.discovery_intents.len() > MAX_RECORDS
            || state.protection_intents.len() > MAX_RECORDS
            || state.delegation_intents.len() > MAX_RECORDS
            || state.operation_intents.len() > MAX_RECORDS
            || state.uncertain_installations.len() > MAX_RECORDS
        {
            return Err(Error::Full);
        }
        let mut random = [0u8; 24];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| Error::Persistence)?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        state.instance = URL_SAFE_NO_PAD.encode(random);
        // No allocation silently survives a service incarnation. Old admissions remain
        // status-only evidence. A restored journal must acquire new fenced authority.
        state.allocations.clear();
        for (authority, epoch) in &state.fences {
            let retired = state.retired.entry(authority.clone()).or_default();
            if !retired.contains(epoch) {
                retired.push(epoch.clone());
            }
        }
        state.fences.clear();
        // A host restart retires the old registration. Ownership and prepared
        // records remain as rejection evidence, never as current authority.
        state.registration = None;
        let mut journal = Self {
            root,
            directory,
            lock,
            state,
            poisoned: false,
        };
        journal.commit(journal.state.clone())?;
        Ok(journal)
    }
    pub fn instance(&self) -> &str {
        &self.state.instance
    }
    pub fn role(&self) -> &Role {
        &self.state.role
    }

    pub fn registration(&self) -> Result<Option<&HostRegistration>, Error> {
        self.ownership()?;
        Ok(self.state.registration.as_ref())
    }

    /// The installer supplies the expected current instance. Fencing is durable before
    /// registration can be acknowledged; a crash between writes leaves no ready ACK.
    pub fn register_host(&mut self, record: HostRegistration, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        if !matches!(self.role(), Role::Host(_))
            || record.host_instance != self.instance()
            || !valid_id(&record.authority)
            || !valid_id(&record.epoch)
            || !valid_id(&record.key_id)
            || record.generation == 0
        {
            return Err(Error::Binding);
        }
        if self.state.registration.as_ref() == Some(&record) {
            return Ok(());
        }
        if record.generation <= self.state.registration_highwater {
            return Err(Error::Binding);
        }
        self.fence(
            &record.authority,
            &record.epoch,
            &record.host_instance,
            clock,
        )?;
        let mut next = self.state.clone();
        next.registration_highwater = record.generation;
        next.registration = Some(record);
        next.ownership.clear();
        next.delegations.clear();
        next.prepared.clear();
        next.protections.clear();
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn installed_ownership(&self, installation: &str) -> Result<Option<&HostOwnership>, Error> {
        self.ownership()?;
        Ok(self.state.ownership.get(installation))
    }

    pub fn install_ownership(&mut self, record: HostOwnership, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        if self.state.registration.is_none()
            || record.host_instance != self.instance()
            || !valid_id(&record.installation)
            || !valid_id(&record.team)
            || !valid_id(&record.subject)
            || !valid_id(&record.metadata_revision)
            || record.generation == 0
            || record.public_seeds.is_empty()
            || record.public_resources.is_empty()
            || record.resource_set.resources.is_empty()
        {
            return Err(Error::Binding);
        }
        let high = self
            .state
            .ownership_highwater
            .get(&record.installation)
            .copied()
            .unwrap_or(0);
        if self.state.ownership.get(&record.installation) == Some(&record) {
            return Ok(());
        }
        // A replacement must first invalidate and acknowledge the old mapping.
        if self.state.ownership.contains_key(&record.installation) {
            return Err(Error::Binding);
        }
        if record.generation <= high {
            return Err(Error::Binding);
        }
        if self.state.ownership.iter().any(|(id, other)| {
            id != &record.installation
                && other.public_resources.iter().any(|a| {
                    record
                        .public_resources
                        .iter()
                        .any(|b| a.target.machine == b.target.machine || a.id == b.id)
                })
        }) {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.ownership_highwater
            .insert(record.installation.clone(), record.generation);
        next.delegations
            .retain(|_, d| d.ownership != record.installation);
        next.protections
            .retain(|_, p| p.installation != record.installation);
        next.ownership.insert(record.installation.clone(), record);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn invalidate_ownership(
        &mut self,
        installation: &str,
        generation: u64,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        if !valid_id(installation) || generation == 0 {
            return Err(Error::Binding);
        }
        let high = self
            .state
            .ownership_highwater
            .get(installation)
            .copied()
            .unwrap_or(0);
        if generation < high {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.ownership_highwater
            .insert(installation.into(), generation);
        next.ownership.remove(installation);
        next.delegations.retain(|_, d| d.ownership != installation);
        next.protections
            .retain(|_, p| p.installation != installation);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn delegation(&self, id: &str) -> Result<Option<&HostDelegation>, Error> {
        self.ownership()?;
        Ok(self.state.delegations.get(id))
    }

    pub fn protection(&self, admission: &str) -> Result<Option<&InstalledProtection>, Error> {
        self.ownership()?;
        Ok(self.state.protections.get(admission))
    }

    pub fn record_protection(
        &mut self,
        record: InstalledProtection,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let Some(owner) = self.state.ownership.get(&record.installation) else {
            return Err(Error::Binding);
        };
        if owner.generation != record.generation
            || owner.resource_set.resources != record.resources
            || owner.resource_set.revision != record.resource_revision
            || !valid_id(&record.admission)
            || record.expires_at_ms
                <= clock
                    .now
                    .saturating_add(clock.uncertainty)
                    .saturating_mul(1000)
        {
            return Err(Error::Binding);
        }
        if self.state.protections.get(&record.admission) == Some(&record) {
            return Ok(());
        }
        if self.state.protections.contains_key(&record.admission) {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.protections.insert(record.admission.clone(), record);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn revoke_delegation(&mut self, id: &str, version: u64, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        if !valid_id(id) || version == 0 {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let high = next.delegation_tombstones.get(id).copied().unwrap_or(0);
        if version < high {
            return Err(Error::Binding);
        }
        next.delegation_tombstones.insert(id.into(), version);
        next.delegations.remove(id);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn prepared(&self, id: &str) -> Result<Option<&PreparedAdmission>, Error> {
        self.ownership()?;
        Ok(self.state.prepared.get(id))
    }

    pub fn prepare(&mut self, record: PreparedAdmission, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        let Some(delegation) = self.state.delegations.get(&record.delegation) else {
            return Err(Error::Binding);
        };
        let Some(owner) = self.state.ownership.get(&record.ownership) else {
            return Err(Error::Binding);
        };
        if record.host_instance != self.instance()
            || record.expires_at <= clock.now.saturating_add(clock.uncertainty)
            || record.ownership_generation != owner.generation
            || delegation.ownership != record.ownership
            || delegation.ownership_generation != owner.generation
            || delegation.grant_digest != record.grant_digest
            || !valid_id(&record.admission)
            || !valid_id(&record.request_digest)
        {
            return Err(Error::Binding);
        }
        if self.state.prepared.get(&record.admission) == Some(&record) {
            return Ok(());
        }
        if self.state.prepared.contains_key(&record.admission) {
            return Err(Error::AlreadyAdmitted);
        }
        let mut next = self.state.clone();
        next.prepared.insert(record.admission.clone(), record);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    /// Called before invoking the manager. A lost response can only be inspected.
    pub fn mark_dispatched(&mut self, id: &str, clock: Clock) -> Result<PreparedAdmission, Error> {
        self.check(clock)?;
        let current = self.state.prepared.get(id).ok_or(Error::Binding)?;
        if current.host_instance != self.instance()
            || current.expires_at <= clock.now.saturating_add(clock.uncertainty)
            || self.state.registration.is_none()
            || self
                .state
                .ownership
                .get(&current.ownership)
                .map(|o| o.generation)
                != Some(current.ownership_generation)
            || self
                .state
                .delegations
                .get(&current.delegation)
                .map(|d| (&d.ownership, d.ownership_generation, &d.grant_digest))
                != Some((
                    &current.ownership,
                    current.ownership_generation,
                    &current.grant_digest,
                ))
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let saved = next.prepared.get_mut(id).ok_or(Error::Binding)?;
        if saved.dispatched {
            return Err(Error::AlreadyAdmitted);
        }
        let record = saved.clone();
        saved.dispatched = true;
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(record)
    }

    /// Host acknowledgement of the current authority epoch. The trusted installer must
    /// serialize handover and must never reuse capacity before every old host has
    /// acknowledged this fence (or every old permit has expired with clock error).
    pub fn fence(
        &mut self,
        authority: &str,
        epoch: &str,
        instance: &str,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        if !matches!(self.role(), Role::Host(_))
            || instance != self.instance()
            || !valid_id(authority)
            || !valid_id(epoch)
        {
            return Err(Error::Binding);
        }
        if self
            .state
            .retired
            .get(authority)
            .is_some_and(|epochs| epochs.iter().any(|old| old == epoch))
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        if let Some(previous) = next.fences.get(authority).filter(|old| *old != epoch) {
            next.retired
                .entry(authority.into())
                .or_default()
                .push(previous.clone());
        }
        next.allocations.retain(|_, a| {
            a.allocation.authority != authority || a.allocation.authority_epoch == epoch
        });
        next.fences.insert(authority.into(), epoch.into());
        next.clock_floor = clock.now;
        self.commit(next)
    }

    /// Install the exact signed allocation vector after trusted ownership/fencing
    /// acknowledgement for `instance`. Repeating an install never resets consumption.
    /// The caller authenticates this administrative channel; a public gateway cannot call it.
    pub fn install(
        &mut self,
        bundle: &VerifiedBundle,
        instance: &str,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        if instance != self.instance() || !self.bound(bundle) {
            return Err(Error::Binding);
        }
        self.install_vector(
            bundle
                .allocations()
                .iter()
                .zip(&bundle.permit().allocations)
                .map(|(a, r)| (a, r.digest.as_str())),
            clock,
        )
    }

    /// Pre-permit allocation installation on the trusted channel. This acknowledges
    /// quota storage only, never metadata, membership protection or dispatch readiness.
    /// Exact service instance and authority fences are still mandatory.
    pub fn install_allocations(
        &mut self,
        delegation: &VerifiedDelegation,
        instance: &str,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        if instance != self.instance()
            || !delegation
                .allocations()
                .iter()
                .all(|a| self.binding(&delegation.grant().target, &a.authority, &a.authority_epoch))
        {
            return Err(Error::Binding);
        }
        self.install_vector(
            delegation
                .allocations()
                .iter()
                .zip(delegation.allocation_digests())
                .map(|(a, digest)| (a, digest.as_str())),
            clock,
        )
    }

    fn install_vector<'a>(
        &mut self,
        allocations: impl Iterator<Item = (&'a Allocation, &'a str)>,
        clock: Clock,
    ) -> Result<(), Error> {
        let mut next = self.state.clone();
        for (allocation, digest) in allocations {
            if allocation.exp <= clock.now.saturating_add(clock.uncertainty) {
                return Err(Error::Binding);
            }
            match next.allocations.get(&allocation.id) {
                Some(old) if old.allocation != *allocation || old.digest != digest => {
                    return Err(Error::Binding)
                }
                Some(_) => {}
                None => {
                    next.allocations.insert(
                        allocation.id.clone(),
                        Installed {
                            allocation: allocation.clone(),
                            digest: digest.to_owned(),
                            used: 0,
                        },
                    );
                }
            }
        }
        next.clock_floor = clock.now;
        self.commit(next)
    }

    /// Authority-side transaction, before the signed permit is returned to any caller.
    /// A retry returns AlreadyAdmitted; the caller may retrieve existing status only.
    pub fn reserve(&mut self, bundle: &VerifiedBundle, clock: Clock) -> Result<(), Error> {
        if !matches!(self.role(), Role::Authority(_)) {
            return Err(Error::Binding);
        }
        self.admit(bundle, clock, Status::Reserved)
    }
    /// Host-side transaction, under the target's lifecycle lock and allocation fence,
    /// before the first guest frame. A duplicate can never obtain dispatch authority.
    pub fn consume(&mut self, bundle: &VerifiedBundle, clock: Clock) -> Result<(), Error> {
        if !matches!(self.role(), Role::Host(_)) {
            return Err(Error::Binding);
        }
        self.admit(bundle, clock, Status::Consumed)
    }
    fn admit(
        &mut self,
        bundle: &VerifiedBundle,
        clock: Clock,
        status: Status,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let permit = bundle.permit();
        if !self.bound(bundle) || permit.exp <= clock.now.saturating_add(clock.uncertainty) {
            return Err(Error::Binding);
        }
        if self.state.admissions.contains_key(&permit.admission) {
            return Err(Error::AlreadyAdmitted);
        }
        // Runtime policy, not arbitrary units chosen by the permit sender.
        let required: &[&str] = match permit.operation {
            Operation::Exec | Operation::ExecStream | Operation::Shell => {
                &["requests", "exec_calls"]
            }
            Operation::FilesRead | Operation::FilesWrite => &["requests"],
        };
        if bundle.allocations().len() != required.len()
            || required
                .iter()
                .any(|bucket| !bundle.allocations().iter().any(|a| &a.bucket == bucket))
            || permit.allocations.iter().any(|a| a.units != 1)
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        for (allocation, reference) in bundle.allocations().iter().zip(&permit.allocations) {
            let installed = next
                .allocations
                .get_mut(&allocation.id)
                .ok_or(Error::Binding)?;
            if installed.allocation != *allocation
                || installed.digest != reference.digest
                || allocation.exp <= clock.now.saturating_add(clock.uncertainty)
            {
                return Err(Error::Binding);
            }
            installed.used = installed
                .used
                .checked_add(reference.units)
                .ok_or(Error::Exhausted)?;
            if installed.used > allocation.units {
                return Err(Error::Exhausted);
            }
        }
        next.admissions.insert(
            permit.admission.clone(),
            Admission {
                permit: permit.clone(),
                status,
            },
        );
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn status(&self, id: &str) -> Result<Option<Status>, Error> {
        self.ownership()?;
        Ok(self.state.admissions.get(id).map(|a| a.status))
    }
    /// Completion records evidence only; capacity is never refunded. Absence of this
    /// record after consume remains uncertain and can never license a second dispatch.
    pub fn finish(&mut self, permit: &Permit, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        if !matches!(self.role(), Role::Host(_)) {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let saved = next
            .admissions
            .get_mut(&permit.admission)
            .ok_or(Error::Binding)?;
        if saved.permit != *permit || saved.status == Status::Reserved {
            return Err(Error::Binding);
        }
        saved.status = Status::Finished;
        next.clock_floor = clock.now;
        self.commit(next)
    }
    /// Only expired evidence may be pruned. The persisted clock floor prevents a local
    /// clock rollback from making a pruned credential live again. Never refunds units.
    pub fn prune(&mut self, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        let earliest = clock
            .now
            .checked_sub(clock.uncertainty)
            .ok_or(Error::Binding)?;
        let mut next = self.state.clone();
        next.admissions.retain(|_, a| a.permit.exp > earliest);
        next.allocations.retain(|_, a| a.allocation.exp > earliest);
        next.prepared.retain(|_, a| a.expires_at > earliest);
        next.delegations.retain(|_, a| a.expires_at > earliest);
        next.protections
            .retain(|_, p| p.expires_at_ms / 1000 > earliest);
        // High-water and tombstones remain: a delayed installation cannot revive
        // a previously revoked identity even after its status record is pruned.
        next.clock_floor = clock.now;
        self.commit(next)
    }
    fn bound(&self, bundle: &VerifiedBundle) -> bool {
        let permit = bundle.permit();
        self.binding(&permit.target, &permit.authority, &permit.authority_epoch)
    }
    fn binding(&self, target: &Target, authority: &str, epoch: &str) -> bool {
        match self.role() {
            Role::Authority(id) => authority == id && epoch == self.instance(),
            Role::Host(host) => {
                target.host == *host
                    && self.state.fences.get(authority).map(String::as_str) == Some(epoch)
            }
        }
    }
    fn check(&self, clock: Clock) -> Result<(), Error> {
        self.ownership()?;
        if clock.now < self.state.clock_floor
            || clock.now > MAX_SAFE_INTEGER
            || clock.uncertainty > MAX_SAFE_INTEGER
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    fn ownership(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Persistence);
        }
        let same = |a: &File, path: &Path| -> Result<bool, Error> {
            let a = a.metadata().map_err(|_| Error::Ownership)?;
            let b = std::fs::symlink_metadata(path).map_err(|_| Error::Ownership)?;
            Ok(a.dev() == b.dev()
                && a.ino() == b.ino()
                && a.nlink() > 0
                && b.uid() == unsafe { libc::geteuid() }
                && b.mode() & 0o077 == 0
                && !b.file_type().is_symlink())
        };
        if !same(&self.directory, &self.root)? || !same(&self.lock, &self.root.join("writer.lock"))?
        {
            return Err(Error::Ownership);
        }
        Ok(())
    }
    fn commit(&mut self, next: State) -> Result<(), Error> {
        self.ownership()?;
        if next
            .delegation_versions
            .values()
            .map(Vec::len)
            .sum::<usize>()
            > MAX_RECORDS
            || next.admissions.len() > MAX_RECORDS
            || next.allocations.len() > MAX_RECORDS
            || next.retired.values().map(Vec::len).sum::<usize>() > MAX_RECORDS
            || next.ownership.len() > MAX_RECORDS
            || next.ownership_highwater.len() > MAX_RECORDS
            || next.delegations.len() > MAX_RECORDS
            || next.delegation_tombstones.len() > MAX_RECORDS
            || next.prepared.len() > MAX_RECORDS
            || next.protections.len() > MAX_RECORDS
            || next.authority_intents.len() > MAX_RECORDS
            || next.authority_highwater.len() > MAX_RECORDS
            || next.discovery_intents.len() > MAX_RECORDS
            || next.protection_intents.len() > MAX_RECORDS
            || next.uncertain_installations.len() > MAX_RECORDS
        {
            return Err(Error::Full);
        }
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::Persistence)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::Full);
        }
        let write = || -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.root.join("journal.next"))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(
                self.root.join("journal.next"),
                self.root.join("journal.json"),
            )?;
            self.directory.sync_all()
        };
        // A retained temp file is uncertain evidence. It is not silently removed or retried.
        if write().is_err() {
            self.poisoned = true;
            return Err(Error::Persistence);
        }
        self.state = next;
        Ok(())
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:/".contains(&b))
}
fn read_state(path: &Path) -> Result<Option<State>, Error> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Persistence),
    };
    let metadata = file.metadata().map_err(|_| Error::Persistence)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(Error::Ownership);
    }
    if metadata.len() > MAX_BYTES {
        return Err(Error::Full);
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Persistence)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(Error::Full);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error::Persistence)
}

#[cfg(test)]
mod tests;
