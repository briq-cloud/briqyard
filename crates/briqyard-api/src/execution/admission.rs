//! Durable reservation and one-shot host consumption. A permit must not leave its
//! trusted issuer before `reserve` succeeds. Dispatch must not begin before `consume`.
//! Opening rotates the service instance and clears installed authority. Reinstallation
//! requires the trusted control channel's acknowledgement of this exact new instance.
use super::*;
use nix::libc;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
            },
        };
        if state.admissions.len() > MAX_RECORDS || state.allocations.len() > MAX_RECORDS {
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
        let mut next = self.state.clone();
        for (allocation, reference) in bundle
            .allocations()
            .iter()
            .zip(&bundle.permit().allocations)
        {
            if allocation.exp <= clock.now.saturating_add(clock.uncertainty) {
                return Err(Error::Binding);
            }
            match next.allocations.get(&allocation.id) {
                Some(old) if old.allocation != *allocation || old.digest != reference.digest => {
                    return Err(Error::Binding)
                }
                Some(_) => {}
                None => {
                    next.allocations.insert(
                        allocation.id.clone(),
                        Installed {
                            allocation: allocation.clone(),
                            digest: reference.digest.clone(),
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
        next.clock_floor = clock.now;
        self.commit(next)
    }
    fn bound(&self, bundle: &VerifiedBundle) -> bool {
        match self.role() {
            Role::Authority(authority) => {
                bundle.permit().authority == *authority
                    && bundle.permit().authority_epoch == self.instance()
            }
            Role::Host(host) => {
                bundle.permit().target.host == *host
                    && self.state.fences.get(&bundle.permit().authority)
                        == Some(&bundle.permit().authority_epoch)
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
        if next.admissions.len() > MAX_RECORDS
            || next.allocations.len() > MAX_RECORDS
            || next.retired.values().map(Vec::len).sum::<usize>() > MAX_RECORDS
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
