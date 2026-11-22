use super::*;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
};

type GuardedJournalOpen<'a> = (
    Clock,
    &'a sealed::objects::Plan,
    &'a dyn Fn(&str) -> Result<sealed::transition::Guard, Error>,
);
impl Journal {
    pub fn open(root: &Path, role: Role) -> Result<Self, Error> {
        Self::open_inner(root, role, None)
    }

    pub(in crate::execution) fn open_guarded(
        root: &Path,
        role: Role,
        clock: Clock,
        plan: &sealed::objects::Plan,
        start: &dyn Fn(&str) -> Result<sealed::transition::Guard, Error>,
    ) -> Result<Self, Error> {
        if role != Role::Authority(plan.pre_record.authority.to_string()) {
            return Err(Error::Binding);
        }
        validate_authority_plan(plan)?;
        Self::open_inner(root, role, Some((clock, plan, start)))
    }

    fn open_inner(
        root: &Path,
        role: Role,
        guarded: Option<GuardedJournalOpen<'_>>,
    ) -> Result<Self, Error> {
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
        if guarded.is_some() {
            guarded_clean(&root)?;
        }
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
                active_operations: BTreeMap::new(),
                operation_policies: BTreeMap::new(),
                renewal_attempts: BTreeMap::new(),
                sealed_authority: None,
            },
        };
        if over_capacity(&state) {
            return Err(Error::Full);
        }
        // A journal image can contain an ACK whose rename succeeded but whose directory
        // fsync failed. Its bytes cannot establish that the old owner saw durable success.
        // Reattachment is read-only to a still-live owner; disk is offline evidence only.
        if state.sealed_authority.is_some() {
            return Err(Error::Binding);
        }
        if let Some((_, plan, _)) = guarded {
            sealed_authority::validate_predecessor(&state, plan)?;
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
        for operation in state.active_operations.values_mut() {
            if matches!(operation.phase, ActivePhase::Consumed | ActivePhase::Active) {
                operation.phase = ActivePhase::Recovered;
            }
        }
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
        if let Some((clock, plan, start)) = guarded {
            if clock.now < state.clock_floor
                || clock.now > MAX_SAFE_INTEGER
                || clock.uncertainty > 5
            {
                return Err(Error::Binding);
            }
            let guard = start(&state.instance)?;
            if guard.phase != sealed::transition::GuardPhase::Started
                || guard.x != plan.x
                || guard.plan != sealed::h(plan).map_err(|_| Error::Binding)?
                || guard.proc.boot != plan.pre_a.boot
                || guard.proc.exe != plan.next_a
                || guard.proc.build != plan.abuild
                || guard.proc == plan.pre_a
                || guard.ordinary_kid != plan.pre_record.key_id
                || guard.ordinary_key != plan.ordinary_key
                || guard.set != plan.new.set().map_err(|_| Error::Binding)?
            {
                return Err(Error::Binding);
            }
            state.sealed_authority = Some(SealedAuthority::started(guard));
            state.clock_floor = clock.now;
            sealed_authority::validate_state(&state)?;
        }
        let view = JournalView {
            state: Arc::new(state),
            fence: Arc::new(Fence {
                root,
                directory,
                lock,
                poisoned: AtomicBool::new(false),
            }),
        };
        let mut journal = Self {
            published: Arc::new(RwLock::new(view.clone())),
            view,
        };
        journal.persist(State::clone(&journal.state))?;
        journal.publish();
        Ok(journal)
    }

    pub(super) fn commit(&mut self, next: State, clock: Option<Clock>) -> Result<(), Error> {
        self.commit_inner(next, clock, None)
    }

    pub(super) fn commit_install(
        &mut self,
        next: State,
        clock: Clock,
        reserve: State,
    ) -> Result<(), Error> {
        self.commit_inner(next, Some(clock), Some(reserve))
    }

    fn commit_inner(
        &mut self,
        next: State,
        clock: Option<Clock>,
        reserve: Option<State>,
    ) -> Result<(), Error> {
        self.ownership()?;
        if self.is_guarded_authority() {
            return Err(Error::Binding);
        }
        if matches!(next.role, Role::Authority(_))
            && (near_capacity(&next)
                || over_capacity(&next)
                || reserve.as_ref().is_some_and(over_capacity))
        {
            let Some(clock) = clock else {
                return if over_capacity(&next) {
                    Err(Error::Full)
                } else {
                    self.persist(next)
                };
            };
            self.check(clock)?;
            let (compacted, report) = compact_authority(&next, clock)?;
            debug_assert_eq!(report.retired_versions > 0, report.reclaimed_bytes > 0);
            if let Some(mut reserve) = reserve {
                capacity::compact_reserve(&next, &compacted, &mut reserve)?;
                if over_capacity(&reserve) {
                    return Err(Error::Full);
                }
            }
            self.persist(compacted)
        } else {
            self.persist(next)
        }
    }

    pub(super) fn persist(&mut self, next: State) -> Result<(), Error> {
        self.persist_inner(next, &mut |_| false)
    }

    pub(super) fn persist_inner(
        &mut self,
        next: State,
        fail: &mut dyn FnMut(&str) -> bool,
    ) -> Result<(), Error> {
        self.ownership()?;
        if over_capacity(&next) {
            return Err(Error::Full);
        }
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::Persistence)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::Full);
        }
        let mut write = || -> std::io::Result<()> {
            let mut checkpoint = |stage| -> std::io::Result<()> {
                if fail(stage) {
                    Err(std::io::ErrorKind::WriteZero.into())
                } else {
                    Ok(())
                }
            };
            checkpoint("create")?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.fence.root.join("journal.next"))?;
            checkpoint("write")?;
            file.write_all(&bytes)?;
            checkpoint("file_fsync")?;
            file.sync_all()?;
            checkpoint("rename")?;
            std::fs::rename(
                self.fence.root.join("journal.next"),
                self.fence.root.join("journal.json"),
            )?;
            checkpoint("directory_fsync")?;
            self.fence.directory.sync_all()
        };
        // A retained temp file is uncertain evidence. It is not silently removed or retried.
        if write().is_err() {
            self.fence.poisoned.store(true, Ordering::SeqCst);
            return Err(Error::Persistence);
        }
        // Visible to readers only at `publish`, once the whole action has returned.
        self.view.state = Arc::new(next);
        Ok(())
    }
}

pub(super) fn guarded_clean(root: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(root.join("journal.next")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::Persistence),
    }
}

pub(super) fn read_state(path: &Path) -> Result<Option<State>, Error> {
    read_state_size(path).map(|state| state.map(|(state, _)| state))
}

pub(super) fn read_state_size(path: &Path) -> Result<Option<(State, usize)>, Error> {
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
    let size = usize::try_from(metadata.len()).map_err(|_| Error::Full)?;
    let state = serde_json::from_slice(&bytes).map_err(|_| Error::Persistence)?;
    sealed_authority::validate_state(&state)?;
    Ok(Some((state, size)))
}
