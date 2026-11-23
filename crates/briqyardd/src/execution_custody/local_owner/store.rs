//! The durable side of the active attempt: one private file, replaced by version
//! compare-and-set under an advisory lock, with a known or an unknown commit and nothing else.

use super::attempt::Attempt;
use super::OwnerError;
use briqyard_api::execution::sealed::canonical::{decode, encode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) const ROOT: &str = "/var/lib/briqyard/sealed-owner/v1";
const ACTIVE: &str = "active.json";
const TEMPORARY: &str = "active.json.tmp";
const LOCK: &str = "lock";
const MAX_FILE: u64 = 64 * 1024;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fail {
    AfterTemporary,
    AfterFileSync,
    AfterRename,
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL: std::cell::Cell<Option<Fail>> = const { std::cell::Cell::new(None) };
}

pub struct Store {
    root: PathBuf,
    owner: u32,
}

/// The held advisory lock; dropping it releases the lock.
pub struct Guard<'a> {
    _store: &'a Store,
    _file: File,
    exclusive: bool,
}

impl Guard<'_> {
    pub(super) fn exclusive(&self) -> bool {
        self.exclusive
    }
}

fn io(operation: &'static str) -> impl Fn(std::io::Error) -> OwnerError {
    move |source| OwnerError::Io { operation, source }
}

impl Store {
    /// The fixed root-private directory. Root only; no argument or environment selects it.
    pub(super) fn system() -> Result<Self, OwnerError> {
        crate::execution_custody::require_root("open the sealed owner store")?;
        Self::rooted_at(Path::new(ROOT), 0)
    }

    /// The directory must already exist, owned by `owner`, private, and not a link.
    pub(crate) fn rooted_at(root: &Path, owner: u32) -> Result<Self, OwnerError> {
        let stat = std::fs::symlink_metadata(root).map_err(io("inspect the sealed owner store"))?;
        if !stat.is_dir() || stat.uid() != owner || stat.mode() & 0o077 != 0 {
            return Err(OwnerError::Refused(
                "sealed owner store is not a private directory",
            ));
        }
        Ok(Self {
            root: root.to_owned(),
            owner,
        })
    }

    pub(super) fn lock(&self, exclusive: bool) -> Result<Guard<'_>, OwnerError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join(LOCK))
            .map_err(io("open the sealed owner lock"))?;
        let stat = file
            .metadata()
            .map_err(io("inspect the sealed owner lock"))?;
        if stat.uid() != self.owner || stat.mode() & 0o077 != 0 || stat.nlink() != 1 {
            return Err(OwnerError::Refused("sealed owner lock is not private"));
        }
        let mode = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), mode) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(io("take the sealed owner lock")(error));
            }
        }
        Ok(Guard {
            _store: self,
            _file: file,
            exclusive,
        })
    }

    pub(super) fn load(&self, _guard: &Guard<'_>) -> Result<Option<Attempt>, OwnerError> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join(ACTIVE))
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io("open the active attempt")(error)),
        };
        let stat = file.metadata().map_err(io("inspect the active attempt"))?;
        if stat.uid() != self.owner
            || stat.mode() & 0o077 != 0
            || stat.nlink() != 1
            || stat.len() > MAX_FILE
        {
            return Err(OwnerError::Refused("active attempt file is not private"));
        }
        let mut bytes = Vec::with_capacity(stat.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(io("read the active attempt"))?;
        Ok(Some(decode::<Attempt>(&bytes)?))
    }

    /// Replace the attempt iff the file still holds exactly `expected` (no file when `None`)
    /// and `next` is its one successor. `Ok` is a known commit: file and parent are synced and
    /// the bytes read back. After the rename a failure is `CommitUnknown`, never a retry.
    pub(super) fn commit(
        &self,
        guard: &Guard<'_>,
        expected: Option<&Attempt>,
        next: &Attempt,
    ) -> Result<(), OwnerError> {
        if !guard.exclusive() {
            return Err(OwnerError::Refused("commit needs the exclusive lock"));
        }
        if self.load(guard)?.as_ref() != expected {
            return Err(OwnerError::Stale);
        }
        let succeeds = match expected {
            None => next.version.get() == 1,
            Some(current) => {
                next.version.get() == current.version.get() + 1
                    && next.x == current.x
                    && next.plan == current.plan
                    && next.generation == current.generation
            }
        };
        if !succeeds {
            return Err(OwnerError::Refused(
                "an attempt only advances by one version",
            ));
        }
        let bytes = encode(next)?;
        let temporary = self.root.join(TEMPORARY);
        let _ = std::fs::remove_file(&temporary);
        let before_rename = || -> Result<(), std::io::Error> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            #[cfg(test)]
            if FAIL.get() == Some(Fail::AfterTemporary) {
                return Err(std::io::Error::other(
                    "injected failure after the temporary file",
                ));
            }
            file.sync_all()?;
            #[cfg(test)]
            if FAIL.get() == Some(Fail::AfterFileSync) {
                return Err(std::io::Error::other(
                    "injected failure after the file sync",
                ));
            }
            Ok(())
        };
        if let Err(source) = before_rename() {
            let _ = std::fs::remove_file(&temporary);
            return Err(io("write the active attempt")(source));
        }
        if let Err(source) = std::fs::rename(&temporary, self.root.join(ACTIVE)) {
            let _ = std::fs::remove_file(&temporary);
            return Err(io("replace the active attempt")(source));
        }
        let after_rename = || -> Result<(), std::io::Error> {
            #[cfg(test)]
            if FAIL.get() == Some(Fail::AfterRename) {
                return Err(std::io::Error::other("injected failure after the rename"));
            }
            File::open(&self.root)?.sync_all()
        };
        if after_rename().is_err() {
            return Err(OwnerError::CommitUnknown);
        }
        match self.load(guard) {
            Ok(Some(read)) if read == *next => Ok(()),
            _ => Err(OwnerError::CommitUnknown),
        }
    }
}
