//! Strict publication for startup metadata. Legacy record writers keep their old contract.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    ParentOpen,
    TemporaryCreate,
    Write,
    FileSync,
    Rename,
    ParentSync,
    ConfirmOpen,
    ConfirmSync,
    ConfirmCheck,
    DirectoryCreate,
    DirectoryMode,
    DirectorySync,
    DirectoryParentSync,
}

/// Rename errors are uncertain too: a filesystem may perform a replacement then report an
/// error. No caller may interpret uncertainty as permission to roll back resource ownership.
#[derive(Debug, thiserror::Error)]
pub(super) enum PublicationError {
    #[error("publication not attempted at {stage:?}: {source}")]
    NotPublished { stage: Stage, source: io::Error },
    #[error("publication uncertain at {stage:?}: {source}")]
    Uncertain { stage: Stage, source: io::Error },
    #[error("publication confirmation conflicts with the current target")]
    Conflict,
}

/// Evidence of the completed file and directory barriers, not just equal visible bytes.
#[derive(Debug)]
pub(super) struct Durable;

type Check = dyn Fn(Stage, &Path) -> io::Result<()> + Send + Sync;

#[derive(Clone, Default)]
pub(super) struct Publisher {
    // Faults are scoped to this publisher/store, never process-global.
    check: Option<Arc<Check>>,
}

impl Publisher {
    #[cfg(test)]
    pub(super) fn with_check(
        check: impl Fn(Stage, &Path) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            check: Some(Arc::new(check)),
        }
    }

    fn at(&self, stage: Stage, path: &Path) -> io::Result<()> {
        self.check
            .as_ref()
            .map_or(Ok(()), |check| check(stage, path))
    }

    fn directory(&self, path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    /// The owner must serialize publication and confirmation for the same target. Exclusive
    /// random temporary names prevent clobbering another writer, but are not compare-and-swap.
    pub(super) fn publish(&self, path: &Path, bytes: &[u8]) -> Result<Durable, PublicationError> {
        let before = |stage, source| PublicationError::NotPublished { stage, source };
        let after = |stage, source| PublicationError::Uncertain { stage, source };
        let parent = path
            .parent()
            .ok_or_else(|| before(Stage::ParentOpen, io::Error::other("no parent")))?;
        self.at(Stage::ParentOpen, parent)
            .map_err(|e| before(Stage::ParentOpen, e))?;
        let directory = self
            .directory(parent)
            .map_err(|e| before(Stage::ParentOpen, e))?;
        let temporary = parent.join(format!(".publish-{:032x}.tmp", rand::random::<u128>()));
        self.at(Stage::TemporaryCreate, &temporary)
            .map_err(|e| before(Stage::TemporaryCreate, e))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|e| before(Stage::TemporaryCreate, e))?;
        // Only a successfully exclusively created temporary belongs to this invocation.
        let temporary_id = identity_of(&file).map_err(|e| before(Stage::TemporaryCreate, e))?;
        let result = (|| {
            self.at(Stage::Write, &temporary)
                .map_err(|e| before(Stage::Write, e))?;
            file.write_all(bytes).map_err(|e| before(Stage::Write, e))?;
            self.at(Stage::FileSync, &temporary)
                .map_err(|e| before(Stage::FileSync, e))?;
            file.sync_all().map_err(|e| before(Stage::FileSync, e))?;
            drop(file);
            self.at(Stage::Rename, &temporary)
                .map_err(|e| after(Stage::Rename, e))?;
            std::fs::rename(&temporary, path).map_err(|e| after(Stage::Rename, e))?;
            self.at(Stage::ParentSync, parent)
                .map_err(|e| after(Stage::ParentSync, e))?;
            directory
                .sync_all()
                .map_err(|e| after(Stage::ParentSync, e))?;
            Ok(Durable)
        })();
        // Never remove the target, including after a successful or uncertain rename.
        if std::fs::symlink_metadata(&temporary)
            .is_ok_and(|metadata| metadata.is_file() && identity(&metadata) == temporary_id)
        {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn regular(&self, path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("target is not a regular file"));
        }
        Ok(file)
    }

    /// Confirm the exact intended bytes without replacing anything. Both the descriptor and
    /// the pathname must still name the same inode after the durability barriers.
    pub(super) fn confirm(
        &self,
        path: &Path,
        expected: &[u8],
    ) -> Result<Durable, PublicationError> {
        let uncertain = |stage, source| PublicationError::Uncertain { stage, source };
        let parent = path
            .parent()
            .ok_or_else(|| uncertain(Stage::ParentOpen, io::Error::other("no parent")))?;
        self.at(Stage::ParentOpen, parent)
            .map_err(|e| uncertain(Stage::ParentOpen, e))?;
        let directory = self
            .directory(parent)
            .map_err(|e| uncertain(Stage::ParentOpen, e))?;
        self.at(Stage::ConfirmOpen, path)
            .map_err(|e| uncertain(Stage::ConfirmOpen, e))?;
        let mut file = self
            .regular(path)
            .map_err(|e| uncertain(Stage::ConfirmOpen, e))?;
        let identity = identity(
            &file
                .metadata()
                .map_err(|e| uncertain(Stage::ConfirmOpen, e))?,
        );
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)
            .map_err(|e| uncertain(Stage::ConfirmOpen, e))?;
        if actual != expected {
            return Err(PublicationError::Conflict);
        }
        self.at(Stage::ConfirmSync, path)
            .map_err(|e| uncertain(Stage::ConfirmSync, e))?;
        file.sync_all()
            .map_err(|e| uncertain(Stage::ConfirmSync, e))?;
        self.at(Stage::ParentSync, parent)
            .map_err(|e| uncertain(Stage::ParentSync, e))?;
        directory
            .sync_all()
            .map_err(|e| uncertain(Stage::ParentSync, e))?;
        self.at(Stage::ConfirmCheck, path)
            .map_err(|e| uncertain(Stage::ConfirmCheck, e))?;
        let mut current = self
            .regular(path)
            .map_err(|e| uncertain(Stage::ConfirmCheck, e))?;
        let current_id = identity_of(&current).map_err(|e| uncertain(Stage::ConfirmCheck, e))?;
        actual.clear();
        current
            .read_to_end(&mut actual)
            .map_err(|e| uncertain(Stage::ConfirmCheck, e))?;
        if identity != current_id
            || actual != expected
            || identity_of(&file).map_err(|e| uncertain(Stage::ConfirmCheck, e))? != identity
        {
            return Err(PublicationError::Conflict);
        }
        Ok(Durable)
    }

    /// Publish every ancestor entry, including existing ones on a retry. Only new ancestors
    /// and the requested Store directory get mode 0700; existing ancestors keep their mode.
    pub(super) fn private_directory(&self, path: &Path) -> io::Result<()> {
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(io::Error::other("Store directory is a symlink"));
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut existing = absolute.as_path();
        let mut missing = Vec::new();
        while !existing.try_exists()? {
            missing.push(
                existing
                    .file_name()
                    .ok_or_else(|| io::Error::other("no directory name"))?
                    .to_os_string(),
            );
            existing = existing
                .parent()
                .ok_or_else(|| io::Error::other("no existing ancestor"))?;
        }
        // Resolve platform aliases in existing ancestors, not a symlink at the Store target.
        let mut target = std::fs::canonicalize(existing)?;
        for name in missing.iter().rev() {
            target.push(name);
        }
        let mut chain: Vec<PathBuf> = target.ancestors().map(Path::to_path_buf).collect();
        chain.reverse();
        for directory in chain {
            self.publish_directory(&directory, directory == target)?;
        }
        Ok(())
    }

    /// The parent is already initialized by Store::open; publish only this direct child.
    pub(super) fn private_child(&self, path: &Path) -> io::Result<()> {
        self.publish_directory(path, true)
    }

    fn publish_directory(&self, directory: &Path, private: bool) -> io::Result<()> {
        self.at(Stage::DirectoryCreate, directory)?;
        let created = match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e),
        };
        let opened = self.directory(directory)?;
        if created || private {
            self.at(Stage::DirectoryMode, directory)?;
            opened.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }
        self.at(Stage::DirectorySync, directory)?;
        opened.sync_all()?;
        if let Some(parent) = directory.parent() {
            let parent_fd = self.directory(parent)?;
            self.at(Stage::DirectoryParentSync, directory)?;
            parent_fd.sync_all()?;
        }
        Ok(())
    }

    /// An initialization lock is never unlinked: all initializers must lock the same inode.
    pub(super) fn host_id(
        &self,
        path: &Path,
        make: impl FnOnce() -> String,
    ) -> anyhow::Result<String> {
        let lock_path = path.with_file_name("host-id.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&lock_path)?;
        if !lock.metadata()?.is_file() {
            anyhow::bail!("host identity lock is not a regular file");
        }
        // SAFETY: flock borrows a valid owned descriptor; dropping it releases the lock.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let lock_id = identity_of(&lock)?;
        if identity(&std::fs::symlink_metadata(&lock_path)?) != lock_id {
            anyhow::bail!("host identity lock changed");
        }
        let id = match self.regular(path) {
            Ok(mut file) => {
                let mut id = String::new();
                file.read_to_string(&mut id)?;
                id
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let id = make();
                self.publish(path, id.as_bytes())?;
                id
            }
            Err(e) => return Err(e.into()),
        };
        self.confirm(path, id.as_bytes())?;
        Ok(id)
    }
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn identity_of(file: &File) -> io::Result<(u64, u64)> {
    Ok(identity(&file.metadata()?))
}

#[cfg(test)]
mod tests;
