//! The raw installed unit file: the one preimage of the `fragment` commitment.
//!
//! The bytes are read through descriptors, one component at a time, from a root the caller
//! names. Every directory on the way and the file itself must be owned by the expected user
//! and writable by nobody else; a link anywhere, a non-regular file, a second hard link, a
//! size outside `1..=64 KiB` or a file that changed while it was read refuses. Nothing is
//! parsed, merged with drop-ins or normalized: the caller hashes exactly what was read
//! ([`briqyard_api::execution::sealed::preimage::fragment_digest`]). Which path is the unit's
//! FragmentPath, and that no drop-in or alias exists, is the service manager's to prove; this
//! reader is only the byte source and refuses to guess either.

use super::OwnerError;
use briqyard_api::execution::sealed::{inputs::Path, preimage::MAX_FRAGMENT_BYTES};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

fn io(operation: &'static str) -> impl Fn(std::io::Error) -> OwnerError {
    move |source| OwnerError::Io { operation, source }
}

fn open_at(parent: &OwnedFd, name: &str, flags: libc::c_int) -> Result<OwnedFd, OwnerError> {
    let name = CString::new(name).map_err(|_| OwnerError::Refused("path component"))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io("open a unit path component")(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn private(file: &File, owner: u32, directory: bool) -> Result<std::fs::Metadata, OwnerError> {
    let stat = file
        .metadata()
        .map_err(io("inspect a unit path component"))?;
    let kind_ok = if directory {
        stat.is_dir()
    } else {
        stat.is_file()
    };
    if !kind_ok || stat.uid() != owner || stat.mode() & 0o022 != 0 {
        return Err(OwnerError::Refused(
            "unit path is not owned and closed to other writers",
        ));
    }
    Ok(stat)
}

/// The exact bytes of the regular file `path` below `root`. `root` is the directory the
/// walk starts from (`/` in production) and is checked like every other directory.
pub fn read_fragment(
    root: &std::path::Path,
    path: &Path,
    owner: u32,
) -> Result<Vec<u8>, OwnerError> {
    let root_dir = std::fs::File::open(root).map_err(io("open the unit path root"))?;
    let mut directory: OwnedFd = root_dir.into();
    private(
        &File::from(
            directory
                .try_clone()
                .map_err(io("duplicate a descriptor"))?,
        ),
        owner,
        true,
    )?;
    let components: Vec<&str> = path.as_str().split('/').skip(1).collect();
    let (name, parents) = components
        .split_last()
        .ok_or(OwnerError::Refused("unit path has no file"))?;
    for component in parents {
        let next = open_at(&directory, component, libc::O_RDONLY | libc::O_DIRECTORY)?;
        private(
            &File::from(next.try_clone().map_err(io("duplicate a descriptor"))?),
            owner,
            true,
        )?;
        directory = next;
    }
    let file = File::from(open_at(
        &directory,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?);
    let before = private(&file, owner, false)?;
    if before.nlink() != 1 || before.len() == 0 || before.len() > MAX_FRAGMENT_BYTES as u64 {
        return Err(OwnerError::Refused(
            "unit file is not one bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(MAX_FRAGMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io("read the unit file"))?;
    let after = file.metadata().map_err(io("inspect the unit file"))?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ino() != before.ino()
    {
        return Err(OwnerError::Refused("unit file changed while it was read"));
    }
    Ok(bytes)
}
