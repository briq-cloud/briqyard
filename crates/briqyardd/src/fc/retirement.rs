//! Checked, nonrecursive removal of one stopped VMM's canonical cgroup.

use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

/// A held leaf, never a record-supplied path. The lifecycle owner retains this through
/// validation and removes it synchronously before forgetting the machine.
pub(super) struct Leaf {
    root: File,
    root_path: std::path::PathBuf,
    parent: File,
    dir: File,
    name: CString,
    original: String,
    owner: u32,
    memberships: Vec<super::recovery::fs::Membership>,
}

fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn directory(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: the descriptor is held, and name is a single checked component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn same(a: &File, b: &File) -> io::Result<bool> {
    let (a, b) = (a.metadata()?, b.metadata()?);
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

fn name(id: &str) -> io::Result<CString> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(invalid());
    }
    let encoded = super::fc_id(id);
    // Firecracker's command-line decoder must recover the original identity exactly.
    // Otherwise two original IDs could address the same kernel leaf.
    if encoded.replacen("m-", "m_", 1) != id {
        return Err(invalid());
    }
    CString::new(encoded).map_err(|_| invalid())
}

fn open_ancestry(root: &Path) -> io::Result<File> {
    let mut root_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in root.components() {
        use std::{os::unix::ffi::OsStrExt, path::Component};
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                root_fd = directory(
                    &root_fd,
                    &CString::new(part.as_bytes()).map_err(|_| invalid())?,
                )?;
            }
            _ => return Err(invalid()),
        }
    }
    Ok(root_fd)
}

impl Leaf {
    #[cfg(target_os = "linux")]
    pub(super) fn capture(id: &str) -> io::Result<Option<Self>> {
        let held = Self::open_owned(Path::new("/sys/fs/cgroup"), id, 0)?;
        if let Some(leaf) = &held {
            let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
            if unsafe { libc::fstatfs(leaf.root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
                return Err(invalid());
            }
        }
        Ok(held)
    }

    #[cfg(test)]
    fn open(root: &Path, id: &str) -> io::Result<Option<Self>> {
        Self::open_owned(&root.canonicalize()?, id, unsafe { libc::geteuid() })
    }

    fn open_owned(root: &Path, id: &str, owner: u32) -> io::Result<Option<Self>> {
        let name = name(id)?;
        let root_file = open_ancestry(root)?;
        let root_path = root.to_path_buf();
        let root = root_file;
        let expected = super::recovery::fs::Owner {
            uid: owner,
            gid: if owner == 0 {
                0
            } else {
                root.metadata()?.gid()
            },
        };
        let mut memberships = vec![super::recovery::fs::Membership::capture(&root, expected)?];
        let parent = match directory(&root, c"firecracker") {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        memberships.push(super::recovery::fs::Membership::capture(&parent, expected)?);
        let dir = match directory(&parent, &name) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        memberships.push(super::recovery::fs::Membership::capture(&dir, expected)?);
        for directory in [&root, &parent, &dir] {
            let metadata = directory.metadata()?;
            if metadata.uid() != owner
                || metadata.gid() != expected.gid
                || metadata.mode() & 0o022 != 0
            {
                return Err(invalid());
            }
        }
        Ok(Some(Self {
            root,
            root_path,
            parent,
            dir,
            name,
            original: id.into(),
            owner,
            memberships,
        }))
    }

    fn read(&self, name: &CStr) -> io::Result<String> {
        // SAFETY: static control filename, held directory, no symlink following.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut text = String::new();
        file.take(4097).read_to_string(&mut text)?;
        if text.len() > 4096 {
            return Err(invalid());
        }
        Ok(text)
    }

    fn check_shape(&self, id: &str) -> io::Result<()> {
        for guard in &self.memberships {
            guard.check()?;
        }
        if id != self.original || name(id)? != self.name {
            return Err(invalid());
        }
        for directory in [&self.root, &self.parent, &self.dir] {
            let metadata = directory.metadata()?;
            if metadata.uid() != self.owner || metadata.mode() & 0o022 != 0 {
                return Err(invalid());
            }
        }
        if !same(&open_ancestry(&self.root_path)?, &self.root)? {
            return Err(invalid());
        }
        let parent = directory(&self.root, c"firecracker")?;
        if !same(&parent, &self.parent)? || !same(&directory(&parent, &self.name)?, &self.dir)? {
            return Err(invalid());
        }
        // Open a fresh directory description: duplicated descriptors share enumeration offsets.
        let scan = directory(&self.dir, c".")?;
        // SAFETY: fdopendir takes ownership of this newly duplicated descriptor.
        use std::os::fd::IntoRawFd;
        let raw = scan.into_raw_fd();
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe {
                libc::close(raw);
            }
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            loop {
                // SAFETY: stream remains open until this loop ends.
                #[cfg(target_os = "linux")]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                #[cfg(target_os = "macos")]
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(0) {
                        return Err(error);
                    }
                    break;
                }
                let component = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                if component == c"." || component == c".." {
                    continue;
                }
                // Any directory or symlink is unresolved ownership; never descend.
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe {
                    libc::fstatat(
                        self.dir.as_raw_fd(),
                        component.as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                let stat = unsafe { stat.assume_init() };
                if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                    return Err(invalid());
                }
            }
            Ok(())
        })();
        unsafe {
            libc::closedir(stream);
        }
        result?;
        for guard in &self.memberships {
            guard.check()?;
        }
        Ok(())
    }

    pub(super) fn inventory(&self, id: &str) -> io::Result<Vec<u32>> {
        self.check_shape(id)?;
        let members = super::recovery::fs::pids(&self.read(c"cgroup.procs")?)?;
        let events = self.read(c"cgroup.events")?;
        let value = |key: &str| {
            let values: Vec<_> = events
                .lines()
                .filter_map(|line| line.split_once(' '))
                .filter(|(k, _)| *k == key)
                .collect();
            if values.len() != 1 {
                return None;
            }
            values[0].1.trim().parse::<u32>().ok()
        };
        if value("frozen") != Some(0) || value("populated") != Some(u32::from(!members.is_empty()))
        {
            return Err(invalid());
        }
        Ok(members)
    }

    pub(super) fn check(&self, id: &str) -> io::Result<()> {
        if self.inventory(id)?.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    pub(super) fn final_usage(&self, id: &str) -> io::Result<super::CgroupUse> {
        self.check(id)?;
        let cpu = self.read(c"cpu.stat")?;
        let values: Vec<_> = cpu
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter(|(key, _)| *key == "usage_usec")
            .collect();
        if values.len() != 1 {
            return Err(invalid());
        }
        let cpu_usec = values[0].1.trim().parse().map_err(|_| invalid())?;
        let memory_bytes = self
            .read(c"memory.current")?
            .trim()
            .parse()
            .map_err(|_| invalid())?;
        let events = self.read(c"memory.events.local")?;
        let value = |key: &str| -> io::Result<u64> {
            let values: Vec<_> = events
                .lines()
                .filter_map(|line| line.split_once(' '))
                .filter(|(name, _)| *name == key)
                .collect();
            if values.len() != 1 {
                return Err(invalid());
            }
            values[0].1.trim().parse().map_err(|_| invalid())
        };
        let (oom, killed, group_killed) =
            (value("oom")?, value("oom_kill")?, value("oom_group_kill")?);
        // These are final local totals, not fabricated per-incarnation deltas. The exit
        // watcher separately records a delta only when it captured a valid baseline.
        tracing::info!(
            machine = id,
            oom_total = oom,
            oom_kill_total = killed,
            oom_group_kill_total = group_killed,
            "final VMM local memory events"
        );
        self.check(id)?;
        Ok(super::CgroupUse {
            cpu_usec,
            memory_bytes,
        })
    }

    /// Caller must first establish exact process death and capture OOM/final usage.
    /// A failure keeps this leaf and the machine's durable destroying record available.
    pub(super) fn remove(self, id: &str) -> io::Result<()> {
        self.check(id)?;
        if !same(&open_ancestry(&self.root_path)?, &self.root)? {
            return Err(invalid());
        }
        let parent = directory(&self.root, c"firecracker")?;
        if !same(&parent, &self.parent)? || !same(&directory(&parent, &self.name)?, &self.dir)? {
            return Err(invalid());
        }
        // SAFETY: one checked component below the held parent; never recursive.
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
