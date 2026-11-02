//! Bounded directory-relative reads for startup identity and supervision.
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};

#[derive(Clone, Copy)]
pub(in crate::fc) struct Owner {
    pub(in crate::fc) uid: u32,
    pub(in crate::fc) gid: u32,
}
impl Owner {
    #[cfg(target_os = "linux")]
    pub(super) const ROOT: Self = Self { uid: 0, gid: 0 };
}

pub(super) fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

pub(super) struct Dir(pub(super) File);
impl Dir {
    pub(super) fn absolute(path: &Path) -> io::Result<Self> {
        let mut dir = Self(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")?,
        );
        for component in path.components() {
            use std::os::unix::ffi::OsStrExt;
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    dir = dir.child(&CString::new(name.as_bytes()).map_err(|_| invalid())?)?
                }
                _ => return Err(invalid()),
            }
        }
        Ok(dir)
    }
    pub(super) fn child(&self, name: &CStr) -> io::Result<Self> {
        self.open(name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map(Self)
    }
    pub(super) fn open(&self, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub(super) fn bytes(&self, name: &CStr, cap: u64) -> io::Result<Vec<u8>> {
        let file = self.open(name, libc::O_RDONLY, 0)?;
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub(super) fn text(&self, name: &CStr, cap: u64) -> io::Result<String> {
        String::from_utf8(self.bytes(name, cap)?).map_err(|_| invalid())
    }
    pub(super) fn owned(&self, owner: Owner, private: bool) -> io::Result<()> {
        let m = self.0.metadata()?;
        if m.uid() != owner.uid
            || m.gid() != owner.gid
            || m.mode() & 0o022 != 0
            || (private && m.mode() & 0o777 != 0o700)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn same(&self, other: &Self) -> io::Result<bool> {
        same(&self.0, &other.0)
    }
    pub(super) fn children(&self, cap: usize) -> io::Result<Vec<CString>> {
        let fresh = self.child(c".")?;
        use std::os::fd::IntoRawFd;
        let fd = fresh.0.into_raw_fd();
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut names = Vec::new();
            loop {
                #[cfg(target_os = "linux")]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                #[cfg(target_os = "macos")]
                unsafe {
                    *libc::__error() = 0;
                }
                let e = unsafe { libc::readdir(stream) };
                if e.is_null() {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() != Some(0) {
                        return Err(err);
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
                if name == c"." || name == c".." {
                    continue;
                }
                if names.len() == cap {
                    return Err(invalid());
                }
                names.push(name.to_owned());
            }
            Ok(names)
        })();
        unsafe {
            libc::closedir(stream);
        }
        result
    }
    pub(super) fn regular(&self, name: &CStr) -> io::Result<bool> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFREG)
    }
    pub(super) fn has_directories(&self) -> io::Result<bool> {
        for name in self.children(4096)? {
            if !self.regular(&name)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
pub(super) fn same(a: &File, b: &File) -> io::Result<bool> {
    let (a, b) = (a.metadata()?, b.metadata()?);
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

pub(in crate::fc) fn pids(text: &str) -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for pid in text.split_whitespace() {
        let pid = pid
            .parse::<u32>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(invalid)?;
        if pids.len() == 4096 || pids.contains(&pid) {
            return Err(invalid());
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    Ok(pids)
}

/// Held membership controls: directory ownership alone does not exclude delegation.
pub(in crate::fc) struct Membership {
    dir: Dir,
    procs: File,
    threads: File,
    owner: Owner,
}
impl Membership {
    pub(in crate::fc) fn capture(dir: &File, owner: Owner) -> io::Result<Self> {
        let dir = Dir(dir.try_clone()?);
        dir.owned(owner, false)?;
        let procs = dir.open(c"cgroup.procs", libc::O_RDONLY, 0)?;
        let threads = dir.open(c"cgroup.threads", libc::O_RDONLY, 0)?;
        let guard = Self {
            dir,
            procs,
            threads,
            owner,
        };
        guard.check()?;
        Ok(guard)
    }
    pub(in crate::fc) fn check(&self) -> io::Result<()> {
        self.dir.owned(self.owner, false)?;
        for (name, held) in [
            (c"cgroup.procs", &self.procs),
            (c"cgroup.threads", &self.threads),
        ] {
            let current = self.dir.open(name, libc::O_RDONLY, 0)?;
            for file in [held, &current] {
                let m = file.metadata()?;
                if !m.is_file()
                    || m.uid() != self.owner.uid
                    || m.gid() != self.owner.gid
                    || m.mode() & 0o022 != 0
                {
                    return Err(invalid());
                }
            }
            if !same(&current, held)? {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn procs(&self) -> io::Result<Vec<u32>> {
        self.check()?;
        let result = pids(&self.dir.text(c"cgroup.procs", 65536)?)?;
        self.check()?;
        Ok(result)
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn fixture() -> (tempfile::TempDir, Dir, Owner) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        let owner = Owner {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["cgroup.procs", "cgroup.threads"] {
            fs::write(path.join(name), "").unwrap();
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let dir = Dir::absolute(&path).unwrap();
        (temp, dir, owner)
    }
    #[test]
    fn empty_inventory_does_not_authorize_writable_missing_or_foreign_membership() {
        let (temp, dir, owner) = fixture();
        Membership::capture(&dir.0, owner).unwrap().procs().unwrap();
        for name in ["cgroup.procs", "cgroup.threads"] {
            fs::set_permissions(temp.path().join(name), fs::Permissions::from_mode(0o666)).unwrap();
            assert!(Membership::capture(&dir.0, owner).is_err());
            fs::set_permissions(temp.path().join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(Membership::capture(
            &dir.0,
            Owner {
                uid: owner.uid + 1,
                gid: owner.gid
            }
        )
        .is_err());
        fs::remove_file(temp.path().join("cgroup.threads")).unwrap();
        assert!(Membership::capture(&dir.0, owner).is_err());
    }
    #[test]
    fn named_membership_replacement_symlinks_and_permission_drift_refuse() {
        let (temp, dir, owner) = fixture();
        let held = Membership::capture(&dir.0, owner).unwrap();
        fs::rename(temp.path().join("cgroup.procs"), temp.path().join("old")).unwrap();
        fs::write(temp.path().join("cgroup.procs"), "").unwrap();
        assert!(held.check().is_err());
        fs::remove_file(temp.path().join("cgroup.procs")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("old"), temp.path().join("cgroup.procs"))
            .unwrap();
        assert!(Membership::capture(&dir.0, owner).is_err());
        fs::remove_file(temp.path().join("cgroup.procs")).unwrap();
        fs::rename(temp.path().join("old"), temp.path().join("cgroup.procs")).unwrap();
        let held = Membership::capture(&dir.0, owner).unwrap();
        fs::set_permissions(
            temp.path().join("cgroup.threads"),
            fs::Permissions::from_mode(0o662),
        )
        .unwrap();
        assert!(held.check().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux root; changes only its owned temporary fixture"]
    fn root_membership_accepts_0644_and_rejects_nonroot_ownership() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run this exact fixture as root"
        );
        let (temp, dir, _) = fixture();
        let held = Membership::capture(&dir.0, Owner::ROOT).unwrap();
        held.check().unwrap();
        std::os::unix::fs::chown(temp.path().join("cgroup.procs"), Some(65534), Some(65534))
            .unwrap();
        assert!(held.check().is_err());
        assert!(Membership::capture(&dir.0, Owner::ROOT).is_err());
    }
}
