//! A permanent lock inode for the fixed machine cgroup domain, never per data directory.
use super::fs::{invalid, same, Dir, Owner};
use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};

pub(in crate::fc) struct DomainLock {
    parent: Dir,
    file: File,
    path: PathBuf,
    owner: Owner,
}
impl DomainLock {
    #[cfg(target_os = "linux")]
    pub(super) fn acquire() -> io::Result<Self> {
        Self::at(Path::new("/run"), Owner::ROOT)
    }
    fn at(base: &Path, owner: Owner) -> io::Result<Self> {
        let base_dir = Dir::absolute(base)?;
        base_dir.owned(owner, false)?;
        if unsafe { libc::mkdirat(base_dir.0.as_raw_fd(), c"briqyard".as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let parent = base_dir.child(c"briqyard")?;
        parent.owned(owner, true)?;
        let file = match parent.open(
            c"cgroup-domain.lock",
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        ) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                parent.open(c"cgroup-domain.lock", libc::O_RDWR, 0)?
            }
            Err(e) => return Err(e),
        };
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != owner.uid
            || m.gid() != owner.gid
            || m.mode() & 0o777 != 0o600
            || m.nlink() != 1
        {
            return Err(invalid());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let lock = Self {
            parent,
            file,
            path: base.join("briqyard"),
            owner,
        };
        lock.check()?;
        Ok(lock)
    }
    pub(in crate::fc) fn check(&self) -> io::Result<()> {
        let parent = Dir::absolute(&self.path)?;
        parent.owned(self.owner, true)?;
        if !parent.same(&self.parent)?
            || !same(
                &parent.open(c"cgroup-domain.lock", libc::O_RDWR, 0)?,
                &self.file,
            )?
        {
            return Err(invalid());
        }
        let m = self.file.metadata()?;
        if m.nlink() != 1
            || m.uid() != self.owner.uid
            || m.gid() != self.owner.gid
            || m.mode() & 0o777 != 0o600
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn uid() -> Owner {
        Owner {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
    #[tokio::test]
    async fn a_concurrent_restart_cannot_enter_the_same_domain() {
        use tokio::io::AsyncReadExt;
        if let Some(path) = std::env::var_os("BRIQYARD_TEST_DOMAIN_DIR") {
            let error = DomainLock::at(Path::new(&path), uid())
                .err()
                .expect("parent must hold domain lock");
            assert!(matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK)));
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().canonicalize().unwrap();
        let _held = DomainLock::at(&path, uid()).unwrap();
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fc::recovery::lock::tests::a_concurrent_restart_cannot_enter_the_same_domain",
                "--nocapture",
            ])
            .env("BRIQYARD_TEST_DOMAIN_DIR", &path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut output = Vec::new();
            stdout.take(8193).read_to_end(&mut output).await.unwrap();
            assert!(output.len() <= 8192);
            let status = child.wait().await.unwrap();
            (status, output)
        })
        .await;
        if result.is_err() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), child.wait()).await;
        }
        let (status, output) = result.expect("owned domain-lock child deadline");
        assert!(status.success());
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("1 passed; 0 failed"));
    }
    #[test]
    fn fixed_domain_serializes_different_configuration_directories_and_keeps_inode() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().canonicalize().unwrap();
        let lock = DomainLock::at(&p, uid()).unwrap();
        assert!(DomainLock::at(&p, uid()).is_err());
        let inode = lock.file.metadata().unwrap().ino();
        drop(lock);
        let next = DomainLock::at(&p, uid()).unwrap();
        assert_eq!(inode, next.file.metadata().unwrap().ino());
    }
    #[test]
    fn replaced_or_symlinked_lock_cannot_authorize_startup() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().canonicalize().unwrap();
        let lock = DomainLock::at(&p, uid()).unwrap();
        std::fs::rename(p.join("briqyard/cgroup-domain.lock"), p.join("old")).unwrap();
        std::os::unix::fs::symlink(p.join("old"), p.join("briqyard/cgroup-domain.lock")).unwrap();
        assert!(lock.check().is_err());
        assert!(DomainLock::at(&p, uid()).is_err());
    }
}
