//! Bind the configured jailer to the source-audited attach-before-fork lineage.
use super::{
    build::{approved, hash},
    fs::{invalid, Dir},
};
use anyhow::Context;
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(in crate::fc) struct Jailer {
    dir: Dir,
    name: std::ffi::CString,
    file: File,
    path: PathBuf,
    stamp: (u64, i64, i64, i64, i64),
    digest: [u8; 32],
}
pub(in crate::fc) struct LaunchExecutable {
    file: File,
    configured: PathBuf,
}
impl LaunchExecutable {
    pub(in crate::fc) fn program(&self, configured: &Path) -> io::Result<PathBuf> {
        use std::os::fd::AsRawFd;
        if configured != self.configured {
            return Err(invalid());
        }
        let metadata = self.file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid());
        }
        approved(&hash(&self.file)?, std::env::consts::ARCH)?;
        Ok(format!("/proc/self/fd/{}", self.file.as_raw_fd()).into())
    }
}
impl Jailer {
    #[cfg(target_os = "linux")]
    pub(super) async fn verify(path: &Path, vmm: &str) -> anyhow::Result<Self> {
        use std::{
            io::Read,
            os::{fd::AsRawFd, unix::ffi::OsStrExt},
        };
        let dir = Dir::absolute(path.parent().ok_or_else(invalid)?)?;
        dir.owned(super::fs::Owner::ROOT, false)?;
        let name = std::ffi::CString::new(path.file_name().ok_or_else(invalid)?.as_bytes())?;
        let mut file = dir.open(&name, libc::O_RDONLY, 0)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || m.mode() & 0o111 == 0
            || m.len() > 64 << 20
        {
            return Err(invalid().into());
        }
        let mut magic = [0; 4];
        Read::read_exact(&mut file, &mut magic)?;
        if magic != *b"\x7fELF" {
            return Err(invalid().into());
        }
        let digest = hash(&file)?;
        approved(&digest, std::env::consts::ARCH)
            .context("configured jailer is not an approved attach-before-fork build")?;
        let provenance = Self {
            dir,
            name,
            file,
            path: path.into(),
            stamp: (
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            ),
            digest,
        };
        // Execute the held ELF inode. CLOEXEC closes its descriptor only after the kernel
        // has opened the executable; no pathname re-resolution chooses another jailer.
        let executable = format!("/proc/self/fd/{}", provenance.file.as_raw_fd());
        let text =
            super::unit::output(std::ffi::OsStr::new(&executable), &["--version"], 1024).await?;
        super::unit::jailer_version(&text, vmm)?;
        provenance.check()?;
        Ok(provenance)
    }
    pub(in crate::fc) fn lease(&self) -> io::Result<LaunchExecutable> {
        self.check()?;
        Ok(LaunchExecutable {
            file: self.file.try_clone()?,
            configured: self.path.clone(),
        })
    }
    pub(in crate::fc) fn check(&self) -> io::Result<()> {
        if !super::fs::same(&self.dir.open(&self.name, libc::O_RDONLY, 0)?, &self.file)?
            || !self
                .dir
                .same(&Dir::absolute(self.path.parent().ok_or_else(invalid)?)?)?
        {
            return Err(invalid());
        }
        let m = self.file.metadata()?;
        if (
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ) != self.stamp
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
        {
            return Err(invalid());
        }
        if hash(&self.file)? != self.digest {
            return Err(invalid());
        }
        Ok(())
    }
}
