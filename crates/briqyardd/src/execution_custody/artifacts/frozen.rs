use super::{
    access_flags, check_hash, check_length, check_syscall, create_memfd, hash_exact, io_error,
    protocol::Class, CustodyError, StageDeadline, SEALS,
};
use briqyard_api::execution::{
    ordinary_key::{self, OrdinaryAuthorityKey},
    sealed::{
        canonical::MAX_MESSAGE_BYTES,
        prim::{HexDigest, KeyBytes},
    },
};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{FileExt, MetadataExt};

pub struct FrozenArtifact {
    pub(super) file: File,
    pub(super) class: Class,
    pub(super) bytes: u64,
}

impl AsFd for FrozenArtifact {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl FrozenArtifact {
    /// The caller supplies the file already opened through its validated source locator and the
    /// independently pinned owner, length and digest. No path is selected or reopened here.
    pub fn freeze(
        source: &File,
        trusted_uid: u32,
        class: Class,
        bytes: u64,
        digest: &HexDigest,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        if matches!(
            class,
            Class::OrdinaryAuthorityKey
                | Class::Signer(_)
                | Class::TransitionServerKey
                | Class::TransitionClientKey
                | Class::DaemonApiKey
                | Class::LocalPoolKey
        ) {
            return Err(CustodyError::Protocol(
                "private keys are staged from memory, never from a file",
            ));
        }
        check_length(class, bytes)?;
        let metadata = source
            .metadata()
            .map_err(|e| io_error("stat native artifact source", e))?;
        if !metadata.is_file()
            || metadata.len() != bytes
            || metadata.uid() != trusted_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7022 != 0
            || access_flags(source.as_fd())? & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
        {
            return Err(CustodyError::Protocol(
                "unexpected or writable native artifact source",
            ));
        }
        let file = create_memfd()?;
        let mut writer = &file;
        let copied = hash_exact(source, bytes, deadline, |chunk| {
            writer
                .write_all(chunk)
                .map_err(|e| io_error("copy native artifact", e))
        })?;
        check_hash(copied, Some(digest))?;
        check_syscall(
            unsafe { libc::fchmod(file.as_raw_fd(), class.mode()) },
            "set native artifact mode",
        )?;
        check_syscall(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
            "seal native artifact",
        )?;
        let readonly = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|e| io_error("open sealed artifact read-only", e))?;
        let frozen = Self {
            file: readonly,
            class,
            bytes,
        };
        frozen.check_metadata()?;
        frozen.check_content(Some(digest), deadline)?;
        frozen.check_profile(None, deadline)?;
        Ok(frozen)
    }

    /// Stage the ordinary authority key from the provisioner's private memory into a fresh
    /// sealed descriptor; nothing is sourced from a file at the destination. The exact profile
    /// and the advertised public key are checked before any descriptor exists, no digest of
    /// the private bytes is computed, and the writable staging descriptor is closed here. The
    /// caller owns, and should clear, `bytes`.
    pub fn freeze_ordinary_key(
        bytes: &[u8],
        public: &KeyBytes,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        let key = OrdinaryAuthorityKey::from_profile(bytes)
            .map_err(|_| CustodyError::Protocol("invalid ordinary authority key"))?;
        if key.public() != *public.as_array() {
            return Err(CustodyError::Protocol(
                "ordinary authority key differs from its advertised public key",
            ));
        }
        let class = Class::OrdinaryAuthorityKey;
        let file = create_memfd()?;
        (&file)
            .write_all(bytes)
            .map_err(|e| io_error("stage ordinary authority key", e))?;
        check_syscall(
            unsafe { libc::fchmod(file.as_raw_fd(), class.mode()) },
            "set ordinary authority key mode",
        )?;
        check_syscall(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
            "seal ordinary authority key",
        )?;
        let readonly = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|e| io_error("open sealed ordinary authority key read-only", e))?;
        let frozen = Self {
            file: readonly,
            class,
            bytes: bytes.len() as u64,
        };
        frozen.check_metadata()?;
        if frozen.ordinary_key()?.public() != key.public() {
            return Err(CustodyError::Protocol(
                "sealed ordinary authority key changed",
            ));
        }
        deadline.check()?;
        Ok(frozen)
    }

    /// The validated key and nothing else: the private bytes never leave as a buffer. The
    /// caller still compares its derived public key with the independently pinned identity.
    pub fn ordinary_key(&self) -> Result<OrdinaryAuthorityKey, CustodyError> {
        if self.class != Class::OrdinaryAuthorityKey {
            return Err(CustodyError::Protocol("not the ordinary authority key"));
        }
        ordinary_key::read_sealed(self.as_fd())
            .map_err(|_| CustodyError::Protocol("invalid ordinary authority key"))
    }

    pub fn read_small(&self, deadline: StageDeadline) -> Result<Vec<u8>, CustodyError> {
        if self.class.is_secret() {
            return Err(CustodyError::Protocol(
                "secret bytes are not a readable artifact",
            ));
        }
        if self.bytes > MAX_MESSAGE_BYTES as u64 {
            return Err(CustodyError::Protocol(
                "native artifact exceeds small read bound",
            ));
        }
        let mut out = Vec::with_capacity(self.bytes as usize);
        hash_exact(&self.file, self.bytes, deadline, |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(out)
    }

    pub(super) fn check_metadata(&self) -> Result<(u64, u64), CustodyError> {
        let fd = self.as_fd();
        if self.class == Class::OrdinaryAuthorityKey {
            return ordinary_key::check_sealed(fd)
                .map_err(|_| CustodyError::Protocol("unexpected sealed native artifact metadata"));
        }
        let metadata = self
            .file
            .metadata()
            .map_err(|e| io_error("stat sealed native artifact", e))?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.len() != self.bytes
            || metadata.mode() & 0o7777 != self.class.mode()
            || access_flags(fd)? & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
        {
            return Err(CustodyError::Protocol(
                "unexpected sealed native artifact metadata",
            ));
        }
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        check_syscall(
            unsafe { libc::fstatfs(fd.as_raw_fd(), fs.as_mut_ptr()) },
            "stat native artifact filesystem",
        )?;
        let seals = check_syscall(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) },
            "read native artifact seals",
        )?;
        if unsafe { fs.assume_init() }.f_type != libc::TMPFS_MAGIC || seals & SEALS != SEALS {
            return Err(CustodyError::Protocol(
                "native artifact is not an immutable memfd",
            ));
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    pub(super) fn check_content(
        &self,
        digest: Option<&HexDigest>,
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        if self.class == Class::OrdinaryAuthorityKey {
            return deadline.check();
        }
        let hash = hash_exact(&self.file, self.bytes, deadline, |_| Ok(()))?;
        check_hash(hash, digest)?;
        if self.class == Class::Candidate {
            let mut header = [0; 4];
            if self
                .file
                .read_at(&mut header, 0)
                .map_err(|e| io_error("read native image format", e))?
                != header.len()
                || header != *b"\x7fELF"
            {
                return Err(CustodyError::Protocol(
                    "native candidate must be an ELF image",
                ));
            }
        }
        deadline.check()
    }
}
