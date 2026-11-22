//! The one native profile of the ordinary authority signing key (interface v3.2).
//!
//! Private material only ever crosses as a sealed, read-only anonymous file; this module owns
//! its exact encoding and the checks of such a descriptor. It never hashes, logs, names or
//! serializes the private bytes, and it supplies no signing method of its own. Closing a
//! descriptor or dropping a buffer does not revoke other copies or guarantee physical erasure.

use nix::libc;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use thiserror::Error;
use zeroize::Zeroizing;

/// 16-byte fixed prefix, 32 seed bytes, `812100`, 32 public bytes, nothing else.
pub const PKCS8_BYTES: usize = 83;
/// Environment key of logical authority slot 15 in the guard and the candidate.
pub const FD_ENV: &str = "BRIQ_SEALED_ORDINARY_AUTHORITY_KEY_FD";

const PREFIX: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PUBLIC_WRAPPER: [u8; 3] = [0x81, 0x21, 0x00];
const SEAL_MASK: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("ordinary authority key is not the exact PKCS#8 v2 profile")]
    Profile,
    #[error("ordinary authority key descriptor is missing, aliased or malformed")]
    Descriptor,
    #[error("sealed ordinary authority key has unexpected metadata")]
    Metadata,
    #[error("ordinary authority key {operation} failed with errno {errno}")]
    Io { operation: &'static str, errno: i32 },
}

fn io(operation: &'static str) -> KeyError {
    KeyError::Io {
        operation,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

/// A key that passed the exact profile. It has no signing method: only the guarded issuer
/// takes it, after comparing its derived public key with the independently pinned identity.
pub struct OrdinaryAuthorityKey(Ed25519KeyPair);

impl std::fmt::Debug for OrdinaryAuthorityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OrdinaryAuthorityKey(..)")
    }
}

impl OrdinaryAuthorityKey {
    /// `ring` checks the version, algorithm and that the embedded public key belongs to the
    /// seed; the explicit constraints reject every other encoding it would still accept.
    pub fn from_profile(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != PKCS8_BYTES || bytes[..16] != PREFIX || bytes[48..51] != PUBLIC_WRAPPER {
            return Err(KeyError::Profile);
        }
        let pair = Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| KeyError::Profile)?;
        if pair.public_key().as_ref() != &bytes[51..] {
            return Err(KeyError::Profile);
        }
        Ok(Self(pair))
    }

    /// The public key derived from the actual private key, never an advertised value.
    pub fn public(&self) -> [u8; 32] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public keys have 32 bytes")
    }

    pub(super) fn into_pair(self) -> Ed25519KeyPair {
        self.0
    }
}

/// The descriptor must be an immutable anonymous regular file of exactly the profile length,
/// mode 0400, opened read-only, with every seal. Returns its (device, inode) identity.
pub fn check_sealed(fd: BorrowedFd<'_>) -> Result<(u64, u64), KeyError> {
    let raw = fd.as_raw_fd();
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(raw, stat.as_mut_ptr()) } < 0 {
        return Err(io("stat"));
    }
    let stat = unsafe { stat.assume_init() };
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io("read access flags"));
    }
    let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
    let mut fs = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(raw, fs.as_mut_ptr()) } < 0 {
        return Err(io("stat filesystem"));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 0
        || stat.st_size != PKCS8_BYTES as i64
        || stat.st_mode & 0o7777 != 0o400
        || flags & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
        || seals < 0
        || seals & SEAL_MASK != SEAL_MASK
        || unsafe { fs.assume_init() }.f_type != libc::TMPFS_MAGIC
    {
        return Err(KeyError::Metadata);
    }
    Ok((stat.st_dev, stat.st_ino))
}

/// Offset-independent exact read of a checked descriptor; the buffer is cleared on return.
pub fn read_sealed(fd: BorrowedFd<'_>) -> Result<OrdinaryAuthorityKey, KeyError> {
    check_sealed(fd)?;
    let mut bytes = Zeroizing::new([0_u8; PKCS8_BYTES + 1]);
    let mut filled = 0;
    while filled < bytes.len() {
        let read = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                bytes[filled..].as_mut_ptr().cast(),
                bytes.len() - filled,
                filled as libc::off_t,
            )
        };
        match read {
            0 => break,
            n if n > 0 => filled += n as usize,
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
            _ => return Err(io("read")),
        }
    }
    if filled != PKCS8_BYTES {
        return Err(KeyError::Metadata);
    }
    OrdinaryAuthorityKey::from_profile(&bytes[..PKCS8_BYTES])
}

/// An exclusively owned, already close-on-exec transfer descriptor. Dropping it closes it.
pub struct SealedKeyFd(OwnedFd);

impl SealedKeyFd {
    /// Takes ownership of `raw`, the slot the guard named for logical index 15, and sets
    /// close-on-exec before anything else. `others` is every other artifact's actual slot:
    /// (listeners included) a slot, or an open file, shared with any of them is refused. Every refusal closes the
    /// slot except one that merely names another artifact's.
    pub fn claim(raw: RawFd, others: &[RawFd]) -> Result<Self, KeyError> {
        if raw < 3 || others.contains(&raw) {
            return Err(KeyError::Descriptor);
        }
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(KeyError::Descriptor);
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let identity = check_sealed(std::os::fd::AsFd::as_fd(&owned))?;
        for other in others {
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(*other, stat.as_mut_ptr()) } < 0 {
                return Err(KeyError::Descriptor);
            }
            let stat = unsafe { stat.assume_init() };
            if (stat.st_dev, stat.st_ino) == identity {
                return Err(KeyError::Descriptor);
            }
        }
        Ok(Self(owned))
    }

    /// Reads and validates the key, then closes the transfer descriptor.
    pub fn read(self) -> Result<OrdinaryAuthorityKey, KeyError> {
        read_sealed(std::os::fd::AsFd::as_fd(&self.0))
    }
}

/// The candidate's only entry: the guard's environment value for logical index 15 and the
/// actual slots of the other inherited artifacts. A missing value is an error whatever other
/// key source exists; there is no path or default.
pub fn adopt_inherited(
    value: Option<&str>,
    others: &[RawFd],
) -> Result<OrdinaryAuthorityKey, KeyError> {
    let value = value.ok_or(KeyError::Descriptor)?;
    let raw: RawFd = value.parse().map_err(|_| KeyError::Descriptor)?;
    if raw.to_string() != value {
        return Err(KeyError::Descriptor);
    }
    SealedKeyFd::claim(raw, others)?.read()
}

#[cfg(test)]
mod tests;
