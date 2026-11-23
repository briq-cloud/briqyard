//! Linux-only: the sealed anonymous-file descriptor that carries the ordinary authority key
//! into the candidate. Memfd seals and the tmpfs check have no equivalent elsewhere, so no
//! other platform has a way to read the key from a file.

use super::{KeyError, OrdinaryAuthorityKey, PKCS8_BYTES};
use nix::libc;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use zeroize::Zeroizing;

/// Environment key of logical authority slot 15 in the guard and the candidate.
pub const FD_ENV: &str = "BRIQ_SEALED_ORDINARY_AUTHORITY_KEY_FD";

const SEAL_MASK: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

fn io(operation: &'static str) -> KeyError {
    KeyError::Io {
        operation,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
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
    /// Takes the descriptor the caller already owns, sets close-on-exec before anything else
    /// and checks it. `others` is every other artifact's actual slot (listeners included): a
    /// slot, or an open file, shared with any of them is refused. Every refusal drops, so
    /// closes, `fd`: it is the only descriptor this function ever closes.
    pub fn claim(fd: OwnedFd, others: &[RawFd]) -> Result<Self, KeyError> {
        let raw = fd.as_raw_fd();
        if raw < 3 || others.contains(&raw) {
            return Err(KeyError::Descriptor);
        }
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(KeyError::Descriptor);
        }
        let identity = check_sealed(fd.as_fd())?;
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
        Ok(Self(fd))
    }

    /// Reads and validates the key, then closes the transfer descriptor.
    pub fn read(self) -> Result<OrdinaryAuthorityKey, KeyError> {
        read_sealed(self.0.as_fd())
    }
}

/// The candidate's only entry: the guard's environment value for logical index 15 and the
/// actual slots of the other inherited artifacts. A missing value is an error whatever other
/// key source exists; there is no path or default. The one place a number becomes an owner.
///
/// A value that is not a canonical decimal, is below 3, names one of `others` or is not an
/// open descriptor is refused before any owner exists, so nothing is closed. Any other
/// refusal closes the named slot, as the claim owns it.
///
/// # Safety
/// The value must name a descriptor this process inherited through the guard that nothing
/// else owns or will close: no `OwnedFd`, `File` or other wrapper holds that number, and
/// no other code closes it. Adopting transfers its close to the returned error or key read;
/// a number someone else still owns would be closed under them, and a later descriptor
/// allocated at that number closed by their drop.
pub unsafe fn adopt_inherited(
    value: Option<&str>,
    others: &[RawFd],
) -> Result<OrdinaryAuthorityKey, KeyError> {
    let value = value.ok_or(KeyError::Descriptor)?;
    let raw: RawFd = value.parse().map_err(|_| KeyError::Descriptor)?;
    if raw.to_string() != value || raw < 3 || others.contains(&raw) {
        return Err(KeyError::Descriptor);
    }
    if unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        return Err(KeyError::Descriptor);
    }
    SealedKeyFd::claim(unsafe { OwnedFd::from_raw_fd(raw) }, others)?.read()
}
