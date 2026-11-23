//! Private native artifact mechanics. A valid packet, descriptor or image does not grant
//! authority. The caller verifies the signed plan, launch, process and grant separately.

use super::fd::open_descriptors;
use super::{io_error, CustodyError, DescriptorFloor, StageDeadline};
use briqyard_api::execution::{private_cert, sealed::prim::HexDigest};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;

const IMAGE_LIMIT: u64 = 256 * 1024 * 1024;
const SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const LISTENER_START: RawFd = 3;

mod frozen;
mod protocol;
mod secret;

pub use frozen::FrozenArtifact;
pub use protocol::{
    check_prepare, prepare_packet, AssetOffer, Class, Descriptor, Member, PoolKeyId, Requirements,
    Signer, MAX_ASSET_RIGHTS,
};
pub use secret::{
    BackupS3Credentials, ContinuationBearer, EvidenceSigner, PoolFileKey, TlsPrivateKey,
};

fn check_length(class: Class, bytes: u64) -> Result<(), CustodyError> {
    if !class.accepts(bytes) {
        return Err(CustodyError::Protocol("invalid native artifact length"));
    }
    Ok(())
}

fn check_hash(actual: [u8; 32], expected: Option<&HexDigest>) -> Result<(), CustodyError> {
    if expected.is_some_and(|pin| actual != pin.to_raw()) {
        return Err(CustodyError::Protocol("native artifact digest mismatch"));
    }
    Ok(())
}

fn create_memfd() -> Result<File, CustodyError> {
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut fd =
        unsafe { libc::memfd_create(c"briq-sealed-asset".as_ptr(), flags | libc::MFD_EXEC) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        fd = unsafe { libc::memfd_create(c"briq-sealed-asset".as_ptr(), flags) };
    }
    let fd = check_syscall(fd, "create native artifact memfd")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn hash_exact(
    file: &File,
    bytes: u64,
    deadline: StageDeadline,
    mut consume: impl FnMut(&[u8]) -> Result<(), CustodyError>,
) -> Result<[u8; 32], CustodyError> {
    let mut buffer = zeroize::Zeroizing::new([0; 64 * 1024]);
    let mut hash = Sha256::new();
    let mut offset = 0;
    loop {
        deadline.check()?;
        let want = (bytes - offset).clamp(1, buffer.len() as u64) as usize;
        let read = match file.read_at(&mut buffer[..want], offset) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error("read native artifact bytes", error)),
        };
        if offset == bytes && read == 0 {
            deadline.check()?;
            return Ok(hash.finalize().into());
        }
        if read == 0 || offset == bytes {
            return Err(CustodyError::Protocol(
                "native artifact byte count mismatch",
            ));
        }
        let chunk = &buffer[..read];
        hash.update(chunk);
        consume(chunk)?;
        offset += read as u64;
    }
}

/// Exact bytes of a public, non-secret descriptor.
fn read_exact(file: &File, bytes: u64, deadline: StageDeadline) -> Result<Vec<u8>, CustodyError> {
    let mut out = Vec::with_capacity(bytes as usize);
    hash_exact(file, bytes, deadline, |chunk| {
        out.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(out)
}

fn check_syscall(result: i32, operation: &'static str) -> Result<i32, CustodyError> {
    if result < 0 {
        Err(io_error(operation, io::Error::last_os_error()))
    } else {
        Ok(result)
    }
}

fn access_flags(fd: BorrowedFd<'_>) -> Result<i32, CustodyError> {
    check_syscall(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) },
        "read native artifact access flags",
    )
}

fn descriptor_flags(raw: RawFd) -> Result<i32, CustodyError> {
    check_syscall(
        unsafe { libc::fcntl(raw, libc::F_GETFD) },
        "read native descriptor flags",
    )
}

/// Facts from the single native seqpacket receive. The socket owner is responsible for
/// MSG_CMSG_CLOEXEC, owning every returned FD even on errors, and failing closed on any later
/// duplicate packet; this type does not authenticate the peer.
pub struct ReceivedAssetFds {
    pub fds: Vec<OwnedFd>,
    pub truncated: bool,
    pub unexpected_control: bool,
    pub queued_packet: bool,
}

/// The descriptors bound to one verified offer. A raw descriptor, its number or its
/// environment slot is never public: consumers get typed values from the validating reader,
/// and only this crate's transfer and exec code touches a descriptor.
///
/// ```compile_fail
/// use briqyardd::execution_custody::artifacts::{BoundAssets, Class};
/// fn raw(bound: &BoundAssets) {
///     let _ = bound.artifact(Class::OrdinaryAuthorityKey);
/// }
/// ```
///
/// ```compile_fail
/// use briqyardd::execution_custody::artifacts::BoundAssets;
/// fn raw(bound: &BoundAssets) {
///     let _ = bound.descriptor_env().count();
/// }
/// ```
///
/// The same imports and a public accessor do compile, so the two refusals above are about
/// those getters alone:
///
/// ```
/// use briqyardd::execution_custody::artifacts::{BoundAssets, Class};
/// fn typed(bound: &BoundAssets) {
///     let _ = bound.requirements();
///     let _ = Class::Plan;
/// }
/// ```
pub struct BoundAssets {
    base: RawFd,
    requirements: Requirements,
    offer: AssetOffer,
    artifacts: Vec<FrozenArtifact>,
}

impl BoundAssets {
    pub fn bind(
        requirements: Requirements,
        offer: AssetOffer,
        received: ReceivedAssetFds,
        listeners: &ListenerEnv,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        offer
            .check_resource(requirements)
            .map_err(|_| CustodyError::Protocol("native asset order or role"))?;
        if received.truncated
            || received.unexpected_control
            || received.queued_packet
            || received.fds.len() != offer.assets.len()
        {
            return Err(CustodyError::Protocol(
                "invalid native asset packet delivery",
            ));
        }
        listeners.check_open()?;
        let floor = DescriptorFloor::for_artifacts(listeners.names.len(), offer.assets.len())?;
        Self::relocate(requirements, offer, received.fds, floor, deadline)
    }

    fn relocate(
        requirements: Requirements,
        offer: AssetOffer,
        received: Vec<OwnedFd>,
        floor: DescriptorFloor,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        let mut artifacts = Vec::with_capacity(offer.assets.len());
        let mut unique = HashSet::new();
        let mut next = floor.minimum();
        for (descriptor, fd) in offer.assets.iter().zip(received) {
            let class = descriptor.class();
            let (bytes, digest) = descriptor.integrity();
            check_length(class, bytes)?;
            if descriptor_flags(fd.as_raw_fd())? != libc::FD_CLOEXEC {
                return Err(CustodyError::Protocol(
                    "native artifact arrived inheritable",
                ));
            }
            let duplicate = check_syscall(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, next) },
                "allocate native artifact descriptor",
            )?;
            let file = unsafe { File::from_raw_fd(duplicate) };
            drop(fd);
            if duplicate < next || descriptor_flags(duplicate)? != libc::FD_CLOEXEC {
                return Err(CustodyError::Protocol(
                    "unexpected native descriptor allocation",
                ));
            }
            let artifact = FrozenArtifact { file, class, bytes };
            if !unique.insert(artifact.check_metadata()?) {
                return Err(CustodyError::Protocol(
                    "duplicate native artifact descriptor",
                ));
            }
            artifact.check_content(digest, deadline)?;
            artifact.check_profile(Some(descriptor), deadline)?;
            artifacts.push(artifact);
            next = duplicate
                .checked_add(1)
                .ok_or(CustodyError::Protocol("native descriptor range exhausted"))?;
        }
        let bound = Self {
            base: floor.minimum(),
            requirements,
            offer,
            artifacts,
        };
        bound.check_identities(deadline)?;
        Ok(bound)
    }

    /// Each private transition certificate belongs to the key that follows it, and the server
    /// and client identities are distinct keys. The full profile is the transport's own
    /// parser; pins, names and validity are the caller's, against the closure. A daemon admin
    /// certificate is one complete ordinary DER leaf whose SPKI is the one of its actual
    /// private key and of neither transition identity; no transition profile applies to it.
    fn check_identities(&self, deadline: StageDeadline) -> Result<(), CustodyError> {
        let leaf = |cert, usage| -> Result<_, CustodyError> {
            let artifact = self
                .artifact(cert)
                .ok_or(CustodyError::Protocol("missing transition certificate"))?;
            private_cert::parse(
                &read_exact(&artifact.file, artifact.bytes, deadline)?,
                usage,
            )
            .map(|leaf| leaf.spki_digest())
            .map_err(|_| CustodyError::Protocol("invalid transition certificate"))
        };
        let key = |class| {
            self.offer.descriptors().iter().find_map(|d| match d {
                Descriptor::TransitionServerKey { spki, .. }
                | Descriptor::TransitionClientKey { spki, .. }
                    if d.class() == class =>
                {
                    Some(spki.clone())
                }
                _ => None,
            })
        };
        let server = leaf(Class::TransitionServerCert, private_cert::Usage::Server)?;
        let client = leaf(Class::TransitionClientCert, private_cert::Usage::Client)?;
        if key(Class::TransitionServerKey) != Some(server.clone())
            || key(Class::TransitionClientKey) != Some(client.clone())
            || server == client
        {
            return Err(CustodyError::Protocol(
                "transition certificate and key do not form distinct identities",
            ));
        }
        if matches!(
            self.requirements,
            Requirements::Daemon {
                admin_tls: true,
                ..
            }
        ) {
            let invalid = || CustodyError::Protocol("invalid daemon API identity");
            let cert = self.artifact(Class::DaemonApiCert).ok_or_else(invalid)?;
            let admin =
                private_cert::leaf_spki_digest(&read_exact(&cert.file, cert.bytes, deadline)?)
                    .map_err(|_| invalid())?;
            let key = self
                .artifact(Class::DaemonApiKey)
                .ok_or_else(invalid)?
                .tls_private_key(deadline)?;
            if admin != *key.spki() || admin == server || admin == client {
                return Err(CustodyError::Protocol(
                    "daemon API certificate and key do not form one distinct identity",
                ));
            }
        }
        deadline.check()
    }

    pub(super) fn offer(&self) -> &AssetOffer {
        &self.offer
    }

    pub fn requirements(&self) -> Requirements {
        self.requirements
    }

    pub(crate) fn artifact(&self, class: Class) -> Option<&FrozenArtifact> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.class == class)
    }

    pub(crate) fn descriptor_env(&self) -> impl Iterator<Item = (&'static str, RawFd)> + '_ {
        std::iter::once(("BRIQ_SEALED_DESCRIPTOR_BASE", self.base)).chain(
            self.artifacts
                .iter()
                .map(|asset| (asset.class.env(), asset.as_fd().as_raw_fd())),
        )
    }

    /// Replace this process only after caller validation of its exact signed Plan, Launch,
    /// LGrant, and Proc. The guard must exclude concurrent creation or inheritance changes of
    /// descriptors and validate exact argv, systemd socket identities and the notify endpoint.
    /// Exec success is neither custody evidence nor a durable authorization.
    pub fn exec(
        self,
        argv: &[&CStr],
        listeners: &ListenerEnv,
        notify_socket: Option<&CStr>,
        log_filter: Option<&CStr>,
    ) -> Result<Infallible, CustodyError> {
        if argv.first().is_none_or(|argv0| argv0.is_empty()) {
            return Err(CustodyError::Protocol("missing native candidate argv"));
        }
        listeners.check_open()?;
        let candidate = self
            .artifact(Class::Candidate)
            .ok_or(CustodyError::Protocol("missing sealed native candidate"))?;
        candidate.check_metadata()?;
        let known: HashSet<_> = self
            .artifacts
            .iter()
            .map(|artifact| artifact.as_fd().as_raw_fd())
            .collect();
        for fd in open_descriptors()? {
            if fd >= listeners.end
                && !known.contains(&fd)
                && descriptor_flags(fd)? & libc::FD_CLOEXEC == 0
            {
                return Err(CustodyError::Protocol(
                    "unrelated descriptor would survive native exec",
                ));
            }
        }
        let mut env = vec![c"PATH=/usr/bin:/bin".to_owned()];
        for (name, value) in self.descriptor_env().chain(listeners.values()) {
            env.push(env_entry(name, value.to_string().as_bytes())?);
        }
        env.push(env_entry(
            "LISTEN_FDNAMES",
            listeners.names.join(":").as_bytes(),
        )?);
        if let Some(notify) = notify_socket {
            env.push(env_entry("NOTIFY_SOCKET", notify.to_bytes())?);
        }
        if let Some(filter) = log_filter {
            env.push(env_entry("BRIQYARD_LOG", filter.to_bytes())?);
        }
        let argv: Vec<_> = argv
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<_> = env
            .iter()
            .map(|entry| entry.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        for artifact in &self.artifacts {
            let fd = artifact.as_fd().as_raw_fd();
            if descriptor_flags(fd)? != libc::FD_CLOEXEC {
                return Err(CustodyError::Protocol(
                    "native artifact became inheritable before exec",
                ));
            }
            if artifact.class != Class::Candidate {
                check_syscall(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) },
                    "retain native startup artifact",
                )?;
            }
        }
        let fd = candidate.as_fd().as_raw_fd();
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                c"".as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        Err(io_error(
            "execveat sealed candidate",
            io::Error::last_os_error(),
        ))
    }
}

fn env_entry(name: &str, bytes: &[u8]) -> Result<CString, CustodyError> {
    let mut entry = Vec::with_capacity(name.len() + 1 + bytes.len());
    entry.extend(name.bytes());
    entry.push(b'=');
    entry.extend(bytes);
    CString::new(entry).map_err(|_| CustodyError::Protocol("invalid native environment value"))
}

pub struct ListenerEnv {
    pid: i32,
    end: RawFd,
    names: Vec<String>,
    identities: Vec<(u64, u64)>,
}

impl ListenerEnv {
    /// The pinned manifest supplies the exact listener names in FD order. Kernel/manifest
    /// verification of which specific sockets the store should contain belongs to the caller.
    pub fn verify(
        pid: &str,
        count: &str,
        names: &str,
        expected: &[String],
    ) -> Result<Self, CustodyError> {
        let own_pid = unsafe { libc::getpid() };
        let end = i32::try_from(expected.len())
            .ok()
            .and_then(|count| count.checked_add(LISTENER_START))
            .ok_or(CustodyError::Protocol("invalid inherited listener count"))?;
        if pid != own_pid.to_string()
            || count != expected.len().to_string()
            || names != expected.join(":")
            || expected
                .iter()
                .any(|name| name.is_empty() || name.contains(':') || name.contains('\0'))
        {
            return Err(CustodyError::Protocol(
                "unexpected inherited listener metadata",
            ));
        }
        Ok(Self {
            pid: own_pid,
            end,
            names: expected.to_vec(),
            identities: listener_identities(end)?,
        })
    }

    fn check_open(&self) -> Result<(), CustodyError> {
        if self.pid != unsafe { libc::getpid() }
            || listener_identities(self.end)? != self.identities
        {
            return Err(CustodyError::Protocol(
                "inherited listener identity changed",
            ));
        }
        Ok(())
    }

    fn values(&self) -> std::array::IntoIter<(&'static str, i32), 2> {
        [
            ("LISTEN_PID", self.pid),
            ("LISTEN_FDS", self.end - LISTENER_START),
        ]
        .into_iter()
    }
}

fn listener_identities(end: RawFd) -> Result<Vec<(u64, u64)>, CustodyError> {
    let mut identities = Vec::new();
    let mut seen = HashSet::new();
    for raw in LISTENER_START..end {
        if descriptor_flags(raw)? != 0 {
            return Err(CustodyError::Protocol("listener is not inheritable"));
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        check_syscall(
            unsafe { libc::fstat(raw, stat.as_mut_ptr()) },
            "stat inherited listener",
        )?;
        let stat = unsafe { stat.assume_init() };
        let mut accepting: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&accepting) as libc::socklen_t;
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    (&mut accepting as *mut libc::c_int).cast(),
                    &mut size,
                )
            } < 0
            || accepting != 1
            || size as usize != std::mem::size_of_val(&accepting)
            || !seen.insert((stat.st_dev, stat.st_ino))
        {
            return Err(CustodyError::Protocol(
                "wrong or duplicate inherited listener",
            ));
        }
        identities.push((stat.st_dev, stat.st_ino));
    }
    Ok(identities)
}

/// Hash the image the kernel actually associated with this process, not argv or a local slot.
pub fn mapped_image_digest(deadline: StageDeadline) -> Result<[u8; 32], CustodyError> {
    let image =
        File::open("/proc/self/exe").map_err(|e| io_error("open mapped native image", e))?;
    let bytes = image
        .metadata()
        .map_err(|e| io_error("stat mapped native image", e))?
        .len();
    check_length(Class::Candidate, bytes)?;
    hash_exact(&image, bytes, deadline, |_| Ok(()))
}

#[cfg(test)]
pub(in crate::execution_custody) mod tests;
