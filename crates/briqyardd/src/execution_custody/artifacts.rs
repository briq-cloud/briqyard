//! Private native artifact mechanics. A valid packet, descriptor or image does not grant
//! authority. The caller verifies the signed plan, launch, process and grant separately.

use super::fd::open_descriptors;
use super::{io_error, CustodyError, DescriptorFloor, StageDeadline};
use briqyard_api::execution::sealed::{
    canonical::MAX_MESSAGE_BYTES,
    custody::Resource,
    objects::Plan,
    prim::{HexDigest, KeyBytes, Uint},
    CodecError, Wire,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

const IMAGE_LIMIT: u64 = 256 * 1024 * 1024;
const SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const LISTENER_START: RawFd = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Member {
    Hi,
    He,
    Ni,
    Ng,
    Tr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Signer {
    Hk,
    Ak,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Plan,
    Launch,
    Grant,
    Inputs,
    Candidate,
    Config,
    CaptureLoad,
    Member(Member),
    Signer(Signer),
    TlsCert,
    TlsKey,
}

impl Class {
    fn env(self) -> &'static str {
        match self {
            Self::Plan => "BRIQ_SEALED_PLAN_FD",
            Self::Launch => "BRIQ_SEALED_LAUNCH_FD",
            Self::Grant => "BRIQ_SEALED_GRANT_FD",
            Self::Inputs => "BRIQ_SEALED_INPUTS_FD",
            Self::Candidate => "BRIQ_SEALED_CANDIDATE_FD",
            Self::Config => "BRIQ_SEALED_CONFIG_FD",
            Self::CaptureLoad => "BRIQ_SEALED_CAPTURE_FD",
            Self::Member(Member::Hi) => "BRIQ_SEALED_MEMBER_HI_FD",
            Self::Member(Member::He) => "BRIQ_SEALED_MEMBER_HE_FD",
            Self::Member(Member::Ni) => "BRIQ_SEALED_MEMBER_NI_FD",
            Self::Member(Member::Ng) => "BRIQ_SEALED_MEMBER_NG_FD",
            Self::Member(Member::Tr) => "BRIQ_SEALED_MEMBER_TR_FD",
            Self::Signer(Signer::Hk) => "BRIQ_SEALED_SIGNER_HK_FD",
            Self::Signer(Signer::Ak) => "BRIQ_SEALED_SIGNER_AK_FD",
            Self::TlsCert => "BRIQ_SEALED_TLS_CERT_FD",
            Self::TlsKey => "BRIQ_SEALED_TLS_KEY_FD",
        }
    }

    fn limit(self) -> u64 {
        if self == Self::Candidate {
            IMAGE_LIMIT
        } else {
            MAX_MESSAGE_BYTES as u64
        }
    }

    fn mode(self) -> u32 {
        if self == Self::Candidate {
            0o555
        } else {
            0o400
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "class", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Descriptor {
    Plan {
        bytes: Uint,
        digest: HexDigest,
    },
    Launch {
        bytes: Uint,
        digest: HexDigest,
    },
    Grant {
        bytes: Uint,
        digest: HexDigest,
    },
    Inputs {
        bytes: Uint,
        digest: HexDigest,
    },
    Candidate {
        bytes: Uint,
        digest: HexDigest,
    },
    Config {
        bytes: Uint,
        digest: HexDigest,
    },
    CaptureLoad {
        bytes: Uint,
        digest: HexDigest,
    },
    Member {
        bytes: Uint,
        member: Member,
        digest: HexDigest,
        member_hash: HexDigest,
    },
    Signer {
        bytes: Uint,
        role: Signer,
        public: KeyBytes,
    },
    TlsCert {
        bytes: Uint,
        digest: HexDigest,
    },
    TlsKey {
        bytes: Uint,
        digest: HexDigest,
    },
}

impl Descriptor {
    pub fn class(&self) -> Class {
        match self {
            Self::Plan { .. } => Class::Plan,
            Self::Launch { .. } => Class::Launch,
            Self::Grant { .. } => Class::Grant,
            Self::Inputs { .. } => Class::Inputs,
            Self::Candidate { .. } => Class::Candidate,
            Self::Config { .. } => Class::Config,
            Self::CaptureLoad { .. } => Class::CaptureLoad,
            Self::Member { member, .. } => Class::Member(*member),
            Self::Signer { role, .. } => Class::Signer(*role),
            Self::TlsCert { .. } => Class::TlsCert,
            Self::TlsKey { .. } => Class::TlsKey,
        }
    }

    fn integrity(&self) -> (u64, Option<&HexDigest>) {
        match self {
            Self::Plan { bytes, digest }
            | Self::Launch { bytes, digest }
            | Self::Grant { bytes, digest }
            | Self::Inputs { bytes, digest }
            | Self::Candidate { bytes, digest }
            | Self::Config { bytes, digest }
            | Self::CaptureLoad { bytes, digest }
            | Self::Member { bytes, digest, .. }
            | Self::TlsCert { bytes, digest }
            | Self::TlsKey { bytes, digest } => (bytes.get(), Some(digest)),
            Self::Signer { bytes, .. } => (bytes.get(), None),
        }
    }
}

#[derive(Deserialize, Serialize)]
enum Format {
    #[serde(rename = "native.prepare/v1")]
    Prepare,
    #[serde(rename = "native.assets/v1")]
    Assets,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    format: Format,
}

impl Wire for Prepare {
    fn validate(&self) -> Result<(), CodecError> {
        if !matches!(self.format, Format::Prepare) {
            return Err(CodecError::Value("native prepare format"));
        }
        Ok(())
    }
}

pub fn prepare_packet() -> &'static [u8] {
    br#"{"format":"native.prepare/v1"}"#
}

pub fn check_prepare(bytes: &[u8]) -> Result<(), CodecError> {
    briqyard_api::execution::sealed::decode::<Prepare>(bytes).map(|_| ())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetOffer {
    format: Format,
    assets: Vec<Descriptor>,
}

impl Wire for AssetOffer {
    fn validate(&self) -> Result<(), CodecError> {
        if !matches!(self.format, Format::Assets) {
            return Err(CodecError::Value("native assets format"));
        }
        if self.assets.iter().any(|asset| {
            let (bytes, _) = asset.integrity();
            bytes == 0 || bytes > asset.class().limit()
        }) {
            return Err(CodecError::Value("native asset length"));
        }
        Ok(())
    }
}

impl AssetOffer {
    pub fn decode(resource: Resource, bytes: &[u8]) -> Result<Self, CodecError> {
        let offer: Self = briqyard_api::execution::sealed::decode(bytes)?;
        offer.check_resource(resource)?;
        Ok(offer)
    }

    pub fn encode(resource: Resource, assets: Vec<Descriptor>) -> Result<Vec<u8>, CodecError> {
        let offer = Self {
            format: Format::Assets,
            assets,
        };
        offer.validate()?;
        offer.check_resource(resource)?;
        briqyard_api::execution::sealed::encode(&offer)
    }

    pub fn descriptors(&self) -> &[Descriptor] {
        &self.assets
    }

    fn check_resource(&self, resource: Resource) -> Result<(), CodecError> {
        let common = [
            Class::Plan,
            Class::Launch,
            Class::Grant,
            Class::Inputs,
            Class::Candidate,
            Class::Config,
            Class::CaptureLoad,
            Class::Member(Member::Hi),
            Class::Member(Member::He),
        ];
        let (members, signer) = match resource {
            Resource::Daemon => (&[][..], Signer::Hk),
            Resource::Authority => (
                &[Class::Member(Member::Ni), Class::Member(Member::Ng)][..],
                Signer::Ak,
            ),
        };
        let tail = [
            Class::Member(Member::Tr),
            Class::Signer(signer),
            Class::TlsCert,
            Class::TlsKey,
        ];
        if !self.assets.iter().map(Descriptor::class).eq(common
            .into_iter()
            .chain(members.iter().copied())
            .chain(tail))
        {
            return Err(CodecError::Value("native asset class order or role"));
        }
        Ok(())
    }

    /// Compare metadata with an independently validated plan; this does not validate the plan,
    /// member envelopes/values, signer handle or either launch-grant signature.
    pub fn check_plan_pins(&self, resource: Resource, plan: &Plan) -> Result<(), CodecError> {
        self.check_resource(resource)?;
        let plan_digest = briqyard_api::execution::sealed::h(plan)?;
        let members = &plan.new;
        let transition = members
            .tr
            .as_ref()
            .ok_or(CodecError::Value("native transition member pin"))?;
        if [
            &members.hi,
            &members.he,
            &members.ni,
            &members.ng,
            transition,
        ]
        .into_iter()
        .collect::<HashSet<_>>()
        .len()
            != 5
        {
            return Err(CodecError::Value("duplicate native member pin"));
        }
        let image = match resource {
            Resource::Daemon => &plan.next_d,
            Resource::Authority => &plan.next_a,
        };
        for asset in &self.assets {
            let valid = match asset {
                Descriptor::Plan { digest, .. } => digest == &plan_digest,
                Descriptor::Inputs { digest, .. } => digest == &plan.inputs,
                Descriptor::Candidate { digest, .. } => digest == image,
                Descriptor::Member {
                    member,
                    member_hash,
                    ..
                } => {
                    Some(member_hash)
                        == match member {
                            Member::Hi => Some(&plan.new.hi),
                            Member::He => Some(&plan.new.he),
                            Member::Ni => Some(&plan.new.ni),
                            Member::Ng => Some(&plan.new.ng),
                            Member::Tr => plan.new.tr.as_ref(),
                        }
                }
                Descriptor::Signer { role, public, .. } => {
                    public
                        == match role {
                            Signer::Hk => &plan.hk,
                            Signer::Ak => &plan.ak,
                        }
                }
                _ => true,
            };
            if !valid {
                return Err(CodecError::Value("native asset plan pin"));
            }
        }
        Ok(())
    }
}

pub struct FrozenArtifact {
    file: File,
    class: Class,
    bytes: u64,
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
        Ok(frozen)
    }

    pub fn read_small(&self, deadline: StageDeadline) -> Result<Vec<u8>, CustodyError> {
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

    fn check_metadata(&self) -> Result<(u64, u64), CustodyError> {
        let fd = self.as_fd();
        let metadata = self
            .file
            .metadata()
            .map_err(|e| io_error("stat sealed native artifact", e))?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.len() != self.bytes
            || (self.class == Class::Candidate && metadata.mode() & 0o7777 != self.class.mode())
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

    fn check_content(
        &self,
        digest: Option<&HexDigest>,
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
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

fn check_length(class: Class, bytes: u64) -> Result<(), CustodyError> {
    if bytes == 0 || bytes > class.limit() {
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
    let mut buffer = [0; 64 * 1024];
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

pub struct BoundAssets {
    base: RawFd,
    offer: AssetOffer,
    artifacts: Vec<FrozenArtifact>,
}

impl BoundAssets {
    pub fn bind(
        resource: Resource,
        offer: AssetOffer,
        received: ReceivedAssetFds,
        listeners: &ListenerEnv,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        offer
            .check_resource(resource)
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
        Self::relocate(offer, received.fds, floor, deadline)
    }

    fn relocate(
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
            artifacts.push(artifact);
            next = duplicate
                .checked_add(1)
                .ok_or(CustodyError::Protocol("native descriptor range exhausted"))?;
        }
        Ok(Self {
            base: floor.minimum(),
            offer,
            artifacts,
        })
    }

    pub(super) fn offer(&self) -> &AssetOffer {
        &self.offer
    }

    pub fn artifact(&self, class: Class) -> Option<&FrozenArtifact> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.class == class)
    }

    pub fn descriptor_env(&self) -> impl Iterator<Item = (&'static str, RawFd)> + '_ {
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
mod tests;
