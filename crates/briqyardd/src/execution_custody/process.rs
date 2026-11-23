use super::{io_error, require_root, CustodyError, OriginalPidFd};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueKernelProcess {
    pid: u32,
    start_ticks: u64,
    boot_id: String,
    executable: [u8; 32],
}

impl OpaqueKernelProcess {
    pub fn current() -> Result<Self, CustodyError> {
        ProcessDir::open(std::process::id() as i32)?.profile()
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn start_ticks(&self) -> u64 {
        self.start_ticks
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn executable(&self) -> &[u8; 32] {
        &self.executable
    }
}

impl std::fmt::Debug for CustodianProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustodianProcess")
            .finish_non_exhaustive()
    }
}

pub struct CustodianProcess {
    process: OpaqueKernelProcess,
    descriptor: OriginalPidFd,
    proc_dir: ProcessDir,
}

impl CustodianProcess {
    pub fn identify_peer(pid: i32) -> Result<OpaqueKernelProcess, CustodyError> {
        require_root("read candidate process identity")?;
        if pid <= 0 {
            return Err(CustodyError::Identity("non-positive candidate pid"));
        }
        ProcessDir::open(pid)?.profile()
    }

    /// Open the one predecessor pidfd while the pinned `/proc` directory identifies the TGID.
    pub fn open_live(pid: i32) -> Result<Self, CustodyError> {
        require_root("open predecessor pidfd")?;
        if pid <= 0 {
            return Err(CustodyError::Identity("non-positive pid"));
        }
        let proc_dir = ProcessDir::open(pid)?;
        let before = proc_dir.profile()?;
        let descriptor = OriginalPidFd::open(pid)?;
        if descriptor.poll_exited()?.is_some() {
            return Err(CustodyError::Identity("predecessor already exited"));
        }
        let after = proc_dir.profile()?;
        if before != after {
            return Err(CustodyError::Identity(
                "process changed while opening pidfd",
            ));
        }
        Ok(Self {
            process: before,
            descriptor,
            proc_dir,
        })
    }

    pub fn process(&self) -> &OpaqueKernelProcess {
        &self.process
    }

    pub fn descriptor(&self) -> &OriginalPidFd {
        &self.descriptor
    }

    pub fn verify_unchanged(&self) -> Result<(), CustodyError> {
        if self.proc_dir.profile()? != self.process {
            return Err(CustodyError::Identity("retained process identity changed"));
        }
        Ok(())
    }

    pub(super) fn verify_pinned(&self) -> Result<(), CustodyError> {
        if self.descriptor.poll_exited()?.is_none() {
            self.verify_unchanged()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pid: i32,
    uid: u32,
    gid: u32,
}

impl PeerIdentity {
    pub(crate) fn from_socket(fd: RawFd) -> Result<Self, CustodyError> {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result < 0 {
            return Err(io_error(
                "read Unix peer credentials",
                std::io::Error::last_os_error(),
            ));
        }
        if length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0 {
            return Err(CustodyError::Protocol("invalid Unix peer credentials"));
        }
        Ok(Self {
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
        })
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// A candidate checks only the connected root endpoint, never a cross-UID `/proc` entry.
    pub fn verify_custodian(&self, expected_pid: i32) -> Result<(), CustodyError> {
        if self.uid != 0 || self.pid != expected_pid {
            return Err(CustodyError::Identity("unexpected custodian peer"));
        }
        Ok(())
    }

    /// The root custodian supplies the pinned successor record and checks the actual peer.
    pub fn verify_candidate(
        &self,
        expected_uid: u32,
        expected: &OpaqueKernelProcess,
    ) -> Result<(), CustodyError> {
        require_root("read candidate process identity")?;
        if self.uid != expected_uid || self.pid != expected.pid as i32 {
            return Err(CustodyError::Identity(
                "candidate peer UID or TGID mismatch",
            ));
        }
        let actual = ProcessDir::open(self.pid)?.profile()?;
        if actual != *expected {
            return Err(CustodyError::Identity(
                "candidate boot/start/executable mismatch",
            ));
        }
        Ok(())
    }
}

pub(super) struct ProcessDir {
    fd: OwnedFd,
    pid: i32,
}

impl ProcessDir {
    pub(super) fn open(pid: i32) -> Result<Self, CustodyError> {
        let path = std::ffi::CString::new(format!("/proc/{pid}")).unwrap();
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(io_error(
                "open pinned process directory",
                std::io::Error::last_os_error(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { fd, pid })
    }

    pub(super) fn profile(&self) -> Result<OpaqueKernelProcess, CustodyError> {
        let stat = self.read("stat", true)?;
        let stat = String::from_utf8(stat)
            .map_err(|_| CustodyError::Identity("non-UTF-8 process stat"))?;
        let (stat_pid, start_ticks) = parse_stat(&stat)?;
        if stat_pid != self.pid {
            return Err(CustodyError::Identity("process directory TGID mismatch"));
        }
        let status = self.read("status", true)?;
        let status = String::from_utf8(status)
            .map_err(|_| CustodyError::Identity("non-UTF-8 process status"))?;
        if parse_tgid(&status)? != self.pid {
            return Err(CustodyError::Identity("pidfd target is not a TGID"));
        }
        let executable = self.hash_executable()?;
        Ok(OpaqueKernelProcess {
            pid: self.pid as u32,
            start_ticks,
            boot_id: host_boot_id()?,
            executable,
        })
    }

    fn read(&self, name: &str, nofollow: bool) -> Result<Vec<u8>, CustodyError> {
        let name = std::ffi::CString::new(name).unwrap();
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC;
        if nofollow {
            flags |= libc::O_NOFOLLOW;
        }
        let raw = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_ptr(), flags) };
        if raw < 0 {
            return Err(io_error(
                "open pinned process evidence",
                std::io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let mut bytes = Vec::new();
        BufReader::new(file)
            .take(128 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read pinned process evidence", error))?;
        Ok(bytes)
    }

    fn hash_executable(&self) -> Result<[u8; 32], CustodyError> {
        let name = std::ffi::CString::new("exe").unwrap();
        let raw = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io_error(
                "open mapped executable",
                std::io::Error::last_os_error(),
            ));
        }
        bounded_executable_hash(
            BufReader::new(unsafe { File::from_raw_fd(raw) }),
            256 * 1024 * 1024,
        )
    }
}

pub(super) fn bounded_executable_hash(
    source: impl Read,
    limit: u64,
) -> Result<[u8; 32], CustodyError> {
    let mut source = source.take(limit + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut total = 0;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| io_error("read mapped executable", error))?;
        if read == 0 {
            return Ok(hash.finalize().into());
        }
        total += read as u64;
        if total > limit {
            return Err(CustodyError::Protocol(
                "mapped executable exceeds its byte limit",
            ));
        }
        hash.update(&buffer[..read]);
    }
}

pub(super) fn parse_stat(stat: &str) -> Result<(i32, u64), CustodyError> {
    let open = stat
        .find(" (")
        .ok_or(CustodyError::Identity("malformed process stat"))?;
    let pid = stat[..open]
        .parse::<i32>()
        .map_err(|_| CustodyError::Identity("malformed process pid"))?;
    let remainder = stat[open + 2..]
        .rsplit_once(") ")
        .ok_or(CustodyError::Identity("malformed process comm"))?
        .1;
    let start = remainder
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(CustodyError::Identity("missing process start ticks"))?
        .parse::<u64>()
        .map_err(|_| CustodyError::Identity("malformed process start ticks"))?;
    if start == 0 {
        return Err(CustodyError::Identity("zero process start ticks"));
    }
    Ok((pid, start))
}

pub(super) fn parse_tgid(status: &str) -> Result<i32, CustodyError> {
    let mut found = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            if found.is_some() {
                return Err(CustodyError::Identity("duplicate process TGID"));
            }
            found = Some(
                value
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| CustodyError::Identity("malformed process TGID"))?,
            );
        }
    }
    found.ok_or(CustodyError::Identity("missing process TGID"))
}

fn host_boot_id() -> Result<String, CustodyError> {
    let bytes = std::fs::read("/proc/sys/kernel/random/boot_id")
        .map_err(|error| io_error("read host boot ID", error))?;
    if bytes.len() != 37 || bytes[36] != b'\n' || !valid_boot_id(&bytes[..36]) {
        return Err(CustodyError::Identity("malformed host boot ID"));
    }
    Ok(String::from_utf8(bytes[..36].to_vec()).unwrap())
}

pub(super) fn valid_boot_id(boot: &[u8]) -> bool {
    boot.len() == 36
        && boot.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}
