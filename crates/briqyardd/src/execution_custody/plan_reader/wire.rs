//! The fixed read socket and its one framed exchange.
//!
//! Only `/run/briqyard-sealed/plan-reader.sock` is ever connected: AF_UNIX, SOCK_STREAM,
//! root:root 0600, beneath ancestors that only root can write. A path that exists is not
//! enough: the kernel's peer credentials and the peer process's executable must equal the
//! enrolled helper, before the request is sent and again after the reply is read. The carrier
//! is never a signer; this module only moves one request frame out and one reply frame back.

use super::trust::{open_dir, same_node, Ownership};
use super::{io, Deadline, PlanReadError};
use crate::execution_custody::process::ProcessDir;
use crate::execution_custody::PeerIdentity;
use briqyard_api::execution::sealed::canonical::MAX_MESSAGE_BYTES;
use nix::sys::socket::{
    connect, recvmsg, sendmsg, socket, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr,
};
use rustix::fs::{fstat, statat, AtFlags, FileType, Stat, CWD};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

/// The only socket production ever connects.
pub const SOCKET_PATH: &str = "/run/briqyard-sealed/plan-reader.sock";
const SOCKET_LEAF: &str = "plan-reader.sock";
const MAX_FRAME: usize = MAX_MESSAGE_BYTES;

/// The independently enrolled identity of the root-owned target helper that serves the socket:
/// the SHA-256 of its mapped executable and its live process (PID, kernel start ticks, host
/// boot), supplied by the root provisioning path that started it. Nothing here comes from the
/// peer, the Plan or the trust record.
///
/// Qualification still owed: the helper is a fixed, dedicated, non-delegating process, and
/// whoever starts it must supply this identity for the helper it started. This module proves
/// the connected peer is that process, alive around the exchange; it does not prove how the
/// process came to exist, and nothing here forwards for another caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledHelper {
    executable: [u8; 32],
    pid: i32,
    start_ticks: u64,
    boot: String,
}

impl EnrolledHelper {
    pub fn new(executable: [u8; 32], pid: i32, start_ticks: u64, boot: String) -> Self {
        Self {
            executable,
            pid,
            start_ticks,
            boot,
        }
    }
}

/// The process a socket peer is: compared before the request and after the reply, so a peer
/// that restarts or re-executes mid-exchange is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ObservedHelper {
    pub(super) pid: i32,
    pub(super) start_ticks: u64,
    pub(super) boot: String,
    pub(super) executable: [u8; 32],
}

pub(super) type HelperProbe = fn(i32) -> Result<ObservedHelper, PlanReadError>;

/// Obtains a pidfd for the process at the other end of a connected stream.
pub(super) type PeerPidfdOpener = fn(&OwnedFd, &PeerIdentity) -> Result<OwnedFd, PlanReadError>;

/// The kernel's view of a process: its start ticks and the hash of its mapped executable. It
/// is only meaningful bracketed by [`PeerBinding::alive`], which pins the PID to the process.
fn kernel_probe(pid: i32) -> Result<ObservedHelper, PlanReadError> {
    let process = ProcessDir::open(pid)?.profile()?;
    Ok(ObservedHelper {
        pid,
        start_ticks: process.start_ticks(),
        boot: process.boot_id().to_string(),
        executable: *process.executable(),
    })
}

pub struct ReaderEndpoint {
    anchor: PathBuf,
    protected_ancestors: &'static [&'static str],
    ownership: Ownership,
    helper: EnrolledHelper,
    probe: HelperProbe,
    peer_pidfd: PeerPidfdOpener,
}

impl ReaderEndpoint {
    /// The fixed production endpoint. Only root custody connects it.
    pub fn fixed(helper: EnrolledHelper) -> Result<Self, PlanReadError> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(PlanReadError::Peer(
                "only root custody connects the plan reader",
            ));
        }
        Ok(Self {
            anchor: PathBuf::from("/"),
            protected_ancestors: &["run", "briqyard-sealed"],
            ownership: Ownership::ROOT,
            helper,
            probe: kernel_probe,
            peer_pidfd: kernel_peer_pidfd,
        })
    }

    /// Test scope only: a socket in a synthetic directory owned by the test's own user, a probe
    /// that stands in for hashing the (over-limit) test binary, and a pidfd opener. The opener
    /// stands in for SO_PEERPIDFD on kernels older than 6.5 and is not a production override;
    /// it does not replace the qualified real-peer proof.
    #[cfg(test)]
    pub(super) fn rooted_at(
        anchor: &std::path::Path,
        ownership: Ownership,
        helper: EnrolledHelper,
        probe: HelperProbe,
        peer_pidfd: PeerPidfdOpener,
    ) -> Self {
        Self {
            anchor: anchor.to_path_buf(),
            protected_ancestors: &[],
            ownership,
            helper,
            probe,
            peer_pidfd,
        }
    }

    /// Send `request` as one frame and return the one framed reply. The stream is closed
    /// on every outcome, and the peer must close after its single frame.
    pub(super) fn exchange(
        &self,
        request: &[u8],
        deadline: Deadline,
    ) -> Result<Vec<u8>, PlanReadError> {
        let frame = encode_frame(request)?;
        let named = self.check_socket_path()?;
        let stream = self.connect(deadline)?;
        let after = self.check_socket_path()?;
        if !same_node(&named, &after) {
            return Err(PlanReadError::Peer("listener socket was replaced"));
        }
        let peer = PeerIdentity::from_socket(stream.as_raw_fd())?;
        if peer.uid() != self.ownership.uid || peer.gid() != self.ownership.gid {
            return Err(PlanReadError::Peer("peer is not the enrolled owner"));
        }
        let binding = PeerBinding::bind(self.peer_pidfd, &stream, &peer)?;
        self.observe_helper(&binding)?;

        send_all(&stream, &frame, deadline)?;
        let mut header = [0u8; 4];
        recv_exact(&stream, &mut header, deadline)?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(PlanReadError::Frame("reply length is outside 1..65536"));
        }
        let mut reply = vec![0u8; length];
        recv_exact(&stream, &mut reply, deadline)?;
        expect_eof(&stream, deadline)?;
        self.observe_helper(&binding)?;
        Ok(reply)
    }

    /// Sample the peer process and require it to be the enrolled helper, with the pidfd proving
    /// the process is alive before and after the sample. A PID that is alive across the
    /// sample cannot have been reused, so the sample describes the connected peer. Two samples
    /// around an exchange do not prove uninterrupted execution of one image; that is the
    /// helper lifecycle's qualification, not this check's claim.
    fn observe_helper(&self, binding: &PeerBinding) -> Result<(), PlanReadError> {
        binding.alive()?;
        let observed = (self.probe)(binding.pid)?;
        binding.alive()?;
        let enrolled = &self.helper;
        if observed.executable != enrolled.executable
            || observed.pid != enrolled.pid
            || observed.start_ticks != enrolled.start_ticks
            || observed.boot != enrolled.boot
        {
            return Err(PlanReadError::Peer("peer is not the enrolled helper"));
        }
        Ok(())
    }

    /// Walk to the socket's directory one descriptor at a time and require a private socket
    /// node. Returns the node as found.
    fn check_socket_path(&self) -> Result<Stat, PlanReadError> {
        let protected = |stat: &Stat| {
            if self.ownership.owns(stat) && stat.st_mode & 0o022 == 0 {
                return Ok(());
            }
            Err(PlanReadError::Peer(
                "plan reader ancestry is foreign or writable",
            ))
        };
        let mut dir = open_dir(CWD, &self.anchor, "open plan reader anchor")?;
        protected(&fstat(&dir).map_err(|e| io("stat plan reader anchor", e.into()))?)?;
        for name in self.protected_ancestors {
            dir = open_dir(
                &dir,
                std::path::Path::new(name),
                "open plan reader ancestor",
            )?;
            protected(&fstat(&dir).map_err(|e| io("stat plan reader ancestor", e.into()))?)?;
        }
        let node = statat(dir.as_fd(), SOCKET_LEAF, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| io("stat plan reader socket", e.into()))?;
        if FileType::from_raw_mode(node.st_mode) != FileType::Socket
            || !self.ownership.owns(&node)
            || node.st_mode & 0o7777 != 0o600
        {
            return Err(PlanReadError::Peer(
                "plan reader socket is not a private socket",
            ));
        }
        Ok(node)
    }

    fn connect(&self, deadline: Deadline) -> Result<OwnedFd, PlanReadError> {
        deadline.check("connect")?;
        let mut path = self.anchor.clone();
        path.extend(self.protected_ancestors);
        path.push(SOCKET_LEAF);
        let address =
            UnixAddr::new(&path).map_err(|e| io("address plan reader socket", e.into()))?;
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|e| io("create plan reader socket", e.into()))?;
        connect(fd.as_raw_fd(), &address)
            .map_err(|e| io("connect plan reader socket", e.into()))?;
        Ok(fd)
    }
}

/// The connected peer's retained kernel pidfd and the PID it names. The pidfd is the proof of
/// identity and liveness; the PID is only how the probe addresses /proc.
struct PeerBinding {
    pidfd: OwnedFd,
    pid: i32,
}

impl PeerBinding {
    fn bind(
        open: PeerPidfdOpener,
        stream: &OwnedFd,
        peer: &PeerIdentity,
    ) -> Result<Self, PlanReadError> {
        let pidfd = open(stream, peer)?;
        let pid = pidfd_pid(&pidfd)?;
        if pid != peer.pid() {
            return Err(PlanReadError::Peer(
                "peer pidfd does not name the credentialed process",
            ));
        }
        let binding = Self { pidfd, pid };
        binding.alive()?;
        Ok(binding)
    }

    /// A pidfd becomes readable when its process exits. A zombie or a process whose
    /// executable is still readable through /proc is dead, and is refused here.
    fn alive(&self) -> Result<(), PlanReadError> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 {
            return Err(io("poll peer pidfd", std::io::Error::last_os_error()));
        }
        if ready > 0 {
            return Err(PlanReadError::Peer("peer process has exited"));
        }
        Ok(())
    }
}

/// The PID a pidfd names in this PID namespace, from its fdinfo; -1 once the process is gone.
pub(super) fn pidfd_pid(pidfd: &OwnedFd) -> Result<i32, PlanReadError> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|source| io("read peer pidfd info", source))?;
    let pid = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<i32>().ok())
        .ok_or(PlanReadError::Peer("peer pidfd carries no process"))?;
    if pid <= 0 {
        return Err(PlanReadError::Peer("peer process has exited"));
    }
    Ok(pid)
}

/// SO_PEERPIDFD: the kernel's own pidfd for the process that connected or listened, created
/// for this socket. Linux 6.5 or newer. Where it is unavailable the read fails closed: there
/// is no fallback to a numeric PID.
pub(super) fn kernel_peer_pidfd(
    stream: &OwnedFd,
    _peer: &PeerIdentity,
) -> Result<OwnedFd, PlanReadError> {
    let mut raw: libc::c_int = -1;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut raw as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOPROTOOPT | libc::EINVAL | libc::ENOTSOCK) => Err(PlanReadError::Peer(
                "kernel peer pidfd is unavailable, so the plan reader fails closed",
            )),
            _ => Err(io("read the peer pidfd", error)),
        };
    }
    if length as usize != std::mem::size_of::<libc::c_int>() || raw < 0 {
        return Err(PlanReadError::Peer("kernel returned no peer pidfd"));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC == 0 {
        return Err(PlanReadError::Peer("peer pidfd is inheritable"));
    }
    Ok(pidfd)
}

/// Four-byte big-endian payload length, then exactly that many bytes; 1..=65536.
pub(super) fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, PlanReadError> {
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(PlanReadError::Frame("request length is outside 1..65536"));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn wait_for(
    fd: RawFd,
    events: i16,
    deadline: Deadline,
    stage: &'static str,
) -> Result<(), PlanReadError> {
    loop {
        let left = deadline.remaining(stage)?;
        let millis = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io("poll plan reader socket", error));
        }
        if ready == 1 {
            return Ok(());
        }
    }
}

fn send_all(stream: &OwnedFd, mut bytes: &[u8], deadline: Deadline) -> Result<(), PlanReadError> {
    while !bytes.is_empty() {
        wait_for(stream.as_raw_fd(), libc::POLLOUT, deadline, "send request")?;
        match sendmsg::<()>(
            stream.as_raw_fd(),
            &[IoSlice::new(bytes)],
            &[],
            MsgFlags::MSG_NOSIGNAL,
            None,
        ) {
            Ok(0) => return Err(PlanReadError::Frame("request not accepted")),
            Ok(written) => bytes = &bytes[written..],
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(io("send plan read request", error.into())),
        }
    }
    Ok(())
}

/// One receive with no ancillary buffer: the kernel closes any descriptor a peer attaches and
/// flags the receive, so no right is ever held, adopted or leaked on the way to refusing it.
fn recv_some(
    stream: &OwnedFd,
    buffer: &mut [u8],
    deadline: Deadline,
    stage: &'static str,
) -> Result<usize, PlanReadError> {
    loop {
        wait_for(stream.as_raw_fd(), libc::POLLIN, deadline, stage)?;
        let mut iov = [IoSliceMut::new(buffer)];
        let received = match recvmsg::<()>(stream.as_raw_fd(), &mut iov, None, MsgFlags::empty()) {
            Ok(received) => received,
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io("receive plan read reply", error.into())),
        };
        if received
            .flags
            .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC)
        {
            return Err(PlanReadError::Frame("reply carries ancillary data"));
        }
        return Ok(received.bytes);
    }
}

fn recv_exact(
    stream: &OwnedFd,
    mut buffer: &mut [u8],
    deadline: Deadline,
) -> Result<(), PlanReadError> {
    while !buffer.is_empty() {
        let read = recv_some(stream, buffer, deadline, "receive reply")?;
        if read == 0 {
            return Err(PlanReadError::Frame(
                "reply ended before its frame was complete",
            ));
        }
        buffer = &mut buffer[read..];
    }
    Ok(())
}

/// After the one reply frame the peer must close: any further byte is a second frame or a relay.
fn expect_eof(stream: &OwnedFd, deadline: Deadline) -> Result<(), PlanReadError> {
    let mut byte = [0u8; 1];
    match recv_some(stream, &mut byte, deadline, "await close")? {
        0 => Ok(()),
        _ => Err(PlanReadError::Frame("bytes follow the reply frame")),
    }
}
