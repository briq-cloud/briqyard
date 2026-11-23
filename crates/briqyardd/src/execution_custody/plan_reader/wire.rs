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
    connect, recvmsg, sendmsg, socket, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag,
    SockType, UnixAddr,
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
/// the SHA-256 of its mapped executable, supplied by the root provisioning path and never read
/// from the peer, the Plan or the trust record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrolledHelper {
    executable: [u8; 32],
}

impl EnrolledHelper {
    pub fn new(executable: [u8; 32]) -> Self {
        Self { executable }
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

pub(super) type HelperProbe = fn(&PeerIdentity) -> Result<ObservedHelper, PlanReadError>;

/// The kernel's view of the peer: its start ticks and the hash of its mapped executable.
fn kernel_probe(peer: &PeerIdentity) -> Result<ObservedHelper, PlanReadError> {
    let process = ProcessDir::open(peer.pid())?.profile()?;
    Ok(ObservedHelper {
        pid: peer.pid(),
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
        })
    }

    /// Test scope only: a socket in a synthetic directory owned by the test's own user, and a
    /// probe that stands in for hashing the (over-limit) test binary. It is not a production
    /// override and does not replace the qualified real-peer proof.
    #[cfg(test)]
    pub(super) fn rooted_at(
        anchor: &std::path::Path,
        ownership: Ownership,
        helper: EnrolledHelper,
        probe: HelperProbe,
    ) -> Self {
        Self {
            anchor: anchor.to_path_buf(),
            protected_ancestors: &[],
            ownership,
            helper,
            probe,
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
        let observed = self.observe_helper(&peer)?;

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
        if self.observe_helper(&peer)? != observed {
            return Err(PlanReadError::Peer(
                "helper process changed during the exchange",
            ));
        }
        Ok(reply)
    }

    fn observe_helper(&self, peer: &PeerIdentity) -> Result<ObservedHelper, PlanReadError> {
        let observed = (self.probe)(peer)?;
        if observed.executable != self.helper.executable {
            return Err(PlanReadError::Peer("peer is not the enrolled helper"));
        }
        Ok(observed)
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

/// One receive. No descriptor and no truncated ancillary data is ever accepted.
fn recv_some(
    stream: &OwnedFd,
    buffer: &mut [u8],
    deadline: Deadline,
    stage: &'static str,
) -> Result<usize, PlanReadError> {
    loop {
        wait_for(stream.as_raw_fd(), libc::POLLIN, deadline, stage)?;
        let mut iov = [IoSliceMut::new(buffer)];
        let mut control = nix::cmsg_space!([RawFd; 4]);
        let received = match recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::MSG_CMSG_CLOEXEC,
        ) {
            Ok(received) => received,
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io("receive plan read reply", error.into())),
        };
        let mut descriptors = Vec::new();
        let mut other = false;
        for message in received
            .cmsgs()
            .map_err(|_| PlanReadError::Frame("malformed ancillary data"))?
        {
            match message {
                ControlMessageOwned::ScmRights(raw) => descriptors.extend(
                    raw.into_iter()
                        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                ),
                _ => other = true,
            }
        }
        if !descriptors.is_empty()
            || other
            || received
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
