use super::fd::poll_socket;
use super::{
    io_error, CandidatePidFd, CustodianProcess, CustodyError, DescriptorFloor, ExitWitness,
    OpaqueKernelProcess, PeerIdentity, StageDeadline,
};
use nix::sys::socket::{
    accept4, bind, connect, listen, recvmsg, sendmsg, socket, AddressFamily, Backlog,
    ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

pub const MAX_PACKET: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Request,
    Handle,
    Echo,
    Matched,
    Exited,
}

impl FrameKind {
    fn fd_count(self) -> usize {
        match self {
            Self::Handle | Self::Echo => 1,
            Self::Request | Self::Matched | Self::Exited => 0,
        }
    }
}

impl std::fmt::Debug for Packet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Packet")
            .field("bytes", &self.bytes.len())
            .field("fd_present", &self.fd.is_some())
            .finish()
    }
}

pub struct Packet {
    bytes: Vec<u8>,
    fd: Option<OwnedFd>,
}

impl Packet {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn take_fd(&mut self) -> Option<OwnedFd> {
        self.fd.take()
    }
}

pub struct PacketSocket {
    fd: OwnedFd,
}

impl PacketSocket {
    pub fn connect(path: &Path) -> Result<Self, CustodyError> {
        let address = unix_address(path)?;
        let fd = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|error| io_error("create custody seqpacket socket", error.into()))?;
        connect(fd.as_raw_fd(), &address)
            .map_err(|error| io_error("connect custody seqpacket socket", error.into()))?;
        Ok(Self { fd })
    }

    #[cfg(test)]
    pub(crate) fn pair() -> Result<(Self, Self), CustodyError> {
        let (left, right) = nix::sys::socket::socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .map_err(|error| io_error("create custody socket pair", error.into()))?;
        Ok((Self { fd: left }, Self { fd: right }))
    }

    pub fn peer_identity(&self) -> Result<PeerIdentity, CustodyError> {
        PeerIdentity::from_socket(self.as_raw_fd())
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(super) fn send_frame(
        &self,
        kind: FrameKind,
        bytes: &[u8],
        fd: Option<RawFd>,
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        if bytes.is_empty() || bytes.len() > MAX_PACKET {
            return Err(CustodyError::Protocol("invalid custody packet size"));
        }
        if fd.is_some() != (kind.fd_count() == 1) || fd.is_some_and(|raw| raw < 0) {
            return Err(CustodyError::Protocol(
                "unexpected custody ancillary descriptors",
            ));
        }
        poll_socket(self.as_raw_fd(), libc::POLLOUT, deadline)?;
        let own = fd.map(|raw| [raw]);
        let empty: [ControlMessage; 0] = [];
        let rights = own.as_ref().map(|fds| [ControlMessage::ScmRights(fds)]);
        let control = rights
            .as_ref()
            .map(|messages| &messages[..])
            .unwrap_or(&empty[..]);
        let written = sendmsg(
            self.as_raw_fd(),
            &[IoSlice::new(bytes)],
            control,
            MsgFlags::MSG_NOSIGNAL,
            None::<&UnixAddr>,
        )
        .map_err(|error| io_error("send custody packet", error.into()))?;
        if written != bytes.len() {
            return Err(CustodyError::Protocol("partial custody packet send"));
        }
        deadline.check()
    }

    pub(super) fn receive_frame(
        &self,
        kind: FrameKind,
        deadline: StageDeadline,
        validate: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<Packet, CustodyError> {
        poll_socket(self.as_raw_fd(), libc::POLLIN, deadline)?;
        let (bytes, packet_len, truncated, mut descriptors) = {
            let mut bytes = [0; MAX_PACKET + 1];
            let mut iov = [IoSliceMut::new(&mut bytes)];
            let mut control = nix::cmsg_space!([RawFd; 2]);
            let received = recvmsg::<()>(
                self.as_raw_fd(),
                &mut iov,
                Some(&mut control),
                MsgFlags::MSG_CMSG_CLOEXEC,
            )
            .map_err(|error| io_error("receive custody packet", error.into()))?;
            let mut descriptors = Vec::new();
            let messages = received
                .cmsgs()
                .map_err(|_| CustodyError::Protocol("malformed custody ancillary data"))?;
            for message in messages {
                match message {
                    ControlMessageOwned::ScmRights(raw) => {
                        descriptors.extend(
                            raw.into_iter()
                                .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                        );
                    }
                    _ => {
                        return Err(CustodyError::Protocol("unexpected custody ancillary data"));
                    }
                }
            }
            let packet_len = received.bytes;
            let truncated = received
                .flags
                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
            (bytes, packet_len, truncated, descriptors)
        };
        if truncated || packet_len > MAX_PACKET {
            return Err(CustodyError::Protocol("truncated custody packet"));
        }
        if packet_len == 0 {
            return Err(CustodyError::Protocol("empty custody packet"));
        }
        if descriptors.len() != kind.fd_count() {
            return Err(CustodyError::Protocol(
                "unexpected custody ancillary descriptors",
            ));
        }
        for descriptor in &descriptors {
            let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
            if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
                return Err(CustodyError::Protocol(
                    "received custody descriptor is inheritable",
                ));
            }
        }
        deadline.check()?;
        let bytes = bytes[..packet_len].to_vec();
        validate(&bytes)?;
        self.reject_queued_packet()?;
        deadline.check()?;
        Ok(Packet {
            bytes,
            fd: descriptors.pop(),
        })
    }

    fn reject_queued_packet(&self) -> Result<(), CustodyError> {
        let mut byte = 0u8;
        let result = unsafe {
            libc::recv(
                self.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if result > 0 {
            return Err(CustodyError::Protocol("extra custody packet queued"));
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(io_error("check extra custody packet", error));
        }
        Ok(())
    }
}

pub struct PacketListener {
    fd: OwnedFd,
    path: PathBuf,
}

impl PacketListener {
    pub fn bind(path: &Path) -> Result<Self, CustodyError> {
        let address = unix_address(path)?;
        let fd = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|error| io_error("create custody seqpacket listener", error.into()))?;
        bind(fd.as_raw_fd(), &address)
            .map_err(|error| io_error("bind custody seqpacket listener", error.into()))?;
        listen(&fd, Backlog::new(1).unwrap())
            .map_err(|error| io_error("listen for custody candidate", error.into()))?;
        Ok(Self {
            fd,
            path: path.to_path_buf(),
        })
    }

    pub(super) fn accept(self, deadline: StageDeadline) -> Result<PacketSocket, CustodyError> {
        poll_socket(self.fd.as_raw_fd(), libc::POLLIN, deadline)?;
        let raw = accept4(
            self.fd.as_raw_fd(),
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .map_err(|error| io_error("accept custody candidate", error.into()))?;
        deadline.check()?;
        Ok(PacketSocket {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }
}

impl Drop for PacketListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateStage {
    Request,
    Handle,
    Echo,
    Matched,
    Exit,
    Exited,
}

pub struct CandidateExchange {
    socket: PacketSocket,
    stage: CandidateStage,
    handle: Option<CandidatePidFd>,
    matched: Option<Vec<u8>>,
    floor: DescriptorFloor,
}

pub struct CompletedCustody {
    handle: CandidatePidFd,
    matched: Vec<u8>,
    exited: Vec<u8>,
}

impl CompletedCustody {
    pub fn handle(&self) -> &CandidatePidFd {
        &self.handle
    }

    pub fn matched(&self) -> &[u8] {
        &self.matched
    }

    pub fn exited(&self) -> &[u8] {
        &self.exited
    }
}

impl CandidateExchange {
    pub fn connect(
        path: &Path,
        expected_custodian_pid: i32,
        floor: DescriptorFloor,
    ) -> Result<Self, CustodyError> {
        let socket = PacketSocket::connect(path)?;
        socket
            .peer_identity()?
            .verify_custodian(expected_custodian_pid)?;
        Ok(Self {
            socket,
            stage: CandidateStage::Request,
            handle: None,
            matched: None,
            floor,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_pair(socket: PacketSocket, floor: DescriptorFloor) -> Self {
        Self {
            socket,
            stage: CandidateStage::Request,
            handle: None,
            matched: None,
            floor,
        }
    }

    pub fn send_request(
        &mut self,
        request: &[u8],
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        self.require_stage(CandidateStage::Request)?;
        self.socket
            .send_frame(FrameKind::Request, request, None, deadline)?;
        self.stage = CandidateStage::Handle;
        Ok(())
    }

    pub fn receive_handle(
        &mut self,
        deadline: StageDeadline,
        validate: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<(), CustodyError> {
        self.require_stage(CandidateStage::Handle)?;
        let mut packet = self
            .socket
            .receive_frame(FrameKind::Handle, deadline, validate)?;
        let handle = CandidatePidFd::from_owned(
            packet
                .take_fd()
                .ok_or(CustodyError::Protocol("missing predecessor pidfd"))?,
            &self.floor,
        )?;
        deadline.check()?;
        self.handle = Some(handle);
        self.stage = CandidateStage::Echo;
        Ok(())
    }

    pub fn echo_handle(
        &mut self,
        echo: &[u8],
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        self.require_stage(CandidateStage::Echo)?;
        let handle = self
            .handle
            .as_ref()
            .ok_or(CustodyError::Protocol("missing retained predecessor pidfd"))?
            .as_raw_fd();
        self.socket
            .send_frame(FrameKind::Echo, echo, Some(handle), deadline)?;
        self.stage = CandidateStage::Matched;
        Ok(())
    }

    pub fn receive_matched(
        &mut self,
        deadline: StageDeadline,
        validate: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<(), CustodyError> {
        self.require_stage(CandidateStage::Matched)?;
        let packet = self
            .socket
            .receive_frame(FrameKind::Matched, deadline, validate)?;
        self.matched = Some(packet.bytes);
        self.stage = CandidateStage::Exit;
        Ok(())
    }

    pub fn wait_for_exit(&mut self, deadline: StageDeadline) -> Result<ExitWitness, CustodyError> {
        self.require_stage(CandidateStage::Exit)?;
        let witness = self
            .handle
            .as_ref()
            .ok_or(CustodyError::Protocol("missing retained predecessor pidfd"))?
            .wait_exited(deadline)?;
        self.stage = CandidateStage::Exited;
        Ok(witness)
    }

    pub fn receive_exited(
        mut self,
        exited: StageDeadline,
        validate: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<CompletedCustody, CustodyError> {
        self.require_stage(CandidateStage::Exited)?;
        let packet = self
            .socket
            .receive_frame(FrameKind::Exited, exited, validate)?;
        Ok(CompletedCustody {
            handle: self
                .handle
                .take()
                .ok_or(CustodyError::Protocol("missing retained predecessor pidfd"))?,
            matched: self
                .matched
                .take()
                .ok_or(CustodyError::Protocol("missing matched evidence"))?,
            exited: packet.bytes,
        })
    }

    pub fn handle(&self) -> Option<&CandidatePidFd> {
        self.handle.as_ref()
    }

    fn require_stage(&self, expected: CandidateStage) -> Result<(), CustodyError> {
        if self.stage != expected {
            return Err(CustodyError::Protocol("candidate frame out of sequence"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustodianStage {
    Request,
    Handle,
    Echo,
    Matched,
    Exit,
    Exited,
}

pub struct CustodianCompletion {
    predecessor: CustodianProcess,
    request: Vec<u8>,
    matched: Vec<u8>,
    exited: Vec<u8>,
}

impl CustodianCompletion {
    pub fn predecessor(&self) -> &CustodianProcess {
        &self.predecessor
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn matched(&self) -> &[u8] {
        &self.matched
    }

    pub fn exited(&self) -> &[u8] {
        &self.exited
    }
}

pub struct CustodianExchange {
    socket: PacketSocket,
    predecessor: CustodianProcess,
    expected_uid: u32,
    expected_candidate: OpaqueKernelProcess,
    floor: DescriptorFloor,
    stage: CustodianStage,
    request: Option<Vec<u8>>,
    matched: Option<Vec<u8>>,
}

impl CustodianExchange {
    pub fn accept_one(
        listener: PacketListener,
        predecessor: CustodianProcess,
        expected_uid: u32,
        expected_candidate: OpaqueKernelProcess,
        floor: DescriptorFloor,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        super::require_root("accept custody candidate")?;
        let socket = listener.accept(deadline)?;
        socket
            .peer_identity()?
            .verify_candidate(expected_uid, &expected_candidate)?;
        deadline.check()?;
        Ok(Self {
            socket,
            predecessor,
            expected_uid,
            expected_candidate,
            floor,
            stage: CustodianStage::Request,
            request: None,
            matched: None,
        })
    }

    pub fn receive_request(
        &mut self,
        deadline: StageDeadline,
        validate: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<Vec<u8>, CustodyError> {
        self.require_stage(CustodianStage::Request)?;
        self.predecessor.verify_pinned()?;
        let packet = self
            .socket
            .receive_frame(FrameKind::Request, deadline, validate)?;
        self.predecessor.verify_pinned()?;
        self.verify_candidate()?;
        deadline.check()?;
        self.request = Some(packet.bytes.clone());
        self.stage = CustodianStage::Handle;
        Ok(packet.bytes)
    }

    pub fn send_handle(
        &mut self,
        handle: &[u8],
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        self.require_stage(CustodianStage::Handle)?;
        self.socket.send_frame(
            FrameKind::Handle,
            handle,
            Some(self.predecessor.descriptor().as_raw_fd()),
            deadline,
        )?;
        self.stage = CustodianStage::Echo;
        Ok(())
    }

    pub fn receive_echo_and_compare(
        &mut self,
        deadline: StageDeadline,
        validate: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<(), CustodyError> {
        self.require_stage(CustodianStage::Echo)?;
        let mut packet = self
            .socket
            .receive_frame(FrameKind::Echo, deadline, validate)?;
        let returned = CandidatePidFd::from_owned(
            packet
                .take_fd()
                .ok_or(CustodyError::Protocol("missing returned predecessor pidfd"))?,
            &self.floor,
        )?;
        if super::compare_open_descriptions(self.predecessor.descriptor(), &returned)?
            != super::Comparison::SameOpenFileDescription
        {
            return Err(CustodyError::Protocol(
                "returned pidfd names a different open file description",
            ));
        }
        drop(returned);
        deadline.check()?;
        self.stage = CustodianStage::Matched;
        Ok(())
    }

    pub fn send_matched(
        &mut self,
        matched: &[u8],
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        self.require_stage(CustodianStage::Matched)?;
        self.socket
            .send_frame(FrameKind::Matched, matched, None, deadline)?;
        self.matched = Some(matched.to_vec());
        self.stage = CustodianStage::Exit;
        Ok(())
    }

    pub fn wait_for_original_exit(
        &mut self,
        deadline: StageDeadline,
    ) -> Result<ExitWitness, CustodyError> {
        self.require_stage(CustodianStage::Exit)?;
        let witness = self.predecessor.descriptor().wait_exited(deadline)?;
        self.stage = CustodianStage::Exited;
        Ok(witness)
    }

    pub fn send_exited(
        mut self,
        exited: &[u8],
        deadline: StageDeadline,
    ) -> Result<CustodianCompletion, CustodyError> {
        self.require_stage(CustodianStage::Exited)?;
        self.socket
            .send_frame(FrameKind::Exited, exited, None, deadline)?;
        Ok(CustodianCompletion {
            predecessor: self.predecessor,
            request: self
                .request
                .take()
                .ok_or(CustodyError::Protocol("missing request evidence"))?,
            matched: self
                .matched
                .take()
                .ok_or(CustodyError::Protocol("missing matched evidence"))?,
            exited: exited.to_vec(),
        })
    }

    pub fn predecessor(&self) -> &CustodianProcess {
        &self.predecessor
    }

    #[cfg(test)]
    pub(crate) fn peer_identity(&self) -> Result<PeerIdentity, CustodyError> {
        self.socket.peer_identity()
    }

    fn verify_candidate(&self) -> Result<(), CustodyError> {
        self.socket
            .peer_identity()?
            .verify_candidate(self.expected_uid, &self.expected_candidate)
    }

    fn require_stage(&self, expected: CustodianStage) -> Result<(), CustodyError> {
        if self.stage != expected {
            return Err(CustodyError::Protocol("custodian frame out of sequence"));
        }
        Ok(())
    }
}

fn unix_address(path: &Path) -> Result<UnixAddr, CustodyError> {
    if path.as_os_str().is_empty() {
        return Err(CustodyError::Protocol("empty custody socket path"));
    }
    UnixAddr::new(path).map_err(|error| io_error("custody socket address", error.into()))
}
