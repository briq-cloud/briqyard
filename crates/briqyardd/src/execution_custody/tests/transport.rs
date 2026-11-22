use super::super::{
    CandidatePidFd, CustodyError, DescriptorFloor, FrameKind, PacketListener, PacketSocket,
    StageDeadline, MAX_PACKET,
};
use super::{expect_protocol, raw_pidfd, send_raw};
use std::os::fd::AsRawFd;

fn pair() -> (PacketSocket, PacketSocket) {
    PacketSocket::pair().unwrap()
}

fn deadline() -> StageDeadline {
    StageDeadline::short("transport test")
}

#[test]
fn request_with_an_unexpected_fd_is_rejected_and_closed() {
    let (sender, receiver) = pair();
    let fd = raw_pidfd(std::process::id() as i32);
    send_raw(sender.as_raw_fd(), b"request", &[fd.as_raw_fd()]);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Request, deadline(), |_| Ok(()))
            .unwrap_err(),
        "unexpected custody ancillary descriptors",
    );
}

#[test]
fn handle_requires_exactly_one_received_fd() {
    let (sender, receiver) = pair();
    send_raw(sender.as_raw_fd(), b"handle", &[]);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Handle, deadline(), |_| Ok(()))
            .unwrap_err(),
        "unexpected custody ancillary descriptors",
    );

    let (sender, receiver) = pair();
    let first = raw_pidfd(std::process::id() as i32);
    let second = raw_pidfd(std::process::id() as i32);
    let numbers = [first.as_raw_fd(), second.as_raw_fd()];
    send_raw(sender.as_raw_fd(), b"handle", &numbers);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Handle, deadline(), |_| Ok(()))
            .unwrap_err(),
        "unexpected custody ancillary descriptors",
    );
}

#[test]
fn oversized_and_control_truncated_packets_fail_closed() {
    let (sender, receiver) = pair();
    send_raw(sender.as_raw_fd(), &vec![b'x'; MAX_PACKET + 1], &[]);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Request, deadline(), |_| Ok(()))
            .unwrap_err(),
        "truncated custody packet",
    );
}

#[test]
fn per_frame_deadline_does_not_wait_five_seconds_after_expiry() {
    let (_sender, receiver) = pair();
    let started = std::time::Instant::now();
    let result = receiver.receive_frame(FrameKind::Request, deadline(), |_| Ok(()));
    assert!(matches!(result, Err(CustodyError::Deadline { .. })));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn a_pipelined_extra_packet_invalidates_the_current_frame() {
    let (sender, receiver) = pair();
    send_raw(sender.as_raw_fd(), b"request", &[]);
    send_raw(sender.as_raw_fd(), b"extra", &[]);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Request, deadline(), |_| Ok(()))
            .unwrap_err(),
        "extra custody packet queued",
    );
}

#[test]
fn peer_close_after_one_frame_is_not_an_extra_packet() {
    let (sender, receiver) = pair();
    send_raw(sender.as_raw_fd(), b"request", &[]);
    drop(sender);
    let packet = receiver
        .receive_frame(FrameKind::Request, deadline(), |bytes| {
            assert_eq!(bytes, b"request");
            Ok(())
        })
        .unwrap();
    assert_eq!(packet.bytes(), b"request");
}

#[test]
fn wrong_frame_or_wire_bytes_do_not_pass_validation() {
    let (sender, receiver) = pair();
    send_raw(sender.as_raw_fd(), b"matched", &[]);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Request, deadline(), |bytes| {
                if bytes == b"request" {
                    Ok(())
                } else {
                    Err(CustodyError::Protocol("wrong frame or wire"))
                }
            })
            .unwrap_err(),
        "wrong frame or wire",
    );
}

#[test]
fn sending_a_pidfd_retains_the_original_owner_and_candidate_copy() {
    let (sender, receiver) = pair();
    let original = raw_pidfd(std::process::id() as i32);
    let number = original.as_raw_fd();
    sender
        .send_frame(FrameKind::Handle, b"handle", Some(number), deadline())
        .unwrap();
    assert!(unsafe { libc::fcntl(number, libc::F_GETFD) } >= 0);
    let mut packet = receiver
        .receive_frame(FrameKind::Handle, deadline(), |bytes| {
            assert_eq!(bytes, b"handle");
            Ok(())
        })
        .unwrap();
    let floor = DescriptorFloor::preserving(&[]).unwrap();
    let candidate = CandidatePidFd::from_owned(packet.take_fd().unwrap(), &floor).unwrap();
    assert!(unsafe { libc::fcntl(number, libc::F_GETFD) } >= 0);
    assert_ne!(candidate.as_raw_fd(), number);
    drop(original);
    assert!(candidate.poll_exited().unwrap().is_none());
}

#[test]
fn an_empty_packet_is_not_a_canonical_custody_frame() {
    let (sender, receiver) = pair();
    send_raw(sender.as_raw_fd(), b"", &[]);
    expect_protocol(
        receiver
            .receive_frame(FrameKind::Request, deadline(), |_| Ok(()))
            .unwrap_err(),
        "empty custody packet",
    );
}

#[test]
fn fresh_connected_unix_endpoint_reports_actual_peer_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("custody.sock");
    let listener = PacketListener::bind(&path).unwrap();
    let expected_uid = unsafe { libc::geteuid() };
    let server = std::thread::spawn(move || {
        let socket = listener.accept(deadline()).unwrap();
        socket.peer_identity().unwrap()
    });
    let client = PacketSocket::connect(&path).unwrap();
    let server_identity = server.join().unwrap();
    let client_identity = client.peer_identity().unwrap();
    assert_eq!(client_identity.uid(), expected_uid);
    assert_eq!(server_identity.uid(), expected_uid);
    assert_eq!(client_identity.pid(), std::process::id() as i32);
    assert_eq!(server_identity.pid(), std::process::id() as i32);
}

#[test]
fn candidate_state_machine_rejects_out_of_sequence_echo() {
    let (socket, _peer) = pair();
    let floor = DescriptorFloor::preserving(&[]).unwrap();
    let mut candidate = super::super::CandidateExchange::from_pair(socket, floor);
    expect_protocol(
        candidate.echo_handle(b"echo", deadline()).unwrap_err(),
        "candidate frame out of sequence",
    );
}
