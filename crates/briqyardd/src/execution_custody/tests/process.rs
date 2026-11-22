use super::super::process::{
    bounded_executable_hash, parse_stat, parse_tgid, valid_boot_id, ProcessDir,
};
use super::super::{CustodianProcess, PacketSocket};
use super::ChildGuard;
use crate::execution_custody::CustodyError;

#[test]
fn current_process_record_has_boot_tgid_start_and_executable() {
    let child = ChildGuard::sleep();
    let process = ProcessDir::open(child.pid()).unwrap().profile().unwrap();
    assert_eq!(process.pid(), child.pid() as u32);
    assert!(process.start_ticks() > 0);
    assert!(valid_boot_id(process.boot_id().as_bytes()));
    let executable = std::fs::read_link(format!("/proc/{}/exe", child.pid())).unwrap();
    let current_exe = std::fs::read(executable).unwrap();
    assert_eq!(
        process.executable(),
        &<[u8; 32] as From<_>>::from(sha2::Sha256::digest(current_exe))
    );
}

#[test]
fn stat_parser_uses_the_final_comm_delimiter() {
    let fields = std::iter::repeat_n("0", 18).collect::<Vec<_>>().join(" ");
    let stat = format!("42 (odd) comm) S {fields} 123456 0");
    assert_eq!(parse_stat(&stat).unwrap(), (42, 123456));
}

#[test]
fn process_identity_rejects_malformed_records() {
    assert!(parse_stat("not a stat").is_err());
    assert!(parse_stat("42 (x) S 0").is_err());
    assert!(parse_tgid("Name:\tx\n").is_err());
    assert!(parse_tgid("Tgid:\t12\nTgid:\t12\n").is_err());
    assert!(!valid_boot_id(b"00000000-0000-0000-0000-00000000000Z"));
    assert!(!valid_boot_id(b"00000000-0000-0000-0000-0000000000000"));
}

#[test]
fn non_root_cannot_open_another_process_pidfd() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let child = ChildGuard::sleep();
    let error = CustodianProcess::open_live(child.pid()).unwrap_err();
    assert!(matches!(error, CustodyError::PermissionDenied { .. }));
}

#[test]
fn peer_uid_or_pid_mismatch_fails_closed() {
    let (local, _peer) = PacketSocket::pair().unwrap();
    let identity = local.peer_identity().unwrap();
    assert!(identity.verify_custodian(identity.pid() + 1).is_err());
    if identity.uid() != 0 {
        assert!(identity.verify_custodian(identity.pid()).is_err());
    }
}

#[test]
fn executable_hash_honors_its_byte_limit() {
    assert!(bounded_executable_hash("abcde".as_bytes(), 4).is_err());
    let hash = bounded_executable_hash("abcd".as_bytes(), 4).unwrap();
    assert_eq!(
        hash,
        <[u8; 32] as From<_>>::from(sha2::Sha256::digest("abcd"))
    );
}

use sha2::Digest;
