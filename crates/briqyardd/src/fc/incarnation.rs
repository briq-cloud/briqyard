//! Evidence tying boot provenance to one actual host process, across daemon handovers.

use super::*;
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incarnation {
    pub pid: u32,
    pub start_ticks: u64,
    pub host_boot_id: String,
}

impl Incarnation {
    /// Missing /proc evidence is unavailable telemetry, never a reason to stop a guest.
    pub fn read(pid: u32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let host_boot_id = host_boot_id()?;
        Some(Self {
            pid,
            start_ticks: start_ticks(&stat)?,
            host_boot_id,
        })
    }
}

/// The parenthesized comm may contain spaces and closing parentheses. Fields after
/// its final delimiter start at field 3; Linux starttime is field 22.
pub(super) fn start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// A canonical Linux boot UUID is positive evidence; unavailable/malformed reads are not.
pub fn valid_host_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && value.bytes().any(|b| b != b'0' && b != b'-')
}

pub fn host_boot_id() -> Option<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let value = value.trim();
    valid_host_boot_id(value).then(|| value.to_string())
}

/// Settle only this registered process. The fd pins the incarnation while ownership
/// is rechecked; neither a recycled PID nor unknown /proc evidence is signalled.
#[cfg(target_os = "linux")]
pub(super) async fn settle_clone_process(id: &str, saved: &Incarnation) -> Result<bool> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    if saved.pid == 0 || !valid_host_boot_id(&saved.host_boot_id) {
        return Ok(false);
    }
    let Some(current_boot) = host_boot_id() else {
        return Ok(false);
    };
    if current_boot != saved.host_boot_id {
        return Ok(true);
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, saved.pid, 0) };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(true)
        } else {
            Err(error.into())
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let exited = || -> Result<bool> {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        anyhow::ensure!(
            poll.revents & libc::POLLNVAL == 0,
            "invalid process observer"
        );
        Ok(poll.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    };
    if exited()? {
        return Ok(true);
    }
    match Incarnation::read(saved.pid) {
        Some(actual) if actual != *saved => return Ok(true),
        Some(_) if super::machine_of(saved.pid).as_deref() == Some(id) => {}
        _ => return Ok(false),
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(std::io::Error::last_os_error().into());
    }
    match tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if exited()? {
                return Ok::<_, anyhow::Error>(true);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Ok(false),
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn settle_clone_process(_id: &str, _saved: &Incarnation) -> Result<bool> {
    Ok(false)
}
