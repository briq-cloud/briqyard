mod fd;
mod process;
mod real_uid;
mod transport;

use super::CustodyError;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use std::io::{IoSlice, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output};

pub(super) fn raw_pidfd(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {:?}", std::io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

pub(super) fn send_raw(socket: RawFd, bytes: &[u8], fds: &[RawFd]) {
    let rights = [ControlMessage::ScmRights(fds)];
    let empty: [ControlMessage; 0] = [];
    let control = if fds.is_empty() {
        &empty[..]
    } else {
        &rights[..]
    };
    let written = sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        control,
        MsgFlags::empty(),
        None::<&nix::sys::socket::UnixAddr>,
    )
    .unwrap();
    assert_eq!(written, bytes.len());
}

pub(super) struct ChildGuard {
    child: Option<Child>,
    pidfd: OwnedFd,
}

impl ChildGuard {
    pub(super) fn spawn(command: &mut Command) -> Self {
        let parent = std::process::id();
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if std::os::unix::process::parent_id() != parent {
                    std::process::exit(125);
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let pidfd = raw_pidfd(child.id() as i32);
        Self {
            child: Some(child),
            pidfd,
        }
    }

    pub(super) fn sleep() -> Self {
        Self::spawn(Command::new("sleep").arg("30"))
    }

    pub(super) fn pid(&self) -> i32 {
        self.child.as_ref().unwrap().id() as i32
    }

    pub(super) fn release_stdin(&mut self) {
        self.child
            .as_mut()
            .unwrap()
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"go")
            .unwrap();
    }

    pub(super) fn kill(mut self) {
        self.terminate();
    }

    pub(super) fn wait_bounded(mut self) -> Output {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 2_000) };
        if ready != 1 || descriptor.revents & libc::POLLIN == 0 {
            self.terminate();
            panic!("test child exceeded its two-second bound");
        }
        let mut child = self.child.take().unwrap();
        let status = child.wait().unwrap();
        Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub(super) fn expect_protocol(error: CustodyError, expected: &'static str) {
    match error {
        CustodyError::Protocol(actual) => assert_eq!(actual, expected),
        other => panic!("expected protocol error {expected}, got {other:?}"),
    }
}
