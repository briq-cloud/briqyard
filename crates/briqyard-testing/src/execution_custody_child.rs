//! Disposable unprivileged candidate for the real-UID custody qualification.
use std::io::{Error, ErrorKind, Read, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::parent_id;
use std::path::Path;
use std::time::{Duration, Instant};

const CAP: usize = 4096;

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn remaining(deadline: Instant) -> Result<i32> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| Error::new(ErrorKind::TimedOut, "custody fixture deadline"))?;
    Ok(left.as_millis().clamp(1, i32::MAX as u128) as i32)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn poll(fd: RawFd, events: libc::c_short, until: Instant) -> Result<libc::c_short> {
    let mut requested = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut requested, 1, remaining(until)?) };
    if result < 0 {
        return Err(Error::last_os_error());
    }
    if result == 0 {
        return Err(Error::new(ErrorKind::TimedOut, "custody fixture poll"));
    }
    if remaining(until).is_err() {
        return Err(Error::new(ErrorKind::TimedOut, "late custody fixture I/O"));
    }
    if requested.revents & libc::POLLNVAL != 0 {
        return Err(invalid("invalid fixture descriptor"));
    }
    if requested.revents & events == 0 {
        return Err(invalid("unexpected fixture readiness"));
    }
    Ok(requested.revents)
}

fn socket() -> Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn connect(path: &Path, custodian_pid: i32) -> Result<OwnedFd> {
    let fd = socket()?;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 {
        return Err(invalid("fixture socket path is too long"));
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    address.sun_path[..bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(bytes.as_ptr().cast::<libc::c_char>(), bytes.len())
    });
    let length = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            length as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(Error::last_os_error());
    }
    verify_peer(fd.as_raw_fd(), custodian_pid)?;
    Ok(fd)
}

fn verify_peer(fd: RawFd, custodian_pid: i32) -> Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(Error::last_os_error());
    }
    if credentials.uid != 0 || credentials.pid != custodian_pid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "unexpected custodian",
        ));
    }
    Ok(())
}

fn send(fd: RawFd, bytes: &[u8], descriptor: Option<RawFd>) -> Result<()> {
    if bytes.is_empty() || bytes.len() > CAP {
        return Err(invalid("fixture packet size"));
    }
    let until = deadline();
    poll(fd, libc::POLLOUT, until)?;
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if let Some(descriptor) = descriptor {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(4) as usize };
        let header = unsafe {
            message
                .msg_control
                .cast::<libc::cmsghdr>()
                .as_mut()
                .unwrap()
        };
        header.cmsg_level = libc::SOL_SOCKET;
        header.cmsg_type = libc::SCM_RIGHTS;
        header.cmsg_len = unsafe { libc::CMSG_LEN(4) as usize };
        unsafe { std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor) };
    }
    let written = unsafe { libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL) };
    if written < 0 {
        return Err(Error::last_os_error());
    }
    if written as usize != bytes.len() {
        return Err(invalid("partial fixture packet"));
    }
    if Instant::now() >= until {
        return Err(Error::new(ErrorKind::TimedOut, "late fixture send"));
    }
    Ok(())
}

fn receive(fd: RawFd, expected: &[u8], expect_fd: bool) -> Result<Option<OwnedFd>> {
    let until = deadline();
    poll(fd, libc::POLLIN, until)?;
    let mut bytes = [0; CAP + 1];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() * std::mem::size_of::<usize>();
    let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err(Error::last_os_error());
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || count as usize > CAP {
        return Err(invalid("truncated fixture packet"));
    }
    if count == 0 || &bytes[..count as usize] != expected {
        return Err(invalid("wrong fixture packet"));
    }
    let mut descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let header_ref = unsafe { &*header };
        if header_ref.cmsg_level != libc::SOL_SOCKET || header_ref.cmsg_type != libc::SCM_RIGHTS {
            return Err(invalid("unexpected fixture ancillary data"));
        }
        let prefix = unsafe { libc::CMSG_LEN(0) as usize };
        if header_ref.cmsg_len < prefix || (header_ref.cmsg_len - prefix) % 4 != 0 {
            return Err(invalid("malformed fixture descriptor"));
        }
        for offset in (0..header_ref.cmsg_len - prefix).step_by(4) {
            let raw = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).add(offset).cast::<RawFd>())
            };
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            if unsafe { libc::fcntl(raw, libc::F_GETFD) } != libc::FD_CLOEXEC {
                return Err(invalid("inheritable fixture descriptor"));
            }
            descriptors.push(descriptor);
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if descriptors.len() != usize::from(expect_fd) {
        return Err(invalid("wrong fixture descriptor count"));
    }
    if Instant::now() >= until {
        return Err(Error::new(ErrorKind::TimedOut, "late fixture receive"));
    }
    Ok(descriptors.pop())
}

fn wait_exit(fd: &OwnedFd) -> Result<()> {
    let revents = poll(fd.as_raw_fd(), libc::POLLIN, deadline())?;
    if revents & libc::POLLIN == 0 {
        return Err(invalid("pidfd readiness is not exit evidence"));
    }
    Ok(())
}

fn run() -> Result<()> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let endpoint = args.next().ok_or(invalid("missing fixture endpoint"))?;
    let custodian: i32 = args
        .next()
        .ok_or(invalid("missing fixture custodian"))?
        .to_str()
        .ok_or(invalid("invalid fixture custodian"))?
        .parse()
        .map_err(|_| invalid("invalid fixture custodian"))?;
    let unavailable = args.next().ok_or(invalid("missing KCMP outcome"))? == "1";
    if args.next().is_some() || unsafe { libc::geteuid() } == 0 {
        return Err(invalid("fixture requires a final unprivileged UID"));
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
        return Err(Error::last_os_error());
    }
    if parent_id() != custodian as u32 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "fixture parent changed",
        ));
    }
    let mut release = [0; 2];
    std::io::stdin().read_exact(&mut release)?;
    if release != *b"go" {
        return Err(invalid("fixture release"));
    }

    let socket = connect(Path::new(&endpoint), custodian)?;
    send(socket.as_raw_fd(), b"opaque-request", None)?;
    let descriptor = receive(socket.as_raw_fd(), b"opaque-handle", true)?.unwrap();
    let echoed_number = descriptor.as_raw_fd();
    send(socket.as_raw_fd(), b"opaque-echo", Some(echoed_number))?;
    if descriptor.as_raw_fd() != echoed_number {
        return Err(invalid("candidate descriptor changed before echo"));
    }
    if unavailable {
        if receive(socket.as_raw_fd(), b"opaque-matched", false).is_ok() {
            return Err(invalid("unsupported KCMP produced a match"));
        }
        wait_exit(&descriptor)?;
        eprintln!("unprivileged candidate returned and positively polled one pidfd");
        return Ok(());
    }
    receive(socket.as_raw_fd(), b"opaque-matched", false)?;
    wait_exit(&descriptor)?;
    receive(socket.as_raw_fd(), b"opaque-exited", false)?;
    if descriptor.as_raw_fd() != echoed_number {
        return Err(invalid("candidate descriptor changed after exit"));
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("execution-custody-child: {error}");
        std::process::exit(1);
    }
}
