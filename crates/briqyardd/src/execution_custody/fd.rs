use super::{io_error, require_root, CustodyError, StageDeadline};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Comparison {
    SameOpenFileDescription,
    DifferentOpenFileDescription { ordering: i32 },
}

pub struct OriginalPidFd {
    fd: OwnedFd,
}

impl OriginalPidFd {
    pub(crate) fn open(pid: i32) -> Result<Self, CustodyError> {
        require_root("open predecessor pidfd")?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(io_error(
                "pidfd_open predecessor",
                std::io::Error::last_os_error(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } != libc::FD_CLOEXEC {
            return Err(CustodyError::Protocol("original pidfd is inheritable"));
        }
        Ok(Self { fd })
    }

    #[cfg(test)]
    pub(crate) fn from_owned(fd: OwnedFd) -> Self {
        Self { fd }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn poll_exited(&self) -> Result<Option<ExitWitness>, CustodyError> {
        poll_pidfd_once(&self.fd)
    }

    pub fn wait_exited(&self, deadline: StageDeadline) -> Result<ExitWitness, CustodyError> {
        wait_pidfd(&self.fd, deadline)
    }
}

pub struct CandidatePidFd {
    fd: OwnedFd,
}

impl CandidatePidFd {
    pub(crate) fn from_owned(fd: OwnedFd, floor: &DescriptorFloor) -> Result<Self, CustodyError> {
        let fd = if fd.as_raw_fd() < floor.minimum {
            floor.relocate(fd)?
        } else {
            fd
        };
        Ok(Self { fd })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn poll_exited(&self) -> Result<Option<ExitWitness>, CustodyError> {
        poll_pidfd_once(&self.fd)
    }

    pub fn wait_exited(&self, deadline: StageDeadline) -> Result<ExitWitness, CustodyError> {
        wait_pidfd(&self.fd, deadline)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExitWitness {
    _positive_pollin: (),
}

impl ExitWitness {
    fn positive() -> Self {
        Self {
            _positive_pollin: (),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DescriptorFloor {
    minimum: RawFd,
}

impl DescriptorFloor {
    pub fn preserving(listeners: &[RawFd]) -> Result<Self, CustodyError> {
        let mut minimum = 0;
        for fd in listeners {
            if *fd < 0 {
                return Err(CustodyError::Protocol("negative preserved descriptor"));
            }
            minimum = minimum.max(fd.checked_add(1).ok_or(CustodyError::Protocol(
                "preserved descriptor exceeds supported range",
            ))?);
        }
        let (soft, hard) = nofile_limit()?;
        if minimum < 0 || soft != libc::RLIM_INFINITY && minimum as u64 >= soft {
            return Err(CustodyError::DescriptorLimit {
                minimum,
                soft: rlimit_value(soft),
                hard: rlimit_value(hard),
            });
        }
        Ok(Self { minimum })
    }

    pub fn minimum(&self) -> RawFd {
        self.minimum
    }

    pub fn relocate(&self, source: OwnedFd) -> Result<OwnedFd, CustodyError> {
        let target = self.minimum;
        let (soft, hard) = nofile_limit()?;
        if soft != libc::RLIM_INFINITY && target as u64 >= soft {
            return Err(CustodyError::DescriptorLimit {
                minimum: target,
                soft: rlimit_value(soft),
                hard: rlimit_value(hard),
            });
        }
        let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, target) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::EMFILE) | Some(libc::EINVAL)
            ) {
                return Err(CustodyError::DescriptorLimit {
                    minimum: target,
                    soft: rlimit_value(soft),
                    hard: rlimit_value(hard),
                });
            }
            return Err(io_error("relocate custody descriptor", error));
        }
        let duplicate = unsafe { OwnedFd::from_raw_fd(raw) };
        if raw < self.minimum {
            return Err(CustodyError::Protocol(
                "kernel returned custody descriptor below floor",
            ));
        }
        if unsafe { libc::fcntl(raw, libc::F_GETFD) } != libc::FD_CLOEXEC {
            return Err(CustodyError::Protocol(
                "relocated custody descriptor is inheritable",
            ));
        }
        Ok(duplicate)
    }
}

pub fn compare_open_descriptions(
    original: &OriginalPidFd,
    returned: &CandidatePidFd,
) -> Result<Comparison, CustodyError> {
    require_root("compare local custody pidfds")?;
    compare_with(original.as_raw_fd(), returned.as_raw_fd(), |a, b| {
        let value =
            unsafe { libc::syscall(libc::SYS_kcmp, libc::getpid(), libc::getpid(), 0, a, b) };
        if value < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(value as i32)
        }
    })
}

pub(super) fn compare_with(
    original: RawFd,
    returned: RawFd,
    kcmp: impl FnOnce(RawFd, RawFd) -> std::io::Result<i32>,
) -> Result<Comparison, CustodyError> {
    if original < 0 || returned < 0 {
        return Err(CustodyError::Protocol("negative process descriptor"));
    }
    match kcmp(original, returned) {
        Ok(0) => Ok(Comparison::SameOpenFileDescription),
        Ok(ordering) if ordering > 0 => Ok(Comparison::DifferentOpenFileDescription { ordering }),
        Ok(_) => Err(CustodyError::Protocol("invalid KCMP_FILE result")),
        Err(error) => Err(io_error("kcmp KCMP_FILE", error)),
    }
}

fn nofile_limit() -> Result<(libc::rlim_t, libc::rlim_t), CustodyError> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } < 0 {
        return Err(io_error(
            "read descriptor limit",
            std::io::Error::last_os_error(),
        ));
    }
    Ok((limits.rlim_cur, limits.rlim_max))
}

fn rlimit_value(value: libc::rlim_t) -> u64 {
    if value == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        value
    }
}

fn poll_pidfd_once(fd: &OwnedFd) -> Result<Option<ExitWitness>, CustodyError> {
    let mut requested = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut requested, 1, 0) };
    if result < 0 {
        return Err(io_error("poll pidfd", std::io::Error::last_os_error()));
    }
    if result == 0 {
        return Ok(None);
    }
    decode_pidfd_revents(requested.revents).map(Some)
}

fn wait_pidfd(fd: &OwnedFd, deadline: StageDeadline) -> Result<ExitWitness, CustodyError> {
    let mut requested = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let remaining = deadline.remaining()?;
    let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut requested, 1, millis.max(1)) };
    if result < 0 {
        return Err(io_error(
            "wait for pidfd exit",
            std::io::Error::last_os_error(),
        ));
    }
    deadline.check()?;
    if result == 0 {
        return Err(deadline.expired());
    }
    let witness = decode_pidfd_revents(requested.revents)?;
    deadline.check()?;
    Ok(witness)
}

fn decode_pidfd_revents(revents: libc::c_short) -> Result<ExitWitness, CustodyError> {
    if revents & libc::POLLNVAL != 0 {
        return Err(CustodyError::Protocol("poll returned invalid pidfd"));
    }
    if revents & libc::POLLIN == 0 {
        return Err(CustodyError::Protocol(
            "poll readiness without POLLIN is not exit evidence",
        ));
    }
    Ok(ExitWitness::positive())
}

pub(crate) fn poll_socket(
    fd: RawFd,
    events: libc::c_short,
    deadline: StageDeadline,
) -> Result<libc::c_short, CustodyError> {
    let mut requested = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let millis = deadline.remaining()?.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut requested, 1, millis.max(1)) };
    if result < 0 {
        return Err(io_error(
            "wait for custody packet socket",
            std::io::Error::last_os_error(),
        ));
    }
    deadline.check()?;
    if result == 0 {
        return Err(deadline.expired());
    }
    if requested.revents & libc::POLLNVAL != 0 {
        return Err(CustodyError::Protocol("invalid custody socket"));
    }
    if requested.revents & events == 0 {
        return Err(CustodyError::Protocol("custody socket is unavailable"));
    }
    Ok(requested.revents)
}
