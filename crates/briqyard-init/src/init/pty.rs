use super::*;

/// Puts the command on a new terminal of `cols` by `rows`: its stdin, stdout and stderr, and
/// its controlling terminal in a session of its own.
pub(super) fn on_terminal(cmd: &mut Command, cols: u16, rows: u16) -> std::io::Result<Pty> {
    let (pty, slave) = Pty::open(cols, rows)?;
    cmd.stdin(Stdio::from(slave.try_clone()?));
    cmd.stdout(Stdio::from(slave.try_clone()?));
    cmd.stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(pty)
}

/// The host side of a command's terminal, non-blocking, read and written through the runtime.
pub(super) struct Pty {
    master: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

/// A terminal's size; 0 is 80 columns, 24 rows.
pub(super) fn winsize(cols: u16, rows: u16) -> libc::winsize {
    libc::winsize {
        ws_row: if rows == 0 { 24 } else { rows },
        ws_col: if cols == 0 { 80 } else { cols },
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// A libc return value as a result.
pub(super) fn cvt(n: isize) -> std::io::Result<usize> {
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

impl Pty {
    /// A new terminal and the command's side of it, both closed on exec.
    pub(super) fn open(cols: u16, rows: u16) -> std::io::Result<(Pty, std::os::fd::OwnedFd)> {
        let size = winsize(cols, rows);
        let p = nix::pty::openpty(Some(&size), None).map_err(std::io::Error::from)?;
        for fd in [&p.master, &p.slave] {
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        let flags = unsafe { libc::fcntl(p.master.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    p.master.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the OwnedFd is a valid descriptor, owned by the AsyncFd and closed only by it.
        let master = unsafe { tokio::io::unix::AsyncFd::register(p.master)? };
        Ok((Pty { master }, p.slave))
    }

    /// What the terminal printed; 0 once every copy of the command's side is closed (the
    /// kernel answers EIO then).
    pub(super) async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut ready = self.master.readable().await?;
            let fd = self.master.as_raw_fd();
            match ready
                .try_io(|_| cvt(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }))
            {
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    pub(super) async fn write_all(&self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let mut ready = self.master.writable().await?;
            let fd = self.master.as_raw_fd();
            match ready
                .try_io(|_| cvt(unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) }))
            {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }

    /// A new size: the kernel sends SIGWINCH to the terminal's foreground process group.
    pub(super) fn resize(&self, cols: u16, rows: u16) -> std::io::Result<()> {
        let size = winsize(cols, rows);
        if unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// The init is Linux-only and so are its tests: run them in the dev VM
// (`cargo test -p briqyard-init` there). Nothing here needs /dev/kvm, a real mount or PID 1.
