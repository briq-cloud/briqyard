//! Listening sockets that outlive their process (ADR 0051). Each one is handed to systemd's
//! file descriptor store when it is bound, and handed back to the next process at its start
//! (`LISTEN_FDS`, `LISTEN_FDNAMES`): while no process runs, the kernel completes handshakes and
//! queues the connections instead of refusing them. Outside systemd (no `NOTIFY_SOCKET`, no
//! `LISTEN_FDS`) a socket is bound and closed as any other.

use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{self, IoSlice};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

/// The queue of connections the kernel completes before the process accepts them: what waits
/// out a hand-over. The kernel caps it at `net.core.somaxconn` (4096 by default).
pub const BACKLOG: i32 = 4096;

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
const FIRST_FD: RawFd = 3;

pub struct Listeners {
    /// What the previous process stored, by name, not taken yet.
    inherited: Mutex<HashMap<String, Vec<OwnedFd>>>,
    /// systemd's notification socket: a path, or `@name` for an abstract one.
    notify: Option<String>,
}

impl Listeners {
    /// The sockets systemd passed to this process, and its notification socket.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        let passed = passed(
            &var("LISTEN_PID"),
            &var("LISTEN_FDS"),
            &var("LISTEN_FDNAMES"),
            std::process::id(),
        );
        let fds = passed
            .into_iter()
            .map(|(name, fd)| {
                // Ours from here on; not for the children (Firecracker, the jailer).
                let _ = nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
                );
                // SAFETY: systemd passed these descriptors to this process (LISTEN_PID is ours),
                // and nothing else in it owns them.
                (name, unsafe { OwnedFd::from_raw_fd(fd) })
            })
            .collect();
        Self::new(fds, std::env::var("NOTIFY_SOCKET").ok())
    }

    pub fn new(inherited: Vec<(String, OwnedFd)>, notify: Option<String>) -> Self {
        let mut by_name: HashMap<String, Vec<OwnedFd>> = HashMap::new();
        for (name, fd) in inherited {
            by_name.entry(name).or_default().push(fd);
        }
        Self {
            inherited: Mutex::new(by_name),
            notify: notify.filter(|s| !s.is_empty()),
        }
    }

    /// No store: every socket bound afresh and kept nowhere.
    pub fn none() -> Self {
        Self::new(vec![], None)
    }

    /// A TCP listener on `addr` under `name`: the one the previous process stored, when it is
    /// on that address, else a new one, stored. A stored one on another address (the
    /// configuration changed) is closed and leaves the store.
    pub fn tcp(&self, name: &str, addr: SocketAddr) -> io::Result<TcpListener> {
        let stored = self
            .inherited
            .lock()
            .unwrap()
            .remove(name)
            .unwrap_or_default();
        let mut kept = None;
        let mut stale = false;
        for fd in stored {
            let sock = Socket::from(fd);
            let on = sock.local_addr().ok().and_then(|a| a.as_socket());
            if kept.is_none() && on == Some(addr) && sock.r#type().ok() == Some(Type::STREAM) {
                kept = Some(sock);
            } else {
                stale = true;
            }
        }
        if stale {
            self.remove(name)?;
        }
        match kept {
            Some(sock) if !stale => Ok(sock.into()),
            // Removing the name took the kept one out of the store too: it goes back in.
            Some(sock) => {
                self.store(name, &sock)?;
                Ok(sock.into())
            }
            None => {
                let sock = bind(addr)?;
                self.store(name, &sock)?;
                Ok(sock.into())
            }
        }
    }

    /// The socket under `name` leaves the store (an endpoint removed).
    pub fn release(&self, name: &str) -> io::Result<()> {
        self.inherited.lock().unwrap().remove(name);
        self.remove(name)
    }

    /// What the previous process stored and this one did not take (an endpoint removed while
    /// no process ran, a listener turned off) leaves the store and is closed.
    pub fn release_unused(&self) -> io::Result<Vec<String>> {
        let names: Vec<String> = self
            .inherited
            .lock()
            .unwrap()
            .drain()
            .map(|(n, _)| n)
            .collect();
        for n in &names {
            self.remove(n)?;
        }
        Ok(names)
    }

    fn store(&self, name: &str, sock: &Socket) -> io::Result<()> {
        self.send(
            &format!("FDSTORE=1\nFDNAME={name}\n"),
            Some(sock.as_raw_fd()),
        )
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        self.send(&format!("FDSTOREREMOVE=1\nFDNAME={name}\n"), None)
    }

    /// One `sd_notify` message, with a descriptor as `SCM_RIGHTS`: systemd keeps its own copy.
    fn send(&self, msg: &str, fd: Option<RawFd>) -> io::Result<()> {
        use nix::sys::socket::{
            sendmsg, socket, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
        };
        let Some(path) = &self.notify else {
            return Ok(());
        };
        let addr = notify_addr(path)?;
        let sock = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )?;
        let fds = fd.map(|f| [f]);
        let cmsgs: Vec<ControlMessage> = fds.iter().map(|f| ControlMessage::ScmRights(f)).collect();
        sendmsg(
            sock.as_raw_fd(),
            &[IoSlice::new(msg.as_bytes())],
            &cmsgs,
            MsgFlags::empty(),
            Some(&addr),
        )
        .map_err(|e| io::Error::other(format!("sd_notify to {path}: {e}")))?;
        Ok(())
    }
}

fn notify_addr(path: &str) -> io::Result<nix::sys::socket::UnixAddr> {
    let bad = |e: nix::Error| io::Error::other(format!("NOTIFY_SOCKET {path}: {e}"));
    match path.strip_prefix('@') {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(name) => nix::sys::socket::UnixAddr::new_abstract(name.as_bytes()).map_err(bad),
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        Some(_) => Err(io::Error::other(format!(
            "NOTIFY_SOCKET {path}: abstract sockets are Linux's"
        ))),
        None => nix::sys::socket::UnixAddr::new(path).map_err(bad),
    }
}

/// A new listening socket, as `TcpListener::bind` makes one, with the backlog set.
fn bind(addr: SocketAddr) -> io::Result<Socket> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())
        .map_err(|e| io::Error::new(e.kind(), format!("bind {addr}: {e}")))?;
    sock.listen(BACKLOG)?;
    Ok(sock)
}

/// The descriptors systemd passed, with their names (`sd_listen_fds_with_names`): none unless
/// `LISTEN_PID` is this process, a name `unknown` where `LISTEN_FDNAMES` has none.
fn passed(pid: &str, count: &str, names: &str, me: u32) -> Vec<(String, RawFd)> {
    if pid.parse::<u32>().ok() != Some(me) {
        return vec![];
    }
    let n: RawFd = count.parse().unwrap_or(0);
    let mut names = names.split(':');
    (0..n.max(0))
        .map(|i| {
            let name = names.next().filter(|s| !s.is_empty()).unwrap_or("unknown");
            (name.to_string(), FIRST_FD + i)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::io::IoSliceMut;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn passed_descriptors_are_ours_only() {
        assert_eq!(
            passed("42", "3", "api:http:ep_1", 42),
            vec![("api".into(), 3), ("http".into(), 4), ("ep_1".into(), 5)],
            "a colon separates names: an endpoint's name carries none"
        );
        assert_eq!(passed("42", "2", "api", 42)[1], ("unknown".into(), 4));
        assert!(passed("41", "2", "api:http", 42).is_empty());
        assert!(passed("", "2", "api:http", 42).is_empty());
        assert!(passed("42", "x", "", 42).is_empty());
    }

    /// systemd's side of the notification socket: each message and the descriptors it carried.
    struct Notify {
        sock: UnixDatagram,
        path: String,
        _dir: tempfile::TempDir,
    }

    impl Notify {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("notify").display().to_string();
            let sock = UnixDatagram::bind(&path).unwrap();
            sock.set_nonblocking(true).unwrap();
            Self {
                sock,
                path,
                _dir: dir,
            }
        }

        fn messages(&self) -> Vec<(String, Vec<OwnedFd>)> {
            let mut out = vec![];
            loop {
                let mut buf = [0u8; 256];
                let mut cmsg = nix::cmsg_space!([RawFd; 1]);
                let mut iov = [IoSliceMut::new(&mut buf)];
                let Ok(r) = recvmsg::<()>(
                    self.sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::empty(),
                ) else {
                    return out;
                };
                let mut fds = vec![];
                for c in r.cmsgs().unwrap() {
                    if let ControlMessageOwned::ScmRights(f) = c {
                        // SAFETY: received with this message, owned by nothing else.
                        fds.extend(f.into_iter().map(|f| unsafe { OwnedFd::from_raw_fd(f) }));
                    }
                }
                let n = r.bytes;
                out.push((String::from_utf8_lossy(&buf[..n]).into_owned(), fds));
            }
        }
    }

    fn any_port() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn a_new_listener_is_stored_and_queues_once_its_process_closed_it() {
        let n = Notify::new();
        let l = Listeners::new(vec![], Some(n.path.clone()));
        let ln = l.tcp("api", any_port()).unwrap();
        let addr = ln.local_addr().unwrap();
        let mut msgs = n.messages();
        assert_eq!(msgs.len(), 1);
        let (msg, mut fds) = msgs.remove(0);
        assert_eq!(msg, "FDSTORE=1\nFDNAME=api\n");
        assert_eq!(fds.len(), 1);
        // The process goes; the store's copy stays, and a client is queued, not refused.
        drop(ln);
        let client = std::net::TcpStream::connect(addr).expect("queued by the stored socket");
        // The next process gets the stored socket back and accepts that client.
        let next = Listeners::new(vec![("api".into(), fds.remove(0))], Some(n.path.clone()));
        let ln = next.tcp("api", addr).unwrap();
        assert!(n.messages().is_empty(), "taken back, not stored again");
        let (_, from) = ln.accept().unwrap();
        assert_eq!(from, client.local_addr().unwrap());
    }

    #[test]
    fn a_stored_listener_on_another_address_is_replaced() {
        let n = Notify::new();
        let old = bind(any_port()).unwrap();
        let other = old.local_addr().unwrap().as_socket().unwrap();
        let l = Listeners::new(vec![("http".into(), old.into())], Some(n.path.clone()));
        let ln = l.tcp("http", any_port()).unwrap();
        assert_ne!(ln.local_addr().unwrap(), other);
        let msgs: Vec<String> = n.messages().into_iter().map(|(m, _)| m).collect();
        assert_eq!(
            msgs,
            ["FDSTOREREMOVE=1\nFDNAME=http\n", "FDSTORE=1\nFDNAME=http\n"]
        );
        assert!(
            std::net::TcpStream::connect(other).is_err(),
            "the old socket is closed"
        );
    }

    #[test]
    fn what_is_not_taken_leaves_the_store() {
        let n = Notify::new();
        let gone = bind(any_port()).unwrap();
        let kept = bind(any_port()).unwrap();
        let kept_addr = kept.local_addr().unwrap().as_socket().unwrap();
        let l = Listeners::new(
            vec![("ep_gone".into(), gone.into()), ("api".into(), kept.into())],
            Some(n.path.clone()),
        );
        l.tcp("api", kept_addr).unwrap();
        assert_eq!(l.release_unused().unwrap(), ["ep_gone"]);
        l.release("ep_2").unwrap();
        let msgs: Vec<String> = n.messages().into_iter().map(|(m, _)| m).collect();
        assert_eq!(
            msgs,
            [
                "FDSTOREREMOVE=1\nFDNAME=ep_gone\n",
                "FDSTOREREMOVE=1\nFDNAME=ep_2\n"
            ]
        );
    }

    #[test]
    fn without_systemd_a_listener_is_only_bound() {
        let l = Listeners::none();
        let ln = l.tcp("api", any_port()).unwrap();
        let addr = ln.local_addr().unwrap();
        drop(ln);
        assert!(std::net::TcpStream::connect(addr).is_err());
        assert!(l.release_unused().unwrap().is_empty());
    }
}
