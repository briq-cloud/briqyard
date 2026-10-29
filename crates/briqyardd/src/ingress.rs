//! How the outside reaches a machine: a TCP port on the host per TCP endpoint, and one HTTP
//! listener that routes by host name. A connection to a sleeping machine's endpoint wakes it.
//! HTTP routing reads the request head on the raw connection and then splices bytes, so
//! WebSockets and streaming responses pass through untouched. The bytes each way are added
//! to the machine's usage as they pass (ADR 0017). Every listener is kept in systemd's file
//! descriptor store (ADR 0051): at a hand-over this daemon stops accepting, the kernel queues
//! what arrives for the next one, and the connections open here go on for the drain's bound.

use crate::machine::{EndpointRec, Manager};
use crate::usage::Traffic;
use anyhow::{anyhow, Context as _, Result};
use briqyard_api::listeners::Listeners;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct Ingress {
    mgr: Manager,
    bind: String,
    http: String,
    wake_timeout: Duration,
    store: Arc<Listeners>,
    /// The accept loop of each listener, by its name in the store.
    accepting: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    hosts: Arc<Mutex<HashMap<String, EndpointRec>>>,
    /// Set at a hand-over or a stop: no listener opens or accepts again.
    stopped: Arc<AtomicBool>,
    open: Arc<Open>,
}

/// The connections being served, and a wake for the drain when the last one ends.
#[derive(Default)]
struct Open {
    n: AtomicUsize,
    none: tokio::sync::Notify,
}

impl Open {
    async fn drain(&self, deadline: tokio::time::Instant) -> usize {
        loop {
            // Registered before the count is read, so a last end in between is not missed.
            let none = self.none.notified();
            tokio::pin!(none);
            none.as_mut().enable();
            let n = self.n.load(SeqCst);
            if n == 0 || tokio::time::timeout_at(deadline, none).await.is_err() {
                return self.n.load(SeqCst);
            }
        }
    }
}

/// One connection being served, from its accept to its end.
struct Served(Arc<Open>);

impl Served {
    fn new(open: &Arc<Open>) -> Self {
        open.n.fetch_add(1, SeqCst);
        Self(open.clone())
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        if self.0.n.fetch_sub(1, SeqCst) == 1 {
            self.0.none.notify_waiters();
        }
    }
}

impl Ingress {
    pub fn new(
        mgr: Manager,
        bind: &str,
        http: &str,
        boot_timeout: Duration,
        store: Arc<Listeners>,
    ) -> Self {
        Self {
            mgr,
            bind: bind.to_string(),
            http: http.to_string(),
            // A connection waits for the machine as long as a boot may take, plus the
            // service's own start.
            wake_timeout: boot_timeout + Duration::from_secs(30),
            store,
            accepting: Default::default(),
            hosts: Default::default(),
            stopped: Default::default(),
            open: Default::default(),
        }
    }

    /// Opens the listeners for every endpoint and follows additions and removals.
    pub async fn start(&self) -> Result<()> {
        for ep in self.mgr.all_endpoints() {
            if let Err(e) = self.add(ep.clone()).await {
                tracing::error!(endpoint = ep.id, err = %e, "endpoint listener");
            }
        }
        let mut events = self.mgr.endpoint_events();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let event = events.recv().await;
                if me.stopped.load(SeqCst) {
                    return;
                }
                match event {
                    Ok((ep, true)) => {
                        if let Err(e) = me.add(ep.clone()).await {
                            tracing::error!(endpoint = ep.id, err = %e, "endpoint listener");
                        }
                    }
                    Ok((ep, false)) => me.remove(&ep),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
        });
        if !self.http.is_empty() {
            let addr: SocketAddr = self
                .http
                .parse()
                .with_context(|| format!("ingress.http {:?}", self.http))?;
            let ln = self.listen("http", addr).context("http ingress")?;
            tracing::info!(addr = self.http, "http ingress listening");
            let me = self.clone();
            let h = tokio::spawn(async move {
                loop {
                    if let Ok((conn, _)) = ln.accept().await {
                        let me = me.clone();
                        let served = Served::new(&me.open);
                        tokio::spawn(async move {
                            me.serve_http(conn).await;
                            drop(served);
                        });
                    }
                }
            });
            self.accepting.lock().unwrap().insert("http".into(), h);
        }
        Ok(())
    }

    /// The listener under `name`: the one the previous daemon left in the store, or a new one.
    fn listen(&self, name: &str, addr: SocketAddr) -> Result<TcpListener> {
        let ln = self
            .store
            .tcp(name, addr)
            .with_context(|| format!("listen on {addr}"))?;
        ln.set_nonblocking(true)?;
        Ok(TcpListener::from_std(ln)?)
    }

    /// Accepts no more: every listener's socket stays in the store, where the kernel queues
    /// what arrives for the next daemon (a stop leaves nothing in it). The connections being
    /// served go on.
    pub fn stop_accepting(&self) {
        self.stopped.store(true, SeqCst);
        for (_, h) in self.accepting.lock().unwrap().drain() {
            h.abort();
        }
    }

    /// Waits until no connection is served, or until `deadline`. Returns how many still are.
    pub async fn drain(&self, deadline: tokio::time::Instant) -> usize {
        self.open.drain(deadline).await
    }

    async fn add(&self, ep: EndpointRec) -> Result<()> {
        match ep.protocol.as_str() {
            "http" => {
                self.hosts
                    .lock()
                    .unwrap()
                    .insert(ep.host.to_lowercase(), ep);
                Ok(())
            }
            "tcp" => {
                // Stored under the endpoint's id (`ep_…`), beside `http` and the API's `api`:
                // letters, digits and `_`, a name sd_notify(3) takes.
                let name = ep.id.clone();
                if self.stopped.load(SeqCst) || self.accepting.lock().unwrap().contains_key(&name) {
                    return Ok(());
                }
                let addr: SocketAddr =
                    format!("{}:{}", self.bind, ep.host_port.unwrap_or(0)).parse()?;
                let ln = self.listen(&name, addr)?;
                tracing::info!(endpoint = ep.id, machine = ep.machine_id, %addr, port = ep.port, "tcp endpoint listening");
                let me = self.clone();
                let h = tokio::spawn(async move {
                    loop {
                        match ln.accept().await {
                            Ok((conn, _)) => {
                                let me = me.clone();
                                let ep = ep.clone();
                                let served = Served::new(&me.open);
                                tokio::spawn(async move {
                                    me.proxy_tcp(ep, conn).await;
                                    drop(served);
                                });
                            }
                            Err(_) => return,
                        }
                    }
                });
                let mut accepting = self.accepting.lock().unwrap();
                // A stop that came while this one opened: it accepts nothing either.
                if self.stopped.load(SeqCst) {
                    h.abort();
                } else {
                    accepting.insert(name, h);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn remove(&self, ep: &EndpointRec) {
        let name = ep.id.clone();
        if let Some(h) = self.accepting.lock().unwrap().remove(&name) {
            h.abort();
            if let Err(e) = self.store.release(&name) {
                tracing::warn!(endpoint = ep.id, err = %e, "endpoint listener left in the store");
            }
        }
        self.hosts.lock().unwrap().remove(&ep.host.to_lowercase());
    }

    /// Connects to the machine's port, waking it, waiting for it to be ready (ADR 0022) and
    /// for the port to listen, all within the wake timeout.
    async fn dial(&self, ep: &EndpointRec) -> Result<TcpStream> {
        let deadline = tokio::time::Instant::now() + self.wake_timeout;
        let ip = tokio::time::timeout(
            self.wake_timeout,
            self.mgr.ready_addr(&ep.machine_id, self.wake_timeout),
        )
        .await
        .map_err(|_| anyhow!("wake timed out"))??;
        let addr = SocketAddr::from((ip, ep.port));
        loop {
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) if tokio::time::Instant::now() > deadline => {
                    return Err(anyhow!("{addr} did not answer: {e}"))
                }
                _ if tokio::time::Instant::now() > deadline => {
                    return Err(anyhow!("{addr} did not answer"))
                }
                _ => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
    }

    async fn proxy_tcp(&self, ep: EndpointRec, conn: TcpStream) {
        match self.dial(&ep).await {
            Ok(mut target) => {
                let traffic = self.mgr.traffic(&ep.machine_id).unwrap_or_default();
                let mut conn = Counted { conn, traffic };
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut target).await;
            }
            Err(e) => {
                tracing::warn!(endpoint = ep.id, machine = ep.machine_id, err = %e, "tcp endpoint: cannot reach machine")
            }
        }
    }

    async fn serve_http(&self, mut conn: TcpStream) {
        let Some((head, host)) = read_head(&mut conn, HEAD_TIMEOUT).await else {
            return;
        };
        let ep = self.hosts.lock().unwrap().get(&host).cloned();
        let ep = match ep {
            Some(ep) => ep,
            None => {
                let body = format!("no endpoint for {host}\n");
                let _ = conn.write_all(format!("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                return;
            }
        };
        let mut target = match self.dial(&ep).await {
            Ok(t) => t,
            Err(e) => {
                let body = format!("the machine did not answer: {e}\n");
                let _ = conn.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                return;
            }
        };
        if target.write_all(&head).await.is_err() {
            return;
        }
        let traffic = self.mgr.traffic(&ep.machine_id).unwrap_or_default();
        traffic.received(head.len() as u64);
        let mut conn = Counted { conn, traffic };
        let _ = tokio::io::copy_bidirectional(&mut conn, &mut target).await;
    }
}

/// The client's side of a proxied connection: what is read from it and written to it is
/// added to the machine's traffic as it passes, so a connection cut short still counts.
struct Counted<S> {
    conn: S,
    traffic: Arc<Traffic>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.conn).poll_read(cx, buf);
        self.traffic.received((buf.filled().len() - before) as u64);
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.conn).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = r {
            self.traffic.sent(n as u64);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

/// How long a client has to send its whole request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads a request head until it names a host, all of it within `limit`: a client that sends
/// it slower is dropped, so it cannot hold a task. A refused head is answered here. Returns the
/// bytes read and the host.
async fn read_head<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut S,
    limit: Duration,
) -> Option<(Vec<u8>, String)> {
    let read = async {
        let mut head = Vec::with_capacity(4096);
        let mut buf = [0u8; 4096];
        loop {
            let n = match conn.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return None,
            };
            head.extend_from_slice(&buf[..n]);
            match parse_head(&head) {
                Head::Partial => continue,
                Head::Host(host) => return Some((head, host)),
                Head::Refused(status) => {
                    let _ = conn
                        .write_all(
                            format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes(),
                        )
                        .await;
                    return None;
                }
            }
        }
    };
    tokio::time::timeout(limit, read).await.ok().flatten()
}

/// The longest request head read, and the most header lines in it: beyond either, 431.
pub const MAX_HEAD: usize = 64 << 10;
const MAX_HEADERS: usize = 100;

/// What the bytes read so far say about a request head, parsed by httparse (ADR 0033).
#[derive(Debug, PartialEq)]
pub enum Head {
    /// The head is not complete yet.
    Partial,
    /// The head is complete and for this host: lowercase, without its port.
    Host(String),
    /// Answered with this status line, and the connection closed.
    Refused(&'static str),
}

const TOO_LARGE: &str = "431 Request Header Fields Too Large";
const BAD_REQUEST: &str = "400 Bad Request";

pub fn parse_head(buf: &[u8]) -> Head {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Partial) if buf.len() > MAX_HEAD => Head::Refused(TOO_LARGE),
        Ok(httparse::Status::Partial) => Head::Partial,
        Ok(httparse::Status::Complete(n)) if n > MAX_HEAD => Head::Refused(TOO_LARGE),
        Ok(httparse::Status::Complete(_)) => match host_of(&req) {
            Some(host) => Head::Host(host),
            None => Head::Refused(BAD_REQUEST),
        },
        Err(httparse::Error::TooManyHeaders) => Head::Refused(TOO_LARGE),
        Err(_) => Head::Refused(BAD_REQUEST),
    }
}

/// The host a parsed request is for, or `None` for a request that must get a 400 (RFC 9112
/// §3.2): no host, more than one `Host`, or an absolute-form target whose authority is not
/// the `Host` the machine will read.
fn host_of(req: &httparse::Request) -> Option<String> {
    let mut hosts = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"));
    let header = hosts.next();
    if hosts.next().is_some() {
        return None;
    }
    let header = match header {
        Some(h) => Some(std::str::from_utf8(h.value).ok()?.trim()),
        None => None,
    };
    let authority = req.path.and_then(absolute_authority);
    let host = match (authority, header) {
        (Some(a), Some(h)) if !a.eq_ignore_ascii_case(h) => return None,
        (Some(a), _) => a,
        (None, Some(h)) => h,
        (None, None) => return None,
    };
    let host = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        Some(_) if host.ends_with(']') => host,
        Some(_) => return None,
        None => host,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The authority of an absolute-form request target (`http://host:port/path`).
fn absolute_authority(target: &str) -> Option<&str> {
    let (scheme, rest) = target.split_once("://")?;
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return None;
    }
    Some(rest.split(['/', '?', '#']).next().unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(head: &[u8]) -> Head {
        Head::Host(String::from_utf8(head.to_vec()).unwrap())
    }

    #[test]
    fn host_header() {
        let head = b"GET / HTTP/1.1\r\nHost: app.byard.localhost\r\nAccept: */*\r\n\r\n";
        assert_eq!(parse_head(head), host(b"app.byard.localhost"));
    }

    #[test]
    fn host_without_port_and_lowercased() {
        for (head, want) in [
            (
                &b"GET / HTTP/1.1\r\nHost: App.Byard.Localhost:8080\r\n\r\n"[..],
                "app.byard.localhost",
            ),
            (
                b"GET / HTTP/1.1\r\nhost:   x.example  \r\n\r\n",
                "x.example",
            ),
            (
                b"GET / HTTP/1.1\r\nHOST: X.EXAMPLE:443\r\n\r\n",
                "x.example",
            ),
            (b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", "[::1]"),
        ] {
            assert_eq!(parse_head(head), host(want.as_bytes()));
        }
    }

    #[test]
    fn a_head_arrives_in_pieces() {
        let head = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\nbody";
        for n in 0..head.len() - 6 {
            assert_eq!(parse_head(&head[..n]), Head::Partial, "at {n}");
        }
        assert_eq!(parse_head(head), host(b"a.example"));
    }

    #[test]
    fn no_host_is_a_bad_request() {
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"),
            Head::Refused(BAD_REQUEST)
        );
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nHost:\r\n\r\n"),
            Head::Refused(BAD_REQUEST)
        );
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nHost: a.example:http\r\n\r\n"),
            Head::Refused(BAD_REQUEST)
        );
    }

    #[test]
    fn the_request_line_is_not_a_header() {
        // A path that looks like a header is not one, and neither is a header that ends in host.
        let head = b"GET /host:evil HTTP/1.1\r\nX-Host: a\r\nHost: one.example\r\n\r\n";
        assert_eq!(parse_head(head), host(b"one.example"));
    }

    #[test]
    fn two_hosts_are_a_bad_request() {
        // The machine might read the other one (RFC 9112 §3.2).
        for head in [
            &b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: one.example\r\nhost: one.example\r\n\r\n",
        ] {
            assert_eq!(parse_head(head), Head::Refused(BAD_REQUEST));
        }
    }

    #[test]
    fn an_absolute_target_must_match_its_host() {
        let ok = b"GET http://A.example:8080/x?y HTTP/1.1\r\nHost: a.example:8080\r\n\r\n";
        assert_eq!(parse_head(ok), host(b"a.example"));
        assert_eq!(
            parse_head(b"GET https://a.example HTTP/1.1\r\n\r\n"),
            host(b"a.example")
        );
        for head in [
            &b"GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n"[..],
            b"GET http://evil@a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
            b"GET http:///x HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                parse_head(head),
                Head::Refused(BAD_REQUEST),
                "{}",
                String::from_utf8_lossy(head)
            );
        }
        // Other targets route by Host.
        assert_eq!(
            parse_head(b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            host(b"a.example")
        );
        assert_eq!(
            parse_head(b"CONNECT b.example:443 HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            host(b"a.example")
        );
    }

    #[test]
    fn header_injection_is_a_bad_request() {
        for head in [
            // A space before the colon, a folded line, a bare CR, a NUL, a line without a colon.
            &b"GET / HTTP/1.1\r\nHost : a.example\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nX: y\r\n Host: b.example\r\nHost: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a.example\rX-Evil: 1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a.example\0b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost a.example\r\n\r\n",
            // A request line with a space in the path, a header before the request line.
            b"GET /a b HTTP/1.1\r\nHost: a.example\r\n\r\n",
            b"Host: a.example\r\nGET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/9.9\r\nHost: a.example\r\n\r\n",
        ] {
            assert_eq!(
                parse_head(head),
                Head::Refused(BAD_REQUEST),
                "{}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn oversize_heads_are_refused() {
        let mut long = b"GET / HTTP/1.1\r\nHost: a.example\r\nX: ".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        assert_eq!(parse_head(&long), Head::Refused(TOO_LARGE));
        long.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse_head(&long), Head::Refused(TOO_LARGE));
        let mut many = b"GET / HTTP/1.1\r\nHost: a.example\r\n".to_vec();
        for i in 0..MAX_HEADERS {
            many.extend_from_slice(format!("X-{i}: 1\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(parse_head(&many), Head::Refused(TOO_LARGE));
    }

    /// A client that sends its head one byte at a time, `every` apart.
    fn trickle(every: Duration) -> tokio::io::DuplexStream {
        let (mut client, server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            for b in b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n" {
                tokio::time::sleep(every).await;
                if client.write_all(&[*b]).await.is_err() {
                    return;
                }
            }
            // Held open, as a slow client would.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        server
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_slower_than_the_deadline_is_dropped() {
        // Each byte comes well within any per-read timeout; the whole head does not.
        let mut conn = trickle(Duration::from_secs(1));
        let t = tokio::time::Instant::now();
        assert!(read_head(&mut conn, HEAD_TIMEOUT).await.is_none());
        assert_eq!(t.elapsed().as_secs(), HEAD_TIMEOUT.as_secs());
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_within_the_deadline_is_read() {
        let mut conn = trickle(Duration::from_millis(100));
        let (head, host) = read_head(&mut conn, HEAD_TIMEOUT).await.unwrap();
        assert_eq!(host, "a.example");
        assert!(head.ends_with(b"\r\n\r\n"));
    }
    #[tokio::test]
    async fn a_counted_connection_adds_both_ways_as_bytes_pass() {
        let (client, near) = tokio::io::duplex(64);
        let traffic = Arc::new(Traffic::default());
        let mut conn = Counted {
            conn: near,
            traffic: traffic.clone(),
        };
        let mut client = client;
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 16);
        conn.write_all(b"HTTP/1.1 200 OK\r\n\r\nhello")
            .await
            .unwrap();
        // Counted before the connection ends: a tick in the middle takes what passed so far.
        assert_eq!(traffic.take(), (16, 24));
        drop(client);
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
        assert_eq!(traffic.take(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_ends_with_the_last_connection_or_at_its_bound() {
        let open = Arc::new(Open::default());
        let t = tokio::time::Instant::now();
        assert_eq!(
            open.drain(t + Duration::from_secs(10)).await,
            0,
            "nothing open"
        );
        assert_eq!(t.elapsed(), Duration::ZERO);
        let (a, b) = (Served::new(&open), Served::new(&open));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(a);
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(b);
        });
        assert_eq!(open.drain(t + Duration::from_secs(10)).await, 0);
        assert_eq!(
            t.elapsed(),
            Duration::from_secs(3),
            "ended with the last one"
        );
        let _held = Served::new(&open);
        let t = tokio::time::Instant::now();
        assert_eq!(open.drain(t + Duration::from_secs(10)).await, 1, "one cut");
        assert_eq!(t.elapsed(), Duration::from_secs(10));
    }

    #[test]
    fn lone_newlines_are_fine() {
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\nHost: a.example\n\n"),
            host(b"a.example")
        );
    }
}
