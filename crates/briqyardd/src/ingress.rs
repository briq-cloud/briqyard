//! How the outside reaches a machine: a TCP port on the host per TCP endpoint, and one HTTP
//! listener that routes by host name. A connection to a sleeping machine's endpoint wakes it.
//! HTTP routing reads the request head on the raw connection and then splices bytes, so
//! WebSockets and streaming responses pass through untouched. The bytes each way are added
//! to the machine's usage as they pass (ADR 0017).

use crate::machine::{EndpointRec, Manager};
use crate::usage::Traffic;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
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
    listeners: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    hosts: Arc<Mutex<HashMap<String, EndpointRec>>>,
}

impl Ingress {
    pub fn new(mgr: Manager, bind: &str, http: &str, boot_timeout: Duration) -> Self {
        Self {
            mgr,
            bind: bind.to_string(),
            http: http.to_string(),
            // A connection waits for the machine as long as a boot may take, plus the
            // service's own start.
            wake_timeout: boot_timeout + Duration::from_secs(30),
            listeners: Default::default(),
            hosts: Default::default(),
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
                match events.recv().await {
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
            let ln = TcpListener::bind(&self.http)
                .await
                .map_err(|e| anyhow!("http ingress on {}: {e}", self.http))?;
            tracing::info!(addr = self.http, "http ingress listening");
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok((conn, _)) = ln.accept().await {
                        let me = me.clone();
                        tokio::spawn(async move { me.serve_http(conn).await });
                    }
                }
            });
        }
        Ok(())
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
                if self.listeners.lock().unwrap().contains_key(&ep.id) {
                    return Ok(());
                }
                let addr: SocketAddr =
                    format!("{}:{}", self.bind, ep.host_port.unwrap_or(0)).parse()?;
                let ln = TcpListener::bind(addr).await?;
                tracing::info!(endpoint = ep.id, machine = ep.machine_id, %addr, port = ep.port, "tcp endpoint listening");
                let me = self.clone();
                let id = ep.id.clone();
                let h = tokio::spawn(async move {
                    loop {
                        match ln.accept().await {
                            Ok((conn, _)) => {
                                let me = me.clone();
                                let ep = ep.clone();
                                tokio::spawn(async move { me.proxy_tcp(ep, conn).await });
                            }
                            Err(_) => return,
                        }
                    }
                });
                self.listeners.lock().unwrap().insert(id, h);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn remove(&self, ep: &EndpointRec) {
        if let Some(h) = self.listeners.lock().unwrap().remove(&ep.id) {
            h.abort();
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
        // Read the request head: enough to find the Host header.
        let mut head = Vec::with_capacity(4096);
        let mut buf = [0u8; 4096];
        let end = loop {
            let n = match tokio::time::timeout(Duration::from_secs(30), conn.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            head.extend_from_slice(&buf[..n]);
            if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if head.len() > 64 << 10 {
                let _ = conn.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n").await;
                return;
            }
        };
        let host = host_of(&head[..end]);
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

/// The host name a request head is for: the first `Host` header, lowercased, without its
/// port. Empty when there is none, which matches no endpoint.
fn host_of(head: &[u8]) -> String {
    let text = String::from_utf8_lossy(head);
    let host = text
        .lines()
        .skip(1)
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim().to_lowercase())
        })
        .unwrap_or_default();
    host.split(':').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header() {
        let head = b"GET / HTTP/1.1\r\nHost: app.byard.localhost\r\nAccept: */*\r\n\r\n";
        assert_eq!(host_of(head), "app.byard.localhost");
    }

    #[test]
    fn host_without_port_and_lowercased() {
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHost: App.Byard.Localhost:8080\r\n\r\n"),
            "app.byard.localhost"
        );
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nhost:   x.example  \r\n\r\n"),
            "x.example"
        );
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHOST: X.EXAMPLE:443\r\n\r\n"),
            "x.example"
        );
    }

    #[test]
    fn missing_host_is_empty() {
        assert_eq!(host_of(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"), "");
        assert_eq!(host_of(b"GET / HTTP/1.1\r\nHost:\r\n\r\n"), "");
        assert_eq!(host_of(b""), "");
    }

    #[test]
    fn the_request_line_is_not_a_header() {
        // A path that looks like a header must not be read as one; only the first Host counts.
        let head = b"GET /host:evil HTTP/1.1\r\nX-Host: a\r\nHost: one.example\r\nHost: two.example\r\n\r\n";
        assert_eq!(host_of(head), "one.example");
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

    #[test]
    fn lone_newlines_are_fine() {
        assert_eq!(host_of(b"GET / HTTP/1.1\nHost: a.example\n\n"), "a.example");
    }
}
