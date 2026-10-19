//! How the outside reaches a machine: a TCP port on the host per TCP endpoint, and one HTTP
//! listener that routes by host name. A connection to a sleeping machine's endpoint wakes it.
//! HTTP routing reads the request head on the raw connection and then splices bytes, so
//! WebSockets and streaming responses pass through untouched.

use crate::machine::{EndpointRec, Manager};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    pub fn new(mgr: Manager, bind: &str, http: &str) -> Self {
        Self {
            mgr,
            bind: if bind.is_empty() {
                "0.0.0.0".into()
            } else {
                bind.to_string()
            },
            http: http.to_string(),
            wake_timeout: Duration::from_secs(90),
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

    /// Connects to the machine's port, waking it and waiting for the port to listen.
    async fn dial(&self, ep: &EndpointRec) -> Result<TcpStream> {
        let deadline = tokio::time::Instant::now() + self.wake_timeout;
        let ip = tokio::time::timeout(
            self.wake_timeout,
            self.mgr.machine_addr(&ep.machine_id, true),
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

    async fn proxy_tcp(&self, ep: EndpointRec, mut conn: TcpStream) {
        match self.dial(&ep).await {
            Ok(mut target) => {
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
        let _ = tokio::io::copy_bidirectional(&mut conn, &mut target).await;
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

    #[test]
    fn lone_newlines_are_fine() {
        assert_eq!(host_of(b"GET / HTTP/1.1\nHost: a.example\n\n"), "a.example");
    }
}
