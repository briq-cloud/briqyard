//! The gateway's DNS: answers `<name>.internal` for the tenant whose gateway the query came in
//! on, and forwards everything else upstream as raw packets.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub struct Resolver {
    upstream: Arc<Vec<SocketAddr>>,
    /// gateway → name (lowercase, no trailing dot) → address
    names: Arc<RwLock<HashMap<Ipv4Addr, HashMap<String, Ipv4Addr>>>>,
    listeners: Arc<RwLock<HashMap<Ipv4Addr, tokio::task::JoinHandle<()>>>>,
}

impl Resolver {
    pub fn new(upstream: &[String]) -> Self {
        let mut ups: Vec<SocketAddr> = Vec::new();
        let sources: Vec<String> = if upstream.is_empty() {
            system_upstreams()
        } else {
            upstream.to_vec()
        };
        for u in sources {
            let u = if u.contains(':') {
                u
            } else {
                format!("{u}:53")
            };
            if let Ok(a) = u.parse() {
                ups.push(a);
            }
        }
        if ups.is_empty() {
            ups.push("1.1.1.1:53".parse().unwrap());
        }
        Self {
            upstream: Arc::new(ups),
            names: Default::default(),
            listeners: Default::default(),
        }
    }

    /// Replaces the names served on a gateway.
    pub fn set(&self, gateway: Ipv4Addr, names: HashMap<String, Ipv4Addr>) {
        let names = names
            .into_iter()
            .map(|(k, v)| (k.to_lowercase().trim_end_matches('.').to_string(), v))
            .collect();
        self.names.write().unwrap().insert(gateway, names);
    }

    pub fn unset(&self, gateway: Ipv4Addr) {
        self.names.write().unwrap().remove(&gateway);
        if let Some(h) = self.listeners.write().unwrap().remove(&gateway) {
            h.abort();
        }
    }

    /// Serves DNS on the gateway address. Idempotent per address.
    pub async fn listen(&self, gateway: Ipv4Addr) -> Result<()> {
        if self.listeners.read().unwrap().contains_key(&gateway) {
            return Ok(());
        }
        let sock = UdpSocket::bind(SocketAddr::from((gateway, 53)))
            .await
            .with_context(|| format!("dns on {gateway}:53"))?;
        let me = self.clone();
        let h = tokio::spawn(async move { me.serve(gateway, sock).await });
        self.listeners.write().unwrap().insert(gateway, h);
        Ok(())
    }

    async fn serve(self, gateway: Ipv4Addr, sock: UdpSocket) {
        let sock = Arc::new(sock);
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let q = buf[..n].to_vec();
            let me = self.clone();
            let sock = sock.clone();
            tokio::spawn(async move {
                if let Some(resp) = me.answer(gateway, &q).await {
                    let _ = sock.send_to(&resp, from).await;
                }
            });
        }
    }

    async fn answer(&self, gateway: Ipv4Addr, q: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_question(q)?;
        if let Some(stem) = parsed.name.strip_suffix(".internal") {
            let _ = stem;
            let ip = self
                .names
                .read()
                .unwrap()
                .get(&gateway)
                .and_then(|m| m.get(&parsed.name).copied());
            return Some(build_answer(q, &parsed, ip));
        }
        self.forward(q).await
    }

    async fn forward(&self, q: &[u8]) -> Option<Vec<u8>> {
        for up in self.upstream.iter() {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if sock.send_to(q, up).await.is_err() {
                continue;
            }
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(4), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => return Some(buf[..n].to_vec()),
                _ => continue,
            }
        }
        None
    }
}

fn system_upstreams() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(s) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in s.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 2 && f[0] == "nameserver" && f[1].parse::<Ipv4Addr>().is_ok() {
                out.push(f[1].to_string());
            }
        }
    }
    out.push("1.1.1.1".into());
    out
}

struct Question {
    name: String,
    qtype: u16,
    /// Where the question section ends.
    end: usize,
}

fn parse_question(q: &[u8]) -> Option<Question> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) < 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *q.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        labels.push(String::from_utf8_lossy(q.get(pos..pos + len)?).to_lowercase());
        pos += len;
    }
    let qtype = u16::from_be_bytes([*q.get(pos)?, *q.get(pos + 1)?]);
    Some(Question {
        name: labels.join("."),
        qtype,
        end: pos + 4,
    })
}

fn build_answer(q: &[u8], question: &Question, ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut r = Vec::with_capacity(question.end + 16);
    r.extend_from_slice(&q[..2]);
    // QR, AA, RD copied, RA; rcode 0 or NXDOMAIN
    let rd = q[2] & 0x01;
    r.push(0x84 | rd);
    r.push(if ip.is_some() { 0x80 } else { 0x83 });
    r.extend_from_slice(&[0, 1]);
    let answers: u16 = if ip.is_some() && (question.qtype == 1 || question.qtype == 255) {
        1
    } else {
        0
    };
    r.extend_from_slice(&answers.to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&q[12..question.end]);
    if answers == 1 {
        let ip = ip.unwrap();
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn parses_and_answers() {
        let q = query("Db.Internal", 1);
        let p = parse_question(&q).unwrap();
        assert_eq!(p.name, "db.internal");
        let r = build_answer(&q, &p, Some(Ipv4Addr::new(10, 64, 0, 2)));
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert_eq!(r[3] & 0x0F, 0);
        assert_eq!(&r[r.len() - 4..], &[10, 64, 0, 2]);
        let nx = build_answer(&q, &p, None);
        assert_eq!(nx[3] & 0x0F, 3);
    }
}
