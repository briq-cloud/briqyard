//! The gateway's DNS: answers `<name>.internal` for the tenant whose gateway the query came in
//! on, and forwards everything else upstream as raw packets, except for the sources whose
//! egress policy keeps them inside (ADR 0015): they get internal answers only.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub struct Resolver {
    upstream: Arc<Vec<SocketAddr>>,
    /// gateway → name (lowercase, no trailing dot) → address
    names: Arc<RwLock<HashMap<Ipv4Addr, HashMap<String, Ipv4Addr>>>>,
    /// gateway → the sources answered from `names` alone
    internal_only: Arc<RwLock<HashMap<Ipv4Addr, HashSet<Ipv4Addr>>>>,
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
            internal_only: Default::default(),
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

    /// Answers `source` on `gateway` from the tenant's names alone; `false` ends that.
    pub fn internal_only(&self, gateway: Ipv4Addr, source: Ipv4Addr, on: bool) {
        let mut all = self.internal_only.write().unwrap();
        let set = all.entry(gateway).or_default();
        if on {
            set.insert(source);
        } else {
            set.remove(&source);
            if set.is_empty() {
                all.remove(&gateway);
            }
        }
    }

    /// Whether `internal_only` holds `source` on `gateway`.
    pub fn is_internal_only(&self, gateway: Ipv4Addr, source: Ipv4Addr) -> bool {
        self.internal_only
            .read()
            .unwrap()
            .get(&gateway)
            .is_some_and(|s| s.contains(&source))
    }

    pub fn unset(&self, gateway: Ipv4Addr) {
        self.names.write().unwrap().remove(&gateway);
        self.internal_only.write().unwrap().remove(&gateway);
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
                let std::net::IpAddr::V4(source) = from.ip() else {
                    return;
                };
                if let Some(resp) = me.answer(gateway, source, &q).await {
                    let _ = sock.send_to(&resp, from).await;
                }
            });
        }
    }

    async fn answer(&self, gateway: Ipv4Addr, source: Ipv4Addr, q: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_question(q)?;
        // A source kept inside gets NXDOMAIN for every name the tenant does not have, never
        // a forward. Not REFUSED: glibc and Go fail at once on it, but musl ignores it and
        // waits out its timeout (5 s; res_msend.c: "ignore all other codes such as
        // refusal"), while NXDOMAIN is final for all three.
        if self.is_internal_only(gateway, source) || parsed.name.ends_with(".internal") {
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

    #[tokio::test]
    async fn a_source_kept_inside_gets_internal_answers_only() {
        // The upstream is a socket that answers every query with the same reply, so a
        // forward is seen for what it is.
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r = Resolver::new(&[up.local_addr().unwrap().to_string()]);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = up.recv_from(&mut buf).await {
                let mut resp = buf[..n].to_vec();
                resp[2] |= 0x80;
                resp.extend_from_slice(b"upstream");
                let _ = up.send_to(&resp, from).await;
            }
        });
        let gw = Ipv4Addr::new(10, 64, 1, 1);
        let (kept, open) = (Ipv4Addr::new(10, 64, 1, 3), Ipv4Addr::new(10, 64, 1, 4));
        let db = Ipv4Addr::new(10, 64, 1, 2);
        r.set(gw, HashMap::from([("db.internal".to_string(), db)]));
        r.internal_only(gw, kept, true);
        let outside = query("example.com", 1);
        let from_open = r.answer(gw, open, &outside).await.unwrap();
        assert!(
            from_open.ends_with(b"upstream"),
            "an open source is forwarded"
        );
        let from_kept = r.answer(gw, kept, &outside).await.unwrap();
        assert_eq!(from_kept[3] & 0x0F, 3, "NXDOMAIN");
        assert!(!from_kept.ends_with(b"upstream"));
        let inside = r.answer(gw, kept, &query("db.internal", 1)).await.unwrap();
        assert_eq!(&inside[inside.len() - 4..], &db.octets());
        // Only on its own gateway, and until it is lifted.
        let other_gw = Ipv4Addr::new(10, 64, 2, 1);
        assert!(r
            .answer(other_gw, kept, &outside)
            .await
            .unwrap()
            .ends_with(b"upstream"));
        r.internal_only(gw, kept, false);
        assert!(r
            .answer(gw, kept, &outside)
            .await
            .unwrap()
            .ends_with(b"upstream"));
        assert!(r.internal_only.read().unwrap().is_empty());
    }
}
