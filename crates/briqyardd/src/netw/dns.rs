//! The gateway's DNS: answers `<name>.internal` for the namespace whose gateway the query came in
//! on, and forwards everything else upstream as raw packets, except for the sources whose
//! egress policy keeps them inside (ADR 0015): they get internal answers only. Packets are
//! decoded and encoded by hickory-proto (ADR 0033); the names and the policy are ours.

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{rdata::A, RData, Record, RecordType};
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

    /// Answers `source` on `gateway` from the namespace's names alone; `false` ends that.
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
        let query = parse_query(q)?;
        let name = query_name(&query);
        // A source kept inside gets NXDOMAIN for every name the namespace does not have, never
        // a forward. Not REFUSED: glibc and Go fail at once on it, but musl ignores it and
        // waits out its timeout (5 s; res_msend.c: "ignore all other codes such as
        // refusal"), while NXDOMAIN is final for all three.
        if self.is_internal_only(gateway, source) || name.ends_with(".internal") {
            let ip = self
                .names
                .read()
                .unwrap()
                .get(&gateway)
                .and_then(|m| m.get(&name).copied());
            return build_answer(&query, ip);
        }
        self.forward(q).await
    }

    /// Sends the query to each upstream in turn and answers the first reply that is from that
    /// upstream (a connected socket drops any other source) and carries the query's ID; a
    /// datagram with another ID is ignored, so a spoofed one cannot answer in its place.
    async fn forward(&self, q: &[u8]) -> Option<Vec<u8>> {
        let id = q.get(..2)?;
        for up in self.upstream.iter() {
            let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
                continue;
            };
            if sock.connect(up).await.is_err() || sock.send(q).await.is_err() {
                continue;
            }
            let reply = async {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = sock.recv(&mut buf).await.ok()?;
                    if buf[..n].get(..2) == Some(id) {
                        return Some(buf[..n].to_vec());
                    }
                }
            };
            if let Ok(Some(r)) = tokio::time::timeout(Duration::from_secs(4), reply).await {
                return Some(r);
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

/// A guest's query, decoded whole by hickory-proto (ADR 0033): anything that does not parse,
/// is not a query or asks nothing is dropped, never forwarded.
pub fn parse_query(q: &[u8]) -> Option<Message> {
    let m = Message::from_vec(q).ok()?;
    (m.metadata.message_type == MessageType::Query && !m.queries.is_empty()).then_some(m)
}

/// The first question's name, lowercase, without the trailing dot.
pub fn query_name(query: &Message) -> String {
    let name = query.queries[0].name().to_lowercase().to_ascii();
    name.trim_end_matches('.').to_string()
}

/// The answer to the first question: the address for A (and ANY) when the name is known,
/// NOERROR with no record for another type of a known name, NXDOMAIN otherwise. TTL 5 s.
pub fn build_answer(query: &Message, ip: Option<Ipv4Addr>) -> Option<Vec<u8>> {
    let question = query.queries[0].clone();
    let mut r = Message::response(query.metadata.id, query.metadata.op_code);
    r.metadata.authoritative = true;
    r.metadata.recursion_desired = query.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    r.metadata.response_code = match ip {
        Some(_) => ResponseCode::NoError,
        None => ResponseCode::NXDomain,
    };
    if let Some(ip) = ip {
        if matches!(question.query_type(), RecordType::A | RecordType::ANY) {
            r.add_answer(Record::from_rdata(
                question.name().clone(),
                5,
                RData::A(A(ip)),
            ));
        }
    }
    r.add_query(question);
    r.to_vec().ok()
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

    fn answer_to(q: &[u8], ip: Option<Ipv4Addr>) -> Message {
        let query = parse_query(q).unwrap();
        Message::from_vec(&build_answer(&query, ip).unwrap()).unwrap()
    }

    #[test]
    fn parses_and_answers() {
        let q = query("Db.Internal", 1);
        assert_eq!(query_name(&parse_query(&q).unwrap()), "db.internal");
        let ip = Ipv4Addr::new(10, 64, 0, 2);
        let r = answer_to(&q, Some(ip));
        assert_eq!(r.metadata.id, 0x1234);
        assert_eq!(r.metadata.message_type, MessageType::Response);
        assert!(r.metadata.authoritative && r.metadata.recursion_desired);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].data, RData::A(A(ip)));
        assert_eq!(r.answers[0].ttl, 5);
        // The question comes back as asked: resolvers that randomise case compare it.
        assert_eq!(r.queries[0].name().to_ascii(), "Db.Internal.");
        assert_eq!(
            answer_to(&q, None).metadata.response_code,
            ResponseCode::NXDomain
        );
        // A known name asked for another type: NOERROR, no record (musl asks A and AAAA).
        let aaaa = answer_to(&query("db.internal", 28), Some(ip));
        assert_eq!(aaaa.metadata.response_code, ResponseCode::NoError);
        assert!(aaaa.answers.is_empty());
        assert_eq!(
            answer_to(&query("db.internal", 255), Some(ip))
                .answers
                .len(),
            1
        );
    }

    #[test]
    fn edns_and_compressed_questions_parse() {
        let mut q = query("db.internal", 1);
        q[11] = 1; // ARCOUNT: an OPT record, as glibc and Go send
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(query_name(&parse_query(&q).unwrap()), "db.internal");
        // Two questions, the second a pointer to the first: only the first is answered.
        let mut q = query("db.internal", 1);
        q[5] = 2;
        q.extend_from_slice(&[0xC0, 12, 0, 28, 0, 1]);
        let r = answer_to(&q, Some(Ipv4Addr::new(10, 64, 0, 2)));
        assert_eq!(r.queries.len(), 1);
    }

    #[test]
    fn what_is_not_a_query_is_dropped() {
        let mut response = query("db.internal", 1);
        response[2] |= 0x80;
        assert!(parse_query(&response).is_none());
        let mut no_question = query("db.internal", 1);
        no_question[5] = 0;
        no_question.truncate(12);
        assert!(parse_query(&no_question).is_none());
    }

    #[tokio::test]
    async fn a_forwarded_answer_must_carry_the_query_id() {
        // The upstream first sends a reply with another ID, then the right one.
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r = Resolver::new(&[up.local_addr().unwrap().to_string()]);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = up.recv_from(&mut buf).await {
                let mut wrong = buf[..n].to_vec();
                wrong[0] ^= 0xFF;
                wrong.extend_from_slice(b"wrong");
                let _ = up.send_to(&wrong, from).await;
                let mut right = buf[..n].to_vec();
                right.extend_from_slice(b"right");
                let _ = up.send_to(&right, from).await;
            }
        });
        let reply = r.forward(&query("example.com", 1)).await.unwrap();
        assert!(reply.ends_with(b"right"), "{reply:?}");
    }

    /// Malformed packets from a guest are dropped, and none panics the daemon (release
    /// builds abort on a panic).
    #[test]
    fn malformed_packets_are_dropped() {
        let q = query("db.internal", 1);
        for n in 0..q.len() {
            assert!(parse_query(&q[..n]).is_none(), "truncated at {n}");
        }
        let header = |qd: u16, an: u16| {
            let mut h = vec![0xab, 0xcd, 0x01, 0x00];
            h.extend_from_slice(&qd.to_be_bytes());
            h.extend_from_slice(&an.to_be_bytes());
            h.extend_from_slice(&[0, 0, 0, 0]);
            h
        };
        let long: Vec<u8> = (0..5)
            .flat_map(|_| [vec![63], vec![b'a'; 63]].concat())
            .collect();
        let bad: Vec<Vec<u8>> = vec![
            // A name pointing at itself, two names pointing at each other, a pointer past the end.
            [header(1, 0), vec![0xC0, 12, 0, 1, 0, 1]].concat(),
            [
                header(2, 0),
                vec![0xC0, 18, 0, 1, 0, 1, 0xC0, 12, 0, 1, 0, 1],
            ]
            .concat(),
            [header(1, 0), vec![0xC0, 0xFF, 0, 1, 0, 1]].concat(),
            // A label longer than 63, a name longer than 255.
            [header(1, 0), vec![64], vec![b'a'; 64], vec![0, 0, 1, 0, 1]].concat(),
            [header(1, 0), long, vec![0, 0, 1, 0, 1]].concat(),
            // Counts far beyond what the packet holds, a record longer than the packet.
            [header(0xFFFF, 0), q[12..].to_vec()].concat(),
            [header(1, 0xFFFF), q[12..].to_vec()].concat(),
            [
                header(1, 1),
                q[12..].to_vec(),
                vec![0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 5, 0xFF, 0xFF],
            ]
            .concat(),
        ];
        for (i, p) in bad.iter().enumerate() {
            assert!(parse_query(p).is_none(), "packet {i} parsed");
        }
        // Random bytes, and random bytes behind a valid header: dropped or answered, never a panic.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        };
        for i in 0..20_000 {
            let len = 1 + (next() as usize) * 2;
            let mut p: Vec<u8> = (0..len).map(|_| next()).collect();
            if i % 2 == 0 && p.len() > 12 {
                p[..12].copy_from_slice(&header(1, 0));
            }
            if let Some(m) = parse_query(&p) {
                let _ = query_name(&m);
                let _ = build_answer(&m, Some(Ipv4Addr::LOCALHOST));
            }
        }
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
