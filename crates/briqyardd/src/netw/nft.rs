//! The nftables rules (ADR 0003, ADR 0012): masquerade tenant egress, forward nothing but a
//! tenant's way to the internet, keep tenants off the host's services and private networks,
//! let only the allowed clients reach the daemon's ports, and pin every TAP to its machine's
//! address so a guest cannot send as anyone else.
//!
//! The tables are rendered once at start. A machine's pin is one element added to or removed
//! from the `pins` set, its egress policy (ADR 0015) and limits (ADR 0018) a few more in the
//! sets and maps beside it, with a named `limit` per rate, its counters (ADR 0017, 0018) one
//! element in each counter set for its life; tenants need no change at all: the rules name
//! their bridges by prefix (`by*`), which only the daemon makes.

use crate::config::EgressLimits;
use anyhow::{anyhow, Context, Result};
use briqyard_api::EgressDrops;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The networks a tenant may not reach, whatever the host routes to them.
const PRIVATE_NETS: &str =
    "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }";

/// A machine's egress policy as the tables hold it (ADR 0015), keyed on its pinned address.
/// `open` is the absence of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    /// `ip` reaches `to` (its gateway machine) and `host` (the tenant's `.1`), nothing else:
    /// elements of `via_sources` and `via_allowed` in the bridge table.
    Via {
        ip: String,
        to: String,
        host: String,
    },
    /// `ip` reaches its tenant and not the internet: an element of `egress_none` in the inet
    /// table, where the route out is.
    None { ip: String },
    /// `ip` reaches its tenant and the internet within `limits` (ADR 0018), which limit
    /// something: elements of `blocked_ports`, `conn_limits` and `bandwidth_limits` in the
    /// inet table, and a named `limit` for each rate. Open with no limits is no policy.
    Open { ip: String, limits: EgressLimits },
}

impl Policy {
    /// The machine's address, which the policy is keyed on.
    pub fn ip(&self) -> &str {
        match self {
            Policy::Via { ip, .. } | Policy::None { ip } | Policy::Open { ip, .. } => ip,
        }
    }

    /// The resolver answers the machine internal names only (ADR 0015).
    pub fn internal_only(&self) -> bool {
        !matches!(self, Policy::Open { .. })
    }

    /// The lines that put this policy in the tables; with `delete`, the lines that take it
    /// out: an element before the object it names.
    fn elements(&self, verb: &str) -> String {
        match self {
            Policy::Via { ip, to, host } => format!(
                "{verb} element bridge briqyard via_sources {{ {ip} }}\n\
                 {verb} element bridge briqyard via_allowed {{ {ip} . {to}, {ip} . {host} }}\n"
            ),
            Policy::None { ip } => {
                format!("{verb} element inet briqyard egress_none {{ {ip} }}\n")
            }
            Policy::Open { ip, limits } => {
                let mut s = String::new();
                let ports = blocked(ip, limits);
                if !ports.is_empty() {
                    s += &format!(
                        "{verb} element inet briqyard blocked_ports {{ {} }}\n",
                        ports.join(", ")
                    );
                }
                for (map, name, spec) in rates(ip, limits) {
                    if verb == "add" {
                        s += &format!("add limit inet briqyard {name} {{ {spec} }}\n");
                        s += &format!("add element inet briqyard {map} {{ {ip} : \"{name}\" }}\n");
                    } else {
                        s += &format!("delete element inet briqyard {map} {{ {ip} }}\n");
                        s += &format!("delete limit inet briqyard {name}\n");
                    }
                }
                s
            }
        }
    }
}

/// The elements of `blocked_ports` for a machine: its address with each port.
fn blocked(ip: &str, l: &EgressLimits) -> Vec<String> {
    l.blocked_ports
        .iter()
        .map(|p| format!("{ip} . {p}"))
        .collect()
}

/// A machine's rates as `(map, limit name, limit spec)`, the ones it has. A `limit` holds one
/// token bucket, so each machine has its own, named after its address. `burst` lets the
/// whole minute's connections through at once (nft's default is 5); bytes have a second's
/// burst, nft's default.
fn rates(ip: &str, l: &EgressLimits) -> Vec<(&'static str, String, String)> {
    let key = ip.replace('.', "_");
    let mut out = vec![];
    if l.new_connections_per_minute > 0 {
        let n = l.new_connections_per_minute;
        out.push((
            "conn_limits",
            format!("conn_{key}"),
            format!("rate over {n}/minute burst {n} packets"),
        ));
    }
    if l.bandwidth_mbit > 0 {
        out.push((
            "bandwidth_limits",
            format!("bandwidth_{key}"),
            format!(
                "rate over {} bytes/second",
                u64::from(l.bandwidth_mbit) * 125_000
            ),
        ));
    }
    out
}

pub struct Ruleset {
    pub egress: String,
    pub range: String,
    /// The IPv4 networks that may reach `ports`; empty: anyone.
    pub allowed_clients: Vec<String>,
    /// The daemon's ports: the API, the HTTP ingress, the TCP endpoint range.
    pub ports: Vec<String>,
    /// The host's own services that machines reach as the internet does (ADR 0028).
    pub host_ports: Vec<u16>,
    /// `(tap, ip)` of every machine whose TAP exists: the guest behind it sends as that
    /// address and nothing else.
    pub pins: Vec<(String, String)>,
    /// The egress policies of those machines.
    pub policies: Vec<Policy>,
    /// The address of every machine on the host: its internet traffic and its drops are
    /// counted.
    pub counted: Vec<String>,
}

/// The counter sets: bytes a machine's address sent to the internet and got back from it
/// (ADR 0017), packets its limits dropped (ADR 0018).
const COUNTERS: [&str; 5] = [
    "internet_out",
    "internet_in",
    "dropped_port",
    "dropped_rate",
    "dropped_bandwidth",
];

impl Ruleset {
    pub fn render(&self) -> String {
        let (mut via_sources, mut via_allowed, mut egress_none) = (vec![], vec![], vec![]);
        let (mut blocked_ports, mut limits, mut named) = (vec![], String::new(), vec![]);
        for p in &self.policies {
            match p {
                Policy::Via { ip, to, host } => {
                    via_sources.push(ip.clone());
                    via_allowed.push(format!("{ip} . {to}"));
                    via_allowed.push(format!("{ip} . {host}"));
                }
                Policy::None { ip } => egress_none.push(ip.clone()),
                Policy::Open { ip, limits: l } => {
                    blocked_ports.extend(blocked(ip, l));
                    for (map, name, spec) in rates(ip, l) {
                        limits += &format!("\tlimit {name} {{\n\t\t{spec}\n\t}}\n");
                        named.push((map, format!("{ip} : \"{name}\"")));
                    }
                }
            }
        }
        let mut s = String::new();
        s.push_str("table inet briqyard\ndelete table inet briqyard\ntable inet briqyard {\n");
        s.push_str("\tset allowed_clients {\n\t\ttype ipv4_addr\n\t\tflags interval\n");
        if !self.allowed_clients.is_empty() {
            s.push_str(&format!(
                "\t\telements = {{ {} }}\n",
                self.allowed_clients.join(", ")
            ));
        }
        s.push_str("\t}\n");
        s.push_str(&set("egress_none", "ipv4_addr", &egress_none));
        s.push_str(&set(
            "blocked_ports",
            "ipv4_addr . inet_service",
            &blocked_ports,
        ));
        // A map names a limit by its name, so the limits come first.
        s.push_str(&limits);
        for name in ["conn_limits", "bandwidth_limits"] {
            let elements: Vec<String> = named
                .iter()
                .filter(|(m, _)| *m == name)
                .map(|(_, e)| e.clone())
                .collect();
            s.push_str(&map(name, "ipv4_addr : limit", &elements));
        }
        for name in COUNTERS {
            s.push_str(&counter_set(name, &self.counted));
        }
        let (out, back) = (
            format!("iifname \"by*\" oifname \"{}\"", self.egress),
            format!("iifname \"{}\" oifname \"by*\"", self.egress),
        );
        s.push_str("\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n");
        s.push_str("\t\tmeta nfproto ipv6 iifname \"by*\" drop\n");
        // Before the reply accept: a policy set while a connection is open ends it.
        s.push_str("\t\tip saddr @egress_none drop\n");
        // The limits (ADR 0018), before the reply accept too, so a port blocked live ends its
        // connections and the cap holds on every byte. Each drop is counted on the way: the
        // lookup in a counter set comes last in its rule, so only what is dropped counts.
        // Forms: a concatenation of address and port looked up in a set of that type, a
        // stateful object found through a map (`limit name ip saddr map @m`, the wiki's
        // "Stateful objects" page), `reject with tcp reset`.
        s.push_str(&format!(
            "\t\t{out} ip saddr . tcp dport @blocked_ports ip saddr @dropped_port reject with tcp reset\n"
        ));
        s.push_str(&format!(
            "\t\t{out} ip saddr . udp dport @blocked_ports ip saddr @dropped_port reject\n"
        ));
        s.push_str(&format!(
            "\t\t{out} ct state new limit name ip saddr map @conn_limits ip saddr @dropped_rate drop\n"
        ));
        s.push_str(&format!(
            "\t\t{out} limit name ip saddr map @bandwidth_limits ip saddr @dropped_bandwidth drop\n"
        ));
        s.push_str(&format!(
            "\t\t{back} limit name ip daddr map @bandwidth_limits ip daddr @dropped_bandwidth drop\n"
        ));
        // Counted after the limits, so what they drop is not traffic, and before the
        // accepts, so replies count too: a lookup in a set with `counter` adds the packet to
        // its element and goes on to the next rule. Only the route to the internet crosses
        // this chain: a tenant's own traffic is bridged, endpoints and DNS end on the host. A
        // first packet to a private network, dropped below, is counted.
        s.push_str(&format!("\t\t{out} ip saddr @internet_out\n"));
        s.push_str(&format!("\t\t{back} ip daddr @internet_in\n"));
        s.push_str("\t\tct state established,related accept\n");
        s.push_str(&format!(
            "\t\tiifname \"by*\" oifname \"{}\" ip daddr {PRIVATE_NETS} drop\n",
            self.egress
        ));
        s.push_str(&format!(
            "\t\tiifname \"by*\" oifname \"{}\" accept\n",
            self.egress
        ));
        s.push_str("\t}\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n");
        s.push_str("\t\tiifname \"lo\" accept\n");
        // The host's own services are the internet's: reached at the host's addresses, never
        // at a tenant's `.1`, the one host address a `via` machine may send to (the bridge
        // table holds it to its pairs); a machine without egress reaches none, and one whose
        // policy turns to none loses its open connections (before the replies' accept).
        let host_ports = (!self.host_ports.is_empty()).then(|| {
            let p: Vec<String> = self.host_ports.iter().map(u16::to_string).collect();
            format!("tcp dport {{ {} }}", p.join(", "))
        });
        if let Some(hp) = &host_ports {
            s.push_str(&format!(
                "\t\tiifname \"by*\" ip saddr @egress_none {hp} drop\n"
            ));
        }
        s.push_str("\t\tct state established,related accept\n");
        s.push_str("\t\tiifname \"by*\" udp dport 53 accept\n");
        s.push_str("\t\tiifname \"by*\" tcp dport 53 accept\n");
        s.push_str("\t\tiifname \"by*\" icmp type echo-request accept\n");
        if let Some(hp) = &host_ports {
            s.push_str(&format!(
                "\t\tiifname \"by*\" ip daddr != {} {hp} accept\n",
                self.range
            ));
        }
        s.push_str("\t\tiifname \"by*\" drop\n");
        if !self.allowed_clients.is_empty() {
            let ports = self.ports.join(", ");
            s.push_str(&format!(
                "\t\ttcp dport {{ {ports} }} ip saddr @allowed_clients accept\n"
            ));
            s.push_str(&format!("\t\ttcp dport {{ {ports} }} drop\n"));
        }
        s.push_str("\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority 100; policy accept;\n");
        s.push_str(&format!(
            "\t\tip saddr {} oifname \"{}\" masquerade\n",
            self.range, self.egress
        ));
        s.push_str("\t}\n}\n");
        // The bridge family sees the port a frame came in by (the inet hooks see the bridge),
        // so this is where a TAP is tied to its address, for IP and for ARP.
        s.push_str(
            "table bridge briqyard\ndelete table bridge briqyard\ntable bridge briqyard {\n",
        );
        let pins: Vec<String> = self.pins.iter().map(|(t, ip)| pin(t, ip)).collect();
        s.push_str(&set("pins", "ifname . ipv4_addr", &pins));
        s.push_str(&set("via_sources", "ipv4_addr", &via_sources));
        s.push_str(&set("via_allowed", "ipv4_addr . ipv4_addr", &via_allowed));
        s.push_str(
            "\tchain prerouting {\n\t\ttype filter hook prerouting priority -200; policy drop;\n",
        );
        // A `via` source may send to its allowed pairs only, in IP and in ARP alike: it
        // resolves its gateway machine and `.1`, answers no other sibling's ARP (so none can
        // address it; its replies would be dropped here anyway), and never learns the rest
        // of the subnet. Forms: a concatenation looked up in a named set of a concatenated
        // type (`ip saddr . ip daddr @myset`, the wiki's "Concatenations" page), a negated
        // set reference (`ip daddr != @blackhole`, its "Sets" page), and the ARP fields
        // `arp saddr ip` / `arp daddr ip` (nft(8), ARP HEADER EXPRESSION).
        s.push_str("\t\tip saddr @via_sources ip saddr . ip daddr != @via_allowed drop\n");
        s.push_str(
            "\t\tarp saddr ip @via_sources arp saddr ip . arp daddr ip != @via_allowed drop\n",
        );
        s.push_str("\t\tiifname . arp saddr ip @pins accept\n");
        s.push_str("\t\tiifname . ip saddr @pins accept\n");
        s.push_str("\t}\n}\n");
        s
    }

    /// Installs the tables atomically: the script declares each so the delete never fails on
    /// a fresh host, then replaces it in one transaction.
    pub async fn apply(&self) -> Result<()> {
        nft(&self.render()).await
    }
}

/// The ports the allowed clients may reach: the API's, the HTTP ingress's when it is on,
/// and the TCP endpoint range, as nftables writes them.
pub fn daemon_ports(listen: &str, http: &str, tcp_ports: &str) -> Result<Vec<String>> {
    let mut ports = vec![port_of("listen", listen)?];
    if !http.is_empty() {
        ports.push(port_of("ingress.http", http)?);
    }
    let bad = || anyhow!("ingress.tcp_ports {tcp_ports:?}: want \"lo-hi\"");
    let (lo, hi) = tcp_ports.split_once('-').ok_or_else(bad)?;
    let (lo, hi): (u16, u16) = (
        lo.trim().parse().map_err(|_| bad())?,
        hi.trim().parse().map_err(|_| bad())?,
    );
    if lo == 0 || lo > hi {
        return Err(bad());
    }
    ports.push(format!("{lo}-{hi}"));
    Ok(ports)
}

fn port_of(field: &str, addr: &str) -> Result<String> {
    let sa: std::net::SocketAddr = addr
        .parse()
        .map_err(|_| anyhow!("{field} {addr:?}: want address:port"))?;
    Ok(sa.port().to_string())
}

fn pin(tap: &str, ip: &str) -> String {
    format!("\"{tap}\" . {ip}")
}

/// A named set, with its elements when it has any.
fn set(name: &str, ty: &str, elements: &[String]) -> String {
    collection("set", name, ty, elements)
}

/// A named map, with its elements when it has any.
fn map(name: &str, ty: &str, elements: &[String]) -> String {
    collection("map", name, ty, elements)
}

fn collection(kind: &str, name: &str, ty: &str, elements: &[String]) -> String {
    let mut s = format!("\t{kind} {name} {{\n\t\ttype {ty}\n");
    if !elements.is_empty() {
        s.push_str(&format!("\t\telements = {{ {} }}\n", elements.join(", ")));
    }
    s.push_str("\t}\n");
    s
}

/// A set of addresses with a counter on each element: every element, added at start or later,
/// counts from zero.
fn counter_set(name: &str, elements: &[String]) -> String {
    let mut s = format!("\tset {name} {{\n\t\ttype ipv4_addr\n\t\tcounter\n");
    if !elements.is_empty() {
        s.push_str(&format!("\t\telements = {{ {} }}\n", elements.join(", ")));
    }
    s.push_str("\t}\n");
    s
}

/// What `count` sends: the address in every counter set; with `delete`, what ends it.
pub fn counter_elements(verb: &str, ip: &str) -> String {
    COUNTERS
        .iter()
        .map(|set| format!("{verb} element inet briqyard {set} {{ {ip} }}\n"))
        .collect()
}

/// Counts a machine's internet traffic and drops, from zero. Again keeps the counts.
pub async fn count(ip: &str) -> Result<()> {
    nft(&counter_elements("add", ip)).await
}

/// Ends the count. Missing is success.
pub async fn uncount(ip: &str) -> Result<()> {
    missing_is_fine(nft(&counter_elements("delete", ip)).await)
}

/// What the counter sets hold for one address since it was counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Bytes got from the internet and sent to it.
    pub internet_in: u64,
    pub internet_out: u64,
    /// Packets its limits dropped.
    pub dropped: EgressDrops,
}

/// The counters of every counted address: what `nft -j list set` says of each set.
pub async fn counters() -> Result<HashMap<String, Counters>> {
    let mut sets: [HashMap<String, (u64, u64)>; 5] = Default::default();
    for (set, into) in COUNTERS.iter().zip(sets.iter_mut()) {
        let out = Command::new("nft")
            .args(["-j", "list", "set", "inet", "briqyard", set])
            .output()
            .await
            .context("run nft")?;
        if !out.status.success() {
            return Err(anyhow!(
                "nft list set {set}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        *into = set_counts(&out.stdout).with_context(|| format!("nft list set {set}"))?;
    }
    Ok(by_address(&sets))
}

/// Each address's counters, from the sets' `(packets, bytes)` in the order of `COUNTERS`: bytes
/// for the internet, packets for the drops. An address missing from a set has zero there.
fn by_address(sets: &[HashMap<String, (u64, u64)>; 5]) -> HashMap<String, Counters> {
    let [out, inb, port, rate, bandwidth] = sets;
    let get =
        |set: &HashMap<String, (u64, u64)>, ip: &str| set.get(ip).copied().unwrap_or_default();
    sets.iter()
        .flat_map(|set| set.keys())
        .map(|ip| {
            let c = Counters {
                internet_in: get(inb, ip).1,
                internet_out: get(out, ip).1,
                dropped: EgressDrops {
                    blocked_port: get(port, ip).0,
                    rate: get(rate, ip).0,
                    bandwidth: get(bandwidth, ip).0,
                },
            };
            (ip.clone(), c)
        })
        .collect()
}

/// The `(packets, bytes)` of each element of a counter set, from `nft -j list set`:
/// `nftables[].set.elem[]` is `{"elem": {"val": "10.64.1.2", "counter": {"packets": 6,
/// "bytes": 504}}}`; an empty set has no `elem`.
fn set_counts(json: &[u8]) -> Result<HashMap<String, (u64, u64)>> {
    let v: serde_json::Value = serde_json::from_slice(json)?;
    let mut out = HashMap::new();
    let items = v["nftables"]
        .as_array()
        .ok_or_else(|| anyhow!("no nftables array"))?;
    for item in items {
        let Some(elems) = item["set"]["elem"].as_array() else {
            continue;
        };
        for e in elems {
            let e = &e["elem"];
            let ip = e["val"]
                .as_str()
                .ok_or_else(|| anyhow!("an element without an address: {e}"))?;
            let count = |field: &str| {
                e["counter"][field]
                    .as_u64()
                    .ok_or_else(|| anyhow!("{ip}: no counter"))
            };
            out.insert(ip.to_string(), (count("packets")?, count("bytes")?));
        }
    }
    Ok(out)
}

/// What `pin_source` sends: one element into the `pins` set.
pub fn pin_element(tap: &str, ip: &str) -> String {
    format!("add element bridge briqyard pins {{ {} }}\n", pin(tap, ip))
}

/// What `unpin_source` sends.
pub fn unpin_element(tap: &str, ip: &str) -> String {
    format!(
        "delete element bridge briqyard pins {{ {} }}\n",
        pin(tap, ip)
    )
}

/// Lets the guest behind `tap` send as `ip`, and as nothing else. Again is fine.
pub async fn pin_source(tap: &str, ip: &str) -> Result<()> {
    nft(&pin_element(tap, ip)).await
}

/// Ends the pin. Missing is success.
pub async fn unpin_source(tap: &str, ip: &str) -> Result<()> {
    missing_is_fine(nft(&unpin_element(tap, ip)).await)
}

/// Puts a machine's policy in the tables. Again is fine.
pub async fn set_policy(p: &Policy) -> Result<()> {
    nft(&p.elements("add")).await
}

/// What `swap_policy` sends: the old policy's deletes, then the new one's adds.
pub fn swap_elements(old: &Policy, new: &Policy) -> String {
    old.elements("delete") + &new.elements("add")
}

/// Replaces a machine's policy in one transaction: never neither, and a refusal leaves the
/// old one in place.
pub async fn swap_policy(old: &Policy, new: &Policy) -> Result<()> {
    nft(&swap_elements(old, new)).await
}

/// Takes it out. Missing is success.
pub async fn unset_policy(p: &Policy) -> Result<()> {
    missing_is_fine(nft(&p.elements("delete")).await)
}

/// A delete of an element that is not there is what was wanted.
fn missing_is_fine(r: Result<()>) -> Result<()> {
    match r {
        Err(e) if e.to_string().contains("No such file or directory") => Ok(()),
        r => r,
    }
}

/// Runs a script through `nft -f -`: one transaction, applied whole or not at all.
async fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("run nft")?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .await?;
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ruleset() -> Ruleset {
        Ruleset {
            egress: "eth0".into(),
            range: "10.64.0.0/10".into(),
            allowed_clients: vec!["10.0.0.0/8".into(), "192.168.64.1/32".into()],
            ports: daemon_ports("0.0.0.0:7420", "0.0.0.0:8080", "20000-29999").unwrap(),
            host_ports: vec![80, 443],
            pins: vec![
                ("btabcdef123456".into(), "10.64.0.2".into()),
                ("bt0000000000a3".into(), "10.64.0.3".into()),
                ("bt0000000000a4".into(), "10.64.0.4".into()),
            ],
            policies: vec![
                open(),
                via(),
                Policy::None {
                    ip: "10.64.0.4".into(),
                },
            ],
            counted: vec!["10.64.0.2".into(), "10.64.0.3".into()],
        }
    }

    /// 10.64.0.2 with every limit: two ports, 600 connections a minute, 100 Mbit/s.
    fn open() -> Policy {
        Policy::Open {
            ip: "10.64.0.2".into(),
            limits: EgressLimits {
                blocked_ports: vec![25, 465],
                new_connections_per_minute: 600,
                bandwidth_mbit: 100,
            },
        }
    }

    /// 10.64.0.3 through its gateway machine 10.64.0.2.
    fn via() -> Policy {
        Policy::Via {
            ip: "10.64.0.3".into(),
            to: "10.64.0.2".into(),
            host: "10.64.0.1".into(),
        }
    }

    #[test]
    fn renders() {
        assert_eq!(
            ruleset().render(),
            r#"table inet briqyard
delete table inet briqyard
table inet briqyard {
	set allowed_clients {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 192.168.64.1/32 }
	}
	set egress_none {
		type ipv4_addr
		elements = { 10.64.0.4 }
	}
	set blocked_ports {
		type ipv4_addr . inet_service
		elements = { 10.64.0.2 . 25, 10.64.0.2 . 465 }
	}
	limit conn_10_64_0_2 {
		rate over 600/minute burst 600 packets
	}
	limit bandwidth_10_64_0_2 {
		rate over 12500000 bytes/second
	}
	map conn_limits {
		type ipv4_addr : limit
		elements = { 10.64.0.2 : "conn_10_64_0_2" }
	}
	map bandwidth_limits {
		type ipv4_addr : limit
		elements = { 10.64.0.2 : "bandwidth_10_64_0_2" }
	}
	set internet_out {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set internet_in {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set dropped_port {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set dropped_rate {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set dropped_bandwidth {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		meta nfproto ipv6 iifname "by*" drop
		ip saddr @egress_none drop
		iifname "by*" oifname "eth0" ip saddr . tcp dport @blocked_ports ip saddr @dropped_port reject with tcp reset
		iifname "by*" oifname "eth0" ip saddr . udp dport @blocked_ports ip saddr @dropped_port reject
		iifname "by*" oifname "eth0" ct state new limit name ip saddr map @conn_limits ip saddr @dropped_rate drop
		iifname "by*" oifname "eth0" limit name ip saddr map @bandwidth_limits ip saddr @dropped_bandwidth drop
		iifname "eth0" oifname "by*" limit name ip daddr map @bandwidth_limits ip daddr @dropped_bandwidth drop
		iifname "by*" oifname "eth0" ip saddr @internet_out
		iifname "eth0" oifname "by*" ip daddr @internet_in
		ct state established,related accept
		iifname "by*" oifname "eth0" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
		iifname "by*" oifname "eth0" accept
	}
	chain input {
		type filter hook input priority 0; policy accept;
		iifname "lo" accept
		iifname "by*" ip saddr @egress_none tcp dport { 80, 443 } drop
		ct state established,related accept
		iifname "by*" udp dport 53 accept
		iifname "by*" tcp dport 53 accept
		iifname "by*" icmp type echo-request accept
		iifname "by*" ip daddr != 10.64.0.0/10 tcp dport { 80, 443 } accept
		iifname "by*" drop
		tcp dport { 7420, 8080, 20000-29999 } ip saddr @allowed_clients accept
		tcp dport { 7420, 8080, 20000-29999 } drop
	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr 10.64.0.0/10 oifname "eth0" masquerade
	}
}
table bridge briqyard
delete table bridge briqyard
table bridge briqyard {
	set pins {
		type ifname . ipv4_addr
		elements = { "btabcdef123456" . 10.64.0.2, "bt0000000000a3" . 10.64.0.3, "bt0000000000a4" . 10.64.0.4 }
	}
	set via_sources {
		type ipv4_addr
		elements = { 10.64.0.3 }
	}
	set via_allowed {
		type ipv4_addr . ipv4_addr
		elements = { 10.64.0.3 . 10.64.0.2, 10.64.0.3 . 10.64.0.1 }
	}
	chain prerouting {
		type filter hook prerouting priority -200; policy drop;
		ip saddr @via_sources ip saddr . ip daddr != @via_allowed drop
		arp saddr ip @via_sources arp saddr ip . arp daddr ip != @via_allowed drop
		iifname . arp saddr ip @pins accept
		iifname . ip saddr @pins accept
	}
}
"#
        );
    }

    #[test]
    fn no_clients_means_no_port_rules_and_empty_sets_have_no_elements() {
        let r = Ruleset {
            allowed_clients: vec![],
            host_ports: vec![],
            pins: vec![],
            policies: vec![],
            counted: vec![],
            ..ruleset()
        };
        let s = r.render();
        assert!(!s.contains("@allowed_clients"), "{s}");
        assert!(!s.contains("20000-29999"), "{s}");
        // No host ports: machines reach nothing on the host but its DNS and ping.
        assert!(!s.contains("tcp dport { 80"), "{s}");
        assert!(!s.contains("elements"), "{s}");
        assert!(
            s.contains("\tset allowed_clients {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n")
        );
        assert!(s.contains("\tset pins {\n\t\ttype ifname . ipv4_addr\n\t}\n"));
        assert!(s.contains("\tset egress_none {\n\t\ttype ipv4_addr\n\t}\n"));
        assert!(s.contains("\tset via_allowed {\n\t\ttype ipv4_addr . ipv4_addr\n\t}\n"));
        assert!(s.contains("\tset internet_in {\n\t\ttype ipv4_addr\n\t\tcounter\n\t}\n"));
        assert!(s.contains("\tset blocked_ports {\n\t\ttype ipv4_addr . inet_service\n\t}\n"));
        assert!(s.contains("\tmap conn_limits {\n\t\ttype ipv4_addr : limit\n\t}\n"));
        assert!(!s.contains("\tlimit "), "{s}");
    }

    #[test]
    fn the_forward_chain_drops_by_default() {
        let s = ruleset().render();
        assert!(s.contains("hook forward priority 0; policy drop;"));
        // The only accepts: replies, and a tenant's way out through the egress interface.
        let accepts: Vec<&str> = s
            .lines()
            .skip_while(|l| !l.contains("chain forward"))
            .take_while(|l| !l.contains("chain input"))
            .filter(|l| l.ends_with("accept"))
            .map(str::trim)
            .collect();
        assert_eq!(
            accepts,
            [
                "ct state established,related accept",
                "iifname \"by*\" oifname \"eth0\" accept"
            ]
        );
    }

    #[test]
    fn pin_elements() {
        assert_eq!(
            pin_element("btabcdef123456", "10.64.0.2"),
            "add element bridge briqyard pins { \"btabcdef123456\" . 10.64.0.2 }\n"
        );
        assert_eq!(
            unpin_element("btabcdef123456", "10.64.0.2"),
            "delete element bridge briqyard pins { \"btabcdef123456\" . 10.64.0.2 }\n"
        );
    }

    #[test]
    fn policy_elements() {
        assert_eq!(
            via().elements("add"),
            "add element bridge briqyard via_sources { 10.64.0.3 }\n\
             add element bridge briqyard via_allowed { 10.64.0.3 . 10.64.0.2, 10.64.0.3 . 10.64.0.1 }\n"
        );
        let none = Policy::None {
            ip: "10.64.0.4".into(),
        };
        assert_eq!(
            none.elements("delete"),
            "delete element inet briqyard egress_none { 10.64.0.4 }\n"
        );
        assert_eq!((via().ip(), none.ip()), ("10.64.0.3", "10.64.0.4"));
        // A swap is one input, so one transaction: the old out, then the new in.
        let none3 = Policy::None {
            ip: "10.64.0.3".into(),
        };
        assert_eq!(
            swap_elements(&via(), &none3),
            "delete element bridge briqyard via_sources { 10.64.0.3 }\n\
             delete element bridge briqyard via_allowed { 10.64.0.3 . 10.64.0.2, 10.64.0.3 . 10.64.0.1 }\n\
             add element inet briqyard egress_none { 10.64.0.3 }\n"
        );
    }

    #[test]
    fn limit_elements() {
        // Every limit: the ports, then each rate's named limit before the map element that
        // names it; taken out in the other order, the element before its limit.
        assert_eq!(
            open().elements("add"),
            "add element inet briqyard blocked_ports { 10.64.0.2 . 25, 10.64.0.2 . 465 }\n\
             add limit inet briqyard conn_10_64_0_2 { rate over 600/minute burst 600 packets }\n\
             add element inet briqyard conn_limits { 10.64.0.2 : \"conn_10_64_0_2\" }\n\
             add limit inet briqyard bandwidth_10_64_0_2 { rate over 12500000 bytes/second }\n\
             add element inet briqyard bandwidth_limits { 10.64.0.2 : \"bandwidth_10_64_0_2\" }\n"
        );
        assert_eq!(
            open().elements("delete"),
            "delete element inet briqyard blocked_ports { 10.64.0.2 . 25, 10.64.0.2 . 465 }\n\
             delete element inet briqyard conn_limits { 10.64.0.2 }\n\
             delete limit inet briqyard conn_10_64_0_2\n\
             delete element inet briqyard bandwidth_limits { 10.64.0.2 }\n\
             delete limit inet briqyard bandwidth_10_64_0_2\n"
        );
        // One limit alone: only its lines.
        let only = |limits| Policy::Open {
            ip: "10.64.1.9".into(),
            limits,
        };
        let rate = only(EgressLimits {
            blocked_ports: vec![],
            new_connections_per_minute: 6,
            bandwidth_mbit: 0,
        });
        assert_eq!(
            rate.elements("add"),
            "add limit inet briqyard conn_10_64_1_9 { rate over 6/minute burst 6 packets }\n\
             add element inet briqyard conn_limits { 10.64.1.9 : \"conn_10_64_1_9\" }\n"
        );
        let port = only(EgressLimits {
            blocked_ports: vec![25],
            new_connections_per_minute: 0,
            bandwidth_mbit: 0,
        });
        assert_eq!(
            port.elements("delete"),
            "delete element inet briqyard blocked_ports { 10.64.1.9 . 25 }\n"
        );
        // A change of rate is the same limit's name deleted and added again, in one input.
        let faster = Policy::Open {
            ip: "10.64.0.2".into(),
            limits: EgressLimits {
                bandwidth_mbit: 2,
                ..EgressLimits::default()
            },
        };
        assert_eq!(
            swap_elements(&open(), &faster),
            open().elements("delete") + &faster.elements("add")
        );
        assert!(faster.elements("add").contains(
            "add limit inet briqyard bandwidth_10_64_0_2 { rate over 250000 bytes/second }\n"
        ));
        // The resolver keeps `via` and `none` to internal names, never an open machine.
        assert!(!open().internal_only());
        assert!(via().internal_only());
        assert_eq!(open().ip(), "10.64.0.2");
    }

    #[test]
    fn counter_elements_name_every_set() {
        assert_eq!(
            counter_elements("add", "10.64.1.2"),
            "add element inet briqyard internet_out { 10.64.1.2 }\n\
             add element inet briqyard internet_in { 10.64.1.2 }\n\
             add element inet briqyard dropped_port { 10.64.1.2 }\n\
             add element inet briqyard dropped_rate { 10.64.1.2 }\n\
             add element inet briqyard dropped_bandwidth { 10.64.1.2 }\n"
        );
        assert_eq!(
            counter_elements("delete", "10.64.1.2"),
            "delete element inet briqyard internet_out { 10.64.1.2 }\n\
             delete element inet briqyard internet_in { 10.64.1.2 }\n\
             delete element inet briqyard dropped_port { 10.64.1.2 }\n\
             delete element inet briqyard dropped_rate { 10.64.1.2 }\n\
             delete element inet briqyard dropped_bandwidth { 10.64.1.2 }\n"
        );
    }

    #[test]
    fn counters_are_read_from_nft_json() {
        // What nft 1.1.6 prints for a counter set, read on the dev VM.
        let listed = br#"{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "internet_out", "table": "briqyard", "type": "ipv4_addr", "handle": 2, "elem": [{"elem": {"val": "10.64.1.2", "counter": {"packets": 6, "bytes": 504}}}, {"elem": {"val": "10.64.1.3", "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}"#;
        let out = set_counts(listed).unwrap();
        assert_eq!(
            out,
            HashMap::from([
                ("10.64.1.2".to_string(), (6, 504)),
                ("10.64.1.3".to_string(), (0, 0))
            ])
        );
        // An empty set has no `elem`.
        let empty = br#"{"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": "internet_in", "table": "briqyard", "type": "ipv4_addr", "handle": 3, "stmt": [{"counter": null}]}}]}"#;
        assert!(set_counts(empty).unwrap().is_empty());
        // A set without counters is an error, not zero.
        let bare = br#"{"nftables": [{"set": {"elem": [{"elem": {"val": "10.64.1.2"}}]}}]}"#;
        assert_eq!(
            set_counts(bare).unwrap_err().to_string(),
            "10.64.1.2: no counter"
        );
        assert!(set_counts(b"not json").is_err());
        // Each set to its field, bytes for the internet, packets for the drops; an address
        // missing from a set has zero there.
        let one = |ip: &str, packets, bytes| HashMap::from([(ip.to_string(), (packets, bytes))]);
        let sets = [
            out,
            one("10.64.1.2", 70, 9000),
            one("10.64.1.2", 1, 60),
            one("10.64.1.3", 10, 600),
            one("10.64.1.2", 57, 280980),
        ];
        assert_eq!(
            by_address(&sets),
            HashMap::from([
                (
                    "10.64.1.2".to_string(),
                    Counters {
                        internet_in: 9000,
                        internet_out: 504,
                        dropped: EgressDrops {
                            blocked_port: 1,
                            rate: 0,
                            bandwidth: 57
                        }
                    }
                ),
                (
                    "10.64.1.3".to_string(),
                    Counters {
                        dropped: EgressDrops {
                            rate: 10,
                            ..Default::default()
                        },
                        ..Default::default()
                    }
                )
            ])
        );
    }

    #[test]
    fn ports() {
        assert_eq!(
            daemon_ports("127.0.0.1:7420", "", "20000-29999").unwrap(),
            ["7420", "20000-29999"]
        );
        assert_eq!(
            daemon_ports("[::]:7420", "0.0.0.0:8080", "30000-31000").unwrap(),
            ["7420", "8080", "30000-31000"]
        );
        let err = daemon_ports("7420", "", "20000-29999").unwrap_err();
        assert_eq!(err.to_string(), "listen \"7420\": want address:port");
        let err = daemon_ports("127.0.0.1:7420", "8080", "20000-29999").unwrap_err();
        assert_eq!(err.to_string(), "ingress.http \"8080\": want address:port");
        for bad in ["20000", "0-10", "30-20", "a-b"] {
            let err = daemon_ports("127.0.0.1:7420", "", bad).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("ingress.tcp_ports {bad:?}: want \"lo-hi\"")
            );
        }
    }
}
