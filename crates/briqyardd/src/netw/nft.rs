//! The nftables rules (ADR 0003, ADR 0012): masquerade namespace egress, forward nothing but a
//! namespace's way to the internet, keep namespaces off the host's services and private networks,
//! let only the allowed clients reach the daemon's ports, and pin every TAP to its machine's
//! address so a guest cannot send as anyone else.
//!
//! The tables are rendered once at start. A machine's pin is one element added to or removed
//! from the `pins` set, its egress policy (ADR 0015) and limits (ADR 0018) a few more in the
//! sets and maps beside it, with a named `limit` per rate, its counters (ADR 0017, 0018) one
//! element in each counter set for its life; namespaces need no change at all: the rules name
//! their bridges by prefix (`by*`), which only the daemon makes.

use crate::config::EgressLimits;
use anyhow::{anyhow, Context, Result};
use briqyard_api::EgressDrops;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

mod siblings;
pub use siblings::attachment_elements;

/// The networks a namespace may not reach, whatever the host routes to them.
const PRIVATE_NETS: &str =
    "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }";

/// A machine's egress policy as the tables hold it (ADR 0015), keyed on its pinned address.
/// `open` is the absence of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    /// `ip` reaches `to` (its gateway machine) and `host` (the namespace's `.1`), nothing else:
    /// elements of `via_sources` and `via_allowed` in the bridge table.
    Via {
        ip: String,
        to: String,
        to_tap: String,
        host: String,
        siblings: bool,
    },
    /// `ip` reaches its namespace and not the internet: an element of `egress_none` in the inet
    /// table, where the route out is.
    None { ip: String },
    /// `ip` reaches its namespace and the internet within `limits` (ADR 0018), which limit
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
            Policy::Via {
                ip,
                to,
                to_tap,
                host,
                siblings,
            } => {
                let mut elements = format!(
                    "{verb} element bridge briqyard via_sources {{ {ip} }}\n\
                     {verb} element bridge briqyard via_allowed {{ {ip} . {to}, {ip} . {host} }}\n\
                     {verb} element bridge briqyard via_targets {{ {ip} . \"{to_tap}\" }}\n"
                );
                if *siblings {
                    elements +=
                        &format!("{verb} element bridge briqyard via_siblings {{ {ip} }}\n");
                }
                elements
            }
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
    /// The actual bridge and address of every admitted pin.
    pub members: Vec<(String, String)>,
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
        let mut via_siblings = Vec::new();
        let mut via_targets = Vec::new();
        let (mut blocked_ports, mut limits, mut named) = (vec![], String::new(), vec![]);
        for p in &self.policies {
            match p {
                Policy::Via {
                    ip,
                    to,
                    to_tap,
                    host,
                    siblings,
                } => {
                    if *siblings {
                        via_siblings.push(ip.clone());
                    }
                    via_targets.push(format!("{ip} . \"{to_tap}\""));
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
        // this chain: a namespace's own traffic is bridged, endpoints and DNS end on the host. A
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
        // at a namespace's `.1`, the one host address a `via` machine may send to (the bridge
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
        let mac_pins = self
            .pins
            .iter()
            .map(|(tap, ip)| siblings::mac_pin(tap, ip))
            .collect::<Vec<_>>();
        s.push_str(&set("mac_pins", "ifname . ether_addr", &mac_pins));
        let members = self
            .members
            .iter()
            .map(|(bridge, ip)| siblings::member(bridge, ip))
            .collect::<Vec<_>>();
        s.push_str(&set("members", "ifname . ipv4_addr", &members));
        s.push_str(&set("via_siblings", "ipv4_addr", &via_siblings));
        s.push_str(&set("via_targets", "ipv4_addr . ifname", &via_targets));
        s.push_str(&set("via_sources", "ipv4_addr", &via_sources));
        s.push_str(&set("via_allowed", "ipv4_addr . ipv4_addr", &via_allowed));
        s.push_str(siblings::chains());
        s.push_str(siblings::prerouting());
        s.push_str("}\n");
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

/// Admit or revoke a complete attachment. A missing revoked attachment is already fenced.
pub async fn attachment(
    verb: &str,
    tap: &str,
    bridge: &str,
    ip: &str,
    policy: Option<&Policy>,
) -> Result<()> {
    nft(&attachment_elements(verb, tap, bridge, ip, policy)).await
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
mod tests;
