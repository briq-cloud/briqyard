//! The nftables rules (ADR 0003, ADR 0012): masquerade tenant egress, forward nothing but a
//! tenant's way to the internet, keep tenants off the host's services and private networks,
//! let only the allowed clients reach the daemon's ports, and pin every TAP to its machine's
//! address so a guest cannot send as anyone else.
//!
//! The tables are rendered once at start. A machine's pin is one element added to or removed
//! from the `pins` set, its egress policy (ADR 0015) a few more in the sets beside it;
//! tenants need no change at all: the rules name their bridges by prefix (`by*`), which only
//! the daemon makes.

use anyhow::{anyhow, Context, Result};
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
}

impl Policy {
    /// The machine's address, which the policy is keyed on.
    pub fn ip(&self) -> &str {
        match self {
            Policy::Via { ip, .. } | Policy::None { ip } => ip,
        }
    }

    /// The `add element` lines of this policy; with `delete`, the lines that end it.
    fn elements(&self, verb: &str) -> String {
        match self {
            Policy::Via { ip, to, host } => format!(
                "{verb} element bridge briqyard via_sources {{ {ip} }}\n\
                 {verb} element bridge briqyard via_allowed {{ {ip} . {to}, {ip} . {host} }}\n"
            ),
            Policy::None { ip } => {
                format!("{verb} element inet briqyard egress_none {{ {ip} }}\n")
            }
        }
    }
}

pub struct Ruleset {
    pub egress: String,
    pub range: String,
    /// The IPv4 networks that may reach `ports`; empty: anyone.
    pub allowed_clients: Vec<String>,
    /// The daemon's ports: the API, the HTTP ingress, the TCP endpoint range.
    pub ports: Vec<String>,
    /// `(tap, ip)` of every machine whose TAP exists: the guest behind it sends as that
    /// address and nothing else.
    pub pins: Vec<(String, String)>,
    /// The egress policies of those machines.
    pub policies: Vec<Policy>,
}

impl Ruleset {
    pub fn render(&self) -> String {
        let (mut via_sources, mut via_allowed, mut egress_none) = (vec![], vec![], vec![]);
        for p in &self.policies {
            match p {
                Policy::Via { ip, to, host } => {
                    via_sources.push(ip.clone());
                    via_allowed.push(format!("{ip} . {to}"));
                    via_allowed.push(format!("{ip} . {host}"));
                }
                Policy::None { ip } => egress_none.push(ip.clone()),
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
        s.push_str("\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n");
        s.push_str("\t\tmeta nfproto ipv6 iifname \"by*\" drop\n");
        // Before the reply accept: a policy set while a connection is open ends it.
        s.push_str("\t\tip saddr @egress_none drop\n");
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
        s.push_str("\t\tct state established,related accept\n");
        s.push_str("\t\tiifname \"by*\" udp dport 53 accept\n");
        s.push_str("\t\tiifname \"by*\" tcp dport 53 accept\n");
        s.push_str("\t\tiifname \"by*\" icmp type echo-request accept\n");
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
    let mut s = format!("\tset {name} {{\n\t\ttype {ty}\n");
    if !elements.is_empty() {
        s.push_str(&format!("\t\telements = {{ {} }}\n", elements.join(", ")));
    }
    s.push_str("\t}\n");
    s
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
            pins: vec![
                ("btabcdef123456".into(), "10.64.0.2".into()),
                ("bt0000000000a3".into(), "10.64.0.3".into()),
                ("bt0000000000a4".into(), "10.64.0.4".into()),
            ],
            policies: vec![
                via(),
                Policy::None {
                    ip: "10.64.0.4".into(),
                },
            ],
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
	chain forward {
		type filter hook forward priority 0; policy drop;
		meta nfproto ipv6 iifname "by*" drop
		ip saddr @egress_none drop
		ct state established,related accept
		iifname "by*" oifname "eth0" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
		iifname "by*" oifname "eth0" accept
	}
	chain input {
		type filter hook input priority 0; policy accept;
		iifname "lo" accept
		ct state established,related accept
		iifname "by*" udp dport 53 accept
		iifname "by*" tcp dport 53 accept
		iifname "by*" icmp type echo-request accept
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
            pins: vec![],
            policies: vec![],
            ..ruleset()
        };
        let s = r.render();
        assert!(!s.contains("@allowed_clients"), "{s}");
        assert!(!s.contains("20000-29999"), "{s}");
        assert!(!s.contains("elements"), "{s}");
        assert!(
            s.contains("\tset allowed_clients {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n")
        );
        assert!(s.contains("\tset pins {\n\t\ttype ifname . ipv4_addr\n\t}\n"));
        assert!(s.contains("\tset egress_none {\n\t\ttype ipv4_addr\n\t}\n"));
        assert!(s.contains("\tset via_allowed {\n\t\ttype ipv4_addr . ipv4_addr\n\t}\n"));
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
