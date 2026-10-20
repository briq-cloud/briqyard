//! The nftables rules (ADR 0003, ADR 0012): masquerade tenant egress, forward nothing but a
//! tenant's way to the internet, keep tenants off the host's services and private networks,
//! let only the allowed clients reach the daemon's ports, and pin every TAP to its machine's
//! address so a guest cannot send as anyone else.
//!
//! The tables are rendered once at start. A machine's pin is one element added to or removed
//! from the `pins` set; tenants need no change at all: the rules name their bridges by prefix
//! (`by*`), which only the daemon makes.

use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The networks a tenant may not reach, whatever the host routes to them.
const PRIVATE_NETS: &str =
    "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }";

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
}

impl Ruleset {
    pub fn render(&self) -> String {
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
        s.push_str("\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n");
        s.push_str("\t\tmeta nfproto ipv6 iifname \"by*\" drop\n");
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
        s.push_str("\tset pins {\n\t\ttype ifname . ipv4_addr\n");
        if !self.pins.is_empty() {
            let els: Vec<String> = self.pins.iter().map(|(t, ip)| pin(t, ip)).collect();
            s.push_str(&format!("\t\telements = {{ {} }}\n", els.join(", ")));
        }
        s.push_str("\t}\n");
        s.push_str(
            "\tchain prerouting {\n\t\ttype filter hook prerouting priority -200; policy drop;\n",
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
    match nft(&unpin_element(tap, ip)).await {
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
            pins: vec![("btabcdef123456".into(), "10.64.0.2".into())],
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
	chain forward {
		type filter hook forward priority 0; policy drop;
		meta nfproto ipv6 iifname "by*" drop
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
		elements = { "btabcdef123456" . 10.64.0.2 }
	}
	chain prerouting {
		type filter hook prerouting priority -200; policy drop;
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
