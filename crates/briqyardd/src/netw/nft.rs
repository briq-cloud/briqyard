//! The nftables ruleset: masquerade tenant egress, let tenants reach the internet and their
//! gateway's DNS, keep them apart from each other and from the host's other services.

use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub struct Ruleset {
    pub egress: String,
    pub range: String,
    /// Bridge names of the tenants on this host.
    pub bridges: Vec<String>,
}

impl Ruleset {
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("table inet briqyard\ndelete table inet briqyard\ntable inet briqyard {\n");
        s.push_str("\tchain forward {\n\t\ttype filter hook forward priority 0; policy accept;\n");
        s.push_str("\t\tct state established,related accept\n");
        s.push_str(&format!(
            "\t\tip saddr {r} ip daddr {r} drop\n",
            r = self.range
        ));
        s.push_str(&format!(
            "\t\tip saddr {} ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }} drop\n",
            self.range
        ));
        s.push_str(&format!(
            "\t\tip saddr {} oifname \"{}\" accept\n",
            self.range, self.egress
        ));
        s.push_str(&format!(
            "\t\tiifname \"{}\" ip daddr {} drop\n",
            self.egress, self.range
        ));
        s.push_str("\t}\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n");
        s.push_str("\t\tct state established,related accept\n");
        for b in &self.bridges {
            s.push_str(&format!("\t\tiifname \"{b}\" udp dport 53 accept\n"));
            s.push_str(&format!("\t\tiifname \"{b}\" tcp dport 53 accept\n"));
            s.push_str(&format!(
                "\t\tiifname \"{b}\" icmp type echo-request accept\n"
            ));
            s.push_str(&format!("\t\tiifname \"{b}\" drop\n"));
        }
        s.push_str("\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority 100; policy accept;\n");
        s.push_str(&format!(
            "\t\tip saddr {} oifname \"{}\" masquerade\n",
            self.range, self.egress
        ));
        s.push_str("\t}\n}\n");
        s
    }

    /// Installs the ruleset atomically: the script declares the table so the delete never
    /// fails on a fresh host, then replaces it in one transaction.
    pub async fn apply(&self) -> Result<()> {
        let script = self.render();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders() {
        let r = Ruleset {
            egress: "eth0".into(),
            range: "10.64.0.0/10".into(),
            bridges: vec!["by0".into()],
        };
        let s = r.render();
        assert!(s.contains("masquerade"));
        assert!(s.contains("iifname \"by0\" udp dport 53 accept"));
        assert!(s.contains("ip saddr 10.64.0.0/10 ip daddr 10.64.0.0/10 drop"));
    }
}
