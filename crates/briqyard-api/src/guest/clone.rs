//! Identity and activation messages for the pre-main memory-clone barrier.
use serde::{Deserialize, Serialize};

pub const INIT_READY_V1: &str = "init-ready-v1";

/// Host-generated identity. No command, environment, path or hook is caller-selected.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneConfigure {
    pub generation: String,
    pub hostname: String,
    pub ip: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub mac: [u8; 6],
    /// Fresh trusted host getrandom bytes, credited and reseeded before identity creation.
    pub entropy: [u8; 32],
    pub realtime_sec: u64,
}

impl std::fmt::Debug for CloneConfigure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloneConfigure")
            .field("generation", &self.generation)
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

impl CloneConfigure {
    pub fn validate(&self) -> Result<(), &'static str> {
        let label = |v: &str| {
            !v.is_empty()
                && v.len() <= 63
                && v.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !v.starts_with('-')
                && !v.ends_with('-')
        };
        if !label(&self.generation) || !label(&self.hostname) {
            return Err("invalid clone generation or hostname");
        }
        let Some((ip, prefix)) = self.ip.split_once('/') else {
            return Err("clone IP requires CIDR");
        };
        let ip = ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "invalid clone IP")?;
        if ip.is_unspecified() || ip.is_multicast() || prefix != "24" {
            return Err("clone IP requires unicast IPv4 /24");
        }
        self.gateway
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "invalid clone gateway")?;
        if self.dns.is_empty()
            || self.dns.len() > 8
            || self
                .dns
                .iter()
                .any(|d| d.parse::<std::net::IpAddr>().is_err())
        {
            return Err("invalid clone DNS");
        }
        if self.mac[0] & 3 != 2 || self.entropy == [0; 32] {
            return Err("clone requires local unicast MAC and host entropy");
        }
        if !(1_735_689_600..=4_102_444_800).contains(&self.realtime_sec) {
            return Err("clone wall clock outside supported interval");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneIdentity {
    pub generation: String,
    pub hostname: String,
    pub ip: String,
    pub mac: [u8; 6],
    pub machine_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneStatus {
    pub protocol: u32,
    pub profile: String,
    /// builder, identity_done, activating, active, failed.
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<CloneIdentity>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_identity_and_redacts_entropy() {
        let mut c = CloneConfigure {
            generation: "clone-1".into(),
            hostname: "clone-1".into(),
            ip: "10.64.1.2/24".into(),
            gateway: "10.64.1.1".into(),
            dns: vec!["10.64.1.1".into()],
            mac: [2, 1, 2, 3, 4, 5],
            entropy: [42; 32],
            realtime_sec: 1_793_404_800,
        };
        assert!(c.validate().is_ok());
        assert!(!format!("{c:?}").contains("42"));
        c.hostname = "bad\nname".into();
        assert!(c.validate().is_err());
        c.hostname = "valid".into();
        c.mac[0] = 1;
        assert!(c.validate().is_err());
    }
}
