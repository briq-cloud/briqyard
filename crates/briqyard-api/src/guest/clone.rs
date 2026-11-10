//! Identity and activation messages for the pre-main memory-clone barrier.
use serde::{Deserialize, Serialize};

pub const INIT_READY_V1: &str = "init-ready-v1";
/// A parked, already-running service sealed as a memory template (ADR 0127).
pub const SERVICE_READY_V1: &str = "service-ready-v1";

/// The guest operation that runs the park hook and quiesces the workload.
pub const SERVICE_PARK_OP: &str = "service_park_v1";
/// The `error_code` of a park or resume hook that failed or timed out.
pub const CLONE_HOOK_FAILED: &str = "clone_hook_failed";
/// The `error_code` of a park that failed after the freeze, leaving the guest frozen and
/// without its identity: the caller stops the source.
pub const PARK_UNRECOVERABLE: &str = "park_unrecoverable";
/// What the guest may spend after the hook ends: the freezer settling, the identity removal.
pub const PARK_QUIESCE_S: u64 = 20;

/// The two argv hooks of a service template. Opt-in at creation and immutable.
/// Both run in the guest as the workload's user, in its environment and working directory.
/// `park` runs before the seal: exit 0 within its timeout means the service holds no
/// external connection it cannot re-establish, no per-instance identity it cannot
/// regenerate, and has flushed its files. `resume` runs in each clone after its identity
/// is configured, while the workload is still frozen; the workload thaws on exit 0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneHooks {
    pub park: Vec<String>,
    pub resume: Vec<String>,
    #[serde(default = "default_hook_timeout_s")]
    pub park_timeout_s: u32,
    #[serde(default = "default_hook_timeout_s")]
    pub resume_timeout_s: u32,
}

fn default_hook_timeout_s() -> u32 {
    30
}

impl CloneHooks {
    pub const MAX_TIMEOUT_S: u32 = 300;
    pub fn validate(&self) -> Result<(), &'static str> {
        let argv = |v: &[String]| {
            !v.is_empty()
                && v.len() <= 64
                && v.iter().all(|a| a.len() <= 4096 && !a.contains('\0'))
                && !v[0].is_empty()
        };
        if !argv(&self.park) || !argv(&self.resume) {
            return Err("clone hooks need non-empty park and resume argv");
        }
        if !(1..=Self::MAX_TIMEOUT_S).contains(&self.park_timeout_s)
            || !(1..=Self::MAX_TIMEOUT_S).contains(&self.resume_timeout_s)
        {
            return Err("clone hook timeouts are 1 to 300 seconds");
        }
        Ok(())
    }
}

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
    /// Generated once in init RAM before sealing; inherited by strict memory restores.
    #[serde(default)]
    pub ram_marker: String,
    /// builder, identity_done, activating, active, failed.
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<CloneIdentity>,
    /// Why the stage is `hook_failed`: the hook, its exit code and the tail of its stderr.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hooks_validate() {
        let ok = CloneHooks {
            park: vec!["/park".into()],
            resume: vec!["/resume".into()],
            park_timeout_s: 30,
            resume_timeout_s: 30,
        };
        assert!(ok.validate().is_ok());
        let json = r#"{"park":["a"],"resume":["b"]}"#;
        let d: CloneHooks = serde_json::from_str(json).unwrap();
        assert_eq!((d.park_timeout_s, d.resume_timeout_s), (30, 30));
        for bad in [
            CloneHooks {
                park: vec![],
                ..ok.clone()
            },
            CloneHooks {
                resume: vec!["".into()],
                ..ok.clone()
            },
            CloneHooks {
                park_timeout_s: 0,
                ..ok.clone()
            },
            CloneHooks {
                resume_timeout_s: 301,
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err());
        }
        assert!(
            serde_json::from_str::<CloneHooks>(r#"{"park":["a"],"resume":["b"],"x":1}"#).is_err()
        );
    }

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
