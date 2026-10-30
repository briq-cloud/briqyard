//! Egress policy and limits, disk limits.

use super::*;

/// Egress modes.
pub mod egress {
    /// The namespace, and the internet through NAT (the default).
    pub const OPEN: &str = "open";
    /// One machine of the namespace and the gateway's DNS, nothing else.
    pub const VIA: &str = "via";
    /// The namespace, no internet.
    pub const NONE: &str = "none";
    /// What `via` takes to name the namespace's gateway (ADR 0016) rather than a machine.
    pub const GATEWAY: &str = "gateway";
}

/// Where a machine's traffic may go: enforced on the host, never by the guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    /// "open" (default), "via" or "none".
    #[serde(default = "default_egress_mode")]
    pub mode: String,
    /// For `via`: the machine of the same namespace that is the only one this machine reaches,
    /// or `"gateway"` for the namespace's gateway, which then runs while this machine does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

fn default_egress_mode() -> String {
    egress::OPEN.into()
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            mode: default_egress_mode(),
            via: None,
        }
    }
}

impl Egress {
    /// Sends through the namespace's gateway.
    pub fn via_gateway(&self) -> bool {
        self.mode == egress::VIA && self.via.as_deref() == Some(egress::GATEWAY)
    }

    /// The mode is one of the three, and `via` names a machine (or `"gateway"`) exactly when
    /// the mode is `via`.
    pub fn check(&self) -> Result<(), String> {
        match (self.mode.as_str(), &self.via) {
            (egress::OPEN | egress::NONE, None) => Ok(()),
            (egress::OPEN | egress::NONE, Some(_)) => {
                Err("egress.via goes with mode \"via\" only".into())
            }
            (egress::VIA, Some(id)) if valid_id(id) => Ok(()),
            (egress::VIA, _) => Err("egress.via must name a machine of the namespace".into()),
            (other, _) => Err(format!(
                "egress.mode {other:?}: want \"open\", \"via\" or \"none\""
            )),
        }
    }
}

/// Limits on a machine's internet traffic, through the host's NAT (ADR 0018). In a request an
/// absent field keeps what the machine has (on create: the host's default); in a machine's
/// view every field is there, the values in force.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressLimits {
    /// Destination ports refused, TCP and UDP; `[]` refuses none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_ports: Option<Vec<u16>>,
    /// New connections a minute, as many at once; 0 is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_connections_per_minute: Option<u32>,
    /// Mbit/s, in and out together; 0 is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_mbit: Option<u32>,
}

impl EgressLimits {
    /// The highest bandwidth: the kernel's byte limit overflows past about 147 Gbit/s.
    pub const MAX_MBIT: u32 = 100_000;

    /// Every port is a port and the bandwidth is within `MAX_MBIT`; the message names the
    /// field under `limits`.
    pub fn check(&self) -> Result<(), String> {
        if self.blocked_ports.iter().flatten().any(|p| *p == 0) {
            return Err("blocked_ports: 0 is not a port".into());
        }
        if self.bandwidth_mbit.unwrap_or(0) > Self::MAX_MBIT {
            return Err(format!("bandwidth_mbit: at most {}", Self::MAX_MBIT));
        }
        Ok(())
    }

    /// This one's fields, and `under`'s where this one has none.
    pub fn over(&self, under: &EgressLimits) -> EgressLimits {
        EgressLimits {
            blocked_ports: self
                .blocked_ports
                .clone()
                .or_else(|| under.blocked_ports.clone()),
            new_connections_per_minute: self
                .new_connections_per_minute
                .or(under.new_connections_per_minute),
            bandwidth_mbit: self.bandwidth_mbit.or(under.bandwidth_mbit),
        }
    }
}

/// Limits on each of a machine's disks, its root disk and its volume, by Firecracker's rate
/// limiter (ADR 0030). In a request an absent field keeps what the machine has (on create: the
/// host's default for its size); in a machine's view every field is there, the values in force.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskLimits {
    /// MB (2^20 bytes) a second, reads and writes together; 0 is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_mb: Option<u32>,
    /// Requests a second (reads, writes, flushes); 0 is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iops: Option<u32>,
    /// What each limit lets through at full speed once, after a start or a change, in seconds
    /// at its rate; 0 is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst_sec: Option<u32>,
}

impl DiskLimits {
    pub const MAX_MB: u32 = 100_000;
    pub const MAX_IOPS: u32 = 10_000_000;
    pub const MAX_BURST_SEC: u32 = 3600;

    /// Every field within its bound; the message names the field under `disk_limits`.
    pub fn check(&self) -> Result<(), String> {
        for (name, v, max) in [
            ("bandwidth_mb", self.bandwidth_mb, Self::MAX_MB),
            ("iops", self.iops, Self::MAX_IOPS),
            ("burst_sec", self.burst_sec, Self::MAX_BURST_SEC),
        ] {
            if v.unwrap_or(0) > max {
                return Err(format!("{name}: at most {max}"));
            }
        }
        Ok(())
    }

    /// No field named.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// This one's fields, and `under`'s where this one has none.
    pub fn over(&self, under: &DiskLimits) -> DiskLimits {
        DiskLimits {
            bandwidth_mb: self.bandwidth_mb.or(under.bandwidth_mb),
            iops: self.iops.or(under.iops),
            burst_sec: self.burst_sec.or(under.burst_sec),
        }
    }
}

/// Packets a machine's egress limits dropped since it started, by limit (ADR 0018).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDrops {
    pub blocked_port: u64,
    pub rate: u64,
    pub bandwidth: u64,
}

impl EgressDrops {
    pub fn total(&self) -> u64 {
        self.blocked_port + self.rate + self.bandwidth
    }
}
