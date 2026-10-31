//! The host network: a bridge per namespace, a TAP per machine, addresses, nftables and the
//! gateway's DNS.

mod conntrack;
pub mod dns;
pub mod host;
pub mod nft;

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};

/// A namespace's /24 inside the range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subnet {
    pub index: u32,
    pub network: Ipv4Addr,
}

impl Subnet {
    /// The host's address on the subnet: .1.
    pub fn gateway(&self) -> Ipv4Addr {
        let o = self.network.octets();
        Ipv4Addr::new(o[0], o[1], o[2], 1)
    }

    /// The address of host number n (2..254).
    pub fn host(&self, n: u8) -> Result<Ipv4Addr> {
        if !(2..=254).contains(&n) {
            return Err(anyhow!("host number {n} out of range 2..254"));
        }
        let o = self.network.octets();
        Ok(Ipv4Addr::new(o[0], o[1], o[2], n))
    }

    pub fn cidr(&self) -> String {
        format!("{}/24", self.network)
    }
}

/// A range like "10.64.0.0/10".
#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub base: Ipv4Addr,
    pub bits: u8,
}

impl Range {
    pub fn parse(s: &str) -> Result<Self> {
        let (ip, bits) = s
            .split_once('/')
            .ok_or_else(|| anyhow!("network range {s:?}: want a.b.c.d/n"))?;
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| anyhow!("network range {s:?}: bad address"))?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| anyhow!("network range {s:?}: bad prefix"))?;
        if bits > 24 {
            return Err(anyhow!("network range {s:?}: must be /24 or wider"));
        }
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        Ok(Self {
            base: Ipv4Addr::from(u32::from(ip) & mask),
            bits,
        })
    }

    /// How many /24s the range holds.
    pub fn count(&self) -> u32 {
        1 << (24 - self.bits)
    }

    pub fn subnet(&self, index: u32) -> Result<Subnet> {
        if index >= self.count() {
            return Err(anyhow!(
                "subnet index {index} out of range: {} holds {}",
                self,
                self.count()
            ));
        }
        Ok(Subnet {
            index,
            network: Ipv4Addr::from(u32::from(self.base) + (index << 8)),
        })
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.bits)
    }
}

/// The smallest integer in [lo, hi] not in `used`.
pub fn first_free(mut used: Vec<u32>, lo: u32, hi: u32) -> Option<u32> {
    used.sort_unstable();
    let mut n = lo;
    for u in used {
        if u < n {
            continue;
        }
        if u > n {
            break;
        }
        n += 1;
    }
    if n > hi {
        None
    } else {
        Some(n)
    }
}

/// The bridge of namespace subnet index n.
pub fn bridge_name(index: u32) -> String {
    format!("by{index}")
}

/// The prefix of every TAP the daemon makes: no other link on the host starts with it.
pub const TAP_PREFIX: &str = "bt";

/// The TAP of a machine: "bt" + the 12 hex digits of its id (14 characters, under IFNAMSIZ).
pub fn tap_name(machine_id: &str) -> String {
    let hex = machine_id.strip_prefix("m_").unwrap_or(machine_id);
    format!("{TAP_PREFIX}{hex}")
}

/// Loopback, RFC 1918, carrier-grade NAT (100.64/10) and link-local: an address the
/// internet cannot reach. Unspecified (`0.0.0.0`, `::`) listens on everything, so it is not.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// An IPv4 network as nftables writes it: `a.b.c.d/n`, or a bare address (`/32`).
pub fn cidr(s: &str) -> Result<String> {
    let (ip, bits) = s.split_once('/').unwrap_or((s, "32"));
    let ip: Ipv4Addr = ip.parse().map_err(|_| anyhow!("{s:?}: want a.b.c.d/n"))?;
    let bits: u8 = bits.parse().map_err(|_| anyhow!("{s:?}: want a.b.c.d/n"))?;
    if bits > 32 {
        return Err(anyhow!("{s:?}: the prefix is at most /32"));
    }
    Ok(format!("{ip}/{bits}"))
}

/// A stable, locally administered MAC from a machine's address.
pub fn mac_for(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("06:b1:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets() {
        let r = Range::parse("10.64.0.0/10").unwrap();
        let s = r.subnet(0).unwrap();
        assert_eq!(s.cidr(), "10.64.0.0/24");
        assert_eq!(s.gateway().to_string(), "10.64.0.1");
        let s = r.subnet(257).unwrap();
        assert_eq!(s.cidr(), "10.65.1.0/24");
        assert_eq!(s.host(2).unwrap().to_string(), "10.65.1.2");
        assert!(r.subnet(1 << 14).is_err());
        assert!(s.host(255).is_err());
    }

    #[test]
    fn free_numbers() {
        assert_eq!(first_free(vec![], 2, 254), Some(2));
        assert_eq!(first_free(vec![2, 3, 4], 2, 254), Some(5));
        assert_eq!(first_free(vec![3, 2, 5], 2, 254), Some(4));
        assert_eq!(first_free(vec![2, 3], 2, 3), None);
        assert_eq!(first_free(vec![1, 7], 2, 254), Some(2));
    }

    #[test]
    fn names() {
        // Every hex digit of the id is kept: two ids that share eleven never share a TAP.
        assert_eq!(tap_name("m_abcdef123456"), "btabcdef123456");
        assert_eq!(tap_name("m_abcdef123457"), "btabcdef123457");
        assert_eq!(tap_name("m_abcdef123456").len(), 14);
        assert_eq!(bridge_name(3), "by3");
        assert_eq!(mac_for(Ipv4Addr::new(10, 64, 0, 2)), "06:b1:0a:40:00:02");
    }

    #[test]
    fn private_addresses() {
        for a in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.9.9",
            "192.168.64.3",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_private(a.parse().unwrap()), "{a}");
        }
        for a in [
            "0.0.0.0",
            "::",
            "203.0.113.5",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "11.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_private(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn cidrs() {
        assert_eq!(cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(cidr("192.168.64.1").unwrap(), "192.168.64.1/32");
        for bad in ["10.0.0.0/33", "10.0.0/8", "fd00::/8", "x", ""] {
            assert!(cidr(bad).is_err(), "{bad}");
        }
    }
}
