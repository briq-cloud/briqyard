//! The host network: a bridge per tenant, a TAP per machine, addresses, nftables and the
//! gateway's DNS.

pub mod dns;
pub mod host;
pub mod nft;

use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

/// A tenant's /24 inside the range.
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

/// The bridge of tenant subnet index n.
pub fn bridge_name(index: u32) -> String {
    format!("by{index}")
}

/// The TAP of a machine: "t" + the first 12 characters of its id, without separators.
pub fn tap_name(machine_id: &str) -> String {
    let id: String = machine_id
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .take(12)
        .collect();
    format!("t{id}")
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
        assert_eq!(tap_name("m_abcdef123456"), "tmabcdef12345");
        assert_eq!(bridge_name(3), "by3");
        assert_eq!(mac_for(Ipv4Addr::new(10, 64, 0, 2)), "06:b1:0a:40:00:02");
    }
}
