//! Physical VMM reservation, separate from guest memory and namespace quotas.

use serde::{Deserialize, Serialize};

pub const VMM_OVERHEAD_MB: u32 = 256;

/// The existing per-VMM hard ceiling, also reserved against physical host capacity.
pub fn vmm_memory_mb(guest_mb: u32) -> Option<u32> {
    guest_mb.checked_add(VMM_OVERHEAD_MB)
}

/// Host accounting semantics. Absence on the wire denotes a legacy host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPolicy {
    pub version: u32,
    pub vmm_overhead_mb: u32,
}

impl MemoryPolicy {
    pub const CURRENT: Self = Self {
        version: 1,
        vmm_overhead_mb: VMM_OVERHEAD_MB,
    };

    /// Unknown policies cannot safely reserve a host's next allocation.
    pub fn reservation(self, guest_mb: u32) -> Option<u32> {
        (self == Self::CURRENT)
            .then(|| vmm_memory_mb(guest_mb))
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_ceiling_is_checked_and_policy_is_explicit() {
        assert_eq!(vmm_memory_mb(128), Some(384));
        assert_eq!(vmm_memory_mb(u32::MAX), None);
        assert_eq!(MemoryPolicy::CURRENT.reservation(2048), Some(2304));
        assert_eq!(
            MemoryPolicy {
                version: 2,
                ..MemoryPolicy::CURRENT
            }
            .reservation(128),
            None
        );
        assert_eq!(
            MemoryPolicy {
                vmm_overhead_mb: 0,
                ..MemoryPolicy::CURRENT
            }
            .reservation(128),
            None
        );
    }
}
