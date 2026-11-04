//! Startup authority for the supported, single-domain systemd service.
//!
//! The lifetime lock serializes new daemons. It is not evidence that an old binary held
//! that lock: legacy launcher absence comes from the supported service/domain barrier.
use super::*;

#[cfg(any(target_os = "linux", test))]
mod build;
#[cfg(any(target_os = "linux", test))]
pub(super) mod fs;
#[cfg(any(target_os = "linux", test))]
pub(super) mod lock;
#[cfg(target_os = "linux")]
pub(super) mod namespace;
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
pub(super) mod provenance;
#[cfg(test)]
mod tests;
#[cfg(any(target_os = "linux", test))]
mod unit;

/// Acquired before host helpers and held by the VMM factory for its entire lifetime.
/// Only the supported official service can construct a native startup authority.
pub struct Startup {
    #[cfg(target_os = "linux")]
    inner: native::Barrier,
}
impl Startup {
    pub async fn acquire() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                inner: native::Barrier::acquire().await?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!(
                "native recovery requires supported Linux systemd supervision"
            ))
        }
    }
    pub(crate) async fn finish(
        self,
        machines: &[RecoveryMachine],
        jailer: &Path,
        vmm: &str,
    ) -> Result<Recovered> {
        if machines.len() > 4096 {
            return Err(anyhow!("machine recovery inventory exceeds bound"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for machine in machines {
            let encoded = super::fc_id(&machine.id);
            if machine.pid == 1
                || !machine.id.starts_with("m_")
                || machine.id.len() > 128
                || !machine
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || encoded.replacen("m-", "m_", 1) != machine.id
                || !ids.insert(encoded)
            {
                return Err(anyhow!("invalid or colliding machine recovery identity"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.inner.finish(machines, jailer, vmm).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (machines, jailer, vmm);
            Err(anyhow!("native recovery requires Linux"))
        }
    }
}

#[doc(hidden)]
pub struct RecoveryMachine {
    pub(crate) id: String,
    pub(crate) pid: u32,
}

/// Non-deserializable, non-cloneable and constructed only after the final kernel barrier.
pub(crate) struct Recovered {
    #[cfg(target_os = "linux")]
    pub(super) lock: std::sync::Arc<lock::DomainLock>,
    #[cfg(target_os = "linux")]
    pub(super) jailer: provenance::Jailer,
    #[cfg(target_os = "linux")]
    pub(super) namespace: Arc<namespace::Namespace>,
    pub(super) entries: Vec<RecoveredEntry>,
}
pub(super) struct RecoveredEntry {
    pub(super) id: String,
    #[cfg(target_os = "linux")]
    pub(super) live: Option<Arc<super::memory::ProcessIdentity>>,
    pub(super) pid: Option<u32>,
}
