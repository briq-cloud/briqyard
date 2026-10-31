//! Fixed cold-boot device profile, compatibility identity and typed balloon API.

use super::*;
use serde::Deserialize;

pub const REPORTING_PROFILE: &str = "balloon-reporting-v1";
pub const LEGACY_PROFILE: &str = "legacy-no-balloon";
pub const UNAVAILABLE_PROFILE: &str = "unavailable-device-profile";

/// Device topology is fixed by the profile; mutable target/actual pages belong to snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonConfig {
    pub amount_mib: u32,
    pub deflate_on_oom: bool,
    pub stats_polling_interval_s: u16,
    pub free_page_hinting: bool,
    pub free_page_reporting: bool,
}

impl BalloonConfig {
    pub fn reporting() -> Self {
        Self {
            amount_mib: 0,
            deflate_on_oom: true,
            stats_polling_interval_s: 5,
            free_page_hinting: false,
            free_page_reporting: true,
        }
    }
}

/// Independent of the historical memory-spec digest, so old snapshots remain readable.
/// Unknown schemas deserialize but never qualify for a memory load.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootIdentity {
    pub schema: u32,
    pub device_profile: String,
    pub kernel_sha256: String,
    pub vmm_sha256: String,
    pub host_kernel: String,
    pub transport: String,
}

impl BootIdentity {
    /// Hash immutable artifacts once at daemon startup, without buffering entire files.
    pub fn read(kernel: &Path, vmm: &Path, pci: bool) -> Result<Self> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        fn digest(path: &Path) -> Result<String> {
            let mut file = std::fs::File::open(path)
                .with_context(|| format!("boot identity: {}", path.display()))?;
            let mut hash = Sha256::new();
            let mut buf = [0; 65536];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hash.update(&buf[..n]);
            }
            Ok(hex::encode(hash.finalize()))
        }
        Ok(Self {
            schema: 1,
            device_profile: LEGACY_PROFILE.into(),
            kernel_sha256: digest(kernel)?,
            vmm_sha256: digest(vmm)?,
            host_kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")?
                .trim()
                .into(),
            transport: if pci { "pci" } else { "mmio" }.into(),
        })
    }

    pub fn with_reporting(&self, enabled: bool) -> Self {
        let mut identity = self.clone();
        identity.device_profile = if enabled {
            REPORTING_PROFILE
        } else {
            LEGACY_PROFILE
        }
        .into();
        identity
    }

    pub fn compatible(&self, host: &Self) -> bool {
        self.schema == 1
            && matches!(
                self.device_profile.as_str(),
                REPORTING_PROFILE | LEGACY_PROFILE
            )
            && !self.kernel_sha256.is_empty()
            && !self.vmm_sha256.is_empty()
            && self == &host.with_reporting(self.device_profile == REPORTING_PROFILE)
    }

    /// Old daemons retain unknown record fields, so a rollback's cold boot can leave
    /// stale provenance. Only a successful contradictory observation invalidates it.
    pub fn after_adoption(
        saved: Option<&Self>,
        observed: Option<&Self>,
        bound: bool,
    ) -> Option<Self> {
        let profile = observed.map_or(LEGACY_PROFILE, |i| i.device_profile.as_str());
        match saved {
            Some(identity)
                if identity.schema > 1
                    || profile == UNAVAILABLE_PROFILE
                    || (bound && identity.device_profile == profile) =>
            {
                Some(identity.clone())
            }
            Some(_) => Some(Self::ambiguous(profile)),
            None => observed.cloned(),
        }
    }

    /// Observed live device with no durable artifact provenance: keep it alive, refuse
    /// future memory loads. Current daemon artifacts cannot establish what this VMM used.
    pub fn ambiguous(profile: &str) -> Self {
        Self {
            schema: 0,
            device_profile: profile.into(),
            kernel_sha256: String::new(),
            vmm_sha256: String::new(),
            host_kernel: String::new(),
            transport: String::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BalloonStatistics {
    pub target_pages: u64,
    pub actual_pages: u64,
    pub free_memory: Option<u64>,
    pub available_memory: Option<u64>,
    pub disk_caches: Option<u64>,
}

impl Client {
    pub async fn configure_balloon(&self, config: &BalloonConfig) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(3), self.put("/balloon", config))
            .await
            .context("balloon configuration timed out")?
    }

    /// A 400/404 for a device that does not exist is distinct from a failed read.
    pub async fn balloon_config(&self) -> Result<Option<BalloonConfig>> {
        let result =
            tokio::time::timeout(Duration::from_secs(3), self.call("GET", "/balloon", None))
                .await
                .context("balloon configuration read timed out")?;
        match result {
            Ok(body) => Ok(Some(serde_json::from_str(&body)?)),
            Err(err)
                if err.downcast_ref::<ApiError>().is_some_and(|e| {
                    matches!(e.status, 400 | 404)
                        && (e.fault.contains("No balloon device")
                            || e.fault == "Internal VMM error: Failed perform action on device: Device not found")
                }) =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    pub async fn balloon_statistics(&self) -> Result<BalloonStatistics> {
        let body = tokio::time::timeout(
            Duration::from_secs(3),
            self.call("GET", "/balloon/statistics", None),
        )
        .await
        .context("balloon statistics timed out")??;
        Ok(serde_json::from_str(&body)?)
    }
}

/// A failed/missing memory load is handled by the manager, which persists the cold
/// identity before a replacement process can start.
#[derive(Debug, thiserror::Error)]
#[error("snapshot resume failed: {0}")]
pub struct ResumeFailed(pub String);
