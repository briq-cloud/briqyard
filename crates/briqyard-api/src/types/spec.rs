//! A machine's building blocks: size, volumes, files, restart and backup policies.

use super::*;

/// A machine's compute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub vcpus: u32,
    /// CPU-time limit in millicores; omitted means one CPU per guest vCPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millis: Option<u32>,
    pub memory_mb: u32,
}

impl Size {
    pub fn cpu_millis(&self) -> u32 {
        self.cpu_millis
            .unwrap_or_else(|| self.vcpus.saturating_mul(1000))
    }

    /// What a host can boot: 1 to 32 vCPUs, 128 MB to 256 GB.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=32).contains(&self.vcpus) {
            return Err("size.vcpus must be 1..32".into());
        }
        if self
            .cpu_millis
            .is_some_and(|n| n == 0 || n > self.vcpus * 1000)
        {
            return Err("size.cpu_millis must be 1..vcpus*1000".into());
        }
        if !(128..=262144).contains(&self.memory_mb) {
            return Err("size.memory_mb must be 128..262144".into());
        }
        Ok(())
    }
}

/// A data volume mounted in the machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub size_gb: u32,
    pub mount: String,
}

/// A volume's new size, as a PATCH grows it (ADR 0040): its mount is fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSize {
    pub size_gb: u32,
}

/// A boot file: written before the process starts, and again at every cold start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    pub path: String,
    pub base64: String,
    /// Mode in octal digits ("0644"); empty is 0644.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// What the daemon does when the main process ends on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// "no", "on-failure" or "always" (default "on-failure").
    #[serde(default = "default_policy")]
    pub policy: String,
    /// Default 3: a request that names the policy alone must not end up with no retries.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_policy() -> String {
    "on-failure".into()
}

fn default_max_retries() -> u32 {
    3
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            policy: default_policy(),
            max_retries: default_max_retries(),
        }
    }
}

/// A machine's backup schedule (ADR 0023): a backup every `every`, the newest `keep` kept with
/// what they continue from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// "6h", "1d": at least an hour.
    pub every: String,
    /// At least 1.
    pub keep: u32,
}

impl BackupPolicy {
    /// The shortest `every`.
    pub const MIN_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

    /// `every` as a duration, checked with `keep`; the message names the field under `backup`.
    pub fn check(&self) -> Result<std::time::Duration, String> {
        let every =
            duration(self.every.trim(), r#"want "6h", "1d""#).map_err(|e| format!("every {e}"))?;
        if every < Self::MIN_EVERY {
            return Err(format!("every {:?}: at least 1h", self.every));
        }
        if self.keep < 1 {
            return Err("keep: at least 1".into());
        }
        Ok(every)
    }
}

/// A field that is there, `null` included, as `Some`: with `#[serde(default)]`, absent is
/// `None` and `null` is `Some(None)`. For a field where `null` removes what absent keeps.
pub(super) fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}
