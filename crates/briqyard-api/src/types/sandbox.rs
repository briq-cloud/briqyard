//! Stable client-request identity for accepted sandbox creates and read-only replay lookup.
use super::*;

pub fn valid_sandbox_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRequestLookup {
    pub namespace: String,
    pub request_id: String,
    pub create_sha256: String,
}
impl SandboxRequestLookup {
    pub fn check(&self) -> Result<(), &'static str> {
        if !valid_id(&self.namespace)
            || !valid_sandbox_request_id(&self.request_id)
            || self.create_sha256.len() != 64
            || !self
                .create_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid sandbox request lookup identity");
        }
        Ok(())
    }
}
impl CreateMachineRequest {
    /// Canonical versioned CLIENT request bytes, independent of current source/host policy.
    pub fn sandbox_create_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut normalized = self.clone();
        normalized.sleep = if self.sleep.trim().is_empty() {
            "never".into()
        } else {
            self.sleep.trim().into()
        };
        normalized.restart = Some(self.restart.clone().unwrap_or_default());
        normalized.egress = Some(self.egress.clone().unwrap_or_default());
        normalized.probes = Some(self.probes.clone().unwrap_or_default());
        normalized.limits = Some(self.limits.clone().unwrap_or_default());
        normalized.disk_limits = Some(self.disk_limits.clone().unwrap_or_default());
        let mut bytes = b"briqyard:sandbox-create-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&normalized)?);
        Ok(bytes)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_request_normalizes_static_defaults_but_preserves_backup_region_and_metadata() {
        let mut request = CreateMachineRequest::default();
        let bytes = request.sandbox_create_bytes().unwrap();
        request.sleep = " never ".into();
        request.restart = Some(RestartPolicy::default());
        assert_eq!(request.sandbox_create_bytes().unwrap(), bytes);
        request.backup = Some(None);
        assert_ne!(request.sandbox_create_bytes().unwrap(), bytes);
        request.backup = None;
        request.region = "one".into();
        assert_ne!(request.sandbox_create_bytes().unwrap(), bytes);
        request.region.clear();
        request.metadata.insert("team".into(), "one".into());
        assert_ne!(request.sandbox_create_bytes().unwrap(), bytes);
    }
}
