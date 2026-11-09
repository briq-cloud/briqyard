//! Shared wire shapes for the dedicated internal host channel. Authentication is
//! enforced by its listener; these types alone grant no authority.
use super::*;
use crate::ExecRequest;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub host_instance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationAck {
    pub host_instance: String,
    pub generation: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Protect {
    pub installation: String,
    pub generation: u64,
    pub admission: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectionAck {
    pub admission: String,
    pub expires_at_ms: u64,
    pub resources: Vec<Target>,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallDelegation {
    pub installation: String,
    pub generation: u64,
    pub id: String,
    pub version: u64,
    pub principal: String,
    pub grant: String,
    pub allocations: Vec<String>,
    pub protection_expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invalidate {
    pub installation: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    pub id: String,
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRequest {
    pub installation: String,
    pub generation: u64,
    pub delegation: String,
    pub grant: String,
    pub allocations: Vec<String>,
    pub permit: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Prepare {
    #[serde(flatten)]
    pub bundle: BundleRequest,
    pub request_digest: String,
    pub admission: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Dispatch {
    #[serde(flatten)]
    pub bundle: BundleRequest,
    pub admission: String,
    pub request: ExecRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub admission: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionStatus {
    pub prepared: bool,
    pub dispatched: bool,
    pub journal: Option<admission::Status>,
}
