//! Version-one scoped execution wire types. No route accepts these credentials yet.
//! Verification is host-only and is insufficient without durable admission consumption,
//! allocation fencing and lifecycle-serialized dispatch to the exact live run.

use serde::{Deserialize, Serialize};

#[cfg(feature = "execution-verifier")]
mod verify;
#[cfg(feature = "execution-verifier")]
pub use verify::*;
#[cfg(feature = "execution-admission")]
pub mod admission;
#[cfg(feature = "execution-admission")]
mod issuer;
#[cfg(feature = "execution-admission")]
pub use issuer::*;
#[cfg(feature = "execution-verifier")]
mod request;
#[cfg(feature = "execution-verifier")]
pub use request::*;

pub const GRANT_TYPE: &str = "briqyard-execution-grant+jwt";
pub const ALLOCATION_TYPE: &str = "briqyard-execution-allocation+jwt";
pub const PERMIT_TYPE: &str = "briqyard-execution-permit+jwt";
pub const MAX_TOKEN_BYTES: usize = 16_384;
pub const MAX_ALLOCATIONS: usize = 16;
pub const MAX_RESOURCES: usize = 64;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub alg: String,
    pub typ: String,
    pub kid: String,
    pub v: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Exec,
    ExecStream,
    Shell,
    FilesRead,
    FilesWrite,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub host: String,
    pub machine: String,
    pub namespace: String,
    /// Actual VMM incarnation, never a logical machine ID alone.
    pub run: String,
    /// Execution epoch changed on ownership/namespace/placement invalidation.
    pub placement: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub kind: String,
    pub id: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceSet {
    pub revision: String,
    pub resources: Vec<Target>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdleProtection {
    pub admission: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_duration_seconds: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub v: u8,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub id: String,
    pub principal: String,
    pub source: Source,
    pub team: String,
    /// Immutable external target identity, independently bound to the runtime target.
    pub subject: String,
    pub target: Target,
    pub resource_set: ResourceSet,
    pub idle: IdleProtection,
    pub metadata_revision: String,
    pub operations: Vec<Operation>,
    pub limits: Limits,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub v: u8,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub id: String,
    pub epoch: String,
    pub authority: String,
    pub authority_epoch: String,
    pub principal: String,
    pub bucket: String,
    pub window_start: u64,
    pub window_end: u64,
    pub units: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllocationRef {
    pub id: String,
    pub epoch: String,
    /// SHA-256 of the exact compact JWS, unpadded base64url.
    pub digest: String,
    pub units: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub v: u8,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub admission: String,
    pub authority: String,
    pub authority_epoch: String,
    pub grant_digest: String,
    pub allocations: Vec<AllocationRef>,
    pub target: Target,
    pub operation: Operation,
    /// SHA-256 commitment to the operation's versioned request encoding.
    /// Defining and enforcing that encoding is required before enabling any route.
    pub request_digest: String,
    pub metadata_revision: String,
    pub limits: Limits,
}

#[cfg(all(test, feature = "execution-verifier"))]
mod tests;
