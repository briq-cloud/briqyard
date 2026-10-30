//! Join tokens and the join call (ADR 0059).

use super::*;

/// `POST /v1/hosts/tokens`: a token servers join the fleet with, until it expires or is revoked.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateJoinTokenRequest {
    /// How long it can be used, in seconds; absent: 24 hours; 0: it never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_sec: Option<u64>,
    /// Free text shown in the listing (at most 256 characters).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// The region the host that joins with it is put in.
    #[serde(default)]
    pub region: String,
    /// Labels the host that joins with it carries (`key=value`, as machine labels).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The id the host must join as; empty: the joiner names itself.
    #[serde(default)]
    pub host: String,
    /// The address (`10.42.0.12`) or network (`10.42.0.0/24`) the join must come from; empty:
    /// from anywhere. A token bound to the server it is for is useless from any other.
    #[serde(default)]
    pub address: String,
}

/// A join token as the fleet lists it. The secret is never in it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinToken {
    pub id: String,
    /// `active`, `expired` or `revoked`.
    pub state: String,
    pub created_at: DateTime<Utc>,
    /// Absent: it never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// How many joins it took.
    #[serde(default)]
    pub uses: u32,
    /// The last of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<JoinTokenUse>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// The id the token is bound to, when it is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// The address or network the token is bound to, when it is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A host that joined with a token, when, and the address its call came from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinTokenUse {
    pub host: String,
    pub at: DateTime<Utc>,
    pub peer: String,
}

/// The answer to a create: the token itself, `<id>.<secret>`, which the fleet does not keep and
/// shows this once.
#[derive(Clone, Serialize, Deserialize)]
pub struct JoinTokenCreated {
    pub token: String,
    #[serde(flatten)]
    pub info: JoinToken,
}

/// Never printed: a `{:?}` of it would put the token in a log.
impl std::fmt::Debug for JoinTokenCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinTokenCreated {{ id: {:?}, .. }}", self.info.id)
    }
}

/// `POST /v1/hosts/join`, with the join token as the bearer: what a server says of itself.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The id it asks for; empty: `h_` and its address. A token bound to an id takes that one
    /// only.
    #[serde(default)]
    pub name: String,
    /// Its API's IPv4 address; empty: the one the call came from. It must be the one the call
    /// came from.
    #[serde(default)]
    pub address: String,
    /// `x86_64` or `aarch64`.
    pub arch: String,
    #[serde(default)]
    pub memory_mb: u32,
    #[serde(default)]
    pub vcpus: u32,
}

/// What the join gives the host: its id and the settings of the bootstrap script
/// (`hack/bootstrap-host.sh`), by their environment names. They hold the host's own API token.
#[derive(Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub id: String,
    pub env: BTreeMap<String, String>,
}

/// Never printed: `env` holds the host's token.
impl std::fmt::Debug for JoinResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinResponse {{ id: {:?}, .. }}", self.id)
    }
}
