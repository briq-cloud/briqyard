//! Join tokens and the join call (ADR 0057).

use super::*;

/// `POST /v1/hosts/tokens`: a one-time token for a server to join the fleet with.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateJoinTokenRequest {
    /// How long it can be used, in seconds; absent: an hour. At most 30 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_sec: Option<u64>,
    /// The region the host that joins with it is put in.
    #[serde(default)]
    pub region: String,
    /// Labels the host that joins with it carries (`key=value`, as machine labels).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The id the host must join as; empty: the joiner names itself.
    #[serde(default)]
    pub host: String,
}

/// A join token as the fleet lists it. The secret is never in it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinToken {
    pub id: String,
    /// `active`, `used`, `expired` or `revoked`.
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// The id the token is bound to, when it is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// Who used it, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_by: Option<JoinTokenUse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// The host that consumed a token, when, and the address its call came from.
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
