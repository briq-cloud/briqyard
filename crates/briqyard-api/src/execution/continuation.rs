//! Dormant operation continuation contract. These credentials cannot reserve quota,
//! prepare an admission or dispatch a guest request.
use super::{verify, *};

/// Ten seconds for initial dispatch, sixty for the guest and ten for terminal I/O.
/// This is distinct from both the guest timeout and the authorization lease.
pub const MAX_OPERATION_MILLIS: u64 = 80_000;

/// Frozen by the trusted host at consumption. Neither renewal nor a new quota
/// window may change this identity or restart its runtime envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveOperationBinding {
    pub operation_id: String,
    pub admission: String,
    pub grant_digest: String,
    pub permit_digest: String,
    pub request_digest: String,
    pub authority: String,
    pub authority_epoch: String,
    pub host_instance: String,
    pub ownership: String,
    pub ownership_generation: u64,
    pub policy_revision: String,
    pub delegation: String,
    pub delegation_version: u64,
    pub principal: String,
    pub source: Source,
    pub team: String,
    pub subject: String,
    pub metadata_revision: String,
    pub target: Target,
    pub resource_set: ResourceSet,
    pub limits: Limits,
    pub guest_timeout_ms: u64,
    pub started_at_ms: u64,
    pub operation_deadline_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationContinuation {
    pub v: u8,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    /// Last independent source/session authorization, never a status read.
    pub checked_at: u64,
    pub previous_sequence: u64,
    pub sequence: u64,
    pub binding: ActiveOperationBinding,
    /// Exact fsynced protection ACK; a requested deadline is insufficient.
    pub protection: admission::InstalledProtection,
}

/// Signature/claims evidence only. The host must serialize durable application
/// with completion/revocation and extend the live timer only after that commit.
pub struct VerifiedContinuation(OperationContinuation);
impl VerifiedContinuation {
    pub fn claims(&self) -> &OperationContinuation {
        &self.0
    }
}

impl ActiveOperationBinding {
    /// Structural bounds only; this does not authenticate or activate an operation.
    pub fn is_valid(&self) -> bool {
        let b = self;
        [
            &b.operation_id,
            &b.admission,
            &b.authority,
            &b.authority_epoch,
            &b.host_instance,
            &b.ownership,
            &b.policy_revision,
            &b.delegation,
            &b.principal,
            &b.source.kind,
            &b.source.id,
            &b.team,
            &b.subject,
            &b.metadata_revision,
            &b.resource_set.revision,
        ]
        .into_iter()
        .all(|s| verify::id(s))
            && [&b.grant_digest, &b.permit_digest, &b.request_digest]
                .into_iter()
                .all(|s| verify::digest(s))
            && b.ownership_generation > 0
            && b.delegation_version > 0
            && b.ownership_generation <= MAX_SAFE_INTEGER
            && b.delegation_version <= MAX_SAFE_INTEGER
            && b.source.expires_at <= MAX_SAFE_INTEGER
            && verify::target(&b.target)
            && !b.resource_set.resources.is_empty()
            && b.resource_set.resources.len() <= MAX_RESOURCES
            && b.resource_set.resources.iter().all(verify::target)
            && b.resource_set.resources.contains(&b.target)
            && b.resource_set.resources.iter().enumerate().all(|(i, t)| {
                !b.resource_set.resources[..i]
                    .iter()
                    .any(|p| p.host == t.host && p.machine == t.machine)
            })
            && verify::limits(&b.limits)
            && b.limits.execution_mode == Some(ExecutionMode::RenewableExecV1)
            && b.guest_timeout_ms > 0
            && b.guest_timeout_ms <= b.limits.max_duration_seconds * 1000
            && b.started_at_ms <= MAX_SAFE_INTEGER
            && b.operation_deadline_ms <= MAX_SAFE_INTEGER
            && b.operation_deadline_ms > b.started_at_ms
            && b.operation_deadline_ms - b.started_at_ms <= MAX_OPERATION_MILLIS
            && b.operation_deadline_ms - b.started_at_ms >= b.guest_timeout_ms
    }
}

/// The independently retained binding must be for the exact active command.
/// There are deliberately no allocation tokens or quota checks in this path.
pub fn verify_continuation(
    token: &str,
    trust: &Trust<'_>,
    clock: Clock,
    active: &ActiveOperationBinding,
) -> Result<VerifiedContinuation, VerifyError> {
    let c: OperationContinuation = verify::decode(
        token,
        CONTINUATION_TYPE,
        KeyRole::Central,
        trust.central_issuer,
        None,
        trust,
    )?;
    verify::common(c.v, &c.iss, &c.aud, trust.central_issuer, trust.audience)?;
    verify::times(c.iat, c.nbf, c.exp, clock)?;
    if !active.is_valid()
        || c.binding != *active
        || c.checked_at > c.iat
        || c.exp > c.checked_at.saturating_add(MAX_COMMAND_SECONDS)
        || c.exp > active.source.expires_at
        || c.exp.saturating_mul(1000) > active.operation_deadline_ms
        || c.sequence > MAX_SAFE_INTEGER
        || c.previous_sequence.checked_add(1) != Some(c.sequence)
        || !verify::id(&c.protection.installation)
        || !verify::id(&c.protection.admission)
        || c.protection.installation != active.ownership
        || c.protection.generation != active.ownership_generation
        || c.protection.generation == 0
        || c.protection.generation > MAX_SAFE_INTEGER
        || c.protection.expires_at_ms > MAX_SAFE_INTEGER
        || c.protection.expires_at_ms < c.exp.saturating_mul(1000)
        || c.protection.resources != active.resource_set.resources
        || c.protection.resource_revision != active.resource_set.revision
    {
        return Err(VerifyError::Claims);
    }
    Ok(VerifiedContinuation(c))
}
