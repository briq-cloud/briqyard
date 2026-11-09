use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    Central,
    Authority,
}

/// Only locally configured raw Ed25519 public keys. No token controls key discovery.
#[derive(Clone)]
pub struct VerificationKey {
    pub kid: String,
    pub role: KeyRole,
    pub issuer: String,
    /// Authority keys belong to exactly one authority; central keys use None.
    pub authority: Option<String>,
    pub public_key: [u8; 32],
}

/// Trusted wall-clock estimate and its maximum absolute error, in whole seconds.
/// Uncertainty narrows acceptance: nbf <= now-error and now+error < exp.
#[derive(Clone, Copy)]
pub struct Clock {
    pub now: u64,
    pub uncertainty: u64,
}

pub struct Trust<'a> {
    pub keys: &'a [VerificationKey],
    pub central_issuer: &'a str,
    pub authority_issuer: &'a str,
    pub audience: &'a str,
}

/// A caller-owned trusted snapshot, never values copied from the submitted credentials.
/// Installed allocations must already be durably fenced to this host incarnation.
pub struct DispatchContext<'a> {
    pub principal: &'a str,
    pub team: &'a str,
    pub subject: &'a str,
    pub target: &'a Target,
    pub resource_set: &'a ResourceSet,
    pub metadata_revision: &'a str,
    pub authority: &'a str,
    pub authority_epoch: &'a str,
    pub installed_allocations: &'a [AllocationRef],
    pub operation: Operation,
    pub request_digest: &'a str,
}

/// Trusted metadata used before an operation permit exists. The authenticated installer
/// supplies this snapshot; submitted credentials must never construct it.
pub struct DelegationContext<'a> {
    pub principal: &'a str,
    pub team: &'a str,
    pub subject: &'a str,
    pub target: &'a Target,
    pub resource_set: &'a ResourceSet,
    pub metadata_revision: &'a str,
    pub authority: &'a str,
    pub authority_epoch: &'a str,
}

/// Checked central credentials, without an operation debit or dispatch permission.
pub struct VerifiedDelegation {
    grant: Grant,
    allocations: Vec<Allocation>,
    allocation_digests: Vec<String>,
}
impl VerifiedDelegation {
    /// Digests of the verified compact tokens, in the same order as allocations().
    pub fn allocation_digests(&self) -> &[String] {
        &self.allocation_digests
    }
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    pub fn allocations(&self) -> &[Allocation] {
        &self.allocations
    }
}

/// Cryptographically checked data, not permission to dispatch or evidence of consumption.
pub struct VerifiedBundle {
    grant: Grant,
    permit: Permit,
    allocations: Vec<Allocation>,
}
impl VerifiedBundle {
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    pub fn permit(&self) -> &Permit {
        &self.permit
    }
    pub fn allocations(&self) -> &[Allocation] {
        &self.allocations
    }
}

/// Fixed categories only: never include submitted credentials in an error or log.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid execution wire encoding")]
    Encoding,
    #[error("invalid execution signing key or signature")]
    Signature,
    #[error("invalid execution claims")]
    Claims,
    #[error("execution credential outside validity interval")]
    Time,
    #[error("execution binding is stale or mismatched")]
    Binding,
}
type Result<T> = std::result::Result<T, VerifyError>;

/// SHA-256 of exact UTF-8 compact JWS bytes (no JSON reserialization).
pub fn token_digest(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:/".contains(&c))
}
fn digest(s: &str) -> bool {
    s.len() == 43 && URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| b.len() == 32)
}
fn safe(n: u64) -> bool {
    n <= MAX_SAFE_INTEGER
}
fn target(t: &Target) -> bool {
    [&t.host, &t.machine, &t.namespace, &t.run, &t.placement]
        .into_iter()
        .all(|s| id(s))
}
fn limits(l: &Limits) -> bool {
    l.max_duration_seconds > 0
        && safe(l.max_duration_seconds)
        && safe(l.max_input_bytes)
        && safe(l.max_output_bytes)
        && (l.output_mode.is_none()
            || (l.max_output_bytes > 0 && l.max_output_bytes <= MAX_CAPTURE_BYTES))
}
fn within(a: &Limits, b: &Limits) -> bool {
    a.output_mode == b.output_mode
        && a.max_duration_seconds <= b.max_duration_seconds
        && a.max_input_bytes <= b.max_input_bytes
        && a.max_output_bytes <= b.max_output_bytes
}
fn times(iat: u64, nbf: u64, exp: u64, clock: Clock) -> Result<()> {
    if ![iat, nbf, exp, clock.now, clock.uncertainty]
        .into_iter()
        .all(safe)
        || iat > nbf
        || nbf >= exp
    {
        return Err(VerifyError::Claims);
    }
    let earliest = clock
        .now
        .checked_sub(clock.uncertainty)
        .ok_or(VerifyError::Time)?;
    let latest = clock
        .now
        .checked_add(clock.uncertainty)
        .filter(|v| safe(*v))
        .ok_or(VerifyError::Time)?;
    if iat > earliest || nbf > earliest || exp <= latest {
        return Err(VerifyError::Time);
    }
    Ok(())
}
fn common(v: u8, iss: &str, aud: &str, issuer: &str, audience: &str) -> Result<()> {
    if v != 1 || !id(iss) || !id(aud) || iss != issuer || aud != audience {
        return Err(VerifyError::Claims);
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(
    token: &str,
    typ: &str,
    role: KeyRole,
    issuer: &str,
    authority: Option<&str>,
    trust: &Trust<'_>,
) -> Result<T> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(VerifyError::Encoding);
    }
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Encoding);
    };
    if head.len() > 512 || body.is_empty() || sig.len() != 86 {
        return Err(VerifyError::Encoding);
    }
    let h: Header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(head)
            .map_err(|_| VerifyError::Encoding)?,
    )
    .map_err(|_| VerifyError::Encoding)?;
    if h.alg != "EdDSA" || h.typ != typ || h.v != 1 || !id(&h.kid) {
        return Err(VerifyError::Claims);
    }
    // Duplicate local IDs are a configuration failure, never first-key-wins.
    let mut keys = trust.keys.iter().filter(|k| k.kid == h.kid);
    let key = keys.next().ok_or(VerifyError::Signature)?;
    if keys.next().is_some()
        || key.role != role
        || key.issuer != issuer
        || key.authority.as_deref() != authority
    {
        return Err(VerifyError::Signature);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| VerifyError::Encoding)?;
    let signed = &token.as_bytes()[..head.len() + 1 + body.len()];
    signature::UnparsedPublicKey::new(&signature::ED25519, key.public_key)
        .verify(signed, &signature)
        .map_err(|_| VerifyError::Signature)?;
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| VerifyError::Encoding)?,
    )
    .map_err(|_| VerifyError::Encoding)
}

/// Verify an installation's central credentials before an operation permit exists.
/// This neither installs a fence nor reserves quota. Each allocation has its own expiry;
/// a longer-lived grant never extends an allocation's usable interval.
pub fn verify_delegation(
    grant_token: &str,
    allocation_tokens: &[&str],
    trust: &Trust<'_>,
    clock: Clock,
    context: &DelegationContext<'_>,
) -> Result<VerifiedDelegation> {
    if allocation_tokens.is_empty() || allocation_tokens.len() > MAX_ALLOCATIONS {
        return Err(VerifyError::Claims);
    }
    let g: Grant = decode(
        grant_token,
        GRANT_TYPE,
        KeyRole::Central,
        trust.central_issuer,
        None,
        trust,
    )?;
    common(g.v, &g.iss, &g.aud, trust.central_issuer, trust.audience)?;
    times(g.iat, g.nbf, g.exp, clock)?;
    if ![
        &g.id,
        &g.principal,
        &g.team,
        &g.subject,
        &g.source.kind,
        &g.source.id,
        &g.resource_set.revision,
        &g.idle.admission,
        &g.metadata_revision,
    ]
    .into_iter()
    .all(|s| id(s))
        || !target(&g.target)
        || !limits(&g.limits)
        || !safe(g.source.expires_at)
        || !safe(g.idle.expires_at)
        || g.exp > g.source.expires_at
        || g.exp > g.idle.expires_at
        || g.resource_set.resources.is_empty()
        || g.resource_set.resources.len() > MAX_RESOURCES
        || !g.resource_set.resources.iter().all(target)
        || !g.resource_set.resources.contains(&g.target)
        || g.operations.is_empty()
        || g.operations.len() > 5
    {
        return Err(VerifyError::Claims);
    }
    for (i, resource) in g.resource_set.resources.iter().enumerate() {
        if g.resource_set.resources[..i]
            .iter()
            .any(|r| r.machine == resource.machine)
        {
            return Err(VerifyError::Claims);
        }
    }
    for (i, op) in g.operations.iter().enumerate() {
        if g.operations[..i].contains(op) {
            return Err(VerifyError::Claims);
        }
    }
    if g.principal != context.principal
        || g.team != context.team
        || g.subject != context.subject
        || g.target != *context.target
        || g.resource_set != *context.resource_set
        || g.metadata_revision != context.metadata_revision
        || !id(context.authority)
        || !id(context.authority_epoch)
    {
        return Err(VerifyError::Binding);
    }
    let mut allocations = Vec::with_capacity(allocation_tokens.len());
    for token in allocation_tokens {
        let a: Allocation = decode(
            token,
            ALLOCATION_TYPE,
            KeyRole::Central,
            trust.central_issuer,
            None,
            trust,
        )?;
        common(a.v, &a.iss, &a.aud, trust.central_issuer, trust.audience)?;
        times(a.iat, a.nbf, a.exp, clock)?;
        if ![
            &a.id,
            &a.epoch,
            &a.authority,
            &a.authority_epoch,
            &a.principal,
            &a.bucket,
        ]
        .into_iter()
        .all(|s| id(s))
            || ![a.window_start, a.window_end, a.units]
                .into_iter()
                .all(safe)
            || a.units == 0
            || a.window_start > a.iat
            || a.window_start > a.nbf
            || a.exp > a.window_end
            || a.window_start >= a.window_end
        {
            return Err(VerifyError::Claims);
        }
        if allocations
            .iter()
            .any(|previous: &Allocation| previous.id == a.id || previous.bucket == a.bucket)
            || a.principal != g.principal
            || a.authority != context.authority
            || a.authority_epoch != context.authority_epoch
        {
            return Err(VerifyError::Binding);
        }
        allocations.push(a);
    }
    Ok(VerifiedDelegation {
        grant: g,
        allocations,
        allocation_digests: allocation_tokens
            .iter()
            .map(|token| token_digest(token))
            .collect(),
    })
}

/// Verify both independent signatures, all ceilings, and the trusted dispatch snapshot.
/// This does not consume an admission. It must not be wired to existing admin routes.
pub fn verify_bundle(
    grant_token: &str,
    permit_token: &str,
    allocation_tokens: &[&str],
    trust: &Trust<'_>,
    clock: Clock,
    context: &DispatchContext<'_>,
) -> Result<VerifiedBundle> {
    let VerifiedDelegation {
        grant: g,
        allocations,
        ..
    } = verify_delegation(
        grant_token,
        allocation_tokens,
        trust,
        clock,
        &DelegationContext {
            principal: context.principal,
            team: context.team,
            subject: context.subject,
            target: context.target,
            resource_set: context.resource_set,
            metadata_revision: context.metadata_revision,
            authority: context.authority,
            authority_epoch: context.authority_epoch,
        },
    )?;
    let p: Permit = decode(
        permit_token,
        PERMIT_TYPE,
        KeyRole::Authority,
        trust.authority_issuer,
        Some(context.authority),
        trust,
    )?;
    common(p.v, &p.iss, &p.aud, trust.authority_issuer, trust.audience)?;
    times(p.iat, p.nbf, p.exp, clock)?;
    if ![
        &p.admission,
        &p.authority,
        &p.authority_epoch,
        &p.metadata_revision,
    ]
    .into_iter()
    .all(|s| id(s))
        || !target(&p.target)
        || !limits(&p.limits)
        || !within(&p.limits, &g.limits)
        || !digest(&p.grant_digest)
        || !digest(&p.request_digest)
        || p.exp > g.exp
        || p.iat < g.iat
        || p.nbf < g.nbf
        || p.allocations.len() != allocation_tokens.len()
    {
        return Err(VerifyError::Claims);
    }
    if p.grant_digest != token_digest(grant_token)
        || p.target != g.target
        || p.metadata_revision != g.metadata_revision
        || !g.operations.contains(&p.operation)
    {
        return Err(VerifyError::Binding);
    }
    for ((token, reference), a) in allocation_tokens
        .iter()
        .zip(&p.allocations)
        .zip(&allocations)
    {
        if !safe(reference.units)
            || reference.units == 0
            || reference.units > a.units
            || p.exp > a.exp
            || p.iat < a.iat
            || p.nbf < a.nbf
            || !digest(&reference.digest)
        {
            return Err(VerifyError::Claims);
        }
        if reference.id != a.id
            || reference.epoch != a.epoch
            || reference.digest != token_digest(token)
            || a.authority != p.authority
            || a.authority_epoch != p.authority_epoch
        {
            return Err(VerifyError::Binding);
        }
    }
    if p.authority != context.authority
        || p.authority_epoch != context.authority_epoch
        || p.operation != context.operation
        || p.request_digest != context.request_digest
        || p.allocations != context.installed_allocations
    {
        return Err(VerifyError::Binding);
    }
    Ok(VerifiedBundle {
        grant: g,
        permit: p,
        allocations,
    })
}
