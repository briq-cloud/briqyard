//! Fixed-host operation renewal. Central authorization arrives only in signed
//! continuations; neither observation nor committed idle input reauthorizes source.
use super::*;
use crate::execution_host::Route;
use briqyard_api::execution::{
    admission::{ActivePhase, RenewalAttempt},
    channel::{ActiveState, ActiveStatus, ContinueOperation, StatusRequest},
    token_digest, verify_continuation,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectOperation {
    id: String,
    operation_id: String,
    previous_sequence: u64,
    committed: CommittedIdleDto,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Continue {
    id: String,
    operation_id: String,
    previous_sequence: u64,
    continuation: String,
}

async fn live(
    service: &Service,
    issuer: &mut briqyard_api::execution::DurableIssuer,
    id: &str,
) -> Result<ActiveStatus, StatusCode> {
    if !service.live.contains(id) {
        return Err(StatusCode::CONFLICT);
    }
    let before = clock(service.clock.as_ref())?;
    let status: ActiveStatus = service
        .host
        .call(
            Route::Active,
            &StatusRequest {
                admission: id.into(),
            },
        )
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let after = clock(service.clock.as_ref())?;
    let observed = &status.observed_at;
    if observed.uncertainty > 5
        || observed.now
            < before
                .now
                .saturating_sub(before.uncertainty)
                .saturating_sub(observed.uncertainty)
        || observed.now
            > after
                .now
                .saturating_add(after.uncertainty)
                .saturating_add(observed.uncertainty)
        || !service.live.contains(id)
    {
        return Err(StatusCode::CONFLICT);
    }
    if status.state == ActiveState::Active {
        let evidence = status.evidence.as_ref().ok_or(StatusCode::CONFLICT)?;
        if evidence.phase != ActivePhase::Active
            || evidence.lease_expires_at <= after.now.saturating_add(after.uncertainty)
            || evidence.checked_at > observed.now
            || evidence.binding.operation_deadline_ms
                <= after
                    .now
                    .saturating_add(after.uncertainty)
                    .saturating_mul(1000)
        {
            return Err(StatusCode::CONFLICT);
        }
        issuer
            .installation_journal()
            .renewal_operation(id, &evidence.binding)
            .map_err(|_| StatusCode::CONFLICT)?;
    } else if let Some(evidence) = &status.evidence {
        // Terminal host evidence must still match the authority's retained identity.
        let saved = issuer
            .installation_journal()
            .operation_intent(id)
            .map_err(|_| StatusCode::CONFLICT)?
            .ok_or(StatusCode::CONFLICT)?;
        if evidence.binding.admission != saved.id
            || Some(&evidence.binding.permit_digest) != saved.permit_digest.as_ref()
            || evidence.binding.host_instance != saved.host_instance
        {
            return Err(StatusCode::CONFLICT);
        }
    }
    Ok(status)
}
fn active_evidence(
    status: &ActiveStatus,
    sequence: u64,
) -> Result<&briqyard_api::execution::admission::ActiveOperation, StatusCode> {
    status
        .evidence
        .as_ref()
        .filter(|e| status.state == ActiveState::Active && e.sequence == sequence)
        .ok_or(StatusCode::CONFLICT)
}

pub(super) async fn run(
    service: &Service,
    action: &str,
    body: &[u8],
) -> Result<serde_json::Value, StatusCode> {
    if !service.renewable {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut issuer = service.issuer.lock().await;
    if action == "operation_active" {
        let dto: Id = parse(body)?;
        // No host lookup is inferred from this ID: Service owns one pinned host.
        return value(live(service, &mut issuer, &dto.id).await?);
    }
    if action == "operation_protect" {
        let dto: ProtectOperation = parse(body)?;
        if let Some(old) = issuer
            .installation_journal()
            .renewal_attempt(&dto.id)
            .map_err(|_| StatusCode::CONFLICT)?
            .cloned()
        {
            if old.operation_id != dto.operation_id
                || old.previous_sequence != dto.previous_sequence
                || old.protection_admission != dto.committed.admission
                || old.protection_expires_at_ms != dto.committed.expires_at_ms
            {
                return Err(StatusCode::CONFLICT);
            }
            let receipt = issuer
                .installation_journal()
                .protection_intent(&old.protection_intent)
                .map_err(|_| StatusCode::CONFLICT)?
                .and_then(|p| p.acknowledgement.clone())
                .ok_or(StatusCode::CONFLICT)?;
            return value(receipt);
        }
        let status = live(service, &mut issuer, &dto.operation_id).await?;
        let evidence = active_evidence(&status, dto.previous_sequence)?;
        if dto.committed.expires_at_ms <= evidence.lease_expires_at.saturating_mul(1000) {
            return Err(StatusCode::CONFLICT);
        }
        let existing_protection = issuer
            .installation_journal()
            .protection_by_admission(&dto.committed.admission)
            .map_err(|_| StatusCode::CONFLICT)?
            .map(|(id, p)| (id.to_owned(), p.clone()));
        if let Some((_, p)) = &existing_protection {
            if p.request.installation != evidence.binding.ownership
                || p.request.generation != evidence.binding.ownership_generation
                || p.request.expires_at_ms != dto.committed.expires_at_ms
                || p.resources != evidence.binding.resource_set.resources
                || p.revision != evidence.binding.resource_set.revision
                || p.acknowledgement.is_none()
            {
                return Err(StatusCode::CONFLICT);
            }
        }
        let attempt = RenewalAttempt {
            id: dto.id.clone(),
            operation_id: dto.operation_id,
            previous_sequence: dto.previous_sequence,
            binding: evidence.binding.clone(),
            protection_intent: existing_protection
                .as_ref()
                .map(|(id, _)| id.clone())
                .unwrap_or_else(|| format!("renewal-{}", dto.id)),
            protection_admission: dto.committed.admission.clone(),
            protection_expires_at_ms: dto.committed.expires_at_ms,
            continuation_digest: None,
        };
        let fresh = clock(service.clock.as_ref())?;
        let first = issuer
            .installation_journal()
            .begin_renewal_attempt(attempt.clone(), fresh)
            .map_err(|_| StatusCode::CONFLICT)?;
        if first && existing_protection.is_none() {
            let op = issuer
                .installation_journal()
                .operation_intent(&attempt.operation_id)
                .map_err(|_| StatusCode::CONFLICT)?
                .ok_or(StatusCode::CONFLICT)?
                .clone();
            let owner = issuer
                .installation_journal()
                .delegation_intent(&op.delegation)
                .map_err(|_| StatusCode::CONFLICT)?
                .ok_or(StatusCode::CONFLICT)?
                .ownership
                .clone();
            Installer {
                journal: issuer.installation_journal(),
                host: &service.host,
                host_id: &service.host_id,
            }
            .protect(
                &attempt.protection_intent,
                &owner,
                CommittedIdle {
                    admission: attempt.protection_admission.clone(),
                    expires_at_ms: attempt.protection_expires_at_ms,
                },
                || {
                    clock(service.clock.as_ref())
                        .map_err(|_| crate::execution_install::InstallError::ClockUnavailable)
                },
            )
            .await
            .map_err(install_error)?;
        }
        // Duplicates are status-only, including an uncertain first RPC.
        let receipt = issuer
            .installation_journal()
            .protection_intent(&attempt.protection_intent)
            .map_err(|_| StatusCode::CONFLICT)?
            .and_then(|p| p.acknowledgement.clone())
            .ok_or(StatusCode::CONFLICT)?;
        return value(receipt);
    }
    let dto: Continue = parse(body)?;
    let attempt = issuer
        .installation_journal()
        .renewal_attempt(&dto.id)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    if attempt.operation_id != dto.operation_id
        || attempt.previous_sequence != dto.previous_sequence
    {
        return Err(StatusCode::CONFLICT);
    }
    let status = live(service, &mut issuer, &dto.operation_id).await?;
    let digest = token_digest(&dto.continuation);
    if let Some(saved) = &attempt.continuation_digest {
        if saved != &digest {
            return Err(StatusCode::CONFLICT);
        }
        // Fresh independently live evidence can resolve a lost ACK; never resend.
        let evidence = status.evidence.as_ref().ok_or(StatusCode::CONFLICT)?;
        if status.state != ActiveState::Active
            || evidence.sequence != dto.previous_sequence.saturating_add(1)
        {
            return Err(StatusCode::CONFLICT);
        }
        return value(status);
    }
    let evidence = active_evidence(&status, dto.previous_sequence)?;
    let verified = verify_continuation(
        &dto.continuation,
        &service.trust.borrowed(),
        clock(service.clock.as_ref())?,
        &evidence.binding,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    if verified.claims().exp <= evidence.lease_expires_at
        || verified.claims().previous_sequence != evidence.sequence
    {
        return Err(StatusCode::CONFLICT);
    }
    issuer
        .installation_journal()
        .bind_renewal_delivery(&dto.id, &verified, digest, clock(service.clock.as_ref())?)
        .map_err(|_| StatusCode::CONFLICT)?;
    let before_delivery = clock(service.clock.as_ref())?;
    let ack: ActiveStatus = service
        .host
        .call(
            Route::Continue,
            &ContinueOperation {
                admission: dto.operation_id.clone(),
                continuation: dto.continuation,
            },
        )
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let now = clock(service.clock.as_ref())?;
    let claims = verified.claims();
    let applied = active_evidence(&ack, claims.sequence)?;
    if applied.binding != claims.binding
        || applied.checked_at != claims.checked_at
        || applied.lease_expires_at != claims.exp
        || applied.protection != claims.protection
        || ack.observed_at.uncertainty > 5
        || ack.observed_at.now
            < before_delivery
                .now
                .saturating_sub(before_delivery.uncertainty)
                .saturating_sub(ack.observed_at.uncertainty)
        || ack.observed_at.now
            > now
                .now
                .saturating_add(now.uncertainty)
                .saturating_add(ack.observed_at.uncertainty)
        || claims.exp <= now.now.saturating_add(now.uncertainty)
    {
        return Err(StatusCode::CONFLICT);
    }
    value(ack)
}

/// A provisioned central authorization service may re-enter operation_active,
/// operation_protect and operation_continue. No issuer turn is retained here.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ContinuationError {
    Unconfirmed,
}
pub(crate) trait ContinuationProvider: Send + Sync {
    fn request<'a>(
        &'a self,
        operation_id: &'a str,
        previous_sequence: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), ContinuationError>> + Send + 'a>,
    >;
}

pub(super) async fn drive(service: &Service, operation_id: &str, initial_expiry: u64) {
    let Some(provider) = &service.continuation else {
        return;
    };
    let mut expiry = initial_expiry;
    let mut attempted = std::collections::BTreeSet::new();
    loop {
        let Ok(now) = clock(service.clock.as_ref()) else {
            return;
        };
        let upper = now.now.saturating_add(now.uncertainty);
        if expiry <= upper {
            return;
        }
        let delay = expiry.saturating_sub(upper).saturating_sub(20);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
        let status = {
            let mut issuer = service.issuer.lock().await;
            match live(service, &mut issuer, operation_id).await {
                Ok(status) => status,
                Err(_) => return,
            }
        };
        let Some(evidence) = status
            .evidence
            .filter(|_| status.state == ActiveState::Active)
        else {
            return;
        };
        let Ok(now) = clock(service.clock.as_ref()) else {
            return;
        };
        if evidence
            .lease_expires_at
            .saturating_sub(now.now.saturating_add(now.uncertainty))
            > 20
        {
            expiry = evidence.lease_expires_at;
            continue;
        }
        if !attempted.insert(evidence.sequence) {
            return;
        }
        // Exactly one request for each observed sequence. A timeout, error or lost
        // reply never licenses a second callback, grant, quota debit or dispatch.
        let remaining = evidence
            .lease_expires_at
            .saturating_sub(now.now.saturating_add(now.uncertainty));
        if remaining == 0
            || tokio::time::timeout(
                std::time::Duration::from_secs(remaining),
                provider.request(operation_id, evidence.sequence),
            )
            .await
            .is_err()
        {
            return;
        }
        let status = {
            let mut issuer = service.issuer.lock().await;
            match live(service, &mut issuer, operation_id).await {
                Ok(status) => status,
                Err(_) => return,
            }
        };
        let Some(current) = status
            .evidence
            .filter(|_| status.state == ActiveState::Active)
        else {
            return;
        };
        if current.sequence != evidence.sequence.saturating_add(1)
            || current.lease_expires_at <= evidence.lease_expires_at
        {
            return;
        }
        expiry = current.lease_expires_at;
    }
}
