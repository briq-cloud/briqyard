//! Host-only renewable operation control. Source checks arrive only in central
//! signed continuations; gateway possession cannot install policy or extend time.
use super::*;
use access::admission::{ActivePhase, HostOperationPolicy};

fn sample() -> Result<access::clock::ClockSample, StatusCode> {
    access::clock::ClockSample::read().ok_or(StatusCode::SERVICE_UNAVAILABLE)
}
fn observed(sample: &access::clock::ClockSample) -> Result<ClockObservation, StatusCode> {
    let clock = sample.interval().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(ClockObservation {
        now: clock.now,
        uncertainty: clock.uncertainty,
    })
}

pub(super) fn installed_policy(
    journal: &Journal,
    bundle: &BundleRequest,
    delegation: &HostDelegation,
) -> Result<HostOperationPolicy, StatusCode> {
    let policy = journal
        .operation_policy(&access::token_digest(&bundle.grant))
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    if policy.host_instance != journal.instance()
        || policy.ownership != bundle.installation
        || policy.ownership_generation != bundle.generation
        || policy.delegation != bundle.delegation
        || policy.delegation_version != delegation.version
    {
        return Err(StatusCode::CONFLICT);
    }
    Ok(policy)
}

pub(super) async fn policy(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(record): Json<HostOperationPolicy>,
) -> Answer<HostOperationPolicy> {
    let _write = st.admission.write(&request, &st.journal).await?;
    st.authorized_journal(&request)
        .await?
        .install_operation_policy(record.clone(), st.clock()?)
        .map_err(|_| delegation_conflict(DelegationRefusal::PolicyInstall))?;
    Ok(Json(record))
}

pub(super) async fn continue_operation(
    State(st): Channel,
    InstallerRequest(request): InstallerRequest,
    Json(req): Json<ContinueOperation>,
) -> Answer<ActiveStatus> {
    let _write = st.admission.write(&request, &st.journal).await?;
    let mut journal = st.authorized_journal(&request).await?;
    let saved = journal
        .active_operation(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let lease = st
        .active
        .in_context(&req.admission, &request)
        .map_err(|_| StatusCode::CONFLICT)?
        .and_then(|owner| owner.lease())
        .ok_or(StatusCode::CONFLICT)?;
    lease
        .observe(&saved, &sample()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    let verified = access::verify_continuation(
        &req.continuation,
        &st.trust(&st.keys),
        st.clock()?,
        &saved.binding,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    let evidence = journal
        .continue_operation(&verified, st.clock()?)
        .map_err(|_| StatusCode::CONFLICT)?;
    let applied = (|| {
        let fresh = sample()?;
        lease
            .apply_committed(evidence.clone(), &fresh)
            .map_err(|_| StatusCode::CONFLICT)?;
        let fresh = sample()?;
        lease
            .observe(&evidence, &fresh)
            .map_err(|_| StatusCode::CONFLICT)?;
        Ok::<_, StatusCode>(ActiveStatus {
            state: ActiveState::Active,
            observed_at: observed(&fresh)?,
            evidence: Some(evidence),
        })
    })();
    if applied.is_err() {
        // A commit crossing old expiry is retained, but cannot advertise a live
        // renewal or permit another update. No rollback, replay or quota refund.
        lease.end();
        journal
            .end_active_operation(&req.admission)
            .map_err(|_| StatusCode::CONFLICT)?;
    }
    applied.map(Json)
}

pub(super) async fn active(
    State(st): Channel,
    ExecutionRequest(request): ExecutionRequest,
    Json(req): Json<StatusRequest>,
) -> Answer<ActiveStatus> {
    // Initial consumption and active publication hold the read turn through the
    // guest ACK and fsync. Status must not reconcile their intermediate record.
    let _write = st.admission.write(&request, &st.journal).await?;
    let mut journal = st.authorized_journal(&request).await?;
    let fresh = sample()?;
    let mut evidence = journal
        .active_operation(&req.admission)
        .map_err(|_| StatusCode::CONFLICT)?
        .cloned();
    let owner = st
        .active
        .in_context(&req.admission, &request)
        .map_err(|_| StatusCode::CONFLICT)?;
    if request.protected() && evidence.is_some() && owner.is_none() {
        return Err(StatusCode::CONFLICT);
    }
    let lease = owner.as_ref().and_then(|owner| owner.lease());
    let state = match evidence.as_ref() {
        None => ActiveState::Unknown,
        Some(saved)
            if saved.phase == ActivePhase::Active
                && lease
                    .as_ref()
                    .is_some_and(|lease| lease.observe(saved, &fresh).is_ok()) =>
        {
            ActiveState::Active
        }
        Some(saved) => {
            // An exact retained owner may have just collected its terminal frame
            // and be waiting for this journal turn to fsync completion. Only an
            // abandoned owner can be reconciled to unresolved by status.
            if matches!(saved.phase, ActivePhase::Consumed | ActivePhase::Active) && owner.is_none()
            {
                journal
                    .end_active_operation(&req.admission)
                    .map_err(|_| StatusCode::CONFLICT)?;
                evidence = journal
                    .active_operation(&req.admission)
                    .map_err(|_| StatusCode::CONFLICT)?
                    .cloned();
            }
            ActiveState::Terminal
        }
    };
    // A fresh sample after any terminal fsync never changes checked_at or sequence.
    let fresh = sample()?;
    if state == ActiveState::Active {
        let saved = evidence.as_ref().ok_or(StatusCode::CONFLICT)?;
        lease
            .ok_or(StatusCode::CONFLICT)?
            .observe(saved, &fresh)
            .map_err(|_| StatusCode::CONFLICT)?;
    }
    Ok(Json(ActiveStatus {
        state,
        observed_at: observed(&fresh)?,
        evidence,
    }))
}
