//! Retirement of authority evidence that no reader can use again (ADR 0149). It only
//! removes map entries, so the result is still a v1 state every earlier runtime opens.
//!
//! A record is removed only when every reader of it already refuses through an expiry,
//! a superseded registration or the host's own fence, and every record a retained record
//! references is retained. Records with an expiry retire by time; records without one
//! retire only once the host's registration generation moved past theirs.
use super::compaction::allocation_expired;
use super::*;

/// How long a record outlives the last expiry it carries: a handler still in flight or a
/// late status read finds it. Safety rests on the expiries, not on this margin.
pub(super) const RETENTION_SECONDS: u64 = 3_600;

/// Returns the retired state and the number of removed records. `earliest_ms` is the
/// qualified lower bound of the committing action's clock.
pub(super) fn retire(state: &State, earliest_ms: u64) -> (State, usize) {
    if !matches!(state.role, Role::Authority(_)) {
        return (State::clone(state), 0);
    }
    let horizon = earliest_ms.saturating_sub(RETENTION_SECONDS * 1000);
    let live = |seconds: u64| seconds > MAX_SAFE_INTEGER || seconds * 1000 > horizon;

    // Records with an expiry. An operation's anchor is its permit and its renewals.
    let operations: BTreeSet<&String> = state
        .operation_intents
        .iter()
        .filter(|(id, op)| {
            live(op.permit.exp)
                || state.renewal_attempts.values().any(|attempt| {
                    attempt.operation_id == **id && attempt.protection_expires_at_ms > horizon
                })
        })
        .map(|(id, _)| id)
        .collect();
    let renewals: BTreeMap<&String, &RenewalAttempt> = state
        .renewal_attempts
        .iter()
        .filter(|(_, attempt)| operations.contains(&attempt.operation_id))
        .collect();
    let used_delegations: BTreeSet<&str> = operations
        .iter()
        .map(|id| state.operation_intents[*id].delegation.as_str())
        .collect();
    let renewed_grants: BTreeSet<&str> = renewals
        .values()
        .map(|attempt| attempt.binding.grant_digest.as_str())
        .collect();
    let mut delegations: BTreeMap<&String, &DelegationIntent> = state
        .delegation_intents
        .iter()
        .filter(|(id, d)| {
            used_delegations.contains(id.as_str())
                || renewed_grants.contains(d.expected.grant_digest.as_str())
                || live(d.expected.expires_at)
                || d.trusted_source
                    .as_ref()
                    .is_some_and(|s| live(s.expires_at))
                || d.request.protection_expires_at_ms > horizon
                || !d
                    .request
                    .allocations
                    .iter()
                    .all(|token| allocation_expired(token, horizon))
        })
        .collect();
    // Readiness refuses an older version only while a newer one of its ID exists, so the
    // newest version of every retained ID stays as its supersession evidence.
    let kept_ids: BTreeSet<&str> = delegations
        .values()
        .map(|d| d.request.id.as_str())
        .collect();
    for id in kept_ids {
        if let Some((key, newest)) = state
            .delegation_intents
            .iter()
            .filter(|(_, d)| d.request.id == id)
            .max_by_key(|(_, d)| d.request.version)
        {
            delegations.insert(key, newest);
        }
    }
    let used_protections: BTreeSet<&str> = delegations
        .values()
        .map(|d| d.protection.as_str())
        .chain(renewals.values().map(|a| a.protection_intent.as_str()))
        .collect();
    let protections: BTreeMap<&String, &ProtectionIntent> = state
        .protection_intents
        .iter()
        .filter(|(id, p)| {
            used_protections.contains(id.as_str()) || p.request.expires_at_ms > horizon
        })
        .collect();

    // Records without an expiry. The registration generation of their host is the frontier.
    let current = |host: &str| {
        state
            .authority_highwater
            .get(&format!("registration:{host}"))
    };
    let superseded = |host: &str, generation: u64| current(host).is_some_and(|g| *g > generation);
    let registration_generation = |id: &str| match state.authority_intents.get(id) {
        Some(AuthorityIntent {
            payload: AuthorityPayload::Registration(r),
            ..
        }) => Some(r.generation),
        _ => None,
    };
    let current_registrations: BTreeMap<&str, &AuthorityIntent> = state
        .authority_intents
        .values()
        .filter(|intent| {
            matches!(&intent.payload, AuthorityPayload::Registration(r)
                if current(&intent.host) == Some(&r.generation))
        })
        .map(|intent| (intent.host.as_str(), intent))
        .collect();
    // A record without a registration generation (an invalidation, a revocation, a legacy
    // ownership) is older than a current registration of this epoch whose host instance or
    // epoch differs from its own. Before this epoch's registration, nothing is.
    let before_registration = |intent: &AuthorityIntent| {
        current_registrations
            .get(intent.host.as_str())
            .is_some_and(|r| {
                r.authority_epoch == state.instance
                    && (r.host_instance != intent.host_instance
                        || r.authority_epoch != intent.authority_epoch)
            })
    };
    let used_ownerships: BTreeSet<&str> = delegations
        .values()
        .map(|d| d.ownership.as_str())
        .chain(protections.values().map(|p| p.ownership.as_str()))
        .collect();
    let ownerships: BTreeSet<&String> = state
        .authority_intents
        .iter()
        .filter(|(id, intent)| {
            matches!(intent.payload, AuthorityPayload::Ownership(_))
                && (used_ownerships.contains(id.as_str())
                    || match &intent.registration_dependency {
                        Some(d) => !superseded(&intent.host, d.generation),
                        None => !before_registration(intent),
                    })
        })
        .map(|(id, _)| id)
        .collect();
    let used_discoveries: BTreeSet<&str> = ownerships
        .iter()
        .filter_map(|id| state.authority_intents[*id].discovery_dependency.as_deref())
        .collect();
    let discoveries: BTreeMap<&String, &DiscoveryIntent> = state
        .discovery_intents
        .iter()
        .filter(|(id, discovery)| {
            used_discoveries.contains(id.as_str())
                || registration_generation(&discovery.registration)
                    .is_some_and(|g| !superseded(&discovery.host, g))
        })
        .collect();
    let used_registrations: BTreeSet<&str> = ownerships
        .iter()
        .filter_map(|id| {
            state.authority_intents[*id]
                .registration_dependency
                .as_ref()
        })
        .map(|d| d.intent.as_str())
        .chain(discoveries.values().map(|d| d.registration.as_str()))
        .chain(delegations.values().map(|d| d.registration.as_str()))
        .collect();
    let installations: BTreeSet<&str> = ownerships
        .iter()
        .filter_map(|id| match &state.authority_intents[*id].payload {
            AuthorityPayload::Ownership(owner) => Some(owner.installation.as_str()),
            _ => None,
        })
        .chain(
            discoveries
                .values()
                .map(|d| d.control.installation.as_str()),
        )
        .chain(
            protections
                .values()
                .map(|p| p.request.installation.as_str()),
        )
        .chain(
            delegations
                .values()
                .map(|d| d.request.installation.as_str()),
        )
        .collect();
    let delegation_ids: BTreeSet<&str> = delegations
        .values()
        .map(|d| d.request.id.as_str())
        .collect();
    let authority: BTreeSet<&String> = state
        .authority_intents
        .iter()
        .filter(|(id, intent)| match &intent.payload {
            AuthorityPayload::Ownership(_) => ownerships.contains(id),
            AuthorityPayload::Registration(r) => {
                !superseded(&intent.host, r.generation) || used_registrations.contains(id.as_str())
            }
            AuthorityPayload::Invalidate { installation, .. } => {
                !before_registration(intent) || installations.contains(installation.as_str())
            }
            AuthorityPayload::Revoke { id: revoked, .. } => {
                !before_registration(intent) || delegation_ids.contains(revoked.as_str())
            }
        })
        .map(|(id, _)| id)
        .collect();
    let fences: BTreeSet<String> = authority
        .iter()
        .map(|id| state.authority_intents[*id].payload.fence().0)
        .collect();

    let mut next = State::clone(state);
    next.operation_intents
        .retain(|id, _| operations.contains(id));
    next.renewal_attempts
        .retain(|id, _| renewals.contains_key(id));
    next.admissions
        .retain(|id, a| operations.contains(id) || live(a.permit.exp));
    next.allocations.retain(|_, a| live(a.allocation.exp));
    next.delegation_intents
        .retain(|id, _| delegations.contains_key(id));
    next.protection_intents
        .retain(|id, _| protections.contains_key(id));
    next.discovery_intents
        .retain(|id, _| discoveries.contains_key(id));
    next.authority_intents
        .retain(|id, _| authority.contains(id));
    next.authority_highwater.retain(|key, _| {
        if let Some(installation) = key.strip_prefix("ownership:") {
            fences.contains(key) || installations.contains(installation)
        } else if let Some(delegation) = key.strip_prefix("delegation:") {
            fences.contains(key) || delegation_ids.contains(delegation)
        } else {
            true
        }
    });
    next.uncertain_installations
        .retain(|marker| match marker.split_once(':') {
            Some(("authority", id)) => next.authority_intents.contains_key(id),
            Some(("discovery", id)) => next.discovery_intents.contains_key(id),
            Some(("protection", id)) => next.protection_intents.contains_key(id),
            Some(("delegation", id)) => next.delegation_intents.contains_key(id),
            _ => true,
        });
    let removed = records(state) - records(&next);
    (next, removed)
}

fn records(state: &State) -> usize {
    state.operation_intents.len()
        + state.renewal_attempts.len()
        + state.admissions.len()
        + state.allocations.len()
        + state.delegation_intents.len()
        + state.protection_intents.len()
        + state.discovery_intents.len()
        + state.authority_intents.len()
        + state.authority_highwater.len()
        + state.uncertain_installations.len()
}

#[cfg(test)]
#[path = "retirement_tests.rs"]
mod tests;
