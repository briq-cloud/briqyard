use super::compaction::collection_lengths;
use super::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CollectionProjection {
    pub before: usize,
    pub after: usize,
}

#[derive(Debug, Serialize)]
pub struct CapacityProjection {
    pub qualified_lower_bound_ms: u64,
    pub bytes_before: usize,
    pub bytes_after: usize,
    pub bytes_reclaimed: usize,
    pub fits_capacity: bool,
    pub collections: BTreeMap<&'static str, CollectionProjection>,
    pub retained_bytes: BTreeMap<&'static str, usize>,
}

pub fn project(path: &Path, qualified_lower_bound_ms: u64) -> Result<CapacityProjection, Error> {
    let (state, bytes_before) = read_state_size(path)?.ok_or(Error::Binding)?;
    if !matches!(state.role, Role::Authority(_)) {
        return Err(Error::Binding);
    }
    let now = (qualified_lower_bound_ms / 1000)
        .checked_add(1)
        .ok_or(Error::Binding)?;
    let (after, _) = compact_authority(
        &state,
        Clock {
            now,
            uncertainty: 1,
        },
    )?;
    let mut without_credentials = State::clone(&after);
    for intent in without_credentials.delegation_intents.values_mut() {
        intent.request.grant.clear();
        intent.request.allocations.clear();
    }
    let encoded = |state: &State| {
        serde_json::to_vec(state)
            .map(|bytes| bytes.len())
            .map_err(|_| Error::Persistence)
    };
    let bytes_after = encoded(&after)?;
    let mut retained = BTreeMap::from([
        (
            "delegation_credentials",
            bytes_after - encoded(&without_credentials)?,
        ),
        (
            "delegation_intents",
            field_bytes(&without_credentials.delegation_intents)?,
        ),
        ("allocations", field_bytes(&after.allocations)?),
        ("fences", field_bytes(&after.fences)?),
        ("retired_epochs", field_bytes(&after.retired)?),
        ("admissions", field_bytes(&after.admissions)?),
        (
            "registration",
            field_bytes(&after.registration)? + field_bytes(&after.registration_highwater)?,
        ),
        (
            "ownership_highwater",
            field_bytes(&after.ownership_highwater)?,
        ),
        ("delegations", field_bytes(&after.delegations)?),
        (
            "delegation_versions",
            field_bytes(&after.delegation_versions)?,
        ),
        (
            "delegation_tombstones",
            field_bytes(&after.delegation_tombstones)?,
        ),
        ("ownership", field_bytes(&after.ownership)?),
        ("prepared", field_bytes(&after.prepared)?),
        ("protections", field_bytes(&after.protections)?),
        ("authority_intents", field_bytes(&after.authority_intents)?),
        (
            "authority_highwater",
            field_bytes(&after.authority_highwater)?,
        ),
        ("discovery_intents", field_bytes(&after.discovery_intents)?),
        (
            "protection_intents",
            field_bytes(&after.protection_intents)?,
        ),
        ("operation_intents", field_bytes(&after.operation_intents)?),
        (
            "uncertain_installations",
            field_bytes(&after.uncertain_installations)?,
        ),
        ("active_operations", field_bytes(&after.active_operations)?),
        (
            "operation_policies",
            field_bytes(&after.operation_policies)?,
        ),
        ("renewal_attempts", field_bytes(&after.renewal_attempts)?),
        (
            "identity_metadata",
            field_bytes(&state.v)?
                + field_bytes(&after.role)?
                + field_bytes(&after.instance)?
                + field_bytes(&after.clock_floor)?,
        ),
    ]);
    let category_bytes = retained.values().sum::<usize>();
    retained.insert("document_overhead", bytes_after - category_bytes);
    let collection_names = [
        "allocations",
        "fences",
        "retired_epochs",
        "admissions",
        "ownership",
        "ownership_highwater",
        "delegations",
        "delegation_versions",
        "delegation_tombstones",
        "prepared",
        "protections",
        "authority_intents",
        "authority_highwater",
        "discovery_intents",
        "protection_intents",
        "delegation_intents",
        "operation_intents",
        "uncertain_installations",
        "active_operations",
        "operation_policies",
        "renewal_attempts",
    ];
    let before = collection_lengths(&state);
    let after_counts = collection_lengths(&after);
    let collections = collection_names
        .into_iter()
        .zip(before.into_iter().zip(after_counts))
        .map(|(name, (before, after))| (name, CollectionProjection { before, after }))
        .collect();
    Ok(CapacityProjection {
        qualified_lower_bound_ms,
        bytes_before,
        bytes_after,
        bytes_reclaimed: bytes_before.saturating_sub(bytes_after),
        fits_capacity: !over_capacity(&after),
        collections,
        retained_bytes: retained,
    })
}

fn field_bytes(value: &impl Serialize) -> Result<usize, Error> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| Error::Persistence)
}

#[cfg(test)]
#[path = "capacity_tests.rs"]
mod tests;
