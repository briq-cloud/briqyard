use super::compaction::{collection_lengths, compact_authority_at_lower_bound};
use super::*;
use serde::Serialize;

pub(in crate::execution) fn transition_projection_target(
    action: sealed::objects::ProjectionAction,
    bind: &sealed::objects::Bind,
) -> Result<sealed::prim::HexDigest, Error> {
    #[derive(Serialize)]
    struct Target<'a> {
        action: sealed::objects::ProjectionAction,
        bind: &'a sealed::objects::Bind,
    }
    if action == sealed::objects::ProjectionAction::Seal {
        return Err(Error::Binding);
    }
    sealed::h(&Target { action, bind }).map_err(|_| Error::Binding)
}

pub(super) fn dimensions(state: &State) -> Result<sealed::objects::Dims, Error> {
    use sealed::prim::Uint;
    let bytes = field_bytes(state)?;
    let native_counts = collection_lengths(state);
    let mut counts = [Uint::new(0).expect("safe zero"); 21];
    for (to, from) in counts.iter_mut().zip(native_counts) {
        *to = Uint::new(from as u64).map_err(|_| Error::Full)?;
    }
    Ok(sealed::objects::Dims {
        bytes: Uint::new(bytes as u64).map_err(|_| Error::Full)?,
        counts,
        fits: bytes as u64 <= MAX_BYTES && native_counts.iter().all(|n| *n <= MAX_RECORDS),
    })
}

pub(super) fn qualified_candidates(
    next: State,
    mut reserve: State,
    clock: Clock,
) -> Result<(State, State), Error> {
    if !near_capacity(&next) && !over_capacity(&reserve) {
        return Ok((next, reserve));
    }
    let (compacted, _) = compact_authority(&next, clock)?;
    compact_reserve(&next, &compacted, &mut reserve)?;
    Ok((compacted, reserve))
}

pub(super) fn compact_reserve(
    next: &State,
    compacted: &State,
    reserve: &mut State,
) -> Result<(), Error> {
    for (id, original) in &next.delegation_intents {
        if !original.request.grant.is_empty()
            && compacted.delegation_intents[id].request.grant.is_empty()
        {
            let reserved = reserve
                .delegation_intents
                .get_mut(id)
                .ok_or(Error::Binding)?;
            reserved.request.grant.clear();
            reserved.request.allocations.clear();
        }
    }
    Ok(())
}
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
    if qualified_lower_bound_ms > MAX_SAFE_INTEGER {
        return Err(Error::Binding);
    }
    let (after, compaction) = compact_authority_at_lower_bound(&state, qualified_lower_bound_ms)?;
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
    if let Some(guarded) = &after.sealed_authority {
        retained.insert("sealed_authority", field_bytes(guarded)?);
    }
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
        bytes_reclaimed: compaction.reclaimed_bytes,
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
