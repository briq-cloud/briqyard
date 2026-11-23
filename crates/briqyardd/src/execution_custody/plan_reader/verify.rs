//! The pair check. Trust comes only from the root-private record; the local Plan, supplied by
//! the operation owner's own record, is checked against it as a consistency check and never
//! establishes it.

use super::trust::EnrolledTrust;
use super::PlanReadError;
use briqyard_api::execution::sealed::{
    canonical::decode,
    plan_pin::{LocalPlan, Pin, Read, ReadPair},
    sig::Tag,
};

fn refuse<T>(why: &'static str) -> Result<T, PlanReadError> {
    Err(PlanReadError::Proof(why))
}

/// Accept the reply only if it is the exact canonical pair for the one outstanding `request`,
/// both observers signed the same body under their enrolled keys, and the pin is this
/// operation's local Plan. Returns the verified pin.
pub(super) fn verify_pair(
    reply: &[u8],
    request: &Read,
    local: &LocalPlan,
    trust: &EnrolledTrust,
) -> Result<Pin, PlanReadError> {
    let plan = local.plan();
    let record = trust.record();
    if record.x != plan.x || record.registered != plan.registered {
        return refuse("trust record is not this operation's");
    }
    if plan.rk != record.rk || plan.bk != record.bk {
        return refuse("local Plan keys differ from the enrolled keys");
    }
    if request.x != plan.x || request.registered != plan.registered {
        return refuse("request is not this operation's");
    }
    let pair: ReadPair =
        decode(reply).map_err(|_| PlanReadError::Proof("pair is not canonical"))?;
    if pair.receiver.kid == pair.api.kid {
        return refuse("observers share a key");
    }
    let receiver = pair
        .receiver
        .verify(Tag::PlanReadReceiver, trust.rk())
        .map_err(|_| PlanReadError::Proof("receiver proof does not verify"))?;
    let api = pair
        .api
        .verify(Tag::PlanReadApi, trust.bk())
        .map_err(|_| PlanReadError::Proof("api proof does not verify"))?;
    if receiver != api {
        return refuse("observers signed different bodies");
    }
    if receiver.read != *request {
        return refuse("read echo is not the outstanding request");
    }
    if receiver.pin.x != plan.x || receiver.pin.registered != plan.registered {
        return refuse("pin scope is not this operation's");
    }
    if receiver.pin.plan != *local.digest() {
        return refuse("pin is not this operation's Plan");
    }
    if receiver.pin != local.pin() {
        return refuse("pin differs from the local commitment");
    }
    Ok(receiver.pin.clone())
}
