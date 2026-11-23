use crate::guestc::{active_lease::ActiveLease, active_operations::ActiveOperations};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::execution::{
    self as access,
    admission::{
        ActiveOperation, HostDelegation, HostOperationPolicy, HostOwnership, HostRegistration,
        InstalledProtection, Journal, PreparedAdmission, Role,
    },
    clock::ClockSample,
    ActiveOperationBinding, Clock, DispatchContext, ExecutionMode, Grant, Permit, PublicResource,
    Trust, VerificationKey,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{sync::Arc, time::Duration};

pub(crate) const CLOCK: Clock = Clock {
    now: 1010,
    uncertainty: 1,
};
pub(crate) const HOST: &str = "host-1";
pub(crate) const EXECUTION: &[u8] = b"synthetic execution";

pub(crate) fn sample() -> ClockSample {
    ClockSample {
        wall: Duration::from_secs(CLOCK.now),
        monotonic: std::time::Instant::now(),
        uncertainty: Duration::from_secs(CLOCK.uncertainty),
    }
}

pub(crate) fn sign(body: &impl serde::Serialize, typ: &str, seed: u8, kid: &str) -> String {
    let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let header = serde_json::json!({"alg":"EdDSA","typ":typ,"kid":kid,"v":1});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(body).unwrap())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).as_ref())
    )
}

pub(crate) struct Fixture {
    pub(crate) journal: Journal,
    pub(crate) registration: HostRegistration,
    pub(crate) intent: PreparedAdmission,
    pub(crate) permit: Permit,
    pub(crate) active: ActiveOperation,
}

pub(crate) fn active_operation(path: &std::path::Path) -> Fixture {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../briqyard-api/tests/fixtures/execution-v1.json"
    ))
    .unwrap();
    let mut grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
    grant.limits.execution_mode = Some(ExecutionMode::RenewableExecV1);
    let grant_token = sign(&grant, access::GRANT_TYPE, 1, "central-test");
    let mut permit: Permit = serde_json::from_value(fixture["permit"].clone()).unwrap();
    permit.limits = grant.limits.clone();
    permit.grant_digest = access::token_digest(&grant_token);
    permit.allocations.clear();
    let allocations = [("general", "requests"), ("calls", "exec_calls")].map(|(id, bucket)| {
        let mut allocation: access::Allocation =
            serde_json::from_value(fixture["allocation"].clone()).unwrap();
        allocation.id = id.into();
        allocation.bucket = bucket.into();
        let token = sign(&allocation, access::ALLOCATION_TYPE, 1, "central-test");
        permit.allocations.push(access::AllocationRef {
            id: allocation.id,
            epoch: allocation.epoch,
            digest: access::token_digest(&token),
            units: 1,
        });
        token
    });
    let permit_token = sign(&permit, access::PERMIT_TYPE, 2, "authority-test");
    let keys = [
        (1, "central-test", access::KeyRole::Central, "central", None),
        (
            2,
            "authority-test",
            access::KeyRole::Authority,
            "authority",
            Some("authority-1".into()),
        ),
    ]
    .map(|(seed, kid, role, issuer, authority)| VerificationKey {
        kid: kid.into(),
        role,
        issuer: issuer.into(),
        authority,
        public_key: Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
            .unwrap()
            .public_key()
            .as_ref()
            .try_into()
            .unwrap(),
    });
    let bundle = access::verify_bundle(
        &grant_token,
        &permit_token,
        &allocations.each_ref().map(String::as_str),
        &Trust {
            keys: &keys,
            central_issuer: "central",
            authority_issuer: "authority",
            audience: "runtime",
        },
        CLOCK,
        &DispatchContext {
            principal: &grant.principal,
            team: &grant.team,
            subject: &grant.subject,
            target: &grant.target,
            resource_set: &grant.resource_set,
            metadata_revision: &grant.metadata_revision,
            authority: &permit.authority,
            authority_epoch: &permit.authority_epoch,
            installed_allocations: &permit.allocations,
            operation: permit.operation,
            request_digest: &permit.request_digest,
        },
    )
    .unwrap();
    let mut journal = Journal::open(path, Role::Host(HOST.into())).unwrap();
    let instance = journal.instance().to_owned();
    let registration = HostRegistration {
        authority: permit.authority.clone(),
        epoch: permit.authority_epoch.clone(),
        key_id: keys[1].kid.clone(),
        public_key: keys[1].public_key,
        host_instance: instance.clone(),
        generation: 1,
    };
    journal.register_host(registration.clone(), CLOCK).unwrap();
    let owner = HostOwnership {
        installation: "owner".into(),
        generation: 1,
        team: grant.team.clone(),
        subject: grant.subject.clone(),
        metadata_revision: grant.metadata_revision.clone(),
        primary: grant.target.clone(),
        public_seeds: vec![grant.target.clone()],
        public_resources: vec![PublicResource {
            id: grant.subject.clone(),
            target: grant.target.clone(),
        }],
        resource_set: grant.resource_set.clone(),
        host_instance: instance.clone(),
    };
    journal.install_ownership(owner.clone(), CLOCK).unwrap();
    let delegation = HostDelegation {
        id: "delegation".into(),
        version: 1,
        ownership: owner.installation.clone(),
        ownership_generation: owner.generation,
        grant_digest: permit.grant_digest.clone(),
        allocation_digests: permit
            .allocations
            .iter()
            .map(|r| r.digest.clone())
            .collect(),
        principal: grant.principal.clone(),
        expires_at: grant.exp,
    };
    journal
        .install_delegation(delegation.clone(), CLOCK)
        .unwrap();
    let policy = HostOperationPolicy {
        host_instance: instance.clone(),
        ownership: owner.installation.clone(),
        ownership_generation: owner.generation,
        delegation: delegation.id.clone(),
        delegation_version: delegation.version,
        grant_digest: permit.grant_digest.clone(),
        policy_revision: "policy".into(),
    };
    journal
        .install_operation_policy(policy.clone(), CLOCK)
        .unwrap();
    let protection = InstalledProtection {
        installation: owner.installation.clone(),
        generation: owner.generation,
        admission: grant.idle.admission.clone(),
        expires_at_ms: grant.idle.expires_at * 1000,
        resources: grant.resource_set.resources.clone(),
        resource_revision: grant.resource_set.revision.clone(),
    };
    journal
        .record_protection(protection.clone(), CLOCK)
        .unwrap();
    let mut intent = PreparedAdmission {
        admission: permit.admission.clone(),
        delegation: delegation.id,
        grant_digest: permit.grant_digest.clone(),
        permit_digest: access::token_digest(&permit_token),
        request_digest: permit.request_digest.clone(),
        allocation_refs: permit.allocations.clone(),
        ownership: owner.installation,
        ownership_generation: owner.generation,
        host_instance: instance.clone(),
        expires_at: permit.exp,
        dispatched: false,
    };
    journal.install(&bundle, &instance, CLOCK).unwrap();
    journal.prepare(intent.clone(), CLOCK).unwrap();
    journal.mark_dispatched(&intent.admission, CLOCK).unwrap();
    intent.dispatched = true;
    journal.consume(&bundle, CLOCK).unwrap();
    let binding = ActiveOperationBinding {
        operation_id: permit.admission.clone(),
        admission: permit.admission.clone(),
        grant_digest: permit.grant_digest.clone(),
        permit_digest: intent.permit_digest.clone(),
        request_digest: permit.request_digest.clone(),
        authority: permit.authority.clone(),
        authority_epoch: permit.authority_epoch.clone(),
        host_instance: instance,
        ownership: intent.ownership.clone(),
        ownership_generation: intent.ownership_generation,
        policy_revision: policy.policy_revision,
        delegation: intent.delegation.clone(),
        delegation_version: delegation.version,
        principal: grant.principal,
        source: grant.source,
        team: grant.team,
        subject: grant.subject,
        metadata_revision: grant.metadata_revision,
        target: grant.target,
        resource_set: grant.resource_set,
        limits: permit.limits.clone(),
        guest_timeout_ms: 1_000,
        started_at_ms: CLOCK.now * 1000,
        operation_deadline_ms: CLOCK.now * 1000 + access::MAX_OPERATION_MILLIS,
    };
    journal
        .record_consumed_operation(&bundle, binding, protection, CLOCK)
        .unwrap();
    let active = journal
        .acknowledge_active_operation(&intent.admission, CLOCK)
        .unwrap();
    Fixture {
        journal,
        registration,
        intent,
        permit,
        active,
    }
}

pub(crate) fn reserve_ordinary(
    registry: &Arc<ActiveOperations>,
    admission: &str,
    active: &ActiveOperation,
) -> (
    crate::guestc::active_operations::ActiveOperationGuard,
    ActiveLease,
) {
    let lease = ActiveLease::from_committed(active.clone(), &sample()).unwrap();
    let owner = registry.register(admission, lease.clone()).unwrap();
    (owner, lease)
}
