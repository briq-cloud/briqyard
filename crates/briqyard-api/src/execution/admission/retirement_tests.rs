use super::*;
use crate::execution::{
    channel::{InstallDelegation, Protect, ProtectionAck},
    DiscoveryReceipt, Limits, Operation, PublicResource, PublicSeed, ResourceSet, Source,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

fn at(now: u64) -> Clock {
    Clock {
        now,
        uncertainty: 1,
    }
}

fn target(machine: &str) -> Target {
    Target {
        host: "host".into(),
        machine: machine.into(),
        namespace: "team".into(),
        run: format!("run-{machine}"),
        placement: "version-1".into(),
    }
}

/// About the size of a signed grant or allocation.
fn token(exp: u64) -> String {
    let pad = "x".repeat(2_000);
    let body = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp},"pad":"{pad}"}}"#));
    format!("header.{body}.signature")
}

fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn open(path: &Path) -> Journal {
    Journal::open(path, Role::Authority("region".into())).unwrap()
}

/// Each generation registers a new host instance, as a host restart does.
fn instance(generation: u64) -> String {
    format!("host-run-{generation}")
}

fn register(journal: &mut Journal, generation: u64, now: u64) {
    let instance = instance(generation);
    let record = HostRegistration {
        authority: "region".into(),
        epoch: journal.instance().into(),
        key_id: "key".into(),
        public_key: [1; 32],
        host_instance: instance.clone(),
        generation,
    };
    let id = format!("registration-{generation}");
    let payload = AuthorityPayload::Registration(record);
    journal
        .begin_authority_intent(&id, "host", &instance, payload.clone(), at(now))
        .unwrap();
    journal
        .acknowledge_authority_intent(&id, payload.expected_ack(&instance).unwrap(), at(now))
        .unwrap();
}

/// Discovery, ownership, protection, delegation and one operation, all at `now`, as a
/// regional installation does. The operation stops at dispatch unless `finish`.
fn install(journal: &mut Journal, generation: u64, i: u64, now: u64, finish: bool) {
    let clock = at(now);
    let registration = &format!("registration-{generation}");
    let instance = instance(generation);
    let installation = format!("install-{i}");
    let control = OwnershipControl {
        require_renewable: false,
        host_instance: instance.clone(),
        installation: installation.clone(),
        generation: 1,
        team: "team".into(),
        primary_id: "public-a".into(),
        seeds: vec![PublicSeed {
            id: "public-a".into(),
            machine: "a".into(),
            namespace: "team".into(),
            team: "team".into(),
            expected_version: Some(1),
        }],
        metadata_revision: "metadata-1".into(),
    };
    let receipt = DiscoveryReceipt {
        host_instance: instance.clone(),
        primary: target("a"),
        public_seeds: vec![target("a")],
        public_resources: vec![PublicResource {
            id: "public-a".into(),
            target: target("a"),
        }],
        resource_set: ResourceSet {
            revision: "revision-1".into(),
            resources: vec![target("a"), target("gateway")],
        },
    };
    let discovery = format!("discovery-{i}");
    journal
        .begin_discovery_intent(&discovery, "host", registration, control, clock)
        .unwrap();
    journal
        .acknowledge_discovery_intent(&discovery, receipt.clone(), clock)
        .unwrap();
    let owner = HostOwnership {
        installation: installation.clone(),
        generation: 1,
        team: "team".into(),
        subject: "public-a".into(),
        metadata_revision: "metadata-1".into(),
        primary: receipt.primary.clone(),
        public_seeds: receipt.public_seeds.clone(),
        public_resources: receipt.public_resources.clone(),
        resource_set: receipt.resource_set.clone(),
        host_instance: instance.clone(),
    };
    let ownership = format!("ownership-{i}");
    let payload = AuthorityPayload::Ownership(Box::new(owner.clone()));
    journal
        .begin_authority_intent(&ownership, "host", &instance, payload.clone(), clock)
        .unwrap();
    journal
        .acknowledge_authority_intent(&ownership, payload.expected_ack(&instance).unwrap(), clock)
        .unwrap();
    let protection = format!("protection-{i}");
    let request = Protect {
        installation: installation.clone(),
        generation: 1,
        admission: format!("idle-{i}"),
        expires_at_ms: (now + 50) * 1000,
    };
    journal
        .begin_protection_intent(&protection, "host", &ownership, request.clone(), clock)
        .unwrap();
    journal
        .acknowledge_protection_intent(
            &protection,
            ProtectionAck {
                admission: request.admission.clone(),
                expires_at_ms: request.expires_at_ms,
                resources: receipt.resource_set.resources.clone(),
                revision: receipt.resource_set.revision.clone(),
            },
            clock,
        )
        .unwrap();
    let grant = token(now + 40);
    let allocation = token(now + 45);
    let expected = HostDelegation {
        id: format!("grant-{i}"),
        version: 1,
        ownership: installation.clone(),
        ownership_generation: 1,
        grant_digest: digest(&grant),
        allocation_digests: vec![digest(&allocation)],
        principal: "principal".into(),
        expires_at: now + 40,
    };
    let delegation = format!("delegation-{i}");
    journal
        .begin_delegation_intent(
            &delegation,
            DelegationIntent {
                host: "host".into(),
                authority_epoch: journal.instance().into(),
                registration: registration.into(),
                ownership: ownership.clone(),
                protection: protection.clone(),
                trusted_source: Some(Source {
                    kind: "source".into(),
                    id: format!("source-{i}"),
                    expires_at: now + 50,
                }),
                projection: Some(Projection::new(b"projection".to_vec()).unwrap()),
                policy_revision: Some("policy".into()),
                request: InstallDelegation {
                    installation: installation.clone(),
                    generation: 1,
                    id: expected.id.clone(),
                    version: 1,
                    principal: "principal".into(),
                    grant,
                    allocations: vec![allocation],
                    protection_expires_at_ms: request.expires_at_ms,
                },
                expected: expected.clone(),
                acknowledgement: None,
                operation_policy: None,
                operation_policy_ack: None,
            },
            clock,
        )
        .unwrap();
    journal
        .acknowledge_delegation_intent(&delegation, expected.clone(), clock)
        .unwrap();
    let operation = format!("operation-{i}");
    let permit = Permit {
        v: 1,
        iss: "issuer".into(),
        aud: "audience".into(),
        iat: now - 1,
        nbf: now - 1,
        exp: now + 30,
        admission: operation.clone(),
        authority: "region".into(),
        authority_epoch: journal.instance().into(),
        grant_digest: expected.grant_digest.clone(),
        allocations: Vec::new(),
        target: owner.primary.clone(),
        operation: Operation::Exec,
        request_digest: "request".into(),
        metadata_revision: "metadata-1".into(),
        limits: Limits {
            execution_mode: None,
            max_duration_seconds: 20,
            max_input_bytes: 1024,
            output_mode: None,
            max_output_bytes: 4096,
        },
    };
    journal
        .begin_operation(
            OperationIntent {
                id: operation.clone(),
                delegation: delegation.clone(),
                authority_epoch: journal.instance().into(),
                host: "host".into(),
                host_instance: instance.clone(),
                request_digest: "request".into(),
                permit: permit.clone(),
                phase: OperationPhase::Intent,
                permit_digest: None,
                prepared: None,
                outcome_digest: None,
                unconfirmed: false,
            },
            clock,
        )
        .unwrap();
    // The authority's reserve needs a signed bundle; record its admission directly.
    Arc::make_mut(&mut journal.view.state).admissions.insert(
        operation.clone(),
        Admission {
            permit,
            status: Status::Reserved,
        },
    );
    journal
        .bind_operation_permit(&operation, "permit".into(), clock)
        .unwrap();
    journal
        .acknowledge_operation_prepare(
            &operation,
            PreparedAdmission {
                admission: operation.clone(),
                delegation: expected.id.clone(),
                grant_digest: expected.grant_digest.clone(),
                permit_digest: "permit".into(),
                request_digest: "request".into(),
                allocation_refs: Vec::new(),
                ownership: installation.clone(),
                ownership_generation: 1,
                host_instance: instance.clone(),
                expires_at: now + 30,
                dispatched: false,
            },
            clock,
        )
        .unwrap();
    journal.mark_operation_dispatch(&operation, clock).unwrap();
    if finish {
        finish_operation(journal, i, clock);
    }
}

fn finish_operation(journal: &mut Journal, i: u64, clock: Clock) {
    let operation = format!("operation-{i}");
    journal
        .record_operation_evidence(&operation, OperationPhase::Consumed, None, clock)
        .unwrap();
    journal
        .record_operation_evidence(
            &operation,
            OperationPhase::Finished,
            Some("outcome".into()),
            clock,
        )
        .unwrap();
}

/// Revocation of the grant and invalidation of the installation, both confirmed.
fn remove(journal: &mut Journal, generation: u64, i: u64, now: u64) {
    let instance = instance(generation);
    for (id, payload) in [
        (
            format!("revoke-{i}"),
            AuthorityPayload::Revoke {
                id: format!("grant-{i}"),
                version: 1,
            },
        ),
        (
            format!("invalidate-{i}"),
            AuthorityPayload::Invalidate {
                installation: format!("install-{i}"),
                generation: 2,
            },
        ),
    ] {
        journal
            .begin_authority_intent(&id, "host", &instance, payload, at(now))
            .unwrap();
        journal
            .confirm_authority_instance(&id, &instance, at(now))
            .unwrap();
    }
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path.join("journal.json")).unwrap().len()
}

/// Installs and removes `cycles` installations `spacing` seconds apart, rolling the host
/// registration every `generation` cycles as a restart does. Returns the largest file.
fn run_cycles(
    path: &Path,
    journal: &mut Journal,
    cycles: u64,
    spacing: u64,
    generation: u64,
) -> u64 {
    let mut largest = 0;
    for i in 0..cycles {
        let now = 10_000 + i * spacing;
        let registration = i / generation + 1;
        if i % generation == 0 {
            register(journal, registration, now);
        }
        install(journal, registration, i, now, true);
        remove(journal, registration, i, now + 60);
        largest = largest.max(file_size(path));
    }
    largest
}

#[test]
fn install_and_revoke_cycles_stay_under_a_fixed_bound() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    let largest = run_cycles(&path, &mut journal, 1_000, RETENTION_SECONDS + 100, 10);
    assert!(largest <= 48 * 1024, "{largest} bytes");
    let state = &journal.state;
    assert!(state.operation_intents.len() <= 1);
    assert!(state.admissions.len() <= 1);
    assert!(state.delegation_intents.len() <= 1);
    assert!(state.protection_intents.len() <= 1);
    assert!(state.discovery_intents.len() <= 10);
    assert!(state.authority_intents.len() <= 31);
    assert!(state.authority_highwater.len() <= 21);
    assert!(state.uncertain_installations.is_empty());
}

#[test]
fn one_registration_generation_keeps_only_its_unanchored_residue() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    run_cycles(&path, &mut journal, 10, RETENTION_SECONDS + 100, 1_000);
    let before = file_size(&path);
    run_cycles_from(&path, &mut journal, 10, 40, RETENTION_SECONDS + 100);
    let per_installation = (file_size(&path) - before) / 30;
    // Ownership, discovery, revocation, invalidation and two fences per installation.
    assert!(per_installation <= 3 * 1024, "{per_installation} bytes");
    let state = &journal.state;
    assert_eq!(state.discovery_intents.len(), 40);
    assert_eq!(state.delegation_intents.len(), 1);
    assert_eq!(state.operation_intents.len(), 1);
}

fn run_cycles_from(path: &Path, journal: &mut Journal, from: u64, to: u64, spacing: u64) {
    for i in from..to {
        let now = 10_000 + i * spacing;
        install(journal, 1, i, now, true);
        remove(journal, 1, i, now + 60);
    }
    file_size(path);
}

/// Clones installation 0 of `state` as installations 1..=count, all in its generation.
fn replicate(state: &State, count: u64) -> State {
    fn rename(value: &mut serde_json::Value, suffix: &str) {
        match value {
            serde_json::Value::String(s) if s.ends_with("-0") => {
                s.truncate(s.len() - 2);
                s.push_str(suffix);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(|v| rename(v, suffix)),
            serde_json::Value::Object(map) => map.values_mut().for_each(|v| rename(v, suffix)),
            _ => {}
        }
    }
    let mut json = serde_json::to_value(state).unwrap();
    for collection in [
        "operation_intents",
        "admissions",
        "delegation_intents",
        "protection_intents",
        "discovery_intents",
        "authority_intents",
        "authority_highwater",
    ] {
        let map = json[collection].as_object_mut().unwrap();
        let chain: Vec<_> = map
            .iter()
            .filter(|(key, _)| key.ends_with("-0"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        for k in 1..=count {
            let suffix = format!("-{k}");
            for (key, value) in &chain {
                let mut value = value.clone();
                rename(&mut value, &suffix);
                map.insert(format!("{}{suffix}", &key[..key.len() - 2]), value);
            }
        }
    }
    serde_json::from_value(json).unwrap()
}

#[test]
fn a_full_journal_recovers_at_its_first_registration_after_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    register(&mut journal, 1, 10_000);
    install(&mut journal, 1, 0, 10_000, true);
    remove(&mut journal, 1, 0, 10_060);
    // A runtime without retirement keeps every installation; fill it as staging was.
    let one = serde_json::to_vec(&replicate(&journal.state, 1))
        .unwrap()
        .len()
        - serde_json::to_vec(&*journal.state).unwrap().len();
    // Longer IDs make each copy a few bytes larger than the first.
    let count = (MAX_BYTES as usize - 256 * 1024) / (one + 128);
    let full = replicate(&journal.state, count as u64);
    journal.persist(full).unwrap();
    assert!(file_size(&path) > MAX_BYTES - 512 * 1024);
    drop(journal);

    let mut journal = open(&path);
    assert!(file_size(&path) > MAX_BYTES - 512 * 1024);
    let now = 20_000;
    register(&mut journal, 2, now);
    assert!(file_size(&path) < 16 * 1024, "{} bytes", file_size(&path));
    install(&mut journal, 2, 1_000_000, now, true);
    remove(&mut journal, 2, 1_000_000, now + 60);
    assert!(journal.state.discovery_intents.len() == 1);
}

#[test]
fn a_registration_during_a_live_dispatch_keeps_its_whole_chain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    register(&mut journal, 1, 10_000);
    install(&mut journal, 1, 0, 10_000, false);
    register(&mut journal, 2, 10_010);
    let state = &journal.state;
    assert!(state.operation_intents.contains_key("operation-0"));
    assert!(state.admissions.contains_key("operation-0"));
    assert!(state.delegation_intents.contains_key("delegation-0"));
    assert!(state.protection_intents.contains_key("protection-0"));
    assert!(state.authority_intents.contains_key("ownership-0"));
    assert!(state.authority_intents.contains_key("registration-1"));
    assert!(state.discovery_intents.contains_key("discovery-0"));
    assert!(state
        .authority_highwater
        .contains_key("ownership:install-0"));
    // The late host evidence of the in-flight dispatch still lands.
    finish_operation(&mut journal, 0, at(10_020));
    // Once the permit and the grant are past retention, the next write retires it all.
    install(&mut journal, 2, 1, 10_030 + RETENTION_SECONDS + 100, true);
    let state = &journal.state;
    for gone in ["ownership-0", "registration-1"] {
        assert!(!state.authority_intents.contains_key(gone), "{gone}");
    }
    assert!(!state.operation_intents.contains_key("operation-0"));
    assert!(!state.admissions.contains_key("operation-0"));
    assert!(!state.delegation_intents.contains_key("delegation-0"));
    assert!(!state.protection_intents.contains_key("protection-0"));
    assert!(!state.discovery_intents.contains_key("discovery-0"));
    assert!(!state
        .authority_highwater
        .contains_key("ownership:install-0"));
    assert!(state.authority_highwater.contains_key("registration:host"));
}

#[test]
fn an_idle_installation_keeps_its_ownership_until_the_next_registration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    register(&mut journal, 1, 10_000);
    install(&mut journal, 1, 0, 10_000, true);
    let later = 10_000 + RETENTION_SECONDS + 100;
    install(&mut journal, 1, 1, later, true);
    let state = &journal.state;
    assert!(!state.delegation_intents.contains_key("delegation-0"));
    assert!(!state.protection_intents.contains_key("protection-0"));
    assert!(!state.operation_intents.contains_key("operation-0"));
    assert!(state.authority_intents.contains_key("ownership-0"));
    assert!(state.discovery_intents.contains_key("discovery-0"));
    assert!(journal.authority_intent_ready("ownership-0").unwrap());
    // The briq wakes: a new protection on the retained ownership is accepted.
    let request = Protect {
        installation: "install-0".into(),
        generation: 1,
        admission: "idle-again".into(),
        expires_at_ms: (later + 50) * 1000,
    };
    assert!(journal
        .begin_protection_intent(
            "protection-again",
            "host",
            "ownership-0",
            request,
            at(later)
        )
        .unwrap());
    // A retired operation ID cannot be replayed: its delegation is gone and expired.
    let mut replay = journal.state.operation_intents["operation-1"].clone();
    replay.id = "operation-0".into();
    replay.permit.admission = "operation-0".into();
    replay.delegation = "delegation-0".into();
    replay.phase = OperationPhase::Intent;
    replay.permit_digest = None;
    replay.prepared = None;
    replay.outcome_digest = None;
    assert!(matches!(
        journal.begin_operation(replay, at(later)),
        Err(Error::Binding)
    ));
}

#[test]
fn a_pending_removal_stays_until_the_registration_moves_on() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    register(&mut journal, 1, 10_000);
    install(&mut journal, 1, 0, 10_000, true);
    journal
        .begin_authority_intent(
            "revoke-0",
            "host",
            &instance(1),
            AuthorityPayload::Revoke {
                id: "grant-0".into(),
                version: 1,
            },
            at(10_010),
        )
        .unwrap();
    let later = 10_000 + RETENTION_SECONDS + 100;
    install(&mut journal, 1, 1, later, true);
    assert!(journal.state.authority_intents.contains_key("revoke-0"));
    assert!(journal
        .state
        .authority_highwater
        .contains_key("delegation:grant-0"));
    assert!(journal.delegation_revoked("grant-0").unwrap());
    register(&mut journal, 2, later + 10);
    assert!(!journal.state.authority_intents.contains_key("revoke-0"));
    assert!(!journal
        .state
        .authority_highwater
        .contains_key("delegation:grant-0"));
}

#[test]
fn retirement_keeps_a_v1_state_that_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    run_cycles(&path, &mut journal, 25, RETENTION_SECONDS + 100, 10);
    let state = State::clone(&journal.state);
    let (again, removed) = retire(&state, 10_000 * 1000);
    assert_eq!(removed, 0);
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&state).unwrap()
    );
    drop(journal);
    let reopened = open(&path);
    assert_eq!(reopened.state.v, 1);
    assert_eq!(reopened.state.discovery_intents, state.discovery_intents);
}

#[test]
fn a_reserve_retires_exactly_as_the_state_it_extends() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority");
    let mut journal = open(&path);
    register(&mut journal, 1, 10_000);
    install(&mut journal, 1, 0, 10_000, true);
    let next = State::clone(&journal.state);
    let mut reserve = next.clone();
    reserve.clock_floor = MAX_SAFE_INTEGER;
    reserve
        .uncertain_installations
        .insert("discovery:discovery-0".into());
    let later = (10_000 + RETENTION_SECONDS + 100) * 1000;
    let (retired, removed) = retire(&next, later);
    assert!(removed > 0);
    let mut expected = retired;
    expected.clock_floor = MAX_SAFE_INTEGER;
    expected
        .uncertain_installations
        .insert("discovery:discovery-0".into());
    assert_eq!(
        serde_json::to_vec(&retire(&reserve, later).0).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}
