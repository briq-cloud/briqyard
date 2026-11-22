use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

const COMPACTION_PERCENT: usize = 75;

pub struct Compaction {
    pub reclaimed_bytes: usize,
    pub retired_versions: usize,
}

pub fn compact_authority(state: &State, clock: Clock) -> Result<(State, Compaction), Error> {
    if !matches!(state.role, Role::Authority(_))
        || clock.now < state.clock_floor
        || clock.now > MAX_SAFE_INTEGER
        || clock.uncertainty > MAX_SAFE_INTEGER
    {
        return Err(Error::Binding);
    }
    let earliest_ms = clock
        .now
        .checked_sub(clock.uncertainty)
        .and_then(|now| now.checked_mul(1000))
        .ok_or(Error::Binding)?;
    let before = serde_json::to_vec(state)
        .map_err(|_| Error::Persistence)?
        .len();
    let mut next = State::clone(state);
    let mut retired_versions = 0;
    for (id, intent) in &mut next.delegation_intents {
        if !intent.request.grant.is_empty()
            && !intent.request.allocations.is_empty()
            && intent.expected.expires_at <= MAX_SAFE_INTEGER
            && intent.expected.expires_at.saturating_mul(1000) <= earliest_ms
            && intent.acknowledgement.as_ref() == Some(&intent.expected)
            && intent.operation_policy_ack == intent.operation_policy
            && !state
                .uncertain_installations
                .contains(&format!("delegation:{id}"))
            && !state.operation_intents.values().any(|operation| {
                operation.delegation == *id && operation.phase != OperationPhase::Finished
            })
            && !state
                .renewal_attempts
                .values()
                .any(|attempt| attempt.binding.grant_digest == intent.expected.grant_digest)
            && intent
                .request
                .allocations
                .iter()
                .all(|token| allocation_expired(token, earliest_ms))
        {
            intent.request.grant.clear();
            intent.request.allocations.clear();
            retired_versions += 1;
        }
    }
    let after = serde_json::to_vec(&next)
        .map_err(|_| Error::Persistence)?
        .len();
    Ok((
        next,
        Compaction {
            reclaimed_bytes: before.saturating_sub(after),
            retired_versions,
        },
    ))
}

pub fn maximum_discovery_receipt(intent: &DiscoveryIntent) -> DiscoveryReceipt {
    let targets = intent
        .request
        .seeds
        .iter()
        .map(|seed| Target {
            host: intent.host.clone(),
            machine: seed.machine.clone(),
            namespace: seed.namespace.clone(),
            run: "x".repeat(128),
            placement: "x".repeat(128),
        })
        .collect::<Vec<_>>();
    let primary = intent
        .request
        .seeds
        .iter()
        .position(|seed| seed.id == intent.control.primary_id)
        .map(|index| targets[index].clone())
        .unwrap_or_else(|| targets[0].clone());
    let mut resources = targets.clone();
    for index in 0.. {
        if resources.len() == MAX_RESOURCES {
            break;
        }
        let candidate = Target {
            host: intent.host.clone(),
            machine: format!("{index:0>128}"),
            namespace: "x".repeat(128),
            run: "x".repeat(128),
            placement: "x".repeat(128),
        };
        if resources
            .iter()
            .all(|target| (&target.host, &target.machine) != (&candidate.host, &candidate.machine))
        {
            resources.push(candidate);
        }
    }
    resources.sort_by(|a, b| (&a.host, &a.machine).cmp(&(&b.host, &b.machine)));
    let mut public_resources = intent
        .request
        .seeds
        .iter()
        .zip(targets.iter())
        .map(|(seed, target)| PublicResource {
            id: seed.id.clone(),
            target: target.clone(),
        })
        .collect::<Vec<_>>();
    public_resources.sort_by(|a, b| {
        (&a.target.host, &a.target.machine).cmp(&(&b.target.host, &b.target.machine))
    });
    DiscoveryReceipt {
        host_instance: intent.request.host_instance.clone(),
        primary,
        public_seeds: targets,
        public_resources,
        resource_set: ResourceSet {
            revision: "x".repeat(128),
            resources,
        },
    }
}

fn allocation_expired(token: &str, earliest_ms: u64) -> bool {
    #[derive(Deserialize)]
    struct Expiry {
        exp: u64,
    }
    let Some(body) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(body) = URL_SAFE_NO_PAD.decode(body) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<Expiry>(&body) else {
        return false;
    };
    claims.exp <= MAX_SAFE_INTEGER && claims.exp.saturating_mul(1000) <= earliest_ms
}

pub(super) fn collection_lengths(state: &State) -> [usize; 21] {
    [
        state.allocations.len(),
        state.fences.len(),
        state.retired.values().map(Vec::len).sum(),
        state.admissions.len(),
        state.ownership.len(),
        state.ownership_highwater.len(),
        state.delegations.len(),
        state.delegation_versions.values().map(Vec::len).sum(),
        state.delegation_tombstones.len(),
        state.prepared.len(),
        state.protections.len(),
        state.authority_intents.len(),
        state.authority_highwater.len(),
        state.discovery_intents.len(),
        state.protection_intents.len(),
        state.delegation_intents.len(),
        state.operation_intents.len(),
        state.uncertain_installations.len(),
        state.active_operations.len(),
        state.operation_policies.len(),
        state.renewal_attempts.len(),
    ]
}

pub fn over_capacity(state: &State) -> bool {
    collection_lengths(state)
        .into_iter()
        .any(|len| len > MAX_RECORDS)
        || serde_json::to_vec(state).map_or(true, |bytes| bytes.len() as u64 > MAX_BYTES)
}

pub fn near_capacity(state: &State) -> bool {
    collection_lengths(state)
        .into_iter()
        .any(|length| length >= MAX_RECORDS * COMPACTION_PERCENT / 100)
        || serde_json::to_vec(state)
            .is_ok_and(|bytes| bytes.len() >= MAX_BYTES as usize * COMPACTION_PERCENT / 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::channel::InstallDelegation;
    use serde_json::Value;

    fn state() -> State {
        let directory = tempfile::tempdir().unwrap();
        let journal = Journal::open(
            &directory.path().join("authority"),
            Role::Authority("authority".into()),
        )
        .unwrap();
        State::clone(&journal.state)
    }

    fn token(exp: u64, size: usize) -> String {
        let body = format!(r#"{{"exp":{exp},"pad":""}}"#);
        let body = format!(
            r#"{{"exp":{exp},"pad":"{}"}}"#,
            "x".repeat(size - body.len())
        );
        format!("header.{}.signature", URL_SAFE_NO_PAD.encode(body))
    }

    fn intent(expires_at: u64, token_size: usize) -> DelegationIntent {
        let grant = token(expires_at, token_size);
        let allocation = token(expires_at + 20, token_size);
        let expected = HostDelegation {
            id: "delegation".into(),
            version: 1,
            ownership: "ownership".into(),
            ownership_generation: 1,
            grant_digest: hash(&grant),
            allocation_digests: vec![hash(&allocation)],
            principal: "principal".into(),
            expires_at,
        };
        DelegationIntent {
            host: "host".into(),
            authority_epoch: "epoch".into(),
            registration: "registration".into(),
            ownership: "ownership".into(),
            protection: "protection".into(),
            trusted_source: Some(Source {
                kind: "source".into(),
                id: "id".into(),
                expires_at: expires_at + 40,
            }),
            projection: Some(Projection::new(b"projection".to_vec()).unwrap()),
            policy_revision: Some("policy".into()),
            request: InstallDelegation {
                installation: "ownership".into(),
                generation: 1,
                id: "delegation".into(),
                version: 1,
                principal: "principal".into(),
                grant,
                allocations: vec![allocation],
                protection_expires_at_ms: (expires_at + 30) * 1000,
            },
            acknowledgement: None,
            expected: expected.clone(),
            operation_policy: None,
            operation_policy_ack: None,
        }
    }

    fn hash(token: &str) -> String {
        use sha2::{Digest, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    }

    fn ready(state: &mut State, id: &str, expires_at: u64, token_size: usize) {
        let mut intent = intent(expires_at, token_size);
        intent.request.id = format!("delegation-{id}");
        intent.expected.id = intent.request.id.clone();
        intent.acknowledgement = Some(intent.expected.clone());
        state.delegation_intents.insert(id.into(), intent);
    }

    fn install(state: &mut State, id: &str, expires_at: u64, token_size: usize) {
        ready(state, id, expires_at, token_size);
        let intent = state
            .delegation_intents
            .get_mut(id)
            .expect("inserted intent");
        intent.authority_epoch = state.instance.clone();
    }

    fn at(now: u64) -> Clock {
        Clock {
            now,
            uncertainty: 1,
        }
    }

    fn bytes(state: &State) -> usize {
        serde_json::to_vec(state).unwrap().len()
    }

    #[test]
    fn compaction_retires_only_expired_fully_acknowledged_payloads() {
        let mut baseline = state();
        install(&mut baseline, "expired", 100, 128);
        baseline.clock_floor = 200;
        let (compacted, report) = compact_authority(&baseline, at(200)).unwrap();
        let intent = &compacted.delegation_intents["expired"];
        assert!(intent.request.grant.is_empty());
        assert!(intent.request.allocations.is_empty());
        assert_eq!(
            intent.expected,
            baseline.delegation_intents["expired"].expected
        );
        assert_eq!(
            intent.acknowledgement,
            baseline.delegation_intents["expired"].acknowledgement
        );
        assert_eq!(
            intent.projection,
            baseline.delegation_intents["expired"].projection
        );
        assert_eq!(report.retired_versions, 1);
        assert_eq!(report.reclaimed_bytes, bytes(&baseline) - bytes(&compacted));
        assert_eq!(
            compact_authority(&compacted, at(200))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );
    }

    #[test]
    fn expiry_uses_the_qualified_lower_bound() {
        let mut original = state();
        install(&mut original, "expires", 100, 128);
        original.clock_floor = 100;
        assert_eq!(
            compact_authority(&original, at(100))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );
        original.clock_floor = 101;
        assert!(compact_authority(&original, at(100)).is_err());
        original.clock_floor = 121;
        assert_eq!(
            compact_authority(&original, at(122))
                .unwrap()
                .1
                .retired_versions,
            1
        );
    }

    #[test]
    fn unexpired_allocations_and_pending_dependencies_remain() {
        let mut original = state();
        install(&mut original, "live-allocation", 100, 128);
        original
            .delegation_intents
            .get_mut("live-allocation")
            .unwrap()
            .request
            .allocations = vec![token(200, 128)];
        original.clock_floor = 200;
        assert_eq!(
            compact_authority(&original, at(200))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );

        let mut original = state();
        install(&mut original, "pending", 100, 128);
        original
            .delegation_intents
            .get_mut("pending")
            .unwrap()
            .acknowledgement = None;
        original.clock_floor = 200;
        assert_eq!(
            compact_authority(&original, at(200))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );

        install(&mut original, "uncertain", 100, 128);
        original
            .uncertain_installations
            .insert("delegation:uncertain".into());
        assert_eq!(
            compact_authority(&original, at(200))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );
    }

    #[test]
    fn partial_policy_unfinished_operations_and_renewals_stay_protected() {
        let mut policy_state = state();
        install(&mut policy_state, "policy", 100, 128);
        let intent = policy_state.delegation_intents.get_mut("policy").unwrap();
        intent.operation_policy = Some(HostOperationPolicy {
            host_instance: "host-run".into(),
            ownership: "ownership".into(),
            ownership_generation: 1,
            delegation: "delegation-policy".into(),
            delegation_version: 1,
            grant_digest: intent.expected.grant_digest.clone(),
            policy_revision: "policy".into(),
        });
        policy_state.clock_floor = 200;
        assert_eq!(
            compact_authority(&policy_state, at(200))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );

        for phase in [
            OperationPhase::Intent,
            OperationPhase::Reserved,
            OperationPhase::Prepared,
            OperationPhase::Dispatched,
            OperationPhase::Consumed,
        ] {
            let mut operation_state = state();
            install(&mut operation_state, "active", 100, 128);
            let digest = operation_state.delegation_intents["active"]
                .expected
                .grant_digest
                .clone();
            let mut operation = finished_operation("op", "active", &digest);
            operation.phase = phase;
            operation_state
                .operation_intents
                .insert(operation.id.clone(), operation);
            operation_state.clock_floor = 200;
            assert_eq!(
                compact_authority(&operation_state, at(200))
                    .unwrap()
                    .1
                    .reclaimed_bytes,
                0,
                "{phase:?}"
            );
        }

        let mut renewal_state = state();
        install(&mut renewal_state, "renewed", 100, 128);
        let intent = &renewal_state.delegation_intents["renewed"];
        let operation = finished_operation("op", "renewed", &intent.expected.grant_digest);
        let binding = ActiveOperationBinding {
            operation_id: operation.id,
            admission: "op".into(),
            grant_digest: intent.expected.grant_digest.clone(),
            permit_digest: "permit".into(),
            request_digest: "request".into(),
            authority: "authority".into(),
            authority_epoch: "epoch".into(),
            host_instance: "host-run".into(),
            ownership: "ownership".into(),
            ownership_generation: 1,
            policy_revision: "policy".into(),
            delegation: intent.request.id.clone(),
            delegation_version: 1,
            principal: intent.request.principal.clone(),
            source: intent.trusted_source.clone().unwrap(),
            team: "team".into(),
            subject: "subject".into(),
            metadata_revision: "metadata".into(),
            target: Target {
                host: "host".into(),
                machine: "machine".into(),
                namespace: "team".into(),
                run: "run".into(),
                placement: "version-1".into(),
            },
            resource_set: ResourceSet {
                revision: "resources".into(),
                resources: vec![Target {
                    host: "host".into(),
                    machine: "machine".into(),
                    namespace: "team".into(),
                    run: "run".into(),
                    placement: "version-1".into(),
                }],
            },
            limits: Limits {
                execution_mode: None,
                max_duration_seconds: 20,
                max_input_bytes: 1024,
                output_mode: None,
                max_output_bytes: 4096,
            },
            guest_timeout_ms: 60_000,
            started_at_ms: 1_000,
            operation_deadline_ms: 2_000,
        };
        renewal_state.renewal_attempts.insert(
            "attempt".into(),
            RenewalAttempt {
                id: "attempt".into(),
                operation_id: "op".into(),
                previous_sequence: 0,
                binding,
                protection_intent: "protection".into(),
                protection_admission: "admission".into(),
                protection_expires_at_ms: 2_000,
                continuation_digest: None,
            },
        );
        renewal_state.clock_floor = 200;
        assert_eq!(
            compact_authority(&renewal_state, at(200))
                .unwrap()
                .1
                .reclaimed_bytes,
            0
        );
    }

    #[test]
    fn all_revocation_operation_and_protection_evidence_survives() {
        let mut original = state();
        install(&mut original, "old", 100, 128);
        let intent = original.delegation_intents.get_mut("old").unwrap();
        intent.operation_policy = Some(HostOperationPolicy {
            host_instance: "host-run".into(),
            ownership: "ownership".into(),
            ownership_generation: 1,
            delegation: "delegation-old".into(),
            delegation_version: 1,
            grant_digest: intent.expected.grant_digest.clone(),
            policy_revision: "policy".into(),
        });
        intent.operation_policy_ack = intent.operation_policy.clone();
        original.authority_intents.insert(
            "revocation".into(),
            AuthorityIntent {
                host: "host".into(),
                host_instance: "host-run".into(),
                authority_epoch: original.instance.clone(),
                registration_dependency: None,
                discovery_dependency: None,
                payload: AuthorityPayload::Revoke {
                    id: "delegation-old".into(),
                    version: 99,
                },
                acknowledgement: None,
                instance_confirmed: true,
            },
        );
        original.clock_floor = 200;
        let (compacted, report) = compact_authority(&original, at(200)).unwrap();
        assert_eq!(report.retired_versions, 1);
        assert_eq!(
            serde_json::to_value(&compacted.authority_intents).unwrap(),
            serde_json::to_value(&original.authority_intents).unwrap()
        );
        assert!(compacted.delegation_intents["old"].request.grant.is_empty());
    }

    #[test]
    fn host_state_is_never_compacted() {
        let directory = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(&directory.path().join("host"), Role::Host("host".into())).unwrap();
        let host = State::clone(&journal.state);
        assert!(compact_authority(&host, at(200)).is_err());
    }

    #[test]
    fn full_collection_histories_still_fit_or_fail_closed() {
        let mut original = state();
        for index in 0..MAX_RECORDS {
            let id = format!("d{index}");
            install(&mut original, &id, 100, 32);
            let intent = original.delegation_intents.get_mut(&id).unwrap();
            intent.request.id = format!("delegation-{index}");
            intent.expected.id = intent.request.id.clone();
        }
        assert_eq!(original.delegation_intents.len(), MAX_RECORDS);
        original.clock_floor = 200;
        let _ = compact_authority(&original, at(200)).unwrap();
    }

    #[test]
    fn compaction_pressure_is_checked_for_every_bounded_collection() {
        let small = state();
        assert!(!near_capacity(&small));
        for index in [MAX_RECORDS * 3 / 4 - 1, MAX_RECORDS * 3 / 4] {
            let mut full = small.clone();
            full.uncertain_installations = (0..index).map(|v| v.to_string()).collect();
            assert_eq!(near_capacity(&full), index == MAX_RECORDS * 3 / 4);
        }
    }

    fn boundary_fixture(after: usize) -> (tempfile::TempDir, Journal, usize) {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(
            &directory.path().join("authority"),
            Role::Authority("authority".into()),
        )
        .unwrap();
        let original = Arc::make_mut(&mut journal.view.state);
        install(original, "old", 100, 128);
        original.clock_floor = 100;
        original.uncertain_installations.insert("p".repeat(1024));
        let (candidate, _) = compact_authority(original, at(200)).unwrap();
        let extra = after - bytes(&candidate);
        original
            .uncertain_installations
            .insert("q".repeat(extra - 3));
        let (compacted, report) = compact_authority(original, at(200)).unwrap();
        assert_eq!(bytes(&compacted), after);
        (directory, journal, report.reclaimed_bytes)
    }

    #[test]
    fn a_434_byte_v1_headroom_fixture_reclaims_and_reopens() {
        let (directory, mut journal, expected) = boundary_fixture(MAX_BYTES as usize - 812);
        journal.persist(State::clone(&journal.state)).unwrap();
        drop(journal);
        let mut journal = Journal::open(
            &directory.path().join("authority"),
            Role::Authority("authority".into()),
        )
        .unwrap();
        let before = std::fs::metadata(directory.path().join("authority/journal.json"))
            .unwrap()
            .len();
        assert_eq!(before as usize, MAX_BYTES as usize - 434);
        journal.prune(at(200)).unwrap();
        let after = std::fs::metadata(directory.path().join("authority/journal.json"))
            .unwrap()
            .len();
        let reclaimed = before as usize - after as usize;
        assert_eq!(reclaimed, expected);
        println!(
            "434-byte fixture: reclaimed {reclaimed} bytes, retained {} bytes",
            after
        );
        assert!(journal
            .delegation_intent("old")
            .unwrap()
            .unwrap()
            .request
            .grant
            .is_empty());
        drop(journal);
        let reopened = Journal::open(
            &directory.path().join("authority"),
            Role::Authority("authority".into()),
        )
        .unwrap();
        assert!(reopened
            .delegation_intent("old")
            .unwrap()
            .unwrap()
            .request
            .grant
            .is_empty());
    }

    #[test]
    fn projected_overflow_fits_an_exactly_full_v1_file_once() {
        let (directory, mut journal, expected) = boundary_fixture(MAX_BYTES as usize);
        assert!(over_capacity(&journal.state));
        journal.prune(at(200)).unwrap();
        let length = std::fs::metadata(directory.path().join("authority/journal.json"))
            .unwrap()
            .len();
        assert_eq!(length, MAX_BYTES);
        println!("exactly-full fixture: reclaimed {expected} bytes, retained {length} bytes");
        let after = std::fs::read(directory.path().join("authority/journal.json")).unwrap();
        journal.prune(at(200)).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("authority/journal.json")).unwrap(),
            after
        );
    }

    #[test]
    fn irreducible_full_state_refuses_without_erasing_evidence() {
        let (directory, mut journal, _) = boundary_fixture(MAX_BYTES as usize);
        Arc::make_mut(&mut journal.view.state)
            .uncertain_installations
            .insert("delegation:old".into());
        let before = std::fs::read(directory.path().join("authority/journal.json")).unwrap();
        assert!(matches!(
            journal.refuse_installation_readiness("protection", "still-pending"),
            Err(Error::Full)
        ));
        assert_eq!(
            std::fs::read(directory.path().join("authority/journal.json")).unwrap(),
            before
        );
        assert!(!directory.path().join("authority/journal.next").exists());
        assert!(!journal.state.delegation_intents["old"]
            .request
            .grant
            .is_empty());
        assert!(matches!(journal.owned(), Err(Error::Persistence)));
    }

    #[test]
    fn a_commit_cannot_consume_the_acknowledgement_or_refusal_reserve() {
        let (_directory, mut journal, _) = boundary_fixture(MAX_BYTES as usize - 20);
        Arc::make_mut(&mut journal.view.state)
            .delegation_intents
            .get_mut("old")
            .unwrap()
            .acknowledgement = None;
        assert!(over_capacity(&journal.state));
        let next = State::clone(&journal.state);
        assert!(matches!(
            journal.commit_install(next.clone(), at(200), next),
            Err(Error::Full)
        ));
        assert!(!journal.state.delegation_intents["old"]
            .request
            .grant
            .is_empty());
        assert!(journal.state.delegation_intents["old"]
            .acknowledgement
            .is_none());
        assert!(journal.owned().is_ok());
    }

    #[test]
    fn every_durability_boundary_fails_closed() {
        for failure in ["create", "write", "file_fsync", "rename", "directory_fsync"] {
            let (directory, mut journal, _) = boundary_fixture(MAX_BYTES as usize - 4096);
            journal.persist(State::clone(&journal.state)).unwrap();
            let file = directory.path().join("authority/journal.json");
            let original = std::fs::read(&file).unwrap();
            let (compacted, report) = compact_authority(&journal.state, at(200)).unwrap();
            assert!(report.reclaimed_bytes > 0);
            let expected = serde_json::to_vec(&compacted).unwrap();
            assert!(matches!(
                journal.persist_inner(compacted, &mut |stage| stage == failure),
                Err(Error::Persistence)
            ));
            assert!(matches!(journal.owned(), Err(Error::Persistence)));
            assert!(!journal.state.delegation_intents["old"]
                .request
                .grant
                .is_empty());
            let stored = std::fs::read(&file).unwrap();
            if failure == "directory_fsync" {
                assert_eq!(
                    stored, expected,
                    "post-rename failure lost the compacted file"
                );
            } else {
                assert_eq!(stored, original, "{failure} replaced the original journal");
            }
        }
    }

    #[test]
    fn failed_compaction_persistence_keeps_the_original_and_poisons_the_writer() {
        let (directory, mut journal, _) = boundary_fixture(MAX_BYTES as usize - 434);
        let before = std::fs::read(directory.path().join("authority/journal.json")).unwrap();
        std::fs::create_dir(directory.path().join("authority/journal.next")).unwrap();
        assert!(matches!(journal.prune(at(200)), Err(Error::Persistence)));
        assert_eq!(
            std::fs::read(directory.path().join("authority/journal.json")).unwrap(),
            before
        );
        assert!(matches!(journal.owned(), Err(Error::Persistence)));
    }

    fn bind_control(
        state: &mut State,
        key: String,
        delegation: &str,
        installation: &str,
        generation: u64,
        confirmed: bool,
    ) {
        let payload = if let Some(delegation) = delegation.strip_prefix("delegation-") {
            AuthorityPayload::Revoke {
                id: format!("delegation-{delegation}"),
                version: generation,
            }
        } else {
            AuthorityPayload::Invalidate {
                installation: installation.into(),
                generation,
            }
        };
        state.authority_intents.insert(
            key,
            AuthorityIntent {
                host: "host".into(),
                host_instance: "host-run".into(),
                authority_epoch: "epoch".into(),
                registration_dependency: None,
                discovery_dependency: None,
                payload,
                acknowledgement: None,
                instance_confirmed: confirmed,
            },
        );
    }

    fn finished_operation(id: &str, delegation: &str, digest: &str) -> OperationIntent {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/execution-v1.json"))
                .unwrap();
        let mut permit: Permit = serde_json::from_value(fixture["permit"].clone()).unwrap();
        permit.admission = id.into();
        permit.grant_digest = digest.into();
        OperationIntent {
            id: id.into(),
            delegation: delegation.into(),
            authority_epoch: "epoch".into(),
            host: "host".into(),
            host_instance: "host-run".into(),
            request_digest: hash(id),
            permit,
            phase: OperationPhase::Finished,
            permit_digest: Some(hash("permit")),
            prepared: None,
            outcome_digest: Some(hash("outcome")),
            unconfirmed: false,
        }
    }

    fn without_credentials(state: &State) -> Value {
        let mut normalized = State::clone(state);
        for intent in normalized.delegation_intents.values_mut() {
            intent.request.grant.clear();
            intent.request.allocations.clear();
        }
        serde_json::to_value(normalized).unwrap()
    }

    #[test]
    fn mixed_histories_match_the_reference_except_retired_credentials() {
        for seed in 0..64u64 {
            let mut random = seed + 1;
            let mut reference = state();
            reference.clock_floor = 200;
            let mut live = Vec::new();
            let mut pending = Vec::new();
            let mut latest: BTreeMap<String, u64> = BTreeMap::new();
            let mut versions: BTreeMap<String, u64> = BTreeMap::new();
            for step in 0..96usize {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                match random % 7 {
                    0 | 1 => {
                        let key = format!("install-{seed}-{step}");
                        install(&mut reference, &key, 50 + (random % 250), 96 + (step % 9));
                        versions.insert(key.clone(), 1);
                        latest.insert(key.clone(), 1);
                        if random % 3 == 0 {
                            reference
                                .delegation_intents
                                .get_mut(&key)
                                .unwrap()
                                .acknowledgement = None;
                            pending.push(key.clone());
                        } else {
                            live.push(key.clone());
                        }
                    }
                    2 if !latest.is_empty() => {
                        let index = random as usize % latest.len();
                        let owner = latest.keys().nth(index).unwrap().clone();
                        let key = format!("renewal-{seed}-{step}");
                        install(&mut reference, &key, 100, 96);
                        let delegation = reference.delegation_intents[&owner].request.id.clone();
                        let version = reference
                            .delegation_intents
                            .values()
                            .filter(|intent| intent.request.id == delegation)
                            .map(|intent| intent.request.version)
                            .max()
                            .unwrap_or(0)
                            + 1;
                        let intent = reference.delegation_intents.get_mut(&key).unwrap();
                        intent.request.id = delegation.clone();
                        intent.request.version = version;
                        intent.request.grant = token(100, 160);
                        intent.expected.id = delegation.clone();
                        intent.expected.version = version;
                        intent.expected.grant_digest = hash(&intent.request.grant);
                        intent.acknowledgement = Some(intent.expected.clone());
                        versions.insert(key.clone(), version);
                        latest.insert(key, version);
                    }
                    3 if !latest.is_empty() => {
                        let owner = latest.keys().nth(random as usize % latest.len()).unwrap();
                        let delegation = reference.delegation_intents[owner].request.id.clone();
                        let version = reference
                            .delegation_intents
                            .values()
                            .filter(|intent| intent.request.id == delegation)
                            .map(|intent| intent.request.version)
                            .max()
                            .unwrap_or(0)
                            + 1;
                        bind_control(
                            &mut reference,
                            format!("revoke-{seed}-{step}"),
                            &delegation,
                            "unused",
                            version,
                            random % 2 == 0,
                        );
                    }
                    4 => {
                        bind_control(
                            &mut reference,
                            format!("invalidate-{seed}-{step}"),
                            "unused",
                            "ownership",
                            step as u64 + 1,
                            random % 2 == 0,
                        );
                    }
                    5 if !pending.is_empty() => {
                        let index = random as usize % pending.len();
                        let key = pending.swap_remove(index);
                        let expected = reference.delegation_intents[&key].expected.clone();
                        reference
                            .delegation_intents
                            .get_mut(&key)
                            .unwrap()
                            .acknowledgement = Some(expected);
                        live.push(key);
                    }
                    6 if !live.is_empty() => {
                        let key = live[random as usize % live.len()].clone();
                        let digest = reference.delegation_intents[&key]
                            .expected
                            .grant_digest
                            .clone();
                        let operation =
                            finished_operation(&format!("exec-{seed}-{step}"), &key, &digest);
                        assert_eq!(operation.phase, OperationPhase::Finished);
                        reference
                            .operation_intents
                            .insert(operation.id.clone(), operation);
                    }
                    _ => {}
                }
                assert!(versions.values().copied().max().unwrap_or(0) <= 32);
            }
            let uncompacted = without_credentials(&reference);
            let (compacted, report) = compact_authority(&reference, at(200)).unwrap();
            assert_eq!(without_credentials(&compacted), uncompacted, "seed {seed}");
            let (repeated, again) = compact_authority(&compacted, at(200)).unwrap();
            assert_eq!(without_credentials(&repeated), uncompacted, "seed {seed}");
            assert_eq!(again.reclaimed_bytes, 0);
            for key in pending {
                assert_eq!(
                    compacted.delegation_intents[&key].request.grant,
                    reference.delegation_intents[&key].request.grant,
                    "seed {seed} retired late evidence"
                );
            }
            for (key, intent) in &reference.delegation_intents {
                if intent.acknowledgement.is_none()
                    || intent.expected.expires_at.saturating_mul(1000) > 199_000
                    || intent.request.allocations.is_empty()
                {
                    assert_eq!(
                        compacted.delegation_intents[key].request,
                        reference.delegation_intents[key].request,
                        "seed {seed} changed protected intent"
                    );
                }
            }
            if report.retired_versions > 0 {
                assert!(report.reclaimed_bytes > 0);
            }
        }
    }

    fn signed_retired_state() -> State {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/execution-v1.json"))
                .unwrap();
        let grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
        let grant_token = fixture["grant_token"].as_str().unwrap().to_owned();
        let allocation = fixture["allocation_token"].as_str().unwrap().to_owned();
        let mut legacy = state();
        let mut intent = intent(1050, 128);
        intent.request.grant = grant_token;
        intent.request.allocations = vec![allocation];
        intent.request.principal = grant.principal.clone();
        intent.request.id = grant.id.clone();
        intent.expected = HostDelegation {
            id: grant.id.clone(),
            version: 1,
            ownership: "ownership".into(),
            ownership_generation: 1,
            grant_digest: hash(&intent.request.grant),
            allocation_digests: vec![hash(&intent.request.allocations[0])],
            principal: grant.principal,
            expires_at: grant.exp,
        };
        intent.acknowledgement = Some(intent.expected.clone());
        intent.trusted_source = Some(grant.source);
        legacy.clock_floor = 1010;
        legacy.delegation_intents.insert("legacy".into(), intent);
        let (retired, report) = compact_authority(&legacy, at(2000)).unwrap();
        assert_eq!(report.retired_versions, 1);
        println!(
            "signed v1 fixture: reclaimed {} bytes",
            report.reclaimed_bytes
        );
        assert!(report.reclaimed_bytes > 0);
        retired
    }

    #[test]
    fn export_signed_retired_fixture() {
        let Some(path) = std::env::var_os("BRIQYARD_UPDATE_COMPACTION_FIXTURE") else {
            return;
        };
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&signed_retired_state()).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn clock_independent_revocation_never_retires_a_payload() {
        let (_directory, mut journal, _) = boundary_fixture(MAX_BYTES as usize * 3 / 4);
        assert!(near_capacity(&journal.state));
        let clock = journal.revocation_order();
        assert!(journal
            .begin_authority_intent(
                "revoke-old",
                "host",
                "host-run",
                AuthorityPayload::Revoke {
                    id: "delegation-old".into(),
                    version: 1,
                },
                clock,
            )
            .unwrap());
        assert!(!journal.state.delegation_intents["old"]
            .request
            .grant
            .is_empty());
        assert_eq!(journal.state.clock_floor, 100);
    }

    #[test]
    fn construction_from_retired_v1_preserves_shapes_old_readers_expect() {
        let mut original = state();
        install(&mut original, "old", 100, 128);
        original.clock_floor = 200;
        let (compacted, _) = compact_authority(&original, at(200)).unwrap();
        let value: Value =
            serde_json::from_slice(&serde_json::to_vec(&compacted).unwrap()).unwrap();
        assert_eq!(value["v"], 1);
        assert_eq!(value["delegation_intents"]["old"]["request"]["grant"], "");
        assert_eq!(
            value["delegation_intents"]["old"]["request"]["allocations"],
            serde_json::json!([])
        );
        let decoded: State = serde_json::from_value(value).unwrap();
        assert_eq!(bytes(&decoded), bytes(&compacted));
    }
}

#[cfg(test)]
#[path = "reserve_cases.rs"]
mod reserve_cases;
