use super::*;
use crate::guestc::{active_lease::ActiveLease, guarded_operations::GuardedOperations};
use crate::machine::guarded_exec::GuardedManager;
use briqyard_api::execution::{
    admission::{ActiveOperation, Role},
    clock::ClockSample,
    Permit,
};
use std::time::Duration;

#[tokio::test]
async fn refused_registration_leaves_an_owned_active_lease_running() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../briqyard-api/tests/fixtures/execution-continuation-v1.json"
    ))
    .unwrap();
    let evidence: ActiveOperation = serde_json::from_value(fixture["active"].clone()).unwrap();
    let sample = ClockSample {
        wall: Duration::from_secs(1035),
        monotonic: std::time::Instant::now(),
        uncertainty: Duration::from_secs(1),
    };
    let clock = Clock {
        now: 1010,
        uncertainty: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&dir.path().join("host"), Role::Host("host-1".into())).unwrap();
    let current = HostRegistration {
        authority: "authority-1".into(),
        epoch: "epoch-2".into(),
        key_id: "key-2".into(),
        public_key: [7; 32],
        host_instance: journal.instance().into(),
        generation: 2,
    };
    let active = Arc::new(GuardedOperations::default());
    register_host(&mut journal, &active, &current, clock).unwrap();

    let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
    let _owner = active
        .register(&evidence.binding.admission, lease.clone())
        .unwrap();
    lease.observe(&evidence, &sample).unwrap();

    register_host(&mut journal, &active, &current, clock).unwrap();
    lease.observe(&evidence, &sample).unwrap();

    let stale = HostRegistration {
        epoch: "epoch-1".into(),
        generation: 1,
        ..current.clone()
    };
    let other_host = HostRegistration {
        host_instance: "another-host".into(),
        generation: 3,
        ..current.clone()
    };
    for refused in [stale, other_host] {
        assert_eq!(
            register_host(&mut journal, &active, &refused, clock),
            Err(StatusCode::CONFLICT)
        );
        assert_eq!(journal.registration().unwrap(), Some(&current));
        assert!(active.get(&evidence.binding.admission).is_some());
        lease.observe(&evidence, &sample).unwrap();
    }

    let next = HostRegistration {
        epoch: "epoch-3".into(),
        generation: 3,
        ..current
    };
    register_host(&mut journal, &active, &next, clock).unwrap();
    assert_eq!(journal.registration().unwrap(), Some(&next));
    assert!(lease.observe(&evidence, &sample).is_err());
}

fn near_capacity_journal(path: &std::path::Path) -> (Journal, HostRegistration) {
    const MAX_BYTES: usize = 16 * 1024 * 1024;
    const MAX_RECORDS: usize = 16_384;
    let journal_path = path.join("journal.json");
    let journal = Journal::open(path, Role::Host("host-1".into())).unwrap();
    let mut next: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
    drop(journal);
    let permit: Permit = serde_json::from_value(
        serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../../../briqyard-api/tests/fixtures/execution-v1.json"
        ))
        .unwrap()["permit"]
            .clone(),
    )
    .unwrap();
    let current = HostRegistration {
        authority: permit.authority.clone(),
        epoch: permit.authority_epoch.clone(),
        key_id: "authority-test".into(),
        public_key: [7; 32],
        host_instance: next["instance"].as_str().unwrap().into(),
        generation: 1,
    };
    next["registration"] = serde_json::to_value(&current).unwrap();
    next["registration_highwater"] = serde_json::json!(1);
    next["fences"][&current.authority] = serde_json::to_value(&current.epoch).unwrap();
    next["clock_floor"] = serde_json::json!(crate::api::execution::test_fixtures::CLOCK.now);
    let mut padded = permit.clone();
    let allocation = padded.allocations[0].clone();
    padded.allocations = (0..access::MAX_ALLOCATIONS)
        .map(|n| access::AllocationRef {
            id: format!("allocation-{n}"),
            ..allocation.clone()
        })
        .collect();
    let mut used = serde_json::to_vec(&next).unwrap().len() - 1;
    let admissions = next["admissions"].as_object_mut().unwrap();
    for n in 0..MAX_RECORDS {
        padded.admission = format!("{n:05}{}", "x".repeat(123));
        let item = serde_json::json!({
            "permit": padded.clone(),
            "status": access::admission::Status::Finished,
        });
        let bytes = serde_json::to_vec(&item).unwrap().len() + 4 + padded.admission.len();
        if MAX_BYTES - 64 - used < bytes + 30 {
            break;
        }
        used += bytes;
        admissions.insert(padded.admission.clone(), item);
    }
    assert!(!next["retired"]
        .as_object()
        .unwrap()
        .contains_key("other-authority"));
    next["retired"]["other-authority"] = serde_json::Value::Array(Vec::new());
    let mut epochs = Vec::new();
    let mut free = MAX_BYTES - 64 - serde_json::to_vec(&next).unwrap().len() + 1;
    while free > 131 {
        let width = (free - 10).min(128);
        epochs.push(format!("{:04}{}", epochs.len(), "x".repeat(width - 4)));
        free -= width + 3;
    }
    epochs.push(format!("{:04}{}", epochs.len(), "x".repeat(free - 7)));
    next["retired"]["other-authority"] = serde_json::to_value(epochs).unwrap();
    assert_eq!(MAX_BYTES - serde_json::to_vec(&next).unwrap().len(), 64);
    next["registration"] = serde_json::Value::Null;
    next["registration_highwater"] = serde_json::json!(0);
    next["fences"] = serde_json::json!({});
    next["clock_floor"] = serde_json::json!(0);
    std::fs::write(&journal_path, serde_json::to_vec(&next).unwrap()).unwrap();
    let mut journal = Journal::open(path, Role::Host("host-1".into())).unwrap();
    let current = HostRegistration {
        host_instance: journal.instance().into(),
        ..current
    };
    journal
        .register_host(current.clone(), crate::api::execution::test_fixtures::CLOCK)
        .unwrap();
    journal.publish();
    assert_eq!(MAX_BYTES - std::fs::read(journal_path).unwrap().len(), 64);
    assert_eq!(journal.registration().unwrap(), Some(&current));
    (journal, current)
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires Linux qualified execution clock"
)]
async fn refused_near_capacity_registration_preserves_every_guarded_effect() {
    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let (journal, current) = near_capacity_journal(&path);
    let reader = journal.reader();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../briqyard-api/tests/fixtures/execution-continuation-v1.json"
    ))
    .unwrap();
    let active_operation: ActiveOperation =
        serde_json::from_value(fixture["active"].clone()).unwrap();
    let refused = HostRegistration {
        epoch: "epoch-2".into(),
        key_id: "n".repeat(128),
        generation: 2,
        ..current.clone()
    };
    let manager = GuardedManager::new(crate::machine::tests::channel_manager().await);
    let channel = Arc::new(
        GuardedHostExecutionChannel::new(
            manager,
            journal,
            "installer-secret".into(),
            "execution-secret".into(),
            vec![
                VerificationKey {
                    kid: refused.key_id.clone(),
                    role: access::KeyRole::Authority,
                    issuer: "authority".into(),
                    authority: Some(refused.authority.clone()),
                    public_key: refused.public_key,
                },
                VerificationKey {
                    kid: "central".into(),
                    role: access::KeyRole::Central,
                    issuer: "central".into(),
                    authority: None,
                    public_key: [1; 32],
                },
            ],
            "central".into(),
            "authority".into(),
            "runtime".into(),
            1,
        )
        .unwrap(),
    );
    channel.clock().unwrap();
    let lease = ActiveLease::from_committed(
        active_operation.clone(),
        &crate::api::execution::test_fixtures::sample(),
    )
    .unwrap();
    let _owner = channel
        .active
        .register(&active_operation.binding.admission, lease.clone())
        .unwrap();
    let before_bytes = std::fs::read(path.join("journal.json")).unwrap();
    let before: serde_json::Value = serde_json::from_slice(&before_bytes).unwrap();
    let response = router(channel.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/internal/execution/v1/register")
                .header(header::AUTHORIZATION, "Bearer installer-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&refused).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let after_bytes = std::fs::read(path.join("journal.json")).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&after_bytes).unwrap();
    assert!(
        after_bytes == before_bytes,
        "capacity refusal changed journal.json"
    );
    assert_eq!(after["fences"], before["fences"]);
    assert_eq!(after["retired"], before["retired"]);
    let journal = channel.journal.lock().await;
    assert_eq!(journal.registration().unwrap(), Some(&current));
    drop(journal);
    assert_eq!(reader.view().registration().unwrap(), Some(&current));
    lease
        .observe(
            &active_operation,
            &crate::api::execution::test_fixtures::sample(),
        )
        .unwrap();
}

#[tokio::test]
async fn ambiguous_registration_persistence_contains_active_leases_and_poisons_the_journal() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../briqyard-api/tests/fixtures/execution-continuation-v1.json"
    ))
    .unwrap();
    let evidence: ActiveOperation = serde_json::from_value(fixture["active"].clone()).unwrap();
    let sample = ClockSample {
        wall: Duration::from_secs(1035),
        monotonic: std::time::Instant::now(),
        uncertainty: Duration::from_secs(1),
    };
    let clock = Clock {
        now: 1010,
        uncertainty: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let mut journal = Journal::open(&path, Role::Host("host-1".into())).unwrap();
    let current = HostRegistration {
        authority: "authority-1".into(),
        epoch: "epoch-2".into(),
        key_id: "key-2".into(),
        public_key: [7; 32],
        host_instance: journal.instance().into(),
        generation: 2,
    };
    let active = Arc::new(GuardedOperations::default());
    register_host(&mut journal, &active, &current, clock).unwrap();

    let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
    let _owner = active
        .register(&evidence.binding.admission, lease.clone())
        .unwrap();
    lease.observe(&evidence, &sample).unwrap();

    std::fs::write(path.join("journal.next"), b"unresolved").unwrap();
    let next = HostRegistration {
        epoch: "epoch-3".into(),
        generation: 3,
        ..current.clone()
    };
    assert_eq!(
        register_host(&mut journal, &active, &next, clock),
        Err(StatusCode::CONFLICT)
    );
    assert!(lease.observe(&evidence, &sample).is_err());
    assert!(matches!(journal.owned(), Err(JournalError::Persistence)));
    assert!(matches!(
        journal.registration(),
        Err(JournalError::Persistence)
    ));
    assert!(matches!(
        journal.register_host(next.clone(), clock),
        Err(JournalError::Persistence)
    ));

    let later = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
    let _later_owner = active.register("later", later.clone()).unwrap();
    later.observe(&evidence, &sample).unwrap();
    assert_eq!(
        register_host(&mut journal, &active, &current, clock),
        Err(StatusCode::CONFLICT)
    );
    assert!(later.observe(&evidence, &sample).is_err());
}

#[test]
fn exact_millisecond_receipt_covers_inward_rounded_grant() {
    let receipt = InstalledProtection {
        installation: "i".into(),
        generation: 1,
        admission: "a".into(),
        expires_at_ms: 1_700_000_001_234,
        resources: vec![],
        resource_revision: "r".into(),
    };
    assert!(idle_receipt_covers(
        &receipt,
        1_700_000_001_234,
        1_700_000_001,
        1_700_000_001
    ));
    assert!(!idle_receipt_covers(
        &receipt,
        1_700_000_001_000,
        1_700_000_001,
        1_700_000_001
    ));
    assert!(!idle_receipt_covers(
        &receipt,
        1_700_000_001_234,
        1_700_000_002,
        1_700_000_002
    ));
}

#[test]
fn only_registered_authority_key_is_eligible_for_permit_verification() {
    let configured = vec![
        VerificationKey {
            kid: "central".into(),
            role: access::KeyRole::Central,
            issuer: "central".into(),
            authority: None,
            public_key: [1; 32],
        },
        VerificationKey {
            kid: "old".into(),
            role: access::KeyRole::Authority,
            issuer: "authority".into(),
            authority: Some("region".into()),
            public_key: [2; 32],
        },
        VerificationKey {
            kid: "current".into(),
            role: access::KeyRole::Authority,
            issuer: "authority".into(),
            authority: Some("region".into()),
            public_key: [3; 32],
        },
    ];
    let registration = HostRegistration {
        authority: "region".into(),
        epoch: "epoch".into(),
        key_id: "current".into(),
        public_key: [3; 32],
        host_instance: "host".into(),
        generation: 2,
    };
    let accepted = registered_keys(&configured, "authority", &registration).unwrap();
    assert_eq!(accepted.len(), 2);
    assert!(accepted.iter().any(|k| k.kid == "central"));
    assert!(accepted.iter().any(|k| k.kid == "current"));
    assert!(!accepted.iter().any(|k| k.kid == "old"));
    let wrong = HostRegistration {
        public_key: [2; 32],
        ..registration
    };
    assert!(registered_keys(&configured, "authority", &wrong).is_err());
}
