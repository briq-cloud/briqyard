use super::*;

fn setup(
    path: &Path,
) -> (
    Journal,
    Fixture,
    ActiveOperationBinding,
    InstalledProtection,
) {
    let mut f = Fixture::new("epoch-1");
    f.grant.limits.execution_mode = Some(ExecutionMode::RenewableExecV1);
    f.grant.limits.max_duration_seconds = 60;
    f.grant_token = sign(&f.grant, GRANT_TYPE, 1, "central-test");
    f.permit.grant_digest = token_digest(&f.grant_token);
    f.permit.limits = f.grant.limits.clone();
    let mut j = host(path, &f);
    let instance = j.instance().to_owned();
    j.register_host(
        HostRegistration {
            authority: f.permit.authority.clone(),
            epoch: f.permit.authority_epoch.clone(),
            key_id: "authority-test".into(),
            public_key: f.keys[1].public_key,
            host_instance: instance.clone(),
            generation: 1,
        },
        clock(),
    )
    .unwrap();
    j.install_ownership(
        HostOwnership {
            installation: "owner".into(),
            generation: 1,
            team: f.grant.team.clone(),
            subject: f.grant.subject.clone(),
            metadata_revision: f.grant.metadata_revision.clone(),
            primary: f.grant.target.clone(),
            public_seeds: vec![f.grant.target.clone()],
            public_resources: vec![PublicResource {
                id: f.grant.subject.clone(),
                target: f.grant.target.clone(),
            }],
            resource_set: f.grant.resource_set.clone(),
            host_instance: instance.clone(),
        },
        clock(),
    )
    .unwrap();
    j.install_delegation(
        HostDelegation {
            id: "delegation".into(),
            version: 1,
            ownership: "owner".into(),
            ownership_generation: 1,
            grant_digest: f.permit.grant_digest.clone(),
            allocation_digests: f
                .permit
                .allocations
                .iter()
                .map(|a| a.digest.clone())
                .collect(),
            principal: f.grant.principal.clone(),
            expires_at: f.grant.exp,
        },
        clock(),
    )
    .unwrap();
    let permit_digest = token_digest(&sign(&f.permit, PERMIT_TYPE, 2, "authority-test"));
    j.prepare(
        PreparedAdmission {
            admission: f.permit.admission.clone(),
            delegation: "delegation".into(),
            grant_digest: f.permit.grant_digest.clone(),
            permit_digest: permit_digest.clone(),
            request_digest: f.permit.request_digest.clone(),
            allocation_refs: f.permit.allocations.clone(),
            ownership: "owner".into(),
            ownership_generation: 1,
            host_instance: instance.clone(),
            expires_at: f.permit.exp,
            dispatched: false,
        },
        clock(),
    )
    .unwrap();
    j.mark_dispatched(&f.permit.admission, clock()).unwrap();
    let b = ActiveOperationBinding {
        operation_id: "operation".into(),
        admission: f.permit.admission.clone(),
        grant_digest: f.permit.grant_digest.clone(),
        permit_digest,
        request_digest: f.permit.request_digest.clone(),
        authority: f.permit.authority.clone(),
        authority_epoch: f.permit.authority_epoch.clone(),
        host_instance: instance,
        ownership: "owner".into(),
        ownership_generation: 1,
        policy_revision: "policy".into(),
        delegation: "delegation".into(),
        delegation_version: 1,
        principal: f.grant.principal.clone(),
        source: f.grant.source.clone(),
        team: f.grant.team.clone(),
        subject: f.grant.subject.clone(),
        metadata_revision: f.grant.metadata_revision.clone(),
        target: f.grant.target.clone(),
        resource_set: f.grant.resource_set.clone(),
        limits: f.permit.limits.clone(),
        guest_timeout_ms: 60_000,
        started_at_ms: 1_010_000,
        operation_deadline_ms: 1_090_000,
    };
    let protection = InstalledProtection {
        installation: "owner".into(),
        generation: 1,
        admission: "idle-active".into(),
        expires_at_ms: 1_050_000,
        resources: b.resource_set.resources.clone(),
        resource_revision: b.resource_set.revision.clone(),
    };
    j.record_protection(protection.clone(), clock()).unwrap();
    (j, f, b, protection)
}
fn continuation(b: &ActiveOperationBinding, p: &InstalledProtection) -> OperationContinuation {
    OperationContinuation {
        v: 1,
        iss: "central".into(),
        aud: "runtime".into(),
        iat: 1030,
        nbf: 1030,
        exp: 1070,
        checked_at: 1030,
        previous_sequence: 0,
        sequence: 1,
        binding: b.clone(),
        protection: p.clone(),
    }
}
fn later() -> Clock {
    Clock {
        now: 1035,
        uncertainty: 1,
    }
}
fn verify(
    f: &Fixture,
    c: &OperationContinuation,
    b: &ActiveOperationBinding,
) -> Result<VerifiedContinuation, VerifyError> {
    verify_continuation(
        &sign(c, CONTINUATION_TYPE, 1, "central-test"),
        &f.trust(),
        later(),
        b,
    )
}
fn active(j: &mut Journal, f: &Fixture, b: &ActiveOperationBinding, p: &InstalledProtection) {
    j.consume(&f.bundle(), clock()).unwrap();
    j.record_consumed_operation(&f.bundle(), b.clone(), p.clone(), clock())
        .unwrap();
    j.acknowledge_active_operation(&b.admission, clock())
        .unwrap();
}
fn extended(j: &mut Journal, p: &InstalledProtection) -> InstalledProtection {
    let p = InstalledProtection {
        installation: "owner".into(),
        admission: "idle-extension".into(),
        expires_at_ms: 1_080_000,
        ..p.clone()
    };
    j.record_protection(p.clone(), later()).unwrap();
    p
}

#[test]
fn continuation_requires_active_first_frame_protection_and_exact_order_without_new_debits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut j, f, b, p) = setup(&dir.path().join("host"));
    assert!(j
        .record_consumed_operation(&f.bundle(), b.clone(), p.clone(), clock())
        .is_err());
    j.consume(&f.bundle(), clock()).unwrap();
    j.record_consumed_operation(&f.bundle(), b.clone(), p.clone(), clock())
        .unwrap();
    let p2 = extended(&mut j, &p);
    let c = continuation(&b, &p2);
    let verified = verify(&f, &c, &b).unwrap();
    assert!(
        j.continue_operation(&verified, later()).is_err(),
        "consumed is not active evidence"
    );
    j.acknowledge_active_operation(&b.admission, later())
        .unwrap();
    let used = j
        .state
        .allocations
        .values()
        .map(|a| a.used)
        .collect::<Vec<_>>();
    let result = j.continue_operation(&verified, later()).unwrap();
    assert_eq!(result.sequence, 1);
    assert_eq!(
        result.lease_expires_at, 1070,
        "lease crosses allocation expiry at1060"
    );
    assert_eq!(
        used,
        j.state
            .allocations
            .values()
            .map(|a| a.used)
            .collect::<Vec<_>>()
    );
    assert!(
        j.continue_operation(&verified, later()).is_err(),
        "duplicate cannot extend/debit"
    );
    j.prune(Clock {
        now: 1065,
        uncertainty: 1,
    })
    .unwrap();
    assert_eq!(j.status(&b.admission).unwrap(), Some(Status::Consumed));
    assert_eq!(
        j.active_operation(&b.admission).unwrap().unwrap().sequence,
        1
    );
}

#[test]
fn expiry_revoke_finish_and_recovery_never_resurrect_active_commands() {
    for terminal in ["expiry", "revoke", "ownership", "finish", "recovery"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host");
        let (mut j, f, b, p) = setup(&path);
        active(&mut j, &f, &b, &p);
        let p2 = extended(&mut j, &p);
        let c = continuation(&b, &p2);
        let verified = verify(&f, &c, &b).unwrap();
        let mut at = later();
        match terminal {
            "expiry" => at.now = 1039, // upper bound reaches old1040 expiry
            "revoke" => j.revoke_delegation(&b.delegation, 1, later()).unwrap(),
            "ownership" => j.invalidate_ownership(&b.ownership, 1, later()).unwrap(),
            "finish" => j.finish(&f.permit, later()).unwrap(),
            "recovery" => {
                drop(j);
                j = Journal::open(&path, Role::Host("host-1".into())).unwrap();
                assert_eq!(
                    j.active_operation(&b.admission).unwrap().unwrap().phase,
                    ActivePhase::Recovered
                );
            }
            _ => unreachable!(),
        }
        assert!(j.continue_operation(&verified, at).is_err(), "{terminal}");
        assert!(j.acknowledge_active_operation(&b.admission, at).is_err());
    }
}

#[test]
fn signed_continuation_cannot_cross_bindings_modes_limits_source_or_protection() {
    let dir = tempfile::tempdir().unwrap();
    let (mut j, f, b, p) = setup(&dir.path().join("host"));
    active(&mut j, &f, &b, &p);
    let p2 = extended(&mut j, &p);
    let c = continuation(&b, &p2);
    for field in [
        "request",
        "policy",
        "source",
        "target",
        "mode",
        "limit",
        "deadline",
        "protection",
        "freshness",
        "sequence",
    ] {
        let mut changed = c.clone();
        match field {
            "request" => changed.binding.request_digest = token_digest("other"),
            "policy" => changed.binding.policy_revision = "other".into(),
            "source" => changed.binding.source.id = "other".into(),
            "target" => changed.binding.target.run = "other".into(),
            "mode" => changed.binding.limits.execution_mode = None,
            "limit" => changed.binding.limits.max_duration_seconds = 61,
            "deadline" => changed.exp = 1091,
            "protection" => changed.protection.expires_at_ms = 1_060_000,
            "freshness" => changed.checked_at = 1000,
            "sequence" => changed.sequence = 2,
            _ => unreachable!(),
        }
        assert!(verify(&f, &changed, &b).is_err(), "{field}");
    }
    let mut uninstalled = c.clone();
    uninstalled.protection.admission = "missing".into();
    let verified = verify(&f, &uninstalled, &b).unwrap();
    assert!(j.continue_operation(&verified, later()).is_err());
    let authority_signed = sign(&c, CONTINUATION_TYPE, 2, "authority-test");
    assert!(verify_continuation(&authority_signed, &f.trust(), later(), &b).is_err());
}

#[test]
fn renewable_mode_is_strict_and_cannot_issue_a_partial_path() {
    let dir = tempfile::tempdir().unwrap();
    let (j, f, _, _) = setup(&dir.path().join("host"));
    for value in [Value::Null, json!("future")] {
        let mut limits = serde_json::to_value(&f.permit.limits).unwrap();
        limits["execution_mode"] = value;
        assert!(serde_json::from_value::<Limits>(limits).is_err());
    }
    drop(j);
    let journal = Journal::open(
        &dir.path().join("issuer"),
        Role::Authority("authority-1".into()),
    )
    .unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let mut issuer = DurableIssuer::new(journal, key, "authority-test".into()).unwrap();
    assert!(issuer
        .issue_with_preflight(
            IssueCredentials {
                grant: &f.grant_token,
                allocations: &f.allocations.iter().map(String::as_str).collect::<Vec<_>>(),
            },
            f.permit.clone(),
            &f.trust(),
            clock(),
            &f.context(),
            |_| panic!("unsupported mode must refuse before preflight or signing")
        )
        .is_err());
    assert_eq!(issuer.status(&f.permit.admission).unwrap(), None);
}
