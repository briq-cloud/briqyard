use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

fn clock() -> Clock {
    Clock {
        now: 1010,
        uncertainty: 1,
    }
}
fn sign(body: &impl Serialize, typ: &str, seed: u8, kid: &str) -> String {
    let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let head = json!({"alg":"EdDSA","typ":typ,"kid":kid,"v":1});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(head.to_string()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(body).unwrap())
    );
    format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).as_ref())
    )
}
struct Fixture {
    grant: Grant,
    grant_token: String,
    allocations: Vec<String>,
    permit: Permit,
    keys: Vec<VerificationKey>,
}
impl Fixture {
    fn new(epoch: &str) -> Self {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/execution-v1.json"))
                .unwrap();
        let grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
        let grant_token = fixture["grant_token"].as_str().unwrap().to_owned();
        let mut allocations = Vec::new();
        let mut refs = Vec::new();
        for (id, bucket, units) in [("general", "requests", 2), ("calls", "exec_calls", 1)] {
            let mut a: Allocation = serde_json::from_value(fixture["allocation"].clone()).unwrap();
            a.id = id.into();
            a.bucket = bucket.into();
            a.units = units;
            a.authority_epoch = epoch.into();
            let token = sign(&a, ALLOCATION_TYPE, 1, "central-test");
            refs.push(AllocationRef {
                id: a.id,
                epoch: a.epoch,
                digest: token_digest(&token),
                units: 1,
            });
            allocations.push(token);
        }
        let mut permit: Permit = serde_json::from_value(fixture["permit"].clone()).unwrap();
        permit.allocations = refs;
        permit.authority_epoch = epoch.into();
        let keys = [
            (1, "central-test", KeyRole::Central, "central", None),
            (
                2,
                "authority-test",
                KeyRole::Authority,
                "authority",
                Some("authority-1"),
            ),
        ]
        .into_iter()
        .map(|(seed, kid, role, issuer, authority)| VerificationKey {
            kid: kid.into(),
            role,
            issuer: issuer.into(),
            authority: authority.map(str::to_owned),
            public_key: Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .try_into()
                .unwrap(),
        })
        .collect();
        Self {
            grant,
            grant_token,
            allocations,
            permit,
            keys,
        }
    }
    fn trust(&self) -> Trust<'_> {
        Trust {
            keys: &self.keys,
            central_issuer: "central",
            authority_issuer: "authority",
            audience: "runtime",
        }
    }
    fn context(&self) -> DispatchContext<'_> {
        DispatchContext {
            principal: &self.grant.principal,
            team: &self.grant.team,
            subject: &self.grant.subject,
            target: &self.grant.target,
            resource_set: &self.grant.resource_set,
            metadata_revision: &self.grant.metadata_revision,
            authority: &self.permit.authority,
            authority_epoch: &self.permit.authority_epoch,
            installed_allocations: &self.permit.allocations,
            operation: self.permit.operation,
            request_digest: &self.permit.request_digest,
        }
    }
    fn delegation(&self) -> VerifiedDelegation {
        let context = self.context();
        verify_delegation(
            &self.grant_token,
            &self
                .allocations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &self.trust(),
            clock(),
            &DelegationContext {
                principal: context.principal,
                team: context.team,
                subject: context.subject,
                target: context.target,
                resource_set: context.resource_set,
                metadata_revision: context.metadata_revision,
                authority: context.authority,
                authority_epoch: context.authority_epoch,
            },
        )
        .unwrap()
    }
    fn bundle(&self) -> VerifiedBundle {
        verify_bundle(
            &self.grant_token,
            &sign(&self.permit, PERMIT_TYPE, 2, "authority-test"),
            &self
                .allocations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &self.trust(),
            clock(),
            &self.context(),
        )
        .unwrap()
    }
}
fn host(path: &Path, fixture: &Fixture) -> Journal {
    let mut j = Journal::open(path, Role::Host("host-1".into())).unwrap();
    let instance = j.instance().to_owned();
    j.fence(
        "authority-1",
        &fixture.permit.authority_epoch,
        &instance,
        clock(),
    )
    .unwrap();
    j.install(&fixture.bundle(), &instance, clock()).unwrap();
    j
}

#[test]
fn installation_highwater_and_restart_retire_old_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let mut journal = Journal::open(&path, Role::Host("host-1".into())).unwrap();
    let instance = journal.instance().to_owned();
    let registration = HostRegistration {
        authority: "authority-1".into(),
        epoch: "epoch-1".into(),
        key_id: "key-1".into(),
        public_key: [7; 32],
        host_instance: instance.clone(),
        generation: 1,
    };
    journal
        .register_host(registration.clone(), clock())
        .unwrap();
    journal.register_host(registration, clock()).unwrap();
    let fixture = Fixture::new("epoch-1");
    let target = fixture.grant.target.clone();
    let owner = HostOwnership {
        installation: "install-1".into(),
        generation: 1,
        team: fixture.grant.team.clone(),
        subject: fixture.grant.subject.clone(),
        metadata_revision: fixture.grant.metadata_revision.clone(),
        primary: target.clone(),
        public_seeds: vec![target.clone()],
        public_resources: vec![PublicResource {
            id: fixture.grant.subject.clone(),
            target,
        }],
        resource_set: fixture.grant.resource_set.clone(),
        host_instance: instance,
    };
    journal.install_ownership(owner.clone(), clock()).unwrap();
    let original = HostDelegation {
        id: "delegation-1".into(),
        version: 1,
        ownership: owner.installation.clone(),
        ownership_generation: owner.generation,
        grant_digest: "grant-one".into(),
        allocation_digests: vec![],
        principal: "key:principal".into(),
        expires_at: 1050,
    };
    journal
        .install_delegation(original.clone(), clock())
        .unwrap();
    journal
        .prepare(
            PreparedAdmission {
                admission: "prepared-v1".into(),
                delegation: original.id.clone(),
                grant_digest: original.grant_digest.clone(),
                permit_digest: "permit-one".into(),
                request_digest: "request-one".into(),
                allocation_refs: vec![],
                ownership: owner.installation.clone(),
                ownership_generation: owner.generation,
                host_instance: journal.instance().into(),
                expires_at: 1050,
                dispatched: false,
            },
            clock(),
        )
        .unwrap();
    let renewed = HostDelegation {
        version: 2,
        grant_digest: "grant-two".into(),
        ..original.clone()
    };
    journal
        .install_delegation(renewed.clone(), clock())
        .unwrap();
    assert!(journal
        .install_delegation(original.clone(), clock())
        .is_err());
    assert!(matches!(
        journal.mark_dispatched("prepared-v1", clock()),
        Err(Error::Binding)
    ));
    assert!(!journal.prepared("prepared-v1").unwrap().unwrap().dispatched);
    assert_eq!(journal.delegation("delegation-1").unwrap(), Some(&renewed));
    assert_eq!(
        journal.state.delegation_versions["delegation-1"],
        vec![original, renewed.clone()]
    );
    assert!(journal
        .install_delegation(
            HostDelegation {
                version: 3,
                principal: "key:another".into(),
                grant_digest: "grant-three".into(),
                ..renewed
            },
            clock()
        )
        .is_err());

    assert!(journal
        .install_ownership(
            HostOwnership {
                generation: 2,
                ..owner.clone()
            },
            clock()
        )
        .is_err());
    journal
        .invalidate_ownership("install-1", 2, clock())
        .unwrap();
    assert!(journal.install_ownership(owner, clock()).is_err());
    drop(journal);
    let journal = Journal::open(&path, Role::Host("host-1".into())).unwrap();
    assert!(journal.registration().unwrap().is_none());
    assert!(journal.installed_ownership("install-1").unwrap().is_none());
    assert!(journal.protection("old").unwrap().is_none());
    assert!(journal
        .state
        .retired
        .get("authority-1")
        .unwrap()
        .contains(&"epoch-1".into()));
}

#[test]
fn complete_vector_is_atomic_and_duplicates_never_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let mut f = Fixture::new("authority-epoch-1");
    let mut journal = host(&dir.path().join("host"), &f);
    let bundle = f.bundle();
    journal.consume(&bundle, clock()).unwrap();
    assert!(matches!(
        journal.consume(&bundle, clock()),
        Err(Error::AlreadyAdmitted)
    ));
    f.permit.admission = "second".into();
    assert!(matches!(
        journal.consume(&f.bundle(), clock()),
        Err(Error::Exhausted)
    ));
    assert_eq!(journal.state.allocations["general"].used, 1);
    assert_eq!(journal.state.allocations["calls"].used, 1);
    assert!(journal.status("second").unwrap().is_none());
    journal.finish(bundle.permit(), clock()).unwrap();
    assert_eq!(
        journal.status(&bundle.permit().admission).unwrap(),
        Some(Status::Finished)
    );
    assert!(matches!(
        journal.consume(&bundle, clock()),
        Err(Error::AlreadyAdmitted)
    ));
}
#[test]
fn reopen_rotates_instance_clears_allocations_and_preserves_no_replay_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let f = Fixture::new("authority-epoch-1");
    let mut j = host(&path, &f);
    let previous = j.instance().to_owned();
    j.consume(&f.bundle(), clock()).unwrap();
    drop(j);
    let mut j = Journal::open(&path, Role::Host("host-1".into())).unwrap();
    assert_ne!(previous, j.instance());
    assert!(j.state.allocations.is_empty());
    assert_eq!(
        j.status(&f.permit.admission).unwrap(),
        Some(Status::Consumed)
    );
    assert!(j.install(&f.bundle(), &previous, clock()).is_err());
    let instance = j.instance().to_owned();
    assert!(j
        .fence("authority-1", &f.permit.authority_epoch, &instance, clock())
        .is_err());
    let newer = Fixture::new("new-authority-epoch");
    j.fence(
        "authority-1",
        &newer.permit.authority_epoch,
        &instance,
        clock(),
    )
    .unwrap();
    j.install(&newer.bundle(), &instance, clock()).unwrap();
    assert!(matches!(
        j.consume(&newer.bundle(), clock()),
        Err(Error::AlreadyAdmitted)
    ));
}
#[test]
fn allocation_fence_refuses_delayed_old_epoch_and_repeated_install_preserves_debits() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new("old-epoch");
    let mut j = host(&dir.path().join("host"), &f);
    let instance = j.instance().to_owned();
    j.consume(&f.bundle(), clock()).unwrap();
    j.install(&f.bundle(), &instance, clock()).unwrap();
    assert_eq!(j.state.allocations["calls"].used, 1);
    j.fence("authority-1", "new-epoch", &instance, clock())
        .unwrap();
    assert!(matches!(
        j.consume(&f.bundle(), clock()),
        Err(Error::Binding)
    ));
    assert!(j.install(&f.bundle(), &instance, clock()).is_err());
    assert!(j
        .fence("authority-1", "old-epoch", &instance, clock())
        .is_err());
}
#[test]
fn exclusive_lock_wrong_role_symlink_and_replaced_inode_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let f = Fixture::new("epoch");
    let j = host(&path, &f);
    assert!(matches!(
        Journal::open(&path, Role::Host("host-1".into())),
        Err(Error::Ownership)
    ));
    std::fs::rename(path.join("writer.lock"), path.join("old.lock")).unwrap();
    std::os::unix::fs::symlink(path.join("old.lock"), path.join("writer.lock")).unwrap();
    assert!(matches!(j.status("unknown"), Err(Error::Ownership)));
    assert!(Journal::open(&path, Role::Host("host-1".into())).is_err());
    drop(j);
    std::fs::remove_file(path.join("writer.lock")).unwrap();
    assert!(Journal::open(&path, Role::Host("other-host".into())).is_err());
}
#[test]
fn uncertain_persistence_poisoning_never_licenses_replay_or_silent_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let f = Fixture::new("epoch");
    let mut j = host(&path, &f);
    std::fs::write(path.join("journal.next"), b"unresolved").unwrap();
    assert!(matches!(
        j.consume(&f.bundle(), clock()),
        Err(Error::Persistence)
    ));
    assert!(matches!(
        j.consume(&f.bundle(), clock()),
        Err(Error::Persistence)
    ));
    drop(j);
    assert!(Journal::open(&path, Role::Host("host-1".into())).is_err());
}
#[test]
fn prune_never_refunds_and_clock_rollback_cannot_revive_expired_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new("epoch");
    let mut j = host(&dir.path().join("host"), &f);
    j.consume(&f.bundle(), clock()).unwrap();
    j.prune(Clock {
        now: 1050,
        uncertainty: 1,
    })
    .unwrap();
    assert!(j.status(&f.permit.admission).unwrap().is_none());
    assert_eq!(j.state.allocations["calls"].used, 1);
    assert!(j.consume(&f.bundle(), clock()).is_err());
}
#[test]
fn issuer_releases_only_after_durable_full_reservation_and_retry_is_status_only() {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(
        &dir.path().join("authority"),
        Role::Authority("authority-1".into()),
    )
    .unwrap();
    let f = Fixture::new(j.instance());
    let mut issuer = DurableIssuer::new(
        j,
        Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap(),
        "authority-test".into(),
    )
    .unwrap();
    let allocations = f.allocations.iter().map(String::as_str).collect::<Vec<_>>();
    let mut preflight_token = String::new();
    let token = issuer
        .issue_with_preflight(
            IssueCredentials {
                grant: &f.grant_token,
                allocations: &allocations,
            },
            f.permit.clone(),
            &f.trust(),
            clock(),
            &f.context(),
            |placeholder| {
                preflight_token = placeholder.to_owned();
                assert!(verify_bundle(
                    &f.grant_token,
                    placeholder,
                    &allocations,
                    &f.trust(),
                    clock(),
                    &f.context()
                )
                .is_err());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(preflight_token.len(), token.len());
    assert_ne!(preflight_token, token);
    verify_bundle(
        &f.grant_token,
        &token,
        &allocations,
        &f.trust(),
        clock(),
        &f.context(),
    )
    .unwrap();
    assert_eq!(
        issuer.status(&f.permit.admission).unwrap(),
        Some(Status::Reserved)
    );
    assert!(matches!(
        issuer.issue(
            &f.grant_token,
            &allocations,
            f.permit.clone(),
            &f.trust(),
            clock(),
            &f.context()
        ),
        Err(IssueError::Journal(Error::AlreadyAdmitted))
    ));
}
#[test]
fn private_permissions_and_malformed_or_oversized_state_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Journal::open(&path, Role::Host("host-1".into())),
        Err(Error::Ownership)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(path.join("journal.json"), b"broken").unwrap();
    std::fs::set_permissions(
        path.join("journal.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(matches!(
        Journal::open(&path, Role::Host("host-1".into())),
        Err(Error::Persistence)
    ));
}

#[test]
fn issuer_can_prune_expired_receipts_without_rotating_its_authority() {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(
        &dir.path().join("authority"),
        Role::Authority("authority-1".into()),
    )
    .unwrap();
    let f = Fixture::new(j.instance());
    let mut issuer = DurableIssuer::new(
        j,
        Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap(),
        "authority-test".into(),
    )
    .unwrap();
    let instance = issuer.instance().to_owned();
    issuer
        .issue(
            &f.grant_token,
            &f.allocations.iter().map(String::as_str).collect::<Vec<_>>(),
            f.permit.clone(),
            &f.trust(),
            clock(),
            &f.context(),
        )
        .unwrap();
    issuer
        .prune(Clock {
            now: 1050,
            uncertainty: 1,
        })
        .unwrap();
    assert_eq!(issuer.instance(), instance);
    assert_eq!(issuer.status(&f.permit.admission).unwrap(), None);
}

#[test]
fn pre_permit_installation_requires_fences_and_never_resets_debits() {
    let dir = tempfile::tempdir().unwrap();
    let mut authority = Journal::open(
        &dir.path().join("authority"),
        Role::Authority("authority-1".into()),
    )
    .unwrap();
    let f = Fixture::new(authority.instance());
    let authority_instance = authority.instance().to_owned();
    authority
        .install_allocations(&f.delegation(), &authority_instance, clock())
        .unwrap();
    assert!(authority.state.admissions.is_empty());
    assert_eq!(authority.state.allocations.len(), 2);
    authority.reserve(&f.bundle(), clock()).unwrap();
    authority
        .install_allocations(&f.delegation(), &authority_instance, clock())
        .unwrap();
    assert_eq!(authority.state.allocations["general"].used, 1);
    assert_eq!(authority.state.allocations["calls"].used, 1);

    let path = dir.path().join("host");
    let mut host = Journal::open(&path, Role::Host("host-1".into())).unwrap();
    let host_instance = host.instance().to_owned();
    assert!(matches!(
        host.install_allocations(&f.delegation(), &host_instance, clock()),
        Err(Error::Binding)
    ));
    assert!(host.state.allocations.is_empty());
    host.fence("authority-1", &authority_instance, &host_instance, clock())
        .unwrap();
    host.install_allocations(&f.delegation(), &host_instance, clock())
        .unwrap();
    host.consume(&f.bundle(), clock()).unwrap();
    host.install_allocations(&f.delegation(), &host_instance, clock())
        .unwrap();
    assert_eq!(host.state.allocations["calls"].used, 1);
    assert_eq!(host.state.allocations["general"].used, 1);

    // A different signed vector cannot replace a previously acknowledged allocation.
    let mut changed = Fixture::new(&authority_instance);
    let mut allocation: Allocation = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(changed.allocations[1].split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    allocation.units += 1;
    changed.allocations[1] = sign(&allocation, ALLOCATION_TYPE, 1, "central-test");
    assert!(matches!(
        host.install_allocations(&changed.delegation(), &host_instance, clock()),
        Err(Error::Binding)
    ));
    assert_eq!(host.state.allocations["calls"].allocation.units, 1);
    assert_eq!(host.state.allocations["general"].used, 1);

    drop(host);
    let mut host = Journal::open(&path, Role::Host("host-1".into())).unwrap();
    assert!(matches!(
        host.install_allocations(&f.delegation(), &host_instance, clock()),
        Err(Error::Binding)
    ));
    let instance = host.instance().to_owned();
    assert!(matches!(
        host.install_allocations(&f.delegation(), &instance, clock()),
        Err(Error::Binding)
    ));
    assert!(matches!(
        host.fence("authority-1", &authority_instance, &instance, clock()),
        Err(Error::Binding)
    ));
}

#[test]
fn incompatible_journal_evidence_is_refused_without_rewrite() {
    for unknown_field in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority");
        let journal = Journal::open(&path, Role::Authority("authority-1".into())).unwrap();
        drop(journal);
        let file = path.join("journal.json");
        let mut state: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        if unknown_field {
            state["future_retained_fence"] = json!({"revoked": true});
        } else {
            state["v"] = json!(255);
        }
        let evidence = serde_json::to_vec(&state).unwrap();
        std::fs::write(&file, &evidence).unwrap();
        assert!(Journal::open(&path, Role::Authority("authority-1".into())).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), evidence);
        assert!(!path.join("journal.next").exists());
    }
}
