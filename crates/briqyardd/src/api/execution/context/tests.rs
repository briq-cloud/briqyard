use super::*;
use crate::guestc::{
    active_lease::ActiveLease,
    active_operations::{ActiveOperationGuard, ActiveOperations, OriginalIntent},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::execution::{
    self as access,
    admission::{
        ActiveOperation, ActivePhase, HostDelegation, HostOperationPolicy, HostOwnership,
        InstalledProtection, PreparedAdmission, Status,
    },
    clock::ClockSample,
    ActiveOperationBinding, Clock, DispatchContext, ExecutionMode, Grant, Permit, PublicResource,
    Trust, VerificationKey,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::time::Duration;
use tokio::sync::Barrier;

const CLOCK: Clock = Clock {
    now: 1010,
    uncertainty: 1,
};
const HOST: &str = "host-1";
const INSTALLER: &[u8] = b"synthetic installer";
const EXECUTION: &[u8] = b"synthetic execution";

#[derive(Default)]
struct TestGate(Publication<Option<Arc<CommittedCohorts>>>);
impl SealedContextSource for TestGate {
    fn committed_cohorts(&self) -> Option<Arc<CommittedCohorts>> {
        self.0.read().unwrap().clone()
    }
}
impl TestGate {
    fn publish(&self, current: Option<Arc<VerifiedCohort>>, retired: Vec<Arc<VerifiedCohort>>) {
        *self.0.write().unwrap() =
            CommittedCohorts::new(current, retired, NonZeroUsize::new(10).unwrap()).map(Arc::new);
    }
}

fn cohort(registration: &HostRegistration, successor: bool) -> Arc<VerifiedCohort> {
    let hash = |bytes: &[u8]| HexDigest::from_raw(Sha256::digest(bytes).into());
    Arc::new(VerifiedCohort {
        context: Reg::from_native(registration)
            .unwrap()
            .ctx(&Ident::new(HOST).unwrap()),
        members: Members {
            hi: hash(if successor {
                b"successor installer"
            } else {
                INSTALLER
            }),
            he: hash(if successor {
                b"successor execution"
            } else {
                EXECUTION
            }),
            ni: hash(if successor {
                b"successor northbound installer"
            } else {
                b"old northbound installer"
            }),
            ng: hash(if successor {
                b"successor northbound gateway"
            } else {
                b"old northbound gateway"
            }),
            tr: Some(hash(if successor {
                b"successor transition"
            } else {
                b"old transition"
            })),
        },
        release: hash(if successor {
            b"new release receipt"
        } else {
            b"old release receipt"
        }),
    })
}

fn sample() -> ClockSample {
    ClockSample {
        wall: Duration::from_secs(CLOCK.now),
        monotonic: std::time::Instant::now(),
        uncertainty: Duration::from_secs(CLOCK.uncertainty),
    }
}

fn sign(body: &impl serde::Serialize, typ: &str, seed: u8, kid: &str) -> String {
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

struct Fixture {
    journal: Journal,
    registration: HostRegistration,
    intent: PreparedAdmission,
    permit: Permit,
    active: ActiveOperation,
}

fn active_operation(path: &std::path::Path) -> Fixture {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../briqyard-api/tests/fixtures/execution-v1.json"
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

fn reserve(
    registry: &Arc<ActiveOperations>,
    request: RequestIdentity,
    dispatched: PreparedAdmission,
    permit: Permit,
    active: &ActiveOperation,
) -> (ActiveOperationGuard, ActiveLease) {
    let owner = registry
        .reserve(
            &permit.admission.clone(),
            Some(OriginalIntent {
                request,
                dispatched,
                permit,
            }),
        )
        .unwrap();
    let lease = ActiveLease::from_committed(active.clone(), &sample()).unwrap();
    owner.activate(lease.clone()).unwrap();
    (owner, lease)
}

#[tokio::test]
async fn unenrolled_channel_opens_without_registration_but_sealed_context_never_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&dir.path().join("journal"), Role::Host(HOST.into())).unwrap();
    let plain = AdmissionTurns::new(&journal).unwrap();
    assert!(plain
        .capture(RequestRole::Installer, INSTALLER, INSTALLER)
        .is_ok());
    let gate = Arc::new(TestGate::default());
    let sealed = AdmissionTurns::new(&journal)
        .unwrap()
        .with_sealed_contexts(gate.clone());
    let registration = HostRegistration {
        authority: "authority-1".into(),
        epoch: "first-epoch".into(),
        key_id: "authority-test".into(),
        public_key: [7; 32],
        host_instance: journal.instance().into(),
        generation: 1,
    };
    assert!(sealed
        .capture(RequestRole::Installer, INSTALLER, INSTALLER)
        .is_err());
    let current = cohort(&registration, false);
    gate.publish(Some(current.clone()), vec![]);
    assert!(sealed
        .capture(RequestRole::Installer, INSTALLER, INSTALLER)
        .is_err());
    let _turn = sealed.turn.write().await;
    journal.register_host(registration, CLOCK).unwrap();
    sealed.publish(&journal).unwrap();
    assert!(sealed
        .capture(RequestRole::Installer, INSTALLER, INSTALLER)
        .is_ok());
    let mut reused = (*current).clone();
    reused.context.epoch = Ident::new("other-epoch").unwrap();
    gate.publish(Some(current), vec![Arc::new(reused)]);
    assert!(sealed
        .capture(RequestRole::Installer, INSTALLER, INSTALLER)
        .is_err());
}

#[tokio::test]
async fn queued_discovery_cannot_read_successor_ownership_or_touch_a_retired_lease() {
    let dir = tempfile::tempdir().unwrap();
    let Fixture {
        journal,
        registration,
        intent,
        permit,
        active,
    } = active_operation(&dir.path().join("journal"));
    let gate = Arc::new(TestGate::default());
    let old = cohort(&registration, false);
    gate.publish(Some(old.clone()), vec![]);
    let turns = AdmissionTurns::new(&journal)
        .unwrap()
        .with_sealed_contexts(gate.clone());
    let journal = Mutex::new(journal);
    let registry = Arc::new(ActiveOperations::default());
    let effect = turns
        .capture(RequestRole::Execution, EXECUTION, b"")
        .unwrap();
    let (_owner, lease) = reserve(&registry, effect, intent, permit, &active);
    let transition = turns.turn.write().await;
    let queued = Barrier::new(2);
    let discovery = async {
        let request = turns
            .capture(RequestRole::Installer, INSTALLER, b"")
            .unwrap();
        queued.wait().await;
        let _read = turns.read(&request, &journal).await?;
        let ledger = journal.lock().await;
        Ok::<_, StatusCode>(
            ledger
                .installed_ownership("successor-owner")
                .unwrap()
                .unwrap()
                .public_resources
                .clone(),
        )
    };
    let advance = async {
        queued.wait().await;
        let mut ledger = journal.lock().await;
        let mut successor = registration.clone();
        successor.epoch = "new-epoch".into();
        successor.generation += 1;
        ledger.register_host(successor.clone(), CLOCK).unwrap();
        let b = &active.binding;
        ledger
            .install_ownership(
                HostOwnership {
                    installation: "successor-owner".into(),
                    generation: 1,
                    team: b.team.clone(),
                    subject: b.subject.clone(),
                    primary: b.target.clone(),
                    metadata_revision: b.metadata_revision.clone(),
                    public_seeds: vec![b.target.clone()],
                    public_resources: vec![PublicResource {
                        id: b.subject.clone(),
                        target: b.target.clone(),
                    }],
                    resource_set: b.resource_set.clone(),
                    host_instance: b.host_instance.clone(),
                },
                CLOCK,
            )
            .unwrap();
        turns.publish(&ledger).unwrap();
        gate.publish(Some(cohort(&successor, true)), vec![old]);
        drop(transition);
    };
    let (result, ()) = tokio::join!(discovery, advance);
    assert_eq!(result, Err(StatusCode::CONFLICT));
    lease.observe(&active, &sample()).unwrap();
    let fresh = turns
        .capture(RequestRole::Installer, b"successor installer", b"")
        .unwrap();
    let _read = turns.read(&fresh, &journal).await.unwrap();
    assert!(registry
        .in_context(&active.binding.admission, &fresh)
        .is_err());
    assert_eq!(
        journal.lock().await.registration().unwrap().unwrap().epoch,
        "new-epoch"
    );
}

#[tokio::test]
async fn retired_owner_can_fsync_only_its_collected_intent_and_cancel_cannot_finish() {
    for cancel in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let Fixture {
            journal,
            registration,
            intent,
            permit,
            active,
        } = active_operation(&path);
        let gate = Arc::new(TestGate::default());
        let old = cohort(&registration, false);
        gate.publish(Some(old.clone()), vec![]);
        let turns = AdmissionTurns::new(&journal)
            .unwrap()
            .with_sealed_contexts(gate.clone());
        let journal = Mutex::new(journal);
        let registry = Arc::new(ActiveOperations::default());
        let request = turns
            .capture(RequestRole::Execution, EXECUTION, b"")
            .unwrap();
        let admission = permit.admission.clone();
        let (owner, lease) = reserve(
            &registry,
            request.clone(),
            intent.clone(),
            permit.clone(),
            &active,
        );
        {
            let _turn = turns.read(&request, &journal).await.unwrap();
            let mut ledger = journal.lock().await;
            assert!(owner.finish(&turns, &mut ledger, &sample()).is_err());
            assert_eq!(ledger.status(&admission).unwrap(), Some(Status::Consumed));
        }
        lease.collect_for_test(&sample()).await.unwrap();
        {
            let crossed = Arc::new(ActiveOperations::default());
            let mut wrong = intent;
            wrong.request_digest.push('x');
            let (wrong_owner, wrong_lease) =
                reserve(&crossed, request.clone(), wrong, permit, &active);
            wrong_lease.collect_for_test(&sample()).await.unwrap();
            let _turn = turns.terminal_turn().await;
            let mut ledger = journal.lock().await;
            assert!(wrong_owner.finish(&turns, &mut ledger, &sample()).is_err());
            assert_eq!(ledger.status(&admission).unwrap(), Some(Status::Consumed));
        }
        let retire = turns.turn.write().await;
        let (terminal_turns, terminal_journal) = (&turns, &journal);
        let mut terminal = Box::pin(async move {
            let _turn = terminal_turns.terminal_turn().await;
            let mut ledger = terminal_journal.lock().await;
            owner.finish(terminal_turns, &mut ledger, &sample())
        });
        assert!(futures::poll!(&mut terminal).is_pending());
        assert!(registry.in_context(&admission, &request).unwrap().is_some());
        gate.publish(None, vec![old]);
        drop(retire);
        assert!(turns.read(&request, &journal).await.is_err());
        assert!(turns
            .capture(RequestRole::Execution, EXECUTION, EXECUTION)
            .is_err());
        if cancel {
            drop(terminal);
        } else {
            terminal.await.unwrap();
        }
        assert!(registry.in_context(&admission, &request).unwrap().is_none());
        let mut ledger = journal.into_inner();
        assert!(ledger.mark_dispatched(&admission, CLOCK).is_err());
        let saved = ledger.active_operation(&admission).unwrap().unwrap();
        let phase = if cancel {
            ActivePhase::Active
        } else {
            ActivePhase::Finished
        };
        assert_eq!(
            saved,
            &ActiveOperation {
                phase,
                ..active.clone()
            }
        );
        let status = if cancel {
            Status::Consumed
        } else {
            Status::Finished
        };
        assert_eq!(ledger.status(&admission).unwrap(), Some(status));
        drop(turns);
        drop(ledger);
        let reopened = Journal::open(&path, Role::Host(HOST.into())).unwrap();
        let phase = if cancel {
            ActivePhase::Recovered
        } else {
            ActivePhase::Finished
        };
        assert_eq!(
            reopened.active_operation(&admission).unwrap(),
            Some(&ActiveOperation { phase, ..active })
        );
        assert_eq!(reopened.status(&admission).unwrap(), Some(status));
    }
}

#[tokio::test]
async fn current_installer_revocation_ends_the_retired_owners_effect() {
    let dir = tempfile::tempdir().unwrap();
    let Fixture {
        journal,
        registration,
        intent,
        permit,
        active,
    } = active_operation(&dir.path().join("journal"));
    let gate = Arc::new(TestGate::default());
    let old = cohort(&registration, false);
    gate.publish(Some(old.clone()), vec![]);
    let turns = AdmissionTurns::new(&journal)
        .unwrap()
        .with_sealed_contexts(gate.clone());
    let mut journal = Mutex::new(journal);
    let registry = Arc::new(ActiveOperations::default());
    let effect = turns
        .capture(RequestRole::Execution, EXECUTION, b"")
        .unwrap();
    let (_owner, lease) = reserve(&registry, effect, intent, permit, &active);
    let transition = turns.turn.write().await;
    let mut successor = registration.clone();
    successor.epoch = "new-epoch".into();
    successor.generation += 1;
    journal
        .get_mut()
        .register_host(successor.clone(), CLOCK)
        .unwrap();
    turns.publish(journal.get_mut()).unwrap();
    gate.publish(Some(cohort(&successor, true)), vec![old]);
    drop(transition);
    let current = turns
        .capture(RequestRole::Installer, b"successor installer", b"")
        .unwrap();
    let _read = turns.read(&current, &journal).await.unwrap();
    let ledger = journal.lock().await;
    let revoked = ledger
        .active_operation(&active.binding.admission)
        .unwrap()
        .unwrap()
        .clone();
    assert_eq!(revoked.phase, ActivePhase::Revoked);
    assert!(registry
        .in_context(&active.binding.admission, &current)
        .is_err());
    lease.observe(&active, &sample()).unwrap();
    registry.revoke_where(|_| Some(revoked.clone()));
    assert!(lease.observe(&active, &sample()).is_err());
}
