use super::*;
use crate::guestc::{
    active_lease::ActiveLease,
    active_operations::{ActiveOperationGuard, ActiveOperations, OriginalIntent},
};
use briqyard_api::execution::admission::{
    ActiveOperation, ActivePhase, HostOwnership, PreparedAdmission, Status,
};
use briqyard_api::execution::{Permit, PublicResource};
use std::{
    fs::DirBuilder,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::DirBuilderExt, process::CommandExt},
    },
};
use tokio::sync::Barrier;

const INSTALLER: &[u8] = b"synthetic installer";

pub(crate) use crate::api::execution::test_fixtures::{active_operation, sample};
use crate::api::execution::test_fixtures::{Fixture, CLOCK, EXECUTION, HOST};

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

pub(crate) fn reserve(
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

/// A restart reads the durable journal bytes under a lock nobody has held. Reopening the
/// dropped journal's own directory is not a barrier: a process another test thread forks
/// meanwhile holds a copy of the old lock until it execs.
fn restart_from_durable_image(path: &std::path::Path) -> (tempfile::TempDir, Journal) {
    let image = tempfile::tempdir().unwrap();
    let root = image.path().join("journal");
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    std::fs::copy(path.join("journal.json"), root.join("journal.json")).unwrap();
    let journal = Journal::open(&root, Role::Host(HOST.into())).unwrap();
    (image, journal)
}

#[test]
fn restart_image_opens_while_a_forked_child_still_holds_the_old_journal_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let journal = Journal::open(&path, Role::Host(HOST.into())).unwrap();
    let (mut forked, forked_write) = std::io::pipe().unwrap();
    let (release_read, release) = std::io::pipe().unwrap();
    let release_fd = release.as_raw_fd();
    let child = std::thread::spawn(move || {
        let mut command = std::process::Command::new("true");
        unsafe {
            command.pre_exec(move || {
                libc::close(release_fd);
                (&forked_write).write_all(&[1])?;
                (&release_read).read(&mut [0]).map(drop)
            });
        }
        command.status().unwrap()
    });
    forked.read_exact(&mut [0]).unwrap();
    drop(journal);
    assert!(matches!(
        Journal::open(&path, Role::Host(HOST.into())),
        Err(briqyard_api::execution::admission::Error::Ownership)
    ));
    let (_image, restarted) = restart_from_durable_image(&path);
    assert_eq!(restarted.role(), &Role::Host(HOST.into()));
    drop(release);
    assert!(child.join().unwrap().success());
    drop(restarted);
    Journal::open(&path, Role::Host(HOST.into())).unwrap();
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
        let (_image, reopened) = restart_from_durable_image(&path);
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
