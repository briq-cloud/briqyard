//! The commit fence after the rename (ADR 0149): which outcomes are unknown, which are known
//! with a cleanup failure, and what each leaves on disk for the next load.

use super::super::store::{Fail, FAIL};
use super::super::*;
use super::fixtures::*;
use super::flow::{daemon_at_guard, guard_proc};
use super::store::{fail_at, intent, raw_attempt, reopened, sha, Clear};

fn fenced(world: &World, owner: &LocalOwner<std::sync::Arc<Host>>) {
    assert!(owner
        .observe(&world.request(Resource::Daemon, Point::Prearm))
        .is_err());
    refused(owner.allocate_lease(Resource::Daemon), "uncertain commit");
    refused(owner.install_fragment(Resource::Daemon), "uncertain commit");
    refused(
        owner.consume(Resource::Daemon, &measured(&guard_proc())),
        "uncertain commit",
    );
    refused(world.install(), "uncertain commit");
}

#[test]
fn a_failure_before_the_commit_is_known_is_unknown_with_the_durable_fence_and_no_projection() {
    for point in [Fail::Rename, Fail::ReadBack, Fail::ReadBackMismatch] {
        let world = World::new();
        world.install().unwrap();
        let previous = std::fs::read(world.path().join("active.json")).unwrap();
        let _clear = Clear;
        fail_at(point);
        assert!(
            matches!(
                world.owner.allocate_lease(Resource::Daemon),
                Err(OwnerError::CommitUnknown)
            ),
            "{point:?}"
        );
        FAIL.set(None);
        let visible = std::fs::read(world.path().join("active.json")).unwrap();
        assert_eq!(raw_attempt(&world).version.get(), 2, "{point:?}");
        assert_eq!(
            std::fs::read_to_string(intent(&world)).unwrap(),
            format!("previous={}\nnext={}\n", sha(&previous), sha(&visible)),
            "{point:?}: the marker is untouched"
        );
        fenced(&world, &world.owner);
        fenced(&world, &reopened(&world));
        assert_eq!(
            std::fs::read(world.path().join("active.json")).unwrap(),
            visible,
            "{point:?}: nothing rewrote the ambiguous bytes"
        );
    }
}

#[test]
fn a_cleanup_failure_after_a_confirmed_commit_is_known_and_never_releases_the_launch() {
    for point in [Fail::UnlinkIntent, Fail::SyncAfterUnlink] {
        let (world, ..) = daemon_at_guard();
        let before = world.attempt();
        let previous = std::fs::read(world.path().join("active.json")).unwrap();
        let _clear = Clear;
        fail_at(point);
        let outcome = world
            .owner
            .consume(Resource::Daemon, &measured(&guard_proc()));
        FAIL.set(None);
        match &outcome {
            Err(OwnerError::CommittedCleanupFailed { .. }) => {}
            other => panic!("{point:?}: wanted a known cleanup failure, got {other:?}"),
        }
        let text = outcome.unwrap_err().to_string();
        assert!(
            text.contains("known") && text.contains("do not retry"),
            "{text}"
        );

        let visible = std::fs::read(world.path().join("active.json")).unwrap();
        let landed = raw_attempt(&world);
        assert_eq!(landed.version.get(), before.version.get() + 1, "{point:?}");
        assert!(
            landed.daemon.consumed.is_some(),
            "{point:?}: the commit is on disk"
        );

        let again = reopened(&world);
        if point == Fail::UnlinkIntent {
            assert_eq!(
                std::fs::read_to_string(intent(&world)).unwrap(),
                format!("previous={}\nnext={}\n", sha(&previous), sha(&visible)),
            );
            fenced(&world, &world.owner);
            fenced(&world, &again);
        } else {
            assert!(!intent(&world).exists(), "the unlink itself succeeded");
            assert_eq!(
                world.attempt(),
                landed,
                "a later load reads the known version"
            );
            assert_eq!(
                again.store.load(&again.store.lock(false).unwrap()).unwrap(),
                Some(landed.clone())
            );
            refused(
                world
                    .owner
                    .consume(Resource::Daemon, &measured(&guard_proc())),
                "already consumed",
            );
            refused(
                again.consume(Resource::Daemon, &measured(&guard_proc())),
                "already consumed",
            );
        }
        assert_eq!(
            std::fs::read(world.path().join("active.json")).unwrap(),
            visible,
            "{point:?}: no second version and no second effect"
        );
    }
}

#[test]
fn after_a_crash_in_the_cleanup_either_restart_outcome_is_safe() {
    let (world, ..) = daemon_at_guard();
    let previous = std::fs::read(world.path().join("active.json")).unwrap();
    world
        .owner
        .consume(Resource::Daemon, &measured(&guard_proc()))
        .unwrap();
    let visible = std::fs::read(world.path().join("active.json")).unwrap();
    let marker = format!("previous={}\nnext={}\n", sha(&previous), sha(&visible));

    std::fs::write(intent(&world), &marker).unwrap();
    fenced(&world, &reopened(&world));

    std::fs::remove_file(intent(&world)).unwrap();
    let restarted = reopened(&world);
    refused(
        restarted.consume(Resource::Daemon, &measured(&guard_proc())),
        "already consumed",
    );
    assert_eq!(
        world.attempt().daemon.consumed,
        raw_attempt(&world).daemon.consumed
    );
}
