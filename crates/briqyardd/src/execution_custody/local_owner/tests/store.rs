use super::super::store::{Fail, FAIL};
use super::super::*;
use super::fixtures::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fail_at(point: Fail) {
    FAIL.set(Some(point));
}

struct Clear;

impl Drop for Clear {
    fn drop(&mut self) {
        FAIL.set(None);
    }
}

#[test]
fn a_failure_before_the_rename_leaves_the_old_attempt_and_no_temporary_file() {
    for point in [Fail::Temporary, Fail::FileSync] {
        let world = World::new();
        world.install().unwrap();
        let before = world.attempt();
        let bytes = std::fs::read(world.path().join("active.json")).unwrap();
        let _clear = Clear;
        fail_at(point);
        assert!(
            matches!(
                world.owner.allocate_lease(Resource::Daemon),
                Err(OwnerError::Io { .. })
            ),
            "{point:?}"
        );
        FAIL.set(None);
        assert_eq!(world.attempt(), before);
        assert_eq!(
            std::fs::read(world.path().join("active.json")).unwrap(),
            bytes
        );
        assert!(!world.path().join("active.json.tmp").exists(), "{point:?}");
        world.owner.allocate_lease(Resource::Daemon).unwrap();
        assert_eq!(world.version(), 2);
    }
}

#[test]
fn a_failure_after_the_rename_is_an_unknown_commit_that_is_never_repeated() {
    let world = World::new();
    world.install().unwrap();
    let _clear = Clear;
    fail_at(Fail::Rename);
    assert!(matches!(
        world.owner.allocate_lease(Resource::Daemon),
        Err(OwnerError::CommitUnknown)
    ));
    FAIL.set(None);
    let attempt = world.attempt();
    assert_eq!(
        attempt.version.get(),
        2,
        "the replaced file is what a reader sees"
    );
    assert!(attempt.daemon.lease.is_some());
    let lease = attempt.daemon.lease.clone();
    refused(
        world.owner.allocate_lease(Resource::Daemon),
        "already allocated",
    );
    assert_eq!(
        world.attempt().daemon.lease,
        lease,
        "the unknown commit was not redone"
    );
    assert_eq!(world.version(), 2);
}

#[test]
fn a_commit_over_a_changed_attempt_is_stale_and_writes_nothing() {
    let world = World::new();
    world.install().unwrap();
    let stale = world.attempt();
    world.owner.allocate_lease(Resource::Daemon).unwrap();
    let mut next = stale.clone();
    next.version = briqyard_api::execution::sealed::prim::PosInt::new(2).unwrap();
    let guard = world.owner.store.lock(true).unwrap();
    assert!(matches!(
        world.owner.store.commit(&guard, Some(&stale), &next),
        Err(OwnerError::Stale)
    ));
    let mut skipped = world.owner.store.load(&guard).unwrap().unwrap();
    let current = skipped.clone();
    skipped.version = briqyard_api::execution::sealed::prim::PosInt::new(9).unwrap();
    assert!(matches!(
        world.owner.store.commit(&guard, Some(&current), &skipped),
        Err(OwnerError::Refused(_))
    ));
    let mut same = current.clone();
    same.lockout = digest(0xee);
    assert!(
        world
            .owner
            .store
            .commit(&guard, Some(&current), &same)
            .is_err(),
        "no rewrite at the same version"
    );
    drop(guard);
    assert_eq!(world.attempt(), current);
}

#[test]
fn a_read_lock_cannot_commit() {
    let world = World::new();
    world.install().unwrap();
    let current = world.attempt();
    let mut next = current.clone();
    next.version = briqyard_api::execution::sealed::prim::PosInt::new(2).unwrap();
    let guard = world.owner.store.lock(false).unwrap();
    refused(
        world.owner.store.commit(&guard, Some(&current), &next),
        "exclusive lock",
    );
}

#[test]
fn an_active_file_that_is_not_private_canonical_and_valid_is_refused() {
    let world = World::new();
    world.install().unwrap();
    let file = world.path().join("active.json");
    let good = std::fs::read(&file).unwrap();
    let load = |world: &World| {
        world.owner.observe(&world.request(
            Resource::Daemon,
            briqyard_api::execution::sealed::owner::Point::Prearm,
        ))
    };

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    refused(load(&world), "not private");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let linked = world.path().join("alias");
    std::fs::hard_link(&file, &linked).unwrap();
    refused(load(&world), "not private");
    std::fs::remove_file(&linked).unwrap();

    let text = String::from_utf8(good.clone()).unwrap();
    for (what, tampered) in [
        ("an unknown field", text.replacen('{', "{\"extra\":1,", 1)),
        (
            "a missing field",
            text.replacen("\"enrolled\":null,", "", 1),
        ),
        (
            "a changed plan commitment",
            text.replacen(world.plan.exception.as_str(), "x", 0)
                .replacen(
                    &HexDigest::of(&world.bytes).to_string(),
                    &digest(0xee).to_string(),
                    1,
                ),
        ),
        (
            "a changed plan body",
            text.replacen("\"plan_bytes\":\"", "\"plan_bytes\":\"00", 1),
        ),
        ("trailing bytes", format!("{text}\n")),
    ] {
        std::fs::write(&file, tampered).unwrap();
        assert!(matches!(load(&world), Err(OwnerError::Codec(_))), "{what}");
        std::fs::write(&file, &good).unwrap();
    }
    std::fs::remove_file(&file).unwrap();
    symlink(world.path().join("elsewhere"), &file).unwrap();
    assert!(
        matches!(load(&world), Err(OwnerError::Io { .. })),
        "a link is never followed"
    );
    std::fs::remove_file(&file).unwrap();
    std::fs::write(&file, &good).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    load(&world).unwrap();
}

#[test]
fn the_store_directory_must_be_private_and_owned() {
    let world = World::new();
    let root = world.path();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(LocalOwner::rooted_at(&root, unsafe { libc::geteuid() }, world.host.clone()).is_err());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        LocalOwner::rooted_at(&root, unsafe { libc::geteuid() } + 1, world.host.clone()).is_err()
    );
    assert!(LocalOwner::rooted_at(
        &root.join("missing"),
        unsafe { libc::geteuid() },
        world.host.clone()
    )
    .is_err());
}
