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

fn raw_attempt(world: &World) -> Attempt {
    decode(&std::fs::read(world.path().join("active.json")).unwrap()).unwrap()
}

fn intent(world: &World) -> std::path::PathBuf {
    world.path().join("commit.intent")
}

fn reopened(world: &World) -> LocalOwner<std::sync::Arc<Host>> {
    LocalOwner::rooted_at(
        &world.path(),
        unsafe { libc::geteuid() },
        world.host.clone(),
    )
    .unwrap()
}

fn sha(bytes: &[u8]) -> String {
    HexDigest::of(bytes).to_string()
}

#[test]
fn a_failure_after_the_rename_is_an_unknown_commit_that_fences_every_reader_and_is_never_repeated()
{
    let world = World::new();
    world.install().unwrap();
    let previous = std::fs::read(world.path().join("active.json")).unwrap();
    let _clear = Clear;
    fail_at(Fail::Rename);
    assert!(matches!(
        world.owner.allocate_lease(Resource::Daemon),
        Err(OwnerError::CommitUnknown)
    ));
    FAIL.set(None);
    let visible = std::fs::read(world.path().join("active.json")).unwrap();
    let attempt = raw_attempt(&world);
    assert_eq!(attempt.version.get(), 2, "the replaced file is on disk");
    assert!(attempt.daemon.lease.is_some());

    refused(
        world.observe(Resource::Daemon, Point::Prearm),
        "uncertain commit",
    );
    refused(
        world.owner.allocate_lease(Resource::Daemon),
        "uncertain commit",
    );
    refused(
        world.owner.allocate_lease(Resource::Authority),
        "uncertain commit",
    );
    refused(
        world.owner.install_fragment(Resource::Daemon),
        "uncertain commit",
    );
    refused(world.install(), "uncertain commit");
    assert_eq!(
        std::fs::read(world.path().join("active.json")).unwrap(),
        visible,
        "no later attempt rewrote or blessed the ambiguous bytes"
    );

    let again = reopened(&world);
    assert!(again
        .observe(&world.request(Resource::Daemon, Point::Prearm))
        .is_err());
    refused(again.allocate_lease(Resource::Daemon), "uncertain commit");
    assert_eq!(
        std::fs::read(world.path().join("active.json")).unwrap(),
        visible
    );

    let record = std::fs::read_to_string(intent(&world)).unwrap();
    assert_eq!(
        record,
        format!("previous={}\nnext={}\n", sha(&previous), sha(&visible)),
        "the marker names the expected and the observed bytes for an operator"
    );
}

#[test]
fn a_marker_left_by_a_crash_between_the_intent_and_the_rename_fences_without_an_error_to_remember()
{
    let world = World::new();
    world.install().unwrap();
    let bytes = std::fs::read(world.path().join("active.json")).unwrap();
    std::fs::write(
        intent(&world),
        format!("previous={}\nnext={}\n", sha(&bytes), sha(b"never renamed")),
    )
    .unwrap();
    refused(
        world.observe(Resource::Daemon, Point::Prearm),
        "uncertain commit",
    );
    refused(
        world.owner.allocate_lease(Resource::Daemon),
        "uncertain commit",
    );
    assert_eq!(
        std::fs::read(world.path().join("active.json")).unwrap(),
        bytes
    );
}

#[test]
fn any_marker_fences_even_one_that_is_not_a_regular_private_file() {
    let world = World::new();
    world.install().unwrap();
    symlink("active.json", intent(&world)).unwrap();
    refused(
        world.observe(Resource::Daemon, Point::Prearm),
        "uncertain commit",
    );
    std::fs::remove_file(intent(&world)).unwrap();
    std::fs::create_dir(intent(&world)).unwrap();
    refused(
        world.observe(Resource::Daemon, Point::Prearm),
        "uncertain commit",
    );
}

#[test]
fn known_commits_and_early_failures_leave_no_marker_and_stay_readable() {
    let world = World::new();
    world.install().unwrap();
    assert!(!intent(&world).exists());
    world.owner.allocate_lease(Resource::Daemon).unwrap();
    assert!(
        !intent(&world).exists(),
        "a known commit clears its own marker"
    );
    for point in [Fail::Temporary, Fail::FileSync] {
        let _clear = Clear;
        fail_at(point);
        assert!(matches!(
            world.owner.allocate_lease(Resource::Authority),
            Err(OwnerError::Io { .. })
        ));
        FAIL.set(None);
        assert!(
            !intent(&world).exists(),
            "{point:?}: the old attempt stands, no fence"
        );
        assert_eq!(world.version(), 2);
    }
    world.owner.allocate_lease(Resource::Authority).unwrap();
    assert_eq!(world.version(), 3);
    world.observe(Resource::Daemon, Point::Prearm).unwrap();
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
