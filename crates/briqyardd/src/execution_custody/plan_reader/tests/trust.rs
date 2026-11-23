use super::*;
use std::os::unix::fs::symlink;

fn load(world: &World) -> Result<EnrolledTrust, PlanReadError> {
    world.loader().load(&world.plan.x, &world.plan.registered)
}

#[test]
fn the_exact_record_yields_the_enrolled_keys() {
    let world = World::new();
    let trust = load(&world).unwrap();
    assert_eq!(trust.record().rk, FixtureSigner::rk().key());
    assert_eq!(trust.record().bk, FixtureSigner::bk().key());
    assert_eq!(trust.rk().raw(), &FixtureSigner::rk().public_key());
    assert_eq!(trust.bk().raw(), &FixtureSigner::bk().public_key());
}

#[test]
fn an_unavailable_record_fails_and_nothing_substitutes() {
    let world = World::new();
    std::fs::remove_file(world.trust_file()).unwrap();
    let error = refused(load(&world));
    assert!(matches!(error, PlanReadError::Io { .. }), "{error}");
    let other_serial = refused(world.loader().load(&x(2), &world.plan.registered));
    assert!(
        matches!(other_serial, PlanReadError::Io { .. }),
        "{other_serial}"
    );
    let other_alias = refused(world.loader().load(&world.plan.x, &id("alias.test")));
    assert!(
        matches!(other_alias, PlanReadError::Io { .. }),
        "{other_alias}"
    );
}

#[test]
fn the_production_loader_is_root_only() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    says(&refused(TrustLoader::system()), "only root");
}

#[test]
fn a_symlinked_directory_component_is_not_followed() {
    let world = World::new();
    let staging = world.trust_dir().parent().unwrap().to_path_buf();
    let elsewhere = world.dir.path().join("elsewhere");
    std::fs::rename(&staging, &elsewhere).unwrap();
    symlink(&elsewhere, &staging).unwrap();
    assert!(matches!(refused(load(&world)), PlanReadError::Io { .. }));
}

#[test]
fn a_symlinked_leaf_is_not_followed() {
    let world = World::new();
    let real = world.dir.path().join("real.json");
    std::fs::rename(world.trust_file(), &real).unwrap();
    symlink(&real, world.trust_file()).unwrap();
    assert!(matches!(refused(load(&world)), PlanReadError::Io { .. }));
}

#[test]
fn a_hardlinked_record_is_refused() {
    let world = World::new();
    std::fs::hard_link(world.trust_file(), world.dir.path().join("alias.json")).unwrap();
    says(&refused(load(&world)), "single-link regular file");
}

#[test]
fn a_record_that_is_not_a_regular_file_is_refused() {
    let world = World::new();
    std::fs::remove_file(world.trust_file()).unwrap();
    nix::unistd::mkfifo(
        &world.trust_file(),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    says(&refused(load(&world)), "single-link regular file");
}

#[test]
fn a_record_readable_by_others_is_refused() {
    let world = World::new();
    std::fs::set_permissions(world.trust_file(), std::fs::Permissions::from_mode(0o640)).unwrap();
    says(&refused(load(&world)), "single-link regular file");
}

#[test]
fn a_directory_that_is_not_private_is_refused() {
    for level in [
        "briqyard-sealed",
        "briqyard-sealed/plan-reader",
        "briqyard-sealed/plan-reader/v1",
    ] {
        let world = World::new();
        let dir = world.trust_root().join(level);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        says(&refused(load(&world)), "not private");
    }
    let world = World::new();
    std::fs::set_permissions(world.trust_dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
    says(&refused(load(&world)), "not private");
}

#[test]
fn a_writable_anchor_is_refused() {
    let world = World::new();
    std::fs::set_permissions(world.trust_root(), std::fs::Permissions::from_mode(0o770)).unwrap();
    says(&refused(load(&world)), "foreign or writable");
}

#[test]
fn foreign_ownership_is_refused() {
    let world = World::new();
    let foreign = TrustLoader::rooted_at(
        &world.trust_root(),
        Ownership {
            uid: own().uid + 1,
            gid: own().gid,
        },
    );
    says(
        &refused(foreign.load(&world.plan.x, &world.plan.registered)),
        "foreign or writable",
    );
}

#[test]
fn a_noncanonical_or_oversized_record_is_refused() {
    let world = World::new();
    let canonical = encode(&trust_record(
        world.plan.x.clone(),
        "registered.test",
        world.plan.rk,
        world.plan.bk,
    ))
    .unwrap();
    for bad in [
        [canonical.clone(), b"\n".to_vec()].concat(),
        [b" ".to_vec(), canonical.clone()].concat(),
        b"{}".to_vec(),
        vec![b'{'; 70_000],
    ] {
        write_private(&world.trust_file(), &bad);
        let error = refused(load(&world));
        assert!(matches!(error, PlanReadError::Trust(_)), "{error}");
    }
    write_private(&world.trust_file(), b"");
    assert!(matches!(refused(load(&world)), PlanReadError::Trust(_)));
}

#[test]
fn another_operations_or_aliases_record_is_refused() {
    let world = World::new();
    let mut other_op = world.plan.x.clone();
    other_op.op = digest(9);
    let mut other_host = world.plan.x.clone();
    other_host.host = id("intrinsic.other");
    for (x, registered) in [
        (other_op, "registered.test"),
        (other_host, "registered.test"),
        (world.plan.x.clone(), "alias.test"),
    ] {
        world.install_trust(&trust_record(x, registered, world.plan.rk, world.plan.bk));
        says(&refused(load(&world)), "another operation");
    }
}

#[test]
fn weak_or_shared_enrolled_keys_are_refused() {
    let world = World::new();
    let same = FixtureSigner::rk().key();
    write_private(
        &world.trust_file(),
        &encode(&trust_record(
            world.plan.x.clone(),
            "registered.test",
            same,
            same,
        ))
        .unwrap(),
    );
    assert!(matches!(refused(load(&world)), PlanReadError::Trust(_)));
    let weak = KeyBytes::from_array([0; 32]);
    world.install_trust(&trust_record(
        world.plan.x.clone(),
        "registered.test",
        weak,
        FixtureSigner::bk().key(),
    ));
    says(&refused(load(&world)), "refused public key");
}
