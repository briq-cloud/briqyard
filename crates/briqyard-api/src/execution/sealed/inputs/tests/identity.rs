//! Erratum 2 §3: the bootstrap guard and the staged candidate are the target release asset.
//! The control gives each guard the candidate's bytes and build; each case changes one side.

use super::*;

fn control() -> (Inputs, Plan) {
    let mut inputs: Inputs = decode(INPUTS).unwrap();
    for resource in [&mut inputs.daemon, &mut inputs.authority] {
        resource.guard.file.sha256 = resource.candidate.file.sha256.clone();
        resource.guard.file.bytes = resource.candidate.file.bytes;
        resource.guard.build = resource.candidate.build.clone();
    }
    (inputs, plan(d(INPUTS)))
}

fn check(inputs: &Inputs, plan: &Plan, releases: &Releases) -> Result<(), CodecError> {
    inputs.check_target_asset_identity(plan, &releases.target)
}

#[test]
fn the_same_asset_and_build_at_distinct_paths_is_accepted() {
    let (inputs, plan) = control();
    check(&inputs, &plan, &releases()).unwrap();
}

#[test]
fn the_accepted_fixture_is_not_this_profile_and_bind_is_unchanged() {
    let inputs: Inputs = decode(INPUTS).unwrap();
    assert_eq!(
        check(&inputs, &plan(d(INPUTS)), &releases()).unwrap_err(),
        value_err("program is not the target release asset")
    );
    bound(|_| {}, |_| {}, |_| {}).unwrap();
}

#[test]
fn every_difference_in_bytes_build_path_or_release_refuses() {
    let releases = releases();
    type Case = (&'static str, Box<dyn Fn(&mut Inputs, &mut Plan)>);
    let cases: Vec<Case> = vec![
        (
            "rebuilt guard bytes",
            Box::new(|i, _| i.daemon.guard.file.sha256 = d(b"a reproducible-looking rebuild")),
        ),
        (
            "rebuilt candidate bytes",
            Box::new(|i, _| i.authority.candidate.file.sha256 = d(b"rebuild")),
        ),
        (
            "guard length",
            Box::new(|i, _| i.daemon.guard.file.bytes = PosInt::new(1).unwrap()),
        ),
        (
            "guard build",
            Box::new(|i, _| i.authority.guard.build = Build::new("guard-v1").unwrap()),
        ),
        (
            "plan build",
            Box::new(|_, p| p.dbuild = Build::new("another").unwrap()),
        ),
        (
            "authority guard is the daemon's asset",
            Box::new(|i, _| {
                i.authority.guard.file.sha256 = i.daemon.candidate.file.sha256.clone();
            }),
        ),
    ];
    for (name, mutate) in cases {
        let (mut inputs, mut plan) = control();
        mutate(&mut inputs, &mut plan);
        assert_eq!(
            check(&inputs, &plan, &releases).unwrap_err(),
            value_err("program is not the target release asset"),
            "{name}"
        );
    }
    let (mut inputs, plan) = control();
    inputs.daemon.guard.file.path = inputs.daemon.candidate.file.path.clone();
    assert_eq!(
        check(&inputs, &plan, &releases).unwrap_err(),
        value_err("guard and candidate share a path")
    );
    let (mut inputs, plan) = control();
    inputs.target_release.release_id = PosInt::new(99).unwrap();
    assert_eq!(
        check(&inputs, &plan, &releases).unwrap_err(),
        value_err("target release")
    );
}
