//! The shared companion vectors of owner-layer erratum 2: B's file, copied byte for byte and
//! reproduced here row by row. Native never edits it. Each row is
//! `name TAB kind TAB input TAB expected`; `expected` is a digest (or `a:b:c:d` for a unit), `accept`
//! or `refuse`. A refusal must come from validation: no row may be repaired into an answer.

use crate::execution::sealed::canonical::{decode, h};
use crate::execution::sealed::custody::Resource;
use crate::execution::sealed::inputs::{Listeners, Path, Program};
use crate::execution::sealed::owner::ArmReceipt;
use crate::execution::sealed::preimage::Argv;
use crate::execution::sealed::prim::{Build, HexDigest};
use crate::execution::sealed::unit_policy::*;
use serde::Deserialize;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/owner_v1/sealed_owner_units_v1.vectors"
));
const VECTORS_SHA256: &str = "8d317e519e8c0d216c462ddcc47f9e97a7a2694e31d0a03e685ca47452b29b72";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FragmentInput {
    bytes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgvInput {
    exec: String,
    args: Vec<Token>,
    x: Option<Transition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FdstoreInput {
    listeners: Listeners,
    store: StoreInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitInput {
    role: Resource,
    policy: UnitPolicy,
    phase: Phase,
    x: Transition,
    listeners: Listeners,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInput {
    path: String,
    bytes: u64,
    sha256: HexDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramInput {
    file: FileInput,
    build: Build,
}

impl ProgramInput {
    fn program(&self) -> Program {
        use crate::execution::sealed::inputs::File;
        use crate::execution::sealed::prim::PosInt;
        Program {
            file: File {
                path: Path::new(&self.file.path).unwrap(),
                bytes: PosInt::new(self.file.bytes).unwrap(),
                sha256: self.file.sha256.clone(),
            },
            build: self.build.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleInput {
    guard: ProgramInput,
    candidate: ProgramInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetInput {
    sha256: HexDigest,
    bytes: u64,
    build: Build,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetInput {
    role: RoleInput,
    target: TargetInput,
}

fn parse<T: serde::de::DeserializeOwned>(
    input: &str,
) -> Result<T, crate::execution::sealed::canonical::CodecError> {
    serde_json::from_str(input).map_err(|_| crate::execution::sealed::canonical::CodecError::Schema)
}

/// What native computes for one row; an error is a refusal.
fn evaluate(
    kind: &str,
    input: &str,
) -> Result<String, crate::execution::sealed::canonical::CodecError> {
    Ok(match kind {
        "fragment" => fragment_from_base64url(&parse::<FragmentInput>(input)?.bytes)?.to_string(),
        "argv" => {
            let row: ArgvInput = parse(input)?;
            argv_digest(&row.exec, &row.args, row.x.as_ref())?.to_string()
        }
        "sandbox" => parse::<SandboxInput>(input)?
            .canonical()?
            .digest()?
            .to_string(),
        "fdstore" => {
            let row: FdstoreInput = parse(input)?;
            fdstore_digest(&row.listeners, row.store)?.to_string()
        }
        "unit" => {
            let row: UnitInput = parse(input)?;
            let unit = row
                .policy
                .expected(row.role, row.phase, &row.x, &row.listeners)?;
            format!(
                "{}:{}:{}:{}",
                unit.fragment, unit.argv, unit.sandbox, unit.fdstore
            )
        }
        "arm" => h(&decode::<ArmReceipt>(input.as_bytes())?)?.to_string(),
        "asset" => {
            let row: AssetInput = parse(input)?;
            same_target_asset(
                &row.role.guard.program(),
                &row.role.candidate.program(),
                &row.target.sha256,
                row.target.bytes,
                &row.target.build,
            )?;
            "accept".to_owned()
        }
        _ => return Err(crate::execution::sealed::canonical::CodecError::Schema),
    })
}

fn rows() -> Vec<[&'static str; 4]> {
    VECTORS
        .strip_suffix('\n')
        .unwrap()
        .split('\n')
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            fields.try_into().expect("four tab-separated fields")
        })
        .collect()
}

#[test]
fn the_mirrored_file_is_exactly_the_shared_source() {
    use sha2::{Digest, Sha256};
    assert_eq!(VECTORS.len(), 43765);
    assert_eq!(
        hex::encode(Sha256::digest(VECTORS.as_bytes())),
        VECTORS_SHA256
    );
    assert_eq!(rows().len(), 63);
    assert!(VECTORS.ends_with('\n') && !VECTORS.contains('\r'));
}

#[test]
fn every_row_is_reproduced_and_every_refusal_comes_from_validation() {
    let mut accepted = 0;
    let mut refused = 0;
    for [name, kind, input, expected] in rows() {
        let got = evaluate(kind, input);
        match expected {
            "refuse" => {
                assert!(got.is_err(), "{name}: expected a refusal, got {got:?}");
                refused += 1;
            }
            _ => {
                assert_eq!(got.as_deref(), Ok(expected), "{name}");
                accepted += 1;
            }
        }
    }
    assert_eq!((accepted, refused), (39, 24));
}

#[test]
fn refusals_are_not_repaired_and_accepted_rows_are_distinct_answers() {
    let by_name: std::collections::BTreeMap<&str, [&str; 4]> =
        rows().into_iter().map(|row| (row[0], row)).collect();
    let digest = |name: &str| by_name[name][3];
    assert_ne!(
        digest("argv/daemon/guarded"),
        digest("argv/daemon/guarded-other-serial")
    );
    assert_ne!(
        digest("argv/daemon/guarded"),
        digest("argv/daemon/guarded-other-op")
    );
    assert_ne!(
        digest("argv/daemon/guarded"),
        digest("argv/daemon/reordered")
    );
    assert_eq!(
        digest("sandbox/daemon/guarded"),
        digest("sandbox/daemon/set-order-is-irrelevant")
    );
    assert_ne!(
        digest("fdstore/daemon"),
        digest("fdstore/same-count-other-order")
    );
    assert_ne!(
        digest("arm/daemon/version-7"),
        digest("arm/daemon/version-8")
    );
    assert_ne!(
        digest("arm/daemon/version-7"),
        digest("arm/daemon/other-leaf")
    );
}

#[test]
fn each_refusal_has_the_reason_its_row_is_about() {
    use crate::execution::sealed::canonical::CodecError::{Schema, Value};
    let asset = Value("program is not the target release asset");
    let expected = [
        ("fragment/empty", Value("unit fragment size")),
        ("fragment/padded", Value("base64url")),
        ("sandbox/daemon/unknown-capability", Schema),
        (
            "sandbox/daemon/duplicate-gid",
            Value("duplicate set member"),
        ),
        ("sandbox/daemon/unsupported-protect-mode", Schema),
        (
            "sandbox/daemon/relative-path",
            Value("canonical absolute path"),
        ),
        (
            "sandbox/daemon/unrestricted-with-names",
            Value("address families"),
        ),
        (
            "sandbox/daemon/duplicate-bind-destination",
            Value("duplicate bind destination"),
        ),
        (
            "sandbox/daemon/duplicate-environment-name",
            Value("duplicate set member"),
        ),
        ("fdstore/unknown-preserve", Schema),
        ("asset/daemon/rebuilt-digest", asset),
        ("asset/daemon/other-length", asset),
        ("asset/daemon/other-candidate-build", asset),
        ("asset/daemon/other-guard-build", asset),
        ("asset/daemon/guard-digest-not-target", asset),
        (
            "asset/daemon/both-lengths-equal-but-not-the-approved-count",
            asset,
        ),
        ("asset/daemon/guard-length-not-target", asset),
        (
            "asset/daemon/candidate-at-guard-path",
            Value("guard and candidate share a path"),
        ),
    ];
    let mut expected: std::collections::BTreeMap<String, _> = expected
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    for role in ["daemon", "authority"] {
        expected.insert(
            format!("argv/{role}/guarded-without-x"),
            Value("placeholder outside a guarded unit"),
        );
        expected.insert(
            format!("unit/{role}/split-flag-guarded-refused"),
            Value("command is not the role's guard command"),
        );
        expected.insert(
            format!("argv/{role}/argv0-not-exec"),
            Value("argv[0] is not the executable"),
        );
    }
    let refusals: Vec<_> = rows()
        .into_iter()
        .filter(|row| row[3] == "refuse")
        .collect();
    assert_eq!(refusals.len(), expected.len());
    for [name, kind, input, _] in refusals {
        assert_eq!(evaluate(kind, input).unwrap_err(), expected[name], "{name}");
    }
}

#[test]
fn a_placeholder_token_is_exactly_one_typed_field() {
    use crate::execution::sealed::canonical::CodecError::Schema;
    let argv = |token: &str| {
        format!(
            "{{\"args\":[\"/usr/local/bin/briqyardd\",{token}],\"exec\":\"/usr/local/bin/briqyardd\",\"x\":{{\"op\":\"{}\",\"serial\":7}}}}",
            "a".repeat(64)
        )
    };
    assert!(evaluate("argv", &argv("{\"x\":\"op\"}")).is_ok());
    for token in [
        "{\"x\":\"op\",\"extra\":true}",
        "{\"x\":\"other\"}",
        "{\"extra\":\"op\"}",
        "{}",
    ] {
        assert_eq!(
            evaluate("argv", &argv(token)).unwrap_err(),
            Schema,
            "{token}"
        );
    }
}

fn transition(op: char, serial: u64) -> Transition {
    serde_json::from_str(&format!(
        "{{\"op\":\"{}\",\"serial\":{serial}}}",
        op.to_string().repeat(64)
    ))
    .unwrap()
}

#[test]
fn the_guard_command_is_the_roles_native_vector_with_one_derived_directory() {
    let x = transition('a', 7);
    assert_eq!(
        guard_argv(Resource::Daemon, &x)
            .unwrap()
            .digest()
            .unwrap()
            .to_string(),
        "c9e8bea4551fa70dbc5e4b59473c276f637f05c370214c7855bc84561eb017ed"
    );
    assert_eq!(
        guard_argv(Resource::Authority, &x)
            .unwrap()
            .digest()
            .unwrap()
            .to_string(),
        "420ef88c1b21979a0911c890b1115e181d2ad559582eee0e743ee69a0326eb93"
    );
    let daemon = guard_argv(Resource::Daemon, &x).unwrap();
    assert_eq!(daemon.args.len(), 8);
    assert_eq!(
        daemon.args[7].as_str(),
        format!("/var/lib/briqyard/sealed-ops/{}/7/daemon", "a".repeat(64))
    );
    let other_op = guard_argv(Resource::Daemon, &transition('b', 7)).unwrap();
    let other_serial = guard_argv(Resource::Daemon, &transition('a', 12)).unwrap();
    assert_ne!(other_op.digest().unwrap(), daemon.digest().unwrap());
    assert!(other_serial.args[7].as_str().ends_with("/12/daemon"));
    assert!(check_guard_argv(Resource::Daemon, &daemon, &x).is_ok());
    assert!(check_guard_argv(Resource::Daemon, &other_serial, &x).is_err());
}

#[test]
fn a_split_or_relabeled_guard_command_hashes_but_is_refused_by_policy() {
    let x = transition('a', 7);
    let op = "a".repeat(64);
    let split = Argv::new(
        "/usr/local/bin/briqyardd",
        &[
            "/usr/local/bin/briqyardd",
            "--config",
            "/etc/briqyard/config.yaml",
            "sealed-guard",
            "--resource",
            "daemon",
            "--op",
            &op,
            "--serial",
            "7",
        ],
    )
    .unwrap();
    assert!(
        split.digest().is_ok(),
        "the codec hashes any well-formed vector"
    );
    assert!(check_guard_argv(Resource::Daemon, &split, &x).is_err());

    let wrong = |args: &[&str]| Argv::new(args[0], args).unwrap();
    let daemon_dir = format!("/var/lib/briqyard/sealed-ops/{op}/7/daemon");
    let authority_dir = format!("/var/lib/briq-execution-authority/sealed-ops/{op}/7/authority");
    let guard_for = |sub: &str| {
        wrong(&[
            "/usr/local/bin/briqyardd",
            "--config",
            "/etc/briqyard/config.yaml",
            sub,
            "--resource",
            "daemon",
            "--operation-dir",
            &daemon_dir,
        ])
    };
    assert!(check_guard_argv(Resource::Daemon, &guard_for("sealed-guard"), &x).is_ok());
    assert!(
        check_guard_argv(Resource::Daemon, &guard_for("sealed-custodian"), &x).is_err(),
        "a custodian relabeled as a guard"
    );
    let authority_command = guard_argv(Resource::Authority, &x).unwrap();
    assert!(check_guard_argv(Resource::Daemon, &authority_command, &x).is_err());
    let daemon_scope_for_authority = guard_argv(Resource::Daemon, &x).unwrap();
    assert!(check_guard_argv(Resource::Authority, &daemon_scope_for_authority, &x).is_err());
    let authority = guard_argv(Resource::Authority, &x).unwrap();
    assert!(authority.args[8].as_str() == authority_dir);
    for tail in [
        format!("{daemon_dir}/"),
        format!("/var/lib/briqyard/sealed-ops/{op}/7/../7/daemon"),
        format!("/var/lib/briqyard/sealed-ops/{op}/07/daemon"),
        format!("/var/lib/briqyard/sealed-ops/{}/7/daemon", "b".repeat(64)),
        "/var/lib/briqyard/sealed-ops/other/7/daemon".to_owned(),
    ] {
        let mut args: Vec<String> = guard_argv(Resource::Daemon, &x)
            .unwrap()
            .args
            .iter()
            .map(|a| a.as_str().to_owned())
            .collect();
        args[7] = tail.clone();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let alias = Argv::new(refs[0], &refs).unwrap();
        assert!(
            check_guard_argv(Resource::Daemon, &alias, &x).is_err(),
            "{tail}"
        );
    }
}

#[test]
fn split_flag_commands_hash_at_the_codec_and_refuse_at_the_phase_policy() {
    let split: Vec<_> = rows()
        .into_iter()
        .filter(|row| row[2].contains("\"--op\""))
        .map(|row| (row[0], row[1], row[3] == "refuse"))
        .collect();
    assert_eq!(
        split,
        [
            ("argv/daemon/split-flags-hash-only", "argv", false),
            ("unit/daemon/split-flag-guarded-refused", "unit", true),
            ("argv/authority/split-flags-hash-only", "argv", false),
            ("unit/authority/split-flag-guarded-refused", "unit", true),
        ]
    );
}

#[test]
fn the_approved_length_is_the_actual_length_not_the_declared_pair() {
    let by_name: std::collections::BTreeMap<&str, [&str; 4]> =
        rows().into_iter().map(|row| (row[0], row)).collect();
    let both_declared = by_name["asset/daemon/both-lengths-equal-but-not-the-approved-count"];
    assert!(both_declared[2].contains("\"bytes\":4097"));
    assert!(both_declared[2].contains("\"target\":{\"build\":\"0.2.16\",\"bytes\":4096,"));
    assert!(evaluate("asset", both_declared[2]).is_err());
    assert!(evaluate("asset", by_name["asset/daemon/accepted"][2]).is_ok());
}
