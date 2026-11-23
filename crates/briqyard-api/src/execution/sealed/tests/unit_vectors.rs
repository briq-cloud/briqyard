//! The shared companion vectors of owner-layer erratum 2: B's file, copied byte for byte and
//! reproduced here row by row. Native never edits it. Each row is
//! `name TAB kind TAB input TAB expected`; `expected` is a digest (or `a:b:c:d` for a unit), `accept`
//! or `refuse`. A refusal must come from validation: no row may be repaired into an answer.

use crate::execution::sealed::canonical::{decode, h};
use crate::execution::sealed::inputs::{Listeners, Path, Program};
use crate::execution::sealed::owner::ArmReceipt;
use crate::execution::sealed::prim::{Build, HexDigest};
use crate::execution::sealed::unit_policy::*;
use serde::Deserialize;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/owner_v1/sealed_owner_units_v1.vectors"
));
const VECTORS_SHA256: &str = "21371a4fd93da81519f9a58fdd2badede01033c1515ff8bfa5c36cc6e309bdf3";

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
            let unit = row.policy.expected(row.phase, &row.x, &row.listeners)?;
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
    assert_eq!(VECTORS.len(), 35649);
    assert_eq!(
        hex::encode(Sha256::digest(VECTORS.as_bytes())),
        VECTORS_SHA256
    );
    assert_eq!(rows().len(), 57);
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
    assert_eq!((accepted, refused), (37, 20));
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
