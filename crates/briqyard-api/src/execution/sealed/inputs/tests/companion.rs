//! The published positive profiles: B's `sealed.owner.inputs.positive/v2` companions, mirrored
//! byte for byte (see `testdata/owner_v1/README.md`). Their guards and candidates are the target
//! asset, both custodians are the target bootstrap daemon, and every operand `bind` compares is
//! given as raw bytes with a declared length and digest. The standard file has one daemon for the
//! source and the target release; the daemon-upgrade file has two, so only the pair tells a
//! custodian chosen from the source release from one chosen from the target. All of it is
//! synthetic and public; nothing here reads the environment or the filesystem beyond the two
//! included files.

use super::*;
use crate::execution::sealed::unit_policy::{same_target_asset, Phase, Transition, UnitPolicy};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

const STANDARD: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/owner_v1/sealed_owner_inputs_v1.positive.json"
));
const STANDARD_SHA256: &str = "df13edca8dd6632f47662c157a3b2085dff45b79daf4541e4095fe6c664d3a8a";
const STANDARD_LEN: usize = 61223;
const UPGRADE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/owner_v1/sealed_owner_inputs_v1.positive-daemon-upgrade.json"
));
const UPGRADE_SHA256: &str = "014eeee72ab22bc8c21d931fb20b47fded709d28cdff0d3111d588c788aeacee";
const UPGRADE_LEN: usize = 61178;
const FORMAT: &str = "sealed.owner.inputs.positive/v2";

/// A frozen file, after its length and hash are checked. Anything else is a failed test.
fn frozen(file: &[u8], sha256: &str, len: usize) -> Value {
    assert_eq!(file.len(), len, "companion length");
    assert_eq!(d(file).as_str(), sha256, "companion bytes");
    let doc: Value = serde_json::from_slice(file).expect("companion is JSON");
    assert_eq!(doc["format"], FORMAT);
    doc
}

pub(super) fn doc() -> Value {
    frozen(STANDARD, STANDARD_SHA256, STANDARD_LEN)
}

fn upgrade_doc() -> Value {
    frozen(UPGRADE, UPGRADE_SHA256, UPGRADE_LEN)
}

/// One raw operand: base64url bytes whose length and SHA-256 are the declared ones.
fn raw(entry: &Value) -> Vec<u8> {
    let text = entry["base64url"].as_str().expect("raw operand text");
    let bytes = URL_SAFE_NO_PAD.decode(text).expect("raw operand base64url");
    assert_eq!(URL_SAFE_NO_PAD.encode(&bytes), text, "canonical base64url");
    assert_eq!(
        entry["bytes"].as_u64().expect("declared length"),
        bytes.len() as u64,
        "declared length"
    );
    assert_eq!(
        entry["sha256"].as_str().expect("declared digest"),
        d(&bytes).as_str(),
        "declared digest"
    );
    bytes
}

fn raw_entries(value: &Value, out: &mut Vec<Vec<u8>>) {
    match value {
        Value::Object(map) if map.contains_key("base64url") => out.push(raw(value)),
        Value::Object(map) => map.values().for_each(|v| raw_entries(v, out)),
        Value::Array(items) => items.iter().for_each(|v| raw_entries(v, out)),
        _ => {}
    }
}

fn uint(value: &Value) -> Uint {
    Uint::new(value.as_u64().expect("unsigned integer")).expect("in range")
}

fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).expect("typed operand")
}

fn release(value: &Value) -> VerifiedRelease {
    verify(
        &raw(&value["pin_file"]),
        &raw(&value["sums"]),
        &[
            raw(&value["daemon"]),
            raw(&value["fleet"]),
            raw(&value["cli"]),
        ],
    )
    .expect("the release verifies from its raw pin, sums and assets")
}

fn resource(n: &Value) -> ResourcePolicy {
    let j = &n["journal"];
    ResourcePolicy {
        custodian: typed(&n["custodian"]),
        custodian_owner: Some(ProcessOwner::measured(
            uint(&n["custodian_owner"]["uid"]),
            uint(&n["custodian_owner"]["gid"]),
        )),
        guard_build: Build::new(n["guard_build"].as_str().unwrap()).unwrap(),
        guard_bytes: raw(&n["guard"]),
        candidate_path: path(n["candidate_path"].as_str().unwrap()),
        config_path: path(n["config_path"].as_str().unwrap()),
        config: raw(&n["config"]),
        tls_cert: raw(&n["tls_cert"]),
        tls_key: raw(&n["tls_key"]),
        fragment: path(n["fragment"].as_str().unwrap()),
        legacy_fragment: raw(&n["legacy_fragment"]),
        guarded_fragment: raw(&n["guarded_fragment"]),
        control_gid: uint(&n["control_gid"]),
        journal: Directory {
            path: path(j["path"].as_str().unwrap()),
            uid: uint(&j["uid"]),
            gid: uint(&j["gid"]),
            mode: uint(&j["mode"]),
        },
        listener_names: n["listener_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect(),
        store_max: uint(&n["store_max"]),
        writer_profile: raw(&n["writer_profile"]),
    }
}

fn plan_of(doc: &Value, inputs: HexDigest) -> Plan {
    let mut plan: Plan =
        decode(doc["plan_canonical"].as_str().unwrap().as_bytes()).expect("canonical Plan");
    plan.inputs = inputs;
    plan
}

fn releases_of(doc: &Value) -> Releases {
    let n = &doc["native"];
    Releases {
        source: release(&n["source_release"]),
        target: release(&n["target_release"]),
    }
}

fn policy_of<'a>(doc: &Value, releases: &'a Releases) -> DeploymentPolicy<'a> {
    let n = &doc["native"];
    let t = &n["topology"];
    let c = &n["closure"];
    DeploymentPolicy {
        source_release: &releases.source,
        target_release: &releases.target,
        source_daemon_build: Build::new(n["source_daemon_build"].as_str().unwrap()).unwrap(),
        topology: TopologyPolicy {
            inventory: raw(&t["inventory"]),
            order: t["order"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| id(s.as_str().unwrap()))
                .collect(),
            floors: t["floors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| RegionFloor {
                    id: id(f["id"].as_str().unwrap()),
                    minimum_accepting: PosInt::new(f["minimum_accepting"].as_u64().unwrap())
                        .unwrap(),
                })
                .collect(),
            reader_floors: t["reader_floors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| (id(f["registered"].as_str().unwrap()), raw(f)))
                .collect(),
        },
        actors: n["actors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| ActorObservation {
                actor: typed(&a["actor"]),
                id: id(a["id"].as_str().unwrap()),
                identity: if a["identity"] == "service" {
                    ProcessIdentity::Service
                } else {
                    ProcessIdentity::Process(typed(&a["identity"]))
                },
            })
            .collect(),
        daemon: resource(&n["daemon"]),
        authority: resource(&n["authority"]),
        closure: ClosurePolicy {
            registry: raw(&c["registry"]),
            admin_host: typed(&c["admin_host"]),
            admin_fleet: typed(&c["admin_fleet"]),
            continuation: typed(&c["continuation"]),
            peers: typed(&c["peers"]),
            admin_tls: None,
            backup_s3: None,
            file_key: None,
            support: SupportPolicy {
                image_root: typed(&c["support"]["image_root"]),
                boot_id: typed(&c["support"]["boot_id"]),
                release_policy: raw(&c["support"]["release_policy"]),
                profile: raw(&c["support"]["profile"]),
            },
        },
    }
}

fn bytes_of(doc: &Value) -> Vec<u8> {
    doc["inputs_canonical"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// Mutate the manifest tree, the Plan and the operands independently, then bind. The Plan's
/// `inputs` digest follows the mutated bytes unless `on_plan` changes it.
fn bound_of(
    doc: &Value,
    on_value: impl FnOnce(&mut Value),
    on_plan: impl FnOnce(&mut Plan),
    on_policy: impl FnOnce(&mut DeploymentPolicy<'_>),
) -> Result<BoundInputs, CodecError> {
    let releases = releases_of(doc);
    let mut v: Value = serde_json::from_slice(&bytes_of(doc)).unwrap();
    on_value(&mut v);
    let bytes = canonical(&v);
    let mut plan = plan_of(doc, d(&bytes));
    on_plan(&mut plan);
    let mut policy = policy_of(doc, &releases);
    on_policy(&mut policy);
    Inputs::bind(&bytes, &plan, &policy)
}

pub(super) fn plan(inputs: HexDigest) -> Plan {
    plan_of(&doc(), inputs)
}

pub(super) fn releases() -> Releases {
    releases_of(&doc())
}

pub(super) fn policy(releases: &Releases) -> DeploymentPolicy<'_> {
    policy_of(&doc(), releases)
}

pub(super) fn bytes() -> Vec<u8> {
    bytes_of(&doc())
}

/// `tests::bound`, on the standard companion.
pub(super) fn bound(
    on_value: impl FnOnce(&mut Value),
    on_plan: impl FnOnce(&mut Plan),
    on_policy: impl FnOnce(&mut DeploymentPolicy<'_>),
) -> Result<BoundInputs, CodecError> {
    bound_of(&doc(), on_value, on_plan, on_policy)
}

fn resource_mut<'a>(policy: &'a mut DeploymentPolicy<'_>, role: &str) -> &'a mut ResourcePolicy {
    match role {
        "daemon" => &mut policy.daemon,
        _ => &mut policy.authority,
    }
}

fn both() -> [Value; 2] {
    [doc(), upgrade_doc()]
}

#[test]
fn each_companion_is_the_frozen_published_file_and_every_raw_operand_is_what_it_declares() {
    for doc in both() {
        let mut operands = Vec::new();
        raw_entries(&doc["native"], &mut operands);
        assert_eq!(operands.len(), 32, "raw operands in the native block");
        let inputs_bytes = bytes_of(&doc);
        let decoded: Inputs = decode(&inputs_bytes).unwrap();
        assert_eq!(
            encode(&decoded).unwrap(),
            inputs_bytes,
            "canonical manifest"
        );
        assert_eq!(
            d(&inputs_bytes).as_str(),
            doc["inputs_sha256"].as_str().unwrap()
        );
        let plan = plan_of(&doc, d(&inputs_bytes));
        assert_eq!(plan.inputs.as_str(), doc["inputs_sha256"].as_str().unwrap());
        let plan_bytes = doc["plan_canonical"].as_str().unwrap().as_bytes();
        assert_eq!(encode(&plan).unwrap(), plan_bytes, "canonical Plan");
        assert_eq!(d(plan_bytes).as_str(), doc["plan_digest"].as_str().unwrap());
        assert_eq!(decoded.x, plan.x);
    }
}

#[test]
fn each_companion_binds_to_its_independent_plan_and_operands_and_is_the_target_asset() {
    for doc in both() {
        let releases = releases_of(&doc);
        let bytes = bytes_of(&doc);
        let plan = plan_of(&doc, d(&bytes));
        let bound = Inputs::bind(&bytes, &plan, &policy_of(&doc, &releases)).unwrap();
        assert_eq!(bound.bytes(), bytes);
        bound
            .inputs()
            .check_target_asset_identity(&plan, &releases.target)
            .unwrap();
        bound_of(&doc, |_| {}, |_| {}, |_| {}).unwrap();
    }
}

#[test]
fn the_published_expected_values_are_what_native_computes_from_the_same_operands() {
    for doc in both() {
        let expected = &doc["expected"];
        let inputs: Inputs = decode(&bytes_of(&doc)).unwrap();
        let plan = plan_of(&doc, d(&bytes_of(&doc)));
        let releases = releases_of(&doc);
        for (role, resource, build) in [
            ("daemon", &inputs.daemon, &plan.dbuild),
            ("authority", &inputs.authority, &plan.abuild),
        ] {
            let target = &doc["policy"]["releases"]["bootstrap"][role];
            let digest: HexDigest = typed(&target["sha256"]);
            same_target_asset(
                &resource.guard,
                &resource.candidate,
                &digest,
                target["bytes"].as_u64().unwrap(),
                &typed(&target["build"]),
            )
            .unwrap();
            assert_eq!(target["build"].as_str().unwrap(), build.as_str());
            assert_eq!(
                typed::<Proc>(&expected["custodians"][role]),
                resource.custodian
            );

            let policy: UnitPolicy = typed(&doc["policy"]["units"][role]);
            let x: Transition = typed(&json!({"op": plan.x.op, "serial": plan.x.serial}));
            for (name, phase) in [
                ("prearm", Phase::Prearm),
                ("armed", Phase::Armed),
                ("launch", Phase::Launch),
            ] {
                let want = &expected["units"][role][name];
                let got = policy
                    .expected(typed(&json!(role)), phase, &x, &resource.listeners)
                    .unwrap();
                for (field, value) in [
                    ("fragment", got.fragment),
                    ("argv", got.argv),
                    ("sandbox", got.sandbox),
                    ("fdstore", got.fdstore),
                ] {
                    assert_eq!(
                        want[field].as_str().unwrap(),
                        value.as_str(),
                        "{role} {name} {field}"
                    );
                }
            }
        }
        let campaign = &expected["campaign"];
        assert_eq!(
            campaign["releases"]["source"].as_str().unwrap(),
            d(&encode(&inputs.source_release).unwrap()).as_str()
        );
        assert_eq!(
            campaign["releases"]["target"].as_str().unwrap(),
            d(&encode(&inputs.target_release).unwrap()).as_str()
        );
        assert_eq!(
            campaign["topology"].as_str().unwrap(),
            d(&encode(&inputs.topology).unwrap()).as_str()
        );
        let order: Vec<&str> = inputs.topology.order.iter().map(Ident::as_str).collect();
        assert_eq!(json!(order), campaign["order"]);
        assert_eq!(
            expected["registry"].as_str().unwrap(),
            doc["native"]["closure"]["registry"]["base64url"]
                .as_str()
                .unwrap()
        );
        assert_eq!(releases.target.release(), &inputs.target_release);
    }
}

#[test]
fn the_target_asset_identity_is_enforced_by_bind_not_left_to_a_caller() {
    for doc in both() {
        for role in ["daemon", "authority"] {
            let other =
                format!("a self-consistent rebuild of the {role} with other bytes").into_bytes();
            let wrong = |p: &mut DeploymentPolicy<'_>| {
                resource_mut(p, role).guard_bytes = other.clone();
            };
            assert_eq!(
                bound_of(
                    &doc,
                    |v| {
                        v[role]["guard"]["file"]["sha256"] = json!(d(&other).as_str());
                        v[role]["guard"]["file"]["bytes"] = json!(other.len());
                    },
                    |_| {},
                    wrong,
                )
                .map(|_| ())
                .unwrap_err(),
                value_err("program is not the target release asset"),
                "{role}: operands that agree with each other but not with the target asset"
            );

            let declared = doc["native"][role]["guard"]["bytes"].as_u64().unwrap();
            assert_eq!(
                bound_of(
                    &doc,
                    |v| {
                        v[role]["guard"]["file"]["bytes"] = json!(declared + 1);
                        v[role]["candidate"]["file"]["bytes"] = json!(declared + 1);
                    },
                    |_| {},
                    |_| {},
                )
                .map(|_| ())
                .unwrap_err(),
                value_err("guard program"),
                "{role}: equal declared lengths that are not the asset's actual length"
            );

            let path = serde_json::from_slice::<Value>(&bytes_of(&doc)).unwrap()[role]["guard"]
                ["file"]["path"]
                .clone();
            let shared = Path::new(
                String::from_utf8(URL_SAFE_NO_PAD.decode(path.as_str().unwrap()).unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                bound_of(
                    &doc,
                    |v| v[role]["candidate"]["file"]["path"] = path.clone(),
                    |_| {},
                    |p| resource_mut(p, role).candidate_path = shared.clone(),
                )
                .map(|_| ())
                .unwrap_err(),
                value_err("candidate locator"),
                "{role}: one path for both programs is refused by the grammar before any comparison"
            );
        }
    }
}

#[test]
fn the_daemon_upgrade_file_has_a_source_daemon_that_is_not_the_target_daemon() {
    let standard = doc();
    let upgrade = upgrade_doc();
    let source = |doc: &Value, key: &str| doc["inputs"]["source_release"][key].clone();
    let target = |doc: &Value, key: &str| doc["inputs"]["target_release"][key].clone();
    assert_eq!(source(&standard, "daemon"), target(&standard, "daemon"));
    assert_ne!(source(&upgrade, "daemon"), target(&upgrade, "daemon"));

    let inputs: Inputs = decode(&bytes_of(&upgrade)).unwrap();
    let plan = plan_of(&upgrade, d(&bytes_of(&upgrade)));
    assert_eq!(plan.pre_d.build.as_str(), "0.2.15");
    assert_eq!(
        inputs.daemon.pre.exe, inputs.source_release.daemon,
        "the original is the source's"
    );
    assert_eq!(inputs.daemon.pre.build.as_str(), "0.2.15");
    assert_eq!(plan.dbuild.as_str(), "0.2.16");
    for custodian in [&inputs.daemon.custodian, &inputs.authority.custodian] {
        assert_eq!(custodian.exe, inputs.target_release.daemon);
        assert_eq!(custodian.build, plan.dbuild);
        assert_ne!(custodian.exe, inputs.source_release.daemon);
    }
}

#[test]
fn a_custodian_on_the_source_daemon_is_refused_even_when_everything_else_is_the_target() {
    let upgrade = upgrade_doc();
    let source_daemon = upgrade["inputs"]["source_release"]["daemon"].clone();
    let source_build = json!(upgrade["native"]["source_daemon_build"].clone());
    assert_ne!(source_daemon, upgrade["inputs"]["target_release"]["daemon"]);
    for role in ["daemon", "authority"] {
        let exe: HexDigest = typed(&source_daemon);
        let build: Build = typed(&source_build);
        assert_eq!(
            bound_of(
                &upgrade,
                |v| {
                    v[role]["custodian"]["exe"] = source_daemon.clone();
                    v[role]["custodian"]["build"] = source_build.clone();
                },
                |_| {},
                |p| {
                    let resource = resource_mut(p, role);
                    resource.custodian.exe = exe.clone();
                    resource.custodian.build = build.clone();
                },
            )
            .map(|_| ())
            .unwrap_err(),
            value_err("custodian image"),
            "{role}: a measured custodian on the source daemon and its source build"
        );
        assert_eq!(
            bound_of(
                &upgrade,
                |v| v[role]["custodian"]["build"] = source_build.clone(),
                |_| {},
                |p| resource_mut(p, role).custodian.build = build.clone(),
            )
            .map(|_| ())
            .unwrap_err(),
            value_err("custodian build"),
            "{role}: the target daemon image under the source build"
        );
    }
}

#[test]
fn both_custodians_on_the_source_daemon_are_refused_though_that_binds_under_a_source_rule() {
    let upgrade = upgrade_doc();
    let source_daemon = upgrade["inputs"]["source_release"]["daemon"].clone();
    let source_build = upgrade["native"]["source_daemon_build"].clone();
    let exe: HexDigest = typed(&source_daemon);
    let build: Build = typed(&source_build);
    assert_eq!(
        bound_of(
            &upgrade,
            |v| {
                for role in ["daemon", "authority"] {
                    v[role]["custodian"]["exe"] = source_daemon.clone();
                    v[role]["custodian"]["build"] = source_build.clone();
                }
            },
            |_| {},
            |p| {
                for role in ["daemon", "authority"] {
                    let resource = resource_mut(p, role);
                    resource.custodian.exe = exe.clone();
                    resource.custodian.build = build.clone();
                }
            },
        )
        .map(|_| ())
        .unwrap_err(),
        value_err("custodian image")
    );
}
