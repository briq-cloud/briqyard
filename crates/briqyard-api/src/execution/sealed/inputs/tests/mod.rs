//! Synthetic fixtures and tests of the closed `native.inputs/v1` reader. Everything here is
//! invented: the release pins, digests, processes, keys and hosts are test data, nothing is
//! signed or secret, and no test approves, qualifies or starts anything. The complete
//! manifest `testdata/native_inputs_v1/inputs.json` was written by the simple Python reference
//! assembler beside it, not by these types; the operands below are written out again here
//! from the same invented strings, so a Rust-side disagreement fails `bind`.
//!
//! These cover the synthetic grammar, equality and release checks only. They say nothing about
//! a real release, a real source owner, a real host or a native qualification.

mod bind;
mod grammar;
mod release;
mod strict;

use super::*;
use crate::execution::sealed::canonical::{decode, encode, CodecError};
use crate::execution::sealed::objects::{Ctx, Members, Plan, Reg};
use crate::execution::sealed::prim::{Bytes, Env};
use serde_json::Value;

pub(super) const INPUTS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/native_inputs_v1/inputs.json"
));
pub(super) const SOURCE_PIN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/native_inputs_v1/source_pin.json"
));
pub(super) const SOURCE_SUMS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/native_inputs_v1/source_sums.txt"
));
pub(super) const TARGET_PIN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/native_inputs_v1/target_pin.json"
));
pub(super) const TARGET_SUMS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/native_inputs_v1/target_sums.txt"
));
/// The SHA-256 of `INPUTS` the reference assembler printed, copied here as a named constant.
pub(super) const INPUTS_SHA256: &str =
    "f8340683e6adbbe04e295fed815b7421014b3ed5c1c00aebeff458532cbdac4b";

const BOOT: &str = "00000000-0000-4000-8000-000000000004";
const OTHER_BOOT: &str = "00000000-0000-4000-8000-000000000005";

pub(super) fn d(bytes: &[u8]) -> HexDigest {
    HexDigest::of(bytes)
}

pub(super) fn text(s: &str) -> Text {
    Text::new(s).unwrap()
}

pub(super) fn path(s: &str) -> Path {
    Path::new(s).unwrap()
}

pub(super) fn id(s: &str) -> Ident {
    Ident::new(s).unwrap()
}

fn proc(pid: u64, exe: HexDigest, build: &str, boot: &str) -> Proc {
    Proc {
        boot: BootId::new(boot).unwrap(),
        pid: PosInt::new(pid).unwrap(),
        start: PosInt::new(100 + pid).unwrap(),
        exe,
        build: Build::new(build).unwrap(),
    }
}

pub(super) struct Releases {
    pub source: VerifiedRelease,
    pub target: VerifiedRelease,
}

pub(super) fn assets(index: u8) -> [Vec<u8>; 3] {
    [
        format!("synthetic-daemon-v{index}").into_bytes(),
        format!("synthetic-fleet-v{index}").into_bytes(),
        format!("synthetic-cli-v{index}").into_bytes(),
    ]
}

pub(super) fn verify(
    pin: &[u8],
    sums: &[u8],
    assets: &[Vec<u8>; 3],
) -> Result<VerifiedRelease, CodecError> {
    VerifiedRelease::validate(
        pin,
        sums,
        ReleaseAssets {
            daemon: &assets[0],
            fleet: &assets[1],
            cli: &assets[2],
        },
    )
}

pub(super) fn releases() -> Releases {
    Releases {
        source: verify(SOURCE_PIN, SOURCE_SUMS, &assets(0)).unwrap(),
        target: verify(TARGET_PIN, TARGET_SUMS, &assets(1)).unwrap(),
    }
}

/// The Plan an independent pin would hold for `INPUTS`, written out from the same invented facts.
pub(super) fn plan(inputs: HexDigest) -> Plan {
    let x = X {
        aud: Env::Staging,
        host: id("host.test"),
        op: HexDigest::new("0".repeat(64)).unwrap(),
        serial: PosInt::new(1).unwrap(),
    };
    let record = Reg {
        authority: id("auth"),
        epoch: id("ep"),
        key_id: id("k"),
        public_key: [5; 32],
        host_instance: id("hi"),
        generation: PosInt::new(2).unwrap(),
    };
    let pre: Ctx = record.ctx(&x.host);
    let digest = |c: char| HexDigest::new(c.to_string().repeat(64)).unwrap();
    let members = |c: char| Members {
        hi: digest(c),
        he: digest(c),
        ni: digest(c),
        ng: digest(c),
        tr: Some(digest(c)),
    };
    let key = |k: u8| Bytes::from_array([k; 32]);
    Plan {
        x,
        registered: id("h15"),
        pre,
        pre_record: record,
        pre_intent: id("pre"),
        pre_d: proc(10, d(&assets(0)[0]), "daemon-v1-build", BOOT),
        pre_a: proc(20, d(&assets(0)[1]), "fleet-v1-build", BOOT),
        next_d: d(&assets(1)[0]),
        next_a: d(&assets(1)[1]),
        dbuild: Build::new("candidate-d").unwrap(),
        abuild: Build::new("candidate-a").unwrap(),
        old: members('1'),
        new: members('2'),
        hk: key(1),
        ak: key(2),
        bk: key(3),
        rk: key(4),
        ordinary_key: key(5),
        exception: digest('a'),
        inputs,
    }
}

fn der_roots() -> Vec<DerBytes> {
    let mut roots = vec![
        b"synthetic trust anchor one".to_vec(),
        b"synthetic trust anchor two".to_vec(),
    ];
    roots.sort_by_key(|root| d(root));
    roots
        .into_iter()
        .map(|r| DerBytes::new(r).unwrap())
        .collect()
}

fn peers() -> Vec<Peer> {
    let rows: [(ActorKind, &str, &str, u16); 6] = [
        (ActorKind::Authority, "A", "authority-1", 7542),
        (ActorKind::Api, "B", "api-1", 9000),
        (ActorKind::Host, "H", "h15", 7541),
        (ActorKind::Receiver, "R", "receiver-1", 9001),
        (ActorKind::Gateway, "gateway", "gateway-1", 9002),
        (ActorKind::Installer, "installer", "installer-1", 9003),
    ];
    rows.iter()
        .map(|(actor, role, ident, port)| {
            let pair = |purpose: &str| Pair {
                leaf: d(format!("synthetic leaf {role} {purpose}").as_bytes()),
                spki: d(format!("synthetic spki {role} {purpose}").as_bytes()),
            };
            Peer {
                actor: *actor,
                id: id(ident),
                endpoint: text(&format!(
                    "https://{}.example.test:{port}",
                    role.to_lowercase()
                )),
                server_name: text(&format!("{}.example.test", role.to_lowercase())),
                server: pair("server"),
                client: pair("client"),
            }
        })
        .collect()
}

fn resource_policy(role: &str) -> ResourcePolicy {
    let daemon = role == "daemon";
    let custodian_pid = if daemon { 30 } else { 40 };
    ResourcePolicy {
        custodian: proc(
            custodian_pid,
            d(b"synthetic custodian image"),
            "custodian-v1",
            BOOT,
        ),
        guard_build: Build::new("guard-v1").unwrap(),
        guard_bytes: format!("synthetic {role} guard").into_bytes(),
        candidate_path: path(&format!("/var/lib/briq-sealed/candidates/{role}")),
        config_path: path(if daemon {
            "/etc/briqyard/config.yaml"
        } else {
            "/etc/briq-execution/authority/config.json"
        }),
        config: format!("synthetic {role} config\n").into_bytes(),
        tls_cert: format!("synthetic {role} ordinary TLS certificate bytes\n").into_bytes(),
        tls_key: format!("synthetic {role} ordinary TLS key placeholder, not a key\n").into_bytes(),
        fragment: path(if daemon {
            "/etc/systemd/system/briqyard.service"
        } else {
            "/etc/systemd/system/briqyard-fleet.service"
        }),
        legacy_fragment: format!("synthetic {role} legacy fragment\n").into_bytes(),
        guarded_fragment: format!("synthetic {role} guarded fragment\n").into_bytes(),
        control_gid: Uint::new(if daemon { 0 } else { 1000 }).unwrap(),
        journal: Directory {
            path: path(if daemon {
                "/var/lib/briqyard/journal"
            } else {
                "/var/lib/briq-execution-authority/journal"
            }),
            uid: Uint::new(if daemon { 0 } else { 1000 }).unwrap(),
            gid: Uint::new(if daemon { 0 } else { 1000 }).unwrap(),
            mode: Uint::new(0o700).unwrap(),
        },
        listener_names: if daemon {
            vec!["api".into(), "metrics".into()]
        } else {
            vec!["api".into()]
        },
        store_max: Uint::new(if daemon { 2770 } else { 1 }).unwrap(),
        writer_profile: format!("synthetic {role} writer profile\n").into_bytes(),
    }
}

pub(super) fn policy(releases: &Releases) -> DeploymentPolicy<'_> {
    let other =
        |pid, exe: &[u8], build| ProcessIdentity::Process(proc(pid, d(exe), build, OTHER_BOOT));
    let service = |actor, ident: &str| ActorObservation {
        actor,
        id: id(ident),
        identity: ProcessIdentity::Service,
    };
    DeploymentPolicy {
        source_release: &releases.source,
        target_release: &releases.target,
        topology: TopologyPolicy {
            inventory: b"synthetic topology inventory\n".to_vec(),
            order: vec![id("h17-eu"), id("h16"), id("h15")],
            floors: vec![
                RegionFloor {
                    id: id("eu"),
                    minimum_accepting: PosInt::new(1).unwrap(),
                },
                RegionFloor {
                    id: id("na"),
                    minimum_accepting: PosInt::new(1).unwrap(),
                },
            ],
            reader_floors: ["h17-eu", "h15", "h16"]
                .into_iter()
                .map(|h| (id(h), format!("synthetic reader floor {h}\n").into_bytes()))
                .collect(),
        },
        actors: vec![
            service(ActorKind::Authority, "authority-1"),
            service(ActorKind::Api, "api-1"),
            service(ActorKind::Host, "h15"),
            service(ActorKind::Receiver, "receiver-1"),
            ActorObservation {
                actor: ActorKind::Gateway,
                id: id("gateway-1"),
                identity: other(50, b"synthetic gateway image", "gateway-v1"),
            },
            ActorObservation {
                actor: ActorKind::Installer,
                id: id("installer-1"),
                identity: other(60, b"synthetic installer image", "installer-v1"),
            },
        ],
        daemon: resource_policy("daemon"),
        authority: resource_policy("authority"),
        closure: ClosurePolicy {
            registry: b"synthetic public registry\n".to_vec(),
            admin_host: d(b"synthetic host administrator commitment"),
            admin_fleet: d(b"synthetic fleet administrator commitment"),
            continuation: Continuation {
                url: text("https://api.example.test/internal/execution/v1/continue"),
                bearer: d(b"synthetic continuation commitment"),
                roots: der_roots(),
                server_name: text("api.example.test"),
            },
            peers: peers(),
            admin_tls: None,
            backup_s3: None,
            file_key: None,
            support: SupportPolicy {
                image_root: d(b"synthetic dm-verity root input"),
                boot_id: BootId::new(BOOT).unwrap(),
                release_policy: b"synthetic release policy\n".to_vec(),
                profile: b"synthetic deployment profile\n".to_vec(),
            },
        },
    }
}

pub(super) fn value() -> Value {
    serde_json::from_slice(INPUTS).unwrap()
}

pub(super) fn canonical(value: &Value) -> Vec<u8> {
    encode(value).unwrap()
}

/// Grammar-only decode of the fixture after `f` changed its tree.
pub(super) fn mutated(f: impl FnOnce(&mut Value)) -> Result<Inputs, CodecError> {
    let mut v = value();
    f(&mut v);
    decode(&encode(&v)?)
}

/// Mutate the manifest tree, the Plan and the operands independently, then bind. The Plan's
/// `inputs` digest follows the mutated bytes unless `on_plan` changes it.
pub(super) fn bound(
    on_value: impl FnOnce(&mut Value),
    on_plan: impl FnOnce(&mut Plan),
    on_policy: impl FnOnce(&mut DeploymentPolicy<'_>),
) -> Result<BoundInputs, CodecError> {
    let releases = releases();
    bound_with(&releases, on_value, on_plan, on_policy)
}

pub(super) fn bound_with(
    releases: &Releases,
    on_value: impl FnOnce(&mut Value),
    on_plan: impl FnOnce(&mut Plan),
    on_policy: impl FnOnce(&mut DeploymentPolicy<'_>),
) -> Result<BoundInputs, CodecError> {
    let mut v = value();
    on_value(&mut v);
    let bytes = canonical(&v);
    let mut plan = plan(d(&bytes));
    on_plan(&mut plan);
    let mut policy = policy(releases);
    on_policy(&mut policy);
    Inputs::bind(&bytes, &plan, &policy)
}

pub(super) fn value_err(what: &'static str) -> CodecError {
    CodecError::Value(what)
}

#[test]
fn the_complete_fixture_is_canonical_and_matches_the_reference_hash() {
    let inputs: Inputs = decode(INPUTS).unwrap();
    assert_eq!(encode(&inputs).unwrap(), INPUTS);
    assert_eq!(d(INPUTS).as_str(), INPUTS_SHA256);
    assert!(
        INPUTS.len() <= 65536 && !INPUTS.ends_with(b"\n") && !INPUTS.starts_with(b"\xef\xbb\xbf")
    );
    assert_eq!(inputs.format, INPUTS_FORMAT);
    assert_eq!(inputs.closure.format, CLOSURE_FORMAT);
    assert_eq!(inputs.actors.len(), inputs.closure.peers.len());
}

#[test]
fn the_complete_fixture_binds_to_its_independent_plan_and_operands() {
    let releases = releases();
    let plan = plan(d(INPUTS));
    let bound = Inputs::bind(INPUTS, &plan, &policy(&releases)).unwrap();
    assert_eq!(bound.bytes(), INPUTS);
    assert_eq!(bound.inputs().x, plan.x);
    assert_eq!(bound.inputs().registered, plan.registered);
}

#[test]
fn a_noop_mutation_binds_like_the_original_control() {
    bound(|_| {}, |_| {}, |_| {}).unwrap();
    mutated(|_| {}).unwrap();
}
