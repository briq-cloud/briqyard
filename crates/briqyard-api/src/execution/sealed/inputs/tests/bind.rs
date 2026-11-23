//! `Inputs::bind`: the exact bytes, the independently loaded Plan and every supplied operand.
//! The control of each group is the accepted fixture; each case changes one side only.

use super::*;
use serde_json::json;

fn refused(
    why: &'static str,
    on_value: impl FnOnce(&mut Value),
    on_plan: impl FnOnce(&mut Plan),
    on_policy: impl FnOnce(&mut DeploymentPolicy<'_>),
) {
    assert_eq!(
        bound(on_value, on_plan, on_policy).unwrap_err(),
        value_err(why)
    );
}

/// `refused` on the published positive profile: the control binds, each case changes one side.
fn refused_c(
    why: &'static str,
    on_value: impl FnOnce(&mut Value),
    on_plan: impl FnOnce(&mut Plan),
    on_policy: impl FnOnce(&mut DeploymentPolicy<'_>),
) {
    assert_eq!(
        companion::bound(on_value, on_plan, on_policy).unwrap_err(),
        value_err(why)
    );
}

#[test]
fn the_plan_inputs_digest_is_the_hash_of_the_exact_manifest_bytes() {
    refused(
        "plan inputs digest",
        |_| {},
        |p| p.inputs = d(b"other manifest"),
        |_| {},
    );
    let releases = releases();
    let plan = plan(d(INPUTS));
    let mut spaced = INPUTS.to_vec();
    spaced.push(b'\n');
    assert!(Inputs::bind(&spaced, &plan, &policy(&releases)).is_err());
    let mut other = plan.clone();
    other.inputs = d(&[INPUTS, b" "].concat());
    assert_eq!(
        Inputs::bind(INPUTS, &other, &policy(&releases)).unwrap_err(),
        value_err("plan inputs digest")
    );
}

#[test]
fn a_plan_that_is_itself_inconsistent_is_refused_before_comparison() {
    let releases = releases();
    let mut plan = plan(d(INPUTS));
    plan.hk = plan.ak;
    assert_eq!(
        Inputs::bind(INPUTS, &plan, &policy(&releases)).unwrap_err(),
        value_err("plan keys")
    );
}

#[test]
fn x_and_registered_are_the_plans() {
    refused(
        "plan scope",
        |_| {},
        |p| p.x.serial = PosInt::new(2).unwrap(),
        |_| {},
    );
    refused("plan scope", |_| {}, |p| p.x.op = d(b"other"), |_| {});
    refused("plan scope", |_| {}, |p| p.x.aud = Env::Production, |_| {});
    refused("plan scope", |_| {}, |p| p.registered = id("h16"), |_| {});
    let changed = |v: &mut Value| {
        v["x"]["serial"] = json!(2);
        v["closure"]["x"]["serial"] = json!(2);
    };
    refused("plan scope", changed, |_| {}, |_| {});
}

#[test]
fn predecessor_pins_follow_the_plan_and_the_source_release() {
    refused(
        "predecessor pins",
        |_| {},
        |p| p.pre_d.pid = PosInt::new(11).unwrap(),
        |_| {},
    );
    refused(
        "predecessor pins",
        |_| {},
        |p| p.pre_a.start = PosInt::new(1).unwrap(),
        |_| {},
    );
    refused(
        "predecessor pins",
        |_| {},
        |p| std::mem::swap(&mut p.pre_d, &mut p.pre_a),
        |_| {},
    );
    refused(
        "predecessor pins",
        |_| {},
        |p| p.pre_d.build = Build::new("other").unwrap(),
        |_| {},
    );
    // The manifest and the Plan agree with each other but the process is not the source's.
    let target_daemon = d(&assets(1)[0]);
    let mut plan_edit_exe = target_daemon.clone();
    refused(
        "predecessor pins",
        |v| v["daemon"]["pre"]["exe"] = json!(target_daemon.as_str()),
        |p| p.pre_d.exe = plan_edit_exe.clone(),
        |_| {},
    );
    plan_edit_exe = d(&assets(0)[1]);
    refused(
        "predecessor pins",
        |v| v["daemon"]["pre"]["exe"] = json!(plan_edit_exe.as_str()),
        |p| p.pre_d.exe = plan_edit_exe.clone(),
        |_| {},
    );
    // Daemon and authority resources swapped in the manifest fail the role's fixed locators.
    assert!(bound(
        |v| {
            let (daemon, authority) = (v["daemon"].clone(), v["authority"].clone());
            v["daemon"] = authority;
            v["authority"] = daemon;
        },
        |_| {},
        |_| {}
    )
    .is_err());
}

#[test]
fn successor_pins_follow_the_plan_and_the_target_release() {
    refused(
        "successor pins",
        |_| {},
        |p| p.next_d = p.next_a.clone(),
        |_| {},
    );
    refused(
        "successor pins",
        |_| {},
        |p| std::mem::swap(&mut p.next_d, &mut p.next_a),
        |_| {},
    );
    refused(
        "successor pins",
        |_| {},
        |p| p.dbuild = Build::new("other").unwrap(),
        |_| {},
    );
    refused(
        "successor pins",
        |_| {},
        |p| p.abuild = p.dbuild.clone(),
        |_| {},
    );
    refused(
        "successor pins",
        |v| v["daemon"]["candidate"]["file"]["sha256"] = json!(d(&assets(0)[0]).as_str()),
        |p| p.next_d = d(&assets(0)[0]),
        |_| {},
    );
    refused(
        "successor pins",
        |v| v["authority"]["candidate"]["build"] = json!("candidate-d"),
        |_| {},
        |_| {},
    );
    refused(
        "successor pins",
        |v| {
            v["daemon"]["candidate"]["file"]["sha256"] =
                v["authority"]["candidate"]["file"]["sha256"].clone()
        },
        |_| {},
        |_| {},
    );
}

#[test]
fn source_and_target_releases_are_the_explicit_selections() {
    let r = releases();
    let swapped = Releases {
        source: verify(TARGET_PIN, TARGET_SUMS, &assets(1)).unwrap(),
        target: verify(SOURCE_PIN, SOURCE_SUMS, &assets(0)).unwrap(),
    };
    assert_eq!(
        bound_with(&swapped, |_| {}, |_| {}, |_| {}).unwrap_err(),
        value_err("source release")
    );
    let twice = Releases {
        source: verify(SOURCE_PIN, SOURCE_SUMS, &assets(0)).unwrap(),
        target: verify(SOURCE_PIN, SOURCE_SUMS, &assets(0)).unwrap(),
    };
    assert_eq!(
        bound_with(&twice, |_| {}, |_| {}, |_| {}).unwrap_err(),
        value_err("target release")
    );
    for (field, replacement) in [
        ("version", json!("0.1.8")),
        ("commit", json!("c".repeat(40))),
        ("release_id", json!(1)),
        ("pin_file", json!("c".repeat(64))),
        ("sums", json!("c".repeat(64))),
        ("daemon", json!("c".repeat(64))),
        ("fleet", json!("c".repeat(64))),
        ("cli", json!("c".repeat(64))),
    ] {
        refused(
            "source release",
            |v| v["source_release"][field] = replacement.clone(),
            |_| {},
            |_| {},
        );
        refused(
            "target release",
            |v| v["target_release"][field] = replacement.clone(),
            |_| {},
            |_| {},
        );
    }
    let _ = r;
}

#[test]
fn topology_facts_come_from_the_receiver_owner() {
    refused(
        "topology policy",
        |_| {},
        |_| {},
        |p| p.topology.inventory.push(b'x'),
    );
    refused(
        "topology policy",
        |_| {},
        |_| {},
        |p| p.topology.order.swap(0, 1),
    );
    refused(
        "topology policy",
        |_| {},
        |_| {},
        |p| {
            p.topology.reader_floors.pop();
        },
    );
    refused(
        "regional floor policy",
        |_| {},
        |_| {},
        |p| {
            p.topology.floors[1].minimum_accepting = PosInt::new(2).unwrap();
        },
    );
    refused(
        "regional floor policy",
        |_| {},
        |_| {},
        |p| {
            p.topology.floors[0].id = id("sa");
        },
    );
    refused(
        "reader floor policy",
        |_| {},
        |_| {},
        |p| {
            let (a, b) = (
                p.topology.reader_floors[0].1.clone(),
                p.topology.reader_floors[1].1.clone(),
            );
            p.topology.reader_floors[0].1 = b;
            p.topology.reader_floors[1].1 = a;
        },
    );
    refused(
        "reader floor policy",
        |_| {},
        |_| {},
        |p| {
            p.topology.reader_floors[1].0 = p.topology.reader_floors[0].0.clone();
        },
    );
}

#[test]
fn actor_identities_come_from_independent_observation() {
    refused_c(
        "actor roster",
        |_| {},
        |_| {},
        |p| {
            p.actors.pop();
        },
    );
    refused_c(
        "actor process identity",
        |_| {},
        |_| {},
        |p| {
            p.actors[2].identity = p.actors[4].identity.clone();
        },
    );
    refused_c(
        "actor process identity",
        |_| {},
        |_| {},
        |p| {
            p.actors[4].identity = ProcessIdentity::Service;
        },
    );
    refused_c(
        "actor process identity",
        |_| {},
        |_| {},
        |p| {
            if let ProcessIdentity::Process(proc) = &mut p.actors[5].identity {
                proc.pid = PosInt::new(61).unwrap();
            }
        },
    );
    refused_c(
        "actor process identity",
        |_| {},
        |_| {},
        |p| p.actors[3].id = id("receiver-2"),
    );
    refused_c(
        "actor process identity",
        |_| {},
        |_| {},
        |p| p.actors[0].actor = ActorKind::Host,
    );
    // A process-scoped B is acceptable only when both sides say so.
    let proc = match &companion::policy(&companion::releases()).actors[4].identity {
        ProcessIdentity::Process(p) => p.clone(),
        ProcessIdentity::Service => unreachable!(),
    };
    refused_c(
        "actor process identity",
        |_| {},
        |_| {},
        |p| {
            p.actors[1].identity = ProcessIdentity::Process(proc.clone());
        },
    );
    companion::bound(
        |v| v["actors"][1]["proc"] = v["actors"][4]["proc"].clone(),
        |_| {},
        |p| p.actors[1].identity = ProcessIdentity::Process(proc.clone()),
    )
    .unwrap();
}

fn swap_roles(p: &mut DeploymentPolicy<'_>, f: impl Fn(&mut ResourcePolicy) -> &mut Vec<u8>) {
    let a = std::mem::take(f(&mut p.daemon));
    let b = std::mem::take(f(&mut p.authority));
    *f(&mut p.daemon) = b;
    *f(&mut p.authority) = a;
}

#[test]
fn per_role_facts_do_not_survive_a_swap_between_daemon_and_authority() {
    refused_c(
        "config or TLS pins",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.config),
    );
    refused_c(
        "config or TLS pins",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.tls_cert),
    );
    refused_c(
        "config or TLS pins",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.tls_key),
    );
    refused_c(
        "unit fragment",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.legacy_fragment),
    );
    refused_c(
        "unit fragment",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.guarded_fragment),
    );
    refused_c(
        "writer profile",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.writer_profile),
    );
    refused_c(
        "guard program",
        |_| {},
        |_| {},
        |p| swap_roles(p, |r| &mut r.guard_bytes),
    );
    refused_c(
        "custodian process",
        |_| {},
        |_| {},
        |p| std::mem::swap(&mut p.daemon.custodian, &mut p.authority.custodian),
    );
}

#[test]
fn tls_blobs_config_fragments_and_writer_profile_are_each_pinned_in_place() {
    refused_c(
        "config or TLS pins",
        |_| {},
        |_| {},
        |p| {
            std::mem::swap(&mut p.daemon.tls_cert, &mut p.daemon.tls_key);
        },
    );
    refused_c(
        "config or TLS pins",
        |_| {},
        |_| {},
        |p| p.daemon.config.push(b' '),
    );
    refused_c(
        "config or TLS pins",
        |_| {},
        |_| {},
        |p| p.authority.config_path = path("/etc/briqyard/config.yaml"),
    );
    refused_c(
        "config or TLS pins",
        |v| v["daemon"]["tls_cert"]["bytes"] = json!(1),
        |_| {},
        |_| {},
    );
    refused_c(
        "unit fragment",
        |_| {},
        |_| {},
        |p| {
            std::mem::swap(
                &mut p.daemon.legacy_fragment,
                &mut p.daemon.guarded_fragment,
            );
        },
    );
    refused_c(
        "unit fragment",
        |_| {},
        |_| {},
        |p| p.daemon.fragment = path("/etc/systemd/system/other.service"),
    );
    refused_c(
        "writer profile",
        |_| {},
        |_| {},
        |p| p.daemon.writer_profile = p.authority.writer_profile.clone(),
    );
    refused_c(
        "writer profile",
        |v| v["daemon"]["writer_profile"] = json!("0".repeat(64)),
        |_| {},
        |_| {},
    );
    refused_c(
        "guard program",
        |_| {},
        |_| {},
        |p| p.daemon.guard_build = Build::new("guard-v2").unwrap(),
    );
    refused_c(
        "candidate locator",
        |_| {},
        |_| {},
        |p| p.daemon.candidate_path = path("/var/lib/briq-sealed/candidates/other"),
    );
    refused_c(
        "candidate locator",
        |v| v["daemon"]["candidate"]["file"]["bytes"] = json!(1),
        |_| {},
        |_| {},
    );
    refused_c(
        "control or journal ownership",
        |_| {},
        |_| {},
        |p| p.authority.control_gid = Uint::new(1000).unwrap(),
    );
    refused_c(
        "control or journal ownership",
        |_| {},
        |_| {},
        |p| p.daemon.journal.mode = Uint::new(0o755).unwrap(),
    );
    refused_c(
        "control or journal ownership",
        |_| {},
        |_| {},
        |p| p.authority.journal.uid = Uint::new(1000).unwrap(),
    );
}

#[test]
fn a_stale_custodian_or_changed_process_is_refused() {
    refused_c(
        "custodian process",
        |_| {},
        |_| {},
        |p| p.daemon.custodian.pid = PosInt::new(31).unwrap(),
    );
    refused_c(
        "custodian process",
        |_| {},
        |_| {},
        |p| p.authority.custodian.start = PosInt::new(1).unwrap(),
    );
    refused_c(
        "custodian process",
        |_| {},
        |_| {},
        |p| p.daemon.custodian.exe = d(b"stale image"),
    );
    refused_c(
        "custodian process",
        |_| {},
        |_| {},
        |p| p.daemon.custodian.build = Build::new("custodian-v0").unwrap(),
    );
}

#[test]
fn both_custodians_run_the_target_bootstrap_daemon_even_when_manifest_and_policy_agree_otherwise() {
    for role in ["daemon", "authority"] {
        let other = d(b"self-consistent but wrong image");
        refused_c(
            "custodian image",
            |v| v[role]["custodian"]["exe"] = json!(other.as_str()),
            |_| {},
            |p| resource_mut(p, role).custodian.exe = other.clone(),
        );
        let fleet = companion::releases().source.release().fleet.clone();
        refused_c(
            "custodian image",
            |v| v[role]["custodian"]["exe"] = json!(fleet.as_str()),
            |_| {},
            |p| resource_mut(p, role).custodian.exe = fleet.clone(),
        );
        refused_c(
            "custodian build",
            |v| v[role]["custodian"]["build"] = json!("custodian-v1"),
            |_| {},
            |p| resource_mut(p, role).custodian.build = Build::new("custodian-v1").unwrap(),
        );
    }
}

#[test]
fn the_source_daemon_build_is_independently_approved_and_is_the_plans() {
    refused(
        "source daemon build",
        |_| {},
        |_| {},
        |p| p.source_daemon_build = Build::new("daemon-v0-build").unwrap(),
    );
    let other = "daemon-v2-build";
    refused(
        "source daemon build",
        |v| {
            v["daemon"]["pre"]["build"] = json!(other);
            v["daemon"]["custodian"]["build"] = json!(other);
            v["authority"]["custodian"]["build"] = json!(other);
        },
        |p| p.pre_d.build = Build::new(other).unwrap(),
        |p| {
            for role in ["daemon", "authority"] {
                resource_mut(p, role).custodian.build = Build::new(other).unwrap();
            }
        },
    );
}

#[test]
fn custodian_ownership_is_a_measured_root_observation_and_never_assumed() {
    let measured = |uid, gid| {
        Some(ProcessOwner::measured(
            Uint::new(uid).unwrap(),
            Uint::new(gid).unwrap(),
        ))
    };
    for role in ["daemon", "authority"] {
        for (uid, gid) in [(1000, 0), (0, 1000), (1000, 1000), (1, 1)] {
            refused_c(
                "custodian owner",
                |_| {},
                |_| {},
                |p| resource_mut(p, role).custodian_owner = measured(uid, gid),
            );
        }
        refused_c(
            "custodian owner",
            |_| {},
            |_| {},
            |p| resource_mut(p, role).custodian_owner = None,
        );
    }
}

/// Every non-null old or new member digest of the Plan, for the closure credential checks.
fn plan_members(plan: &mut Plan) -> Vec<&mut HexDigest> {
    let (old, new) = (&mut plan.old, &mut plan.new);
    let mut slots = vec![
        &mut old.hi,
        &mut old.he,
        &mut old.ni,
        &mut old.ng,
        &mut new.hi,
        &mut new.he,
        &mut new.ni,
        &mut new.ng,
    ];
    slots.extend(old.tr.as_mut());
    slots.extend(new.tr.as_mut());
    slots
}

#[test]
fn the_plans_members_are_distinct_before_anything_is_compared() {
    refused(
        "plan members",
        |_| {},
        |p| p.new.hi = p.old.he.clone(),
        |_| {},
    );
}

#[test]
fn no_old_or_new_member_equals_a_closure_credential_commitment() {
    let admin_host = d(b"synthetic host administrator commitment");
    let admin_fleet = d(b"synthetic fleet administrator commitment");
    let bearer = d(b"synthetic continuation commitment");
    for target in [&admin_host, &admin_fleet, &bearer] {
        for slot in 0..10 {
            refused_c(
                "closure credential reuse",
                |_| {},
                |p| *plan_members(p)[slot] = target.clone(),
                |_| {},
            );
        }
    }
    refused_c(
        "closure credential reuse",
        |_| {},
        |p| p.old.hi = admin_host.clone(),
        |_| {},
    );
    refused_c(
        "closure credential reuse",
        |_| {},
        |p| p.new.hi = bearer.clone(),
        |_| {},
    );
}

fn resource_mut<'a>(policy: &'a mut DeploymentPolicy<'_>, role: &str) -> &'a mut ResourcePolicy {
    match role {
        "daemon" => &mut policy.daemon,
        _ => &mut policy.authority,
    }
}

#[test]
fn listener_count_order_and_names_are_compared_in_delivery_order() {
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.daemon.listener_names.reverse(),
    );
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.daemon.listener_names.push("extra".into()),
    );
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.daemon.listener_names[0] = "api:metrics".into(),
    );
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.daemon.listener_names[1] = String::new(),
    );
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.daemon.listener_names[1] = "met rics\n".into(),
    );
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.daemon.store_max = Uint::new(2771).unwrap(),
    );
    refused_c(
        "listener table",
        |v| v["daemon"]["listeners"]["count"] = json!(1),
        |_| {},
        |_| {},
    );
    refused_c(
        "listener table",
        |v| v["authority"]["listeners"]["names"] = json!("0".repeat(64)),
        |_| {},
        |_| {},
    );
    refused_c(
        "listener table",
        |_| {},
        |_| {},
        |p| p.authority.listener_names.clear(),
    );
    // An explicitly empty table hashes zero bytes and has count zero on both sides.
    companion::bound(
        |v| {
            v["authority"]["listeners"]["count"] = json!(0);
            v["authority"]["listeners"]["names"] = json!(d(b"").as_str());
        },
        |_| {},
        |p| p.authority.listener_names.clear(),
    )
    .unwrap();
}

#[test]
fn closure_pins_are_compared_with_their_independent_owners() {
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.registry.push(b'\n'),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| std::mem::swap(&mut p.closure.admin_host, &mut p.closure.admin_fleet),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.continuation.bearer = d(b"other"),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.continuation.roots.reverse(),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.continuation.url = text("https://api.example.test/other"),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.peers.swap(4, 5),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| {
            let (s, c) = (
                p.closure.peers[1].server.clone(),
                p.closure.peers[1].client.clone(),
            );
            p.closure.peers[1].server = c;
            p.closure.peers[1].client = s;
        },
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.peers[2].endpoint = text("https://other.example.test:7541"),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| {
            p.closure.admin_tls = Some(Pair {
                leaf: d(b"l"),
                spki: d(b"s"),
            })
        },
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.backup_s3 = Some(d(b"s3")),
    );
    refused_c(
        "closure policy",
        |_| {},
        |_| {},
        |p| p.closure.file_key = Some(Hex32::new("a".repeat(32)).unwrap()),
    );
    refused_c(
        "closure policy",
        |v| v["closure"]["backup_s3"] = json!("1".repeat(64)),
        |_| {},
        |_| {},
    );
    refused_c(
        "support policy",
        |_| {},
        |_| {},
        |p| p.closure.support.image_root = d(b"other root"),
    );
    refused_c(
        "support policy",
        |_| {},
        |_| {},
        |p| p.closure.support.release_policy = b"other".to_vec(),
    );
    refused_c(
        "support policy",
        |_| {},
        |_| {},
        |p| p.closure.support.profile = b"other".to_vec(),
    );
    refused_c(
        "support policy",
        |_| {},
        |_| {},
        |p| {
            std::mem::swap(
                &mut p.closure.support.release_policy,
                &mut p.closure.support.profile,
            );
        },
    );
    refused_c(
        "support policy",
        |_| {},
        |_| {},
        |p| {
            p.closure.support.boot_id =
                BootId::new("00000000-0000-4000-8000-0000000000aa").unwrap();
        },
    );
}

#[test]
fn optional_closure_members_bind_only_when_both_owners_agree() {
    let pair = Pair {
        leaf: d(b"admin leaf"),
        spki: d(b"admin spki"),
    };
    let s3 = d(b"synthetic s3 pair commitment");
    let key = Hex32::new("b".repeat(32)).unwrap();
    let bound = companion::bound(
        |v| {
            v["closure"]["admin_tls"] =
                json!({"leaf": pair.leaf.as_str(), "spki": pair.spki.as_str()});
            v["closure"]["backup_s3"] = json!(s3.as_str());
            v["closure"]["file_key"] = json!(key.as_str());
        },
        |_| {},
        |p| {
            p.closure.admin_tls = Some(pair.clone());
            p.closure.backup_s3 = Some(s3.clone());
            p.closure.file_key = Some(key.clone());
        },
    )
    .unwrap();
    assert!(bound.inputs().closure.admin_tls.is_some());
}

#[test]
fn a_manifest_cannot_name_a_second_candidate_or_a_successor_process() {
    for field in ["next", "successor", "candidate_proc"] {
        assert_eq!(
            bound(
                |v| v["authority"][field] = v["authority"]["pre"].clone(),
                |_| {},
                |_| {}
            )
            .unwrap_err(),
            CodecError::Schema,
            "{field}"
        );
    }
    refused(
        "actor process form",
        |v| v["actors"][0]["proc"] = v["actors"][4]["proc"].clone(),
        |_| {},
        |_| {},
    );
}

#[test]
fn the_four_processes_have_four_distinct_pids() {
    // Slots: daemon original, daemon custodian, authority original, authority custodian. Each
    // case moves one slot onto another's pid across the manifest and the operand that pins it,
    // so every other comparison still agrees and only the pid rule can refuse.
    let slots: [(&str, &str); 4] = [
        ("daemon", "pre"),
        ("daemon", "custodian"),
        ("authority", "pre"),
        ("authority", "custodian"),
    ];
    let pid = |role: &str, kind: &str| match (role, kind) {
        ("daemon", "pre") => 123,
        ("daemon", _) => 4300,
        (_, "pre") => 124,
        _ => 4301,
    };
    for (i, (role, kind)) in slots.iter().enumerate() {
        for (other_role, other_kind) in &slots[..i] {
            let shared = PosInt::new(pid(other_role, other_kind)).unwrap();
            refused_c(
                "process identities",
                |v| v[*role][*kind]["pid"] = json!(shared.get()),
                |p| match (*role, *kind) {
                    ("daemon", "pre") => p.pre_d.pid = shared,
                    ("authority", "pre") => p.pre_a.pid = shared,
                    _ => {}
                },
                |policy| match (*role, *kind) {
                    ("daemon", "custodian") => policy.daemon.custodian.pid = shared,
                    ("authority", "custodian") => policy.authority.custodian.pid = shared,
                    _ => {}
                },
            );
        }
    }
}
