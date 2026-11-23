//! Grammar-level invariants: topology, actors, native resources and the v3.3 closure. Each
//! negative case names the exact refusal, so it cannot pass for an unrelated reason; each
//! group starts from the accepted fixture (the control) and changes one thing.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

fn refused(why: &'static str, f: impl FnOnce(&mut Value)) {
    assert_eq!(mutated(f).unwrap_err(), value_err(why));
}

fn t(s: &str) -> Value {
    Value::String(URL_SAFE_NO_PAD.encode(s))
}

fn host(registered: &str, intrinsic: &str) -> Value {
    json!({"registered": registered, "intrinsic": intrinsic, "reader_floor": "9".repeat(64)})
}

#[test]
fn regions_and_hosts_are_strictly_sorted_unique_and_nonempty() {
    refused("region order", |v| {
        v["topology"]["regions"].as_array_mut().unwrap().reverse()
    });
    refused("region order", |v| {
        let first = v["topology"]["regions"][0].clone();
        v["topology"]["regions"].as_array_mut().unwrap().push(first);
    });
    refused("region order", |v| v["topology"]["regions"] = json!([]));
    refused("host order", |v| {
        v["topology"]["regions"][1]["hosts"]
            .as_array_mut()
            .unwrap()
            .reverse()
    });
    refused("host order", |v| {
        v["topology"]["regions"][0]["hosts"] = json!([])
    });
    refused("host order", |v| {
        let dup = v["topology"]["regions"][1]["hosts"][0].clone();
        v["topology"]["regions"][1]["hosts"]
            .as_array_mut()
            .unwrap()
            .push(dup);
    });
}

#[test]
fn registered_and_intrinsic_ids_map_one_to_one_across_regions() {
    refused("host alias", |v| {
        v["topology"]["regions"][0]["hosts"] = json!([host("h17-eu", "host.test")]);
    });
    refused("host alias", |v| {
        v["topology"]["regions"][0]["hosts"] = json!([host("h16", "host-eu.test")]);
    });
    refused("host alias", |v| {
        v["topology"]["regions"][1]["hosts"][1]["intrinsic"] = json!("host.test");
    });
}

#[test]
fn exactly_one_row_matches_the_registered_and_intrinsic_host() {
    refused("target host row", |v| v["registered"] = json!("h16"));
    refused("target host row", |v| {
        v["x"]["host"] = json!("host-na-2.test");
        v["closure"]["x"]["host"] = json!("host-na-2.test");
    });
    refused("target host row", |v| v["registered"] = json!("unenrolled"));
    refused("target host row", |v| {
        v["topology"]["regions"][1]["hosts"][0]["intrinsic"] = json!("host-na-3.test");
    });
}

#[test]
fn the_rollout_order_names_every_enrolled_host_exactly_once() {
    refused("rollout order", |v| {
        v["topology"]["order"] = json!(["h17-eu", "h16"])
    });
    refused("rollout order", |v| {
        v["topology"]["order"] = json!(["h17-eu", "h16", "h15", "h15"])
    });
    refused("rollout order", |v| {
        v["topology"]["order"] = json!(["h17-eu", "h16", "h14"])
    });
    refused("rollout order", |v| {
        v["topology"]["order"] = json!(["h17-eu", "h16", "h15", "h99"])
    });
    refused("rollout order", |v| {
        v["topology"]["order"] = json!(["h17-eu", "h15", "h15"])
    });
    mutated(|v| v["topology"]["order"] = json!(["h15", "h16", "h17-eu"])).unwrap();
}

#[test]
fn the_regional_serving_floor_survives_the_target_leaving() {
    refused("regional serving floor", |v| {
        v["topology"]["regions"][1]["minimum_accepting"] = json!(2)
    });
    refused("regional serving floor", |v| {
        v["topology"]["regions"][0]["minimum_accepting"] = json!(2)
    });
    mutated(|v| {
        v["topology"]["regions"][0]["hosts"] =
            json!([host("h17-eu", "host-eu.test"), host("h18", "h18.test")]);
        v["topology"]["order"] = json!(["h17-eu", "h18", "h16", "h15"]);
        v["topology"]["regions"][0]["minimum_accepting"] = json!(2);
    })
    .unwrap();
    assert_eq!(
        mutated(|v| v["topology"]["regions"][1]["minimum_accepting"] = json!(0)).unwrap_err(),
        CodecError::Schema,
        "the floor is never below one accepting host"
    );
}

#[test]
fn actors_are_sorted_by_wire_name_then_id_not_by_enum_declaration() {
    refused("actor order", |v| {
        v["actors"].as_array_mut().unwrap().reverse()
    });
    // Rust enum declaration order: H, A, B, R, installer, gateway.
    refused("actor order", |v| {
        let rows = v["actors"].as_array().unwrap().clone();
        let order = [2, 0, 1, 3, 5, 4];
        v["actors"] = Value::Array(order.iter().map(|i| rows[*i].clone()).collect());
    });
    refused("actor order", |v| {
        let dup = v["actors"][1].clone();
        v["actors"].as_array_mut().unwrap().insert(1, dup);
    });
    mutated(|v| {
        let mut installer = v["actors"][5].clone();
        installer["id"] = json!("installer-0");
        v["actors"]
            .as_array_mut()
            .unwrap()
            .insert(5, installer.clone());
        let mut peer = v["closure"]["peers"][5].clone();
        peer["id"] = json!("installer-0");
        peer["server"] = json!({"leaf": "e".repeat(64), "spki": "e".repeat(64)});
        peer["client"] = json!({"leaf": "f".repeat(64), "spki": "f".repeat(64)});
        v["closure"]["peers"]
            .as_array_mut()
            .unwrap()
            .insert(5, peer);
    })
    .unwrap();
    refused("actor order", |v| {
        let mut installer = v["actors"][5].clone();
        installer["id"] = json!("installer-0");
        v["actors"].as_array_mut().unwrap().push(installer);
    });
}

#[test]
fn the_actor_rows_and_closure_peers_have_exactly_the_same_key_set() {
    refused("actor and peer key sets", |v| {
        v["closure"]["peers"].as_array_mut().unwrap().remove(1);
    });
    refused("actor and peer key sets", |v| {
        v["actors"].as_array_mut().unwrap().remove(1);
    });
    refused("actor and peer key sets", |v| {
        v["actors"][0]["id"] = json!("authority-2")
    });
    refused("actor and peer key sets", |v| {
        v["closure"]["peers"][3]["id"] = json!("receiver-2")
    });
    for missing in ["H", "A", "B", "R", "gateway", "installer"] {
        refused("actor roster", |v| {
            v["actors"]
                .as_array_mut()
                .unwrap()
                .retain(|row| row["actor"] != missing);
            v["closure"]["peers"]
                .as_array_mut()
                .unwrap()
                .retain(|row| row["actor"] != missing);
        });
    }
    assert_eq!(
        mutated(|v| v["actors"][0]["actor"] = json!("X")).unwrap_err(),
        CodecError::Schema
    );
}

#[test]
fn process_form_is_null_for_h_and_a_required_for_replicas_and_not_invented() {
    refused("actor process form", |v| {
        v["actors"][2]["proc"] = v["actors"][4]["proc"].clone()
    });
    refused("actor process form", |v| {
        v["actors"][0]["proc"] = v["actors"][4]["proc"].clone()
    });
    refused("actor process form", |v| {
        v["actors"][4]["proc"] = Value::Null
    });
    refused("actor process form", |v| {
        v["actors"][5]["proc"] = Value::Null
    });
    mutated(|v| v["actors"][1]["proc"] = v["actors"][4]["proc"].clone()).unwrap();
    mutated(|v| v["actors"][3]["proc"] = v["actors"][4]["proc"].clone()).unwrap();
    // No successor is projected anywhere: neither a Proc nor any extra field on a resource.
    for field in ["next", "successor", "candidate_proc", "proc"] {
        assert_eq!(
            mutated(|v| v["daemon"][field] = v["daemon"]["pre"].clone()).unwrap_err(),
            CodecError::Schema,
            "{field}"
        );
    }
    assert_eq!(
        mutated(|v| v["daemon"]["candidate"]["proc"] = v["daemon"]["pre"].clone()).unwrap_err(),
        CodecError::Schema
    );
}

#[test]
fn each_role_has_its_fixed_guard_and_control_socket() {
    let daemon_guard = t("/usr/local/bin/briqyardd");
    let fleet_guard = t("/usr/local/bin/briqyard-fleet");
    refused("guard locator", |v| {
        v["daemon"]["guard"]["file"]["path"] = fleet_guard
    });
    refused("guard locator", |v| {
        v["authority"]["guard"]["file"]["path"] = daemon_guard
    });
    refused("guard locator", |v| {
        v["daemon"]["guard"]["file"]["path"] = t("/tmp/briqyardd")
    });
    refused("candidate locator", |v| {
        v["daemon"]["candidate"]["file"]["path"] = v["daemon"]["guard"]["file"]["path"].clone();
    });
    refused("control socket", |v| {
        v["daemon"]["control"]["path"] = t("/run/briqyard-sealed/authority/control");
    });
    refused("control socket", |v| {
        v["authority"]["control"]["path"] = t("/run/briqyard-sealed/daemon/control");
    });
    refused("control socket", |v| {
        v["daemon"]["control"]["mode"] = json!(0o666)
    });
    refused("control socket", |v| {
        v["daemon"]["control"]["mode"] = json!(432)
    });
    refused("control socket", |v| {
        v["authority"]["control"]["mode"] = json!(384)
    });
    refused("control socket", |v| {
        v["daemon"]["control"]["uid"] = json!(1000)
    });
    refused("control socket", |v| {
        v["authority"]["control"]["uid"] = json!(1000)
    });
    refused("control socket", |v| {
        v["daemon"]["control"]["gid"] = json!(1000)
    });
    refused("control socket", |v| {
        v["authority"]["control"]["gid"] = json!(4294967296u64)
    });
    refused("journal directory", |v| {
        v["authority"]["journal"]["mode"] = json!(0o1777)
    });
    refused("journal directory", |v| {
        v["daemon"]["journal"]["uid"] = json!(4294967296u64)
    });
    mutated(|v| v["authority"]["control"]["gid"] = json!(4242)).unwrap();
}

#[test]
fn byte_bounds_hold_for_executables_and_small_objects() {
    mutated(|v| v["daemon"]["candidate"]["file"]["bytes"] = json!(256u64 * 1024 * 1024)).unwrap();
    refused("executable byte bound", |v| {
        v["daemon"]["candidate"]["file"]["bytes"] = json!(256u64 * 1024 * 1024 + 1);
    });
    refused("executable byte bound", |v| {
        v["authority"]["guard"]["file"]["bytes"] = json!(256u64 * 1024 * 1024 + 1);
    });
    mutated(|v| v["daemon"]["config"]["bytes"] = json!(65536)).unwrap();
    for field in ["config", "tls_cert", "tls_key"] {
        refused("config or TLS byte bound", |v| {
            v["daemon"][field]["bytes"] = json!(65537)
        });
        refused("config or TLS byte bound", |v| {
            v["authority"][field]["bytes"] = json!(65537)
        });
    }
}

#[test]
fn listener_count_order_names_and_store_maximum_are_closed() {
    refused("listener count above the store maximum", |v| {
        v["authority"]["listeners"]["count"] = json!(2)
    });
    refused("listener count above the store maximum", |v| {
        v["daemon"]["listeners"]["store_max"] = json!(1)
    });
    refused("empty listener table digest", |v| {
        v["authority"]["listeners"]["count"] = json!(0)
    });
    mutated(|v| {
        v["authority"]["listeners"]["count"] = json!(0);
        v["authority"]["listeners"]["names"] = json!(HexDigest::of(b"").as_str());
    })
    .unwrap();
    mutated(|v| v["daemon"]["listeners"]["store_max"] = json!(2)).unwrap();
}

#[test]
fn every_native_process_shares_the_one_surviving_boot() {
    let other = "00000000-0000-4000-8000-0000000000ff";
    refused("surviving boot", |v| {
        v["daemon"]["pre"]["boot"] = json!(other)
    });
    refused("surviving boot", |v| {
        v["daemon"]["custodian"]["boot"] = json!(other)
    });
    refused("surviving boot", |v| {
        v["authority"]["pre"]["boot"] = json!(other)
    });
    refused("surviving boot", |v| {
        v["authority"]["custodian"]["boot"] = json!(other)
    });
    refused("surviving boot", |v| {
        v["closure"]["support"]["boot_id"] = json!(other)
    });
    assert_eq!(
        mutated(|v| v["closure"]["support"]["boot_id"] = json!("0000000000000000000080000000004"))
            .unwrap_err(),
        CodecError::Schema
    );
    assert_eq!(
        mutated(
            |v| v["closure"]["support"]["boot_id"] = json!("00000000-0000-4000-8000-00000000000A")
        )
        .unwrap_err(),
        CodecError::Schema
    );
}

#[test]
fn closure_x_is_the_manifest_x_and_the_credential_purposes_are_distinct() {
    refused("closure scope", |v| v["closure"]["x"]["serial"] = json!(2));
    refused("closure scope", |v| v["x"]["op"] = json!("1".repeat(64)));
    refused("closure scope", |v| {
        v["closure"]["x"]["aud"] = json!("production")
    });
    refused("credential purposes", |v| {
        v["closure"]["admin_fleet"] = v["closure"]["admin_host"].clone()
    });
    refused("credential purposes", |v| {
        v["closure"]["continuation"]["bearer"] = v["closure"]["admin_host"].clone();
    });
    refused("credential purposes", |v| {
        v["closure"]["continuation"]["bearer"] = v["closure"]["admin_fleet"].clone();
    });
}

#[test]
fn continuation_roots_are_a_sorted_unique_set_of_one_to_eight_anchors() {
    let root = |n: u8| Value::String(URL_SAFE_NO_PAD.encode([n; 40]));
    let mut anchors: Vec<(HexDigest, Value)> = (1..=9).map(|n| (d(&[n; 40]), root(n))).collect();
    anchors.sort_by(|a, b| a.0.cmp(&b.0));
    let sorted: Vec<Value> = anchors.iter().map(|(_, r)| r.clone()).collect();
    mutated(|v| v["closure"]["continuation"]["roots"] = Value::Array(sorted[..8].to_vec()))
        .unwrap();
    refused("continuation roots", |v| {
        v["closure"]["continuation"]["roots"] = Value::Array(sorted.clone())
    });
    refused("continuation roots", |v| {
        v["closure"]["continuation"]["roots"] = json!([])
    });
    refused("continuation roots", |v| {
        v["closure"]["continuation"]["roots"] = json!([sorted[0].clone(), sorted[0].clone()]);
    });
    refused("continuation roots", |v| {
        v["closure"]["continuation"]["roots"] = json!([sorted[1].clone(), sorted[0].clone()]);
    });
    assert_eq!(
        mutated(|v| v["closure"]["continuation"]["roots"] = json!(["!!"])).unwrap_err(),
        CodecError::Schema
    );
    assert_eq!(
        mutated(|v| v["closure"]["continuation"]["roots"] = json!([""])).unwrap_err(),
        CodecError::Schema
    );
}

#[test]
fn continuation_url_is_an_exact_https_url_without_userinfo_query_or_fragment() {
    mutated(|v| {
        v["closure"]["continuation"]["url"] =
            t("https://api.stg.example.test/internal/execution/v1/continue")
    })
    .unwrap();
    for bad in [
        "http://api.example.test/x",
        "https://user@api.example.test/x",
        "https://api.example.test/x?y=1",
        "https://api.example.test/x#f",
        "https://",
        "https:///x",
        "api.example.test/x",
        "ftp://a/x",
        "https://api.example.test:/x",
        "https://api.example.test/x y",
        "https://exa mple.test/x",
    ] {
        refused("continuation url", |v| {
            v["closure"]["continuation"]["url"] = t(bad)
        });
    }
}

#[test]
fn peers_are_sorted_unique_exact_private_https_origins_on_their_ports() {
    refused("peer order", |v| {
        v["closure"]["peers"].as_array_mut().unwrap().reverse()
    });
    for bad in [
        "http://h.example.test:9000",
        "https://h.example.test",
        "https://u@h.example.test:9000",
        "https://h.example.test:9000/",
        "https://h.example.test:9000/x",
        "https://h.example.test:9000?x=1",
        "https://h.example.test:9000#f",
        "https://h.example.test:0",
        "https://h.example.test:09000",
        "https://h.example.test:65536",
        "https://:9000",
        "https://h.example.test:",
        "h.example.test:9000",
        "https://h_x.example.test:9000",
        "https://h.example.test:9000 ",
    ] {
        refused("peer endpoint", |v| {
            v["closure"]["peers"][1]["endpoint"] = t(bad)
        });
    }
    mutated(|v| v["closure"]["peers"][1]["endpoint"] = t("https://[::1]:9000")).unwrap();
    mutated(|v| v["closure"]["peers"][1]["endpoint"] = t("https://10.0.0.7:9000")).unwrap();
    refused("peer endpoint port", |v| {
        v["closure"]["peers"][2]["endpoint"] = t("https://h.example.test:7542")
    });
    refused("peer endpoint port", |v| {
        v["closure"]["peers"][0]["endpoint"] = t("https://a.example.test:7541")
    });
    refused("peer endpoint port", |v| {
        v["closure"]["peers"][2]["endpoint"] = t("https://h.example.test:7441")
    });
    for port in [7541, 7542, 7441, 7442, 3003] {
        refused("peer endpoint port", |v| {
            v["closure"]["peers"][1]["endpoint"] = t(&format!("https://b.example.test:{port}"));
        });
    }
}

#[test]
fn no_tls_identity_is_shared_between_peers_roles_or_the_admin_pair() {
    refused("shared TLS identity", |v| {
        v["closure"]["peers"][1]["client"] = v["closure"]["peers"][1]["server"].clone();
    });
    refused("shared TLS identity", |v| {
        v["closure"]["peers"][4]["server"] = v["closure"]["peers"][5]["server"].clone();
    });
    refused("shared TLS identity", |v| {
        v["closure"]["peers"][4]["client"]["spki"] =
            v["closure"]["peers"][5]["client"]["spki"].clone();
    });
    refused("shared TLS identity", |v| {
        v["closure"]["peers"][4]["client"]["leaf"] =
            v["closure"]["peers"][5]["server"]["leaf"].clone();
    });
    refused("shared TLS identity", |v| {
        v["closure"]["admin_tls"] = v["closure"]["peers"][2]["server"].clone();
    });
    mutated(|v| {
        v["closure"]["admin_tls"] = json!({"leaf": "d".repeat(64), "spki": "d".repeat(64)})
    })
    .unwrap();
}
