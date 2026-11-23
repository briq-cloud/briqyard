//! Raw-byte strictness and the closed scalar forms (versions, commits, T, paths, integers).

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

fn raw(replace: &str, with: &str) -> Vec<u8> {
    let text = std::str::from_utf8(INPUTS).unwrap();
    assert!(text.contains(replace), "fixture lacks {replace}");
    text.replacen(replace, with, 1).into_bytes()
}

fn t(s: &str) -> Value {
    Value::String(URL_SAFE_NO_PAD.encode(s))
}

fn assert_schema(f: impl FnOnce(&mut Value)) {
    assert_eq!(mutated(f).unwrap_err(), CodecError::Schema);
}

#[test]
fn the_document_is_one_bounded_canonical_utf8_object() {
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(INPUTS);
    let mut lf = INPUTS.to_vec();
    lf.push(b'\n');
    let mut space = INPUTS.to_vec();
    space.push(b' ');
    let spaced = raw(
        r#""format":"native.inputs/v1""#,
        r#""format": "native.inputs/v1""#,
    );
    let escaped = raw("native.inputs/v1", "native.inputs\\u002fv1");
    for (why, bytes) in [
        ("BOM", bom),
        ("final LF", lf),
        ("trailing space", space),
        ("whitespace", spaced),
        ("escape", escaped),
        ("empty", Vec::new()),
        ("array root", b"[]".to_vec()),
    ] {
        assert!(decode::<Inputs>(&bytes).is_err(), "{why}");
    }
    let oversize = vec![b' '; 65537];
    assert_eq!(
        decode::<Inputs>(&oversize).unwrap_err(),
        CodecError::TooLarge
    );
}

#[test]
fn duplicate_unsorted_unknown_and_missing_fields_are_refused() {
    assert_eq!(
        decode::<Inputs>(&raw(r#"{"actors":"#, r#"{"actors":[],"actors":"#)).unwrap_err(),
        CodecError::DuplicateKey
    );
    assert_eq!(
        decode::<Inputs>(&raw(r#"{"actors":"#, r#"{"assets_abi":3,"actors":"#)).unwrap_err(),
        CodecError::UnsortedKeys
    );
    assert_schema(|v| {
        v["zz_extension"] = json!(1);
    });
    assert_schema(|v| {
        v["daemon"]["unknown"] = json!(0);
    });
    assert_schema(|v| {
        v["closure"]["peers"][0]["extra"] = json!("x");
    });
    for key in [
        "closure",
        "daemon",
        "authority",
        "actors",
        "topology",
        "x",
        "registered",
        "assets_abi",
    ] {
        assert_schema(|v| {
            v.as_object_mut().unwrap().remove(key);
        });
    }
    for key in ["admin_tls", "backup_s3", "file_key"] {
        assert_schema(|v| {
            v["closure"].as_object_mut().unwrap().remove(key);
        });
    }
    assert_schema(|v| {
        v["actors"][0].as_object_mut().unwrap().remove("proc");
    });
    assert_schema(|v| v["closure"] = Value::String("0".repeat(64)));
    assert_schema(|v| v["closure"]["registry"] = Value::Null);
}

#[test]
fn unknown_formats_and_abi_versions_are_refused() {
    for format in ["native.inputs/v2", "native.inputs/v0", "native.inputs", ""] {
        let err = mutated(|v| v["format"] = json!(format)).unwrap_err();
        assert_eq!(err, value_err("format"), "{format}");
    }
    assert_eq!(
        mutated(|v| v["closure"]["format"] = json!("native.closure/v2")).unwrap_err(),
        value_err("format")
    );
    for abi in [
        json!(2),
        json!(4),
        json!(0),
        json!("3"),
        json!(3.5),
        Value::Null,
    ] {
        assert!(mutated(|v| v["assets_abi"] = abi).is_err());
    }
}

#[test]
fn versions_are_exactly_three_canonical_decimal_components() {
    for good in ["0.0.0", "1.2.3", "10.200.3000"] {
        mutated(|v| v["source_release"]["version"] = json!(good)).unwrap();
    }
    for bad in [
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2",
        "1",
        "1.2.3.4",
        "v1.2.3",
        "1.2.3-rc1",
        "1.2.3+b",
        "1.2.x",
        "1..3",
        ".1.2",
        "1.2.",
        " 1.2.3",
        "1.2.3 ",
        "+1.2.3",
        "-1.2.3",
        "1.2.99999999999999999999",
        "",
    ] {
        assert_schema(|v| v["target_release"]["version"] = json!(bad));
    }
}

#[test]
fn commits_are_forty_lowercase_hex_and_other_digests_sixty_four() {
    for bad in [
        "A".repeat(40),
        "a".repeat(39),
        "a".repeat(41),
        "g".repeat(40),
        format!("{}A", "a".repeat(39)),
    ] {
        assert_schema(|v| v["source_release"]["commit"] = json!(bad));
    }
    for bad in [
        "A".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64),
    ] {
        assert_schema(|v| v["source_release"]["pin_file"] = json!(bad));
    }
    mutated(|v| v["source_release"]["commit"] = json!("0123456789abcdef0123456789abcdef01234567"))
        .unwrap();
    for bad in [0, -1] {
        assert!(mutated(|v| v["source_release"]["release_id"] = json!(bad)).is_err());
    }
    for bad in [
        json!("5"),
        json!(1.0),
        json!(9007199254740992u64),
        Value::Null,
    ] {
        assert!(mutated(|v| v["target_release"]["release_id"] = bad).is_err());
    }
}

#[test]
fn strict_t_accepts_only_canonical_bounded_text() {
    mutated(|v| v["closure"]["continuation"]["server_name"] = t("ok.example.test")).unwrap();
    let long = "a".repeat(2049);
    let max = "a".repeat(2048);
    mutated(|v| v["closure"]["continuation"]["server_name"] = t(&max)).unwrap();
    for (why, value) in [
        ("padding", json!("b2s=")),
        ("standard alphabet", json!("a+b/")),
        ("whitespace", json!("b2s ")),
        ("trailing bits", json!("YR")),
        ("empty", json!("")),
        ("too long", t(&long)),
        ("NUL", t("a\0b")),
        ("newline", t("a\nb")),
        ("tab", t("a\tb")),
        ("DEL", t("a\u{7f}b")),
        ("not text", json!(7)),
        ("null", Value::Null),
    ] {
        assert!(
            mutated(|v| v["closure"]["continuation"]["server_name"] = value).is_err(),
            "{why}"
        );
    }
    let invalid_utf8 = Value::String(URL_SAFE_NO_PAD.encode([0xff, 0xfe, 0x41]));
    assert_schema(|v| v["closure"]["continuation"]["server_name"] = invalid_utf8);
}

#[test]
fn paths_are_t_of_canonical_absolute_ascii_and_reencode_exactly() {
    mutated(|v| v["daemon"]["fragment"] = t("/etc/systemd/system/x.service")).unwrap();
    for bad in [
        "relative/path",
        "etc/x",
        "/",
        "/etc/",
        "/etc//x",
        "//etc/x",
        "/etc/./x",
        "/etc/../x",
        "/..",
        "/.",
        "/etc/x/",
        "/etc/x\ny",
        "/etc/\u{1}x",
        "/etc/é",
        "/etc/x\0",
        "./etc/x",
    ] {
        assert_schema(|v| v["daemon"]["fragment"] = t(bad));
    }
    assert_schema(|v| v["daemon"]["fragment"] = json!(""));
    let padded = format!("{}=", URL_SAFE_NO_PAD.encode("/etc/x"));
    assert_schema(|v| v["daemon"]["fragment"] = json!(padded));
    let plain = Value::String("/etc/x".into());
    assert_schema(|v| v["daemon"]["fragment"] = plain);
    for field in ["config", "guard"] {
        let pointer = if field == "guard" {
            "/daemon/guard/file/path"
        } else {
            "/daemon/config/path"
        };
        assert_schema(|v| *v.pointer_mut(pointer).unwrap() = t("/a/../b"));
    }
}

#[test]
fn integers_are_unsigned_decimal_json_numbers_only() {
    let mode_text = raw(r#""mode":384"#, r#""mode":"0600""#);
    assert!(decode::<Inputs>(&mode_text).is_err());
    for replacement in ["-1", "1.5", "1e3", "0600", "00", "384.0", "+384", "0x180"] {
        let bytes = raw(r#""mode":384"#, &format!(r#""mode":{replacement}"#));
        assert!(decode::<Inputs>(&bytes).is_err(), "{replacement}");
    }
    assert!(mutated(|v| v["daemon"]["control"]["uid"] = json!("0")).is_err());
    assert!(mutated(|v| v["daemon"]["config"]["bytes"] = json!(0)).is_err());
    assert!(mutated(|v| v["daemon"]["tls_key"]["bytes"] = json!(0)).is_err());
    assert!(mutated(|v| v["daemon"]["tls_cert"]["bytes"] = json!(0)).is_err());
    assert!(mutated(|v| v["daemon"]["guard"]["file"]["bytes"] = json!(0)).is_err());
}

#[test]
fn nullable_fields_accept_a_value_or_explicit_null_and_nothing_else() {
    let pair = json!({"leaf": "1".repeat(64), "spki": "2".repeat(64)});
    let inputs = mutated(|v| {
        v["closure"]["admin_tls"] = pair;
        v["closure"]["backup_s3"] = json!("3".repeat(64));
        v["closure"]["file_key"] = json!("a".repeat(32));
    })
    .unwrap();
    assert!(inputs.closure.admin_tls.is_some() && inputs.closure.backup_s3.is_some());
    assert!(inputs.closure.file_key.is_some());
    for bad in [
        "A".repeat(32),
        "a".repeat(31),
        "a".repeat(33),
        "g".repeat(32),
    ] {
        assert_schema(|v| v["closure"]["file_key"] = json!(bad));
    }
    assert_schema(|v| v["closure"]["admin_tls"] = json!({"leaf": "1".repeat(64)}));
    assert_schema(|v| v["closure"]["admin_tls"] = json!(false));
    assert_schema(|v| v["actors"][4]["proc"] = json!("none"));
}
