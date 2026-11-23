//! Release-pin, checksum-list and asset checks over explicitly supplied bytes. Pin files and
//! lists here are synthetic; the historical 0.2.15 file is a shape reference only and is
//! never selected, approved or checked against real assets.

use super::*;
use crate::execution::sealed::inputs::release::parse_pin;
use serde_json::json;

const HISTORICAL_PIN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/native_inputs_v1/historical_pin_0.2.15.json"
));

const DAEMON: &str = "briqyardd-linux-x86_64";
const FLEET: &str = "briqyard-fleet-linux-x86_64";
const CLI: &str = "briqyard-linux-x86_64";

fn list(rows: &[(&str, HexDigest)]) -> Vec<u8> {
    rows.iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>()
        .into_bytes()
}

fn good_rows(a: &[Vec<u8>; 3]) -> Vec<(&'static str, HexDigest)> {
    vec![(DAEMON, d(&a[0])), (FLEET, d(&a[1])), (CLI, d(&a[2]))]
}

/// A pin value for `sums` and `a`, shaped like a real release pin file.
fn pin(version: &str, sums: &[u8], a: &[Vec<u8>; 3]) -> Value {
    json!({
        "release": version,
        "commit": "a".repeat(40),
        "releaseId": 7,
        "sha256": {
            "SHA256SUMS-x86_64": d(sums).as_str(),
            DAEMON: d(&a[0]).as_str(),
            FLEET: d(&a[1]).as_str(),
            CLI: d(&a[2]).as_str(),
        },
        "source": format!("https://github.com/briq-cloud/briqyard/releases/tag/v{version}"),
    })
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}

fn check(pin: &Value, sums: &[u8], a: &[Vec<u8>; 3]) -> Result<VerifiedRelease, CodecError> {
    verify(&bytes(pin), sums, a)
}

#[test]
fn the_fixture_releases_agree_with_the_manifest_rows() {
    let inputs: Inputs = decode(INPUTS).unwrap();
    let r = releases();
    assert_eq!(*r.source.release(), inputs.source_release);
    assert_eq!(*r.target.release(), inputs.target_release);
    assert_eq!(inputs.source_release.pin_file, d(SOURCE_PIN));
    assert_eq!(inputs.target_release.sums, d(TARGET_SUMS));
    assert_eq!(inputs.target_release.daemon, d(&assets(1)[0]));
    assert_eq!(inputs.source_release.fleet, d(&assets(0)[1]));
}

#[test]
fn the_historical_pin_has_exactly_the_documented_five_field_shape() {
    assert_eq!(
        d(HISTORICAL_PIN).as_str(),
        "c1a0a50d1c33c6f87c273e193598e2a9998fdc0755155e50f4f20c162223a6a9"
    );
    let release = parse_pin(HISTORICAL_PIN).unwrap();
    assert_eq!(release.version.as_str(), "0.2.15");
    assert_eq!(
        release.commit.as_str(),
        "892fa23be717e63c6523a12c425e24856b3d09f8"
    );
    assert_eq!(release.release_id.get(), 447394990);
    assert_eq!(release.pin_file, d(HISTORICAL_PIN));
    assert_eq!(
        release.sums.as_str(),
        "4e966c173eae42e338f621bbb82659cf3d92fa2a1f6a2c518ef20b5143454a7e"
    );
    assert_eq!(
        release.daemon.as_str(),
        "430530e6a4e947e0b99e9809c28aaab56cdbbd88adb6dde883129440576e13cd"
    );
    assert!(
        HISTORICAL_PIN.ends_with(b"}\n"),
        "the raw digest covers the final LF"
    );
    let without_lf = &HISTORICAL_PIN[..HISTORICAL_PIN.len() - 1];
    assert_ne!(d(without_lf), release.pin_file);
    assert_eq!(parse_pin(without_lf).unwrap().pin_file, d(without_lf));
}

#[test]
fn a_pin_checksum_list_and_three_assets_that_agree_are_accepted() {
    let a = assets(3);
    let sums = list(&good_rows(&a));
    let verified = check(&pin("1.2.3", &sums, &a), &sums, &a).unwrap();
    let release = verified.release();
    assert_eq!(release.version.as_str(), "1.2.3");
    assert_eq!(release.sums, d(&sums));
    assert_eq!(release.cli, d(&a[2]));
    assert_eq!(verified.daemon_asset_bytes(), a[0].len() as u64);
}

#[test]
fn unrelated_official_checksum_entries_neither_matter_nor_confer_a_right() {
    let a = assets(3);
    let mut rows = good_rows(&a);
    rows.insert(1, ("nested-vmlinux-x86_64", d(b"kernel")));
    rows.push(("briqyard-linux-x86_64.sig", d(b"signature")));
    rows.push(("briqyardd-linux-aarch64", d(b"arm daemon")));
    let sums = list(&rows);
    check(&pin("1.2.3", &sums, &a), &sums, &a).unwrap();
    // An unrelated row cannot stand in for a required one, by any spelling of its name.
    for alias in [
        "./briqyardd-linux-x86_64",
        "briqyardd-linux-x86_64 ",
        "BRIQYARDD-LINUX-X86_64",
        "dist/briqyardd-linux-x86_64",
    ] {
        let mut rows = good_rows(&a);
        rows[0].0 = alias;
        let sums = list(&rows);
        assert_eq!(
            check(&pin("1.2.3", &sums, &a), &sums, &a).unwrap_err(),
            value_err("checksum entry"),
            "{alias:?}"
        );
    }
}

#[test]
fn the_pin_file_is_a_closed_five_field_object_with_its_own_tag_source() {
    let a = assets(3);
    let sums = list(&good_rows(&a));
    let ok = pin("1.2.3", &sums, &a);
    let broken = |f: &dyn Fn(&mut Value)| {
        let mut v = ok.clone();
        f(&mut v);
        check(&v, &sums, &a)
    };
    for key in ["release", "commit", "releaseId", "sha256", "source"] {
        assert_eq!(
            broken(&|v| {
                v.as_object_mut().unwrap().remove(key);
            })
            .unwrap_err(),
            CodecError::Schema,
            "{key}"
        );
    }
    for key in ["SHA256SUMS-x86_64", DAEMON, FLEET, CLI] {
        assert_eq!(
            broken(&|v| {
                v["sha256"].as_object_mut().unwrap().remove(key);
            })
            .unwrap_err(),
            CodecError::Schema,
            "{key}"
        );
    }
    assert_eq!(
        broken(&|v| v["extra"] = json!(1)).unwrap_err(),
        CodecError::Schema
    );
    assert_eq!(
        broken(&|v| v["sha256"]["briqyard-linux-aarch64"] = json!("0".repeat(64))).unwrap_err(),
        CodecError::Schema
    );
    assert_eq!(
        broken(&|v| v["releaseId"] = json!("7")).unwrap_err(),
        CodecError::Schema
    );
    assert_eq!(
        broken(&|v| v["releaseId"] = json!(0)).unwrap_err(),
        CodecError::Schema
    );
    assert_eq!(
        broken(&|v| v["commit"] = json!("A".repeat(40))).unwrap_err(),
        CodecError::Schema
    );
    for version in ["v1.2.3", "1.2", "1.2.3-rc1", "01.2.3"] {
        assert_eq!(
            broken(&|v| v["release"] = json!(version)).unwrap_err(),
            CodecError::Schema,
            "{version}"
        );
    }
    for source in [
        "https://github.com/briq-cloud/briqyard/releases/tag/v1.2.4",
        "https://github.com/briq-cloud/briqyard/releases/tag/1.2.3",
        "http://github.com/briq-cloud/briqyard/releases/tag/v1.2.3",
        "https://github.com/other/briqyard/releases/tag/v1.2.3",
        "https://github.com/briq-cloud/briqyard/releases/tag/v1.2.3/",
        "https://github.com/briq-cloud/briqyard/releases/latest",
        "",
    ] {
        assert_eq!(
            broken(&|v| v["source"] = json!(source)).unwrap_err(),
            value_err("release source"),
            "{source}"
        );
    }
}

#[test]
fn duplicate_keys_and_trailing_or_prefixed_bytes_in_the_pin_are_refused() {
    let a = assets(3);
    let sums = list(&good_rows(&a));
    let text = String::from_utf8(bytes(&pin("1.2.3", &sums, &a))).unwrap();
    let dup_top = text.replacen("\"commit\"", "\"release\": \"1.2.3\",\n  \"commit\"", 1);
    let dup_nested = text.replacen(
        &format!("\"{DAEMON}\""),
        &format!("\"{DAEMON}\": \"{}\",\n    \"{DAEMON}\"", "0".repeat(64)),
        1,
    );
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(text.as_bytes());
    for (why, pin) in [
        ("duplicate top-level key", dup_top.into_bytes()),
        ("duplicate asset key", dup_nested.into_bytes()),
        ("trailing bytes", format!("{text}{{}}").into_bytes()),
        ("BOM", bom),
        ("empty", Vec::new()),
        ("array", b"[]".to_vec()),
    ] {
        assert!(verify(&pin, &sums, &a).is_err(), "{why}");
    }
    verify(text.as_bytes(), &sums, &a).unwrap();
    verify(format!("{text}\n").as_bytes(), &sums, &a).unwrap();
}

#[test]
fn the_checksum_list_must_match_its_pinned_digest_and_hold_each_binary_exactly_once() {
    let a = assets(3);
    let sums = list(&good_rows(&a));
    let ok = pin("1.2.3", &sums, &a);
    let mut changed = sums.clone();
    changed.extend_from_slice(b"\n");
    assert_eq!(
        check(&ok, &changed, &a).unwrap_err(),
        value_err("checksum list digest")
    );
    let rows = good_rows(&a);
    for (why, bad) in [
        ("missing daemon", list(&rows[1..])),
        ("missing fleet", list(&[rows[0].clone(), rows[2].clone()])),
        ("missing cli", list(&rows[..2])),
        ("empty", Vec::new()),
        (
            "duplicate with the same digest",
            list(&[
                rows[0].clone(),
                rows[0].clone(),
                rows[1].clone(),
                rows[2].clone(),
            ]),
        ),
        (
            "duplicate with another digest",
            list(&[
                rows[0].clone(),
                (DAEMON, d(b"x")),
                rows[1].clone(),
                rows[2].clone(),
            ]),
        ),
        (
            "wrong digest",
            list(&[(DAEMON, d(b"x")), rows[1].clone(), rows[2].clone()]),
        ),
        (
            "swapped digests",
            list(&[(DAEMON, d(&a[1])), (FLEET, d(&a[0])), rows[2].clone()]),
        ),
    ] {
        let err = check(&pin("1.2.3", &bad, &a), &bad, &a).unwrap_err();
        assert!(
            matches!(
                err,
                CodecError::Value("checksum entry" | "checksum row" | "checksum list")
            ),
            "{why}: {err:?}"
        );
    }
    let text = String::from_utf8(sums.clone()).unwrap();
    for (why, bad) in [
        ("no final LF", text.trim_end().to_owned()),
        ("CRLF", text.replace('\n', "\r\n")),
        ("single space", text.replacen("  ", " ", 1)),
        ("tab", text.replacen("  ", "\t", 1)),
        (
            "uppercase digest",
            text.replacen(
                &d(&a[0]).as_str()[..4],
                &d(&a[0]).as_str()[..4].to_uppercase(),
                1,
            ),
        ),
        ("short digest", text[1..].to_owned()),
        ("blank line", format!("\n{text}")),
        ("star name", text.replacen("  briqyardd", "  *briqyardd", 1)),
    ] {
        let bad = bad.into_bytes();
        assert!(check(&pin("1.2.3", &bad, &a), &bad, &a).is_err(), "{why}");
    }
    let invalid = [sums.as_slice(), b"\xff\xfe"].concat();
    assert!(check(&pin("1.2.3", &invalid, &a), &invalid, &a).is_err());
}

#[test]
fn each_asset_must_hash_to_its_pinned_digest_and_not_a_sibling() {
    let a = assets(3);
    let sums = list(&good_rows(&a));
    let ok = pin("1.2.3", &sums, &a);
    for index in 0..3 {
        let mut other = a.clone();
        other[index].push(b'!');
        assert_eq!(
            check(&ok, &sums, &other).unwrap_err(),
            value_err("release asset digest"),
            "{index}"
        );
    }
    let mut swapped = a.clone();
    swapped.swap(0, 1);
    assert_eq!(
        check(&ok, &sums, &swapped).unwrap_err(),
        value_err("release asset digest")
    );
    // A pin that disagrees with its own list is refused even when the asset matches the pin.
    let mut forged = ok.clone();
    forged["sha256"][DAEMON] = json!(d(b"forged").as_str());
    let mut forged_assets = a.clone();
    forged_assets[0] = b"forged".to_vec();
    assert_eq!(
        check(&forged, &sums, &forged_assets).unwrap_err(),
        value_err("checksum entry")
    );
}
