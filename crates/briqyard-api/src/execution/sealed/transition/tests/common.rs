//! Raw-byte decoding of the new objects: nulls are explicit, never omitted; key order,
//! whitespace and unknown or duplicate fields are refused before any typed check.

use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, CodecError};
use crate::execution::sealed::tests::{dg, pos};
use crate::execution::sealed::transition::*;

#[test]
fn a_nullable_field_is_present_as_null_and_never_omitted() {
    let text = json(&gate(GatePhase::Closed));
    assert!(text.contains(r#""arm":null"#) && text.contains(r#""bind":null"#));
    assert!(decode::<Gate>(text.as_bytes()).is_ok());
    let omitted = text.replace(r#""arm":null,"#, "");
    assert_ne!(omitted, text);
    assert_eq!(decode::<Gate>(omitted.as_bytes()), Err(CodecError::Schema));
    let guard_text = json(&guard(GuardPhase::Started));
    let omitted = guard_text.replace(r#""adoption":null,"#, "");
    assert_ne!(omitted, guard_text);
    assert_eq!(decode::<Guard>(omitted.as_bytes()), Err(CodecError::Schema));
}

#[test]
fn raw_bytes_must_be_exactly_the_canonical_encoding() {
    let text = json(&guard(GuardPhase::Started));
    assert!(decode::<Guard>(text.as_bytes()).is_ok());
    assert!(
        decode::<Guard>(format!("{text}\n").as_bytes()).is_err(),
        "trailing newline"
    );
    assert!(
        decode::<Guard>(text.replace(",\"epoch\"", ", \"epoch\"").as_bytes()).is_err(),
        "whitespace"
    );
    assert!(
        decode::<Guard>(
            text.replace(r#""epoch":"ep2""#, r#""epoch":"\u0065p2""#)
                .as_bytes()
        )
        .is_err(),
        "escape"
    );
    assert!(
        decode::<Guard>(
            text.replace(r#""plan":"1"#, r#""extra":1,"plan":"1"#)
                .as_bytes()
        )
        .is_err(),
        "unknown key"
    );
    assert!(
        decode::<Guard>(
            text.replacen(
                r#""phase":"started","#,
                r#""phase":"started","phase":"started","#,
                1
            )
            .as_bytes()
        )
        .is_err(),
        "duplicate key"
    );
    let swapped = text.replace(r#""epoch":"ep2","launch":"8888888888888888888888888888888888888888888888888888888888888888""#, r#""launch":"8888888888888888888888888888888888888888888888888888888888888888","epoch":"ep2""#);
    assert_ne!(swapped, text);
    assert!(
        decode::<Guard>(swapped.as_bytes()).is_err(),
        "unsorted keys"
    );
}

#[test]
fn integers_are_safe_unsigned_and_positive_where_the_schema_says() {
    let text = json(&reg_done());
    assert!(text.contains(r#""host_water":3"#));
    for bad in [
        text.replace(r#""host_water":3"#, r#""host_water":0"#),
        text.replace(r#""host_water":3"#, r#""host_water":3.0"#),
        text.replace(r#""host_water":3"#, r#""host_water":-3"#),
        text.replace(r#""host_water":3"#, r#""host_water":9007199254740992"#),
    ] {
        assert!(decode::<RegDone>(bad.as_bytes()).is_err());
    }
    assert!(pos(9007199254740991).get() > 0);
}

#[test]
fn null_literals_and_bearers_do_not_accept_look_alikes() {
    assert_eq!(serde_json::to_string(&LitNull).unwrap(), "null");
    assert!(serde_json::from_str::<LitNull>("null").is_ok());
    for bad in ["0", "false", "\"\"", "{}", "[]"] {
        assert!(serde_json::from_str::<LitNull>(bad).is_err(), "{bad}");
    }
    assert!(Bearer::new(&format!("brx_{}", dg('a').as_str())).is_err());
}
