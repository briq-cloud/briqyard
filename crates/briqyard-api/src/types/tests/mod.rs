use super::*;
use serde_json::{json, Value};

/// Parses `input` as a `T`, then checks it serializes to exactly `expected`: the field
/// names the API description promises, the defaults filled in, the skipped ones absent.
fn round_trip<T>(input: Value, expected: Value) -> T
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let v: T = serde_json::from_value(input.clone()).unwrap_or_else(|e| panic!("{input}: {e}"));
    assert_eq!(serde_json::to_value(&v).unwrap(), expected);
    v
}

/// `input` round-trips to itself.
fn same<T>(input: Value) -> T
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    round_trip(input.clone(), input)
}

fn ts() -> DateTime<Utc> {
    "2026-01-02T03:04:05Z".parse().unwrap()
}

mod events;
mod host;
mod lifecycle;
mod limits;
mod machine;
mod names;
mod namespaces;
