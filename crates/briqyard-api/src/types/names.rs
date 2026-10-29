//! Sleep windows, ids, names and labels.

use super::*;

/// Parses a sleep window: "30m", "2h", "7d", "never" or "". `None` is never.
pub fn parse_sleep(s: &str) -> Result<Option<std::time::Duration>, String> {
    let s = s.trim();
    if s.is_empty() || s == "never" {
        return Ok(None);
    }
    duration(s, r#"want "30m", "2h", "7d" or "never""#)
        .map(Some)
        .map_err(|e| format!("sleep {e}"))
}

/// A duration as the API writes one: a positive count and a unit, `s`, `m`, `h` or `d`. The
/// error starts with the value, for the caller to put its field before; `want` says what a
/// malformed one should look like.
pub(super) fn duration(s: &str, want: &str) -> Result<std::time::Duration, String> {
    let bad = || format!("{s:?}: {want}");
    // The unit is the last character, not the last byte: splitting inside a multi-byte
    // character would panic.
    let (num, unit) = match s.char_indices().last() {
        Some((i, _)) => s.split_at(i),
        None => return Err(bad()),
    };
    let n: u64 = num.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(format!("{s:?}: must be positive"));
    }
    let per_unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(bad()),
    };
    let secs = n
        .checked_mul(per_unit)
        .ok_or_else(|| format!("{s:?}: too long"))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// An id the API takes from a caller (a namespace, a machine id in a path or a restore): a-z,
/// 0-9, `_` and `-`, 1 to 64 characters. Ids become file and object names on the host, so
/// nothing else gets in.
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// A DNS label: a-z, 0-9, hyphens inside, at most 63 characters.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 || b[0] == b'-' || b[b.len() - 1] == b'-' {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// One requirement of a label selector, `?label=` on a listing (ADR 0025): `key=value` (equal)
/// or `key` (present). A machine's labels are its `metadata`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub key: String,
    pub value: Option<String>,
}

impl Label {
    /// Reads `k=v` or `k`, checked as Kubernetes checks labels. `!=`, `!k` and set-based
    /// selectors are refused by name.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.contains('!') || s.contains(['(', ' ']) {
            return Err(format!(
                "label {s:?}: only key=value and key are supported (no !=, !key, in or notin)"
            ));
        }
        let (key, value) = match s.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (s, None),
        };
        if !label_key(key) {
            return Err(format!(
                "label {s:?}: the key is an optional DNS prefix and \"/\", then at most 63 of a-z, A-Z, 0-9, -, _, ., alphanumeric at both ends"
            ));
        }
        if let Some(v) = value {
            if !v.is_empty() && !label_name(v) {
                return Err(format!(
                    "label {s:?}: the value is empty or at most 63 of a-z, A-Z, 0-9, -, _, ., alphanumeric at both ends"
                ));
            }
        }
        Ok(Self {
            key: key.into(),
            value: value.map(String::from),
        })
    }

    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match (labels.get(&self.key), &self.value) {
            (Some(have), Some(want)) => have == want,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

/// A label's name, or a value that is not empty: 1 to 63 characters, alphanumeric at both
/// ends, `-`, `_` and `.` inside.
fn label_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// `[prefix/]name`, the prefix a DNS subdomain of at most 253 characters.
fn label_key(s: &str) -> bool {
    match s.rsplit_once('/') {
        None => label_name(s),
        Some((prefix, name)) => {
            prefix.len() <= 253 && prefix.split('.').all(valid_name) && label_name(name)
        }
    }
}
