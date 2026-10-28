//! The Prometheus text exposition (0.0.4), written by hand: the daemon's `/metrics` (ADR 0021)
//! and the fleet's (ADR 0042) share these.

/// A label value as the format writes it: `\\`, `\"` and `\n` escaped.
pub fn label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// One family: its HELP and TYPE, then its samples, `(labels, value)`.
pub fn family(
    out: &mut String,
    name: &str,
    kind: &str,
    help: &str,
    samples: Vec<(String, String)>,
) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
    for (labels, v) in samples {
        match labels.is_empty() {
            true => out.push_str(&format!("{name} {v}\n")),
            false => out.push_str(&format!("{name}{{{labels}}} {v}\n")),
        }
    }
}

/// Checks text against the exposition format (0.0.4): every line a `# HELP`, a `# TYPE` or a
/// sample; a family's HELP and TYPE once, before its samples, which are together; label names
/// and values well formed; values numbers; no series twice. Panics on the first fault: for
/// tests, the daemon's and the fleet's.
// For tests only: it panics.
#[doc(hidden)]
pub fn check_exposition(text: &str) {
    use std::collections::HashSet;
    let name_ok = |n: &str| {
        let mut c = n.chars();
        c.next()
            .is_some_and(|f| f.is_ascii_alphabetic() || f == '_' || f == ':')
            && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == ':')
    };
    let (mut typed, mut helped, mut done, mut series) = (
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    );
    let mut current = String::new();
    // A family begins: the one before it is done.
    let enter = |name: &str, current: &mut String, done: &mut HashSet<String>| {
        assert!(!done.contains(name), "{name} again, apart from its samples");
        if current != name {
            done.insert(std::mem::replace(current, name.to_string()));
        }
    };
    assert!(text.ends_with('\n'), "ends with a newline");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            let (kw, rest) = rest.split_once(' ').expect(line);
            let (name, arg) = rest.split_once(' ').expect(line);
            assert!(name_ok(name), "{line}");
            enter(name, &mut current, &mut done);
            match kw {
                "HELP" => assert!(helped.insert(name.to_string()), "HELP twice: {line}"),
                "TYPE" => {
                    assert!(["counter", "gauge", "untyped"].contains(&arg), "{line}");
                    assert!(typed.insert(name.to_string()), "TYPE twice: {line}");
                }
                _ => panic!("not a comment of the format: {line}"),
            }
            continue;
        }
        let (head, value) = line.rsplit_once(' ').expect(line);
        assert!(
            value.parse::<f64>().is_ok() || ["+Inf", "-Inf", "NaN"].contains(&value),
            "value: {line}"
        );
        let (name, labels) = match head.split_once('{') {
            Some((n, l)) => (n, l.strip_suffix('}').expect(line)),
            None => (head, ""),
        };
        assert!(name_ok(name), "{line}");
        assert!(typed.contains(name), "a sample before its TYPE: {line}");
        enter(name, &mut current, &mut done);
        let mut names = HashSet::new();
        let mut rest = labels;
        while !rest.is_empty() {
            let (l, after) = rest.split_once("=\"").expect(line);
            assert!(name_ok(l) && !l.contains(':'), "label {l}: {line}");
            assert!(names.insert(l), "label {l} twice: {line}");
            let mut chars = after.char_indices();
            let end = loop {
                match chars.next().expect(line) {
                    (_, '\\') => {
                        let (_, e) = chars.next().expect(line);
                        assert!(['\\', '"', 'n'].contains(&e), "escape: {line}");
                    }
                    (i, '"') => break i,
                    _ => {}
                }
            };
            rest = &after[end + 1..];
            rest = rest.strip_prefix(',').unwrap_or(rest);
        }
        assert!(series.insert(head.to_string()), "series twice: {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_check_refuses_what_is_not_the_format() {
        check_exposition("# HELP a A.\n# TYPE a gauge\na{x=\"1\\\"\"} 1\na 2\n");
        for bad in [
            "a 1\n",
            "# TYPE a gauge\na{x=\"1\"} one\n",
            "# TYPE a gauge\na{x=1} 1\n",
            "# TYPE a gauge\na 1\n# TYPE b gauge\nb 1\na 2\n",
            "# TYPE a gauge\na 1\na 1\n",
            "# TYPE a gauge\na{x=\"\\t\"} 1\n",
        ] {
            assert!(
                std::panic::catch_unwind(|| check_exposition(bad)).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
