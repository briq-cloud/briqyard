//! Runtime classes (ADR 0088): the named kernels a host serves.

use super::*;

/// The class every host serves and no configuration writes.
pub const DEFAULT_CLASS: &str = "default";

/// A class a host serves, as its status and heartbeat tell it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeClassInfo {
    pub name: String,
    /// Its machines see the CPU's virtualization extensions (`/dev/kvm` works in them), and
    /// take no memory snapshot.
    #[serde(default, skip_serializing_if = "super::limits::is_false")]
    pub nested: bool,
    /// The release of the class's kernel, `6.18.54-briqyard-nested`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kernel_release: String,
    /// The OpenZFS version of the class's modules, when it carries them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub openzfs: String,
}

/// A class name a configuration may write: a DNS label other than `default`.
pub fn valid_class_name(s: &str) -> bool {
    s != DEFAULT_CLASS && valid_name(s)
}

/// A machine's class as the API names it: an empty one is the default.
pub fn class_name(s: &str) -> &str {
    if s.is_empty() {
        DEFAULT_CLASS
    } else {
        s
    }
}

/// The classes a host's status lists, without `default`, which every host serves: whether a
/// request naming `class` can run there.
pub fn serves_class(classes: &[RuntimeClassInfo], class: &str) -> bool {
    class_name(class) == DEFAULT_CLASS || classes.iter().any(|c| c.name == class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_serving() {
        assert!(valid_class_name("nested"));
        assert!(!valid_class_name("default"));
        assert!(!valid_class_name("Nested"));
        assert!(!valid_class_name(""));
        assert_eq!(class_name(""), "default");
        assert_eq!(class_name("nested"), "nested");
        let nested = [RuntimeClassInfo {
            name: "nested".into(),
            ..Default::default()
        }];
        assert!(serves_class(&[], ""));
        assert!(serves_class(&[], "default"));
        assert!(!serves_class(&[], "nested"));
        assert!(serves_class(&nested, "nested"));
        assert!(!serves_class(&nested, "other"));
    }
}
