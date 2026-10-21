//! What a binary says it is (ADR 0027): the workspace's version and the commit it was built
//! from, `0.1.0+fdad892eeefa`. Every binary of one build says the same.

/// This build's version.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BRIQYARD_COMMIT"));

/// The release part of a version (`0.1.0` of `0.1.0+fdad892eeefa`), as numbers; None when it
/// is not `major.minor.patch`.
fn release(v: &str) -> Option<(u64, u64, u64)> {
    let mut n = v
        .split('+')
        .next()?
        .split('.')
        .map(|p| p.parse::<u64>().ok());
    let r = (n.next()??, n.next()??, n.next()??);
    n.next().is_none().then_some(r)
}

/// Whether `a` is a later release than `b`. Two builds of one release are not ordered (a
/// commit says nothing of which came first), and neither is a version that cannot be read.
pub fn newer(a: &str, b: &str) -> bool {
    matches!((release(a), release(b)), (Some(a), Some(b)) if a > b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_build() {
        let (rel, commit) = VERSION.split_once('+').unwrap();
        assert_eq!(rel, env!("CARGO_PKG_VERSION"));
        assert!(!commit.is_empty());
        assert!(release(VERSION).is_some());
    }

    #[test]
    fn releases_are_ordered_by_their_numbers() {
        assert!(newer("0.2.0+b", "0.1.9+a"));
        assert!(newer("0.10.0", "0.9.0"), "numbers, not text");
        assert!(newer("1.0.0+x", "0.99.99+y"));
        assert!(!newer("0.1.0+b", "0.1.0+a"), "two builds of one release");
        assert!(!newer("0.1.0", "0.2.0"));
        // An empty version (a host from before ADR 0027) or anything else is not ordered.
        assert!(!newer("0.2.0", ""));
        assert!(!newer("", "0.1.0"));
        assert!(!newer("0.2", "0.1.0"));
        assert!(!newer("0.2.0.1", "0.1.0"));
        assert!(!newer("v0.2.0", "0.1.0"));
    }
}
