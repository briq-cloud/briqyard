//! What a host binary says it is (ADR 0027): the workspace's version and the commit it was
//! built from, `0.1.0+fdad892eeefa`. The daemon, the fleet and the CLI of one build say the same.
//!
//! The guest init does not link this crate: it says its guest version
//! (`briqyard_api::version::GUEST_VERSION`), which does not follow the release (ADR 0101).

/// This build's version.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BRIQYARD_COMMIT"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_build() {
        let (rel, commit) = VERSION.split_once('+').unwrap();
        assert_eq!(rel, env!("CARGO_PKG_VERSION"));
        assert!(!commit.is_empty());
    }
}
