//! Versions and their order (ADR 0027). A host binary says its release and commit
//! (`briqyard_version::VERSION`, `0.1.0+fdad892eeefa`). The guest init says [`GUEST_VERSION`],
//! which is not the release: the init's bytes do not follow the release or the commit (ADR 0098).

/// The version the guest init reports in its `pong` and its exit report: the first release
/// whose guest protocol it speaks. Set it to the workspace release in the change that adds
/// something the daemon gates on (a [`SESSIONS`]-style constant, compared with [`before`]);
/// leave it otherwise. A release that does not touch the guest protocol keeps it, so the
/// init, and the seeds bound to its digest, stay the same.
pub const GUEST_VERSION: &str = "0.1.20";

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

/// The first release whose init runs exec sessions, input streamed and a terminal (ADR 0029).
pub const SESSIONS: &str = "0.1.0";

/// Whether `v` is of a release before `release`. A version that cannot be read (an init older
/// than the version report says none) is before every release.
pub fn before(v: &str, release_: &str) -> bool {
    match (release(v), release(release_)) {
        (Some(v), Some(r)) => v < r,
        _ => true,
    }
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
    fn the_guest_version_is_a_release_this_build_has_reached() {
        let build = briqyard_version::VERSION;
        assert!(release(GUEST_VERSION).is_some());
        assert!(
            !newer(GUEST_VERSION, build),
            "{GUEST_VERSION} is ahead of {build}"
        );
    }

    #[test]
    fn a_version_before_a_release() {
        assert!(before("0.0.9+a", SESSIONS));
        assert!(!before("0.1.0+a", SESSIONS), "the release itself");
        assert!(!before("0.2.0", SESSIONS));
        assert!(before("", SESSIONS), "no version: older than the report");
        assert!(before("garbage", SESSIONS));
        assert!(!before(GUEST_VERSION, SESSIONS), "this init runs sessions");
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
