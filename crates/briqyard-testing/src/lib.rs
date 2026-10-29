//! What every test binary of the workspace shares: it ends with its parent, and in bounded time.
//!
//! A test binary whose `cargo test` is killed (a timeout, a closed terminal) is reparented and
//! runs on, a hanging test forever. Each crate installs [`exit_with_parent`] before its tests
//! start, from its test root:
//!
//! ```ignore
//! #[cfg(test)]
//! #[ctor::ctor(unsafe)]
//! fn exit_with_parent() {
//!     briqyard_testing::exit_with_parent();
//! }
//! ```
//!
//! The same on Linux and macOS: a thread that reads the parent's pid every second. Linux's
//! `PR_SET_PDEATHSIG` follows the thread that forked, and macOS has nothing like it.

use std::io::Write;
use std::os::unix::process::parent_id;
use std::time::{Duration, Instant};

/// How long a test binary may run: well above the slowest one (a debug build in the
/// development VM, or under `cargo llvm-cov`), well below a wasted CI hour.
pub const LIMIT: Duration = Duration::from_secs(15 * 60);

/// Exits this process once its parent is gone (the pid it started under changed: reparented to
/// init, launchd or a subreaper) or once [`LIMIT`] has passed. `exit` runs no destructor, so
/// `kill_on_drop` does nothing then: whatever a test spawns ends on its own once this process
/// is gone (the fake `zfs` scripts watch their `$PPID`).
pub fn exit_with_parent() {
    let parent = parent_id();
    let start = Instant::now();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        if parent_id() != parent {
            std::process::exit(101);
        }
        if start.elapsed() > LIMIT {
            // Each test that ended is reported above this line: the ones missing still ran.
            let _ = writeln!(
                std::io::stderr(),
                "briqyard-testing: {} minutes passed; the tests not reported above were still running",
                LIMIT.as_secs() / 60
            );
            std::process::exit(101);
        }
    });
}
