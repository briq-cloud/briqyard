//! Local owner tests.
//!
//! **Non-authorizing fixtures.** Every signer below is a synthetic cfg(test) seed, the host and
//! the retained processes are stand-ins written for these tests, and the store lives in a
//! temporary directory owned by the test's own user. None of it is a real target, a real
//! pidfd, a real service manager or R/B enrollment. What the tests check is the owner's own
//! logic over those inputs: the persisted rows and files, the version arithmetic and the
//! refusals. Real-kernel and real-unit measurement is the disposable qualification's.

mod fixtures;
mod flow;
mod fragment;
mod golden;
mod store;
