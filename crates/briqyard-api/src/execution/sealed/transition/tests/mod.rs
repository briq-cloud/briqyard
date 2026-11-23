//! Transition conformance tests. The fixtures are synthetic: RFC 8032 section 7.1 test seeds
//! (test-only material, never a provisioning default), fixed digests and one coherent scenario
//! of the single supported transition. Interface-vector values are copied from the contract,
//! never computed by the code under test; every other expectation comes from the clause named
//! in the test.

mod actions;
mod common;
mod control;
mod corrections;
mod evidence;
mod fixtures;
mod launch;
mod reads;
mod tags;
mod vectors_json;
