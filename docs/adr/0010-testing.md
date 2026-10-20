# ADR 0010: Testing: unit tests with fakes, shell suites in `hack/`, a stress driver with invariants

Date: 2026-10-20 · Status: accepted

## Context

The daemon needs Linux, KVM, ZFS and root. Most of its logic does not. Bugs must be found on the Mac, not on paid servers.

## Decisions

**Unit tests run anywhere**, with fakes where the host is needed: a fake `zfs` binary (`Zfs::with_paths`), in-test Unix sockets for the Firecracker and guest clients, a stub HTTP daemon for every fleet handler, pure functions for the manager's decisions (restart, sleep, adoption, placement). The init's tests are Linux-only and run in the VM.

**End-to-end suites are shell scripts in `hack/`** (`e2e.sh` 54 checks, `fleet-smoke.sh` 19, `fleet-two-hosts.sh` 16), run against the installed daemon in the Lima VM on every change. `hack/` is the Kubernetes convention for dev tooling that is not the product.

**A stress driver with invariants.** `hack/stress.py` (stdlib only) runs N tenants through create, exec, files, endpoints, stop and start, fork, sleep and wake, suspend and resume, a daemon SIGKILL, destroy, in parallel; `hack/stress-invariants.sh` checks between phases that every zvol, Firecracker process, TAP, bridge, listening port, run dir and jail belongs to a machine the API knows, and prints the daemon's RSS, fds and threads.

**Every bug a suite finds gets a unit test** that fails without the fix. Coverage is measured with `cargo llvm-cov` in the VM and recorded with each measure.

## Consequences

- `api.rs` and `machine.rs` are covered by the e2e suite, not by unit tests (24 % lines on the manager): a `Manager` test harness is open (review finding D4).
- Timings on the Mac are not a benchmark: nested virtualization, 6 vCPUs, 24 guests saturate it.
- No contract test between the TypeScript provider and the Rust API yet (review finding D3).
