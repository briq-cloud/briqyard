# ADR 0010: Testing: unit tests with fakes, shell suites in `hack/`, a stress driver with invariants

Date: 2026-10-20 · Status: accepted

## Context

The daemon needs Linux, KVM, ZFS and root. Most of its logic does not. Bugs must be found on the Mac, not on paid servers.

## Decisions

**Unit tests run anywhere**, with fakes where the host is needed: a fake `zfs` binary (`Zfs::with_paths`), in-test Unix sockets for the Firecracker and guest clients, a stub HTTP daemon for every fleet handler, pure functions for the manager's decisions (restart, sleep, adoption, placement). The init's tests are Linux-only and run in the VM.

**The host behind the manager is three traits**, one per module that touches it, held by the `Manager` as `Arc<dyn>`: `fc::Vmm` (boot a machine from a `Boot` into a `Vm` with its pid, sockets, `exited` watch and the init's exit report; adopt one a previous daemon left; snapshot; kill; the `/proc` checks), `guestc::Guest` (ping, shutdown, exec, files, by the vsock socket) and `netw::host::Net` (bridges, TAPs, pins). The real implementations are the modules' own code, unchanged; the manager's tests run on the fake `zfs` and one `Mock` of all three, where a boot is a pid, a console file, an `exited` watch and an exit report channel, the guest answers as told (after a delay, never, or exits with its report), and every call is on record. A transition is tested by what it did to the disks, the processes and the network, never by how. What a `Manager::new` does once to the host (forwarding, the ruleset, the egress interface, a tenant's bridge and DNS listener) is not behind the seam: the harness builds the manager without it.

**End-to-end suites are shell scripts in `hack/`** (`e2e.sh` 54 checks, `fleet-smoke.sh` 19, `fleet-two-hosts.sh` 16), run against the installed daemon in the Lima VM on every change. `hack/` is the Kubernetes convention for dev tooling that is not the product.

**A stress driver with invariants.** `hack/stress.py` (stdlib only) runs N tenants through create, exec, files, endpoints, stop and start, fork, sleep and wake, suspend and resume, a daemon SIGKILL, destroy, in parallel; `hack/stress-invariants.sh` checks between phases that every zvol, Firecracker process, TAP, bridge, listening port, run dir and jail belongs to a machine the API knows, and prints the daemon's RSS, fds and threads.

**Every bug a suite finds gets a unit test** that fails without the fix. Coverage is measured with `cargo llvm-cov` in the VM and recorded with each measure.

## Consequences

- `api.rs` is covered by the e2e suite, not by unit tests. The manager's transitions are unit-tested on the mock host since 2026-10-20; the coverage number is measured in the VM.
- Timings on the Mac are not a benchmark: nested virtualization, 6 vCPUs, 24 guests saturate it.
- The TypeScript provider parses every daemon answer through zod schemas and a fixtures file of real answers; the live contract check is a script in briq's repository, run against a daemon.
