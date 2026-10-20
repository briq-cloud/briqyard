# Stress spike and coverage (night of 2026-10-19 → 20)

On the Mac (Apple M4, Lima VM `fc`: 6 vCPUs, 16 GB, nested virtualization, ARM64, a file-backed pool). Timings are load figures for the VM, not a benchmark of the runtime. Driver: `hack/stress.py` with `hack/stress-invariants.sh` (ADR 0010).

## Coverage, unit tests only (`cargo llvm-cov`)

| | Before | After |
|---|---|---|
| Lines | 15.36 % | 62.08 % |
| Unit tests | 30 | 236 (199 macOS + 37 Linux-only init) |

After, per file: config 100 %, api types / guest / fleet config / provision / registry 99 %, store 96 %, zfs 84 %, fleet main 83 %, init 78 %, fc 75 %, image 47 %, machine 24 %, ingress 21 %, CLI 20 %, api 0 % (api and machine are covered by `hack/e2e.sh`).

## Runs

| Run | Shape | Result |
|---|---|---|
| 1 | 2 tenants × 2 | Driver bug (`busybox httpd` absent from Alpine). Host finding: two run dirs with no record from an earlier crash |
| 2 | 2 × 2 | Two tenants made together got the same subnet index (3 of 4 creates failed). A suspend took 15.5 s (entry lock held while waiting for the exit) |
| 3 | 2 × 2, fixed daemon | suspend 0.42 s, resume 0.32 s, stop 0.41 s, start 5 s, fork 7.4 s, exec p50 0.22 s, 0 invariant breaks. Destroying a forked source refused ("dependent clones") |
| Big 1 | 6 × 4, 2 rounds, 12 workers, SIGKILL | 23 of 24 concurrent boots past a fixed 60 s timeout. Round 2's creates all failed at Docker Hub's pull rate limit. RSS 116 MB with 24 machines |
| Big 2 | 6 × 4, 2 rounds, 6 workers, SIGKILL, boot gate on | 0 boots lost; create p50 55 s / p95 195 s, start p50 86 s at load 21; exec p50 2.4 s, suspend 0.6 s, resume 12 s, fork 21 s; 20 of 960 endpoint hits and 4 operations timed out, all load-bound; all 24 machines adopted after SIGKILL; RSS 53 MB, 113 fds |
| Fleet | 2 × 3 through `briqyard-fleet`, two hosts | 0 API failures, 0 invariant breaks. Two wakes through endpoints on `fc2` failed "no route to host": Lima forwards only the API port of `fc2` |

## Bugs found and fixed, each with a unit test

| Bug | Fix |
|---|---|
| Tenants created together shared a subnet index and bridge | A lock around tenant creation; a raced `ip link add` tolerated |
| A suspend held the entry lock while waiting for the exit it needed | The guard is dropped before the wait |
| Run dirs, jails, TAPs, datasets left by a crash | `sweep_orphans()` at daemon start |
| Destroying a forked machine refused | Clones promoted before the destroy |
| 23 of 24 concurrent boots timed out | `boots_at_once` gate, `boot_timeout_sec` 120 (ADR 0009) |
| Every create resolved the tag at the registry | Digest cached `image_resolve_minutes`, stale served when the registry refuses |
| Ingress wake timeout fixed at 90 s | Follows `boot_timeout_sec` + 30 s |
| `parse_sleep` panicked on a multi-byte last character and overflowed on a huge count | Char boundary, checked multiply |
| `RestartPolicy.max_retries` read as 0 when `restart` was given | Serde default |

## Suites after

`hack/e2e.sh` 54 / 54 · `hack/fleet-smoke.sh` 19 / 19 · `hack/fleet-two-hosts.sh` 16 / 16.

## Day 3 (2026-10-20): the review fixes under the same stress

Same shape (6 tenants × 4, one round, 6 workers, a daemon SIGKILL), on the merged main after the review fixes (ADR 0011–0014). The Mac was shared with other work all day (OrbStack and other sessions at load 6–38), so timings are worse than night 2's, not comparable.

| | Result |
|---|---|
| Races added by the review (a client hanging up mid-create, start against destroy, starts past capacity) | Pass. The hang-up's machine still boots and the next create of the image works; the start/destroy race ends in one state, never `destroying` with a live process (p50 0.3 s, was 36 s before the destroy ran under one lock); refused starts answer 503 `capacity` and stay stopped |
| Invariants after each phase | Only "no machine in error" breaks, from boot timeouts; no leaked zvol, process, TAP, bridge, port, run dir or jail after any phase or the crash |
| Boot timeouts | 9 of 24 creates past the daemon's 120 s under 24 guests. Not a regression: an A/B on the same host, back to back, booting 12 machines at once in one tenant (gate of 3): night 2's daemon 41 / 113 / 234 / 350 s per batch of three; today's 8 / 29 / 58 / 96 s |
| Why concurrent boots are slow here | One guest alone boots in 4 s with 2.7 s of kernel time; three at once take 8 s, then each later batch longer. The guests' own command (`python3 -m http.server`) spends 10–25 s at 100 % starting up when siblings boot beside it: page-fault-heavy user code under nested virtualization on six shared vCPUs. Not memory (384 MB limit, 232 MB used, zero reclaim), not the init (idle), not the kernel copy into the jail (65 ms for three) |

Consequence: `hack/config.dev.yaml` sets `boot_timeout_sec: 300` so a stress run on the Mac fails on bugs, not on the host. Real servers boot a guest in about a second; the production default stays 120 s.

After the egress policy and the tenant gateway (ADR 0015, 0016), same driver, 4 tenants × 4, a daemon SIGKILL, the dev boot timeout at 300 s: 0 invariant breaks, 0 boot failures; the only API failures are the three status polls that land while the daemon is down on purpose.

API TLS (ADR 0020), checked end to end on the Mac 2026-10-21: fc2 bootstrapped on `0.0.0.0` with `ALLOWED_CLIENTS` served TLS and printed its fingerprint; with it pinned in the fleet's host entry, fc2 turned ready over `https`, `hack/fleet-two-hosts.sh` passed 16/16 through it, and the CLI with a wrong pin was refused naming both fingerprints. The dev loop keeps fc2 plain (loopback bind), since a fingerprint is per machine and cannot live in `hack/fleet.dev.yaml`.
