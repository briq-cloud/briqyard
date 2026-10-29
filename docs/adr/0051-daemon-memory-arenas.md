# ADR 0051: The daemon's memory: jemalloc, one glibc arena, a churn check in the stress driver

Date: 2026-10-29 · Status: accepted

## Context

On real hosts the daemon's RSS grew with churn and never came back down: 16 → 260 MB after
about 70k requests through the fleet with the machine count back where it was, 14.5 → 305 MB
(systemd peak 380 MB) after 57k direct ones. The fleet stayed small (19 → 44 MB).

A leak and an allocator that keeps freed memory look the same from `ps`. Measured on the dev VM
(6 vCPUs, Ubuntu 26.04, glibc 2.43, kernel 7.0, transparent huge pages `madvise`), with
`hack/stress.py --churn 8` (8 tenants, each cycle: create, files, an endpoint, a snapshot
restored, a backup restored, a fork, suspend and resume, destroy) and glibc's own
`malloc_stats` read through `gdb` after the run:

| Build | glibc arenas | RSS after cycle 1 → last | idle | after `malloc_trim` | peak |
|---|---|---|---|---|---|
| glibc (v0.1.2) | 25 | 106 → 118 MB | 121 MB | 110 MB | 148 MB |
| glibc, second run | 30 | 113 → 150 MB | 154 MB | 140 MB | 174 MB |
| jemalloc | 42 | 75 → 131 MB | 114 MB | 114 MB | 193 MB |
| glibc, `M_ARENA_MAX=1` | 1 | 23 → 112 MB | 115 MB | 24 MB | 115 MB |
| jemalloc, `M_ARENA_MAX=1` | 1 | 35 → 33 MB | 31 MB | 31 MB | 122 MB |
| this change | 1 | 44 → 39 MB | 38 MB | 37 MB | 116 MB |

Eight cycles in the first three rows, six in the others; the first run's driver skipped the
restore from a backup and the fork, the second cut 16 of 64 cycles short: the glibc rows did
less work than the others, not more.

- **No leak in the daemon's own state.** The manager, the API and backups driven in process
  (mock host, the fake `zfs`, a directory store) through 15 cycles: the heap the allocator
  hands out stayed within 0.1 MB after the second cycle, every per-machine map back to zero.
  At the end of the real runs glibc counted 10.8 MB in use.
- **glibc kept the rest in per-thread arenas.** glibc gives a thread that allocates an arena of
  its own, up to 8 per core, and never unmaps one. On this system each arena holds at least a
  2 MB huge page, even for a few KB in use (a 4 KB `malloc` in each of 4 threads: 5 huge pages).
  tokio's blocking pool starts and ends threads all the time (every `tokio::fs` call, every
  `spawn_blocking`), so the arena count follows the peak of threads at once: 25 to 30 here,
  up to 8 × the cores on a host. `malloc_trim(0)` gave back 10 MB of 120.
- **Another Rust allocator alone does not fix it.** With jemalloc as the global allocator,
  glibc still made 42 arenas holding 4.6 KB each (libc's own per-thread allocations: a thread's
  TLS destructors are registered with `calloc`), 84 MB of huge pages of a 114 MB RSS, and the
  RSS still grew in the second half of the run.

## Decisions

**jemalloc is the daemon's global allocator** (`tikv-jemallocator`, Linux only): it gives
freed pages back to the system after its decay time (10 s), so the RSS follows what the daemon
holds, not its peak. **glibc is limited to one arena** (`mallopt(M_ARENA_MAX, 1)`, first thing
in `main`, before the runtime starts a thread), for what still goes through it: libc's own
allocations, a few KB.

Each alone is not enough (the table): with one glibc arena and glibc for everything, the heap
stays at its peak (98 MB of huge pages, 5 MB in use) until a `malloc_trim`; jemalloc alone
leaves glibc's arenas growing. A periodic `malloc_trim` would paper over the first, and an
environment variable in the unit (`MALLOC_ARENA_MAX`) would not reach a daemon started another
way. mimalloc returns memory the same way; jemalloc is the one measured. The cost: jemalloc's C
build, 0.3 MB of binary. The fleet, the CLI and the init keep the system allocator: the fleet stayed at 44 MB.

**`process_resident_memory_bytes` on `/metrics`**, the Prometheus process collector's name,
from `VmRSS`: the trend to alert on, and what the stress driver reads.

**`hack/stress.py --churn N`**: N cycles per tenant of what a machine goes through, the
daemon's RSS read after each; growth over the second half of the cycles past `--rss-growth-mb`
(32) is a break. The first cycles fill caches and the allocator's pools; a leak keeps its slope
after them.

**The ingress resyncs when it missed endpoint events.** Its broadcast channel holds 64; a
receiver that lagged skipped what it missed, so a removed endpoint's listener stayed open, its
port held, for good. On a lag it now makes its listeners and host names match the endpoints.

## Consequences

- On the dev VM the RSS levels off after the first cycle (31 to 44 MB) instead of following
  the peak of threads; a real host, with more cores and so more arenas before, is still to be
  measured with `--churn`.
- What is left: the 32 MB part buffers of a backup's multipart upload (ADR 0034) are the
  largest transient allocations, up to 160 MB per stream in flight; they are freed, but set
  the peak. The fleet process was not measured beyond its 44 MB.
