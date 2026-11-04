# ADR 0109: `scale` on its own runner, a smaller idle-leaf count in e2e

2026-11-04 · Accepted

## Context

Run 41902737838 (`native`, PR #156). The `suites` job took 23.4 min and set the run's total:

| Part of `suites` | Time |
|---|---|
| build | about 2.6 min |
| `hack/e2e.sh` | 13.5 min |
| `hack/fleet-smoke.sh` | 1.2 min |
| `hack/native-ci-scale.sh` (`scale`) | 5.2 min |

Two of these make and retire idle machine cgroups, the leaves an in-place upgrade finds (ADR 0068, 0099):

- `hack/e2e-siblings.sh` made 5000 across the SIGUSR2 hand-over. Making and retiring them took 211 s, about 42 ms a leaf (the `rmdir` of a memory cgroup costs a kernel offline and an RCU grace period).
- `scale` makes 6500, restarts the daemon and waits for it to answer: 276 s.

`scale` starts from the installed host alone. It runs its own first machine (`alpine:3.20`, pulled through the registry mirror that `hack/native-ci.sh` configures), uses its own namespace and counts leaves against its own starting number. Nothing from e2e or the fleet smoke is read.

## Decisions

| Decision | Setting |
|---|---|
| `scale` | An entry of the `more-suites` matrix, run by `hack/native-ci-more.sh scale` (which runs the script beside it). It leaves `suites`: step, summary entry and artifact. The harness still comes from `.native-harness`, so a dispatch on an older source ref still fails it. The log, the `passed` line and `native-scale-log` come from the matrix job's steps, as for the other suites |
| e2e hand-over check | 200 idle leaves instead of 5000, in the same four checks (renamed to say what is true). It still proves that the barrier passes idle cgroups and that the sweep retires them across the hand-over |

## Consequences

See [ADR 0089](0089-native-suites-in-ci.md) for how the native suites run and [ADR 0099](0099-leaf-goes-with-its-vmm.md) for what `scale` proves.

- Projected, to be read on this change's own `native` run: `suites` loses 5.2 min of `scale` and about 203 s of leaves (200 x 42 ms is 8 s, down from 211 s), from 23.4 to about 15 min. `scale` runs in parallel on a runner that pays its own build (about 2.6 min) and takes about 8 min in all, well under the longest job.
- **The trade-off.** The count past the old 4096 cap (ADR 0068, 0099: 6404 and 5234 leaves met a 4096 cap) is no longer exercised through the hand-over path. Only `scale` covers it, and it covers a restart, not a SIGUSR2 hand-over. A defect that needs both a large count and the hand-over would not be seen by either suite. The hand-over path itself, with idle leaves, stays covered at 200.
- `scale` uses one more runner per PR.
- The check counts in `docs/DEVELOPMENT.md` do not move: the hand-over block keeps its four checks, `scale` its nine.
