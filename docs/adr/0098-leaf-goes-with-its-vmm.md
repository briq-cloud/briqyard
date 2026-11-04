# ADR 0098: A VMM's cgroup leaf goes when the VMM does

2026-11-04 · Status: accepted; extends ADR 0068

## Context

v0.1.19 failed to start on both staging hosts: the startup barrier met 6404 and 5234 empty
`m-*` leaves under `/sys/fs/cgroup/firecracker` against a 4096 cap (fixed by #134, with a
first start of 118 to 168 s). Those leaves are not from one bug in the current code:

- Before ADR 0068 (#102, v0.1.19) **nothing removed a leaf**. `git log -S AT_REMOVEDIR` finds
  `unlinkat` once, in that change. Every machine destroyed by an earlier version left its leaf,
  and the staging hosts had run the e2e, stress and chaos suites for weeks. These are the
  thousands.
- Since #102 a destroy removes the leaf, and the start's orphan sweep removes leaves with no
  record. Nothing removed the leaf of a machine that **stays**: a VMM killed by a signal, a
  crash, an exit, a cgroup OOM group kill (all `stopped`, exit 255 or the program's code), a
  failed start (`error`), an adopted VMM that later died. The leaf waited for the next start
  or the destroy. The qualification batch (ADR 0095) saw it: a `kill -9`ed VMM keeps an empty
  leaf on its stopped machine.
- The first sweep after an upgrade is the only cleanup of the old leaves, and it runs once.

## Decisions

**The leaf is removed as soon as its VMM is confirmed gone.** The watcher that settles a
machine's exit (`watch`) calls `retire_idle_leaf` when the settlement is done, whichever way
the VMM went. It takes the machine's lock without waiting: a start, a stop or a destroy under
way owns the leaf, and the pass below finds it later.

**A periodic pass is the backstop.** The 15 s tick lists the parent once (`cgroup_leaves`, one
directory read, no leaf opened), and retires at most 128 leaves of machines with no VMM and no
transition (`stopped`, `error`, `created`). What it cannot remove (the kernel still tearing the
group down, `EBUSY`; a zombie not yet reaped) is tried again 15 s later: no call waits, retries
or sleeps, and no stop is ever slower for it. A leaf with no record is not touched in a pass;
the start's sweep owns that case.

**Order: the evidence, the last CPU, the removal.** `retire_cgroup` asks for the launch's
death proof, and the proof is published after the OOM evidence is read (ADR 0096), so removal
cannot precede the read. The leaf is also where a machine's CPU time is read, so the last
reading is counted into the meter before the leaf is removed; a refused removal counts it once.

**The leak is visible.** `briqyard_cgroup_leaves` (all leaves) and `briqyard_cgroup_leaves_idle`
(leaves no running VMM explains: idle machines' and ownerless ones) from the last pass, and
the counters `briqyard_cgroup_leaves_retired_total` and `_retire_failed_total`. The idle gauge
is 0 on a healthy host; a number that stays above 0 for minutes is a leak or a stuck removal.
A pass that retired or failed anything logs one `info` line (`idle cgroup leaves`) with the
counts; the start logs `orphans swept at start`.

**Startup cost follows the leaves present.** With the leaves gone as machines stop, a host
holds about one per running VMM, so a restart no longer pays for history. An upgrade from a
version that leaked still pays once (the 118 to 168 s above, for about 6000 leaves) and never
again. The barrier keeps its cap of 65536 and says so when it is passed.

## Tests

Mock VMM: a killed and an exited VMM leave no leaf and their last CPU is counted; a running
and a busy machine keep theirs; a refused removal is the next pass's and counts the CPU once;
a pass is bounded and publishes the counts. `hack/native-ci-scale.sh` (the `scale` step of the
`suites` job): 6500 idle leaves, a daemon restart, the barrier open, memory protection healthy,
a create accepted and the leaves retired within 300 s. It runs from the workflow revision, so
`workflow_dispatch` with an older `ref` shows it failing without #134.
