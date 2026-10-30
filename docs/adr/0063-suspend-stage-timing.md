# ADR 0063: Measure suspend stages without changing durability

Date: 2026-10-30 · Status: proposed

## Context

A suspend includes a pause, a durable memory snapshot, two record writes and process teardown.
One request duration cannot identify which stage dominates. ADR 0037 measured 3.67 s and 4.05 s for
Firecracker's durable snapshot creation, against 2.20 s and 2.24 s unsynced plus 1.07 s and 1.34 s syncing
later. Those measurements describe that workload; they do not establish the bottleneck of every
suspend.

The successful suspend path contains no fixed sleep. Its 15-second settlement wait is a ceiling:
the watcher notification ends it earlier. A failed snapshot resumes the guest and falls back to
an ordinary stop. The stop's grace deadlines belong to that fallback, not a successful suspend.

## Decision

Add opt-in debug events on the existing `tracing` path, target `briqyardd::profile`. Each carries
a `profile=lifecycle` marker, operation, stage, machine, process id, elapsed microseconds, a process-local monotonic finish
time and the stage's completion result. No request body, environment, guest content or path.

| Operation | Stages |
|---|---|
| suspend/stop | entry lock, stopping record |
| successful suspend | snapshot, suspended record, kill-to-notify, total |
| snapshot_durable/snapshot_unsynced | pause, create, resume after error |
| settle | process exit observed, entry lock, network cleanup, exit report, stopped record |

`create` is one Firecracker request: it includes memory/state writes, block-device flushes and,
when durable, snapshot-file syncs. These events cannot separate writing from syncing inside
Firecracker. A syscall trace of `fsync`/`fdatasync` can supplement them on a disposable machine;
never change `sync_snapshot_files` to measure a suspend.

The consumer of the events is an offline log summarizer, `hack/profiling/suspend.py`. It filters
one machine/process, preserves nested stages and records the installed runtime commit and optional
caller commit. A matching request id joins the daemon's existing request duration; a supplied
caller duration shows transport/forwarding/caller overhead together. They are not separate
measurements of those layers. Repeated or out-of-order kill/exit markers are left unpaired.

The stop notification is emitted by `set_state`, before the subsequent record save completes.
Thus `kill_to_notify` is not final record durability, and stopped-record timing can finish later.
Parent and child stage durations overlap and must not be summed. Exit-report completion can be
false when its channel closes without a report, which is normal after killing a paused guest.

## Unchanged

A suspend still calls `snapshot(..., true)`. The snapshot completes before the suspended record
is saved and before the process is killed. Memory snapshots keep ADR 0037's existing unsynced-write,
resume, then explicit-sync sequence. Persistence calls, event syncs, fallback behavior, deadlines
and notifications retain their ordering. This decision adds measurement, not an optimization.

## Validation

A socket-contract test covers both durability choices, successful snapshots staying paused, and
failed snapshots resuming and removing partial files. Existing manager tests cover a durable
suspend before kill and resumption on the next start. Pure log fixtures cover nested timing,
foreign machine/process exclusion, missing data and ambiguous kill/exit pairs.

Native workspace checks: 745 tests passed, 3 ignored; the 23 Firecracker checks include the new
socket contract. Both offline log fixtures, formatting and strict workspace clippy passed.
Linux lifecycle, fleet and failure suites remain
required before merging a daemon change. The measurement procedure is in
[the suspend profile runbook](../SUSPEND-PROFILING.md). No new live timing is claimed here.
