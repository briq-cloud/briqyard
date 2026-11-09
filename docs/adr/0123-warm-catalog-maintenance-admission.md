# 0123 — Fence warm-catalog maintenance at handover

## Decision

`GET /v1/maintenance/warm-catalog` reports a conservative host-local observation through configured API authentication. `briqyard warm-maintenance` prints the typed response. It returns only the runtime/config identity, a fixed reason and complete counts; failed inspection returns unknown with no counts.

Observation and SIGUSR2 use the same predicate under exclusive warm admission, then exclusive namespace admission. This matches seed creation and refill lock order. GET releases both guards. Handover reacquires them, checks again, runs existing replacement-capability checks, and retains both through exit. An earlier eligible GET cannot authorize a later signal.

All pools must have desired zero and no outstanding claims. Pool claim receipts are validated and retained; a receipt whose destination is absent from both live and durable machines is history, not ownership. Live or durable warm machines (including claimed/failed records), launch holds/transitions, pending names, assignment reservations and unsettled run/read/update authority refuse maintenance. Valid request receipts, settled run histories with matching durable machine/reference and reader links, and compatibility floors alone do not. Cache/durable disagreement, malformed or inaccessible state refuses without repair or cleanup.

## Bounds

One five-second deadline covers lock acquisition, inspection checkpoints and replacement probes. A shared inspection budget permits at most 4096 directory entries and 32 MiB of record bytes. Exceeding either limit is unknown, never empty. Record and collection symlinks are refused. Local filesystem calls cannot be preempted; this is not a hard wall-clock guarantee on a stalled filesystem. No synchronous mutex is held across an await.

Cancellation or failure drops both admission guards and leaves the daemon serving. The diagnostic creates no pool, guest request, reader, receipt or reservation. It exposes no raw decoder errors, configuration or tenant records.

## Compatibility

This deliberately tightens SIGUSR2: compatible replacement capabilities no longer permit handover with outstanding warm ownership, including a healthy assigned workload. Operators must settle that ownership through its normal lifecycle; maintenance never destroys or drains it. Ordinary workloads without warm authority remain eligible. The daemon being replaced must implement this check; it cannot protect the first upgrade from an older daemon.

Native handover, workload continuity, warm auto-claim/refill and recovery remain separate acceptance gates. Unit observations establish neither deployed eligibility nor physical capacity.

## Acceptance diagnostics

The sealed acceptance cleanup records fixed restoration failure categories at every return
boundary, including command and overall timeouts. It suppresses command diagnostics and
prints no configuration, credentials, paths or command arguments. Readiness still requires a
new serving incarnation and the exact restored configuration identity after signal and PID
change; no fallback is introduced. Offline exported-function caller tests
cover success, refusal and exhaustion. These diagnostics do not establish a native root cause.

On failure after a signal attempt, disposable CI projects a bounded journal selection for the
recorded daemon PID and attempt timestamp. Journal-owned unit, executable, transport and PID
metadata must match; exact structured daemon messages distinguish refusal from accepted
shutdown or completion. Only allowlisted reason categories leave the projection. Missing,
malformed, ambiguous or over-budget evidence stays unknown. No raw error or journal message
is printed. The signal targets the recorded PID; restoration predicates remain unchanged.
Offline Bash fixtures exercise this boundary without a journal, systemd or network.

The fixture's former 15-second PID wait could expire during a legal shutdown. Its shared
handover budget is now 128 seconds: 22 for existing preflight calls, five for admission
(`machine/launch_identity.rs`), 60 for shutdown (`main.rs`, including connection drain),
five for a PID query, seven for start, 25 for readiness and four for failure evidence.
Command bounds include kill grace. Calls fit the remaining phase deadline; PID polling
reserves start/readiness/evidence time. Fake-clock regressions spend the full preflight,
admission and shutdown allowances before PID change and exact restored readiness. Expiry,
refusal and identity mismatch still fail. Accepted-shutdown evidence alone does not prove
why shutdown was delayed. Runtime bounds and behavior are unchanged; native qualification
still requires a new native run.
