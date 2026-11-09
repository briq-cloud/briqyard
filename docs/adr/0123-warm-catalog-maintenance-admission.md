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

## Replay admission settlement

The native acceptance run at `a23ac83` passed both exact warm-create replay assertions
and the cleanup ownership predicate, then reported accepted shutdown exceeding 60 seconds.
Source tracing found that `create` reserves a make I/O scope before recording, including
replays. `spawn_make_admitted` returned for `Make::Existing` without running that scope.
An abandoned scope is deliberately fenced, so `hand_over` waited in `drain_backups`
even after the fixture removed every warm record and namespace.

The existing retained make task now settles an empty scope for a replay and returns before
machine work or warm metrics. Uncertain abandoned scopes still fence; admission, identity,
authentication, configuration and cleanup predicates and all deadlines stay unchanged.
A unit regression dispatches two replay admissions and requires handover to finish with
both maintenance gates held, preserving the machine record and issuing no machine work.
This source-established defect explains a permanent shutdown drain after the successful
replays; the complete native restoration outcome still needs validation on the fixed head.

## Restored readiness with authentication disabled

After replay settlement was repaired, native acceptance at `eecfb88` reported
accepted handover completion followed by readiness query failure. The native host
bootstrap defaults to an empty API token. Sealed acceptance temporarily installs
its own token, then restores the original configuration and CLI environment.
`warm-maintenance` calls an endpoint that deliberately returns 409 when no token
is configured, so it cannot observe the restored native daemon. The exported Bash
caller fake had incorrectly allowed that request without configured authentication.
Correcting that fake reproduced the readiness failure before the fixture fix.

`GET /v1/status` now includes the existing runtime observation once recovery is
resolved. Older daemons and daemons with a recovery fault omit it. It uses ordinary
API authentication: a configured token is still required, and a host configured
without one can answer. Maintenance authentication and admission are unchanged.
The restored readiness query uses status with the original CLI environment and
still requires a new nonempty incarnation and the exact restored configuration
identity. Missing observation fails. The 128-second budget is unchanged.

Offline caller regressions cover both original authentication modes, wrong config,
stale incarnation, missing observation, recovery fault and existing deadline/failure
boundaries. The source mismatch is established; native qualification of the new
candidate remains outstanding.
