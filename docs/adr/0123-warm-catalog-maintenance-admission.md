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
