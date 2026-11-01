# 0074: Operator catalog and resource admission for warm slots

Warm slots hold host resources before a caller claims them. A per-pool desired count
alone cannot bound aggregate use or leave room for ordinary creates.

Extend `templates` with an authoritative host policy: RAM, CPU millis and logical-root
budgets, ordinary-workload headroom, fresh availability floors, a concurrent-fill bound
and a catalog of namespace/template/generation/exact-size bindings. Defaults stay off.
The catalog API changes only desired counts for configured entries. Existing direct pool
requests must match those same bindings. Each entry's configured ceiling applies across
its pools. Desired counts use the unsigned 16-bit wire bound and the operator ceiling;
the concurrent-fill limit bounds work independently of the requested target.

Warm admission runs under the machines-map lock shared with ordinary creates. It charges
the complete recipe, including creating, paused, failed and cleanup-in-progress records;
physical sharing gives no admission discount. Durable claim receipts, read under the same
lock used to publish them, change classification to ordinary without releasing host or
namespace resources. Startup loads machine records and receipts before admitting requests.

Before each fill, read `MemAvailable` and pool space outside the admission lock. Inside
the lock, reject unavailable or older-than-five-second samples, storage stalls, exhausted
budgets or headroom, and aggregate fill or entry limits. Subtract outstanding fill memory
liabilities and every unclaimed logical root from the respective measured availability.
Keep the configured absolute disk floor and the existing percentage floor.

The existing warm reconciler drains unused slots after pressure, a lowered limit, or a
removed binding. Its existing claim lock protects durable claims. Cleanup retains charges
until completion. It never preempts ordinary or claimed guests. Ordinary workloads may
consume admission headroom later; this stops refill and drains unused slots, but cannot
guarantee continuous free capacity if ordinary workloads alone consume it.

Configuration changes use the existing validated daemon handover. Bootstrap preserves
existing YAML, and rejects invalid configuration before installing a replacement binary.
Catalog status exposes desired and actual counts, full resource charges, measurement age,
draining count and structured blocked reasons. Namespace ownership, source-host binding,
template qualification and secret restrictions continue to apply.

Expose warm telemetry through the existing host metrics and dashboard. Cache durable pool
metadata at recovery and successful writes; combine it with current machine records under
the admission lock. Scrapes run no pool probe or artifact verification. Reuse full-charge
accounting and bounded state/reason labels. Host prepare/claim counters and duration sums
describe host readiness, excluding fleet and public API transport. Missing observations
remain absent; reservations are distinct from physical usage.
