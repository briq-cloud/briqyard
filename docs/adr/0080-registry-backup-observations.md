# ADR 0080: Observe registry backup ACKs through existing caches

2026-11-03 · Status: implemented candidate; validation pending

## Context

The registry publication worker can finish after its caller times out or leaves (ADR 0079).
Caller results and worker ACKs therefore describe independent facts.

## Decisions

**Separate caller outcomes from worker ACKs.** The fleet exposes five fixed metric families, ten samples, even when backup is disabled.
Four relaxed atomic counters settle a polled caller exactly once: acknowledged, unchanged,
failed or canceled. A scoped guard counts cancellation; an unpolled future counts nothing.
Only the existing worker records receipt time, after both actual PUT successes, in the same
short cache assignment as digest and keys. Late success preserves the caller's outcome.
Receipt time is Unix wall time, may regress, and says nothing about remote commit or data age.

**Observe existing caches without waiting.** The observation helper tries the ACK cache once, then the durable digest cache once while
holding the ACK guard. It compares digests under both guards and returns scalars only.
Absent, busy, poisoned or invalid state yields an unknown comparison; an unavailable ACK
cache also yields NaN observation and time. A busy durable cache preserves readable ACK
history. No fallback match is retained. The helper never waits, retries, hashes, reads keys,
clones the registry or accesses files or the store. Rendering follows the handler's existing
registry-lock scope; the complete handler still uses its existing locks.

**Track durable observation validity without changing saves.** Durable observation validity starts false. The existing owned blocking save clears it before
writing, and sets it only after file sync, rename, directory sync and digest settlement.
Failure or panic leaves it false and preserves the old digest. An unchanged save still skips
writing and cannot heal invalidity. Shared private write/save seams support fault injection
and retained task handles without a second writer or changes to error and dedup behavior.

## Consequences

Match means equal valid cached digests at one simultaneous observation. Mismatch gives no
direction or loss claim. This assumes exclusive file ownership; external edits are invisible,
and offline restore requires a stopped process. Counters are independent relaxed reads,
not an atomic whole-scrape accounting identity. Restart infers no ACK from existing files or
objects. These metrics add no reachability, store coverage, fencing, recovery or durability
guarantee and change no publication, key admission or save policy.

Deterministic fixtures cover late ACKs after timeout/drop, unconsumed replies, cache contention
and poison, coherent comparisons, save failures before and after rename, panic, unchanged
invalidity and repair. Gates establish ordering; finite deadlines bound cleanup only. Cargo,
CI, CodeQL and native fleet/monitoring qualification remain pending.
