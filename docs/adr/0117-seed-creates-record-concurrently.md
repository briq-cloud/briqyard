# ADR 0117: Seed creates record concurrently

Date: 2026-11-07 · Status: accepted

## Context

A sandbox create (`sandbox_seed`, ADR 0076) held `warm_lock` and `sandbox_create_lock` through the whole record step of `record_with_warm_slot`, so seed creates recorded one at a time. A burst of 50 on a 24-thread NVMe host was answered one every 62 ms with a shared namespace and one every 72 ms with a namespace each: 14-16 creates per second however many arrived. The daemon's user CPU was about 6% of the samples: the creates were waiting, not computing.

The record step has 11 fsyncs of about 4 ms each under load: the machine and the request index (`persist_sandbox_assignment`), the reader (`reserve_named_clone`), the machine and the index again (`freeze_sandbox_assignment`), the machine (`save`), plus `net.count`, an `nft` command. That is 51 of the 62 ms. An ordinary create runs the same function with neither lock, so concurrent fsyncs on one filesystem already share journal commits there.

## Decision

**Both locks are `RwLock`s.** Every holder except a seed create keeps exclusivity (`write`, `try_write`). The lock order is unchanged: warm, namespace, sandbox, entry.

**A seed create holds both shared.** Seed creates then record at once, as ordinary creates do. A writer (staging an assignment, a run reservation, a pool put or delete, the refill, a claim) still excludes them, and they exclude it.

**Unbound pools keep it exclusive.** When `unbound_warm_available()` is true, a seed create takes both exclusively, as before: the unbound selector (ADR 0077) picks a slot and reserves its assignment, and relies on being the only create doing so. That gate is off by default.

**One request, one turn.** A map of async mutexes keyed by (namespace, request id) is held from before `replay` to the end of the record. A twin (a retry, a duplicate send) waits, then replays a machine that is on disk; it is never answered with one a crash could lose. The same request with another spec waits too, then gets the conflict. `sandbox_request_lookup` takes the same turn and the sandbox lock shared, so it does not read a request half recorded either. An entry leaves the map when its last holder or waiter drops it, a cancelled wait included.

**The order and number of durable writes do not change.** The record still writes the machine and the index, the reader, the machine and the index again, then counts and saves, in that order. Only who waits for whom changes. `reserve_named_clone` still takes the seed's entry lock, `namespace_create` and the boot gate are as they were, and `net.count` is still one `nft` command per create.

## What the locks no longer order

Between seed creates the sandbox lock ordered nothing that the machines map does not: the name, the address, the quota and the host's memory and CPU are checked and taken under one hold of `machines` in `add_machine`. A create is visible to the next one from there on, whatever the disk has. The request's identity (index, binding) is per request id, which the turn orders. The failure paths keep a seed's machine in `error` with the request bound, so a retry reads the same answer; the turn makes that retry wait for the record rather than race it.

## Consequences

- Seed creates overlap in the record; the 11 fsyncs queue on the disk's journal, not on a lock. The expected gain is the queue's share of the 62 ms. Each next step (`net.count`, the double write, the seed's entry lock) is its own change.
- A writer that waits for the locks now waits for every shared holder, and tokio's fair lock holds back later seed creates behind it: a queued writer is not starved.
- With unbound pools available nothing changes.
