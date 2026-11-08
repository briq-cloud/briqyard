# ADR 0118: Namespaces are made in parallel

Date: 2026-11-08 · Status: accepted

## Context

A create in a namespace that does not exist makes the namespace first (`ensure_namespace`): it chooses a free subnet index, plumbs the network (the bridge with its gateway address, the DNS listener) and writes the namespace record. All of it ran under one mutex, `namespace_create`, so namespaces were made one at a time. Once seed creates recorded concurrently (ADR 0117), that mutex was the serial part of a burst of creates that each name a new namespace: about 33 ms per namespace under the lock, against a burst in one shared namespace that did not wait for it.

The lock exists for one reason: two namespaces made together would read the same free index before either had taken it, and share a bridge. That needs the choice and the reservation to be atomic, not the plumbing.

## Decision

**The lock covers the choice only.** Under `namespace_create` a create checks that the namespace is not there, picks the first free subnet index and reserves it in memory (`namespace_reserved`, id to index). `free_namespace_subnet` counts the reserved indices with the stored ones, the launch holds and the assignment targets, so a parallel create never takes the same index, interface names or subnet.

**Bridge and record are outside it.** The bridge, the DNS listener and the durable record are done after the lock is released. A reservation is dropped when the namespace is in `namespaces`, after the record is written, so an index is never free between the two; it is dropped on failure or cancellation too.

**One turn per namespace.** Creates of the same new namespace take a turn keyed by its id (`Turns`, ADR 0117) before the check. The second waits for the first, then finds the namespace made and uses it; the namespace is made once. Different namespaces do not wait for each other.

**A failure leaves nothing that a later create trusts.** A namespace exists for others only once its record is written and it is in `namespaces`; before that the reservation is the only trace. If the bridge or the write fails, the reservation is released and the next create makes the namespace again, on the same index. A bridge left on the host by a failed attempt is reused by that create (`ensure_bridge` is idempotent), as before. The order is unchanged: bridge, then record, then the map, so startup finds the whole namespace or none; it plumbs every recorded namespace again.

**Delete, rename and handover.** Every caller of `ensure_namespace` holds `namespace_lifecycle` shared, and a delete or a handover holds it exclusively, so neither runs over a namespace being plumbed. A rename of a machine's namespace still takes `namespace_create`; it also refuses a new name that is being made, reading the reservation before the map.

## What stays serial

- Choosing and reserving an index: in memory, microseconds. A namespace rename holds the same lock while it waits for the machine to stop, so creates of new namespaces wait for a rename.
- Plumbing of one index is not shared state: each namespace has its own bridge, address and DNS socket, and the host tables are not written when a namespace is made (a machine's pin and policy are written when it is attached, as before).

## Consequences

- Creates that each name a new namespace overlap the bridge and the record write; the record's fsync queues on the disk's journal, not on a lock.
- A failed or cancelled attempt can leave a bridge and its bound DNS socket with no record until a namespace is made on that index; nothing reads them as a namespace.
