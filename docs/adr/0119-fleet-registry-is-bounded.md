# ADR 0119: The fleet registry forgets what nothing can ask for, and writes only what changed

Date: 2026-11-08 · Status: accepted

## Context

The fleet's registry (`registry.json`, ADR 0043) is written whole at every save: encoded, hashed, synced. Nothing removed the records of settled requests, so the file grew with every create and every save cost more. A fleet with 45 machines held a 4.6 MB registry: 11,391 sandbox request records (2.9 MB), 1,053 admissions, 8,358 namespace versions. A create makes several saves, saves take turns (ADR 0043), so under concurrency the create's latency was the queue of encodes and syncs of a registry that was mostly dead entries.

## Decisions

**Each record has a window, and is forgotten when it passes.** Pruning runs when a host's heartbeat is applied (already every few seconds per host, under the registry lock) and once at start on the registry as loaded. It is idempotent and never runs in a request.

| Record | Kept while | Window |
|---|---|---|
| Sandbox request route, not accepted | always | none: it fences its namespace and host until an operator reconciles it (ADR 0076); expiry is refused there |
| Sandbox request route, accepted | `REPLAY_WINDOW` after acceptance | 24 h |
| Admission, pending with a sandbox seed | always | none: it fences its namespace (ADR 0076) |
| Admission, whose dispatch is not accepted | always | its route is kept, so is the admission a retry of that create needs |
| Any other admission (dispatched, cancelled, pending without a seed) | `REPLAY_WINDOW` after it was made or last changed phase, and never before its route goes (a replay reads both) | 24 h |
| Namespace version | while its namespace is pinned or an unsettled move, admission or request names it | the namespace's life |
| `pinned_at` | while the namespace is pinned | the pin's |

The ADRs give a retry of a create no window: a settled route lets a retry find the machine (ADR 0076), and the daemon keeps its own request index. 24 hours is chosen: a caller retries within its own timeout (the fleet forwards for up to 15 minutes), so the bound is more than an order of magnitude past any retry, and it is a day of creates at most, not their history. Within it a retried create with the same request id still reaches the same host and gets the same machine. After it, the fleet treats the id as new; the daemon still answers for the host it is sent to.

**Records from before the times were kept.** A route or admission written by an earlier fleet has no time. If its namespace is pinned nowhere it goes at once (nothing it could replay to exists); if the namespace is pinned its window starts when the fleet first prunes it. A registry of that kind shrinks at the start, and the rest a day later.

**A version is never given twice.** A namespace's version tells a stale answer to a create (a refusal that arrives after another create) from the current one: it may only unpin the namespace if the version is unchanged. Dropping a namespace's version would let its next create start again at 1 and match a stale holder's. `namespace_version_floor` holds the highest version dropped; a namespace without a record starts above it (`max(version, floor) + 1`) and reads as the floor. Versions of a namespace pinned or named by a fence are kept as they were.

**A save that finds nothing changed does not encode.** The registry's lock counts the times it was borrowed for a change (`RegLock`: a guard changes the registry through `DerefMut`, which counts, so no code can change it without the count; it is read under the same lock as the registry). A save records the count it saw before it waits for its turn, and the count its write encoded. If the last write encoded that count or a later one, the caller's change is on disk and the save returns without encoding. This serves the callers that waited for a write in flight with one following write (a group commit): the turn is the same, and a caller returns `Ok` only when its change is in a file that was synced, written by its own turn or by an earlier one that began after the caller's change. A write that failed records nothing, so the next caller writes. The hash of the encoded bytes (ADR 0043) stays, for a borrow that changed nothing.

## Consequences

- The registry's size follows what is live and the last day's settled requests, not the fleet's history.
- A save with no new change is a lock and a comparison. Callers that wait for a turn behind a write share the next one.
- A heartbeat borrows the registry for a change, so it is still encoded and written; only its callers are cheaper.
- Refused: pruning by file size or entry count (a request still fencing would go), and a timer separate from the heartbeat.
