# ADR 0141: Serve installer reads from committed snapshots

Date: 2026-11-16 · Status: accepted

## Context

The execution installer served every action under one `tokio::sync::Mutex` around the
durable issuer, `identity` and `status` included. A mutating action holds it across the host
probe, the intent commit, the host RPC and the ack commit, and each commit rewrites the
whole journal state (serialize, write, `sync_all`, rename, directory `sync_all`).

Measured on one host with 40 concurrent grants (4–5 installer calls each): a call waited
about 1 s behind the others, against about 90 ms alone, and callers timed out at 5 s. A
release build with a 20 ms stub host and 8 looping writers gave the same shape:

| read action | p50 | p90 | max |
|---|---|---|---|
| before: behind the lock | ~400 ms | ~440 ms | ~440 ms |
| after: committed snapshot | ~0.5 ms | ~10 ms | ~25 ms |

## Decisions

**Reads do not take the issuer lock.** They read an immutable snapshot of the journal.

- `Journal` keeps its own committed state and, separately, a published `Arc<State>` in an
  `Arc<RwLock<JournalView>>`. A `JournalReader` hands out clones of the published view.
- **Publish at the action boundary, not at each commit.** A commit makes the state durable
  (the file is renamed and its directory synced) and updates only the writer's view. The
  service publishes once per action, when the guard around the issuer is released, after
  the action's last commit. An installer action is several commits (intent, ack, and a
  refusal when the clock is lost after the ack); publishing each would let a read see a
  `ready` that the same action then refuses for good. Before this change the lock covered
  all of them, and a read now sees the same two states: before the action and after it.
  `exec` releases the lock between its phases (dispatch intent, host call, result), so
  each phase is visible when it ends, as it was.
- `JournalView` holds the state and a shared fence: the poison flag and the directory and
  lock identity the writer checks. A view applies the same ownership and poison checks as
  the writer. A poisoned or disowned journal refuses every read that returns journal
  records, and `identity`, which checks ownership through the view before it answers.
- Read methods (`instance`, `role`, `status`, `check`, installation, projection and
  operation lookups) live on `JournalView`; `Journal` derefs to it. `instance` and `role`
  return facts fixed at `Journal::open` and never check the fence.
- `identity` answers the authority role and epoch fixed at `Journal::open`, after the
  ownership check, and still asks the host for its instance on each call.
- Mutating actions, and `observe`, keep the lock, in the same order as before.

**Why it is safe.**

- Writes stay serialized by the same lock and the single writer; nothing about them changed.
- A state is published only after its commit is durable, so a reader never sees a state
  that a crash could undo. A failed commit never reaches the writer's state, publishes
  nothing and poisons the journal; the guard then publishes only what earlier commits of
  the action made durable, and every read refuses anyway.
- A read is ordered before any action that has not returned and sees every action that has:
  the publish happens before the guard releases the lock, so before the caller's reply.
- Epoch and host-instance fencing are unchanged: they are checked on the facts in the view,
  which are the published ones.

**The writer lock follows the fence.** The directory lock lives in the shared fence, so it
is released when the `Journal` and every reader and view made from it are dropped, not
when the `Journal` is. A retained reader makes a second `open` of the same directory in
the same process fail with `Ownership` (fail-closed) and keeps answering the last
published state.

## Consequences

- A mutating action still holds the lock across its host RPC and about three fsyncs.
  Shrinking that means relocking between steps and auditing every interleaving of the
  installer protocol (intent, at-most-once RPC, ack). It needs its own decision. Until
  then, concurrent mutations still queue; reads no longer queue behind them.
- While an action is in flight, `installation_status` answers from the state before it
  (`unknown` for a record the action is creating) instead of its intent (`pending`). A
  caller that polls sees the final state when the action returns.
- Every user of the issuer lock goes through the guard that publishes. Code that commits
  to a `Journal` outside it must call `Journal::publish` itself, or no reader sees the
  commit.
- Tests. A fleet test holds a write inside the host RPC and requires `identity`, `status`,
  `projection`, `projection_lookup` and operation reads to answer meanwhile, and a second
  write to wait. It fails if a read takes the lock. A second fleet test holds the clock
  between a registration's ack commit and its refusal and requires the read to see
  `unknown`, then `pending`, never `ready`. Journal tests require a reader to see only
  published actions, never a failed write, and to apply the writer's ownership and poison
  checks.
- Reopen this if a read must see an intermediate state of an action (it would need a
  per-commit publish and the argument that each intermediate state is safe).
