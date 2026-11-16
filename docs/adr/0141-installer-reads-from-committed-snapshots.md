# 0141: Serve installer reads from committed snapshots

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

## Decision

Reads do not take the issuer lock.

- `Journal` publishes an immutable `Arc<State>` in an `Arc<RwLock<JournalView>>` after each
  commit is durable (the file is renamed and its directory synced). A `JournalReader` hands
  out clones of the current view.
- `JournalView` holds the state and a shared fence: the poison flag and the directory and
  lock identity the writer checks. A view applies the same ownership and poison checks as
  the writer. A poisoned journal refuses reads.
- Read methods (`instance`, `role`, `status`, `check`, installation, projection and
  operation lookups) live on `JournalView`; `Journal` derefs to it.
- `identity` answers from facts fixed at `Journal::open` (authority role, instance, epoch).
- Mutating actions, and `observe`, keep the lock, in the same order as before.

## Why it is safe

- Writes stay serialized by the same lock and the single writer; nothing about them changed.
- A snapshot is published only after its commit is durable, so a reader never sees a state
  that a crash could undo. A failed commit publishes nothing and poisons the journal.
- A read is ordered before any write that has not returned and sees every write that has
  returned: the publish happens before the writer's call returns and releases the lock.
- Epoch and host-instance fencing are unchanged: they are checked on the facts in the view,
  which are the committed ones.

## Not changed

A mutating action still holds the lock across its host RPC and about three fsyncs. Shrinking
that means relocking between steps and auditing every interleaving of the installer
protocol (intent, at-most-once RPC, ack). It needs its own decision. Until then, concurrent
mutations still queue; reads no longer queue behind them.

## Tests

A fleet test holds a write inside the host RPC and requires `identity`, `status`, projection
and operation reads to answer meanwhile, and a second write to wait. It fails if a read
takes the lock. Journal tests require a reader to see every commit and never an uncommitted
state, and to apply the writer's ownership check.
