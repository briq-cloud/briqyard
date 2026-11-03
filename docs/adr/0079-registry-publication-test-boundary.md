# ADR 0079: Exercise registry publication through the production transaction

2026-11-03 · Status: regression preparation; ownership correction pending

## Decision

Keep one private generic PUT callable inside the existing backup transaction. Production
uses the object store through this callable. Tests replace only PUT, preserving the same
borrowed publication guard, snapshot, encryption, daily/LATEST order, timeout and ACK commit.
There is no runtime switch or additional dependency.

A regression drops the caller during either daily or LATEST publication. Its stand-in starts
real blocking work, retains every task handle, and replaces encrypted fake object bytes only
after an explicit gate release. A manual poll detects whether a second publication enters
before the first blocking writer is terminal. After cleanup, both objects and the ACK must
contain the second snapshot and its generated host key; assertions never print key values.

The borrowed guard releases on caller cancellation while blocking work survives. These two
tests therefore intentionally expect behavior the current implementation does not provide.
They prepare the ownership correction; they do not implement it or change key admission or
file-store durability. Existing encryption, deduplication and host-key tests remain intact.

## Cleanup

The fixture releases its blocking gate on Drop. Each blocking gate independently fails after
10 seconds. Normal cleanup retains and joins all handles against one 10-second deadline;
Drop waits for terminal signals against one further 10-second deadline, including during
unwind. A cleanup timeout fails a normal test exit; unwind preserves the original failure.
No sleep establishes ordering, and no timed-out operation is replayed. The existing test
binary parent watcher remains the process-level bound (ADR 0049).
