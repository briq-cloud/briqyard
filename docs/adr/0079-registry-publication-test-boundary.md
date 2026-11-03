# ADR 0079: Registry publication owns its work through terminal completion

2026-11-03 · Status: implemented candidate; validation pending

## Context

A borrowed publication guard ended when a caller canceled or timed out. The local object
store's started blocking writer could survive that future and rename later. The two
caller-abort regressions failed against the borrowed-guard transaction before correction.

## Decision

One private worker owns an Arc-backed publication lease across daily, LATEST and the ACK
commit. It snapshots only after admission. There is no await between preparation and launch.
A separate short synchronous ACK cache holds the digest and exact host keys of the last
fully acknowledged snapshot. Cache poisoning refuses publication and key eligibility.

Publication admission, key-creation admission and each PUT's caller wait have 30-second
bounds. Each PUT pins one backend future. A deadline sends the caller an error and continues
awaiting that same future; the worker never cancels, replaces or replays it. Daily success
starts LATEST with a fresh deadline. Two actual successes commit the ACK even if the caller
has left or timed out. A timeout never becomes a retroactive caller success. Returned backend
errors leave the ACK unchanged and release the turn after terminal client completion.

An armed exit guard blocks publication before releasing the lease on unexpected worker
unwind or destruction, including before first poll. Normal success and returned errors
disarm it. Historical ACKs remain eligible unless their cache is poisoned. Neither a retry
nor cache access clears a blocked or poisoned state.

There is at most one detached publication worker per backup. A hung PUT keeps its lease;
waiters time out without starting more workers. Publication waiting is at most 90 seconds
including admission, excluding synchronous work and scheduler delays. This bounds waiting,
not total request population or worker completion.

Key creation and existing local save/rollback remain under the key gate. That gate is
released before backup eligibility or publication. Local save keeps its existing unbounded
durability wait. Already acknowledged authenticated keys remain available during unrelated
publication. A response rechecks exact ACK and current identity, token, address and key after
awaits. Requested restore-source keys retain their existing separate authorization path.

The shared SDK LocalFileSystem constructor enables `with_fsync(true)` alongside automatic
cleanup for both machine and registry backups. No backend, format, configuration, encryption,
object naming, retention or deduplication protocol changes.

## Durability and ordering limits

The pinned object_store 0.14.2 SDK syncs new object-parent directories, syncs and closes the
staged file, renames it, and syncs destination parents on Unix. Multipart completion uses
the same publication helper. This does not prove durable provisioning of a configured root
created earlier by the wrapper; that root must be durably provisioned separately. Readback
is not a power-loss test. Filesystem/hardware behavior and non-Unix directory sync remain
separate durability qualifications.

An S3 terminal client error is not proof of server rollback: a sent request or retry can
remain ambiguous. Process death/runtime shutdown, multiple writers and external changes
are outside this process-local ownership guarantee. Restart does not prove prior remote
work has ended. Remote fencing/CAS, graceful draining, reconciliation, object custody and
production recovery qualification remain separate gates; no remote never-regresses claim
is made here.

## Regression boundary and cleanup

Production and tests share the private generic transaction and admission/deadline helpers.
Blocking stand-ins retain real task handles and replace encrypted fake object bytes. Manual
polls and injected deadlines establish ordering without sleeps or Tokio test-util. Tests
cover daily/LATEST cancellation and timeout, late ACK, partial/error no-ACK, panic blocking,
poison refusal, admission, snapshot-after-turn, deduplication and key revalidation. Real SDK
round-trip/multipart/failed-stream tests remain, with constructor-mode and large-registry
multipart coverage. Test secrets and objects are fixture-owned only.

The test owns gate release separately from the Arc retained by its worker, so Drop releases
on unwind. Blocking gates independently fail after 10 seconds. Normal cleanup waits for the
transaction lease, then joins retained handles, each phase with a shared 10-second bound.
Fallback fixture Drop waits for terminal signals against one 10-second deadline. Cleanup
timeout fails the test; no timeout authorizes replay. The test binary retains ADR 0049's
parent watcher and process lifetime bound. The correction's Cargo and native checks remain
pending; formatting and source review do not establish runtime qualification.
