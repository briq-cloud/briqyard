# ADR 0144: Compact expired authority credentials

Date: 2026-11-22 · Status: accepted

## Decision

The authority journal reclaims space from retired credentials while preserving all
execution and refusal evidence. The 16 MiB serialized limit and the 16,384-record limit
of every bounded collection remain unchanged. Host journals never run this compaction.

Before an authority commit, the writer checks the projected state. At 75% of the byte cap
or any collection cap, or when the action would exceed a cap, it performs one sweep with
the action's qualified clock. It then rechecks once before returning `Full`. A commit
without qualified time does not gain a new retirement decision. Revocation and
invalidation ordering therefore remain clock-independent. A cold open also introduces no
wall-clock authority and does not retire new payloads; an already compacted bounded state
opens normally and the next qualified writer can compact again.

A delegation version is eligible only when all of these hold:

- the qualified lower bound `now - uncertainty` reaches the grant's expiry, compared in
  milliseconds;
- every allocation token has independently reached its own expiry at that bound;
- the complete expected host delegation and operation policy, when present, are
  acknowledged;
- no uncertain-installation refusal names the intent;
- no unfinished operation or retained renewal attempt depends on the grant.

The sweep clears only the raw grant string and allocation token strings. The representation
stays v1: an empty grant string and empty allocation vector, never a new record variant.
Expected ordered digests, typed acknowledgements, projection, source and policy binding,
request identity, revoked and invalidated records, operation and continuation history,
status, protection and uncertainty records remain untouched. Empty installer credentials
remain invalid. An expired grant does not retire an active continuation or operation ID.

Before transmitting installation work, a projected commit reserves the complete acknowledged
or uncertain follow-up evidence for each pending installation. If that reserve cannot fit,
the writer returns `Full` rather than sending work whose acknowledgement cannot be retained.
Compaction does not refund allocation units and never restores expired authority.

The existing durability sequence is unchanged, including for a compacted clone: create a
private new temporary file, write and fsync it, rename it, then fsync the directory. Any
uncertain write poisons the writer. A retained temporary file still refuses open; recovery
never guesses whether a write committed. Compaction changes neither the service instance
nor normal epoch rotation. There is no timer, RPC replay or operator prune verb.

Historical readers from 0.2.11, 0.2.14 and 0.2.15 retain the typed acknowledgement and
expected digests, reject an empty grant or allocation vector as installer credentials, and
refuse expired projection access. There is no v1 payload misinterpretation requiring a
versioned retired representation or downgrade barrier. Historical versions still maintain
no automatic headroom.

## Capacity limit

Compaction relieves expired payloads; it is not unbounded execution history. Perpetual
exact membership of arbitrary delegation and one-shot operation IDs cannot fit fixed
space for unbounded distinct IDs. Irreducible evidence fails closed at the existing caps.
No legacy ID receives a time-to-live and no revocation or replay evidence is silently
forgotten. Sustained indefinite turnover needs a separately designed ordered retirement
frontier or exact history outside the bounded journal.

## Verification

Unit fixtures cover a 434-byte remaining-space case and a projected overflow resulting in
an exactly-full v1 file. The test generator measured 378 reclaimed bytes on both synthetic
cap fixtures and 1,734 bytes on the signed historical-reader fixture. Additional checks
cover full collections, nothing reclaimable, acknowledgement reserves, stale or uncertain
clocks, repeated sweeps, reopen, and an ambiguous temporary file that preserves the
original journal and poisons its writer.

A deterministic model generates mixed grants, renewals, revocation, invalidation, late
acknowledgements, execution and status histories and compares all retained records with an
uncompacted reference. It also protects independent IDs at version 1 from renewal and
revocation histories of other IDs. The shared historical-reader integration test exercises
the exact signed v1 fixture under the three prior source revisions.
