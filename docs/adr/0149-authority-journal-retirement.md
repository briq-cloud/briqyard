# ADR 0149: Retire authority evidence by expiry and registration generation

Date: 2026-11-27 · Status: accepted · Supersedes in part: [ADR 0144](0144-authority-journal-compaction.md) (no intent ever removed)

## Context

The authority journal kept every intent it ever wrote. Staging reached `Full` at 16,743,373
of 16,777,216 bytes with about 1,580 records in each of the operation, delegation,
protection, discovery and authority intent maps and in `authority_highwater`: about 10.6 KB
per regional installation. A restart frees nothing. ADR 0144 only clears expired credential
strings.

## Decision

Before every authority commit that carries a qualified clock, one pure sweep removes the
records no reader can use again. A record is removed only when every reader of it already
refuses through an expiry, a superseded registration or the host's own fence. Every record
a retained record references is retained. Removal only deletes map entries: the journal stays
v1, and every earlier runtime opens it (runtime rollback stays possible).

| Class | Records | Retired when |
| --- | --- | --- |
| Expiring | operation intents and their admissions and renewal attempts, delegation and protection intents, allocations | the latest expiry the record carries is older than the qualified lower bound minus 1 h, and no retained record references it |
| No expiry | registration, ownership, invalidation and revocation intents, discovery intents, `ownership:*` and `delegation:*` highwater | the host's registration generation moved past theirs, and no retained record references them |

- **Anchors.** An operation: its permit expiry and its renewal attempts' protection expiry. A
  delegation: grant, source, allocation and protection expiry. A protection: its own expiry.
  Phase does not matter: an unconfirmed or stuck operation is still bounded by its permit.
- **Why expiry suffices.** Re-presenting a retired record needs an unexpired grant, permit,
  protection or allocation, which every begin path refuses. The host keeps its own one-shot
  admissions, ownership highwater and tombstones.
- **Why 1 h.** It covers the 300 s handler timeout, an in-flight dispatch and a late status
  read. It is not the safety argument. At 1 h an authority holds about 4.5 operations a second
  within the record cap.
- **Registration frontier.** A record without an expiry belongs to the registration it was
  made under: an ownership through its registration dependency, a discovery through its
  registration, an invalidation or revocation through the host instance and authority epoch
  it was sent to. The current registration and `registration:*` highwater stay. A record
  whose registration cannot be told apart from the current one stays.
- **`unknown` stays exact.** The control plane reads `unknown` for an ownership as "never
  reached the authority" during pending-control recovery. That recovery runs before it can
  reserve the next registration generation, so the authority only forgets an ownership after
  the control plane has settled or superseded it.
- **No sweep at open.** Open has no qualified clock and a cold open never decides retirement.
  After an upgrade the new epoch needs a registration at the next generation. That is a
  qualified commit, so its sweep recovers a full journal before `Full` is evaluated.
- **Every qualified commit, not only at 75 %.** The steady state stays small, and so does
  the file every commit rewrites. Credential compaction (ADR 0144) still runs at 75 %. The
  reserve of an installation commit is swept with the same bound.
- **Sealed path unchanged.** `qualified_candidates` keeps ADR 0144 behaviour.

## Capacity

| Measure (unit fixtures, signed-size tokens) | Value |
| --- | --- |
| Full installation chain | 11.9 KB |
| Residue per installation within one registration generation (ownership, discovery, revocation, invalidation, two highwater keys) | 2.9 KB |
| 1,000 install and revoke cycles, a registration every 10 | largest file under 48 KiB |
| Staging-shaped full journal (1,410 chains, 16.5 MB), reopened, then registration N+1 | under 16 KiB |

Within one registration generation the residue is not reclaimed: about 5,700 installations
fill the byte cap, 4,300 reach 75 %. A host or runtime restart starts a new generation. Two
follow-ups make it unbounded: the control plane sending Invalidate when an installation ends,
with a retirement rule for it, and pruning host journals, which keep their own caps.

## Signals

- After every authority action, a WARN `execution journal near capacity after retirement`
  with the fullest cap in percent, while it is at or above 75 %.
- An ERROR `execution journal full` when an installation is refused with `Full`.

## Verification

Unit tests in `admission/retirement_tests.rs`: the cycle bound above; the residue within one
generation; a staging-shaped full journal that opens and recovers at registration N+1; a
registration during a live dispatch keeps its whole chain and late host evidence lands; an
idle installation keeps its ownership and accepts a new protection, while a retired
operation ID is refused; a pending revocation stays until the registration moves on; a
retired journal is a v1 state that reopens. The reader test
`tests/execution_retired_reader.rs` opens a retired fixture; the same file was run against
0.2.11, 0.2.14 and 0.2.16 sources.
