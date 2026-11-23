# ADR 0149: The target's local owner state and its read-only collector

Date: 2026-11-23 · Status: accepted for the draft slice; one decision open (below)

## Context

The owner layer (SYL-268, SHA-256 e144dc71e3eceb0ae9ad0627558b9c9ede2e968343cdcb78574d6eb1bbeee179),
its erratum 1 (599c742b…) and the B bindings v2 (9efbee80…) name a target-side owner of one
enrolled operation: it writes the arm receipts, answers a read-only `sealed-owner-observe`
request, compares an exact version before the first handoff, and checks the lineage between a
launch grant and its consumption. The receiver (R) and the API (B) already share a byte-exact
golden (SHA-256 3e14f6a769042dae6e17fbea5c83ca8ac99d3c6057c5cd7fd5624a577aae9337, 15 records).
Before this change the target had no concrete `PlanReadOwner` and no wire types for the owner
records.

## Decisions

**Wire types follow the golden, not a second reading of the prose.**
`briqyard_api::execution::sealed::owner` holds `ObserveRequest`, `Observation`, `ArmReceipt`,
`Collected` and `TurnBody`. `Tag::OwnerTurn` is signed by Bk and `Tag::OwnerEnroll` by Rk. Every
record decodes through the existing canonical codec and re-encodes to the golden's bytes;
`owner.turn` hashes are all-or-none for launches and both null for a seal.

**One private attempt, replaced by version compare-and-set.** `/var/lib/briqyard/sealed-owner/v1`
is root-owned and private; `active.json` is written to a temporary file, fsynced, renamed and the
directory fsynced, under an exclusive advisory lock. A failure before the rename leaves the old
attempt and no temporary file. A failure after the rename is an *unknown commit*: it is reported,
never repeated, and the next reader sees whichever file is on disk. Every mutation bumps the
version by exactly one; a rewrite at the same version, a skipped version or a stale expectation
refuses. The file must be private, canonical, at most 64 KiB and valid, or it is not read.

**Receipts are written together.** Both arm receipts are committed in one version, only after both
guarded fragments are installed and the effective-unit checks pass. A partial or ambiguous commit
supplies neither.

**The collector is read-only and derives its answer from the target's own state.** It takes the
shared lock, measures the live processes, projects only what the resource and point allow
(arm receipt on launch, retired launch and death for the authority launch, the captured pair on
the first launch of each join) and refuses a changed unit, a vanished original or another boot. A
caller flag selects nothing.

**Handoff, exit, guard start and consumption are one lineage.** The first handoff compares the
exact target version, the grant, the turn and every binding, then records one use under the lock
before the process changes. The original's exit and the guard's start are recorded as consecutive
versions by the owner. Consumption requires that exact lineage and happens once; an unrelated
mutation, a gap or a replaced process refuses and writes nothing.

**No activation path.** Nothing here selects an operation, signs, starts a process or opens a
listener. The ordinary route does not depend on an enrolled owner, and no existing ordinary file
changes except two additive re-exports and a constructor on `OriginalOwner` that only this
module can call.

## Open decision (escalated, not decided here)

The preimages of the unit commitments `argv`, `sandbox`, `fdstore` and of what
`fragment` hashes are not defined by the golden or by B's grammar. The production `LiveHost`
therefore measures processes from `/proc` and returns `OwnerError::Unprovisioned` for every fact
that needs one of them, final-I/O evidence included. The consequence is deliberate: no production
caller can enroll or answer a read until the preimages are pinned. Tests use their own fact
sources inside the crate. The preimages need one decision shared by R, B and native, with the
source-build versus installed-bootstrap pin question that is already open.

## Consequences

A joint run with B needs that decision first; the qualification procedure is in
`docs/OWNER-QUALIFICATION.md`. The version bump on main changes no pinned label here: build labels
come from the plan's pins, and the tests use the synthetic label `fence-3`.
