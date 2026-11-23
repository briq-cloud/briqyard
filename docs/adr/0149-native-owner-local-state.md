# ADR 0149: The target's local owner state and its read-only collector

Date: 2026-11-23 · Status: accepted for the draft slice; producers still unprovisioned (below)

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

## Unit commitments (owner-layer erratum 2, SHA-256 ec90a9a9fe3d88480802d8f3fd5307179c096ebe4d044ed856dff321c998b84d)

The preimages that were open are decided by erratum 2 and implemented as pure codecs in
`briqyard_api::execution::sealed::preimage`:

| Commitment | Preimage |
|---|---|
| `fragment` | SHA-256 of the raw installed file, first byte to EOF, 1..=64 KiB, nothing normalized |
| `argv` | `H(owner.argv/v1)`: the executable and the whole ordered vector, argv[0] included |
| `sandbox` | `H(owner.sandbox/v1)`: closed typed projection; sets unique and in byte order, binds and environment files in manager order |
| `fdstore` | `H(owner.fdstore/v1)`: the v3.6 `Listeners` object in qualified delivery order plus preserve and notify policy |

Every expected digest in the tests comes from an independent Python computation, not from the
code under test. `local_owner::read_fragment` is the byte source for `fragment`: descriptor walk,
owner and writer checks on every component, no links, one hard link, bounded size, stable while
read. `Inputs::check_target_asset_identity` checks that guard and candidate are the target
release asset at distinct paths with the same approved build; `bind` does not call it, because
the accepted `native.inputs/v1` fixture's guard is not the target asset.

## Still unprovisioned

`LiveHost` measures processes only and refuses everything else. What is missing, and each is a
producer rather than a codec:

* **Loaded unit facts.** A typed query of the pinned manager (loaded `ExecStart`, the sandbox
  properties, `FileDescriptorStoreMax`, preserve, notify access, FragmentPath, drop-in paths, reload
  state) from one coherent cut. No manager client exists in this tree, and adding one is a new
  dependency and security decision.
* **The installed `unit_policy`.** The closed per-role preimages and templates the owner compares
  against have no installed format yet.
* **Delivery order.** The qualification that the manager's snapshot order is the order it delivers.
* **Final I/O.** The root custodian's proof (retained pidfd exit, exclusion, read-only validation of
  the journals and side stores, durability barriers, one-use commit). The scoped-writer profile
  artifact that names the stores and ranges is not defined in this tree.

## Consequences

A joint run needs those producers. The qualification procedure is in
`docs/OWNER-QUALIFICATION.md`. The version bump on main changes no pinned label here: build
labels come from the plan's pins, and the tests use the synthetic label `fence-3`.
