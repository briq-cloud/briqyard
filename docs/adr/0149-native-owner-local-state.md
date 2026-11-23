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

**One private attempt, replaced by version compare-and-set, with a durable fence.** `/var/lib/briqyard/sealed-owner/v1`
is root-owned and private; `active.json` is written to a temporary file, fsynced, renamed and the
directory fsynced, under an exclusive advisory lock. A failure before the rename leaves the old
attempt and no temporary file. A failure after the rename is an *unknown commit*: it is reported,
never repeated, and fences the attempt (below). Every mutation bumps the
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

## Uncertain commits fence the attempt

A failure after the rename (directory sync, read-back, or clearing the marker) used to leave the
new bytes visible, so the next load treated them as known and could project receipts from them.
Now every commit first writes `commit.intent`, durably (file and directory synced), holding
`previous=<sha256 of the old canonical attempt, or none>` and `next=<sha256 of the new one>`.
It removes the marker only after the rename, the directory sync and a byte-for-byte read-back
all succeeded. A failure before the rename removes the temporary file and the marker, so the old
attempt stands and nothing is fenced.

`load` refuses while any entry named `commit.intent` exists, whatever it is: a regular file, a
link, a directory, or something that cannot be examined. That one check covers observation,
`PlanReadOwner` capture, every mutation and an install, in this process and after a restart or a
crash between the marker and the rename. A later commit never reinterprets the ambiguous bytes.

Recovery is an explicit operator act and is not automatic: compare `sha256(active.json)` with
`previous` (the rename did not happen, the old attempt stands) and `next` (the commit landed
but was not confirmed); any other value stays fenced. Only then is the marker removed by hand.
Equal hashes show which write won; they do not make the operation's uncertain effect known, which
a human decides. There is no timer, retry or compare-and-set path that clears it. The store stays
local and private; no R or B wire changes. A failure to clear the marker after a confirmed commit
also fences, which is conservative and visible.

Rejected: a flag stored inside `active.json`. Writing it needs the same rename that is uncertain,
so the failure it records could lose it.

## Review fixes at 4fb97cb

* An exit needs the enrolled original's retained identity, not only a readable descriptor: an
  unknown or failing identity refuses, for the daemon exit and the authority exit and handoff.
  No post-exit evidence is invented; a real descriptor that cannot say refuses.
* The daemon's retirement also needs the custodian's own final I/O through `TargetFacts`. A typed
  Launch and Death agreeing is not that record; the production host still refuses it.
* A placeholder token is exactly `{"x":"op"}` or `{"x":"serial"}`.
* An `owner.fdstore/v1` listener count above `store_max` refuses, like the v3.6 object.

## Erratum 2a (guard command and asset binding)

Erratum 2a (SHA-256 `6d98b6dfb5bb39d9176c0e857a32b66456e2401c2b797fbfe70e8d15693c2477`) fixes the
guard command as the role's whole native vector with one derived token, the role-rooted operation
directory. `unit_policy::guard_argv` builds it and `check_guard_argv` is the policy boundary: a
split `--op`/`--serial` command, another role's root or scope, an alias or a relabeled custodian
hashes as an `Argv` and is refused by policy. For op of 64 `a` and serial 7 the daemon hash is
`c9e8bea4…17ed` and the authority hash `420ef88c…eb93`, as the erratum states.

The shared `sealed_owner_units_v1.vectors` is unchanged (SHA-256 `21371a4f…bdf3`): its guarded
rows still use the split flags and are replaced when the revised file is published. Native does not
edit it. The release-identity half (the bind enforcing the target asset's digest, length and build, and
both custodians as the target bootstrap daemon Program) is not applied yet: it contradicts the
accepted `native.inputs/v1` positive fixture, and replacing that fixture is a shared change.

## Shared unit vectors

The API's `sealed_owner_units_v1.vectors` (57 rows, SHA-256 `21371a4f…bdf3`) is the shared source of
the four commitments for R, B and native. `unit_policy` holds the typed policy (`UnitPolicy`:
legacy and guarded unit with placeholders `op` and `serial`), sorts sets into canonical order, and
computes what each phase shows (`prearm`: legacy file and legacy loaded unit; `armed`: guarded file,
legacy loaded unit; `launch`, `seal`, `launch_a`: guarded file and guarded loaded unit). Native reproduces all 57 rows:
37 digests or accepts, 20 refusals, each with its own reason. No row conflicts with erratum 2.
Native is stricter than the API's reader in places the rows do not exercise: address families must be
`AF_*` names, state directories one component, environment names variable names, permission bits
within 07777, the transition's `op` a digest and `serial` positive, and a listener count of zero
exactly when the names digest is the empty one.

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
