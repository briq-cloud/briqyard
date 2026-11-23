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

A failure after the rename used to leave the new bytes visible, so the next load treated them as
known and could project receipts from them. Now every commit first writes `commit.intent`,
durably (file and directory synced), holding `previous=<sha256 of the old canonical attempt, or
none>` and `next=<sha256 of the new one>`. Everything after that point has exactly one of
three outcomes, and a caller can tell them apart:

| Outcome | What happened | What is on disk | The caller |
|---|---|---|---|
| `Ok` | file synced, rename, **parent directory synced**, exact byte read-back, intent removed and that removal synced | the new version, no marker | continues |
| `CommitUnknown` | the parent directory sync or the read-back failed or differed | the new bytes may be visible; the marker stays | stops; every load refuses |
| `CommittedCleanupFailed` | the parent sync and the exact read-back both succeeded (the version is known and durable), then removing the marker, or syncing that removal, failed | the new version; the marker is present (removal failed) or absent (only its sync failed) | stops this turn: no retry, no second effect, no outward payload |

The parent directory sync after the rename, followed by the exact read-back under the exclusive
lock, is what makes the active file known. The cleanup that follows never decides the active
file's durability: its failure cannot make a known commit unknown. It also never becomes plain
`Ok`: `mutate` returns the error, so `consume` cannot hand out its `Launch` and no caller
can release a receipt or outward effect on it. The error keeps the failing operation and the I/O
error and carries no attempt bytes. No caller of `LocalOwner` exists outside its tests yet; the
first must stop on this variant and must not turn it into a generic I/O error or a retry.

Before the rename the failure removes the temporary file and the marker and the old attempt
stands. A crash between the marker and the rename leaves the marker alone: the next load refuses.

`load` refuses while any entry named `commit.intent` exists, whatever it is: a regular file, a
link, a directory, or something that cannot be examined. That one check covers observation,
`PlanReadOwner` capture, every mutation and an install, in this process and after a restart. A
later commit never reinterprets the ambiguous bytes. After a crash in the cleanup either result
is safe: a surviving marker refuses every load, an absent one lets the next load read the known
version, and neither releases anything by itself. A later read classifies the local active state;
it is never proof that a caller got success or may dispatch again. There is no extra in-memory
fence and no global kill switch.

Recovery is an explicit operator act and is not automatic. Under the exclusive lock compare
`sha256(active.json)` with `previous` (the rename did not happen and the old attempt stands; for
a first install `previous` is `none` and the file is absent) and with `next` (the commit
landed); any other value stays fenced. Only then is the marker removed by hand. A matching hash
shows which write won; it does not make the operation's uncertain effect known, which a human
decides. There is no timer, retry or compare-and-set path that clears the marker, and no receipt
is permitted on a match. The store stays local and private; no R or B wire changes.

Tests (`local_owner::tests::cleanup`, with test-only injection at the parent sync, the
read-back as a failure and as a mismatch, the marker unlink and the sync after the unlink): the
first three points are `CommitUnknown`, leave the marker byte for byte, show the new version on
disk, and fence observation, install and every mutation on the original and a reopened handle.
The last two are `CommittedCleanupFailed`: the version is visible and later calls do not change
it, a second `consume` refuses, and the marker is present or absent as the point of failure
dictates. A modeled crash covers both restart results. Both cleanup cases failed on the previous
classification, which returned `CommitUnknown` for them.

Rejected: a flag stored inside `active.json`. Writing it needs the same rename that is uncertain,
so the failure it records could lose it.

## Review fixes at 4fb97cb

* An exit needs the enrolled original's retained identity, not only a readable descriptor: an
  unknown or failing identity refuses, for the daemon exit and the authority exit and handoff.
  No post-exit evidence is invented; a real descriptor that cannot say refuses.
* A reaped original is identified by the snapshot pinned to its own retained pidfd, not by a
  reread. `RetainedProcess::identity` for `CustodianProcess` reuses `verify_pinned`: while the
  descriptor reports the process running it reads `/proc` again and refuses any change; once the
  same descriptor reports the exit, nothing can be read from the reaped process and the stored
  `MeasuredProc` answers. A descriptor or identity error still refuses, `has_exited` is still
  required of every caller, and no other PID evidence is accepted. The earlier reread refused every
  genuine exit (`No such process`). The regression
  (`review::a_reaped_original_keeps_its_stored_identity_on_its_own_retained_pidfd`) pins a real
  child, kills and reaps it, and checks `has_exited`, the failing reread and the stored identity;
  it needs root and runs only with `BRIQYARD_CUSTODY_TEST_REAL_UID=1`, like the other real-UID fixtures.
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

The revised shared file (63 rows, SHA-256 `8d317e51…2b72`, B draft #896 at `628b9a32`) replaced the
57-row file `21371a4f…bdf3`. Its guarded rows carry the full role command with one typed token,
`{"operation_dir":{"root":R,"leaf":L}}`, expanded to `R/<op>/<serial>/L` from the approved
transition, and a `role` on every unit row. `UnitPolicy::expected` takes the role and refuses a
guarded command that is not `guard_argv` for it, so the two split-flag unit rows hash at the codec
(the `argv` rows) and refuse at phase policy (the `unit` rows). `same_target_asset` takes the
independently approved asset length: a pair of equal declared lengths that is not that count
refuses (declared 4097 against approved 4096). Native does not edit the file.

## Release identity in the bind (erratum 2a)

`Inputs::bind` now calls `check_target_asset_identity` for both roles. The guard and the staged
candidate are the target release's asset: the same digest, the actual length of the independently
verified asset (never the length the manifest declares for itself), the Plan's approved build
(`dbuild`, `abuild`) and distinct paths. Both resource custodians are the target bootstrap
daemon: their image is `target_release.daemon` and their build is `Plan.dbuild`. The originals
keep their source pins: `pre.exe` is the source release's, and `DeploymentPolicy::source_daemon_build`
is compared with `Plan.pre_d.build`; its doc no longer says the custodians run the source binary.
A source and a target release with different daemons is the ordinary upgrade, not a release error.

The positive profiles are B's published `sealed.owner.inputs.positive/v2` companions, mirrored byte
for byte under `crates/briqyard-api/testdata/owner_v1/` (B draft #896; sizes and digests in the
README there):

* `sealed_owner_inputs_v1.positive.json`, commit `09325ad3`: source and target share one daemon,
  so it cannot tell a custodian chosen from the source release from one chosen from the target.
* `sealed_owner_inputs_v1.positive-daemon-upgrade.json`, commit `df4d6a88`: source daemon build
  0.2.15, target 0.2.16, a different source daemon. Only the pair discriminates. It binds under the
  target rule; it is refused with `custodian image` under the earlier source rule, and one or both
  custodians on the source daemon and build are refused under the target rule.

Every raw operand in the `native` block (32 per file) is checked against its declared length and
SHA-256 before use, and the Releases verify from their raw pin, sums and assets. B's `expected`
values stay cross-checks computed by native producers: the 18 unit commitments per file from
`UnitPolicy::expected`, the campaign release, topology and order digests, the registry, the
custodian processes and the target asset. The `native.inputs/v1` fixture remains a codec fixture;
it is refused by `bind` (`custodian image`) and is no longer a positive profile. The eight tests
named in review, and the custodian, per-role, TLS and ownership tests that need a valid base, now
run on the standard companion with unchanged refusal reasons. Two expected values were adapted
where the companion's pinned value equalled the mutation (the authority control gid and journal
uid).

## Shared unit vectors

The API's `sealed_owner_units_v1.vectors` (63 rows, SHA-256 `8d317e51…2b72`) is the shared source of
the four commitments for R, B and native. `unit_policy` holds the typed policy (`UnitPolicy`:
legacy and guarded unit with placeholders `op` and `serial`), sorts sets into canonical order, and
computes what each phase shows (`prearm`: legacy file and legacy loaded unit; `armed`: guarded file,
legacy loaded unit; `launch`, `seal`, `launch_a`: guarded file and guarded loaded unit). Native reproduces all 63 rows:
39 digests or accepts, 24 refusals, each with its own reason. No row conflicts with erratum 2 or 2a.
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
