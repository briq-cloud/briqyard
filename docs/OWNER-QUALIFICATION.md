# Owner-layer qualification

What the target-side owner (ADR 0149) is checked against, and what a joint run with the API (B)
and the receiver (R) still needs. Everything here runs on a disposable host only.

## What `hack/owner-qualify.sh` runs

It reports 10 checks, or 12 when `OWNER_B_GOLDEN` and `OWNER_B_UNITS` are both set; a skipped
comparison is printed as skipped. None of it is a live or joint result.

Needs `BRIQYARD_DISPOSABLE=1`, root, Linux, and no active `briqyardd` or `briqyard-fleet` unit.
It makes one scratch directory, removes it on exit, interrupt or termination, and starts no
service and no daemon.

| Step | Proves |
|---|---|
| golden hash, and B's copy with `OWNER_B_GOLDEN` | R, B and native hold the same 15 records |
| unit vectors hash, and B's copy with `OWNER_B_UNITS` | the same fixed SHA-256 for native's and B's bytes; it changes when the revised shared file is published |
| `sealed::tests::owner` | each record decodes, re-encodes to the same bytes and hash, signatures verify under the public keys |
| `local_owner` | one private attempt replaced by version compare-and-set with a durable fence on any unknown commit and a distinct known-but-cleanup-failed outcome; both arm receipts at one version; collector projections per point; the first handoff compares version and every binding before anything changes; exit, then guard start, then one consumption; every break in that lineage refuses and writes nothing; store failures before and after the rename |
| `review::a_reaped_original_keeps_its_stored_identity_on_its_own_retained_pidfd` | its own check: the one gated regression, run with `--ignored --exact` and `BRIQYARD_CUSTODY_TEST_REAL_UID=1`. A real child is pinned by `CustodianProcess`, killed and reaped; the same pidfd reports the exit and `identity()` returns the stored snapshot. It is not part of the default `local_owner` run (48 passed, 1 ignored) and no other ignored fixture runs |
| `sealed::tests::unit_vectors` | all 63 rows of the shared unit vectors: exact digests, and each refusal for its own reason; the guard command policy, the split-flag rows refused by phase policy, the actual-length asset negatives |
| `sealed::tests::preimage` | the four commitment preimages match an independent computation; the arm receipts built from them hash to the independent values |
| `inputs::tests` | `Inputs::bind` on the two published positive profiles (standard and daemon upgrade): guard and candidate are the target asset at distinct paths with its actual length, both custodians are the target bootstrap daemon at the Plan build, originals keep their source pins, B's expected digests match native's own; the old `native.inputs/v1` fixture is refused |
| ordinary parity | only the three wiring files differ from the base outside `local_owner`; `execution_custody` and `guarded` suites pass unchanged |

## Not run, and why

* **Live joint read.** R and B each challenge `sealed-owner-observe` on a running target over their
  own read-only SSH identity. The production `LiveHost` refuses every fact whose preimage is
  not produced here (the manager query, the installed unit policy, delivery order, final I/O; ADR 0149), so a target
  cannot answer yet.
* **Exit-75 handover on one host with the enrolled guard.** Same dependency.
* **Sealed context source attach.** A guarded listener must refuse to open until its source of
  enrolled operations is attached. No production source exists yet, so this slice adds none.

## Joint run, once the preimages are pinned

1. Boot a throwaway host; install this head with the checked-release path of `hack/native-ci.sh`.
2. Enroll through R with B reading both receipts; confirm B stores R's committed
   enrollment revision, its envelope hash and the two receipt digests as evidence. On any later
   observation the exact committed revision and receipt pair are required: a different revision
   refuses (erratum 1 §A.3), and so does a swapped fragment.
3. Mutate the target between B's first read and its final probe (same facts, higher version, then
   same version with a changed fact); B's commit must refuse.
4. Run the handover: first handoff at the pre-withdrawal version, the original's exit, the guard's
   start, one consumption. Repeat with an unrelated mutation, a replaced guard and a second
   consumption; each refuses.
5. Run `hack/e2e.sh` and `hack/fleet-smoke.sh` unenrolled; counts must equal `docs/DEVELOPMENT.md`.
6. Destroy the host. No credentials, keys or private descriptors are used; every key here is a public
   synthetic fixture.
