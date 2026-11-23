# ADR 0146: Root custody reads the two prior Plan commitments

Date: 2026-11-23 · Status: accepted

## Context

Interface v3.5 section (c) (SYL-268, SHA-256
595a10200a659341972af036f677dc07507cd8aebd2495d3b72b16560d64dc59) has root custody read the
receiver's (R) and the API's (B) independently committed pin of the operation's Plan before a
resource is armed, launched or sealed. v3.1 says both pin `H(Plan)`, but neither the
trust root nor the reader existed. The native v3.3/v3.4 FD table and every asset format stay
frozen. No concrete root operation owner or lease exists at this boundary yet.

## Decisions

**A read is an observation and nothing else.** The result, `VerifiedPlanObservation`, says both
enrolled observers signed the same pin of the local Plan for one nonce. It has no constructor
outside its module, no `Clone`, no wire form and no conversion into a rooted act. No journal
opens, no epoch advances, no permit, service call, launch, Gate mutation, readiness or secret
delivery follows from it. The two tags, `plan.read.receiver` (Rk) and `plan.read.api` (Bk), are
in no effect or claim ACL.

**Trust comes from a root-private file, never from the Plan.** `/etc/briqyard-sealed/plan-reader/v1/<aud>/<reg-hash>/<serial>.json`
holds the enrolled Rk/Bk. The loader walks one pinned directory descriptor at a time and
requires root:root 0700 directories and a 0600 single-link regular file. It refuses a symlink,
hardlink, foreign owner or file replaced during the read. A missing record fails the read; no
eligibility record or offered Plan substitutes. Local `Plan.rk/bk` must equal the enrolled keys,
as a consistency check only.

**One fixed socket, one frame each way.** Only `/run/briqyard-sealed/plan-reader.sock` is connected:
AF_UNIX stream, root:root 0600 under non-writable ancestors. Kernel peer credentials and the
enrolled helper image must match before the request and after the reply. Frames are a 4-byte
big-endian length, 1..65536, no descriptors; the peer must close after its one frame.

**The reader compares, the owner supplies state.** `PlanReadOwner` has `capture` (locks released on
return) and `lock_and_capture` (locks kept). The read happens between them, outside every
lock, and the reader compares all facts and the exact Plan bytes. An owner reporting "unchanged"
for itself would be an `is_owned` flag. The snapshot carries the v3.6 original-owner identity
(registered and intrinsic IDs from the one Host row, and the resource's `pre` and `custodian`
processes); `pre` must equal the Plan's `pre_d` or `pre_a`, and a changed or restarted
custodian refuses. The manifest is public assembly, never trust.

**Nonce lineage lasts through local use.** Each exchange draws 32 bytes from the OS source;
one read per resource is outstanding (at most two), held until the observation is dropped. The
bound is five seconds, monotonic, from nonce generation through local use.

**Test scope is labelled.** Tests use synthetic seeds, a mutex-backed stand-in owner, a
user-owned tree and a probe reading the peer's start ticks. The test binary (512 MiB) exceeds
the 256 MiB executable-hash limit, so that probe reports a fixed image digest. Production
constructors take no root, path, clock or probe argument.

## Consequences

The next package must implement `PlanReadOwner` on the real root owner, with the
prescribed lock order and no I/O under a lock. The receiver and API pin writers, the SSH relay
and helper, the mTLS client, trust provisioning and the helper's enrolled image digest remain
separate packages, and startup stays closed without them. The real root peer is not qualified
here. Reopen if a concrete owner needs a different capture shape.
