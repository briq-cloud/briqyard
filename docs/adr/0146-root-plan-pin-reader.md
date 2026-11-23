# ADR 0146: Root custody reads the two prior Plan commitments

Date: 2026-11-23 · Status: accepted

## Context

Interface v3.5 section (c) (SYL-268, SHA-256
595a10200a659341972af036f677dc07507cd8aebd2495d3b72b16560d64dc59) has root custody read the
receiver's (R) and the API's (B) independently committed pin of the operation's Plan before a
resource is armed, launched or sealed. v3.1 says both pin `H(Plan)`, but neither the
trust root nor the reader existed. The native v3.3/v3.4 FD table and every asset format stay
frozen. No concrete root operation owner or lease exists at this boundary yet. An independent
review found four defects in the first version; this revision records their fixes.

## Decisions

**A read is an observation and nothing else.** The result, `VerifiedPlanObservation`, says both
enrolled observers signed the same pin of the local Plan for one nonce. It has no constructor
outside its module, no `Clone`, no wire form and no conversion into a rooted act. No journal
opens, no epoch advances, no permit, service call, launch, Gate mutation, readiness or secret
delivery follows from it. The two tags, `plan.read.receiver` (Rk) and `plan.read.api` (Bk), are
in no effect or claim ACL.

**One presentation, checked at the gate.** `RejoinedObservation::consume(self, gate)` checks the
five-second bound immediately, then hands the observation (data, by reference) and the owner's
held state (by value) to the gate once. Past the bound the gate never runs and the locks are
released. Read and Pin are data, not freshness capabilities; nothing returned can be shown to a
later gate. This type cannot make an effect single: the owner's gate must still compare-and-set
its own state under the held locks and take at most one action. No real gate consumes it today.

**One reservation per resource per process.** Production handles share one process-wide
reservation (`production_ledger`), so two `PlanReader` handles cannot hold the same resource.
It is in-process bookkeeping, not a nonce store or approval store. The guarantee across
processes is the operation owner's sole lease, which this module does not replace.

**Trust comes from a root-private file, never from the Plan.** `/etc/briqyard-sealed/plan-reader/v1/<aud>/<reg-hash>/<serial>.json`
holds the enrolled Rk/Bk. The loader walks one pinned directory descriptor at a time and
requires root:root 0700 directories and a 0600 single-link regular file. It refuses a symlink,
hardlink, foreign owner or file replaced during the read. A missing record fails the read; no
eligibility record or offered Plan substitutes, and there is no default path. Local
`Plan.rk/bk` must equal the enrolled keys, as a consistency check only.

**One fixed socket, bound to the peer's kernel pidfd.** Only `/run/briqyard-sealed/plan-reader.sock`
is connected: AF_UNIX stream, root:root 0600 under non-writable ancestors. The connected
peer is identified by `SO_PEERPIDFD` (Linux 6.5 or newer), the kernel's own pidfd for that socket.
Its PID must equal the SO_PEERCRED PID, UID and GID must be the enrolled ones, and the
process (PID, start ticks, boot, executable hash) must equal the independently supplied
`EnrolledHelper`. The pidfd is polled before and after each probe: a process that is alive
across a sample cannot have had its PID reused, and a process whose stat and executable are
still readable but which has exited is refused. Where the primitive is unavailable the read
fails closed; there is no fallback to a numeric PID. Two samples around an exchange do not
prove one image ran uninterrupted.

**No descriptor is ever held.** Replies are received with no ancillary buffer. The kernel
closes anything the peer attaches and flags the receive; the reader refuses on the flag.
Framing is a 4-byte big-endian length, 1..65536, and the peer must close after its one frame.

**The reader compares, the owner supplies state.** `PlanReadOwner` has `capture` (locks released on
return) and `lock_and_capture` (locks kept, taken in the owner's prescribed order, no I/O
under them). The read happens between them, outside every lock, and the reader compares every
captured fact and the exact Plan bytes. An owner reporting "unchanged" for itself would be an
`is_owned` flag.

**Owner-supplied assertions are not row, process or lease truth.** `OriginalOwner` (registered and
intrinsic IDs, `pre`, `custodian`) is what the owner asserts. Its raw constructor is test-only. A
production constructor must project it from the separately validated `native.inputs` target Host
row and the selected Resource row, with the processes taken from the live retained owner, under
the owner's fixed lookup and lock order. That projection belongs to the manifest package; this
module has no second parser and never approves a snapshot by equality alone. What it adds is
the comparison: `pre` must equal the Plan's, and a changed custodian, resource or mapping refuses.

**Nonce lineage lasts through local use.** Each exchange draws 32 bytes from the OS source;
the reservation is held until the observation is dropped or consumed. The bound is five
seconds, monotonic, from nonce generation through local use.

**Test scope is labelled.** Tests use synthetic seeds, a mutex-backed stand-in owner, a
user-owned tree, a probe for the executable hash (the 512 MiB test binary exceeds the 256 MiB
hash limit) and, on kernels without `SO_PEERPIDFD`, a pidfd opened for the credentialed PID.
Production constructors take no root, path, clock, probe or opener argument. The one test of
the real socket option is ignored on this machine's 6.1 kernel and is not replaced by a
stand-in.

## Consequences

The next package must implement `PlanReadOwner` on the real root owner, project
`OriginalOwner` from validated rows, and take the sole lease. The receiver and API pin
writers, the SSH relay and helper, the mTLS client, trust provisioning and the helper's
enrolled identity remain separate packages, and startup stays closed without them. The
helper must be a fixed, dedicated, non-delegating process whose starter supplies its
identity; that lifecycle, the real root peer and `SO_PEERPIDFD` itself are unqualified here.
Reopen if a concrete owner needs a different capture shape.
