# ADR 0135: Prepare host artifacts before admission withdrawal

2026-11-15 · Accepted

## Decision

The embedded bootstrap has `prepare` and `activate` phases for installed hosts.
Fleet upgrades prepare before marking the host `upgrading`. Standalone full installs
retain provisioning before downloads. Custom bootstrap scripts retain their existing
single invocation after withdrawal; no phase protocol is inferred from file contents.

Preparation reuses the release checksum and checked-runtime verifier. It stages all
binaries, extracted runtime files, default kernel bytes and requested nested assets.
It writes no live runtime paths, config, packages, firewall or guest state. Activation
verifies a local receipt and consumes it before provisioning. All artifact inputs then
come from that preparation; release or kernel downloads are not repeated.

One root-private directory bounds retained preparation storage to one candidate. Its
receipt hashes every staged file and binds the release, architecture, nested selection,
kernel URL/digest, current config and random operation identity. It lasts one hour.
The root-owned installer lock serializes every phase, full install and peer update.
The retained directory reserves mutation between phases. Only expired complete receipts
are removed automatically under the lock. Incomplete or consumed preparation requires
inspection and explicit discard; interrupted activation is never blindly replayed.
A fleet restart does not redispatch a preparation. An interrupted withdrawn host retains
ADR 0027's draining recovery. An operator state change during download refuses withdrawal.

Artifact HTTP requests have 20-second connection and 300-second total bounds. A failed
fetch removes its temporary file. Ordinary exits remove incomplete preparation; a killed
process can retain the single directory for inspection.

## Scope

This first slice moves artifact downloads only. Package and host provisioning remain
after withdrawal, with their existing memory, warm runtime and assignment compatibility
gates. Candidate config validation and rollback capture still precede executable/config
replacement. The preparation receipt establishes local integrity, not release authenticity
beyond the existing checksum source. It contains no credentials.

Readiness during downloads does not imply zero downtime. Long daemon streams still end
at the handover bound. Namespace admission pinned to a withdrawn host needs a later
handover mechanism. No new release or native qualification is implied by portable tests.

## Validation

Bootstrap tests stall a download and assert no provisioning or config replacement. They
remove the origin before activation, refuse artifact access in activation, and test corrupt,
stale, symlinked and consumed receipts. Fleet tests hold preparation pending while the
host remains ready, then check withdrawal ordering and changed-state/failure refusal.
