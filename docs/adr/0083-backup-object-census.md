# ADR 0083: Bounded backup-object observations

2026-11-03 · Status: source candidate; execution and native qualification pending.

## Context

The backup listing skips unreadable records and starts from known machines and holders.
It cannot inventory objects whose owner is absent locally. Streams publish before metadata;
retained holders, admitted jobs and machines on other hosts remain legitimate owners.

## Decisions

**Observe only `backups/`, at most daily, through the existing retained backup job.**
The first attempt is due after one day of daemon uptime. Admission, a dedicated turn and
shutdown drain retain the census after its observer leaves. A busy active backup gate skips
that day's attempt. Active store work, including waiting for a shared read permit, has a
30-second timeout. No upload, deletion, ZFS command or lifecycle mutation is introduced.

**Bound retained observations and strict metadata reads.** The list retains at most 4,096
objects, with 1,024-byte keys and at most 1,024 bytes each of ETag and version identity.
One extra item distinguishes exhaustion from truncation. Reads are serial: at most 64 KiB per
record and 8 MiB reserved response bytes per attempt, including failed reads and each read's
one-byte overflow probe. Empty records reserve two bytes. The SDK retains its own listing page and transport buffers; these limits
bound application inventory and metadata allocation, not the SDK or allocator's exact RSS.
The existing read gate is shared with ordinary listings.

**Validate paths and actual backup types before following references.** Unknown record/disk
fields, invalid IDs, duplicate fields/disks, foreign stream paths, nonolder bases, inconsistent
sizes or incremental flags and malformed encryption envelopes remain malformed. No key is
requested and sealed contents are never opened. A GET must match the listed size and provider
identity and return its exact expected length. A changed/missing/oversized read stays unknown.
Version identity is checked when LIST supplied it; a version reported only by GET is accepted
when the listed path, length, ETag and modification time still match.
Each disk's transitive bases must have matching machine, namespace, disk and key identity.
Only stream existence and length are observed: ciphertext authenticity, content hashes, key
availability, snapshot identity and successful restore remain unqualified.

**Cache fixed scalar observations, never clean or orphan verdicts.** Unknown or malformed
records and unresolved stream references invalidate metadata coverage. Truncation invalidates enumeration and metadata coverage.
Failed/timed-out attempts retain only partial scalars and clear coverage. Scrapes use a
nonwaiting cache read and perform no store I/O. Coverage expires after two days; timestamps
always identify the attempt, not the freshness of every object. Overlapping retained jobs
are flagged and clear coverage, but quiet local jobs do not establish a race-free view.

## Consequences

Matching local active machines, retained destroyed holders and admitted job owners count as
positive local observations. Everything else remains unresolved, including foreign owners.
Unreferenced streams can be in-flight publication; missing references can be concurrent
pruning or a truncated listing. Repeated observations replace gauges and confer no authority.
Even exhausted enumeration and validated metadata are observations across time, never an
atomic snapshot or an integrity/restore certificate. Global ownership and deletion qualification
are always false. Fleet registry daily/latest backups, archives, multipart uploads/versions,
unknown prefixes, assigned-run/update references and image/snapshot backing are outside this
census. Their protection and future authorities cannot be inferred from missing local owners.
