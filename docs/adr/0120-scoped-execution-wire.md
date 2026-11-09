# ADR 0120: Scoped execution credential wire

Date: 2026-11-09 · Status: accepted prerequisite; no scoped route enabled

## Decision

Define version-one grant, allocation and single-operation permit types in `briqyard-api::execution`.
Host verification is optional (`execution-verifier`); the guest init gains no cryptographic dependencies.
No daemon or fleet route accepts these credentials. Administrator authentication is unchanged.

Three compact JWS credentials have separate purposes:

| Type (`typ`) | Signing role | Binding |
| --- | --- | --- |
| `briqyard-execution-grant+jwt` | central | Original credential identity/expiry, quota principal, team, external subject, exact runtime target, frozen resource set, idle protection, metadata revision, operations, limits |
| `briqyard-execution-allocation+jwt` | central | Authority/epoch, quota principal/bucket, fixed window, units, allocation epoch/deadline |
| `briqyard-execution-permit+jwt` | authority | Exact grant and allocation digests, debit units, admission ID, authority/epoch, target/run/placement, operation, request commitment, metadata revision, limits |

Headers contain exactly `alg`, `typ`, `kid`, `v`; `alg` is `EdDSA`, keys are raw Ed25519 only,
and both header and claims `v` equal 1. Public keys, roles and issuer assignments come from a local allowlist.
Each authority key also belongs to exactly one authority identity; central keys have no authority.
Verification binds the key's issuer and authority to the trusted dispatch context, independently
of signed identity strings. A valid key cannot impersonate another configured authority.
Unknown IDs, duplicate local IDs, key URLs, embedded keys, unknown/duplicate JSON fields and
algorithm fallback are refused. Signature verification precedes claims deserialization.
The maximum compact token is 16 KiB, its encoded header 512 bytes. IDs are 1–128 ASCII characters
from letters, digits and `_ - . : /` (without spaces). Resource sets hold 1–64 distinct machines;
permits hold 1–16 distinct allocations/buckets. Operations are a unique nonempty subset of
`exec`, `exec_stream`, `shell`, `files_read`, `files_write`.

Numeric dates are integer Unix seconds from zero through 9007199254740991, inclusive.
Other integers use that same safe range. No optional claim has an implicit default.
`iat <= nbf < exp`; a trusted clock with uncertainty `u` accepts only when
`iat <= now-u`, `nbf <= now-u` and `now+u < exp`. Clock arithmetic failure refuses.
Grant expiry cannot exceed original credential or idle-protection expiry.
The issuer sets its authorization-freshness maximum; this verifier does not impose a 60-second cap.
Allocation expiry cannot exceed the fixed window end. Permit expiry cannot exceed grant or
any allocation expiry; issuance/not-before cannot predate its source authorities.
Permit limits cannot exceed grant limits. Positive allocation debits cannot exceed delegated units.
No duration cap extends a credential deadline; future routes must terminate ongoing work by
its deadline and enforce all byte/duration limits.

Digests are unpadded base64url SHA-256. Grant/allocation commitments hash the exact UTF-8 compact
JWS bytes, including its signature; they never hash a JSON reserialization.
The versioned request encoding is deliberately undefined here: a route must define its semantic
commitment (including file path, mode, length/checksum policy and deadlines) before activation.

The caller supplies an independently trusted dispatch snapshot: issuer policy, principal, team,
external subject, exact target, resource set, metadata revision, authority/epoch, installed
allocation references, operation and request digest. The verifier checks equality, including
vector order. It never derives this snapshot from submitted credentials or mutable machine metadata.
The external subject must be bound independently to issuer/team/runtime target.
Run identifies the actual VMM incarnation; placement is an execution epoch invalidated by moves
or ownership changes even when the VMM stays alive.

## Required before activation

A verified bundle is only checked data. It does not consume an admission or reserve quota.
Activation requires durable authority admission records, exact allocation fence installation and
acknowledgements, one-time daemon consumption, lifecycle-serialized invalidation/initial dispatch,
bounded evidence retention/recovery, request commitments, deadline enforcement and race tests.
Recovery uncertainty must refuse dispatch; replaying an admission must never launch again.
Scoped routes must require both credentials and never fall through to administrator authentication.

`crates/briqyard-api/tests/fixtures/execution-v1.json` is the machine-readable positive wire fixture.
Its public deterministic test seeds are explicitly test-only. Rust tests reproduce and verify it,
then reject mutated signatures, headers, claims, ceilings, time intervals and trusted bindings.
