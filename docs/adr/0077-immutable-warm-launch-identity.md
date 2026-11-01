# 0077: Immutable host identity for unbound warm slots

Status: prerequisite implementation; unbound sandbox pool consumption is not enabled.

A jailed VMM's UID and GID currently derive from its namespace subnet and host number.
Changing those coordinates while its process survives would change adoption's exit-socket
owner and allow the original UID to be reused. Disk datasets and TAP names already use the
stable machine ID.

A pristine sandbox warm record carries a versioned immutable launch identity: original
namespace, subnet and host number, UID/GID, jail mode, jailer path, jail base and UID base.
An independent durable `launch-holds` record reserves that source allocation before launch.
Destination assignment must preserve both records, the machine ID and the live incarnation.
Legacy configured pools keep their existing identity derivation and namespace restrictions.
Unjailed launch identities are rejected until their process credentials are qualified.

The identity also freezes the source machine, snapshot and complete immutable artifact hash.
Reader destination, namespace, source, snapshot, generation and lifecycle stage must agree
with the owning record. A recorded live PID requires the exact boot incarnation, start ticks,
host boot ID and sealed boot identity. The owned launch path durably records that evidence
before guest configuration or readiness; its existing failure path settles an unconfirmed
launch. This validates stored evidence and does not substitute for native same-PID/UID proof.

Startup reconciles holds before stale-record removal, network publication or orphan sweep.
Missing or disagreeing identities, changed jail configuration, conflicting allocations and
journal-only holds stop startup while retaining the allocation and backing. Address and
subnet selection, namespace deletion and namespace rename respect source holds. Destruction
releases a hold last, after verified process exit and successful backing/run/jail cleanup.
An uncertain write or failed cleanup retains the allocation. A retry can finish an identical
hold, but cannot replace either its cached or durable identity. The machine record is
durably deleted under write exclusion before its hold is durably deleted.

Graceful handover fences namespace admission while checking `state-capabilities` on the
installed replacement executable. The admission wait and target probe share a bounded
deadline; stop signals and server completion can cancel the wait. A target lacking `launch-identity-v1` leaves the current
daemon serving with its listeners and ownership intact. This guard covers graceful handover;
it does not make arbitrary older installers or forced restarts compatible. Normal managed
rollback must refuse incompatible installed targets and fallback/restart paths while holds
exist before unbound pools can be enabled. Draining requires verified exit and completed
cleanup, not merely desired zero. Preserving unknown JSON fields alone is insufficient.

Resource accounting exposes full data-volume capacity separately from logical roots,
checks each configured budget and subtracts their sum before the disk free-space floor.
Zero data charge retains the legacy resource wire shape. Record-level tests cover these
logical liabilities; native disk creation and durable assignment consumption remain unqualified.

Remaining integration includes unbound preparation, durable destination assignment with
full create identity, assignment/reader ownership transfer, quota transfer,
recovery/drain races and native qualification. These prerequisites are not a working warm
sandbox feature.
