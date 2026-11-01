# 0077: Immutable host identity for unbound warm slots

Status: internal preparation and recovery evidence; public unbound pool creation/consumption is not enabled.

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
launch. Live adoption/preparation/activation additionally requires a fresh backend proof:
matching host PID incarnation and machine ID, all real/effective/saved/filesystem UID/GID
values and no foreign supplementary groups. Missing kernel evidence is refusal. Native
same-PID/UID proof remains required.

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

An internal `UnboundPaused` transition parks at the verified pristine builder barrier without
sending destination configuration or activation. It requires an owned resumed process and
sealed `/work` geometry. The existing disk path creates and formats a new private data
volume with a fresh UUID for these records. The public profile selector still rejects this
mode, configured-slot recovery does not select it, and binding/activation explicitly refuses
it until durable assignment integration is complete.

`launch-transitions` journals each launch-identity record/reader stage change before either
write. Startup reconciles only exact journal-evidenced record-first/reader-second states
before strict provenance checks. Workload, ownership, boot evidence and the complete origin
remain fingerprinted; terminal exit/error/accounting observations survive reconciliation.
Contradictory reader-first states, changed controls, missing records/holds/readers or unknown
journal schemas stop reconciliation with reservations retained. This is stage-write evidence,
not a destination assignment journal or permission to infer a missing tenant assignment.

A separate private `unbound-assignments` journal records the complete destination request,
source and target records/readers. `unbound-requests` retains only the permanent request
namespace, request ID, normalized create digest and slot identity after completion or
destruction. Preparation journals grant no such authority. Existing sandbox replay checks
this authority first: pending, missing, conflicting or uncertain assignment state is never
a warm miss. Pending source slots are protected from drain and destruction.

The model plans only an owned `UnboundPaused` process, preserves its machine/backing and
launch identity, freezes fresh destination identity/configuration, and validates destination
name, address and complete root/data/CPU/RAM quota independently of physical availability.
Startup repairs ownership and reader metadata before stage journals and exact provenance
checks. Interrupted index, record and reader writes retain the same consumed request/slot.
Missing records/readers and PID absence without exit proof retain reservations and backing.

This writer has no public call path. Live pending destination name/address/quota reservation,
ordinary-create lock ordering, catalog/drain race checks, assignment-aware live adoption,
full bind/ACK/network/main/exec integration and complete managed rollback protection remain
required before reachability. A stored request index or a fresh physical sample is not proof
that concurrent tenant admission or guest activation is safe.
