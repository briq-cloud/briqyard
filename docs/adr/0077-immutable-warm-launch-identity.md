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

Startup reconciles holds before stale-record removal, network publication or orphan sweep.
Missing or disagreeing identities, changed jail configuration, conflicting allocations and
journal-only holds stop startup while retaining the allocation and backing. Address and
subnet selection, namespace deletion and namespace rename respect source holds. Destruction
releases a hold last, after verified process exit and successful backing/run/jail cleanup.
An uncertain write or failed cleanup retains the allocation.

Graceful handover fences namespace admission while checking `state-capabilities` on the
installed replacement executable. A target lacking `launch-identity-v1` leaves the current
daemon serving with its listeners and ownership intact. This guard covers graceful handover;
it does not make arbitrary older installers or forced restarts compatible. Normal managed
rollback must refuse incompatible installed targets and fallback/restart paths while holds
exist before unbound pools can be enabled. Draining requires verified exit and completed
cleanup, not merely desired zero. Preserving unknown JSON fields alone is insufficient.

Remaining integration includes unbound preparation, durable destination assignment with
full create identity, incarnation/reader binding, quota transfer, data-volume accounting,
recovery/drain races and native qualification. These prerequisites are not a working warm
sandbox feature.
