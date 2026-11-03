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

Graceful handover fences namespace admission while checking the installed replacement
executable. State inspection fails closed on malformed or unknown evidence. Every candidate
must pass the exact assignment, assigned-run and assigned-run-lifecycle capability probes,
regardless of the sampled floor; launch holds additionally require `launch-identity-v1`.
The admission wait and target probes share a bounded deadline; cancellation or a weaker
target leaves the current daemon serving with its listeners and ownership intact.

Managed installation and automatic rollback use the same unconditional assignment protocol
requirements before copying any executable, including when the daemon is stopped. An
admitted writer or a daemon restart can advance the floor between preflight and copying.
Updated installers serialize with a root-owned lock held through preflight, rollback capture,
installation, handover and failure cleanup. The staged candidate remains private and its
bytes are checked again before activation. Automatic rollback refuses a weaker retained
daemon and leaves the compatible replacement installed while reporting the failure. Weaker
offline downgrades are unsupported. Draining requires verified exit and completed cleanup,
not merely desired zero; preserving unknown JSON fields alone is insufficient.

Resource accounting exposes full data-volume capacity separately from logical roots,
checks each configured budget and subtracts their sum before the disk free-space floor.
Zero data charge retains the legacy resource wire shape. Enabling unbound pools requires a
positive data-volume budget; otherwise startup refuses the configuration rather than letting
zero silently drain all unused warm slots. Record-level tests cover these logical liabilities;
native disk creation and durable assignment consumption remain unqualified.

Live egress `via` resolution applies the same assignment-publication predicate used when
rebuilding host rules. An unverified assigned target is treated as absent until its identity
and durable publication state are proven.

The source candidate integrates unbound preparation, durable destination assignment with
the full create identity, assignment/reader ownership transfer, quota transfer and
recovery/drain handling. These are source-level prerequisites, not qualification evidence.
Public exposure remains behind a separate default-off operator gate until native process,
disk, network, recovery and failure-path qualification passes.

The `UnboundPaused` transition parks at the verified pristine builder barrier without
sending destination configuration or activation. It requires an owned resumed process and
sealed `/work` geometry. The existing disk path creates and formats a new private data
volume with a fresh UUID for these records. The configured warm-pool selector and public
named-clone path retain their existing profile restrictions. Ordinary `sandbox_seed` create
can select these slots only when `templates.unbound_warm_pools` is enabled.

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

Private staging takes warm, namespace, sandbox-create and entry locks in that order, then
rechecks under the ordinary machines admission lock. Before uncertain intent publication,
the exact target reserves its name, address, subnet and full namespace quota. Ordinary
create, start, growth, move and configured-pool claim admission respect these reservations;
namespace deletion/rename cannot discard them. Quota uses replace the source by stable
machine ID while physical host accounting retains its one source record. Startup reconstructs
all pending targets before reconciling any one intent, so coexisting liabilities cannot pass
quota independently.

A private live commit shares the recovery writer's exact source/target record and reader
checks. It requires fresh actual process proof from the immutable launch identity, then
updates the same Entry under the admission lock after the durable record write, before
the reader write. An uncertain reader write therefore leaves target ownership in memory. The
record-write exclusion stays held through publication and the Entry update, preventing a
concurrent save from restoring source ownership afterward. Usage
through the ownership boundary is drained to its old owner; CPU/address baselines start
over without discarding host counter totals. A tick begun under old ownership cannot seed
the new owner's baselines. Unbound destination names stay out of DNS before activation.
Failed or uncertain writes retain request authority and reservations; a missing durable
intent in an uncertain process remains blocked until startup reconciliation.

Staging and ownership writers remain separate from guest binding. A private assigned
caller now validates the complete destination frame before consuming a pristine slot,
then journals the exact full payload in Configuring before resume or vsock transmission.
It requires settled permanent assignment authority and the original trusted owned handle.
The assignment-only VMM resume operation queries actual Paused/Running state; fresh
immutable process proof brackets that API operation. Legacy paused resume remains strict.
Running alone cannot authorize main: Configuring accepts only the exact guest builder or
matching destination-done pre-main barrier. A lost resume/ACK retries the same frozen
payload, entropy and clock; unknown state, missing handle or unsettled journal is refusal.

The existing complete bind ACK becomes durable IdentityDone before target traffic counting,
bridge activation, main activation and first exec. Active follows successful first exec;
RUNNING, probes and namespace DNS follow that barrier. The activation core is shared with
legacy clones, while their existing unbound guards remain. Interrupted stage writes use
existing launch-transition recovery; restarted records cannot bind without a fresh owned
handle from assignment-aware adoption.

Assigned startup recovery now dispatches before configured warm recovery or incomplete
clone settlement. It quarantines first and requires settled durable receipt, exact reader,
launch hold and schema-1 artifact evidence. Actual API Paused/Running adoption is bracketed
by exact immutable host-process proof. Saved boot identity populates only a local provisional
handle: a known matching observed device profile is required, while unavailable or
contradictory observations refuse adoption. Fresh guest init/protocol/profile/RAM-marker
continuity and stage-specific full bind ACK/main-PID evidence precede installing trusted
ownership. Configuring and IdentityDone remain quarantined for exact private bind replay;
Active network, probes and DNS return only after continuity, with via dependencies also
restricted to verified targets. Unknown exit never enters legacy kill/cleanup or fallback.

Ordinary operations remain fenced for unverified assigned ownership. Ordinary cold start
and automatic stopped-by-host restart refuse previously launched assignment records; this
is a safety fence, not complete stop/start or reboot behavior. An assignment-aware path
that preserves mutable root/data/configuration across user stop/start and host reboot is
still a pre-enable requirement. Loading or stopped records without an adoption contract,
and unassigned pristine sources, remain conservatively retained.

A separate private assigned-run journal now reserves the first continuation only after
positive old-process exit. Its host generation is separate from the saved checkpoint guest
lineage or a fresh ordinary-boot generation. It freezes actual current dataset GUIDs and
either current checkpoint fingerprints or the exact encoded ordinary config drive and
expected measured-bundle digest. Expected host evidence is never observed guest proof.
Intent, current-run record, machine link and distinct run reader are repaired before
creation-stage validation; actual backing is checked before startup side effects. Creation
receipt, launch identity, clone origin and creation reader remain unchanged. Reserved and
observed links never confer trust and remain excluded from the initial-assignment lifecycle.

This is metadata authority only: no continuation launcher consumes it. Pending updates are
retained and refused until explicit integration; subsequent run sequences, new-process
observation/guest proof, checkpoint-to-fresh fallback and stop/start/reboot completion remain
separate required work. Uncertain authority retains full reservations without a second run.

Outside the default-off `templates.unbound_warm_pools` path, public selectors do not call
these primitives. Current/desired-zero/catalog generation race checks, complete
assignment-aware stop/start/reboot behavior, compatible managed
rollback/fallback qualification and native qualification remain required before reachability. A stored
request index or a fresh physical sample is not proof that guest activation is safe. Tests
use stand-in VMMs, synthetic disks and a local API socket; Linux/native process, TAP, disk
and recovery qualification remains required.

The source candidate now connects the catalog factory and ordinary `sandbox_seed`
create through `templates.unbound_warm_pools`, a separate default-off gate. It gates
profile advertisement, pristine internal factory allocation and selection together;
legacy configured claims and public named clones keep their existing restrictions.
Warm hits retain the source machine ID, backing, process and immutable launch identity.
Existing assignment intent/receipt and reader transfer settle before the accepted
STARTING response. The existing create worker then binds and publishes that exact
assignment. Request replay never queues another worker. The worker's I/O admission
exists before ownership commitment; binding errors never enter generic disk cleanup.

Selection validates the full explicit seed request and recipe, current catalog,
positive demand, exact artifact fingerprint, effective CPU/RAM/topology/device, and
fresh process/reader/launch authority under the existing admission order. Gate-off
or an unused-slot miss retains the same selected-seed restore and request digest;
uncertain or consumed assignment authority is never a miss or ordinary-image fallback.
This is source integration only. The gate remains off until native process, disk,
network, recovery and failure-path qualification and ordinary review/CI are complete.
