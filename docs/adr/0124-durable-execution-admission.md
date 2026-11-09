# ADR 0124: Durable scoped execution admission

Date: 2026-11-09 · Status: implemented boundary; scoped HTTP access remains unavailable

## Decision

The trusted admission issuer owns an exclusive journal and an Ed25519 authority key.
The public execution gateway owns neither. `DurableIssuer::issue` verifies the complete
credential bundle and persists every quota debit and the admission before releasing its
signed permit. Repeated admission IDs return a status-only refusal, never another dispatch.

Installation precedes any operation permit. `verify_delegation` validates the central grant
and allocation vector against an independently supplied trusted snapshot, without an
authority signing key or a fabricated permit. Dispatch reuses these checks before validating
the authority permit. Allocation IDs and buckets must both be unique. Each allocation keeps
its own expiry even when the grant lives longer.

`Journal::install_allocations` durably stores those exact signed allocations under the
current service instance and authority fence. Repeated installation preserves every debit;
a different signed allocation cannot replace the same ID. This acknowledges quota storage
only. It does not install ownership metadata, freeze membership or acknowledge protection,
and is insufficient to make a delegation ready for dispatch.

The host consumes that admission durably before its first guest frame. Both boundaries
use `briqyard-api/execution-admission`; guest builds do not enable this feature.

| Boundary | Required evidence |
| --- | --- |
| Issuer | Exact signed allocations, authority identity and current issuer instance/epoch, complete operation debit vector |
| Host installation | Authenticated scoped installer, exact current host journal instance, acknowledged authority epoch, exact signed allocation vector |
| Host dispatch | Independently installed ownership snapshot, current allocation fence, live VMM incarnation, unchanged frozen resources, committed request, unused admission ID |

Synchronous execution consumes one `requests` and one `exec_calls` unit. The issuer and
host refuse missing, extra or differently sized debits. The entire vector is atomic.
Unused, failed, uncertain and completed admissions never refund capacity.
Other operation families have no dispatch implementation in this change.

### Persistence and recovery

Each private directory has one permanent 0600 lock inode held with a nonblocking OS lock.
The owner checks directory and lock identity before reads and writes. State is one bounded
JSON record: at most 16 MiB, 16,384 admissions, 16,384 allocations and 16,384 retired epochs.
Writes create a new 0600 file, fsync it, rename it, then fsync the containing directory.
Any uncertain write poisons the writer. It cannot issue or consume again.
A retained temporary file refuses startup; recovery never guesses which write committed.

Opening creates a fresh unpredictable service instance. Installed allocations are cleared.
Hosts retire every previously installed authority epoch, including across restart, and
refuse reinstallation of retired epochs. A fresh authority epoch needs fresh allocations;
old capacity remains charged until its original expiry. Epoch handover must receive every
old dispatch host's fencing acknowledgement, or wait for every old permit's expiry plus
clock uncertainty, before capacity can be reassigned. Installation is an administrative
trust boundary, not a public gateway operation.

The runtime run ID hashes actual host boot ID, VMM PID, kernel start ticks and the current
host journal instance. Even restoration of an older journal before an admission changes
this run ID. Old grants and permits cannot dispatch into the restored service instance.
The host requires positive live kernel incarnation evidence, including the current record's
incarnation. Logical machine IDs and persisted process IDs alone are insufficient.
The placement value is the machine record version. This conservatively invalidates access
on every version change, including namespace, ownership and lifecycle changes.

Reserved/consumed records are evidence, not instructions. A crash between consumption and
guest dispatch leaves an uncertain outcome. Recovery reads status and never launches it
again. Completion changes status only. Expired evidence can be pruned through the issuer
or host API without reopening; the persisted clock floor refuses rollback. Retired epochs
remain until journal replacement under a fully fenced new authority registration.

For uncertain storage or journal restoration: stop admission, retain both state files,
fence the old authority on all hosts or wait out all old permits, then establish fresh
service instances and authority registration through the trusted installer. Never refund
old allocations, resume an old instance, or replay a consumed command.

### Dispatch and deadlines

`Manager::scoped_exec` acquires the frozen local machines' lifecycle locks in machine-ID
order without waiting while holding a partial set. A busy member releases the partial set
before waiting, bounded by ten seconds. This avoids cycles with starts that hold their
machine while starting its gateway. It checks every actual run, namespace and placement, and independently binds the external
subject to the target's operator-owned `briq_id` metadata. The authenticated metadata
installer supplies team, resource and policy revisions; it must retain that revision fence
through initial dispatch. Submitted credentials cannot construct this snapshot.
Remote resource members are refused until distributed resource fencing exists.
All frozen resources remain in use while the command connection lives.

The host holds its journal fence through the initial guest write. Stop/move/restore use
the same lifecycle locks. After the write, explicit lifecycle operations may terminate an
accepted command; its receipt remains consumed regardless of the resulting connection error.

### Native idle protection before permit issuance

`Manager::protect_execution_resources` accepts the authenticated installer's exact
pre-grant request under all local resource lifecycle locks. It checks every current
VMM incarnation, namespace, placement and primary subject, then fsyncs one immutable receipt
containing the admission ID, ordered target vector and expiry in milliseconds. A
second call with the same ID must match exactly. The host rechecks every identity
before acknowledging. This receipt does not authorize dispatch or freeze membership.
Allocation installation remains a separate pre-permit step.
The host accepts at most 60 seconds from its current clock and at most five seconds of
declared uncertainty. A skewed deadline outside that bound is refused before ACK.

Receipts live outside machine records so assignment recovery and ownership transfer
cannot erase them. Startup reads the whole private collection with a bounded strict
inspection before network setup or ticks and derives each machine's maximum expiry.
Idle sleep uses the later of actual last use and that expiry, plus the sleep window;
it never changes actual use or the record version. Tick is preliminary: both ordinary
and assigned idle stops recheck under the lifecycle lock immediately before `stopping`.
The final admission predicate and state transition also share the record mutex with
activity registration. A command arriving after an earlier idle snapshot cannot be
stopped using that stale snapshot. A refused stop writes no stop intent or deadline.
Gateway idle stop checks the same bound. A protected deadline is released only when
the lower clock bound has passed it. Explicit stops still take precedence.

One receipt write makes multi-target protection atomic. Uncertain persistence gives
no acknowledgement and disables idle stops until a clean restart inspects disk state.
The strict inspection admits at most 4,096 receipt files and 32 MiB in all; reaching
that cap refuses new protection. Receipts are not pruned, since the expiry plus sleep
window can outlive the grant. Long-running service activation needs a safe retention
scheme and a release compatibility barrier: an older daemon that ignores this new
collection must not run accepted protected admissions.

### Namespace generation and mutation fencing

The host keeps namespace generations in a separate bounded durable record. Namespace
deletion does not erase a generation. The resource revision hashes a versioned domain,
the ordered namespace generation vector and the exact run targets sorted by host and
machine. Discovery durably seeds missing names; it establishes no protection. Protection
requires that exact revision, persists namespace deadlines before idle receipts, and
returns the revision in its acknowledgement. Dispatch checks the current revision and
coverage through the permit deadline before consuming its admission.

A mutation persists a unique pending ticket and advances every affected generation
before effects. Independent mutations may overlap; only an exact ticket can retire its
own evidence. Pending mutations refuse snapshot installation and dispatch. Broadening
is refused through the protected deadline plus five seconds of clock uncertainty.
Explicit revocation may proceed and retains the deadline. A failed or cancelled effect
retains its ticket across restart; recovery does not replay it or clear it on drop.
No fence mutex is held while waiting for lifecycle or network work.

Pure network revocation attempts durable invalidation first. A fence failure poisons
scoped admission before detachment, but does not skip detachment. Its actual network
result determines success and address retention. A failed post-detachment ticket write
also poisons admission without changing a successful network result. Reopening can read
a valid older record and clear in-memory poison; safety still requires fresh journal/run
identity, actual lifecycle reconciliation and the retained namespace deadlines.

The record admits at most 16,384 namespace names, 4,096 pending tickets and 4 MiB of
serialized state. Strict startup inspection refuses stray files, malformed records and
uncertain writes. Persisted clock observations refuse rollback beyond five seconds.
Successful effect completion retires only its ticket after the relevant network or
record publication has completed.
Namespaces never discovered for scoped access retain only pending generation-zero
tickets while their effects run. Once those tickets finish, ordinary namespace churn
uses no permanent generation capacity. First discovery seeds generation zero durably;
every later mutation advances it, and tracked names are never reset or evicted.

Current hooks cover machine creation and cold start, ordinary metadata and policy
updates, network attachment, clone network activation, namespace moves and renames,
gateway replacement, assigned ownership and live publication, policy replacement and
explicit network revocation. Composite tickets remain pending through durable record
publication, including directory synchronization, and network and DNS effects. Source
and destination namespaces share one ticket for ownership transfers.
Pending-ticket reconciliation, retention and a downgrade compatibility barrier remain
activation gates.
No public scoped route is enabled by these hooks.

The lifecycle contract retains namespace records as subnet reservations.
Machine and gateway teardown may proceed, but empty namespace network deletion is a
broadening operation: protection refuses it before DNS or bridge removal. Successful
teardown durably deletes the namespace record before releasing its in-memory reservation.
Namespace creation fences and durably reserves its namespace record before bridge/DNS
setup. Its ticket remains through map publication. Failed setup retains the durable
reservation across restart.

Startup drains the maximum retained protection deadline before backing recovery or
network reconstruction, while preserving native startup ownership, existing processes
and kernel topology. Validate the persisted clock floor, wait monotonically through the
deadline plus uncertainty, then recheck the wall-clock lower bound. Invalid state or an
insufficient bound refuses startup without reconstructing topology. Reconstruction
advances namespace generations before forwarding, bridges, DNS or rules change, and
retires its tickets after those effects complete. Deferred adoption is not failed
adoption. Ordinary adoption holds a composite ticket through durable publication;
a failed save aborts recovery while retaining process ownership and pending evidence.
Draining deadlines never clears pending tickets.

Request commitment v1 is SHA-256, unpadded base64url, over these bytes:

1. UTF-8 `briqyard-exec-request-v1` followed by one zero byte.
2. Argument count, then each argument as byte length followed by UTF-8 bytes.
3. Environment count, then key/value fields ordered by UTF-8 key bytes.
4. Working directory and stdin, each as a length-prefixed UTF-8 field.
5. Explicit nonzero timeout in milliseconds.

Counts, lengths and timeout are unsigned 64-bit big-endian integers. Wake must be false.
No default timeout or JSON member ordering can change the meaning of an accepted commitment.
The request timeout and stdin must fit the signed limits. Output counts stdout and stderr
together, including bytes beyond retained buffers; crossing the cap closes access.

An absolute wall deadline subtracts clock uncertainty, preserves fractional seconds and
maps once to monotonic time. The command boundary accepts at most 60 seconds of remaining
authority. Verification, hashing, lock waits and fsync never renew that deadline. The host
rechecks after consumption, and the actual guest connection checks expiry on every read
and write poll. Unsupported guest transports refuse scoped dispatch. Connection closure
bounds access; it does not prove cleanup of detached descendants or undo committed effects.

## Remaining activation gates

### Host-owned private resource closure

The host boundary uses one resolver for discovery, protection and dispatch.
Its independently installed scope contains a primary target and required public-runtime
seeds, separate from the submitted resource set. Discovery returns the canonical complete
closure; it grants no authority. Native gateways retain real runtime targets without
fabricated public identities. Remote seeds and a 65th resource refuse local admission.

Private edges require a shared namespace and both endpoints' installed bridge policies.
An endpoint permits its peer when it is not strict `Via`, enables siblings, or its exact
installed `to` and `to_tap` identify that peer. Apply this predicate at both endpoints,
then take transitive closure from the trusted seeds. `egress:none` still permits private
peers. Missing or unresolved installed policy never implies open access. This closure
covers managed private resources, not arbitrary public-URL reachability.

Snapshot namespace generations before enumeration. Acquire selected lifecycle turns,
validate kernel run identities and trusted seeds, recompute membership, then require the
same generations before returning a revision. Exclude stopped or quarantined entries only
with lifecycle/process evidence; uncertain publication or launch is a refusal, not absence.
Protection independently recomputes exact closure and checks identities and generations
again after durable idle receipt persistence. Dispatch repeats closure validation before
consuming admission: a namespace deadline alone cannot attest a caller's proposed subset.
Stopped entries require a settled launch, no live process or adoption, no pending launch
and no retained launch hold before exclusion. Running builders and inactive clones refuse
admission until positive kernel quarantine evidence is available; record metadata alone
does not establish absence. Unresolved same-namespace state conservatively refuses even
when the final reachable component might exclude that entry.

Six focused Mac tests cover the installed graph, transitive and bounded closure, uncertain
records, builder metadata, multiple local seed namespaces and retained launch identity/process
proof. Matching IDs never discharge a launch hold: the complete record identity must match,
and existing provenance/process verification must confirm the live launch. Enumeration clones
records before inspecting other entry mutexes, preserving persistence's removal/record lock order.
Daemon Clippy, formatting and diff checks pass. Static security review found no remaining
production-code issue after these fixes. The signed manager integration
case compiles on Mac but requires Linux to run; it checks native gateway inclusion and a
validly signed subset refused before consumption. Actual kernel/network and lifecycle race
qualification remains required before activation.

### Authenticated installation and qualification

The host now contains a dormant dedicated internal router. It is not merged with
the administrator router and has no listener or configuration rollout. Its
installer and execution credentials are mandatory, distinct and checked on every
route, including loopback. A future listener must provide authenticated pinned
transport and credential provisioning before mounting it.

The host journal retains registration high-water, ownership generations,
delegation tombstones, exact protection receipts and prepared admissions with
the existing fsync/rename/directory-sync write. A restart retires the old
authority epoch and removes registration readiness. The installer discovers
actual run targets from logical public seeds and validates host metadata
(`briq_id`, `team`, namespace and machine version). Ownership installation
rechecks the full closure. Every public member needs an explicit mapping;
an unmapped member is accepted only when it is the namespace's registered
native gateway. Replacement ownership requires explicit invalidation first.

Delegation installation checks the signed credentials against installed
ownership and the exact persisted millisecond protection receipt. The signed
whole-second deadline is the inward floor of that receipt. It installs no host
allocation and issues no permit. Prepare verifies the signed permit against the
active registered authority key, then installs its exact allocation vector and
persists the prepared request binding. Dispatch marks that binding spent before
calling the manager. Every uncertain retry is status-only. Invalidation holds
the exclusive admission guard; dispatch holds its read guard through the
manager's first guest write. Lock order is admission guard, lifecycle turns,
then journal. Handlers make no network calls while holding lifecycle turns or
the journal.

This is a disabled source candidate. The internal listener, fleet installation
authority, bounded clock qualification, retention and downgrade barriers, and
Linux lifecycle/partition/crash evidence remain activation gates. No public
scoped access is mounted.

The dormant fleet host transport captures a trusted registry destination and
requires its provisioned certificate pin over HTTPS. It disables redirects,
proxies and retries. Fixed internal routes select distinct installer or execution
credentials; neither may equal the host administrator credential. Requests and
responses share an 8 MiB wire bound with the host router. JSON can encode each
control byte as six bytes, so a 1 MiB logical input or output needs more than
6 MiB including its envelope. Admission must check the complete serialized
operation against the wire bound before debit. Any failed or malformed response is unconfirmed,
never permission to resend dispatch or choose another host. Typed replies still
require exact validation against durable installation intent before readiness.

No mounted HTTP route or configuration accepts these credentials yet. Administrator routes do not
call this boundary and keep their existing authentication and behavior.

Activation still requires authenticated ownership/metadata installation, host-instance and
allocation acknowledgement transport, authority registration/key provisioning, regional
routing, bounded clock monitoring and integrated lifecycle/partition/crash qualification.
The installer must fence membership/policy updates and acknowledge every old owner before
publishing replacement authority. A dedicated authenticated channel must enforce installer,
authority and gateway roles separately from administrator credentials, including on loopback.
Missing scoped credentials refuse access.

Membership protection must cover the complete reachable native resource set. Network attach,
clone publication, policy replacement, namespace/ownership moves, gateway replacement and
assignment publication must advance the trusted revision before their effects are visible.
Broadening membership or reachability remains blocked through the frozen command deadline;
invalidation of later dispatch alone cannot protect an already running command. Explicit
stop/removal may terminate work. Protection must survive journal reopening: a fresh journal
instance invalidates old credentials, but does not prove a previously accepted guest command
has stopped. These gates are not implemented by allocation installation. The end-to-end caller must recover uncertain receipts by
status without replay. Files, sessions, streams and multi-host frozen resources remain
unavailable through scoped access until their own commitments and fences are implemented.
