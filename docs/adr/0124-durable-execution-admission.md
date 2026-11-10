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

The host consumes that admission durably before its first execution frame. Both boundaries
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

The host holds its journal fence through the initial command write. Stop/move/restore use
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

Authority installation intents share the issuer's locked journal. Registration
and ownership become ready only after the exact host instance, generation and
record digest are acknowledged. Lost ACKs remain pending. Invalidation and
revocation persist their local fence before querying or mutating the host;
unreachable hosts leave propagation pending, without restoring local readiness.
Ownership retains its exact registration intent and generation dependency.
Beginning registration replacement makes old ownership unready, including when
the host instance stays the same. A new registration ACK never revives that
ownership; it must be independently installed under the new registration.

The dormant fleet installer now records authenticated logical ownership input
before discovery and records the exact typed host receipt before ownership.
It checks the full ordered resource vector, every public mapping and the host
instance; omitted public members refuse installation. Ownership readiness also
depends on that exact discovery intent and its current registration. After a
committed idle deadline is supplied, the installer records the ownership,
admission, full resource vector, revision and exact millisecond deadline before
calling host protection. Only a matching ordered ACK is ready. Pending calls
are never resent by this path. These steps use the issuer's existing exclusive
journal and do not create another authority ledger.

The dormant authority installer also persists each signed delegation request before its
one host call. Its authenticated input supplies principal, delegation ID and version,
ownership, and protection independently of the signed tokens. It verifies the central
grant and complete allocation vector against the current ready registration, exact
ownership and acknowledged millisecond protection receipt. The signed idle deadline
is the inward whole-second floor of that receipt and covers grant expiry. The complete
serialized host request fits the channel bound before persistence or transmission.
Only an exact typed host delegation receipt makes the intent ready. Lost or mismatched
ACKs stay pending; retries do not resend. Any retained delegation revocation, even
before host confirmation or at a lower version, refuses installation and readiness.
Restart rotates the issuer epoch and leaves old intents unready. This path installs no
host allocation, issues no permit and dispatches no command.

No mounted HTTP route or configuration accepts these credentials yet. Administrator routes do not
call this boundary and keep their existing authentication and behavior.

### Dormant regional synchronous execution

The regional coordinator accepts an operation ID, a current installed delegation intent ID and
a generic runtime `ExecRequest` from an authenticated control handler. The installed delegation
retains the independently authenticated source kind, ID and expiry. Its trusted principal, team,
subject, exact closure, metadata revision, ownership generation, host instance, authority epoch,
protection receipt and signed allocation digests construct the dispatch context. Source revocation
must be propagated as a retained delegation revoke before another operation can be admitted.
No public or administrator route invokes this coordinator.

The issuer's existing exclusive journal keeps each immutable operation ID bound to its delegation,
epoch, request commitment and destination before permit issuance. A retained ID always returns
status only; a changed request conflicts. The issuer verifies the full signed vector and checks
both complete serialized prepare and dispatch envelopes against the 8 MiB wire limit before debit
or permit release. The permit stays inside the issuer until quota reservation is durable. A crash
after intent persistence conservatively burns the operation ID, including before debit. There is
no resend, host fallback or permit regeneration.

An exact typed prepare ACK is durable before dispatch intent. Its request, permit and grant
digests, allocation references, ownership generation, host instance, admission and expiry must
match. Dispatch intent is durable before one host dispatch. The caller supplies a fresh qualified
clock at each security transition, including after network calls; the earlier clock estimate is
not reused as evidence of remaining authority. The positive request timeout fits both the signed
limit and remaining permit lifetime. Failed, missing or malformed replies are
unconfirmed; host status absence is never evidence of non-execution. A confirmed first result
must fit the permit's signed output mode and byte limit. It returns bounded guest output
transiently and persists only its outcome hash. An over-limit response is unconfirmed. Later
calls return status without guest output. This source candidate keeps scoped access dormant pending
the host lifecycle and Linux qualification gates below.

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

Permit envelope preflight receives an inert, equal-length signature placeholder.
The issuer retains the usable signature until the complete durable reservation
succeeds. Permit issue and not-before times use the qualified clock interval's
lower bound; verified grant and allocation lower bounds still apply.

### Dormant regional HTTP boundary

The fleet source now has an unmounted regional authority router. Construction receives one
live `DurableIssuer`, one fixed pinned host transport, distinct central-installer and
gateway-only bearers, trusted verification keys and an injectable qualified-clock source.
Neither role accepts the fleet or host administrator credential. Authentication applies on
loopback. The router has no listener, config field or production credential/clock provisioner.
Construction checks the fleet administrator against the fleet configuration and the host
identity and administrator against the fixed transport. Caller-supplied comparison values
alone do not establish credential separation.
A clock observation includes a monotonic expiry and maximum five-second uncertainty;
missing or expired evidence refuses mutation. Ordinary `SystemTime` is not a clock
qualifier. The issuer journal remains the single writer across all handlers; an async
turn serializes network calls and journal mutations without a synchronous mutex held
across awaits.

The wire prefix is `/internal/authority/v1/`. All endpoints are POST with an
`application/json` body bounded to 8 MiB; replies are JSON and errors contain no
request, token or destination text. The central-installer bearer alone accesses
`register`, `discover`, `ownership`, `protect`, `delegation`, `invalidate`, `revoke`
and `installation_status`. Their request DTOs contain an immutable intent `id` plus
the named typed control input; `delegation` has separate `control` and `signed`
objects. `installation_status` accepts `{kind,id}`. It returns `{state,evidence}`:
`unknown`, `pending` or `ready`, with typed host acknowledgement or receipt evidence.
Delegation evidence also includes its persisted projection, intent and authority epoch.
The gateway bearer alone accesses `projection`, `exec`, `operation_status`
and `observe`. `exec` accepts `{id,delegation_intent,grant,projection_digest,request}` and returns a first
`completed` response with status and bounded result, or `existing` with status only.
`operation_status` and `observe` accept `{id}` and return status evidence, never
replay permission. Request DTOs have no destination URL or caller-selected role.

### Immutable delegation projections and renewal

Authenticated delegation control installs an opaque projection with the grant intent,
before the host call. The envelope is `{version:1,bytes,digest}`: 1–4,096 decoded bytes
and a SHA-256 digest encoded as unpadded base64url. Recovery validates the bound and
digest before rotating the journal epoch. The runtime never interprets the bytes;
Debug output omits them. There is no separate projection update or listing endpoint.
Changed projection bytes under an existing intent conflict.

Gateway `projection` accepts `{delegation_intent,grant}` and returns only that installed
version's projection, grant digest, delegation, ownership generation and authority epoch.
It requires exact grant possession, current ready dependencies, an unrevoked delegation
and qualified clock coverage for grant, source and protection. Dispatch repeats those
checks under the issuer turn and requires the same projection digest before any admission.
A previous read cannot authorize a later command. No signed credentials or allocations
are returned by this read. Gateway `projection_lookup` accepts `{delegation,grant}`
and resolves exactly one retained intent by delegation and compact-token digest before
applying the same eligibility checks. Zero or multiple matches refuse; an ineligible
historical match never falls back to another version. Dispatch uses the returned exact
intent and projection digest without another lookup.

Authenticated control also installs an opaque `policy_revision` identifier. It is part
of immutable intent equality and must remain identical across renewal. Missing legacy
revisions fail readiness. The runtime records this snapshot; the control-plane caller
still owns policy authorization and revocation. Installer status returns stored policy,
registration, ownership and protection identities with the existing acknowledgement.

Renewal retains the delegation, principal, ownership and source identity and installs a
strictly higher version with a fresh grant, protection admission and projection. Starting
that immutable intent fences all older versions for new admission, even while its host
ACK is pending. Only the current acknowledged version is eligible; there is no fallback
to an older ready installation. Hosts retain immutable version records and reject changed
or lower versions. Host dispatch also requires the prepared grant digest to match
the current delegation. Revocation remains delegation-wide. Existing operations keep
their status and cannot be redispatched. Retained version records share the bounded journal;
exhaustion refuses admission rather than dropping rejection evidence.

The production provisioner for the regional listener, its two central credentials,
trusted keys, pinned host endpoint and qualified clock is still missing. This source
candidate does not activate scoped access or satisfy the native lifecycle, retention,
downgrade and Linux qualification gates above.

Installer-only `identity` accepts an empty object and returns the live authority
journal identity/epoch, fixed host identity and the current host journal instance
read over pinned installer transport. Every request reads the host again and
requires qualified clock evidence before and after that call. It changes no
registration, ownership or admission. This response is neither installation
readiness nor a trust bootstrap: authority verification keys and control generations
must still arrive through independent trusted provisioning. A host restart or
epoch change requires reconciliation and fencing before any installation is ready.

## Explicit listener activation candidate

The daemon and fleet now accept optional `execution` configuration. This supersedes
this ADR's earlier statements that listener provisioning is missing. Configuration
absence leaves the scoped router unmounted. Administrator routers remain separate.
Activation still requires independent security review and native qualification.

Each scoped listener requires explicit PEM certificate/key files and serves TLS,
including on loopback. It uses a dedicated port and the existing systemd listener
store and bounded shutdown. Both sockets are registered before unused sockets close.
The fleet captures one configured HTTPS execution endpoint for a registered host;
the registry's host identity, certificate pin and administrator token still govern it.
The ordinary host URL is unchanged. Redirects, proxies and dispatch retries stay off.

Credentials are a private JSON file read once at startup. Host installer, host
execution, central installer and gateway credentials must all differ, and each must
differ from both administrator credentials. Local administrator configuration and
registry state independently verify the two administrator comparisons. TLS, key and
credential reads have fixed byte bounds; symlinks and non-regular files refuse.
The fleet validates its PKCS8 signing key against the configured authority identity,
issuer, key ID and public key before mounting its listener.

Host services share a clock qualifier. Linux `adjtimex` with modes zero observes the
kernel clock without changing it. Non-TIME_OK, unsynchronised/error status, syscall
failure, invalid fractions, negative error values and arithmetic overflow refuse.
`maxerror` and `esterror` remain microseconds with `STA_NANO`; only offset and time
fraction change units. Error adds maximum error, absolute offset, estimated error,
monotonic syscall bracket, one second of freshness and outward quantization. The
existing five-second ceiling applies after whole-second rounding. Unsupported
systems have no production fallback. Every observation must remain consistent with
the first wall/monotonic anchor retained for the process lifetime. Accepted samples
never reset that anchor: repeated individually small steps cannot accumulate time
authority. Excess cumulative drift refuses until restart, whose retained-protection
drain still applies. Fresh observations guard admission, protection,
consumption, completion, protected broadening and the final idle stop decision.
Explicit revocation and removal use retained ordering evidence without granting time
based authority. Lost clock qualification cannot release retained protection.

A command maps the qualified wall/monotonic sample to its original deadline.
`MAX_COMMAND_SECONDS` (60) bounds both the host command deadline and protection
interval; a longer remaining permit refuses even if its signed limit is larger.
A refresh after durable consume may shorten that deadline; it never extends it.
Guest I/O refuses after clock loss or expiry. Recovery retains a full 60-second
monotonic maximum command lifetime before checking fresh qualified wall evidence.
Thus a wall forward step at restart cannot release topology while a previously
accepted bounded command retains access. This adds recovery latency after scoped
protection has been used, including when execution configuration is removed.

The existing permanent assignment floor gains schema 5, `scoped-execution-v1`.
Ordinary namespace generations and mutation tickets do not raise this floor.
Nonempty retained namespace protection or any idle-protection receipt reconstructs
it after marker loss, including when execution configuration is absent.
Previous readers reject this unknown schema instead of silently ignoring a separate
marker. The floor is fsynced before the first scoped listener journal or durable
protection/fence write. Surviving receipts or namespace fences reconstruct a missing
floor at Store open. Candidate probes, bootstrap replacement and automatic rollback
all require the exact new capability, even with empty sampled state or old config.
Removing configuration does not erase receipts, startup drains or compatibility.

The first finite activation retains journal admission receipts, installation and
operation intents, immutable versions, high-water marks and tombstones. No listener
runs pruning or journal replacement. Each journal is bounded to 16 MiB and 16,384
records per bounded collection; host idle protection retains 4,096 receipts / 32 MiB,
and namespace fences retain 16,384 namespaces / 4,096 pending tickets / 4 MiB.
Capacity refuses before acknowledgement or dispatch; uncertain failures do not
refund quota. Exhaustion needs explicit recovery design, not deletion of evidence.

Remaining native proof: real guest dispatch through both authenticated TLS listeners;
closure changes racing accepted commands; clock loss/steps with adopted guests;
partition and process crash at every durable boundary; handover of both listeners;
and downgrade/old-configuration rollback against the exact candidate binaries.
Mac unit checks or a mock guest do not qualify these paths.

## Standalone authority process

`briqyard-fleet --config <file> authority` branches before normal fleet configuration,
registry state, AppState construction or background tasks. Its separate strict
configuration requires `execution`, `host_tls_fingerprint`,
`host_administrator_file` and `fleet_administrator_file`. No fields have defaults.
Fleet management, registry, placement, bootstrap, backup, administrator listener
and metrics fields are rejected. The configured file must already exist.

The process holds one immutable trusted host identity, configured execution URL,
certificate pin and independently read administrator references. Host transport
uses the same narrow identity input when the normal fleet derives it from its
registry. No synthetic registry or administrator config is constructed. The shared
service, installer, coordinator, issuer and journal remain the only execution path.
The sole listener uses explicit TLS, systemd socket retention and bounded shutdown.
No administrator routes, polling, management tasks, fallback or replay are started.
Never share live registry or journal files between writers.

Administrator references are distinct private files containing exact raw ASCII
bearers without whitespace or a trailing newline. Both must match the credential
bundle's administrator comparisons before a journal opens. Reads have a 4 KiB bound,
require current ownership and private regular files, and reject symlinks.

Installer admission methods accept a fresh qualified-clock callback. They sample
before intent persistence, after host-instance waits, before transmitting persisted
work, before host acknowledgement persistence and after its fsync. Clock loss after
a host call leaves the immutable intent pending. Clock loss after ACK fsync retains
the ACK and adds a permanent uncertain-installation refusal before reporting failure.
Readiness and all dependent installations then remain false; a recovered clock never
makes that ID resend or ready. These refusal keys share the existing journal's
16 MiB bound and a 16,384-key ceiling. A refusal write failure poisons the live journal;
a restart rotates its epoch and cannot revive old readiness. Installation status
requires fresh qualification before advertising ready. Explicit invalidation and
revocation retain their clock-independent ordering path.

Every qualified wall interval is translated to one process-lifetime monotonic origin.
The retained intersection of all accepted intervals may narrow but never widen or
reset after clock loss. Overlap with the first sample alone is insufficient: two
later samples could occupy opposite sides and release protection before a retained
command timer expires. A contradictory sample refuses qualification without changing
the retained evidence. Restart still requires the full monotonic command drain.

The standalone mode and clock callbacks remain candidates until independent review
and native qualification. They do not supply real-guest, closure-race, partition,
crash or clock-step evidence for the authenticated end-to-end execution path.

## Synchronous output capture

The optional signed `limits.output_mode` accepts only `capture_per_stream_v1`.
Omission preserves the original wire bytes and combined raw-output exhaustion rule.
Permit attenuation requires identical output modes and nonincreasing limits.
In capture mode `max_output_bytes` is a positive raw-byte retention cap per stream,
at most 4 MiB. The host retains each stream's first bytes, then drains all later
frames until terminal exit under the same expiring connection and absolute deadline.
Exhausting retention alone is neither success nor failure; EOF, guest error or
authorization expiry before exit still leaves an unresolved operation.
The four-field execution result is unchanged; lossy UTF-8 conversion happens after
raw capture. The authority bounds each decoded UTF-8 stream to three times its
signed raw cap. Legacy replies keep their combined decoded-byte validation.

Host dispatch replies alone have a 64 MiB JSON transport bound. Two 4 MiB streams
fit even when each control byte expands to six JSON bytes; lossy UTF-8 expands each
invalid byte to at most three. Requests, installation, metadata and status replies
keep their 8 MiB bounds. This changes no activation or qualification gate.

The native channel fixture records its protection deadline before installation and
waits for the qualified lower clock bound, including the mutation uncertainty
margin, before namespace teardown. Successful guest completion does not release
topology protection early. Cleanup remains bounded and emits fixed stage failures.

## Dormant renewable operation primitives

`limits.execution_mode` optionally names `renewable_exec_v1`. Omission preserves
legacy signed bytes and deadlines. Null and unknown modes refuse. Execution and
output modes attenuate independently and must each match the grant; every numeric
limit is nonincreasing. Renewable guest duration is at most 60 seconds. The existing
issuer explicitly refuses this mode. Host support below is available only through
the authenticated internal channel; fleet issuance remains disabled.

The new central-signed token type is `briqyard-execution-continuation+jwt`, with the
existing Ed25519 header, key roles, token bound and strict decoding. Its claims are:

| Field | Binding or bound |
| --- | --- |
| `v, iss, aud, iat, nbf, exp` | Existing version, issuer, audience and qualified interval rules |
| `checked_at` | Independent source/session authorization; no later than `iat`; `exp <= checked_at + 60` |
| `previous_sequence, sequence` | Exact retained sequence and its successor; safe integers |
| `binding` | Exact immutable active operation identity below |
| `protection` | Exact `InstalledProtection` ACK already persisted by this host; same ownership generation, resource vector and revision; coverage through `exp` |

`ActiveOperationBinding` contains `operation_id`, `admission`, original
`grant_digest`, `permit_digest`, `request_digest`, `authority`, `authority_epoch`,
`host_instance`, `ownership`, `ownership_generation`, `policy_revision`,
`delegation`, `delegation_version`, `principal`, `source`, `team`, `subject`,
`metadata_revision`, `target`, `resource_set`, `limits`, `guest_timeout_ms`,
`started_at_ms` and `operation_deadline_ms`. It binds the exact run and frozen
resource closure. The source's absolute expiry also bounds every lease.
The guest timeout remains positive and at most 60,000 ms. The immutable operation
envelope is at most 80,000 ms from consumption: ten seconds for dispatch, sixty for
the guest and ten for terminal I/O. This envelope is not an authorization lease.
Continuation cannot change it or extend execution by restarting either timer.

The host journal records a consumed operation only after its exact admission was
consumed and its initial dispatch was marked. A separate trusted first-frame ACK
changes it to active. Neither unused reservations nor status polling establish
activity. Only active operations accept continuation, before the old lease's upper
clock bound expires, with a strictly higher expiry and exact next sequence. The
source check time cannot regress. The complete protection ACK must already exist
before the new sequence and expiry are fsynced. No allocation is read or debited;
quota-window expiry does not itself end a consumed operation's authorization lease.

Completion, delegation revocation and ownership invalidation serialize with lease
updates in the same journal. Terminal evidence never becomes active again. Reopen
marks all previously consumed/active records recovered, regardless of wall time;
there is no command replay or lease recovery. Active-operation evidence and its
admission survive pruning of expired permits. The existing 16 MiB / 16,384-record
bounds apply; exhaustion refuses instead of deleting rejection evidence.

`guestc::active_lease` is a separate live guard. It accepts only active
committed evidence and applies the exact next fsynced ACK before extending a timer.
Its immutable monotonic operation deadline never moves. A new ACK must arrive
before the old wall and monotonic deadlines; expiry, revocation, completion,
cancellation and clock loss cannot resume work. An independent timer and registered
notification wake quiet guest I/O at lease expiry or revocation. Fresh qualification guards each poll and terminal result. The guarded future
is created once and never replayed across updates.

## Host renewable execution

The installer installs an immutable `HostOperationPolicy` at
`POST /internal/execution/v1/policy`: `host_instance`, `ownership`,
`ownership_generation`, `delegation`, `delegation_version`, `grant_digest` and
`policy_revision`. It binds policy identity to the exact installed grant. A
changed record for the same grant refuses. Preparation and dispatch require it.

`POST /internal/execution/v1/continue` requires installer credentials and
`{admission, continuation}`. The host requires exact live evidence before verifying
the central signature. Under the admission write guard it fsyncs the new sequence
and already-installed protection, then applies that evidence to the live timer.
Only a fresh successful observation after application returns an active ACK. A
commit crossing the old lease's expiry ends the operation instead of resuming it.

`POST /internal/execution/v1/active` requires execution credentials and
`{admission}`. Both endpoints return
`{state, observed_at: {now, uncertainty}, evidence}`; state is `active`, `terminal`
or `unknown`. `observed_at` is a fresh qualified host clock interval. The evidence's
`checked_at` remains the last signed source authorization. Polling does not advance
it or the sequence. Durable active records without a matching live owner become
unresolved terminal evidence. A retained owner awaiting completion fsync remains
distinct from abandoned ownership, even after its terminal frame ends the timer.
No status path creates or reconnects a guest session.

The new guest operation `exec_renewable_v1` validates a positive timeout of at most
60,000 ms and emits an exact `accepted` frame only after successful process spawn.
The guest timeout starts before spawn. The host retains its initial admission,
ownership, lifecycle and lease fences through that ACK and the active journal
fsync. Activation retains the original monotonic admission deadline and the
consumption-time monotonic operation cap; a newer wall sample cannot reconstruct
elapsed authority. It then publishes the exact live lease and releases the admission read
guard, allowing continuation and revocation while output is collected. Legacy
operations keep their existing operation, fixed deadline and lock scope.

Guest upgrades do not replace an init already running in an adopted microVM.
A `pong` therefore advertises `exec_renewable_v1` explicitly, defaulting to false
when omitted. Streaming support or a daemon version is insufficient. The trusted
installer's discovery control accepts `require_renewable` (default false) and
retains it in the immutable discovery intent and host request. Renewable callers
must request it before reserving execution capacity. Under the resource lifecycle
locks, discovery checks only the primary's live capability; dependencies need no
renewable protocol. Legacy discovery and fixed-deadline execution remain available.
Renewable dispatch repeats the bounded read-only ping under the exact run's
lifecycle fence before admission consumption or command creation. Neither check
holds the journal mutex across guest I/O; both revalidate run and journal identity
before using the result. No compatibility probe starts a command.

A live owner exists only for that one connected execution. Every I/O poll checks a
fresh qualified clock; a separate timer and notification interrupt quiet I/O.
Revocation, ownership invalidation and authority changes persist terminal state
and end the matching live lease before control ACK. Dropping the execution ends
and removes its live owner. Recovery retains terminal evidence without replay.
Dispatch is bounded to ten seconds; guest timeout remains independent; terminal
collection has ten additional seconds, all within the immutable 80-second envelope.

Before renewable consumption, the original idle-protection receipt gains
`operation_envelope_ms: 80000`. Its strict schema and reconstructible assignment
requirement `scoped-execution-v2` / schema 6 prevent an older runtime from accepting
the store. Startup drains the full 80 seconds and still requires qualified wall
clock proof before protected guests can resume. Legacy receipts retain schema 5
and their existing 60-second drain. Stamped receipts retain the stronger barrier.

## Fleet operation continuation

The authority installs and retains the exact host policy ACK before a renewable
delegation becomes ready. It preserves signed execution mode and numeric limits.
A named renewable issuer entry point supports the integrated coordinator; the
legacy issuer entry point continues to refuse renewable permits.

The authority fsyncs one-shot dispatch intent before returning an immutable
in-memory dispatch owner. It releases the sole issuer journal turn only around
that one host dispatch, and reacquires it for the terminal digest. Status may record
consumption concurrently. Duplicate IDs and restart recovery are status-only;
no path reconstructs dispatch from a durable intent. A cancelled owner disappears
from the live registry and cannot request continuation.

Installer-only authority routes use one independently provisioned, pinned host:

| Action | Request | Successful reply |
| --- | --- | --- |
| `operation_active` | `{id}` | Fresh host `ActiveStatus` for the exact saved operation |
| `operation_protect` | `{id, operation_id, previous_sequence, committed: {admission, expires_at_ms}}` | Full exact `ProtectionAck` |
| `operation_continue` | `{id, operation_id, previous_sequence, continuation}` | Fresh host `ActiveStatus` after exact signed timer application |

Protection attempts bind immutable operation identity, sequence and exact committed
protection deadline. Existing matching protection is inspected without reissuing an
uncertain installation. Its reservation may conservatively outlast the operation;
only signed lease expiry authorizes execution and it remains bounded by the
immutable operation deadline. New protection uses a separate typed intent key.
The continuation token digest is fsynced before its sole delivery. A duplicate is
status-only; changed attempts or tokens refuse. A lost ACK never licenses redelivery,
a new grant, delegation renewal or another quota debit.

An optional provisioned `ContinuationProvider` requests fresh central authorization
for a live renewable command when its lease has at most twenty seconds remaining.
Commands expected to finish within initial admission do not arm this driver. Each
observed sequence permits one callback attempt. No issuer turn is held across the
callback, which may re-enter the three authority routes. Failure retains the
original lease and never replays the callback or command.

The fixed HTTPS provider uses `execution.continuation: {url, credential_file}`.
The URL has a non-root path, no userinfo, query or fragment. The private credential
is separate from the bundle and all six existing credential values. There are no
redirects, proxies or retries. Request and response are bounded to 4 KiB and the
whole request to ten seconds. It posts `{operation_id, previous_sequence}` and
accepts only `{state: "continued" | "recovered" | "not-needed"}`. Source checks,
committed idle authorization and central signing remain the callback service's
responsibility; unsigned callback success itself never extends a host timer.

Provisioning defaults to no callback and refuses renewable issuance in that state.
The production constructor negotiates renewal only with an explicitly configured,
validated callback. Deployment requires independent review, Linux lifecycle/crash/clock
qualification, compatibility evidence and CI. Mac checks do not supply native evidence.


## Activation observation and authorization clocks

The continuation driver may run before its sole dispatch RPC reaches the host.
It waits only for authenticated active evidence, bounded by the original signed
expiry and ten-second dispatch budget. Unknown observation never authorizes a
callback or a new dispatch. Terminal evidence ends the wait. Host active status
takes the admission write turn so it cannot reconcile the consumed record while
initial acceptance and durable active publication still hold the read turn.

Installer `POST /internal/authority/v1/authorization_clock` accepts only `{}` and
returns `{authority:{now,uncertainty},host:{now,uncertainty}}`. The host sample uses
installer `GET /internal/execution/v1/clock` on the same pinned dedicated transport.
Both are qualified clock observations, independent of source authorization and
renewable capability. Neither reads or changes a journal. Missing or stale local
clock qualification refuses the request. A signer may conservatively use these
lower bounds; observation alone never extends signed authorization freshness.

The existing disposable native proof uses the production Service constructor with
an explicitly injected callback. It covers central callback reentry, exact host
protection and continuation ACK, a quiet
60-second guest timeout across the original quota window, one-unit quota budgets,
status-only duplicates, source refusal/lease expiry and active revocation. It also
runs the monotonic activation and completion-owner regressions. There is no separate
test-only capability override. A compiled fixture or Mac checks do not satisfy native
qualification; deployment with renewal requires separately reviewed native evidence.

The native fixture requests at most 60 seconds of protection per initial or
continuation admission, matching the production installer. Longer commands renew
that bounded protection; the fixture does not bypass the installer with a single
120-second receipt. Renewable discovery also requests the live guest capability.
