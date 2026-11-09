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

No HTTP route or configuration accepts these credentials yet. Administrator routes do not
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
