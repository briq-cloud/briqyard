# ADR 0103: Restore qualification with real workloads

2026-11-04 · Status: candidate; extends ADRs 0008, 0023, 0031, 0092, 0095 and 0100

`hack/restore-qualify.py` runs through the daemon or fleet API in fresh namespaces.
Stock Postgres 17 and Python 3.12 images are pinned by manifest digest. The host's
configured mirror handles pulls. No init change or custom guest image is needed.

| Check | Evidence required |
|---|---|
| Postgres under writes | External JSONL acknowledgements; backup while writes continue; automatic recovery, contiguous ids, exact payloads, every pre-request acknowledgement; `fsync` and `synchronous_commit` on; retained verbose `pg_amcheck` output |
| Closed, unsynced files | Host manifest of 256 files across root and data; frozen backup restores every hash |
| Startup bytecode | Copy during Python imports; restored boot imports all modules and emits readiness without a traceback |
| Two disks | Three samples after writer warmup and progress; atomic epoch/complement records replaced root then data; both disks recorded, both epochs at least the pre-request floor, `0 <= root - data <= 1` |
| Chain | Full and two linked incrementals; restore newest and first; middle deletion refused with `409 conflict` |
| Off-host | Distinct fleet regions and verified host ids; destroy source machine, restore from backup-store objects on the second host, never copied datasets |
| Interrupted backup | Explicit opt-in, disposable native runner only; 300 MB of new data, observe stream bytes, pause exact sender, kill daemon and sender, failed client; API absence, marker/object/upload/snapshot observations, last complete and fresh post-recovery backups restore |

`filesystem` promises filesystem consistency, not application-level atomicity across
files or disks. Pre-request durable database commits and closed files are required.
Later acknowledged commits may be absent. Each database restore reports their count,
lost ids, their acknowledgement time span, and the time from request to final ack.
An empty lost-id list means zero observed loss, not a zero RPO guarantee.
`filesystem`, suspended `synced`, and explicit `unsynced` are asserted literally.
The unsynced positive control must demonstrate missing bytes after a successful read;
no loss in four trials is inconclusive and fails, not evidence of safety.
It uses a disk fork with explicit `unsynced`, not a backup upload.

Each execution is a single run. `--rounds` defaults to one; CI selects three
independent Postgres machines, ledgers and full-plus-two-incremental chains.
Each backup samples one snapshot instant; rounds and the three two-disk samples
increase coverage without proving every interleaving or failure time. The two-disk
bound detects skew exceeding one ordered update and torn per-file records. It
does not establish an application transaction or prove nanosecond simultaneity.

Exit 0 requires the base workload checks and every selected check, in every
Postgres round, plus cleanup. `--require offhost,failure` adds explicit gates;
a missing, failed or skipped required check fails. Destination placement selects
off-host; daemon-kill mode without a destination selects interruption. CI also
requires `offhost` in two-hosts and `failure` in restore, so losing a mode flag
cannot silently omit that evidence.

Native CI adds `restore` to the parallel suites and runs the off-host case in `two-hosts`.
After the existing two-host suites, the fixture configures the source with
`storage.key: fleet`, as on a normally bootstrapped fleet host. It copies only this
run's backup objects into the second directory store, destroys the source machine,
stops its daemon and waits for the fleet to mark that host down. The restore must
then use only store objects and the fleet-held key. "Source offline" means a
stopped daemon: its pool stays up on the same runner/VM. It is not physical host
or disk loss. The destination shares the registry mirror; an absent image cache
is not proven. The fixture restarts the source in a `finally` block for cleanup.
This tests raw encrypted stream receive and key lookup without the source API,
but not S3 transport. Every restore reports time to first query and seconds per GiB of the
entire restored stream chain, with no performance threshold. These are compressed
stream bytes, not allocated disk capacity. JSONL and workload logs are artifacts.

The script never retries a mutation after a timeout. Cleanup checks generated names
and metadata, lists exact namespaces and removes only its own machines and backups.
Requests, boots, probes and external commands have bounds. Default mode changes no
host configuration, restarts no daemon and needs no root. A defect fails the run;
this qualification does not repair it or relax its oracle.

The failure check uses a pidfd for the observed daemon child, scoped to this
machine's data snapshot. It requires stream bytes before pausing. After killing
the daemon it kills that sender and waits for automatic recovery. ADR 0102's
leftover-helper barrier is never bypassed, reset or cleared by the harness.
The interrupted id's listing result comes from the API, never a literal claim.
Before killing and after recovery, it records published `.zfs` objects, temporary
`.zfs#…` uploads, the durable marker and the exact `bk-` snapshots. ADR 0100's
marker must settle and remove published orphan streams. Temporary uploads and
local snapshots may remain by that ADR's contract; the harness reports them,
then commits a new ledger row, backs up and restores again. A retained interrupted
snapshot must not become the new backup's incremental base. Another observation
records snapshot pruning after that backup. Cleanup removes only exact temporary
upload files observed in this run's own interrupted attempt.

Not proven here: real disk sizes, physical disk failures, real object-store latency,
real-host restore times or production capacity. Run against the real backup store
and two actual hosts to collect those measurements. Native results are required
before accepting this candidate; dispatching a run is not passing qualification.

## Postgres initialization readiness

The first candidate failed before any backup: the official image's temporary init
server answered a socket query, then shut down before the schema write. A single
`SELECT 1` was not final-server readiness. The bounded probe now requires
`pg_isready` and a socket query with nonempty `listen_addresses` (the pinned
image's temporary server sets it empty) and `pg_is_in_recovery()` false. The same
probe gates restored queries. It retries reads only, never schema writes or commits.
Timeout identifies the final-server requirement, socket and last probe result.
