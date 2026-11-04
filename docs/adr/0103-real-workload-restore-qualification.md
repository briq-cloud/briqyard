# ADR 0103: Restore qualification with real workloads

2026-11-04 · Status: candidate; extends ADRs 0008, 0023, 0031, 0092, 0095 and 0100

`hack/restore-qualify.py` runs through the daemon or fleet API in fresh namespaces.
Stock Postgres 17 and Python 3.12 images are pinned by manifest digest. The host's
configured mirror handles pulls. No init change or custom guest image is needed.

| Check | Evidence required |
|---|---|
| Postgres under writes | External JSONL acknowledgements; backup while writes continue; automatic recovery, ordered contiguous rows, every pre-request acknowledgement, `pg_amcheck` |
| Closed, unsynced files | Host manifest of 256 files across root and data; frozen backup restores every hash |
| Startup bytecode | Copy during Python imports; restored boot imports all modules and emits readiness without a traceback |
| Two disks | Both disks recorded; a concurrent ordered root/data writer restores a legal pair (equal or root one ahead) |
| Chain | Full and two linked incrementals; restore newest and first; middle deletion refused with `409 conflict` |
| Off-host | Distinct fleet regions and verified host ids; restore from backup-store objects on the second host, never copied datasets |
| Interrupted backup | Explicit opt-in, disposable native runner only; pause this machine's sender, kill daemon, failed client, unchanged listing, last complete backup restores |

`filesystem` promises filesystem consistency, not application-level atomicity across
files or disks. Pre-request durable database commits and closed files are required.
Later acknowledged commits may be absent. Each database restore reports their count,
lost ids, their acknowledgement time span, and the time from request to final ack.
An empty lost-id list means zero observed loss, not a zero RPO guarantee.
`filesystem`, suspended `synced`, and explicit `unsynced` are asserted literally.
The unsynced positive control must demonstrate missing bytes after a successful read;
no loss in four trials is inconclusive and fails, not evidence of safety.

Native CI adds `restore` to the parallel suites and runs the off-host case in `two-hosts`.
That fixture copies only this run's backup objects into the second directory store;
it tests raw encrypted stream receive and key lookup, not S3 transport or source-host
unavailability. Every restore reports time to first query and seconds per GiB of the
entire restored stream chain, with no performance threshold. These are compressed
stream bytes, not allocated disk capacity. JSONL and workload logs are artifacts.

The script never retries a mutation after a timeout. Cleanup checks generated names
and metadata, lists exact namespaces and removes only its own machines and backups.
Requests, boots, probes and external commands have bounds. Default mode changes no
host configuration, restarts no daemon and needs no root. A defect fails the run;
this qualification does not repair it or relax its oracle.

Not proven here: real disk sizes, physical disk failures, real object-store latency,
real-host restore times or production capacity. Run against the real backup store
and two actual hosts to collect those measurements. Native results are required
before accepting this candidate; dispatching a run is not passing qualification.
