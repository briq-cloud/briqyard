# ADR 0019: Events, a watch and versions: what makes an imperative API safe to drive

Date: 2026-10-20 · Status: accepted

## Context

briqyard is imperative; briq's reconciler is the declarative layer above it (`../KUBERNETES-MAP.md`). A reconciler driving an imperative API needs three things Kubernetes gives its controllers: a version on each record so a write based on an old read is refused (`resourceVersion`, 409), a way to learn what changed without polling every record (watch), and a record of what happened and why (Events, `kubectl describe`). Today a reader polls `GET /v1/machines`, guesses why a machine is `stopped` from `stopped_reason`, and two writers race.

## Decisions

**One event log per host, append-only.** An event is `{ seq, at, type, reason, message, machine_id?, tenant?, host?, data? }`:

```json
{"seq": 812, "at": "2026-10-20T14:03:11.204Z", "type": "warning", "reason": "exited",
 "message": "exited with code 7", "machine_id": "m_3f9a01c2d4e5", "tenant": "t1",
 "data": {"code": 7, "oom": false, "restarting": true}}
```

`seq` counts from 1 on each host, one more per event, never reused: at start it goes on from the larger of the log's last event and the machines' records' versions (a record is written with its version, so a log lost or cut keeps it monotonic). `type` is `normal` or `warning`, as in Kubernetes. `message` is at most 1 KB. `host` is set by the fleet on fleet-wide reads only.

**The reasons are a closed list** (`briqyard_api::reason`):

| Reason | Type | When | `data` |
|---|---|---|---|
| `created` | normal | made from an image | `image`, `digest` |
| `forked` | normal | made from another machine's disks | `from` |
| `restored` | normal | made from a backup | `from`, `backup` |
| `starting` | normal | its memory reserved, a boot or a resume under way | `resume` |
| `started` | normal | a cold boot answered | `pid` |
| `resumed` | normal | a memory snapshot resumed | `pid` |
| `ready` | normal | defined for probes, not emitted yet | |
| `stopping` | normal | asked to stop (by a caller, the sleeper, the host) | `reason`, `suspend` |
| `stopped` | normal; warning for `host` at start | its process is gone; also a sleeping machine stopped on request | `reason` |
| `suspended` | normal | stopped with a memory snapshot | `reason` |
| `exited` | warning unless code 0 | its process ended on its own | `code`, `oom`, `restarting` |
| `restarting` | warning | the restart policy starts it again | `attempt`, `policy`, `delay_sec` |
| `boot_failed` | warning | the guest never came up or exited booting (ADR 0011); the console tail in `message` | |
| `start_failed` | warning | the host failed the start (network, disk, Firecracker): ADR 0011's 500 | |
| `updated` | normal | a PATCH changed its sleep or metadata, a PUT the gateway's spec | `fields` |
| `egress_changed` | normal | a PATCH changed its egress | `from`, `to` |
| `backed_up` | normal | a backup reached the store | `backup`, `bytes`, `incremental` |
| `destroyed` | normal | its record is gone | |
| `gateway_started` | normal | the tenant's gateway was started and its port answers | `port` |
| `gateway_stopped` | normal | the sleeper stopped the gateway: nothing sends through it | |
| `image_pulled` | normal | an image was pulled and built into a root disk | `image`, `digest`, `seconds` |
| `host_started` | normal | the daemon started | `version`, `machines`, `adopted`, `stopped`, `swept` |
| `adopted` | normal | a machine left running by a previous daemon was taken over | `pid` |

`updated` and `start_failed` are two more than the first list: without `updated` a PATCH of the sleep window would not move the version, and a host's fault is not the image's (`boot_failed`). `destroying` has no event: the destroy is one critical section and `destroyed` ends it.

**Emitted where the fact becomes true.** `Entry::set_state` is the one place a state changes; its closure, which edits the record, returns the event, so the state, the record and the event move under one lock. One exception: `starting` is logged just after its reservation, which holds the lock of every machine's map and must not wait for a disk. The rest at their single call sites: the create (`created`, `forked`, `restored`), the restart decision, the PATCH, the backup, the destroy, the gateway's start and sleep, the image builder, the daemon's start, the adoption.

**Kept on the host, appended and synced before anyone reads it.** `state/events/<hour>.ndjson`, one line per event, appended and `fdatasync`ed under the log's lock, then sent to watchers: a watcher never sees an event a crash could lose. A file is never appended to once a later hour has begun (a clock that steps back stays in the newest file), so files sort as their seqs do. A torn last line (a crash during a write) is cut at start. Retention: `events_keep_days` (7), and at most 100,000 events per host (whole hours go, oldest first); the newest file always stays, so the last seq is never lost. A busy host (200 machines, 50 wakes a day each, about 4 events a wake) writes 40,000 events a day at about 300 bytes: the cap holds 2.5 days of it, 30 MB. Kubernetes keeps one hour.

**A version on every machine.** `version` is the seq of the last event about the machine: every event about a machine moves it, its last use does not (a touch is not a change). `PATCH`, `DELETE` and the lifecycle POSTs (`start`, `stop`, `wake`) take `If-Match: <version>`; checked under the machine's lock, a version that moved answers 409 `conflict` with the machine as it is in `machine`. No header: as before. A PATCH that changes nothing is no event and keeps the version.

**Read from a cursor.** `GET /v1/events?since=&tenant=&machine=&type=&limit=` answers `{ events, next }`, oldest first, the events after `since` (absent or `0`: the oldest kept). `limit` is 500 by default, 5000 at most. `next` is the cursor to send back: the last event returned when the page is full, else the host's last seq, so a filtered reader never reads the same lines twice. A `since` whose next events are gone (pruned), or past the host's last seq (its state began again), answers 410 `gone` with `oldest`, the oldest seq kept: read again from there, as after Kubernetes's "too old resource version".

**Watch is the same read, kept open.** `?watch=true` answers `application/x-ndjson`: the events after `since`, then each new one as it is logged, one JSON line each. It subscribes before it reads the backlog and skips what it already sent, so nothing falls between. `{}` every 30 s keeps proxies from cutting it. Watchers share a `tokio::sync::broadcast` of 1,024 events fed after the event is synced; a watcher that falls further behind (it reads slower than the host logs) is closed with a last line `{"code": "lagged", …}` and watches again from the last seq it got; the daemon never waits for it. A daemon going down ends every watch with `{"code": "shutdown", …}`.

**Through the fleet.** Events are per host: seqs of two hosts do not compare. A read with `tenant` goes to the tenant's host, else one with `machine` to the machine's host (a destroyed machine is found through its tenant: `?tenant=…&machine=…`); its cursor is that host's seq, the host in `x-briqyard-host`, and a watch is streamed through. A read with neither asks every host and fails whole when one does not answer, as listings do (ADR 0006): events are merged by time, each with `host`, and the cursor is opaque, `<host>:<seq>,<host>:<seq>`. A fleet-wide watch answers 400: it would hold one stream per host and lose a host silently when one drops, which is a partial answer; a reader that wants everything watches each tenant, or polls the fleet-wide read.

## Consequences

- briq's reconciler can drop polling for change: a watch per host from its last cursor, `If-Match` on every write it bases on a read, and `describe` for a person debugging a briq.
- No global order across hosts; a fleet-wide cursor is a vector of host seqs.
- A machine's events are read by scanning the host's log (at most 100,000 lines); no index. Reopen with an index per machine if `describe` gets slow.
- One `fdatasync` per event; transitions already sync their record, so this doubles the syncs of a transition and adds none elsewhere.
- `image_pulled` is emitted by the image builder, which needs a registry: the unit tests do not cover it, a host does.
- Not built: events for endpoints and tenants, label selectors on events, a `ready` condition (probes, next).
