# ADR 0023: Scheduled backups and retention, run by the host

Date: 2026-10-21 · Status: accepted

## Context

Backups (ADR 0008) are made on request only, and nothing is ever deleted from the store. briq's current provider gives every volume a daily snapshot kept 5 days (`../ROLLOVER.md` item 2). On Kubernetes this is Velero's job; here the host owns the disks, so the host runs it (`../KUBERNETES-MAP.md`: the daemon runs scheduled backups from a policy briq sets). And a destroyed machine's backups stay in the store with no usage bucket after its last hour (ADR 0017).

## Decisions

**A policy per machine: `backup: { "every": "6h", "keep": 4 }`.** `every` is a duration (`30m`… `7d`, at least `1h`: below that, an incremental of a busy database can outlast its period), `keep` at least 1. Set on create (absent: the host's `backup.default_every` and `backup.default_keep`, none by default; `null`: none) and by PATCH (`null` removes it). The view shows `backup`, `last_backup_at` and `next_backup_at`. A restore or a fork takes the request's policy, not its source's.

**The daemon's tick starts what is due, detached.** A machine's next backup is `every` after its last one (or after its creation, or after the PATCH that set the policy), and 15 minutes after one that failed. The tick starts each due machine's backup and goes on; `backup.at_once` (2) run at once (a semaphore). A machine has one backup at a time, the API's included: every backup takes the machine's turn, and the tick skips a machine whose turn is held. Nothing needs the control plane.

| Case | What the tick does |
|---|---|
| running (or starting, stopping) | a backup, crash-consistent |
| no process (`stopped`, `created`, `error`), each disk's `written@bk-<last>` is 0 | nothing: next time is `every` from now |
| no process, a disk written, or no snapshot of its last backup on the host | a backup |
| a backup that fails | `backup_failed` (warning, the error), next time in 15 minutes |

**Every `keep`-th backup is whole; retention keeps the newest `keep` and what they continue from.** An incremental restores only with its chain back to a whole stream, and the store cannot merge streams. Keeping exactly `keep` restorable points with incrementals is impossible: the oldest kept would have to be whole after every backup, so every backup would be. So a backup is sent whole when the chain since the last whole one has `keep` backups, and after each backup every backup that is neither among the newest `keep` nor the base of one of them is deleted. Whole chains go: the store holds between `keep` and `2·keep − 1` backups, every one restorable.

| keep 2 | sent | in the store after it |
|---|---|---|
| 1 | whole | 1 |
| 2 | from 1 | 1 2 |
| 3 | whole | 1 2 3 (2 is kept and needs 1) |
| 4 | from 3 | 3 4 |

Every backup whole costs `keep` whole streams; rebasing when a prune would break a chain needs the same decision at prune time and a second path. A base must also be a backup of this machine in the store: a restored machine's received snapshots, or a newest backup deleted by hand, start a whole one.

**Delete: `DELETE /v1/machines/{id}/backups/{backup}`.** Refused 409 `conflict` while another backup continues from it, naming them; `?chain=true` deletes it and every backup that continues from it. Streams go first, then the records: an interrupted delete leaves a record whose streams are gone, never an object no record names, and the next delete or prune removes it. Every deletion is a `backup_deleted` event with `backups` and `reason`: `retention`, `request` or `expired`. Ids are timestamps to the millisecond (`20261021T101500.123Z`): the API can make two in a second.

**A destroy keeps the machine's backups; a holder keeps them visible, counted and finite.** Restoring a destroyed machine is the point of a backup. The destroy writes `state/holders/<id>.json` (tenant, name, metadata, size, `destroyed_at`, bytes). `GET /v1/backups?tenant=` lists the backups of the host's machines and holders, a destroyed machine's with `deletes_at`; the fleet asks the tenant's host, or every host, never partial. `backup.keep_destroyed_days` (30) after the destroy, the backups are deleted, then the holder.

**A holder's usage goes on in the machine's own buckets, `backup_gb_hours` only.** No role and no flag: a bucket is one machine and one hour (ADR 0017), and the hour of the destroy holds both its last running seconds and its backups, so a marker would be wrong there. briq knows which briqs are gone.

## Consequences

- briq sets the policy per plan at create: today's daily snapshots kept 5 days are `{ every: "1d", keep: 5 }`, at most 9 backups in the store, 2 of them whole.
- No time of day and no cron: the schedule drifts by a tick (15 s) and by the backup's length. A daemon down skips nothing for good: what fell due runs at its first tick.
- A backup lists the machine's records in the store and reads each: `2·keep` requests at most, beside the streams.
- Holders live on the host, like the usage hours: `host retire` takes them, and the store objects stay, unlisted. Backups of machines destroyed before this change have no holder.
- Not built: a run against a real bucket (ADR 0008's); a backup of a tenant's gateway (it keeps no state).
