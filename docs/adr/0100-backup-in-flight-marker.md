# ADR 0100: A backup in flight is written down, and a stream with no record goes at the next start

2026-11-04 · Status: accepted; extends ADR 0008 and ADR 0083

## Context

A backup sends each disk's stream to the store, then writes the backup's record
(`backups/<machine>/<id>.json`). The listing, a restore and a deletion read records, so a
stream with no record is reachable by nothing. A daemon killed between the first stream and the
record leaves exactly that. The qualification batch (ADR 0095) hit it in 2 of 3 runs: a `kill -9`
of the daemon during a backup, the stream left in the store, never listed, never removed, not
even by the next backup. The census (ADR 0083) counts it as unreferenced and, by design, never
acts. A failed backup in a living daemon already takes its streams back (`take_back`).

## Decisions

**The attempt is written down before the first byte.** `send_backup` writes a marker to the
local store (`backup-attempts/<machine>.<id>.json`: the machine, the backup id, the disks whose
streams it will send) with a durable write, after the snapshot and before the first stream. A
marker that cannot be written fails the backup, which takes its snapshot back: no stream is ever
sent that nothing remembers.

**The marker ends in two places.** After the record is written, and after `take_back` removed
every stream of a failed attempt. A failed delete keeps it. The marker's absence says nothing
else: only its presence acts.

**At the next start, a marker whose listing shows no record gives its streams away.** "No record" is read from a listing of `backups/<machine>/`, never from a GET: the object store reports "not found" for an absent object and also for a 404 from a missing bucket or a degraded S3-compatible node, and a false "no record" after a crash between the record and the end of the marker would delete a whole backup. Only a listing that answers, shows the streams and shows no record deletes. A listing that comes back falsely empty deletes nothing: the orphan stays, as before this ADR. The markers a previous
process left are read when the daemon starts, before this process writes one, and settled in a
detached task (the store is asked off the start's path). For each:

| Marker | Record in the store | Done |
|---|---|---|
| names of ours | listed | the backup is whole: the marker ends, nothing else |
| names of ours | not listed, streams listed | those streams go, then the marker |
| names of ours | not listed, no stream listed | nothing to remove: the marker ends |
| names of ours | listing failed | everything stays, tried again at the next start |
| a stream delete fails | absent | the marker stays |
| names that are not ours | | the marker stays, nothing is deleted |

Names are ours when the machine id is valid, the backup id has the shape `send_backup` makes
(`%Y%m%dT%H%M%S%.3fZ`), and every disk is `root` or `data`. The keys are rebuilt from those
fields, never taken from the marker. A crash between the record write and the end of the marker
keeps the backup: the record is there.

**Why no second daemon can be mid-backup.** A marker found at start belongs to a process that is
gone: the new daemon holds the host's exclusive domain lock (ADR 0068), which the old one holds
until it exits. A hand-over starts the next daemon after the old one ended.

**What this does not do.** Objects with no marker are not touched: a stream from a daemon that
predates the marker, or written by another host, stays unlisted as before; a global sweep of the
store is not proven safe. The snapshot `bk-<id>` of a killed backup stays on the dataset, and
being the newest `bk-` snapshot with no backup behind it, makes the next backup whole instead of
incremental; the `keep_snapshots` pruning removes it in time. An incomplete upload is the store's
own: S3 keeps no object for an unfinished multipart upload, and the directory store's temporary
file (`<key>#<n>`) is not listed as an object.

## Tests

A finished backup leaves no marker. Cut in a task, as the process ending there, before the first
stream and between two streams (the fake `zfs` holds one disk's send): the next start removes the
written stream and the marker and leaves the earlier backup, listed and whole. Constructed from the
state a kill leaves, where no step separates two states: streams written and no record (removed),
a record and a marker (kept, marker ended). A stream with no marker is left alone, and a marker with
names that are not ours changes nothing.
