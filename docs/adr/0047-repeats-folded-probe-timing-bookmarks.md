# ADR 0047: Repeats folded in the event log, probes on a fixed period, watch bookmarks

Date: 2026-10-28 · Status: accepted; amends ADR 0019 (events, versions, the watch's quiet line) and ADR 0022 (probe timing, the timeout's default)

## Context

Four gaps between briqyard and the Kubernetes behaviour it follows (`../KUBERNETES-MAP.md`):

| Gap | Today | Kubernetes |
|---|---|---|
| Repeated events | a line each: a readiness probe flipping every second, or an agent opening exec sessions in a loop, fills the host's 100,000 events within a day and pushes every other machine's history out | the event recorder folds repeats into one event with a `count` and the first and last times |
| A probe's first run | at once, for every machine: a daemon start that adopts 200 machines probes them all in the same instant | the kubelet spreads each probe's first run over its period when the kubelet started less than a period ago |
| A probe's period | `period_sec` slept after each probe ends: a slow probe stretches it | a ticker: runs start on a fixed period |
| A quiet watch | `{}` every 30 s: a filtered watcher that sees no event keeps its old cursor, which retention may prune | `BOOKMARK` events carry the current `resourceVersion` |

The probes' timeout default is 5 s, where Kubernetes's is 1 s, and the docs called the defaults "Kubernetes's timings".

## Decisions

**Two kinds of repeats fold; a change is otherwise always its own line.** The log is append-only and a machine's `version` is a seq (ADR 0019), so a repeat cannot update an earlier line: it is either a line or none. Folding is limited to two classes:

| Class | Reasons | A folded repeat | Why |
|---|---|---|---|
| Uses and refusals | `session_opened`, `quota_exceeded` | no seq, no line, no version move | nothing in the machine changed: `GET` and its version stay consistent |
| Readiness flips | `ready`, `not_ready` | a seq with no line: the version moves, the record is saved | `ready` is in the machine's view; If-Match must refuse a write based on a read from before the flip |

The key is (tenant, machine, reason): no type (fixed per reason), no message (Kubernetes's aggregator ignores it too). The host's own events never fold. The first occurrence of a key is logged at once; its repeats within 10 minutes of that line are folded; when the window ends, one line stands for them: `count` (the repeats it folds), `first_at` (the first one's time), `at` the last one's time, and the last one's `message` and `data`. The series then ends; the next occurrence is logged at once and starts another. One logged repeat would already be a line, so a window folds every repeat after the first, not after the tenth as Kubernetes does.

Who writes the folded line: the next occurrence once the window is over; the daemon's 15 s tick (a machine's flips under its lock, as the tick's other record writes: only while the daemon still holds the machine and no transition is under way, whose own line logs them; then under its record's lock, written with the line's seq as its version before anyone can read it); the daemon going down (every series, before the watches end); and any other line about the machine, which logs the machine's folded repeats first. So the last line about a machine says what it is now, and `describe` reads "50 sessions, then stopped", never a count after `destroyed`. A machine's two flip series are written together, due or not, last-seen last; its uses only once their own window is over.

**Not folded, and why:**

| Reason | Bound without folding |
|---|---|
| The restart chain (`exited`, `restarting`, `crash_loop`, `starting`, `started`) | the backoff (10 s to 300 s): 5 lines a restart, 1,440 a day per machine once in backoff; 69 machines in a crash loop fill the cap in a day. Folding would spread one sequence of states over five lines and lose each attempt's `attempt` and `delay_sec` |
| `backup_failed` | one every 15 min (the retry), and it changes `backup.next_at` |
| `host_condition`, `created`, `destroyed`, `host_started` | changes, or once per machine or start |

**What it buys:**

| Source | Lines a day, per machine, unfolded | Folded |
|---|---|---|
| Readiness flipping at `period_sec` 1, thresholds 1/1 | 86,400 (1.2 machines fill the cap) | at most 576 (4 per 10 min: each reason's first and its fold) |
| Readiness flipping at the defaults (10 s, 3/1) | 2,160 | 576 |
| An exec session a second | 86,400 | 288 |

**Seqs no line carries.** A folded flip's seq is a gap in the log. The record is written with it, under the record's lock and the guard every record write takes (a destroyed machine's record is never written back), before the version can be read: a crash after that finds it in the record, so the restart floor never gives it out again. Cursors are untouched (`read` and a watch skip what is at or before their cursor, so a cursor on a gap reads on), the restart floor takes the records' versions, and retention counts lines, not seqs (a seq span would count the gaps and prune real lines; the files' lines are counted at start). A read answers 410 only for a cursor before the last seq retention removed (each file's last seq is kept), so a cursor in a gap reads on; after a restart that seq is taken as the one before the oldest file kept, and a cursor in the gap just before it answers 410 though nothing it lacked was pruned. `/metrics`' event counters count occurrences, folded ones included.

**Probes run on a fixed period, the first run spread just after a daemon start.** A probe's first run is `initial_delay_sec` after its task starts, plus, while the daemon is younger than the probe's period, a random point of one more period: the kubelet's rule, applied whatever started the run (an adoption, a machine the host stopped started again at the start, a boot or a wake just after it). Later runs are on ticks one period apart from the first; a probe slower than its period skips the ticks it ran over and runs on the next one. The kubelet's Go ticker, like tokio's `MissedTickBehavior::Skip`, delivers one late tick at once, so a probe slower than its period there runs back to back; here it runs every other tick. The jitter adds the sum, not the max, to the initial delay: with the max, machines with `initial_delay_sec: 10` all probe at 10 s. Readiness and liveness, which start once startup passed, apply the same rule at their own start. The cost: a wake in the first period after a daemon start may wait up to one more period for `ready` (10 s with the defaults); none after that. The semaphore of 32 executions at once stays.

**A quiet watch sends a bookmark.** `{}` every 30 s becomes `{"bookmark": <seq>}`: the stream's cursor, the last seq it looked at, matching its filter or not, so a watch again from it misses nothing. Never the log's live seq: events still in the broadcast, not looked at yet, would be skipped. No `seq` key: a client that tells events by `seq`, or ignores lines it does not know, skips it. A client that watches again (after `lagged`, `shutdown`, a cut connection) starts from the later of its last event's `seq` and its last bookmark. Through the fleet a tenant's or a machine's watch is relayed as it is; the bookmark is that host's seq, which is what its `since` is anyway.

**The probes' timeout stays 5 s.** Kubernetes defaults to 1 s. An exec probe here crosses the vsock and the guest's init before the command starts, and its timeout counts once its turn of the 32 is held; 1 s fails a probe on a busy guest that is healthy. The cost is on a wedged guest only: three liveness failures take at most 25 s with the defaults (two periods and a timeout). The other defaults are Kubernetes's: `period_sec` 10, `failure_threshold` 3, `success_threshold` 1, `initial_delay_sec` 0.

## Consequences

- A watcher that follows `ready` learns of a flip folded within the window at the window's end, at most 10 minutes and 15 s later; `GET` and the version are current at once. A load balancer that needs every flip reads the machine, not the log.
- A writer that read a machine between its last folded flip and the folded line gets one 409 more: the line moves the version again.
- At a shutdown the folded flips are written without their machines' lock: those machines keep the last flip's seq as their version, which no line carries, until their next event.
- A crash loses the counts not yet written (memory only), as it loses any fact not yet logged.
- On a fleet-wide read, merged by time, a folded line sorts by its last occurrence, before lines of its host with lower seqs.
- Reopen folding for the restart chain if a host shows many machines in a crash loop at once; a per-machine share of the cap is the next lever, with numbers.
