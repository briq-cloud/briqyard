# ADR 0094: The alerts fire and resolve in native CI, received by a local webhook

2026-11-04 · Status: accepted; extends ADR 0054 and 0042

## Context

`monitoring-check.sh` proves the stack runs and the dashboards answer. `monitoring-alert-check.py` proves
the capacity and backup expressions on synthetic samples (ADR 0054). Nothing had shown a rule going
firing then resolved in Grafana and the notification arriving somewhere. A rule that never fires, or never
resolves, looks the same as a healthy fleet.

## Decisions

**The job runs the real install and changes only timings.** The CI script writes
`/etc/briqyard-monitoring/alerting.env` with `SLACK_WEBHOOK_URL` set to a receiver on loopback
(`hack/monitoring-alerts-check.py`, port 18199) and runs `hack/install-monitoring.sh` with
`LARGEST_SLOT_MB=8192`. So the install's gating on `alerting.env`, the unit's `EnvironmentFile`, the
`$SLACK_WEBHOOK_URL` expansion, the Slack contact point and the `@LARGEST_SLOT_MB@` substitution
(`hack/render-alerting.sh`, one `sed` the install and the check both call) are the production path.
Grafana's Slack integration posts to any URL; the receiver reads each alert's status and labels from the
message as Grafana's default template writes it (`[FIRING:1]` title, `**Firing**` / `**Resolved**`
sections, `Labels:` lists). Only these are changed on top of the installed file, printed in the job
output and pinned by `hack/test_monitoring_alerts.py` (every other field of every rule and the
contact points must be equal):

| Changed for the job | Production | Why |
|---|---|---|
| Group evaluation interval 10 s | 1 m | firing and resolving are seen within seconds of the data |
| Policy `group_wait` 5 s, `group_interval` 10 s | 30 s, 5 m | `resolved` is sent at the next group flush |
| `Largest slot too small` `for: 1m` | 10 m | the wait, not the expression |
| `LARGEST_SLOT_MB=8192`, given to the install | 16384 (default) | the fixture holds 12288 MB; the install's own knob |

The Slack endpoint is the only thing replaced: the URL is a loopback receiver. After Grafana restarts, the
script reads every rule back from Grafana's provisioning API and fails unless its queries, thresholds,
labels, states, annotations, `for` and `keepFiringFor` equal the rendered file's (the `for` override
aside), and the installed file equals the rendered one. Expressions are never shortened: the backup
alert's ten-minute and the capacity alert's five-minute windows are waited out.

**Without `alerting.env` there is no notification path at all.** The install then provisions no alert
rule and no contact point: a host can be down and nobody is told. The install now prints a warning to
stderr at that point and again in its last line (it said only `alerting off` before).

**Causes are real; recoveries are real.** A notification counts when the webhook receives an alert whose
`alertname` and labels match (host, region, resource, condition, instance) with status `firing`, then
`resolved` after it. An alert over a window cannot truly resolve before the window has passed, so a
`resolved` earlier than the window minus a minute is not accepted as the recovery. Every alert must also
show one firing episode and one resolved episode: Grafana re-sends still-firing members whenever another
alert of the group changes, so repeats of a status are one episode, while a `resolved` followed by a new
`firing` is a flap and fails the job.

| Alert | Cause | Recovery | Synthetic? |
|---|---|---|---|
| Backup failure observed | the backup store path is a file: `briqyard machine backup` fails and the daemon records `backup_failed` | the store put back (a backup succeeds); the alert resolves when the ten-minute window passes | no |
| Creates refused: no room | a create of 20000 MB on a host of 12288 MB, asking region `dev`, no region, and a region no host is in (`other`) | the five-minute window passes | no |
| Host condition | one machine, sized from the host's free memory, commits over 95 % of its 12288 MB: `memory_pressure` | the machine destroyed | no |
| Creates refused: host under pressure | a create in that machine's namespace, refused under the condition | the five-minute window passes | no |
| Largest slot too small | the same machine: the host is over the fill ceiling and takes no new namespace, so the region's largest slot is 0 | the machine destroyed | no |
| Machine in a crash loop | a machine that runs 10 s and exits, restarted by its default policy (3 restarts) | the ten-minute window, then `keepFiringFor` (3 m) | no |
| Not answering | the daemon stopped (`monitoring` suite, with the live daemon) | the daemon started | no |

The first six run in the `alerts` suite on their own runner, concurrently; Not answering runs in the
`monitoring` suite after `monitoring-check.sh`, because stopping the daemon would end the series the
others read and resolve them for the wrong reason. Nothing is driven with synthetic samples here: the
promtool fixtures of ADR 0054 stay the only synthetic check.

**Not covered: Pool over 80 %.** Its cause is 80 % of the pool used. The runner's pool is a 40 GB file
and the disk cannot hold 32 GB of writes beside the build. It stays proved on its expression and its
loaded definition only; a fault in it is not found here. Not answering is proved on the live daemon only
(the registered `unreachable` host keeps it firing for itself, matched apart by `instance`).

## Defects found, and fixed here

- **The first "no room" refusal never alerted.** The rule reads `increase()` over five minutes, empty for a
  counter series whose first sample is already 1. Regions with a host had every series at zero from the
  first scrape; an ask with no region (`region=""`) or a region no host is in (`other`) was a series
  born at its first refusal. Fixed at the metric (`signals::render`, ADR 0042): the refusal counter is
  published at zero from the fleet's start for both, beside every region with a host. The labels are a
  fixed set (a caller's region string maps to `other`, never a series of its own), so cardinality grows by
  eight series. Pinned by a unit test, and by the job, which asks for a region, for none and for
  `nowhere` and requires a `firing` and a `resolved` for each. The rule is unchanged.
  "Creates refused: host under pressure" has no such problem: it is counted in the refused host's own
  region, which has its series at zero.
- **"Machine in a crash loop" fired, resolved and fired again, and could miss a loop.**
  `round(increase(...[10m])) > 2` reads about N-1 to 1.2 N for N restarts: a series is first seen at its
  first sample, and a machine that restarted before it, or stops between restarts (the daemon leaves gaps),
  has that restart outside the window. Three restarts read 2.0 to 3.6, so the alert crossed its threshold
  back and forth, and a loop of three whose first restart came before the first sample (about 2.0 to 2.4)
  never fired at all, at any evaluation interval (the job's 10 s, production's 1 m: the reading holds for the
  window, so a slower evaluation does not change which side of 2.5 it falls on). Fixed in the rule:
  the threshold is now `> 1` on the rounded value (two restarts seen or more, so a loop of three is always
  seen; the alert says "at least twice"), and `keepFiringFor: 3m` (Grafana 13.2.5 supports it) holds the
  alert through readings that cross the threshold. `increase()` keeps its reset handling, and the
  expression has no first-sample branch, so a Prometheus restart raises no false alert. The price: a
  machine that restarts exactly twice in ten minutes also alerts. The job requires one firing episode and
  one resolved.
- No rule was found that never fires or never resolves when its cause is driven as above.

## Consequences

- This proves rule → Grafana → webhook: a real cause becomes a firing and a resolved notification with the
  right labels, for seven of the eight rules, along the install's own path from `alerting.env` to a posted
  Slack message. It does not prove Slack's endpoint or any real receiver (that needs a secret and belongs to
  the operator), nor real saturation: the memory is committed, not used, and the
  fixture is a 12 GiB host.
- A resolved notification of the window alerts says the event left its window, not that backups work or
  capacity came back (ADR 0054).
- Slack's own endpoint, the message as Slack renders it, and the policy's real timings (30 s, 5 m) are not
  exercised; `group_wait` and `group_interval` are replaced for the job only.
- Cost: the `alerts` suite is a runner of its own, about 14 minutes (3 for the build and install, 10.6 for
  the alerts, bounded at 20); in parallel with the others, it adds no wall time. The `monitoring` suite
  grows by about 3 minutes (Not answering fires after 133 to 143 s, resolves 29 s after the daemon is back).
- A rule that never fires or resolves fails the job, with Grafana's rule states, the receiver's
  notifications, each rule's query result, Prometheus samples, the fleet's hosts and Grafana's journal printed.
