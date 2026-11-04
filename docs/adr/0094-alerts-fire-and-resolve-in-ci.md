# ADR 0094: The alerts fire and resolve in native CI, received by a local webhook

2026-11-04 · Status: accepted; extends ADR 0054 and 0042

## Context

`monitoring-check.sh` proves the stack runs and the dashboards answer. `monitoring-alert-check.py` proves
the capacity and backup expressions on synthetic samples (ADR 0054). Nothing had shown a rule going
firing then resolved in Grafana and the notification arriving somewhere. A rule that never fires, or never
resolves, looks the same as a healthy fleet.

## Decisions

**The job loads the production file and changes only what it names.** `hack/monitoring-alerts-check.py`
reads `hack/monitoring/grafana/alerting.yaml`, applies the install's `LARGEST_SLOT_MB` substitution, and
writes a provisioning file with these changes, printed in the job output and pinned by
`hack/test_monitoring_alerts.py` (every other field of every rule must be equal):

| Changed for the job | Production | Why |
|---|---|---|
| Contact point: a webhook on loopback | Slack | no external service, no secret |
| Group evaluation interval 10 s | 1 m | firing and resolving are seen within seconds of the data |
| Policy `group_wait` 5 s, `group_interval` 10 s | 30 s, 5 m | `resolved` is sent at the next group flush |
| `Largest slot too small` `for: 1m` | 10 m | the wait, not the expression |
| `LARGEST_SLOT_MB=8192` | 16384 (default) | the fixture holds 12288 MB; the install's own knob |

After Grafana starts, the script reads every rule back from Grafana's provisioning API and fails unless
its queries, thresholds, labels, states and annotations equal the file's, and its `for` equals the file's
or the override above. Expressions are never shortened: the backup alert's ten-minute and the capacity
alert's five-minute windows are waited out.

**Causes are real; recoveries are real.** A notification counts when the webhook receives an alert whose
`alertname` and labels match (host, region, resource, condition, instance) with status `firing`, then
`resolved` after it. An alert over a window cannot truly resolve before the window has passed, so a
`resolved` earlier than the window minus a minute is not accepted as the recovery. Every alert must also
show exactly one `firing` and one `resolved`: a flap fails the job.

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
- **"Machine in a crash loop" fired, resolved and fired again at exactly three restarts.**
  `round(increase(...[10m])) > 2` reads about 2.4 to 3.3 for three restarts, depending on the first
  sample the series was seen at and the gaps while the machine is stopped between restarts. Fixed in the
  rule with `keepFiringFor: 3m` (supported by Grafana 13.2.5, pinned in the install): once true the alert
  is held through the gaps and resolves once, three minutes after the window. The expression is unchanged,
  so a Prometheus restart raises no false alert. The job requires exactly one `firing` and one `resolved`.
- No rule was found that never fires or never resolves when its cause is driven as above.

## Consequences

- This proves rule → Grafana → webhook: a real cause becomes a firing and a resolved notification with the
  right labels, for seven of the eight rules. It does not prove Slack or any real receiver (that needs a
  secret and belongs to the operator), nor real saturation: the memory is committed, not used, and the
  fixture is a 12 GiB host.
- A resolved notification of the window alerts says the event left its window, not that backups work or
  capacity came back (ADR 0054).
- The production Slack contact point and the policy's real timings (30 s, 5 m) are not exercised; the
  file's `group_wait` and `group_interval` are replaced for the job only.
- Cost: the `alerts` suite is a runner of its own, about 14 minutes (3 for the build and install, 10.6 for
  the alerts, bounded at 20); in parallel with the others, it adds no wall time. The `monitoring` suite
  grows by about 3 minutes (Not answering fires after 143 s, resolves 29 s after the daemon is back).
- A rule that never fires or resolves fails the job, with Grafana's rule states, the receiver's
  notifications, each rule's query result, Prometheus samples, the fleet's hosts and Grafana's journal printed.
