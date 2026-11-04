# ADR 0094: The alerts fire and resolve in native CI, received by a local webhook

2026-11-04 · Status: accepted; extends ADR 0054

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
`alertname` and labels match (host, region, resource, condition, instance), with status `firing`; then
`resolved` after it.

| Alert | Cause | Recovery | Synthetic? |
|---|---|---|---|
| Backup failure observed | the backup store path is a file: `briqyard machine backup` fails and the daemon records `backup_failed` | the store put back (a backup succeeds); the alert resolves when the ten-minute window passes | no |
| Creates refused: no room | a create of 20000 MB on a host of 12288 | the five-minute window passes | no |
| Host condition | one machine of 10600 MB commits, with the others and their overhead, over 95 % of the host's 12288 MB: `memory_pressure` | the machine destroyed | no |
| Creates refused: host under pressure | a create in that machine's namespace, refused under the condition | the five-minute window passes | no |
| Largest slot too small | the same machine: the host is over the fill ceiling and takes no new namespace | the machine destroyed | no |
| Machine in a crash loop | a machine that exits at once, restarted by its policy | the machine destroyed | no |
| Not answering | the daemon stopped (`monitoring` suite, with the live daemon) | the daemon started | no |

The first six run in the `alerts` suite on their own runner, concurrently; Not answering runs in the
`monitoring` suite after `monitoring-check.sh`, because stopping the daemon would end the series the
others read and resolve them for the wrong reason.

**Not covered: Pool over 80 %.** Its cause is 80 % of the pool used. The runner's pool is a 40 GB file
and the disk cannot hold 32 GB of writes beside the build. It stays proved on its expression only by
review; a fault in it is not found here. The Not answering rule is proved on the live daemon only (the
registered `unreachable` host keeps it firing for itself, matched by `instance`).

## Consequences

- This proves rule → Grafana → webhook: a real cause becomes a firing and a resolved notification with the
  right labels. It does not prove Slack, a real receiver (that needs a secret and belongs to the
  operator), nor the saturation of real hardware: the memory is committed, not used, and the fixture is
  a 12 GiB host.
- A resolved notification of the two window alerts says the event left its window, not that backups
  work or capacity came back (ADR 0054).
- The run adds the `alerts` runner, about 14 minutes in parallel with the others, and about 6 minutes to
  `monitoring`.
- A rule that never fires or resolves fails the job.
