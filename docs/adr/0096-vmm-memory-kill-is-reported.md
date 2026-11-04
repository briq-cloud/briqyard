# ADR 0096: A VMM killed over its memory ceiling is reported in the exit

2026-11-04 · Status: accepted; extends ADR 0065 and 0092

## Context

A VMM killed by its cgroup sends no init report, so the machine ended as `exit.code` 255,
`oom_killed: false`, `stopped_reason: exit`. The only evidence was a log line from the cgroup's
`memory.events.local` delta (`vmm_cgroup_oom_evidence`, ADR 0065). The owner of a machine that
died of memory saw only "code 255", the same as any other lost VMM.

## Decisions

**A separate field, `exit.vmm_oom_killed`.** `oom_killed` is the guest kernel's word, from the
init's report (ADR 0065: exit 137 or the guest flag alone never identifies a VMM cgroup OOM, and
the reverse holds). The host's evidence is its own field, omitted while false. The CLI shows
"VMM over its memory ceiling" on the exit line.

**Set only when the init sent no report and the delta reads `vmm_cgroup_oom_evidence`**
(`oom`, `oom_kill` and `oom_group_kill` all above zero). A report is the exit; the evidence then
stays in the log. Local kill counters without a group kill stay unclassified and set nothing.
The event reads "killed: VMM over its memory ceiling".

**Evidence first, then the exit.** `OomEvidence::record` returns the delta's reason. The task
that reads it sets a shared `VmmOom` flag, then publishes the process's exit; the settling code
runs on that exit, so it never sees the exit without the evidence. There is no later arrival to
reconcile. Where the baseline or the counters are unreadable the flag stays false and the exit is
the plain 255, as before.

**A stopped copy stays `unsynced` with its own reason** (ADR 0092): `consistency_reason:
vmm_oom_killed` instead of `unclean_exit`, since the VMM died with the guest's page cache lost.

## Tests

Each ordering: evidence then exit without a report (flag set, event, `crash`/`vmm_oom_killed`),
exit with no evidence (255, flag false), evidence with the init's report (the report wins, flag
false).
