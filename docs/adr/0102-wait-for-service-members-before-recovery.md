# ADR 0102: Wait for service members before recovery

2026-11-04 · Candidate; amends ADR 0068. Native qualification pending.

## Defect

The official unit retains `KillMode=process` and `RestartSec=0`. Host helpers
(`zfs`, `nft`, `ip`) inherit its cgroup. Killing the daemon leaves its helpers
there. The final singleton check correctly refuses an unexplained member, but
`recovery_failed` latches `recovery_unresolved`: no adoption, sweep, workers or
admission until another restart. A short-lived send on a broken pipe therefore
can refuse an entire host indefinitely.

## Decision

Before storage/network setup, observe the held service membership every 100 ms
for at most 10 seconds. Only exactly the daemon, with no child cgroups, succeeds.
Missing daemon membership, directories and read failures fail closed immediately.
The bound is a startup latency budget, not evidence of process death. Nothing
is classified safe because time passed. A survivor may fork or join the VMM
domain during this wait; inventory starts afterwards and every original final
unit, namespace, service and VMM-domain check remains in place. The wait creates
no recovered authority and never opens managed spawning.

A timeout is retained in the startup authority. Diagnostic startup skips pool
setup, network reconciliation, adoption, sweep and background recovery workers;
the inert ZFS handle exists only to construct the existing manager/API. It does
not validate the pool. Existing mounted state and host identity must be readable to serve diagnostics.
Machine/namespace inventory is withheld; disk availability reports zero while
unreconciled. Diagnostic startup never creates a replacement host identity.
The API is not serving during the wait (up to ten extra seconds). Stored systemd
listeners can queue connections; request deadlines can expire. After a timeout,
status reports `memory_protection`, admissions return `startup: recovery_unresolved`.
Only health, status, metrics and OpenAPI routes serve in the fault state; other
routes return 503 rather than observing or mutating unreconciled records.
The existing host-condition alert covers this condition. Its message directs the
operator to journald and the recovery runbook. Exe and process-state observations name up
to 32 survivors; they are diagnostics, never authority to signal a process.

## Alternatives

- Retrying a failed final inventory requires discarding it and starting over. Waiting
  before any inventory or host reconciliation avoids retrying partially recovered state.
  The latched manager fault is never cleared in-process.
- Exe/name allowlists cannot identify pre-exec children, whose image is still the
  daemon. A safe kill would require retained incarnation identity plus a trusted
  executable and exact read-only operation proof. No kill is needed for helpers
  that exit naturally. Mutating helpers must finish, not be interrupted by recovery.
- A helper sub-cgroup needs a new trusted pre-exec placement contract, ownership
  checks and a migration rule for old helpers. It cannot exempt unknown legacy
  members. Retain the literal service-unit contract.
- `PR_SET_PDEATHSIG` follows the creating thread. Tokio's blocking-pool thread
  retirement could kill a healthy backup; it is not used.

Stopped helpers do not exit on a broken pipe until continued. Production does
not automatically continue or kill them. D-state or otherwise persistent members
still refuse the entire host. Unknown launchers retain exactly the same fence.

## Checks

Unit tests retain singleton rejection and cover exit, a newly forked member,
unreadable membership and exact timeout. A Linux check observes an exited but
unreaped child: zombies leave `cgroup.procs`; reaping is not required for this test.
The native qualification check pauses a real daemon-owned send, kills or hands
over the daemon, observes the new daemon waiting, resumes that exact send via a
pidfd, and requires create acceptance within 30 seconds. Old code cannot satisfy
the wait observation and latches its final-barrier failure instead.

PR #143 edits `crash_daemon`; this check does not use that function. Its broad
`pkill` workaround is unnecessary for naturally exiting helpers after this fix;
a deliberately stopped helper still needs continuation or an operator decision.
No guest-init source changes.
