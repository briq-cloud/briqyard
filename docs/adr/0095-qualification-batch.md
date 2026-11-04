# ADR 0095: The qualification batch: chaos, isolation and OOM in native CI

2026-11-04 · Status: accepted; extends ADR 0010, 0049, 0065, 0084 and 0089

## Context

The gate was "one combined batch: smoke, controlled stress, chaos and recovery, isolation, OOM behaviour".
Smoke (`e2e`, `fleet-smoke`, two-host suites) and controlled stress (`stress.py --crash --churn`, with
`stress-invariants.sh`) already ran in native CI (ADR 0089). The other three were partial. An audit of the
suites on `main` before this change:

| Area | Before | In CI before |
|---|---|---|
| Daemon SIGKILL | `e2e` "daemon crash: running machines are adopted" (idle machine); `stress.py --crash` once in round 1, between phases, machines idle, then the invariants | yes (`e2e`, `stress`: the job passes `--crash`) |
| Kill in the middle of a create, fork, backup, snapshot, suspend | a client hanging up mid-create (`stress.py`), never a kill; `chaos.py` races operations but kills nothing | no kill mid-operation; `chaos.py` not run |
| VMM killed, fleet killed | none | no |
| Host reboot | a stop with the pool unmounted and the key unloaded (`e2e` "a stop (a reboot)", `fleet-two-hosts`) | yes (simulation of what a reboot leaves) |
| Pool or disk full | unit tests of `disk_pressure` only | no |
| Network isolation | `e2e` "other namespace cannot reach": a ping that passes on any failure, no control; egress `none` and `via` sections | weak |
| Host, API, metadata, vsock, private ranges | none | no |
| Jailer in effect, uid per machine, cgroup limits, secrets | `jail-check.sh` by hand; CPU weight and gateway quota in `e2e`; "every firecracker holds its own disks" in the invariants | partly |
| `/dev/kvm` only in `nested` | `e2e` "no vmx or svm", "nested: /dev/kvm" | yes |
| Guest OOM, VMM OOM | unit tests of the evidence; `oom-group-smoke.sh` on a stand-in cgroup, by hand | no |
| Physical admission | unit tests; `stress.py` starts past capacity (refusal seen, no exact figure) | partly |
| Host pressure refuses placement | none | no |

## Decision

**One suite, `hack/qualify.sh`, its own parallel job `qualification`** in `native.yml` (a fourth entry of the
`more-suites` matrix beside stress, monitoring and alerts), run by `hack/native-ci-more.sh qualification` on
the isolated runner. It kills the daemon, the fleet and every Firecracker, fills the pool and lowers one VMM's
ceiling, so `hack/native-ci-more.sh` refuses to run it outside a disposable GitHub-hosted runner. `chaos.py` runs inside it for four minutes. 119 checks,
about 460 s of suite time (about 11 minutes of job). The existing suites are unchanged.

**An attempt that must fail is checked for its reason, beside a control.** A refused connection is told from a
dropped one by the client's own words (`timed out` is a drop, `refused` would be a reject), a loss by its
`100% packet loss`, a permission by `Permission denied`. Each has a control that succeeds the same way:
the sibling reads the same server, the host answers its own, the gateway answers DNS and ping, the real MAC
and address send, the host reads the file the other uid cannot.

**A kill is real and lands in the operation.** `kill -9` on the daemon's pid alone (a `systemctl kill` would
take the machines). The client of a synchronous call must have failed (backup, snapshot, suspend, create);
for a fork, which answers at the record, the kill waits for the fork to be `creating` or `starting`. Delays are
tried in turn until one lands; none landing fails the check. After each kill: the daemon answers, nothing
stays in motion, no error is silent, the source runs with its counter intact on both disks, what the
operation left is whole or reported (every backup listed restores), `stress-invariants.sh` holds after the
leftover is destroyed (nothing leaked), and the same operation succeeds again.

| Area | Covered now by |
|---|---|
| Daemon killed mid-create, mid-fork, mid-backup, mid-snapshot (with memory), mid-suspend | the five `-- mid-…` sections |
| VMM killed | "VMM killed": only that machine stops (exit 255), the other, its VMM and the daemon untouched, restart whole |
| Fleet killed | "the fleet killed": machines run on, the fleet returns, lists and creates |
| Power cut | the daemon and every VMM killed at once: nothing stuck, none claims to run without a VMM, counters whole |
| Pool full | a reservation takes the pool's last space: the create fails with `No space left`, the daemon and the machines live, `disk_pressure`, the fleet refuses, then everything recovers |
| Network | other namespace both ways, ping, the host through two bridge addresses, the API and ingress ports, the metadata address, two private ranges, a changed MAC, a foreign address, egress `none` (name and address) |
| Filesystem, devices, vsock | a guest sees its three disks only, a sibling's file is absent, `/dev/kvm` absent, vsock to the host reset, to another CID not made |
| Jail and limits | uid per machine, no capabilities, no new privileges, seccomp on every thread, chroot, pid namespace, own cgroup holding one process, another uid denied, VMM ceiling guest + 256 MiB, no swap, group kill, CPU quota, OOM scores +500 and -900 |
| Secrets | an env secret in its machine only (siblings, host process list, no host credential in the guest) |
| Guest OOM | a real memory hog killed in the guest (exit 137, the kernel's message on the console); the machine, its VMM, the daemon and the sibling untouched, no cgroup event; the main process killed: `exit.oom_killed` |
| VMM OOM | one leaf's `memory.max` lowered under what its VMM holds (a guest cannot push Firecracker past guest + 256 MiB): the kernel group-kills it, the machine is `stopped` with exit 255, `oom_killed` false, the daemon logs `vmm_cgroup_oom_evidence` for it, the daemon and the sibling survive, the next start has the policy ceiling |
| Physical admission | two 4096 MB machines commit 2 × (4096 + 256); a third is refused `capacity` and changes nothing; the exact remainder is admitted to the megabyte; one more is refused; `memory_pressure` follows and the fleet refuses; a stop releases at once |

**How the daemon reports a VMM's OOM.** The record carries no `oom_killed` for it: that flag is the guest's init
reporting its main process killed by the guest's OOM. A VMM killed by its cgroup ends as exit 255 (no report from
the init), and the proof is the daemon's log line `VMM local memory events` with
`reason: vmm_cgroup_oom_evidence` (ADR 0065: exit 137 or `oom_killed` alone never identifies it). The suite checks
that and checks `oom_killed` is false, so the two causes cannot be confused.

## Findings

No product bug found. Observations:

- A fork starts the image's own command, not the source's. A fork of a machine whose command is `sleep` exits 0
  at once. The suite forks an image whose command keeps running.
- After a freed pool the fleet keeps refusing for a few seconds (its view follows the heartbeat); the suite polls.
- The fleet's refusal under disk pressure reads `no host has room for this machine (capacity)`, under memory
  pressure it names `memory_pressure`.
- `stress` failed once in validation on its churn bound (`daemon RSS grew 48.3 MB over cycles 3..4 (bound 32 MB)`),
  a job this change does not touch.

## Not covered, and why

| Gap | Why it needs more than the runner |
|---|---|
| A real host reboot | the runner cannot reboot mid-job; the power cut and the unmounted pool above are what a reboot leaves in processes and the pool, not its network devices, mounts and boot ordering |
| A disk or pool failing underneath (I/O errors, a pool that stalls) | needs a device that can fail; the runner's pool is a file. Only the full pool is covered |
| Full-capacity saturation | the runner has 16 GiB and 4 vCPUs; the admission figures are exact, memory is not touched to the limit by many guests at once |
| cgroup behaviour on M and L machines, CPU shares and quotas under contention | needs the real core count; only the ceilings are read |
| A VMM growing past its ceiling by itself | not reachable from a guest; the ceiling is lowered instead. The kernel's group kill is real, the trigger is ours |
| Global (host) OOM and victim order | by design not part of normal tests (ADR 0065): it takes the runner down; `hack/oom-group-smoke.sh` stays the by-hand test on an empty host |
| Sustained soak | hours, not minutes: `stress.py --churn` and `chaos.py` run for minutes here |
| Noisy neighbours on shared hardware, hostile guest code against Firecracker or KVM | needs dedicated hosts and a threat model, not a nested runner |
| A second kill during recovery, a kill of the registry's host | the fleet suites own the registry; a second crash during adoption is not tried |

## Consequences

The three missing areas are checks in CI per relevant PR, in a job of its own so its time adds nothing to the
others. The suite is destructive by design: it is only for an installed disposable host and asserts that at
the start. Timing-sampled kills mean a rare window can still be missed; the suite fails if no attempt lands
instead of passing quietly.
