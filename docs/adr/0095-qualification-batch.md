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
ceiling, so `hack/native-ci-more.sh` refuses to run it outside a disposable GitHub-hosted runner. `chaos.py` runs inside it for four minutes. about 460 s of suite time (about 10 minutes of job). The images are pinned by digest and pulled through the host's registry mirror. The invariants script gains the cgroup leaf checks, which every stress run uses too.

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
| Network | other namespace both ways, ping, the host through two bridge addresses and its uplink address, the API and ingress ports, the metadata address, two private ranges, DNS across namespaces, a changed MAC, a foreign address, egress `none` (name and address), IPv6 (the forward chain's rule state plus a probe) |
| Filesystem, devices, vsock | a guest sees its three disks only, a sibling's file is absent, `/dev/kvm` absent, vsock to the host reset, to another CID not made |
| Jail and limits | uid and gid per machine, no capabilities, no new privileges, seccomp on every thread, chroot, pid namespace, own cgroup holding one process, another uid denied, VMM ceiling guest + 256 MiB, no swap, group kill, CPU quota, OOM scores +500 and -900 |
| Processes | 300 guest processes add no host thread to the VMM |
| Secrets | an env secret in its machine only (siblings, host process list, no host credential in the guest) |
| Guest OOM | a real memory hog killed in the guest (exit 137, the kernel's message on the console); the machine, its VMM, the daemon and the sibling untouched, no cgroup event; the main process killed: `exit.oom_killed` |
| VMM OOM | one leaf's `memory.max` lowered under what its VMM holds (a guest cannot push Firecracker past guest + 256 MiB): the kernel group-kills it, the machine is `stopped` with exit 255, `oom_killed` false, the daemon logs `vmm_cgroup_oom_evidence` for it, the daemon and the sibling survive, the next start has the policy ceiling |
| Physical admission | two 4096 MB machines commit 2 × (4096 + 256); a third is refused `capacity` and changes nothing; the exact remainder is admitted to the megabyte; one more is refused; `memory_pressure` follows and the fleet refuses; a stop releases at once |

**How a VMM's OOM is reported.** Since ADR 0096 the exit carries `vmm_oom_killed` for a VMM killed over its
cgroup ceiling, apart from the guest's `oom_killed`. The suite asserts `vmm_oom_killed` true and `oom_killed` false
for the lowered-ceiling kill, and `vmm_oom_killed` false for a plain `kill -9` of a VMM. The daemon's
`vmm_cgroup_oom_evidence` log line is still asserted.

## Findings

- **Fixed by ADR 0096:** the VMM OOM report (the suite now asserts the field).
- **Known, being decided elsewhere:** a fork starts the image's own command, not the source's, so a fork of a
  `sleep` machine exits 0 at once. The suite forks an image whose command keeps running and pins neither behaviour.
- After a freed pool the fleet keeps refusing for a few seconds (its view follows the heartbeat); the suite polls.
- The fleet's refusal under disk pressure reads `no host has room for this machine (capacity)`, under memory
  pressure it names `memory_pressure`.
- `stress` failed once in validation on its churn bound (`daemon RSS grew 48.3 MB over cycles 3..4`), a job this
  change does not touch.
- **Open defect, found by this batch (a separate PR fixes it):** a backup killed while its stream is being written can leave that stream in
  the store with no record (seen in 2 of 3 runs; the third kill landed after the record). It is listed and restorable
  by nothing, and nothing removes it, not even the next successful backup; the census (ADR 0083) only counts. The
  suite bounds it (at most the interrupted backup's one stream, never listed), prints `KNOWN DEFECT`, and prints
  `FIXED` once the daemon cleans it, when the check should become `[ -z "$orphans" ]`.
- **Open defect, found by this batch (a separate PR fixes it):** a machine whose VMM was killed (`kill -9`) is `stopped` with its empty cgroup
  leaf still in place; a stop through the API removes the leaf. Nothing else is left behind, and the leaf goes with
  the machine's next start or destroy. `stress-invariants.sh` allows exactly that case (a `stopped` machine with exit 255), prints `KNOWN DEFECT`, and prints `FIXED` once the leaf is gone; a leaf of any other machine without a Firecracker fails. The orphan
  stream above is timing-dependent: a kill that cuts a backup left one in some runs and none in others, so `FIXED`
  there is evidence only after several runs.
- Added after review: the invariants now check cgroup leaves (none without a machine, one for every live
  Firecracker); a backup is killed while its stream is on disk and the store is read afterwards (listed ==
  recorded, no stream without a record, every listed backup restores whole); a suspend is killed while the
  machine is `stopping`. Their results are in the PR description.

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
| IPv6 proven by traffic | the runner has no IPv6 route, so a probe cannot distinguish the firewall from no route; the forward chain's rule is checked as state, with no control |
| A `pids.max` on the VMM leaf | its value is printed; no limit is asserted since none is specified |
| A second kill during recovery, a kill of the registry's host | the fleet suites own the registry; a second crash during adoption is not tried |

## Consequences

The three missing areas are checks in CI per relevant PR, in a job of its own so its time adds nothing to the
others. The suite is destructive by design: it is only for an installed disposable host and asserts that at
the start. Timing-sampled kills mean a rare window can still be missed; the suite fails if no attempt lands
instead of passing quietly.

## Two checks made deterministic (2026-11-04)

- **Memory pressure refusal.** The fleet names a host under pressure (`memory_pressure`) only to a create bound to it (a pinned namespace, ADR 0042). A new namespace is told "no host has room" and counted as `memory`, by design. The check used a new namespace, so it passed only when the fleet's view was stale for one poll (the create was placed and the host refused it, which pinned the namespace). Not a product defect; the check now pins the namespace through the fleet first, asserts `memory_pressure` there, and asserts "no host has room" for a new namespace.
- **Backup cut.** The second backup is incremental, so on a volume that changed by a few KB its stream lasts milliseconds. Each attempt now writes 300 MB first, and the `zfs send` is paused the moment the stream is seen, so the daemon kill lands inside it. The kill and the failed client are still required.
