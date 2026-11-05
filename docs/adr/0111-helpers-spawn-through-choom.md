# ADR 0111: Host helpers spawn through `choom`, not a `pre_exec` closure

2026-11-05 · Accepted

## Context

A helper must not inherit the daemon's protected OOM score (ADR 0065, `docs/MEMORY-POLICY.md`), so `host_process::command()` wrote `/proc/self/oom_score_adj` in a `pre_exec` closure. std spawns a command with `posix_spawn` (`CLONE_VM | CLONE_VFORK`, no page-table copy) only when it has no `pre_exec`; with one it calls `fork`.

Measured on a host, a burst of 30 sandbox creates and deletes:

| Measure | Value |
|---|---|
| `fork` calls | 1,224 (about 40 helpers per machine: zfs 12, nft 11, ip 8, conntrack 4, udevadm 2, zvol_id 2) |
| Time per `fork` | 0.5 to 4 ms |
| Time in the syscall | 1.9 s of 3.3 s wall |

Forks serialize on the parent's mmap lock, run synchronously on async workers, and mark the daemon's pages copy-on-write, so create latency grows with concurrency.

## Decision

| Class | Spawn |
|---|---|
| Helper (score 0) | `/usr/bin/choom -n 0 -- <program> <args>`, no `pre_exec`: `posix_spawn` |
| Machine (500), Gateway (250) | `pre_exec` as before: rare, and the jailer forks the VMM and drops credentials afterward |

- `choom` writes the score and execs the helper in the same process: the pid is unchanged, so `kill_on_drop`, `wait` and pidfds behave as before. It exits non-zero when it cannot write the score, so a helper never runs with the daemon's.
- The class is chosen when the command is built (`command_for(class, program)`; `command()` is the helper). There is no way to set it afterward, so a helper cannot be reset through `choom` after a `pre_exec` set 500 or 250.
- `/usr/bin/choom` is absolute: `unit.rs` runs helpers with `PATH=/usr/bin:/bin` and a bare name with a modified `PATH` also makes std fall back to `fork`. `choom` resolves the helper through the child's `PATH`.
- `choom` comes with util-linux. `hack/bootstrap-host.sh` and `hack/install-dev.sh` fail without it, `briqyard doctor` reports it. If it is missing the spawn fails: no fallback to an unprotected or forking path.
- Cost: 0.23 ms per spawn, all in the child, not in the daemon.
- `arg0` on a helper names `choom`; the two tests that need an exact `firecracker` command line use a plain `std::process::Command`.
- One helper keeps `pre_exec`: the startup check of the jailer runs the file the daemon holds open, at `/proc/self/fd/N`. That descriptor closes on exec, so `choom` could not open the path (`held_executable_command`).
- Other spawns that use `fork`: none on the helper paths (`pre_exec`, `uid`, `gid`, `groups` and `setsid` appear only in the guest init and the machine classes above).

## Rejected

- The parent writes the child's score after the spawn: not atomic, the helper runs at -900 in the window.
- A broker process that spawns helpers: more moving parts.
- Replacing the helpers with netlink and libzfs: a much larger change; it may come later and removes the spawns instead of making them cheaper.
