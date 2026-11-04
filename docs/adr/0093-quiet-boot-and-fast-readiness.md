# ADR 0093: A quiet kernel console and a readiness wait that polls every 5 ms

Date: 2026-11-04 · Status: accepted

## Context

A cold boot on a production-class host measured, for a small machine, kernel start to the
init serving in 491 ms, and the daemon noticing 88 ms later: `wait_ready` slept 100 ms between
pings. The boot arguments had no `quiet`, so the kernel wrote about 19 KB to the serial
console before the init ran. A serial port is slow to emulate: the guest waits on every byte.

What the console carries (`machine logs`, ADR 0021 and 0025):

| Source | Read by |
|---|---|
| Firecracker's own log lines (its API requests, the VMM start) | a person |
| The kernel's `printk` messages | a person |
| The init's `[briqyard] …` lines (`started pid=…`, the exit trace) | a person; nothing parses them (ADR 0004) |
| The program's stdout and stderr (`/dev/console`) | a person, `machine logs`, `last_console_lines` in a boot failure |

Nothing parses the kernel's lines. The init detects an OOM kill from the kernel ring buffer
(`klogctl(3)`, `Out of memory`), which holds every message whatever the console's level.

## Decisions

**`quiet` on the kernel command line, before the operator's `kernel_args`.** The console's
level becomes 4: errors, critical messages, alerts and panics print (`Kernel panic`,
`VFS: Cannot open root device`, a failed `exec` of the init, an ext4 error, the `Out of
memory: Killed process` line); informational and warning messages do not (the boot banner, the
device list, `invoked oom-killer` with its memory dump). The ring buffer keeps all of them for
the init's OOM check. `kernel_args: "loglevel=7"` brings every message back; the operator's
arguments come last, so they win. The program's output, the init's lines and Firecracker's
lines are not kernel messages and are untouched.

**`wait_ready` polls every 5 ms for the first 5 s, then every 100 ms.** The same deadline
(`boot_timeout_sec`), the same error (`guest init did not answer within …`, with the last
failure) and the same single caller. A ping that finds nobody listening costs one local
connect and a refusal, so a fast interval costs the VMM little while a guest boots; a guest
silent for 5 s is slow or wedged and falls back to the old rate, so a stuck machine costs ten
connects a second, as before. The expected notice delay falls from 50 ms (up to 100 ms) to
2.5 ms (up to 5 ms).

## Alternatives

**The guest tells the host it is ready** (it connects out to a host port, as for the exit
report, ADR 0004). No polling at all, but the init would have to dial before every `serve`
path, the daemon would listen on one more socket per machine before the VMM starts, and
machines whose init predates the change would need the polling anyway. A 5 ms poll gets the
same latency (within one interval) with no protocol change and no second path.

**`loglevel=3` instead of `quiet`.** `quiet` is level 4 and keeps the kernel's warnings
off the console too; level 3 would drop one more class (error-level lines stay in both). Not
measured separately; `quiet` is the kernel's own name for the setting and `loglevel=` stays
available to an operator.

**`console=` off the serial port.** Loses the panic and the early-boot failures that a
person needs, and the program's output, which uses the same device.

## Measurements

Development VM (`fc`, aarch64, nested virtualization, a 128 MB alpine machine, release
daemon builds of main, of the readiness change, and of both changes; cold creates, the image
pulled, variants interleaved in rounds, 14 to 15 samples each). `starting` to `running`
(`briqyard_machine_boot_seconds`), which ends when the daemon sees the init:

| Daemon | Median | Console bytes before the program |
|---|---|---|
| main (100 ms sleep, no `quiet`) | 36.3 s | 21,968 |
| 5 ms polling | 29.1 s | 21,968 |
| 5 ms polling and `quiet` | 16.8 s | 4,633 |

The VM's serial console is the slowest part of its boot (the kernel's output reached the
daemon at about one line every 10 to 20 ms), so `quiet` is large there and the run-to-run
spread (3 s to 46 s) is larger than the readiness change, which saves at most 100 ms: the
first two rows differ by noise. The readiness change is checked by its tests and by the 88 ms
gap measured on the production-class host, not by this table. The hosts' own figure (how much
of the 19 KB console time `quiet` saves there) is a measurement to take after release.

## Consequences

- Warnings from the guest kernel are not on the console by default. Errors, panics and the OOM
  kill line are. `loglevel=7` restores the rest for a host being debugged.
- A guest that boots in half a second is noticed within 5 ms of the init serving instead of
  within 100 ms.
- The poll costs up to 200 local connects a second per machine for the first 5 s of a boot,
  and nothing after. One attempt is in flight per machine at a time. The VMM does not see them
  before the guest's vsock driver activates; after that each one is a guest round trip, until
  the init listens.
- A silent hang before the init no longer shows the last kernel line in the "guest did not come
  up" error. `loglevel=7` brings it back. A loud failure (a panic, a missing root device, a
  failed init exec) still prints.
- Nothing already saved is invalidated. A snapshot resumes with the command line it was taken
  with, since a resume does not set the boot source, and the boot identity does not include
  the boot arguments, so templates and warm slots stay compatible.
