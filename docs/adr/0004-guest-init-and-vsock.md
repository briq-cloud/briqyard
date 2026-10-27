# ADR 0004: The guest: a static init, a config drive, vsock for exec and files

Date: 2026-10-18 · Status: accepted; amended by ADR 0029 (an exec's input frames, a terminal, the host's close ends the command)

## Context

The image is anyone's. The guest has no agent of ours installed, no libc we can count on, and no network path from the host but the tenant bridge. Exec, files and the exit code have to work on every image.

## Decisions

**`briqyard-init` is PID 1, a static musl binary**, passed to the kernel as init from the jail. A dynamically linked init fails with "error -2" before anything prints.

**Configuration arrives on a config drive**: a tar stream on `/dev/vdb` with `config.json` and the boot files, read raw by the init. No MMDS, no kernel command line parsing, no cloud-init. Secrets reach the guest this way and never through an API response.

**Host and guest talk over vsock, port 7421**, a small framed protocol in `briqyard-api`: `exec` (stdin, streamed stdout and stderr, exit code, timeout), `put`, `get`, `ping`, `shutdown`. No SSH, no agent on the tenant network.

**The init reaps with `waitid(WNOWAIT)`.** PID 1 inherits every orphan; a plain `wait` steals the exit status of a command the exec server started. The reaper peeks and reaps only orphans.

**The exit of the main process is one frame over vsock** (since 2026-10-20): the init connects out to host port 7422, which Firecracker brings to the daemon as `<vsock socket>_7422` next to the machine's socket, sends one `ExitReport` (code, oom, requested), waits for the daemon's close, then resets the machine, which ends Firecracker. The daemon settles the machine from that report and applies the restart policy; a process gone without one (killed, a kernel panic) reads as exit 255. Before, the init printed `[briqyard] exit code=N oom=B requested=R` and the daemon parsed the console for it: string parsing where a structured channel existed, and a guest that printed the same line could forge its exit status. The line stays as a trace for a person reading the console; nothing reads it. The serial console is the machine's log.

**The init builds `/dev`** with `/dev/fd`, `stdin`, `stdout`, `stderr` links (bash's `<(...)` needs them), mounts the data volume at its path, writes `/etc/hosts` and `/etc/resolv.conf`, sets the hostname, configures `eth0` over netlink, then runs the image's entrypoint and command as the image's user.

## Consequences

- One binary to ship per architecture; no per-image agent.
- The protocol is versioned by the init shipped with the daemon: a daemon upgrade is also an init upgrade at the next cold boot.
- `/tmp` is a tmpfs: kept through a resume, lost on a cold boot.
