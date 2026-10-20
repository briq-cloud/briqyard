# ADR 0004: The guest: a static init, a config drive, vsock for exec and files

Date: 2026-10-18 · Status: accepted

## Context

The image is anyone's. The guest has no agent of ours installed, no libc we can count on, and no network path from the host but the tenant bridge. Exec, files and the exit code have to work on every image.

## Decisions

**`briqyard-init` is PID 1, a static musl binary**, passed to the kernel as init from the jail. A dynamically linked init fails with "error -2" before anything prints.

**Configuration arrives on a config drive**: a tar stream on `/dev/vdb` with `config.json` and the boot files, read raw by the init. No MMDS, no kernel command line parsing, no cloud-init. Secrets reach the guest this way and never through an API response.

**Host and guest talk over vsock, port 7421**, a small framed protocol in `briqyard-api`: `exec` (stdin, streamed stdout and stderr, exit code, timeout), `put`, `get`, `ping`, `shutdown`. No SSH, no agent on the tenant network.

**The init reaps with `waitid(WNOWAIT)`.** PID 1 inherits every orphan; a plain `wait` steals the exit status of a command the exec server started. The reaper peeks and reaps only orphans.

**The exit of the main process is one console line**: `[briqyard] exit code=N oom=B requested=R`, then the machine resets, which ends Firecracker. The daemon reads the line and applies the restart policy. The serial console is the machine's log.

**The init builds `/dev`** with `/dev/fd`, `stdin`, `stdout`, `stderr` links (bash's `<(...)` needs them), mounts the data volume at its path, writes `/etc/hosts` and `/etc/resolv.conf`, sets the hostname, configures `eth0` over netlink, then runs the image's entrypoint and command as the image's user.

## Consequences

- One binary to ship per architecture; no per-image agent.
- The protocol is versioned by the init shipped with the daemon: a daemon upgrade is also an init upgrade at the next cold boot.
- `/tmp` is a tmpfs: kept through a resume, lost on a cold boot.
