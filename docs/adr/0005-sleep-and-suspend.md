# ADR 0005: Sleep: stop on idle, wake on connect, a memory snapshot for a quarter-second resume

Date: 2026-10-19 · Status: accepted; amended by ADR 0027 (a stop's machines are booted again at the next start; a snapshot resumes only under the Firecracker and host kernel that took it; SIGUSR2 hands the machines over) and by ADR 0052 (a connection is use until it reaches the program)

## Context

The control plane's rule: one `sleep` window, use is an API call or ingress traffic, a sleeping machine keeps its disk and frees its compute, the next use wakes it. The runtime has to make that cheap enough that a wake feels like nothing.

## Decisions

**Use is an exec, an ingress connection or `POST /machines/{id}/touch`.** After the window with no use the daemon stops the machine with `stopped_reason: idle`. A start, a connection or an exec wakes it. `sleep: "never"` keeps it on. `PATCH` changes the window in any state without a restart.

**A stop can keep a memory snapshot** (`suspend: true`, or `suspend_on_sleep`): pause, write memory and state beside the run files, and the next start loads them into a fresh Firecracker. Measured on the Mac under nested virtualization: resume in 0.15–0.25 s, processes, connections and uptime carried on. A cold boot is about 3 s.

**The snapshot is used once.** If it cannot be loaded, the start is a cold boot. A stale snapshot is never a reason to fail a start.

**The daemon suspends every running machine when it shuts down**, so an upgrade costs each machine a quarter-second wake on its next use. A daemon killed hard leaves its machines running (`KillMode=process`) and the next daemon adopts them by pid, name and API socket.

**Exec wakes by default** (`wake: false` to refuse): a sleeping machine answering a command is the product, not an error.

## Consequences

- A suspend costs the machine's memory in disk, on the pool (ADR 0014).
- The snapshot ties the machine to the host's Firecracker and CPU: it is never sent anywhere.
- Firecracker's VMClock (1.15) tells the guest it was restored; clocks and random numbers after a resume are the guest's problem, as on every platform.
