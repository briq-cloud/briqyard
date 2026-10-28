# ADR 0011: Transitions run detached from the request; a boot the image fails is 409 `boot_failed`

Date: 2026-10-20 · Status: accepted; amended 2026-10-28 (a command that exits at once is an exit, not a failed boot)

## Context

The review of 2026-10-20 found two things in how the daemon answers the control plane.

axum drops a handler's future when the client closes the connection. Every transition ran inside that future, so a create whose caller timed out (the provider gives it 130 s; a first pull of a large image takes longer) was cut wherever it was: an image build's `Notify` left in the map, so every later create of that image waited forever; a Firecracker running with its record still `starting`; an entry with no record, its name taken until the next restart.

A guest that never came up, or exited while booting, answered 500 `internal`. The provider turns every 5xx into `ProviderUnavailableError`; the control plane keeps the pending state, retries the create, and logs the failure as ours. A `create` with `start: true` answered 201 with `state: error` while a `start` of the same machine answered 500: two answers for one event.

## Decisions

**A transition is a task the request waits on.** `detached(fut)` spawns the work and awaits its join handle; every handler that moves a machine (create, start, wake, stop, destroy, backup, snapshot, image and tenant removal) goes through it. A dropped request drops the wait, never the work. No queue: the per-machine `tokio::sync::Mutex` already orders transitions, and a second request for the same machine waits on it as before. A panic in the task is a 500.

**A boot the image fails is `boot_failed`, HTTP 409.** `MError::BootFailed` carries the machine, left in state `error` with the console's last lines in `error`, and the body repeats it as `machine`. The process is ended under the machine's lock, so the watcher finds nothing to settle and no restart policy applies: a bad image fails once, not four times. `create` with `start: true` answers the same 409 a `start` would; the machine stays for the caller to read and destroy. The daemon logs it at `warn`: the image's fault is not an operator's page. The host's own faults (network, disk, Firecracker refusing) stay 500 `internal`.

**`capacity` stays 503.** The host has no room now and may later; the control plane's retry is the right reaction.

What the control plane does with each code: `boot_failed` → the briq ends in `error`, with the console tail, and the agent is told (a `MachineNotRunningError`, not a retry); `capacity` → the job keeps its pending state and tries later, and the fleet places the next machine elsewhere; `internal`, a timeout or a connection failure → `ProviderUnavailableError`, retried.

## Consequences

- A request that times out at the client still completes on the host; the client reads the result with `GET` or `/wait`, which now blocks on the machine's state changes instead of polling.
- `ApiError` has an optional `machine`; the provider reads it on `boot_failed`.
- The fleet forwards the status and body as they are; it needs no change.
- Reopen when a transition must be cancelled on purpose (a long image pull the caller gave up on): that would be a request of its own, not a dropped connection.

## Amended 2026-10-28

**A boot fails only when the init never started the main process.** When the process ends before the first pong, the host reads the init's exit report: `started` (with the init's version) means the boot came up and the exit settles as any later one (`stopped`, reason `exit`, the restart policy); no report, or the init's own 125/126/127, is `boot_failed`. The machine's `error` is then the init's reason from the report (`start "/run.sh": Operation not permitted (os error 1)`), or the console's last lines from an init older than it. The init answers ping only once the main process runs, so either order gives the same result. A root disk older than the field keeps the old answer until its image changes.
