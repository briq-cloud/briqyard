# ADR 0022: Probes in the daemon: startup, readiness, liveness; `ready`; a capped restart backoff

Date: 2026-10-21 · Status: accepted

## Context

A machine is `running` once its init answers on vsock (ADR 0004), which says nothing of the program: Postgres takes seconds to accept, a web app minutes to warm up. briq runs its healthcheck from the control plane (`BriqyardProvider.waitReady`: `/wait`, then an exec every `intervalMs` until `timeoutMs`), the ingress proxies as soon as a TCP connect succeeds, and nothing notices a program that hangs while its process lives. The restart backoff is linear (the attempt's number in seconds) and never resets. Kubernetes has all of this in the kubelet; the scope test (`../KUBERNETES-MAP.md`) puts it here, and the advisor decided "probes run in the daemon and briq's healthcheck moves onto them".

## Decisions

**A probe is Kubernetes's, one action each.** On create and PATCH, `probes: { startup?, readiness?, liveness? }`:

```json
{"probes": {
  "startup":   {"tcp": 5432, "period_sec": 2, "failure_threshold": 30},
  "readiness": {"http": {"port": 8080, "path": "/healthz"}},
  "liveness":  {"exec": ["test", "-f", "/tmp/alive"], "period_sec": 10, "timeout_sec": 5,
                "failure_threshold": 3, "success_threshold": 1, "initial_delay_sec": 0}
}}
```

Exactly one of `exec` (argv, through the guest's exec, exit 0 passes), `tcp` (a connect from the host to the machine's address), `http` (a GET from the host, 200–399 passes; `path` defaults to `/`; a 40-line HTTP/1.1 client, no dependency). Defaults: `period_sec` 10, `timeout_sec` 5, `failure_threshold` 3, `success_threshold` 1, `initial_delay_sec` 0. Refused with the field named (`probes.liveness.success_threshold: must be 1`): no action or two, an empty argv, port 0, a path that is not `/…` printable ASCII, a period, timeout or threshold of 0, a `success_threshold` other than 1 on startup or liveness (as Kubernetes). A restore takes the backup's probes unless the request sets some; a PATCH replaces the whole set.

**What gates what.** The startup probe runs first; readiness and liveness start once it passed (or at once without one), each on its own period from its `initial_delay_sec`. `ready` is false until the machine is `running`, then true at once without a startup or a readiness probe, else after the startup probe passed (no readiness probe) or the readiness probe passed `success_threshold` times in a row; it goes false after `failure_threshold` failures in a row. `failure_threshold` liveness failures in a row end the process (the guest asked to stop, 10 s, then killed) and count as a failure for the restart policy whatever the exit code: `on-failure` and `always` restart it, `no` leaves it `stopped (exit)`.

**A startup probe that fails ends the boot or the run, by who started it.** A run a caller asked for (create, start, wake: the ingress's and the gateway's included) whose startup probe fails `failure_threshold` times is a boot that failed (ADR 0011): the process ended, the machine in `error` with the last result and the console tail, no restart; a `/wait` on it answers 409 `boot_failed` with the machine. A run the restart policy started, or one adopted from a previous daemon, ran before: its startup failure is a crash, ended and restarted by the policy like a liveness failure. A bad image fails once; a crash loops with the backoff below.

**One task per running machine with probes, in `machine/probes.rs`.** Spawned when the machine becomes `running` (a boot, a resume, an adoption), ended when its process does (the task watches `exited`), replaced when a PATCH changes the probes of a running machine (the run starts over as at a boot: statuses cleared, `ready` recomputed). The result of each probe and the consecutive failures are in the machine's view (`probes_status`), in memory: a daemon restart runs them again. A probe is not use: it never moves `last_used_at`, so probes never keep a machine awake.

**Probe executions take a turn: 32 at once per host** (`PROBES_AT_ONCE`, a semaphore), the timeout counted once the turn is held: a probe that waits is late, never failed. 200 machines with a readiness and a liveness probe every 10 s are 40 executions a second, each a few milliseconds over vsock or a local connect: under one at a time on average. The bound is for the burst after a daemon restart (every adopted machine probes at once) and for slow probes, which hold a turn up to their timeout.

**Events** (ADR 0019's closed list, now 27):

| Reason | Type | When | `data` |
|---|---|---|---|
| `ready` | normal | `ready` went true through a probe (a machine without probes is ready with `started`) | `probe` |
| `not_ready` | warning | the readiness probe failed `failure_threshold` times in a row, or a PATCH of the probes reset it | `probe`, `failures` |
| `liveness_failed` | warning | liveness failed `failure_threshold` times in a row: the process is ended; `exited` and `restarting` follow | `failures` |
| `startup_failed` | warning | startup failed `failure_threshold` times in a row | `failures`, `boot` (true: the boot failed; false: ended for the policy) |
| `crash_loop` | warning | the third restart, and each one after it, with no run of 10 minutes between | `restarts`, `delay_sec` |

**Who waits on `ready`.** `POST /v1/machines/{id}/wait` waits for `ready` (`?for=running` keeps the old meaning): 200 when ready; 409 `not_ready` with the machine (its `probes_status`) when the timeout ends while it runs not ready; 409 `boot_failed` with the machine when it is in `error`; 409 `not_running` when it will not run. The ingress waits for `ready` before it proxies a connection, woken or not, within the wake timeout (`boot_timeout_sec` + 30 s, ADR 0009): readiness gates traffic. The tenant's gateway (ADR 0016) takes `probes` too; a start that needs it waits for its `ready` when it has a startup or readiness probe, else for its port as before, within `boot_timeout_sec`, and a gateway that is not ready by then is ended and left in `error`. Create and start still answer at `running`, as `kubectl apply` does not wait: callers wait.

**The restart backoff doubles: 10 s, 20 s, 40 s, 80 s, 160 s, then 300 s**, Kubernetes's CrashLoopBackOff. The step is `recent_restarts`, the restarts since the last run that lasted 10 minutes; a run of 10 minutes resets it at its exit. The view says `restarting_at` while it waits. `max_retries` keeps its meaning: `on-failure` restarts while `restarts` (in a row, reset only by an exit the policy does not restart) is under it; a 10-minute run resets the backoff, not the count, as Docker does.

**briq's healthcheck moves onto probes.** `BriqyardProvider` (up-lab/briq#250) changes as follows; the daemon side is built.

1. `machineBody` adds, when `spec.healthcheck` is set (`period = max(1, ceil(intervalMs / 1000))`):
   `probes: { startup: { exec: healthcheck.cmd, period_sec: period, timeout_sec: 10, failure_threshold: max(1, ceil(timeoutMs / (period × 1000))) }, readiness: { exec: healthcheck.cmd, period_sec: 10, timeout_sec: 10 } }`.
   The startup probe is the timeout part (it fails the boot after about `timeoutMs`); readiness keeps gating the router's traffic after each wake.
2. `waitReady` is one call: `POST /wait?timeout=<ceil(timeoutMs/1000) + 30, at most 600>`, with the client's timeout 10 s over that. 200: ready. 409 `boot_failed`: the startup probe failed; throw `HealthcheckTimeoutError(cmd, last = machine.probes_status.startup.message)`, or `BootFailedError` when `probes_status.startup` is absent (the guest itself did not come up). 409 `not_ready`: `HealthcheckTimeoutError` with `probes_status.readiness.message`. 409 `not_running`: `MachineNotRunningError` as today. The exec loop goes.
3. Without a healthcheck, `/wait` answers at `running`, as now.

## Consequences

- briq drops its polling exec: one request per create instead of one every `intervalMs`, and the router's traffic waits for the program, not only for the port.
- A readiness probe delays every connection to a machine that is not ready by up to the wake timeout, then 502: a machine with one replica has nowhere else to send it. Groups behind one name would route around it (`../KUBERNETES-MAP.md`, later).
- Probe results are not persisted: after a daemon restart a machine with a readiness probe is not ready until it passes again.
- A crash loop costs at most one boot every 5 minutes per machine.
- A probe from the host reaches a `none` or `via` machine too (the host is the tenant's router); a TCP or HTTP probe needs the program to listen on the machine's address, not only on `127.0.0.1`; an exec probe does not.
- Not built: gRPC probes, probe events on endpoints, a `terminationGracePeriod` of the machine's own for a liveness kill (10 s, as a stop's default).
