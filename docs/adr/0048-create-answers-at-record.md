# ADR 0048: A create answers once the machine is recorded; the pull, the disks and the boot follow

Date: 2026-10-29 · Status: accepted; amends ADR 0011 (a create's answer), ADR 0022 (what `/wait` answers at its timeout) and ADR 0044 (what a host counts during a create)

## Context

`POST /v1/machines` answered once the image was pulled, the disks made and the guest booted. Driving the control plane against two real hosts (2026-10-28) showed what that costs:

| Seen | Effect |
|---|---|
| A first pull of a large sandbox image took 502 s | longer than the control plane's request deadline (130 s, three tries): the create failed there while it went on here |
| Four such creates at once | held every create worker of the control plane; every other create, of any image, waited behind them |
| A retry after no answer | found nothing to adopt: the record was written after the pull, so the name was free and the retry waited on the same pull again |

ADR 0011 made the work detached from the request, so the host finished it; the caller still had to hold a connection for it. Kubernetes answers a Pod's create once it is stored (`Pending`); the kubelet pulls (`Pulling`, `Pulled`, `ErrImagePull` events, the container `Waiting` with `ContainerCreating`) and starts it, and a client watches or `kubectl wait`s.

## Decisions

**A create answers 201 once the machine is recorded, in state `creating`.** Before the answer, what can refuse it: the spec (as before), a fork's source or a restore's backup found, the name, an address, the tenant's quota, the pool's room for a volume, and, when it starts, the host's memory. Then the record is written. A task of its own pulls the image (when the host has not built it), makes the disks (a clone, a fork, a restore's receive) and starts it (`starting`, `running`), or leaves it `created` with `start: false`. `creating`, a gerund like `starting`, is Kubernetes's `Pending` with `ContainerCreating`; `pending` is taken, by a PATCH's pending change (ADR 0024).

**Room is taken at the record, not at the boot.** A `creating` machine that will start counts in the host's committed memory (`/v1/status`'s `used`, `memory_pressure`, the next create's admission); its boot's reservation takes it over without counting it twice. A `creating` machine counts no usage: nothing runs. Through the fleet, a create's hold (ADR 0044) ends at the first report after the 201, which now counts the machine: the over-count while a create booted (ADR 0044, "What is left") is gone.

**The wait is `/wait` (ADR 0022), and a timeout says "not yet".** `POST /v1/machines/{id}/wait?for=ready|running&timeout=<s>` (60 by default, 600 at most) answers 200 when the machine is ready (or running), and 409 with the machine in the body otherwise: `not_ready` when the timeout ends while it is on its way (`creating`, `starting`, a restart waiting, running not ready; before, every case but the last answered `not_running`), so the caller waits again; `pull_failed` or `create_failed` when its create failed; `boot_failed` as before; `not_running` when it will not run. `GET` serves a caller that polls.

**A failure leaves the machine in `error` with the reason; nothing is tried again.** `error_reason` names the event that put it there (also on the record): `pull_failed` (the image could not be pulled: a reference that does not exist, credentials refused, a registry that does not answer), `create_failed` (its disks could not be made, its create's start was refused, or the daemon restarted during a fork's or a restore's), `boot_failed`, `start_failed`. `pull_failed` and `create_failed` leave no disks: a start answers 409 `bad_state` saying to destroy it and create again, a fork from it 400. No retry in the daemon, unlike the kubelet's image backoff (10 s doubling to 5 minutes, without end): the daemon cannot tell a name that does not exist from a registry that is down by what the pull answers (a mirror that fails already falls back to the registry, ADR 0036), and a create retried without end would hold the host's memory, taken at its record, for a typo. The caller knows its own budget and retries with a destroy and a create.

**The name is a create's idempotency key.** A create of a name the tenant has answers 409 `conflict` with that machine in the body, so a create sent again after no answer finds the one the first made (and its `metadata` says whether it is the caller's). The record is written before the 201, so the name is taken from the first moment a caller could have been told.

**Pulls take turns; a create of an image already built takes none.** Each create's background work is a task of its own: no pool for a slow pull to starve. Pulls of different images run `PULLS_AT_ONCE` (4) at once, a semaphore around the pull and the build: one slow pull leaves three turns to the others, and four builds extracting at once fit the root disk ADR 0028 sized for builds. Creates of one image share its one build (`image::take`, since ADR 0011). Boots still take their turns (ADR 0009). Four, not the kubelet's default of one pull at a time, which lets one slow pull hold every other image of the node; not unbounded, which lets a burst of new images fill the link and the root disk together.

**The pull runs without the machine's lock; the disks and the start under it.** A destroy during a pull answers at once and the create stops when the pull returns (the image stays on the host, as any built image). Calls that act on a `creating` machine: `GET`, `/wait`, endpoints (the ingress then waits for it as for a wake), `DELETE`; a start or a wake asks its create to start it (its memory taken then, as at a create) and answers it as it is. A PATCH, a stop, an exec, a backup, a snapshot answer 409 `bad_state` until it is made. A hand-over (ADR 0027) waits for creates in their disks or start, as for a start; one still pulling is cut.

**A create from an image cut by a restart of the daemon is taken up at the next start.** Its task is gone with the process (a crash, a hand-over during an upgrade, ADR 0027); the record holds its image and whether it starts, so the next daemon removes its partial disks and runs its create again, the pull included (a build cut halfway is made again; one finished is on the host). Without it, every upgrade would fail every pull in flight and the caller would pay a slow pull twice. A fork's or a restore's create is not: what it was made from is not on the record (`from_source`), so it is `create_failed` ("cut short by a restart of the host's daemon"), its partial disks removed, logged at `warn`: the caller creates again, and there is nothing for a person to do.

**Events.** `pulling` (normal), on the machine, when its create waits for a pull, its own or another create's of the same image; `image_pulled` (ADR 0019, on the host) when the build ends; `pull_failed` and `create_failed` (warning) on the machine. `created`, `forked`, `restored` keep their meaning: its disks are made. A pull failure is logged once at `warn` (the image's or its registry's), a create failure at `error` (the host's).

**The wire stays additive (ADR 0027).** A state, a field (`error_reason`), two codes and three reasons, no field changed. No `?wait=` or blocking form: whoever used it would be back to holding a connection for a pull. The CLI waits on its side (`machine run` calls `/wait` until the machine runs, `--detach` answers at `creating`). With one version of skew, fleet first:

| Caller | Against | What it sees |
|---|---|---|
| The fleet, newer | an older host | the host blocks as before; the fleet forwards both the same |
| A caller that waits after its create (briq's adapter: `POST`, then `/wait`) | a newer host | the answers the blocking create gave, from the `/wait`: running, `boot_failed` with the machine; a slow pull's timeout is `not_ready`, which it reads as a slow boot and waits again on its next attempt; a failed pull is `pull_failed` (it knew a 500), an unknown code: its create ends in error with the reason |
| A caller that reads the create's answer as the outcome | a newer host | `creating`: it must wait |

## Measurements

Dev VM (`fc`, aarch64, 6 vCPUs, the pool encrypted), `hack/e2e.sh`'s create section, three runs; before, the answer came when the machine ran:

| | The create's answer | Then `running` (before: the answer) |
|---|---|---|
| `busybox:1.36.1-musl`, removed from the host first (pulled through the dev mirror) | 0.011–0.061 s | 5.4–6.7 s |
| The same image on the host | 0.013–0.078 s | 3.4–4.9 s |
| A pull that fails (`127.0.0.1:1/…`) | 201, then `/wait` 409 `pull_failed` at once | — |

On a real host the second column is the pull: 502 s for the sandbox image of 2026-10-28, while the answer stays the record's write.

## Consequences

- A create's 201 says nothing about the image: every caller waits (`/wait`) or reads the machine. briq's adapter makes its create job record the machine, wait a bounded step, and hand the rest of the wait to a later run of the job.
- A machine whose create failed stays, in `error` and holding nothing, until it is destroyed.
- A create's reservation is held while its image pulls: a host full of slow pulls refuses new creates (503 `capacity`) as one full of running machines does.
- Open: resuming a fork's or a restore's create after a restart of the daemon (the record would need its source, and a restore's key is served once, ADR 0035); a deadline on a pull other than the 15 minutes a registry may stay silent (`READ_TIMEOUT`); pull turns fair between tenants.
