# ADR 0042: No autoscaler in the fleet: signals for an external scaler

Date: 2026-10-28 · Status: accepted; supersedes ADR 0007's provisioners, orders and autoscaler (removed in a second change, below)

## Context

The fleet orders and releases servers itself (ADR 0007): a provisioner per provider (`hetzner-robot`, `scaleway`, `ovh`), `POST /v1/hosts/order`, a release at the provider on retire, and an autoscaler loop that orders a host when no slot of `slot_mb` is left. That puts each provider's API, its credentials and the decision to spend money inside the runtime, and every provider added is code in the fleet.

Kubernetes has no node autoscaler in its core. The scheduler leaves a pod it cannot place `PodScheduled=False` with reason `Unschedulable`, emits a `FailedScheduling` event, and counts it (`scheduler_schedule_attempts_total{result="unschedulable"}`, `scheduler_pending_pods{queue="unschedulable"}`). Separate projects read those signals and add nodes: the Cluster Autoscaler (one implementation per cloud) and Karpenter. Joining a node (`kubeadm join`) is core; buying one is not.

Before this change the fleet's only capacity signal was a 503 `capacity` answer and the totals of `GET /v1/status`. It had no `/metrics`.

## Decisions

**The fleet places, refuses and says why; something outside it buys servers.** An external scaler (the operator's own, or a script) reads the signals below, buys a server where it sees fit, and adds it with `briqyard host add`. The fleet never calls a provider's API.

**Every refusal for want of room is counted by what ran out.** Where placement refuses (503 `capacity`), the fleet names the resource:

| `resource` | When | A new host fixes it |
|---|---|---|
| `memory` | A new tenant: no host of the region is ready and under its fill ceiling with the memory free (no host at all included), or those with the room are under `memory_pressure` | yes |
| `disk` | A new tenant: hosts have the memory, none the disk (a volume plus 2 GB), or those with both are under `disk_pressure` | yes |
| `pressure` | The host the create is bound to (a pinned tenant's, a fork's source's) is under a condition (ADR 0021) | no: the tenant's machines stay on its host (ADR 0006), so that host must be freed |

A host under a condition is short of what its condition names, so a new tenant refused for it counts as `memory` or `disk` (the condition of the host with the most memory free among those with the room). That keeps the scaler's rule to one line: `memory` or `disk` grew, add a host in the region. A host's own refusal (its answer passes through, ADR 0013) is not counted: a host the fleet thought had room, or a pinned tenant's, and the daemon does not say which resource.

**The signals, on the fleet's `GET /metrics`** (Prometheus text, written as the daemon's, the helpers shared in `briqyard_api::metrics`):

| Series | Labels | What |
|---|---|---|
| `briqyard_fleet_hosts` | `state` | hosts in the registry (`ready` always present) |
| `briqyard_fleet_free_mb` | `resource="memory\|disk"`, `region` | free on the region's hosts that take a new tenant (ready, under the fill ceiling, no condition), summed |
| `briqyard_fleet_largest_slot_mb` | same | the most free on one of them: the largest machine the region still takes |
| `briqyard_fleet_unschedulable_total` | `resource="memory\|disk\|pressure"`, `region` | refusals since the fleet started |

Every region a host is in has every series, zeros included, so `increase()` works from the first scrape. A region asked that no host is in counts as `region="other"`: a caller's typo never makes a new series. `/metrics` takes the API's token, or `metrics_token` when set (then only it), and none on a loopback listener with `tls` unset: the daemon's rule (ADR 0021).

**The same numbers elsewhere.** `GET /v1/status` gets `regions` (additive, ADR 0027): per region `free`, `largest_slot` (`memory_mb`, `disk_mb`) and `unschedulable` (`memory`, `disk`, `pressure`). `briqyard host ls` prints them under the hosts. Each refusal is a `warn` line, `unschedulable`, with `resource`, `region`, `tenant`, `host` (a pinned one), the ask (`memory_mb`, `disk_mb`) and the region's largest slot (`largest_memory_mb`, `largest_disk_mb`), for log-based alerts.

**The counters live in memory.** A restart resets them, which Prometheus counters allow. Nothing is persisted: the gauges are read from the registry at each scrape.

## The second change: what goes, what stays

This change only adds the signals. The next one removes the autoscaler:

| Goes | Stays |
|---|---|
| the `scaler()` loop, `ScalePolicy`, `registry::decide` | `host add` with the SSH bootstrap and its key pinning (ADR 0020, 0028) |
| `provisioner.{enabled, dry_run, kind, min_hosts, max_hosts, slot_mb, idle_grace}` | `drain`, `undrain`, `retire`, `host rm` |
| the `hetzner`, `scaleway` and `ovh` modules of `provision.rs` | `host upgrade` (ADR 0027) |
| `POST /v1/hosts/order`, `briqyard host order` | placement, conditions, the signals above |
| releasing a server at its provider | |

`provisioner.bootstrap` becomes a top-level `bootstrap:`. `retire` still takes a host out once it is empty; giving the server back to its provider is the operator's (or the scaler's).

## Consequences

- Scaling needs a component outside briqyard. A minimal one is an alert on the signals (`OPERATIONS.md`) and a person who runs `host add`.
- No provider code, credentials or spending decision in the runtime; a new provider is the scaler's concern.
- The fleet cannot tell a scaler how big a host to buy. `largest_slot_mb` against the largest machine size the control plane offers says when one is needed; the size is the scaler's choice.
- `pressure` is for a person (free the host, or move the tenant), not for a scaler.
