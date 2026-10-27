# ADR 0025: Placement by region, label selectors, quotas per tenant, logs follow

Date: 2026-10-21 · Status: accepted; amends ADR 0019 (`quota_exceeded`)

## Context

Four Kubernetes features the scope test (`../KUBERNETES-MAP.md`) puts in briqyard: node selectors (a tenant's region), label selectors on listings, ResourceQuota per namespace, and `kubectl logs -f`. Hosts carried a region the placement ignored; machines carried `metadata` nobody could select on; a tenant could fill a host; the CLI followed a console by polling `/logs` every second.

## Decisions

**A create may name a `region`; the fleet places a new tenant only on a host of that region.** `CreateMachineRequest.region` is a host's `region` string as the fleet's `hosts:` or the host's `fleet.region` set it (the control plane passes the code of the tenant's region). No region: any host, as before. No host of the region with room: 503 `capacity`, `no host in region gra has room for this machine`. A PUT that can place a tenant (`/v1/tenants/{id}/gateway`, `/v1/tenants/{id}/quota`) takes the same as `?region=`: a spec is not a place. The daemon ignores the field: a host is in one region, and placing is the fleet's.

**A tenant never spans regions: its region is its host's.** A create naming another region than the host the tenant is pinned to (or a fork's source's host) is 400 `invalid`, `tenant t1 is in region "gra" (host h1), not "vin": a tenant never spans regions`. No second record: the pin is the tenant's place, and a region kept beside it could disagree with it. The fleet's tenant listing shows each tenant's `region`. Unpinning (ADR 0013) is how an operator moves a tenant, to another region too.

**`metadata` is the label map; `GET /v1/machines?label=k=v&label=k` selects.** Equality and existence, every one ANDed; `!=`, `!k` and set-based selectors (`in`, `notin`) are refused by name: a control plane selects by its own ids, and a reconciler that needs more reads the tenant's listing. A selector is checked as Kubernetes checks labels (a key is an optional DNS subdomain prefix and `/`, then a name of at most 63 characters, alphanumeric at both ends, `-_.` inside; a value is empty or a name), 400 otherwise. Metadata itself is not checked: values written before stay, and a `briq_id` is a valid key anyway. Through the fleet the query goes as it came, to the tenant's host or to every host, never partial (ADR 0006). The selector lives in `briqyard-api` (`Label`), shared by the daemon, the fleet's tests and the CLI.

**A quota per tenant, in the daemon: `PUT /v1/tenants/{id}/quota {machines?, memory_mb?, vcpus?, disk_gb?}`.** A field left out is no limit; no quota is none: the daemon has no defaults, the control plane sets the values. `GET` answers `{quota, used}`. The PUT makes the tenant (its network) when it has nothing yet, as a gateway does, so a quota set before the first create is enforced on it and the host lists the tenant. Through the fleet, both go to the tenant's host; a PUT for a tenant with no host places it with no need, in `?region=`.

| Limit | Counts | Checked at |
|---|---|---|
| `machines` | every machine of the tenant, its gateway included | create, fork, restore, gateway put |
| `disk_gb` | the volumes' sizes (a root disk is a clone of an image the host shares) | the same |
| `memory_mb`, `vcpus` | what the tenant's machines in `starting`, `running`, `stopping` reserved | a start's reservation (create, start, wake, restart), under the lock that takes the host's memory; a create that starts checks before making anything |

A refusal is 403 `quota` naming the limit and the use (`tenant t1's quota: memory_mb 1536 of 2048 used, 1024 more asked`) and a `quota_exceeded` warning event with `resource`, `limit`, `used`, `need`: about the machine when one is being started, about the tenant at a create. A quota lowered under the use refuses what comes next and stops nothing, as Kubernetes. 403, not 503: retrying does not help until the tenant frees something or briq raises its plan.

**`GET /v1/machines/{id}/logs?follow=true&since=` streams the console as NDJSON**: the lines after the cursor, then each new one, in the paged answer's shape (`{ts, line}`); `{}` every 30 s, as the events watch; a last error line ends it: `destroyed` when the machine is (it waits on the machine's `destroyed` event, subscribed before the read), `shutdown` when the daemon goes down, each with the cursor to read from. A rotation is crossed as a page crosses it (ADR 0021): the cursor is an offset in the whole console. The writer of a console wakes its followers after each line through a notifier per console directory (`console::grown`), held while a writer or a follower uses it: no polling. Each line is flushed before the writer goes on, so a follower or a page sees a line once it is written, not at the next one. Through the fleet a follow is streamed as a watch is.

## Consequences

- The control plane passes the tenant's region (`region` on a create, `?region=` on a gateway or quota put) and puts each tenant's quota, again whenever it changes.
- The autoscaler still adds a host when no slot is left anywhere, in its provisioner's region: scaling per region is for when a second region has hosts.
- A quota is per host, like the tenant: with a tenant across hosts (`../MESH.md`) it becomes the fleet's to add up.
- A follower costs a task and a wake per line its machine prints; nothing when it is quiet.
- Not built: label selectors on events, top and usage; quotas on endpoints, exec or backups.
