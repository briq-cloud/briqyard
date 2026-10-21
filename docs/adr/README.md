# Architecture decision records

One file per decision, numbered, never rewritten: a changed decision is a new ADR that supersedes the old one. Research and measurements that drove a decision are in `../research/`, linked from the ADR.

Format: `# ADR NNNN: Title`, `Date · Status`, `## Context` (the problem, in a few lines), `## Decisions` (each one bold, then why), `## Consequences` (what it costs, what it rules out, when to reopen).

| ADR | Decision |
|---|---|
| [0001](0001-own-runtime-on-firecracker.md) | A runtime of our own: Firecracker, a daemon per host, Rust, AGPL |
| [0002](0002-disks-on-zfs.md) | Disks: ZFS zvols on the host's NVMe, Writeback, an image to a root disk once |
| [0003](0003-tenant-network.md) | Network: a bridge and a /24 per tenant, nftables, the host's DNS, the ingress as the only way in |
| [0004](0004-guest-init-and-vsock.md) | The guest: a static init, a config drive, vsock for exec and files |
| [0005](0005-sleep-and-suspend.md) | Sleep: stop on idle, wake on connect, a memory snapshot for a quarter-second resume |
| [0006](0006-fleet-tenant-per-host.md) | Fleet: a tenant on one host, calls forwarded, listings never partial |
| [0007](0007-hosts-from-providers.md) | Hosts from providers: dry-run provisioners, bootstrap over SSH, OVH Eco first |
| [0008](0008-backups-zfs-send.md) | Backups: ZFS streams to an object store, incremental, restore is a create |
| [0009](0009-load-controls.md) | Load: boots take turns, a tag's digest is remembered |
| [0010](0010-testing.md) | Testing: unit tests with fakes, shell suites in `hack/`, a stress driver with invariants |
| [0011](0011-transitions-as-tasks-and-error-codes.md) | Transitions run detached from the request; a boot the image fails is 409 `boot_failed`, not 500 |
| [0012](0012-host-exposure-and-forwarding-policy.md) | The host exposes its ports to `allowed_clients` only and refuses a public bind without them; forward drops by default; every TAP pinned to its address |
| [0013](0013-fleet-trust-and-capacity.md) | Fleet: one token per host, capacity reserved at placement, a tenant released by hand |
| [0014](0014-jail-and-snapshots-on-the-pool.md) | Machine files: jails and memory snapshots on the pool, everything the daemon writes for itself alone |
| [0015](0015-egress-policy.md) | Egress per machine: open, via a gateway machine, or none; enforced on the host, never by the guest |
| [0016](0016-tenant-gateway.md) | A tenant's gateway is a machine of the daemon: declared on the tenant, named by `via: gateway`, running while something needs it |
| [0017](0017-usage-not-costs.md) | briqyard reports usage per machine in hourly buckets (compute, disk, object storage, network); costs live in briq |
| [0018](0018-egress-limits.md) | Egress limits per machine (blocked ports, a connection rate, a bandwidth cap) on its internet traffic, in nftables, host defaults with per-field overrides; drops counted |
| [0019](0019-events-watch-versions.md) | An event log per host (closed reasons, `seq` per host), a watch from a cursor, and a version on every machine checked by `If-Match` |
| [0020](0020-api-tls.md) | The daemon's API serves TLS with a self-signed certificate made once; the fleet pins its SHA-256, read at bootstrap over the pinned SSH connection |
| [0021](0021-metrics-and-conditions.md) | Per-machine series on `/metrics` from the tick, host conditions (memory and disk pressure) that keep the fleet off a host, image removal under disk pressure, the console rotated by size, `top` from the last two ticks |
| [0022](0022-probes.md) | Probes in the daemon (startup, readiness, liveness: exec, TCP, HTTP), a `ready` that `/wait`, the ingress and the gateway follow, and a restart backoff doubling to 5 minutes |
| [0023](0023-scheduled-backups.md) | Backups on a schedule per machine (`every`, `keep`), run by the daemon's tick; every `keep`-th backup whole and whole chains pruned; delete; a destroyed machine's backups kept, listed and counted for `keep_destroyed_days` |
| [0024](0024-changes-at-next-boot.md) | A PATCH of the image, command, env, files, size, ports or restart is kept as `pending` and applied at the next start: a new image re-clones the root disk, the volume stays, a memory snapshot of the old spec is dropped; `POST /restart` applies it now |
| [0025](0025-scheduling-labels-quotas-logs.md) | Placement within a create's region, a tenant never across regions; `?label=` selectors on listings; quotas per tenant checked at create and at a start's reservation; logs followed as NDJSON |
| [0027](0027-host-upgrade-and-version-skew.md) | Every binary and the init say `0.1.0+<commit>`; the wire is additive; SIGUSR2 hands the machines over to the next daemon, a stop suspends them and the next start boots them again; `host upgrade` runs the bootstrap script with a release and waits for the new version; drain is not retire |
