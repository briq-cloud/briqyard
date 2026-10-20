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
| [0012](0012-host-exposure-and-forwarding-policy.md) | The host exposes its ports to `allowed_clients` only and refuses a public bind without them; forward drops by default; every TAP pinned to its address |
| [0013](0013-fleet-trust-and-capacity.md) | Fleet: one token per host, capacity reserved at placement, a tenant released by hand |
| [0014](0014-jail-and-snapshots-on-the-pool.md) | Machine files: jails and memory snapshots on the pool, everything the daemon writes for itself alone |
