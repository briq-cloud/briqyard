# briqyard architecture

briqyard runs services for AI agents in Firecracker microVMs on servers you own: any OCI image,
a durable disk, a private network per tenant, sleep when idle and wake on the next use. One
daemon per server (`briqyardd`), an orchestrator across servers (`briqyard-fleet`), a CLI
(`briqyard`) and an init that runs inside every microVM (`briqyard-init`). Rust, one workspace;
the init is a static binary (musl) because the guest has no shared libraries of ours.

Status: v0, in development. The API is not stable yet.

## One server

```
                 HTTP API (:7420)                     TCP / HTTP ingress (:20000-29999, :8080)
                        │                                          │
 ┌──────────────────────┴──────────────────────────────────────────┴─────────────────────┐
 │ briqyardd (root)                                                                        │
 │                                                                                         │
 │  machine manager ── storage (ZFS) ── network (bridge per tenant, TAP per VM, nft, DNS)  │
 │        │                                                                                │
 │  firecracker process per machine ─ serial log ─ vsock to briqyard-init                  │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
          │ tap-<id>              │ zvol root (clone of image)   │ zvol data (the volume)
    ┌─────┴──────────────────────┴──────────────────────────────┴───────┐
    │ microVM: guest kernel + briqyard-init (PID 1) → the image's command │
    └─────────────────────────────────────────────────────────────────────┘
```

### Machines

A machine is one microVM running one OCI image, like a Fly Machine. `POST /v1/machines` takes the
image, command, environment, boot files, size (vCPUs, memory), an optional data volume and its
mount path, the ports the image listens on, and the sleep window. The daemon:

1. pulls the image and turns it into a root disk, once per image digest (`image` package);
2. clones that root disk for the machine (ZFS clone: instant, copy-on-write);
3. makes the data volume (a ZFS zvol with an ext4 filesystem), when asked;
4. gives the machine an address on its tenant's bridge and a TAP device;
5. writes a config drive (a tar archive, read raw by the init: `config.json`, the boot files);
6. starts Firecracker with the kernel, the three drives, the TAP and a vsock, and watches it.

States: `created` → `starting` → `running` → `stopping` → `stopped` → (`starting` again) …
→ `destroying` → gone. A `stopped` machine keeps both disks. `stopped_reason` says why it
stopped: `user`, `idle` (went to sleep), `exit` (its process ended; `exit_code` says how).

### Disks

Every disk is a ZFS zvol in one pool (`byard` by default):

| Dataset | What |
|---|---|
| `byard/images/<digest>` | A root disk built from an image, with a `@base` snapshot |
| `byard/m/<id>/root` | The machine's root disk, a clone of `@base` |
| `byard/m/<id>/data` | The machine's data volume, when it has one |

The root disk outlives restarts and stops, as on Fly. Boot files are rewritten at every cold
start from the config drive, so an edit inside the machine lasts until then. The data volume is
attached with Firecracker's `Writeback` cache mode, so a guest `fsync` reaches the host's disk:
a database on it is as safe as the host's drive. A snapshot is `zfs snapshot`; a fork is a clone
of a snapshot of both disks, taken while the source runs (crash-consistent for the data volume).

The root disk is not mounted by the host, ever: the host writes nothing into guest filesystems.
Image extraction happens once per image into a directory the host controls: layers in manifest
order, whiteouts applied, every path resolved inside the directory (a symlink in a layer never
leads outside, and the last component is never followed, so a rewritten link replaces the link
rather than its target), devices skipped; then `mkfs.ext4 -d` builds the disk.

### Network

One Linux bridge per tenant, one /24 from `10.64.0.0/10` per tenant, the host as gateway (`.1`),
one TAP per machine. nftables masquerades egress and drops traffic between tenants. The daemon
answers DNS on every gateway: `<alias>.internal` follows the machine's alias (what a sibling's
env holds), `<id>.vm.internal` is that exact machine; everything else is forwarded upstream.
The guest configures its interface from the config drive (`briqyard-init`), so the guest kernel
needs no `ip=` support.

No machine has a public address. Something outside reaches a port through the ingress, which is
how sleep works: a connection to a sleeping machine's endpoint starts it, waits for the port and
then proxies. Two kinds of endpoints: a TCP port on the host (Postgres, Redis), and an HTTP host
name on the shared HTTP port (`<endpoint>.<domain>`), both allocated by the API.

### Inside the microVM

`briqyard-init` is PID 1. It mounts `/proc`, `/sys`, `/dev` (plus `/dev/fd` and friends, which
bash's `<(...)` needs), reads the config drive (`/dev/vdb`, a tar stream), mounts the data
volume (`/dev/vdc`) at its mount path (a fresh one gets the image directory's owner and content
and loses `lost+found`, so a database accepts it), writes the boot files, sets the hostname,
`/etc/hosts` and `/etc/resolv.conf`, configures `eth0` over netlink, then runs the image's
entrypoint and command with its environment and user. It listens on vsock port 7421 for the
host: `exec` (a command with stdin, streamed stdout and stderr, exit code, timeout), `put` and
`get` (files), `ping`, `shutdown`. PID 1 inherits every orphan on the system; the init reaps
them with `waitid(WNOWAIT)` and leaves alone the children it waits for itself, so a command's
exit status is never stolen. When the main process exits, the init prints
`[briqyard] exit code=N oom=B requested=R` on the serial console and resets the machine, which
ends Firecracker; the daemon reads the line and applies the restart policy.

### Sleep

Use is an exec, an ingress connection, or an explicit `POST /machines/{id}/touch`. After the
machine's `sleep` window with no use, the daemon stops it (`stopped_reason: idle`). A start, an
ingress connection or an exec on an idle machine wakes it. `sleep: "never"` keeps it on.

A stop can keep a memory snapshot instead (`POST /machines/{id}/stop {"suspend": true}`, or
`suspend_on_sleep: true` for the sleeper): the machine is paused, Firecracker writes its memory
and state next to its run files, and the next start loads them into a fresh Firecracker and
resumes, in about a quarter of a second under nested virtualization, without a boot: processes,
connections and uptime carry on. The snapshot is used once; if it cannot be loaded, the start is
a cold boot. The daemon suspends every running machine when it shuts down, so an upgrade costs
each machine a quarter-second wake on its next use.

## Several servers

`briqyard-fleet` offers the same machine API as a daemon and forwards each request to the host
that runs the machine. It places each tenant on one host: a tenant's machines share a host, so
its private network needs no overlay. Placement picks, among ready hosts under the fill
ceiling, the one with the most free memory; a fork lands where its source is.

Hosts register with their capacity and tenants (`POST /v1/hosts/register`, every 15 s, from
the daemon's `fleet:` configuration) or are listed in the fleet's configuration and polled. A
host silent for a minute is `down`; `POST /v1/hosts/{id}/drain` stops placing on a host. The
registry (hosts, tenant → host, machine → host) is one JSON file.

Provisioners add and release hosts through a cloud API: `hetzner-robot` (dedicated servers,
monthly), `scaleway` (Elastic Metal, hourly), `static` (none). Adding a host costs money, so the
autoscaler runs only when `provisioner.enabled` is set, stays in `dry_run` unless told
otherwise, never passes `max_hosts`, and adds one host at a time: when no ready host has a
slot of `slot_mb` left, it orders one; a provisioned host with no machine for `idle_grace`
and above `min_hosts` is released. A new server is not a host until `hack/bootstrap-host.sh`
has installed briqyardd on it and its first heartbeat arrives.

A WireGuard mesh between hosts, so a tenant can span several, is the next step after that.

## Security

Every machine is a KVM virtual machine: its own kernel, its own memory, three virtio devices and
a vsock. With `jailer` configured (every deployment; only development runs without it), the
daemon launches Firecracker through Firecracker's jailer: a chroot per machine under `jail_dir`
holding only the kernel, the config drive, the machine's block device nodes and its sockets; a
uid and gid of its own (`jail_uid_base` plus its place in the tenant's network, so no two
machines share one); a new pid namespace; a cgroup v2 of its own; and Firecracker's seccomp
filters. The daemon never mounts a guest filesystem. Guests reach only their tenant's bridge,
the gateway's DNS, and the internet through NAT; nothing reaches a guest but the ingress.
Secrets reach the guest on its config drive and never through the API's responses.

The daemon runs as root (ZFS, TAP devices, nftables, mknod in the jails). Its API listens on
loopback unless told otherwise; put it behind TLS or a private network before that.
