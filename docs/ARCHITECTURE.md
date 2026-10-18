# briqyard architecture

briqyard runs services for AI agents in Firecracker microVMs on servers you own: any OCI image,
a durable disk, a private network per tenant, sleep when idle and wake on the next use. One
daemon per server (`briqyardd`), an orchestrator across servers (`briqyard-fleet`), a CLI
(`briqyard`) and an init that runs inside every microVM (`briqyard-init`).

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
Image extraction happens once per image into a directory the host controls, with every path
checked (`securejoin`), then `mkfs.ext4 -d` builds the disk.

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

`briqyard-init` is PID 1. It mounts `/proc`, `/sys`, `/dev`, reads the config drive (`/dev/vdc`,
a tar stream), mounts the data volume (`/dev/vdb`) at its mount path, writes the boot files, sets
the hostname, `/etc/hosts` and `/etc/resolv.conf`, configures `eth0`, then runs the image's
entrypoint and command with its environment. It listens on vsock port 7421 for the host: `exec`
(a command with stdin, streamed stdout and stderr, exit code, timeout), `put` and `get` (files),
`ping`. When the main process exits, the init prints `[briqyard] exit code=N` on the serial
console and halts; the daemon reads it and applies the restart policy.

### Sleep

Use is an exec, an ingress connection, or an explicit `POST /machines/{id}/touch`. After the
machine's `sleep` window with no use, the daemon stops it (`stopped_reason: idle`). A start, an
ingress connection or an exec on an idle machine wakes it. `sleep: "never"` keeps it on. A
memory snapshot (`suspend`) instead of a stop is planned: Firecracker supports it; the TAP and
vsock must be recreated under the same names on restore.

## Several servers

`briqyard-fleet` offers the same machine API and places each tenant on one host: a tenant's
machines share a host, so its private network needs no overlay. Hosts register with their
capacity (`POST /v1/hosts/register`) and report it on a heartbeat; placement picks the host with
the most free memory among those below a fill ceiling. A full fleet is the signal to add a host.

Provisioners add and remove hosts through a cloud API (`hetzner`, `scaleway`, or `static` for
servers you manage yourself). Adding a host costs money, so provisioning runs only when enabled
and within a configured maximum; it is `dry-run` by default. A host that has been empty for the
grace period and is above the minimum count is drained and released.

A WireGuard mesh between hosts, so a tenant can span several, is the next step after that.

## Security

Every machine is a KVM virtual machine: its own kernel, its own memory, three virtio devices and
a vsock. The daemon runs Firecracker under its `jailer` (chroot, namespaces, cgroups, seccomp)
when `jailer` is configured, and plain otherwise (development). Guests reach only their tenant's
bridge, the gateway's DNS, and the internet through NAT. Secrets reach the guest on its config
drive and never through the API's responses.
