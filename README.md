# briqyard

**Open source Fly Machines for AI agents.** Run any OCI image in a Firecracker microVM on your
own servers, with a durable disk, a private network per tenant, and sleep when idle.

briqyard is the runtime under [briq](https://briq.cloud). It is written in Rust and licensed under
the AGPL-3.0.

> Status: v0, under development. Nothing here is stable yet.

## What it does

- **Any image.** `postgres:16`, `redis:7`, your app: pulled from a registry, turned into a root
  disk once, cloned per machine in milliseconds.
- **A real disk.** A data volume per machine on ZFS, attached with write-back caching so `fsync`
  means what it says. Snapshots and forks are copy-on-write clones.
- **A private network per tenant.** Machines of one tenant reach each other by name; nothing else
  reaches them. No machine has a public address.
- **Sleep and wake.** A machine unused for its sleep window stops and keeps its disks. A
  connection to its endpoint, or a command, wakes it. With a memory snapshot (`--suspend`), the
  wake takes a quarter of a second and the processes carry on where they were.
- **Exec, files, logs.** A command inside the machine with stdin and streamed output, files in and
  out, the serial console as logs.
- **Jailed.** Firecracker runs under its jailer: a chroot, a uid, a pid namespace and a cgroup
  per machine, on top of KVM.
- **Several servers.** `briqyard-fleet` places tenants across hosts and can add or release hosts
  through a cloud API.

## Layout

| Binary | Runs | Does |
|---|---|---|
| `briqyardd` | on every server, as root | the machines of that server: HTTP API, Firecracker, ZFS, network, ingress |
| `briqyard-init` | inside every microVM, as PID 1 | a static binary: boots the image's command, serves exec and files over vsock |
| `briqyard-fleet` | once | the same API across servers; placement, host provisioning |
| `briqyard` | on your laptop | the CLI |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it works, [docs/adr/](docs/adr/) for why, [docs/OPERATIONS.md](docs/OPERATIONS.md) to run a host, [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) to work on it.

## Try it on one machine

You need a Linux host with `/dev/kvm`, ZFS (`zfsutils-linux`), `nft`, `mkfs.ext4`, a guest kernel
and the Firecracker binary. On a Mac with Apple silicon (M3 or later, macOS 15 or later), a Lima
VM with nested virtualization does it; see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

```bash
make                       # cargo build --release; the init is built static (musl)
sudo target/release/briqyardd --config hack/config.dev.yaml
briqyard machine run --image postgres:16-alpine -e POSTGRES_PASSWORD=secret --volume 10G:/var/lib/postgresql/data -p 5432 --sleep 30m
briqyard machine exec <id> -- psql -U postgres -c 'select 1'
briqyard endpoint add <id> 5432          # a TCP port on the host; a connection wakes the machine
briqyard machine fork <id>               # a copy of its disks, taken now, as a new machine
```

What works today, checked by `hack/e2e.sh` on every change: boot in a few seconds, exec with
stdin, exit codes and timeouts, files in and out, names on the tenant's network, egress through
NAT, tenant isolation, stop and start with the disk kept, exit codes and the restart policy,
Postgres on a volume with honest `fsync`, TCP and HTTP endpoints, sleep on idle and wake on
connect, suspend and resume with the processes carrying on, a fork with its data, and backups
to an S3 bucket (whole, then incremental) that restore on any host.

Across servers, checked by `hack/fleet-smoke.sh` and `hack/fleet-two-hosts.sh` (two VMs under
one fleet): tenants placed by free memory and disk, every call forwarded to the right host, a
host that stops answering marked down with its calls refused rather than guessed, hosts
ordered from Hetzner or Scaleway through the API and installed over SSH, retired once empty.

## Numbers

From `hack/e2e.sh` on an Apple M4 inside a Lima VM with nested virtualization (ARM64), so a
real x86 server does better:

| | |
|---|---|
| Create a machine, image already on the host | about 3 s to the machine's init, 6 s with a small image pull |
| Resume from a memory snapshot | 0.15–0.25 s |
| Fork of a Postgres machine with its data | a ZFS clone: instant, then a cold boot |
| Image to root disk (alpine) | 1.2 s |

## License

AGPL-3.0. See [LICENSE](LICENSE). Contributions need a signed CLA; see
[CONTRIBUTING.md](CONTRIBUTING.md).
