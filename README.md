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
- **Several servers.** `briqyard-fleet` places tenants across hosts and can add or release hosts
  through a cloud API.

## Layout

| Binary | Runs | Does |
|---|---|---|
| `briqyardd` | on every server, as root | the machines of that server: HTTP API, Firecracker, ZFS, network, ingress |
| `briqyard-init` | inside every microVM, as PID 1 | a static binary: boots the image's command, serves exec and files over vsock |
| `briqyard-fleet` | once | the same API across servers; placement, host provisioning |
| `briqyard` | on your laptop | the CLI |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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
connect, suspend and resume with the processes carrying on, and a fork with its data.

## License

AGPL-3.0. See [LICENSE](LICENSE). Contributions need a signed CLA; see
[CONTRIBUTING.md](CONTRIBUTING.md).
