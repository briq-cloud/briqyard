# Development

briqyard is a Rust workspace. The daemon and the init only run on Linux with KVM; the API
types, the CLI and the unit tests build anywhere.

## On a Linux host with KVM

```bash
apt install zfsutils-linux nftables e2fsprogs build-essential pkg-config
cargo build --release --workspace
```

You also need a Firecracker binary and an uncompressed guest kernel. Firecracker's own CI
publishes both; `hack/fetch-firecracker.sh` downloads the latest release and a matching kernel
into `/usr/local/bin/firecracker` and `/var/lib/briqyard/vmlinux`.

A ZFS pool for the disks. For development, a file-backed one:

```bash
truncate -s 30G /var/lib/briqyard/pool.img
zpool create -o ashift=12 -O compression=lz4 -O atime=off byard /var/lib/briqyard/pool.img
```

Then `sudo briqyardd --config hack/config.dev.yaml`, and `briqyard status`.

## On a Mac

Apple silicon M3 or later with macOS 15 or later can run a Linux VM that has `/dev/kvm`:

```bash
brew install lima
limactl start --name=fc --vm-type=vz --nested-virt --cpus=6 --memory=16 --disk=60 template://ubuntu
```

Inside it, follow the Linux steps (Rust, ZFS, Firecracker). The repository is mounted read-only
in the VM at the same path; `hack/vm.sh` builds there, installs the binaries, writes the systemd
unit and restarts the daemon:

```bash
hack/vm.sh install     # build in the VM, install, restart briqyardd
hack/vm.sh logs        # follow the daemon's log
hack/vm.sh e2e         # install, then run hack/e2e.sh inside the VM
```

Everything under nested virtualization is slower than on a real server; the timings are not a
benchmark.

## Tests

- `cargo test --workspace`: unit tests (extraction and whiteouts, DNS packets, the guest
  protocol, address allocation).
- `hack/e2e.sh`: the end-to-end suite against a running daemon: boot, exec, files, DNS,
  egress, tenant isolation, stop and start, exit codes, Postgres on a volume, an endpoint,
  wake on connect, a fork.

## Layout

```
crates/briqyard-api     the API types and the host–guest protocol (shared by everything)
crates/briqyardd        the daemon: config, state, zfs, netw (bridges, nft, dns), fc, image,
                        guestc (vsock client), machine (the manager), ingress, api
crates/briqyard-init    PID 1 inside the guest
crates/briqyard         the CLI
crates/briqyard-fleet   the orchestrator across hosts
api/openapi.yaml        the API description, served at /v1/openapi.yaml
hack/                   dev VM, e2e, systemd unit, dev config
```
