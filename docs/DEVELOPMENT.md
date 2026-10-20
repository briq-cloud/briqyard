# Development

briqyard is a Rust workspace. The daemon and the init only run on Linux with KVM; the API
types, the CLI and the unit tests build anywhere.

## On a Linux host with KVM

```bash
apt install zfsutils-linux nftables e2fsprogs build-essential pkg-config
cargo build --release --workspace
```

You also need a Firecracker binary and an uncompressed guest kernel. Firecracker's own CI
publishes both; `hack/bootstrap-host.sh` downloads the latest release and a matching kernel
into `/usr/local/bin/firecracker` and `/var/lib/briqyard/vmlinux` (and does everything else a
host needs: run it on a fresh server).

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

### Two hosts on the Mac

A second VM is a second host, so the fleet's placement, forwarding and host-down path run
for real. Lima's `vzNAT` network isolates each VM (VMs reach the Mac at 192.168.64.1, not each
other; `socket_vmnet` would fix that but needs root), so the VMs talk through ports the Mac
forwards on every interface: in `~/.lima/fc/lima.yaml`, before `vmType: vz`,

```yaml
portForwards:
- {guestPort: 7420, hostIP: 0.0.0.0, hostPort: 7420}
- {guestPort: 7430, hostIP: 0.0.0.0, hostPort: 7430}
networks:
- vzNAT: true
```

then `limactl stop fc && limactl start fc`. The second VM, with the daemon's port forwarded as
27420 the same way, is installed from the binaries `hack/vm.sh` built (copied out with
`limactl copy` into `bin/`) by the bootstrap script, and registers with the fleet:

```bash
limactl start --name=fc2 --vm-type=vz --nested-virt --cpus=2 --memory=6 --disk=30 --network=vzNAT template://ubuntu
limactl shell fc2 sudo bash -c 'cd /Users/uplab/projects/briqyard && BRIQYARD_POOL_FILE_GB=15 BRIQYARD_TOKEN=fc2-token \
  FLEET_URL=http://192.168.64.1:7430 ADVERTISE=http://192.168.64.1:27420 bash hack/bootstrap-host.sh'
cargo build --release -p briqyard   # the CLI, on the Mac
PATH=target/release:$PATH BRIQYARD_URL=http://127.0.0.1:7430 \
  SECOND_HOST_STOP="limactl shell fc2 sudo systemctl stop briqyardd" \
  SECOND_HOST_START="limactl shell fc2 sudo systemctl start briqyardd" hack/fleet-two-hosts.sh
```

## Tests

- `cargo test --workspace`: unit tests, which run anywhere (extraction and whiteouts, DNS
  packets, the guest protocol, address allocation, the store, the configuration, the ZFS
  backend against a fake `zfs`, the Firecracker and guest clients against in-test sockets,
  the config drive, restart and sleep decisions).
- `hack/e2e.sh`: the end-to-end suite against a running daemon: boot, exec, files, DNS,
  egress, tenant isolation, stop and start, exit codes, Postgres on a volume, an endpoint,
  sleep on idle, wake on connect, a fork, suspend and resume, the HTTP ingress, a daemon crash,
  backups to a directory store and a restore. 54 checks.
- `hack/fleet-smoke.sh`: the same flow through a fleet (`hack/fleet.dev.yaml` fronts the local
  daemon in the VM, a dry-run provisioner for order and retire). 19 checks.
- `hack/stress.py` with `hack/stress-invariants.sh`: N tenants through every feature in parallel,
  a daemon SIGKILL, host invariants between phases (ADR 0010). `--tenants 6 --per-tenant 4 --rounds 2 --crash`.
- `hack/fleet-two-hosts.sh`: a fleet with two hosts: tenants placed on different hosts, calls
  forwarded to each, a host that stops answering marked down with its tenant's calls refused
  (`host_down`) and its listings refused rather than partial, while the other host goes on, and the host back. 16 checks.

## Layout

```
crates/briqyard-api     the API types and the host–guest protocol (shared by everything)
crates/briqyardd        the daemon: config, state, zfs, netw (bridges, nft, dns), fc, image,
                        guestc (vsock client), machine (the manager), ingress, api
crates/briqyard-init    PID 1 inside the guest
crates/briqyard         the CLI
crates/briqyard-fleet   the orchestrator across hosts
api/openapi.yaml        the API description, served at /v1/openapi.yaml
hack/                   dev VM, systemd units, dev configs, the shell suites, the stress driver
docs/adr                every technical decision; docs/research the numbers behind them
```
