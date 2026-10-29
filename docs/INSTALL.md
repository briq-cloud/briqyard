# Install

## What you need

- A Linux server, x86_64 or arm64, with KVM: `ls /dev/kvm` lists it.
- Ubuntu Server 26.04 (every test suite runs there; 24.04 is untested).
- A disk for the pool, or free space on the OS's disks: a partition is made in it.
- A release: each carries the binaries for both architectures and their checksums (`SHA256SUMS-x86_64`, `SHA256SUMS-aarch64`).

## One host

As root on the server:

```bash
curl -fsSLO https://raw.githubusercontent.com/briq-cloud/briqyard/main/hack/bootstrap-host.sh
BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.2 \
BRIQYARD_POOL_DEVICE=/dev/nvme1n1 \
BRIQYARD_TOKEN=$(openssl rand -hex 24) \
ALLOWED_CLIENTS=203.0.113.0/24 \
bash bootstrap-host.sh
```

The script:

1. installs ZFS and nftables, caps the ZFS cache and turns swap off;
2. makes the encrypted pool on the device (on a file when `BRIQYARD_POOL_DEVICE` is not set, for a trial);
3. downloads Firecracker, the jailer and a guest kernel, and checks each against its pinned digest;
4. installs the briqyard binaries, each checked against the release's checksums;
5. writes `/etc/briqyard/config.yaml` and the systemd unit, and starts `briqyardd`.

Run it again with another release to upgrade: the running daemon hands its machines over to the new one, and nothing stops.

| Variable | Meaning |
|---|---|
| `BRIQYARD_RELEASE` | Where the binaries come from. Unset, they are read from `./bin` (built with `make`) |
| `BRIQYARD_POOL_DEVICE` | One device, or two comma-separated for a mirror. A device already in use is refused: nothing is overwritten |
| `BRIQYARD_TOKEN` | The API's token: what the CLI and a control plane present |
| `ALLOWED_CLIENTS` | Comma-separated networks that may reach the API and the endpoints. Without it (or `PRIVATE_ADDRESS`, or `ALLOW_PUBLIC=1`), both listen on loopback only, in plain HTTP |
| `PRIVATE_ADDRESS`, `PRIVATE_INTERFACE` | Put the API and the endpoints on a private network, and close the public interface to all but SSH (and `PUBLIC_TCP_PORTS`) |

Every variable: [OPERATIONS.md, Install](OPERATIONS.md#install).

**Keep the pool's key.** Without a fleet, the key is `/etc/briqyard/pool.key`: keep a copy off the host, the pool is unreadable without it. With a fleet, the fleet holds it.

**Check it.** Off loopback, the API serves TLS with a certificate of its own; the script prints its fingerprint. From a computer in `ALLOWED_CLIENTS`:

```bash
export BRIQYARD_URL=https://<host>:7420 BRIQYARD_TOKEN=<token> BRIQYARD_TLS_FINGERPRINT=<fingerprint>
briqyard status
```

On the host, `briqyard doctor` checks KVM, ZFS, nftables, Firecracker and the kernel, one line each, and warns about what would restart the daemon or the host on its own.

## Several hosts

Run `briqyard-fleet` on one server ([OPERATIONS.md, A fleet](OPERATIONS.md#a-fleet)), then add each server by its SSH address. The fleet runs `bootstrap-host.sh` over SSH, gives the host its pool key, and pins its SSH key and API certificate. The host turns `ready` at its first heartbeat.

```bash
export BRIQYARD_URL=https://<fleet> BRIQYARD_TOKEN=<the fleet's token>
briqyard host add <ssh address> --address <API address> --region <region>
briqyard host ls
briqyard host upgrade <id> --release <version or URL>   # drained, upgraded, back; its machines keep running
```

The fleet buys no server. When a create finds no room, it says where and what ran out on its `/metrics` ([OPERATIONS.md, Capacity signals](OPERATIONS.md#capacity-signals-adr-0042)); you, or a scaler of yours, buy a server and add it.

A first dedicated server with a private network, step by step: [OPERATIONS.md, First OVH host](OPERATIONS.md#first-ovh-host).

## On a Mac, for development

Apple silicon (M3 or later, macOS 15 or later) runs a host in a Lima VM with nested virtualization, with the test suites: [DEVELOPMENT.md](DEVELOPMENT.md).
