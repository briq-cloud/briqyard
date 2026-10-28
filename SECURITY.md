# Security

## Reporting

Email security@briq.cloud with what you found and how to reproduce it. We answer within three
working days and say what we will do and when. Do not open a public issue for a vulnerability.

## What briqyard protects, and how

- **Guests from the host and from each other.** Every machine is a KVM virtual machine with its
  own kernel, under Firecracker's minimal device model, run through Firecracker's jailer: a
  chroot per machine holding only its kernel, config drive and block device nodes, a uid of its
  own, a new pid namespace, a cgroup v2, and Firecracker's seccomp filters.
- **Tenants from each other.** One bridge and one /24 per tenant; nftables forwards nothing by
  default and accepts only a tenant's way to the internet through NAT, never to another tenant
  or to the host's private networks; a tenant reaches its gateway's DNS and nothing else of the
  host. Every TAP is pinned to its machine's address (IP and ARP), so a guest cannot send as
  another address. No machine has a public address: the ingress is the only way in.
- **The host's ports from the internet.** The API, the HTTP ingress and the TCP endpoints
  accept connections only from `ingress.allowed_clients` (an nftables rule set the daemon
  renders) and from loopback; the daemon refuses to start on an address the internet could
  reach unless that list is set or `ingress.allow_public` says a firewall of your own does
  it (ADR 0012).
- **The host from images.** Image layers are extracted into a directory the host controls, with
  every path resolved inside it by the kernel (`openat2` with `RESOLVE_IN_ROOT`: symlinks never
  lead outside, the last component is never followed) and device nodes skipped; the disk is built with `mkfs.ext4 -d`. The host never
  mounts a guest filesystem.
- **Secrets.** Environment values reach the guest on its config drive, inside its jail, and are
  never returned by the API.

## What it does not protect yet

- The API speaks plain HTTP with a bearer token: keep it on loopback or a private network, or
  put TLS in front. A daemon's heartbeat carries its API token so the fleet can forward to it:
  the fleet's URL needs the same care.
- The HTTP ingress trusts the first `Host` header and limits neither connections nor their
  rate per client: it is for the router in `allowed_clients`, not for the internet.
- `allowed_clients` is IPv4 only; IPv6 to the daemon's ports is dropped when it is set.
- A tenant spans one host; a WireGuard mesh is planned (`docs/MESH.md`), and will keep the
  same rules with `allowed_clients` as the mesh range.
