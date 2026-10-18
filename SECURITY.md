# Security

## Reporting

Email security@briq.cloud with what you found and how to reproduce it. We answer within three
working days and say what we will do and when. Do not open a public issue for a vulnerability.

## What briqyard protects, and how

- **Guests from the host and from each other.** Every machine is a KVM virtual machine with its
  own kernel, under Firecracker's minimal device model, run through Firecracker's jailer: a
  chroot per machine holding only its kernel, config drive and block device nodes, a uid of its
  own, a new pid namespace, a cgroup v2, and Firecracker's seccomp filters.
- **Tenants from each other.** One bridge and one /24 per tenant; nftables drops traffic between
  tenant ranges and from tenants to the host's private networks; a tenant reaches only the
  internet through NAT, its gateway's DNS, and its own machines. No machine has a public
  address: the ingress is the only way in.
- **The host from images.** Image layers are extracted into a directory the host controls, with
  every path resolved inside it (symlinks never lead outside, the last component is never
  followed) and device nodes skipped; the disk is built with `mkfs.ext4 -d`. The host never
  mounts a guest filesystem.
- **Secrets.** Environment values reach the guest on its config drive, inside its jail, and are
  never returned by the API.

## What it does not protect yet

- The API speaks plain HTTP with a bearer token: keep it on loopback or a private network, or
  put TLS in front. A daemon's heartbeat carries its API token so the fleet can forward to it:
  the fleet's URL needs the same care.
- TCP endpoints bind `ingress.bind` (all interfaces by default): bind a private address or
  firewall the port range when the host has a public address.
- A tenant spans one host; a WireGuard mesh is planned, and will keep the same rules.
