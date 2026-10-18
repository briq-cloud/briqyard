# A tenant across hosts: the WireGuard mesh

Today a tenant lives on one host: its machines share a bridge, a /24 and a DNS there, and the
fleet pins the tenant to that host. This is the design for letting a tenant span hosts, kept
small on purpose. Not built yet.

## What has to stay true

- A machine reaches its tenant's other machines by name (`<name>.internal`) and by id, and
  nothing of any other tenant, whatever host either is on.
- No machine has a public address; the ingress is the only way in, on the host that runs it.
- Placement stays per machine: a new machine goes where there is room, a fork where its source
  is (a ZFS clone needs the same pool).
- A host that loses the fleet keeps working for the machines it has.

## The design

**Addresses from the fleet.** A tenant's /24 is allocated by the fleet, not the host, so it is
unique across the fleet (`10.64.0.0/10` still: 16,384 tenants). Each machine's address inside
it is allocated by the host that runs it, from a slice the fleet hands that host for that
tenant (a /26 per host per tenant: 62 machines of one tenant on one host, four hosts per
tenant to start; a tenant that needs more gets a second /24). A daemon without a fleet
allocates as it does today.

**One WireGuard interface per host** (`wg0`, a key made at bootstrap, the public key in the
heartbeat). The fleet hands every host the list of peers: for each other host, its endpoint
and the `AllowedIPs` of the tenant slices it holds. A host adds a peer only for hosts that
share a tenant with it, so a host with ten tenants talks to a few peers, not the whole fleet.
The daemon reconciles the interface from the fleet's answer every heartbeat (`/v1/hosts/mesh`,
a GET that returns the peers for this host) and keeps the last answer on disk.

**Routing.** Each tenant bridge keeps its /24 address on the host; traffic for the tenant's
other slices goes out `wg0` (one route per remote slice, from the peer list). The nftables
table gets one more rule family: forward between `by<n>` and `wg0` only when both addresses
are in the same tenant's /24, and nothing else across `wg0`. The tenant isolation rule set
already drops between tenant ranges on the bridge side; the mesh side mirrors it.

**DNS.** Each host's DNS answers for the machines it runs. For a name it does not have in a
tenant it hosts, it asks the fleet (`/v1/tenants/{id}/names`, cached for its TTL), which
knows every machine of the tenant and its host. A daemon with no fleet answers what it has.

**Sleep and wake.** Wake on connect works on the host that runs the machine: a machine on host
A connecting to a sleeping sibling on host B reaches B's bridge address, where B's wake-on-
connect sees the SYN as it does today. Nothing new.

**The fleet.** Placement no longer pins a tenant: `place` picks the host with the most free
memory and disk among those that already hold a slice of the tenant, then any host, and asks
the fleet for a slice there. The registry keeps `tenant → [(host, slice)]`. A host that goes
down keeps its slice reserved for an hour, then the slice is freed and its machines are
reported as `error` (there is no live migration; the disks are on that host).

## What it costs

A WireGuard hop between two hosts in one data center adds under a millisecond and runs at
line rate on ChaCha20; the kernel module needs nothing installed on Ubuntu 24.04. The fleet
becomes a dependency for a new tenant slice and for cross-host DNS, not for anything running.

## In what order

1. Fleet-allocated tenant /24s and per-host slices (`briqyard-api` types, registry, placement
   test). The daemon takes its slice from the fleet when it has one.
2. `wg0` from the fleet's peer list, routes and the nftables rules; an e2e check with two
   daemons in two VMs on the Mac (Lima runs several).
3. DNS over the fleet.
4. Placement without the pin, and the fork rule.
