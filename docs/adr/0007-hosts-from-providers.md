# ADR 0007: Hosts from providers: dry-run provisioners, bootstrap over SSH, OVH Eco first

Date: 2026-10-20 · Status: accepted

## Context

Capacity is rented servers with KVM. Adding one costs money; it must be an API call we control, repeatable, and never a surprise. Prices read on 2026-10-18 and 2026-10-19: `../research/2026-10-18-microvm-field-guide.md`, section 12.

## Decisions

**A provisioner per provider behind one trait**: `hetzner-robot` (dedicated, monthly), `scaleway` (Elastic Metal, hourly), `ovh` (Eco and Bare Metal, cart order flow, `$1$`+sha1 signed calls), `static` (none). **Every one is `dry_run` unless told otherwise.**

**A server becomes a host in three steps.** `POST /v1/hosts/order` orders it; the fleet polls the provider for its address and runs `hack/bootstrap-host.sh` on it over SSH (script on stdin, fleet URL, host token and a fresh API token in the environment) until it succeeds; the host turns `ready` on its first heartbeat, matched to the order by address. The same script installs a host by hand.

**The autoscaler, when enabled, orders a host when no slot of `slot_mb` is left and releases a provisioned host empty for `idle_grace` above `min_hosts`**, one change a minute, never past `max_hosts`.

**OVH Eco first for capacity, Scaleway for hourly trials.** Per GB of RAM, monthly, excl. VAT: OVH RISE-L 1.17 € (16 cores, 128 GB DDR5, 2 × 960 GB NVMe, 149.99 €), RISE-8 0.74 € before disks (256 GB ECC); Hetzner AX102-1 2.01 € plus 129 € setup; Scaleway EM-I620E 1.18 € (576 GB). OVH's vRack is a free layer-2 network across every region: on OVH a tenant across hosts rides a VLAN instead of the WireGuard mesh. Advance and Scale lines only when a tenant needs the SLA or the 25–50 Gbps private link. OVH's API is the fullest (order cart, install with an SSH key, reboot).

**Memory decides density**: 8 GB kept for the host, 15 % free on top, no memory overcommit, shared vCPUs 4 per hardware thread, performance vCPUs a thread each. An AX102-1 (102 GB usable) runs 128 nano, 51 small, 25 medium or 12 large briqs at once; sleeping briqs cost disk only.

## Consequences

- The OVH provisioner is stub-tested only; nine assumptions about the real API are listed in `OPERATIONS.md` and are verified at the first real order.
- The bootstrap installs the latest Firecracker and a CI kernel unpinned (review finding C4): pin both before the first paid host.
- The first real x86 host is a Scaleway hourly server, by hand, the day the account arrives.
