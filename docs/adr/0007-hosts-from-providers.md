# ADR 0007: Hosts from providers: dry-run provisioners, bootstrap over SSH, OVH Eco first

Date: 2026-10-20 · Status: accepted; superseded in part by ADR 0042 (the provisioners, `host order`, the release at the provider and the autoscaler removed; the bootstrap over SSH stays, under `bootstrap:`)

## Context

Capacity is rented servers with KVM. Adding one costs money; it must be an API call we control, repeatable, and never a surprise. Catalogs read on 2026-10-18 and 2026-10-19.

## Decisions

**A provisioner per provider behind one trait**: `hetzner-robot` (dedicated, monthly), `scaleway` (Elastic Metal, hourly), `ovh` (Eco and Bare Metal, cart order flow, `$1$`+sha1 signed calls), `static` (none). **Every one is `dry_run` unless told otherwise.**

**A server becomes a host in three steps.** `POST /v1/hosts/order` orders it; the fleet polls the provider for its address and runs `hack/bootstrap-host.sh` on it over SSH (script on stdin, fleet URL, host token and a fresh API token in the environment) until it succeeds; the host turns `ready` on its first heartbeat, matched to the order by address. The same script installs a host by hand.

**The autoscaler, when enabled, orders a host when no slot of `slot_mb` is left and releases a provisioned host empty for `idle_grace` above `min_hosts`**, one change a minute, never past `max_hosts`.

**OVH Eco first for capacity, Scaleway for hourly trials.** Memory per euro decides, and OVH's Eco range (RISE-L: 16 cores, 128 GB DDR5, 2 × 960 GB NVMe) had the most, with no setup fee; Scaleway Elastic Metal is billed by the hour, which suits a trial host. OVH's vRack is a free layer-2 network across every region: on OVH a tenant across hosts rides a VLAN instead of the WireGuard mesh. Advance and Scale lines only when a tenant needs the SLA or the 25–50 Gbps private link. OVH's API is the fullest (order cart, install with an SSH key, reboot).

**Memory decides density**: 8 GB kept for the host, 15 % free on top, no memory overcommit, shared vCPUs 4 per hardware thread, performance vCPUs a thread each. An AX102-1 (102 GB usable) runs 128 machines of 512 MB, 51 of 2 GB, 25 of 4 GB or 12 of 8 GB at once; sleeping machines take disk only.

## Consequences

- The OVH provisioner is stub-tested only; nine assumptions about the real API are listed in `OPERATIONS.md` and are verified at the first real order.
- The bootstrap installs the latest Firecracker and a CI kernel unpinned: pin both before the first real host.
