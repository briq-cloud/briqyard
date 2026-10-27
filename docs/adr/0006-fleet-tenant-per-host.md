# ADR 0006: Fleet: a tenant on one host, calls forwarded, listings never partial

Date: 2026-10-19 · Status: accepted

## Context

Several hosts, one API for the control plane. The control plane reads a machine missing from a listing as gone and errors the briq (briq's rule: `Provider.list` must throw, never return `[]`). A tenant's private network has no overlay yet (ADR 0003).

## Decisions

**`briqyard-fleet` offers the daemon's API and forwards each call to the host that runs the machine.** It adds nothing a daemon does not do: a rule about a machine lives in the daemon, once.

**A tenant is placed on one host**: the ready host under the fill ceiling with the most free memory, disk counted too; a fork lands where its source is (same pool). A pin is kept while the host reports the tenant, and dropped from a heartbeat unless it is under 10 minutes old.

**Hosts register by heartbeat every 15 s**, carrying capacity, tenants and the daemon's own API token. Silent for a minute: `down`. Its machines' calls answer 503 `host_down`; nothing is guessed. Static hosts can be listed in the fleet's config and polled.

**A listing is never partial.** A tenant's listing asks its host alone; a host down or not answering fails the listing. Every forwarded call has a 5 s connect timeout.

**The registry is one JSON file** (hosts, tenant → host, machine → host), rewritten on change. Enough for tens of hosts; not for hundreds.

**`drain` stops placement on a host; `retire` drains and releases it once empty** (ADR 0007).

## Consequences

- A tenant's machines are capped by one host. A tenant across hosts is `../MESH.md`, after this.
- A host down takes its tenants down with it: no migration, the disks are there.
- Registry save errors were swallowed, and the shared host token let a host impersonate another: both fixed by ADR 0013.
- Reopen the single file when the fleet passes a few dozen hosts: a small database, same shape.
