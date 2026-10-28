# ADR 0003: Network: a bridge and a /24 per tenant, nftables, the host's DNS, the ingress as the only way in

Date: 2026-10-18 · Status: accepted

## Context

Machines of one tenant must reach each other by name and nothing of any other tenant. No machine may have a public address: the control plane's router is the only public entry, which is what makes a private endpoint private. A sleeping machine must wake on its first connection.

## Decisions

**One Linux bridge and one /24 per tenant**, from `10.64.0.0/10` (16,384 tenants per host), the host as gateway at `.1`, one TAP per machine. nftables masquerades egress through the host's default route and drops traffic between tenant ranges.

**The daemon answers DNS on every gateway.** `<alias>.internal` follows a machine's alias (what a sibling's env holds), `<id>.vm.internal` is that exact machine; everything else is forwarded upstream. No dnsmasq, no CoreDNS: a few hundred lines, and the answers follow the store. The wire format is `hickory-proto`'s since ADR 0033.

**The guest configures its own interface from the config drive.** The guest kernel needs no `ip=` support.

**The ingress is the only way in.** Two kinds of endpoints allocated by the API: a TCP port on the host (`20000-29999`; `30000-32767` since ADR 0028) and an HTTP host name on one shared listener. A connection to a sleeping machine's endpoint starts it, waits for the port, then proxies. The address the endpoint is reported at is `ingress.advertise`, so a router on another machine knows what to dial.

**A tenant lives on one host** today, so the private network needs no overlay. A tenant across hosts is `../MESH.md` (WireGuard), or a vRack VLAN on OVH (ADR 0007).

## Consequences

- The /24 per tenant caps a tenant at 253 machines per host; the mesh design hands a /26 slice per host per tenant.
- The TCP ingress carries no authentication: the host must not expose it publicly. The bind defaulted to `0.0.0.0` (review, 2026-10-20). ADR 0012: the bind defaults to loopback, `ingress.allowed_clients` is the firewall, and a public bind without it is refused.
- Credential-gateway enforcement (force tenant egress on 443 through the tenant's gateway, DNS answering only allowed names) is nftables and DNS rules on this layer (ADR 0015, 0016).
- The DNS forwarder opens one UDP socket per upstream query, by choice (2026-10-20). A shared upstream socket needs a request map keyed by a rewritten transaction id, a reader task and per-entry timeouts: more code than the forwarder itself, for a cost that does not show at the scale of one host (a socket per query is a few microseconds; a tenant's resolver caches). Reopen when a host's DNS rate is measured to matter.
