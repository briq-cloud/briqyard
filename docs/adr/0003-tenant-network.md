# ADR 0003: Network: a bridge and a /24 per tenant, nftables, the host's DNS, the ingress as the only way in

Date: 2026-10-18 · Status: accepted

## Context

Machines of one tenant must reach each other by name and nothing of any other tenant. No machine may have a public address: the control plane's router is the only public entry, which is what makes a private endpoint private. A sleeping machine must wake on its first connection.

## Decisions

**One Linux bridge and one /24 per tenant**, from `10.64.0.0/10` (16,384 tenants per host), the host as gateway at `.1`, one TAP per machine. nftables masquerades egress through the host's default route and drops traffic between tenant ranges.

**The daemon answers DNS on every gateway.** `<alias>.internal` follows a machine's alias (what a sibling's env holds), `<id>.vm.internal` is that exact machine; everything else is forwarded upstream. No dnsmasq, no CoreDNS: a few hundred lines, and the answers follow the store.

**The guest configures its own interface from the config drive.** The guest kernel needs no `ip=` support.

**The ingress is the only way in.** Two kinds of endpoints allocated by the API: a TCP port on the host (`20000-29999`) and an HTTP host name on one shared listener. A connection to a sleeping machine's endpoint starts it, waits for the port, then proxies. The address the endpoint is reported at is `ingress.advertise`, so a router on another machine knows what to dial.

**A tenant lives on one host** today, so the private network needs no overlay. A tenant across hosts is `../MESH.md` (WireGuard), or a vRack VLAN on OVH (ADR 0007).

## Consequences

- The /24 per tenant caps a tenant at 253 machines per host; the mesh design hands a /26 slice per host per tenant.
- The TCP ingress carries no authentication: the host must not expose it publicly. Review finding B1 (`../review-2026-10-20.md`): the bind defaulted to `0.0.0.0`. ADR 0012: the bind defaults to loopback, `ingress.allowed_clients` is the firewall, and a public bind without it is refused.
- Credential-gateway enforcement for briq (force tenant egress on 443 through the team's gateway machine, DNS answering only allowed names) is nftables and DNS rules on this layer: the next addition here.
