# ADR 0142: DNS queries stay in their source namespace

2026-11-17 · Status: accepted

## Context

Each namespace has a disjoint /24, a gateway at `.1`, and machine addresses `.2` through `.254`
(ADR 0003). The host pins every guest's source address and MAC before accepting its packets
(ADR 0012). DNS restrictions for `none` and `via` are stored under the machine's own gateway
(ADR 0015).

A packet to another namespace's gateway addresses the host, not a forwarded destination.
That resolver must not treat the foreign source as unrestricted or return its internal names.

## Decisions

**Check the source before lookup or forwarding.** A gateway answers only sources in its own
/24 with a machine host number, `.2` through `.254`. Other sources receive no response and
cause no upstream query. The listener supplies its bound gateway address; the socket supplies
the source address.

**Keep source authentication in the host's existing pins.** The resolver checks the namespace
and address shape, not allocation or live membership. A guest cannot claim a different source
to pass this check because its TAP has an address and MAC pin. Trusted host-origin traffic is
not authenticated by this check.

**Do not use published names as an admission registry.** Discovery publication can be withheld
during assignment or clone activation. A valid source need not have a published name to use
its own resolver. No second ownership map or lifecycle hook is added.

## Consequences

Own-namespace open sources retain upstream forwarding. Restricted sources retain internal
answers and NXDOMAIN for outside names. Namespace peers remain trusted; this does not prevent
an allowed peer from relaying traffic, add a hostname allowlist, or introduce a network-off mode.

The regression uses a controlled loopback upstream and two namespace gateways. It denies
foreign open and restricted sources before internal lookup or upstream forwarding, rejects
non-machine source addresses, and keeps legitimate own-gateway behavior. Production nftables
packet traversal and microVM lifecycle qualification are separate checks; a resolver unit test
does not establish deployed enforcement.
