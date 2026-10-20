# ADR 0012: What a host exposes and to whom; the forward chain drops by default; a TAP is pinned to its address

Date: 2026-10-20 · Status: accepted

## Context

Review finding B1 (`../review-2026-10-20.md`): on a server with a public address, the daemon's
API (plain HTTP, a bearer), the HTTP ingress and every TCP endpoint were open to the internet.
A `private` endpoint is private only because the control plane's router is the only way in; a
port anyone can scan to is not. B4: the forward chain accepted by default and every rule keyed
on the tenant range, so a guest that set another address (it is root in its VM) was forwarded,
unmasqueraded, anywhere the host routes. C5: the input chain grew four rules per tenant and was
reloaded whole on every tenant change. A2 and C12: the TAP name lost a hex digit of the id and
an existing link was reused silently.

## Decisions

**A host exposes three things, and only to its allowed clients.** The API port (`listen`), the
HTTP ingress (`ingress.http`) and the TCP endpoint range (`ingress.tcp_ports`), on
`ingress.bind`. `ingress.allowed_clients` lists the IPv4 networks that may reach them; the
daemon renders it into its own nftables table (`tcp dport { … } ip saddr @allowed_clients
accept`, then `drop`), so the firewall ships with the daemon and follows its config. Loopback
always may. The defaults are loopback for `listen` and `bind`; nothing is public by default.

**The daemon refuses to start on an address the internet could reach when nothing says who
may connect.** `Config::load` refuses a `listen`, `ingress.bind` or `ingress.http` that is not
loopback, RFC 1918, 100.64/10 or link-local (`0.0.0.0` and `::` included) unless
`allowed_clients` is set or `allow_public: true` says a firewall of the operator's own does the
job. The error names the field and both ways out. A refusal at start beats a port open for a
day.

**The forward chain drops by default; the only accepts are replies and a tenant's way out
through the egress interface**, minus the private networks (`10/8`, `172.16/12`, `192.168/16`,
`100.64/10`, `169.254/16`). Anything from the outside to a tenant, between tenants, or in IPv6
(`meta nfproto ipv6 iifname "by*" drop`, stated although the policy covers it) never matches
an accept. Frames switched inside a tenant bridge stay out of the IP hooks: each bridge gets
`nf_call_iptables = 0` (and ip6, arp) when it is made, so the rule set is the same whether or
not `br_netfilter` is loaded, and nftables could not express "drop only between different
bridges" anyway (it compares an expression to a constant, never two expressions).

**Every TAP is pinned to its machine's address, in the bridge family.** The inet hooks see the
bridge as the input interface, never the port; the `bridge` family's prerouting hook sees the
TAP. `table bridge briqyard` holds one set `pins` of `ifname . ipv4_addr` and a chain with
`policy drop` that accepts a frame only when its port and source (IP, and ARP's sender address)
are an element. A machine start adds its element (`nft add element`), a stop deletes it; the
tables are rendered whole once, at daemon start, with the pins of the running machines the
daemon may adopt. A guest can change its address or its MAC; nothing it sends then leaves its
TAP.

**Tenants need no rule change.** The input chain names tenant bridges by prefix (`iifname
"by*"`): a fixed set of rules, and a tenant create or delete touches nftables not at all. Only
the daemon makes a `by<n>`.

**A TAP is `bt` + the 12 hex digits of the machine id** (14 characters, under IFNAMSIZ): the
whole id, so two machines never share a TAP, and a prefix no other link on the host starts
with, so the orphan sweep deletes only ours. A TAP lives for one boot: `ensure_tap` replaces a
link of that name rather than reuse it, since one there is a start that failed after making it.

## Consequences

- An operator with a public address writes `allowed_clients` (the control plane's addresses)
  or `allow_public: true` with a firewall of their own; `hack/bootstrap-host.sh` writes the
  first from `ALLOWED_CLIENTS`. The bind default moved from `0.0.0.0` to loopback: a config
  that relied on it sets `ingress.bind` now.
- `allowed_clients` is IPv4; IPv6 to the daemon's ports is dropped whenever the list is set.
- The HTTP ingress trusts the `Host` header and limits nothing per client: it is for the
  router, which is in `allowed_clients`, not for the internet (review B17).
- The WireGuard mesh (`../MESH.md`) is the next step: the router and the hosts share a private
  network, `ingress.advertise` becomes the host's mesh address and `allowed_clients` the mesh
  range, and the bearer stops crossing the internet in clear.
- Kernels without bridge netfilter have no `nf_call_*` knob and nothing to switch off; the
  daemon ignores the missing file and fails on any other error.
