# ADR 0018: Egress limits per machine: blocked ports, a connection rate, a bandwidth cap

Date: 2026-10-20 · Status: accepted

## Context

Every machine of a host leaves through the host's IP. A sandbox that sends spam or scans the internet gets that IP blocklisted, and the provider (OVH, Scaleway) can suspend the server, taking every tenant on it down. Kubernetes's NetworkPolicy filters by port and CIDR; a multi-tenant host also needs a rate and a cap per machine.

## Decisions

**Limits are part of a machine's egress policy (ADR 0015), on its internet traffic only.** `limits` on create and PATCH:

| Field | Meaning | Host default (`egress_limits`) |
|---|---|---|
| `blocked_ports` | destination ports refused, TCP and UDP | `[25]` |
| `new_connections_per_minute` | new connections a minute, as many at once; 0: none | 0 |
| `bandwidth_mbit` | Mbit/s, in and out together; 0: none; at most 100000 | 0 |

A machine's own value overrides the host's, per field; PATCH changes the fields it names and keeps the rest. The view shows the values in force. Only routed traffic through the host's NAT is limited: a tenant's own traffic is bridged and never crosses the forward chain. `via` and `none` machines never reach the NAT, so they get no limits in the tables. A tenant's gateway is an `open` machine with the host's defaults: what `via: gateway` machines send to the internet is limited there.

**Enforced in the inet forward chain, keyed on the pinned source address, by elements alone.** The rules are rendered once, as the policy's are; a machine adds elements and named objects:

| Limit | nftables | Verdict |
|---|---|---|
| blocked ports | `ip saddr . tcp dport @blocked_ports` (`ipv4_addr . inet_service`), same for `udp` | TCP: `reject with tcp reset`; UDP: `reject` (ICMP port unreachable). Both fail at once on the client |
| connection rate | `ct state new limit name ip saddr map @conn_limits`, a named `limit` per machine, `rate over N/minute burst N packets` | `drop` |
| bandwidth | `limit name ip saddr map @bandwidth_limits` out, `ip daddr` in, one named `limit` per machine, `rate over N×125000 bytes/second` | `drop` |

A dynamic set (`update @s { ip saddr limit rate over N/minute }`) or a `meter` holds one rate per rule; machines have different rates, so each machine has its own `limit` object, found through a map. `burst N packets` makes the rate mean what it says: without it nft allows 5 at once. Bandwidth is policed (dropped over the rate, a second of burst), not shaped: TCP backs off on the drops. `tc` on the TAP was ruled out: the TAP carries the tenant's bridged traffic too. The limits come before the reply accept (a port blocked on a live machine ends its open connections) and before the internet counters (dropped bytes are not the machine's traffic).

**One transaction per change.** A start adds the machine's elements and objects, a stop deletes them, a PATCH swaps old for new in one `nft -f` input, as the policy swap does; the daemon renders them from the running records at start.

**Drops are counted per machine.** Three counter sets (`dropped_port`, `dropped_rate`, `dropped_bandwidth`), an element per machine address for the machine's life like the internet counters (added at create, before any start; removed at destroy, after the last stop), matched last in each drop rule, so only a drop counts. The view's `egress_drops` holds the packets dropped since the machine started (read by the tick, every 15 s); the usage bucket gets `egress_dropped_packets`, the three together (amends ADR 0017). Events on drops are a separate change; the counters are read through the `Net` seam.

Verified in throwaway network namespaces on the dev VM (nft 1.1.6, kernel 7.0), with the table exactly as the daemon renders it and the lines it sends: it loads; port 25 refused in 20 ms while 443 connects; at 6 a minute, six quick connections pass and the seventh is dropped; a 1 MiB download at 2 Mbit takes 3.4 to 3.6 s (0.03 s without); a same-named `limit` deleted and added again in one input swaps the rate; deleting a `limit` a map still names is refused whole (EBUSY); a delete of what is not there is "No such file or directory".

## Consequences

- The control plane sets the limits per tenant and owns abuse response (suspending a tenant, answering the provider's abuse desk).
- Policing costs retransmissions: the 1 MiB download above dropped 0.45 to 0.78 MB on the way. The cap protects the host's IP and link, it is not quality of service.
- A limit's bucket starts full at every start and every change.
- The drop counts restart at zero at a daemon start, as the internet counters do (ADR 0017).
- IPv4 only, as the policy is; tenant IPv6 is dropped already (ADR 0012).
- Later: a separate egress IP for untrusted sandboxes, so their reputation is not the databases'.
