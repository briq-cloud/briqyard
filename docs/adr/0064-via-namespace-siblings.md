# ADR 0064: Explicit namespace peers alongside a selected gateway

Date: 2026-10-31 · Status: proposed; extends ADR 0015, ADR 0012 and ADR 0056

## Context

A `via` machine can use its selected gateway and the host's internal resolver. A service that
needs both that gateway and a database in the same namespace cannot express both permissions.
Changing it to `open` also grants direct internet access. Namespace membership already defines
an address domain; a peer permission can use that identity without a pair of rules per machine.

The existing source-only bridge policy also permits a different peer to send one-way traffic
into a strict `via` machine if it already knows the destination MAC. A failed TCP exchange does
not prove that ingress was denied: the request may arrive while only its reply is blocked.

## Decision

`egress.siblings` is a boolean, absent or false by default and valid only with `mode: via`.
With true, the selected gateway and current admitted IPv4 peers of exactly that namespace are
reachable. A strict peer's own policy still applies in the reverse direction. The CLI spelling
is `--egress via:gateway+siblings`, also accepted by `machine set-egress`; the EGRESS column
round-trips it. The API, persisted record and event all use the shared `Egress` type.

**A namespace is a trust boundary.** A reachable peer can relay traffic or credentials for a
consumer. This permission does not enforce how peers proxy, which ports a peer serves, or how
credentials move between them. Use separate namespaces for services that must not communicate.
It is not a general ingress policy or arbitrary Kubernetes NetworkPolicy selector.

| State | Enforcement |
|---|---|
| Admitted machine | TAP + IPv4 pin, TAP + Ethernet source MAC pin, ARP sender MAC pin, actual bridge + IPv4 membership |
| `via` source | Source address, selected destination address + target TAP identity, optional sibling permission |
| Peer forward | Source pin first; destination TAP + address pin, actual bridge membership, source and destination policy |
| Revocation | One nft transaction; checked on every bridged packet, before any conntrack accept can bypass it |
| Host ingress and exposed endpoints | Reverse guard applies only to TAP-to-TAP bridge forwarding; host-origin traffic retains its existing path |

Membership is one set entry per admitted machine, keyed by bridge name and address. Policies
are a constant number of entries each. There is no pair matrix: rendered state grows O(N),
and one start, stop or PATCH changes O(1) entries. A 64/128-member fixture checks this bound.
Membership follows live pins, never DNS answers or an IP-prefix inference. Ethernet and ARP
source pins are checked before any gateway or peer allowance. IPv6 is still denied. Cross
namespace, host management, private routes, direct internet, host ports and external DNS keep
the existing restrictions for `via` consumers.

The bridge forward hook checks **both directions** for traffic between TAPs. Its regular
chains return to the caller after an allowance so a source allowance cannot skip the
destination policy. This closes the cached-neighbor one-way ingress gap for strict `via`.
A gateway permission includes its TAP identity, so another machine that reuses its address
does not inherit that permission. An opted-in consumer may still reach the replacement as an
explicitly trusted namespace peer.

## Lifecycle and address ownership

A host network lock serializes attachment, revocation and policy updates. A new TAP stays down
and unpinned until pins, membership and policy commit in one nft transaction. Restrictive DNS
is set before admission. An uncertain admission is kept by the host network until cleanup succeeds, including a link-up
failure followed by a cleanup failure and a stopped-record PATCH. A failed transaction never
boots an admitted guest. PATCH swaps the
old and new policy in one transaction; failed PATCH leaves the persisted policy unchanged.

Revocation ensures the elements and named objects exist, then deletes them in the same batch.
The `add` operations are idempotent; their temporary state is not visible outside the batch.
This avoids interpreting one missing element as proof that an entire failed delete succeeded.
A failed revocation still removes the TAP, but destroy/move cannot release the address until
revocation and connection cleanup succeed. Startup reconstructs admitted members only from
running records whose policy can be resolved; unresolved policies get no source pin.

The host requires `conntrack` from conntrack-tools. Cleanup targets one IPv4 address in all
original/reply source/destination tuple positions. No host-wide flush is used. It runs before
first admission (`boots == 0`), deletion releases an address, and a move releases its old and
reserves its new address. A move reserves both source and destination slots under the allocator
lock. Its source record remains unchanged while destination cleanup and counter setup run;
commit rechecks names/quotas and writes the new owner before releasing the source. The source
slot stays reserved through old-counter removal. Errors/cancellation release the temporary
holds without exposing a rollback address. A new create, fork or backup restore starts with `boots == 0`; a
record retained across suspend, stop/start, or adoption keeps its owner identity and address,
so these operations **do not clear existing flows**. New ownership after unknown/orphan state
has no positive boot history and clears before admission. Permission/protocol errors keep the
address reserved; only the exact, complete zero-deleted summary is success. Per-flow stdout
is discarded. Stderr is fully drained with a 4096-byte retained prefix; the deadline covers
process exit and draining, and timeout/read failures kill and reap the command before return. The prerequisite is part of the
versioned host bootstrap and development install.

## Capability and mixed versions

The host status and heartbeat advertise `egress_siblings_v1: true`. Absence is false, independent
of the version string. A heartbeat without it revokes the registry's previous capability.
The fleet chooses a capable host for an unbound namespace and refuses a pinned unsupported
host, including forks and live PATCH, with `409 capability_unsupported`; it does not silently
move the namespace. Fleet status advertises its ability to enforce this gate, separately from
which registered hosts support it. The CLI preflights live status before an opt-in write and
never sends it to a server without explicit support. Strict/default requests need no preflight.
A restore with omitted egress may inherit a sibling-enabled policy from sealed backup metadata,
which public listings do not expose. The fleet and CLI conservatively require capability for
all such restores, including explicit sizes and `latest`. An explicit egress replaces the
backup policy and permits legacy restores without this additional requirement. Direct API
clients must perform the same capability check before sending explicit or inherited opt-in to
an older server, whose unknown-field behavior cannot be changed retroactively.

## Verification

The API regression first failed because the unknown field was dropped. Focused tests cover
validation/serialization, capability refusal before forwarding, mixed-host placement and
capability removal, persisted/failed PATCH, failed admission, stop/move/rebuild membership,
address reuse on failed cleanup, and preserving known-owner resume/adoption flows.

`hack/network-siblings.py` runs the production rules renderer in disposable Linux network
namespaces with local TCP/UDP endpoints. It checks strict cached-neighbor one-way ingress,
reverse packets on an established connection after opt-out/member removal, spoofed IP/MAC/ARP,
IPv6, a selected gateway recreated at its old address, failed-batch atomicity, host ingress,
host ports, cross-namespace denial and controlled direct egress. It changes no real host table.
`hack/e2e-siblings.sh` adds PostgreSQL queries and a controlled gateway fixture through real
microVMs, including live PATCH, stop/start, adoption and moves. These kernel/microVM gates must
run under the shared VM lock before push, alongside workspace tests, fleet suites and stress.
Native test counts and Linux results belong in the PR after execution, not inferred here.

## References

- [nftables manual: batches, add/create elements and bridge metadata](https://netfilter.org/projects/nftables/manpage.html)
- [Kubernetes nft transaction implementation: add/delete for idempotent destruction](https://github.com/kubernetes-sigs/knftables/blob/main/transaction.go)
- [conntrack-tools manual: tuple selectors and deletion](https://netfilter.org/projects/conntrack-tools/conntrack-manpage.html)
