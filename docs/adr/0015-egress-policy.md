# ADR 0015: Egress policy per machine: open, via a gateway, or none

Date: 2026-10-20 · Status: accepted

## Context

briq's credential gateway (monorepo ADR 0015, merged 2026-10-20) puts a placeholder in the sandbox and swaps the real value in at a proxy the sandbox reaches through `HTTPS_PROXY`. On briq's current provider the sandbox can bypass the proxy; the exfiltration side needs the host. The usual design enforces on the host and injects outside the VM (per-sandbox nftables on the node, or policy and credentials on the host). `docs/research/2026-10-18-microvm-field-guide.md`, the monorepo's ADR 0015.

## Decisions

**Egress is a property of the machine, generic, not credential-specific.** `egress` on create and on PATCH:

| Mode | May reach | DNS answers |
|---|---|---|
| `open` (default) | its tenant, the internet through NAT | internal names, then upstream |
| `via: <machine>` | only that machine of its tenant (any port) and the host gateway on 53; no sibling, no internet | internal names only; the proxy resolves the outside |
| `none` | its tenant; no internet | internal names only |

**Enforced where the host sees the port, never by the guest.** `via` and `none` are rendered into the bridge-family table beside the source pins (ADR 0012): a drop rule keyed on the pinned source address and the allowed destinations, before the accept. The guest's `HTTPS_PROXY` is a courtesy for compliant clients; a client that ignores it reaches nothing. `none` keeps the tenant network and drops the route out in the inet forward chain.

**DNS follows the policy.** The tenant resolver keeps a set of addresses that get internal answers only; an outside name from them is answered NXDOMAIN, not forwarded. Not REFUSED: glibc and Go fail at once on it, musl ignores it and waits out its 5 s timeout (`res_msend.c`); NXDOMAIN is final for all three.

**A machine's policy is applied at every start and withdrawn at every stop**, like its pin, and re-applied from the records at daemon start. Changing `via` to a gateway that does not exist in the tenant is refused.

**The injector is never the daemon.** Credentials are terminated and swapped in a process that holds one team's secrets, not in the root process every tenant shares. That rules out a proxy inside `briqyardd`; it does not decide who starts the gateway machine.

## Who runs the gateway machine

The daemon, as the tenant's gateway: ADR 0016 (decided 2026-10-20). The credential program stays briq's.

## Consequences

- A `via` machine cannot reach its siblings: a stack whose sandbox needs its database goes through `none` plus an allow-list, which is the next mode (ADR 0005 on the briq side).
- The policy is IPv4; IPv6 from tenants is dropped already (ADR 0012).
- A gateway machine destroyed under `via` machines leaves their policy as it is: they reach nothing (its address is not handed out while a policy names it), and their next start is refused until `egress` names a machine that exists.
- e2e: a `via` machine reaches the gateway and nothing else, a `none` machine reaches a sibling and not the internet, an outside name is refused for both, `open` is unchanged.
