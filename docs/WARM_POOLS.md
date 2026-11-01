# Paused template pools

Warm pools hold identity-configured, paused destinations of one immutable qualified
named-memory template on its source host. They use normal machine records, addresses,
root clones, durable memory readers and full CPU/RAM/machine/disk admission. Warm records additionally charge the sealed logical root size to namespace disk quota,
alongside any volume charge. This server-owned marker persists after claim and through
destruction until cleanup; existing ordinary-machine disk policy is unchanged. A ready
slot has not started the fixed workload. It is neither a cold spare nor free capacity.

Enable `templates.warm_pools = true` alongside the exact template init digest binding
on a candidate host. Status/heartbeats advertise `warm_pool_profiles` from the configured
qualified template inputs and implemented paused lifecycle. Default-off/missing reports
are unsupported. Native paused adoption, claim, recovery and performance still require
qualification; an advertised implementation is not measured performance evidence.

```sh
briqyard warm-pool put TEAM tools --source TEMPLATE_ID --snapshot ready --desired 2
briqyard warm-pool ls TEAM
briqyard warm-pool claim TEAM tools --name worker --request-id stable-request-123
briqyard warm-pool rm TEAM tools
```

Listings include slot IDs, actual states and claim keys, including pending claims that
need cleanup. Closed pools retain their bounded receipts and remain listed for audit.

Desired counts reconcile in the existing periodic tick, at most one new slot per pool
per pass, through ordinary full admission. Source snapshot IDs/generations, owner,
profile, recipe, boot/CPU/init identities and network policy are fingerprinted together.
Changed or unavailable inputs stop new claims/refills and drain unused slots. The current implemented
profile is `init-ready-v1`; the pool API consumes a template profile and
fingerprint, so future qualified service barriers can use the same lifecycle. Full
running-service/Postgres/prepared-process/mid-episode cloning remains open.

A claim durably binds its request key to exactly one preassigned machine before resume.
Its existing reservation transfers with it; neither host nor fleet charges a second
one. The preassigned ID/IP/MAC/machine identity and guest hostname stay fixed. The
requested name changes machine metadata and namespace DNS. The workload/recipe and
its environment remain fixed. Per-exec environment does not change a running main.

The CLI defaults `--fail-fast true`: an empty/busy allocation turn returns `pool_empty`
without waiting for refill or starting another VM. With `--fail-fast false`, allocation
can wait for that lock, then also returns `pool_empty` if no ready slot exists. Neither
mode implicitly allocates fresh capacity; use an ordinary named memory fork for that.
A retry of an existing request can wait for that same machine's first-command readiness.
Reusing its key with another requested name conflicts. Receipts remain after machine
or pool destruction and cannot consume another slot. A pool retains at most 1024 claim
receipts; use a new pool name after reaching that bound.

Paused slots resume through explicit owned paused adoption. Missing identity/incarnation
or reader proof refuses the claim and uses the same non-activating settlement as strict
memory-clone recovery. Unknown exit retains full quota/backing and blocks refill. A
claim interrupted after resume can fail conservatively; its receipt still names the
same machine. A timeout never permits another claim or proves process exit. Unused
slots can drain after confirmed exit; claimed machines are never recycled into a pool.

This source candidate is not deployed and does not establish a latency target. Compare
cold boot, named fork and warm claim with one final source/image/init/shape/runtime
identity. Measure first-command readiness separately from API polling, and include
failures, quota/reservation totals, actual network identity, COW/refault and restart
correctness. Full service-profile and public-provider integration remain required.

Paused slots persist as the existing starting state plus a server-owned marker and
confirmed paused stage; API views report warm. This preserves initial accounting for
readers of older records, but does not qualify downgrades: older daemons can stop or
reclassify these processes without the exact exit discipline. Before downgrading, drain
and positively settle all warm VMMs, local backing and durable readers. Do not rely on
the state label as a rollback guarantee. Same-version restart adopts only proven paused
slots; unknown ownership retains full reservations. An ordinary daemon stop leaves
already-paused unused slots resident for its next same-version start. Drain the pool
first to release that capacity. Claim/refill work uses the existing owned scope gate,
so shutdown closes admission and waits for in-flight work before handover.
