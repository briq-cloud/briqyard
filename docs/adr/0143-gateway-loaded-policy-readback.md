# ADR 0143: Read a gateway's loaded policy back before bound machines reach it

Date: 2026-11-17 · Status: proposed (source change; no runtime is activated by it)

## Context

A namespace's gateway is a machine the daemon runs for the namespace's `via: gateway`
machines (ADR 0016). A configured policy, a CA certificate or an accepting port is not
evidence that the gateway process enforces a given policy. Four facts of the source decide
the design:

- `own_entry` refuses a gateway on every machine route, exec and files included, and that
  stays. The readback must not reopen them.
- A gateway replacement keeps the machine id (`replace_gateway`): the id is not a process
  identity. `fc::Incarnation` (pid, start ticks, host boot id) is, and the daemon already
  keeps it for every live machine.
- Automatic restart called `start_boxed` without `run_gateway` (`shutdown.rs`), and startup
  pinned running machines before their adoption (`startup.rs`). A readback done only at
  start admission would not cover either.
- A challenge answered by the guest cannot prove which process answered: an old process can
  answer before a replacement and deliver late.

## Decisions

**One binding.** `GatewayPolicyBinding { policy_format: 1, policy_digest:
"sha256:<64 lowercase hex>", enforcement_version: 1 }` is the value of optional
`GatewaySpec.policy`, of the gateway's record `gateway_policy` and of a machine's
`egress.gateway_policy`. It is parsed strictly wherever it is read. Absent is the legacy
route, exactly as before; `Egress::label` is unchanged.

**Cold-born only.** A gateway's loaded policy serves ordinary standalone machines created
fresh: no seed, warm-pool fast start, fork, template, backup restore, assigned run or clone
hook is ever bound to it, and none of them routes through a gateway that carries a policy,
bound or not, by `gateway` or by the gateway's machine id. Stop, start, wake, resize and
same-machine suspend and resume are unchanged. The refusal comes before any replay, lock
with an effect, claim or mutation: the raw request first, then the source or backup record
(a bound source is never derived from, whatever the request says its egress is), then the
effective record immediately before its insertion under the namespace's turn. A PATCH, a
move, a snapshot restore and an assignment's staging, selection and commit apply the same
rule to the stored and the proposed shape. A gateway carrying a policy is refused while a
machine or a retained assignment target that was not created fresh routes through the
namespace's gateway, in any state. At recovery such a stored record keeps its backing,
journals and reservations, is neither adopted, published nor cleared, and is never pinned;
the rules for everything else are still installed, with every bound gateway gated, before
the daemon serves its diagnostic refusal. Assigned runs keep their earlier lifecycle and
recovery; the loaded policy adds nothing to them but these refusals.

**Bound machines.** A bound machine needs `via: gateway`, no siblings, and a binding equal
to its namespace gateway's. The binding is fixed for the machine's life (a PATCH that adds,
removes or changes it is refused) and for the gateway's (a put with another or no policy is
refused; delete and put again). Admission checks equality in `check_egress`, which every
path that derives a machine's egress (create, restore, move, PATCH) already calls, and again
under the namespace's turn immediately before the record is inserted. Replacing or deleting
the gateway takes the same turn and is refused, before any change, while any bound machine
record exists in any state.

**Readback.** `POST /v1/namespaces/{id}/gateway/policy-status {challenge}`. The daemon
selects the namespace's gateway and never wakes or creates anything. Under the namespace's
turn it requires the gateway running with a live handle whose incarnation equals its record,
then runs the fixed internal argv `["/credential-gateway", "policy-status", challenge]`
(cwd `/`, no env, no stdin, guest timeout 2 s, one outer 3 s deadline for lock, session and
read) through the guest session, never the public exec route. Output is collected with a
rejecting 4096-byte limit, because capture silently truncates. It requires exit 0, no
timeout, empty stderr, exactly one report with no unknown field, the same challenge,
`ready: true`, and the format, digest and version of the gateway's binding. It compares the
gateway's identity before and after. The answer's `namespace`, `machine_id` and
`native_incarnation` come from the daemon's record, not from the guest. No guest output
reaches an error or a log.

**Admission.** `ensure_gateway` performs a fresh readback on every call for a bound gateway,
under the namespace's turn that the caller keeps through the machine's reservation. This
also applies if an ordinary consumer names the policy gateway by its machine ID without a
binding; a literal ID of an ordinary peer is unchanged. An egress PATCH of a bound record or
one naming a binding, of a derived record whose current or requested mode is `via`, or one
whose old or new egress uses a policy gateway or the `gateway` alias, takes the
namespace turn before the consumer entry, refuses a busy transition or changed namespace
before effects, and keeps the turn through the network change and record save; any other
egress PATCH waits for the entry as before. The caller checks
the live proof again just before reserving or publishing. A status call is not a token.

Gateway PUT and DELETE take a per-name admission turn before the namespace's gateway boot
turn. A move takes both names in sorted order before checking its source or attempting a
rename. A derived move keeps both through the record save or rollback and releases them
before restarting; a derived egress PATCH takes its source name before the boot or entry
turn. This also orders a rename into an absent namespace without creating it first. A
configured gateway's insertion checks live records and retained assignment targets under
the machine map's lock, matching either the alias or its exact machine ID. A derived create,
an assignment's staging and its commit check policy ownership under the machine map's lock in
the same step that inserts the record or reserves the target, never awaiting a namespace turn
under warm admission.

**Lock order.** Warm admission, then namespace admission, then the per-name admission turn,
then the namespace's turn, then the sandbox lock and the entry. Namespace admission is a
write-preferring lock that a namespace deletion takes exclusively, so no holder of a
namespace turn may wait for it: gateway PUT and DELETE, a cold-born `via` create and a scoped
egress PATCH hold namespace admission while they wait for the turn, and a queued deletion
waits for them. An assigned start through a gateway therefore takes warm admission
exclusively and namespace admission before its gateway turn and keeps all three through its
reservation, instead of taking them inside the reservation under the turn. This changes the
baseline assigned start: a gateway boot it waits for now holds warm admission, delaying seed
creates and warm claims on the host until the gateway serves or fails.

**Unverified-gateway bridge gate.** A bound gateway's address is in the bridge table's
`gateway_gate` set; `prerouting` drops ARP and IP between that address and any member of its
bridge, in both directions, after the source pins and before every allow rule. The gateway's
own frames to the host's `.1` stay, so it can still register its CA, fetch configuration and
use routed internet and DNS; this is not a TAP quarantine. The gate closes before the
gateway's TAP exists on every boot (including the restart policy's), is rendered closed for
every bound gateway when the daemon installs its tables (so recovery pins nothing open), and
opens only after a readback of the current incarnation whose identity is unchanged after the
open. A bound gateway's automatic restart takes the namespace's turn, then the gateway's, and
runs the same path a start does; a running bound gateway adopted at startup is read back the
same way.

An owner holds the namespace and gateway entry through each fresh verification, including
when its caller is cancelled. It closes the gate before readback. The caller installs the
prepared proof and acknowledges it together, after rechecking the record and exact live
handle; without acknowledgment the owner closes the gate again. A failed or timed-out
command is settled before another command or replacement can act. The nft helper has a
3 s deadline that includes its network turn; an overdue child is killed and reaped.

If closure cannot be proved, the owner requests termination of the exact gateway and
requires a positive exit within 10 s. That can proceed while a delayed gate command
settles; the address cannot be reused before settlement. The exit is intentional and
does not restart the gateway. If neither the gate nor exit proves isolation, the daemon
reports `gateway isolation unconfirmed` and retains the process, address and backing
without admitting new consumers or replacing the gateway.

**Capability.** `gateway_policy_v1` in the daemon's and the fleet's status, absent is false.
The fleet forwards the readback to the namespace's pinned host only, and before forwarding
a gateway put with `policy`, a machine create or PATCH naming `egress.gateway_policy`, or a
restore that leaves `egress` to the backup, it asks that host's status and refuses with 409
`capability_unsupported` unless it says true. No registry or heartbeat field is added.

## Rollback and mixed versions

A daemon without this change ignores the new JSON fields of requests and drops them from
nested egress. Its stored gateway record keeps `gateway_policy` in the flattened unknown
fields, but it neither gates nor reads back: rolling a host back under bound machines
returns it to unverified routing. A control plane must therefore require `gateway_policy_v1`
before sending a binding and must not roll a host back while bound machines or gateways
exist. A restore on a host without the capability that leaves `egress` to a backup is
refused by the fleet for the same reason.

## Not claimed

Unit tests drive `MockNet` and a mock guest. They show the order of calls, the refusals and
the rendered rules, not packets: the nft rules need native packet qualification (both
directions, ARP and IP, gateway bootstrap preserved, restart and recovery) before any host
enables the capability. The incarnation recheck uses the daemon's own live handle and exit
signal; it does not re-read /proc. The gateway-side helper and policy object are implemented
in the gateway repository.
