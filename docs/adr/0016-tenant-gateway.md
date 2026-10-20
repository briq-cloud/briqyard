# ADR 0016: A tenant's gateway is the daemon's, not a machine of the tenant

Date: 2026-10-20 · Status: accepted (Sylvain, 2026-10-20); amended with the implementation the same day (marked *Built*)

## Context

ADR 0015 lets a machine send only through one machine of its tenant (`egress: via`). briq's credential gateway is that machine: one per team, holding the team's secrets, swapping placeholders into outbound HTTPS. On Fly the control plane runs it as a hidden briq (`briqs.kind = 'credential-gateway'`) and special-cases it in lists, limits, metering, the reconciler and the tenant's deletion, because Fly gives nothing else to run it on. briqyard replaces Fly (`CLAUDE.md`): the host should own it.

Competitors run a shared injector on the host (E2B, SPACE). We keep one per tenant: a proxy bug or a leak stays inside one team, and the root daemon never holds a credential (ADR 0015).

## Decisions

**A tenant may declare one gateway**: `PUT /v1/tenants/{id}/gateway { image, cmd, env, size, port, volume_gb }`, `DELETE` to remove it, `GET /v1/tenants/{id}` shows it (`state`, `ip`, `port`, `machine_id`, `error`). The spec is the subset of a machine's create that a proxy needs; env values are secrets like any machine's (config drive, 0600).

*Built:* `cmd` was missing: a stock proxy image needs its command (the e2e runs one). The tenant's existing `gateway` field (the bridge's `.1`, read by nobody) is now `router`, so `gateway` is this one. A PUT on a tenant with nothing yet makes the tenant; a PUT on an existing gateway keeps its machine, address and volume (`volume_gb` cannot change) and restarts it if it runs. `DELETE` answers 409 `gateway_in_use` while a `via: gateway` machine runs or starts.

**It is a machine of the daemon, not of the tenant.** One record per tenant with `role: gateway`, on the tenant's bridge, with an address of the tenant's /24 and the name `gateway.internal` in the tenant's DNS. Absent from `GET /v1/machines`: the tenant's listing stays the tenant's machines, which is what a control plane reconciles against. Destroyed with the tenant.

*Built:* the machine is named `gateway`, so its DNS name is a machine's like any other and the name is taken in the tenant. Absent from the tenant's `machines` count and the status' `machines`; its memory counts. `GET /v1/machines/{id}` and `/logs` answer for it.

**`via: "gateway"` names it.** A machine created or patched with it sends through the gateway only (ADR 0015); the policy resolves the gateway's address at apply time.

**It runs while something needs it.** Starting a `via: gateway` machine starts the gateway first and waits for its port, under the tenant's lock; the sleeper stops it when no running machine of the tenant points at it. A gateway that cannot boot fails the start of its consumer with `boot_failed`, the gateway's console in the message. A machine-to-machine connection does not wake a sleeping sibling (only the ingress does), so this rule is what keeps the consumer's first request working.

*Built:* the tenant's lock is held until the consumer is `starting`, and the sleeper counts `starting` as well as `running`: otherwise a tick between the gateway's port answering and the consumer's reservation stops the gateway under it. The sleeper skips a tenant whose lock is held. The `boot_failed` body's `machine` is the consumer, unmoved (`stopped` or `created`), the gateway's reason in its `error`: the provider destroys the machine a failed create names, which must not be the gateway. A gateway whose port does not answer within `boot_timeout_sec` after its boot is ended and left in `error`, like a boot that fails; the next consumer start tries again. A PATCH to `via: gateway` on a running machine runs the gateway before the policy changes. The gateway runs with `restart: always`, so a program that dies while consumers run comes back.

**The program is the tenant's choice.** The daemon knows nothing of credentials: briq passes its credential-gateway image and token; another operator may run any forward proxy.

## Consequences

- briq's control plane, on briqyard, sets the gateway on the tenant and waits for the program to register its CA; it creates no briq for it, and the exceptions for `kind = 'credential-gateway'` stay on the Fly path only, to be removed with Fly.
- The gateway's cost is ours, not the tenant's: nothing meters it (it is not a briq).
- One gateway per tenant; a second kind of system machine would generalize `role`, not before it is needed.
- e2e: a tenant gateway (a forward proxy image), a `via: gateway` machine whose start boots it, a request through it, the gateway stopped by the sleeper once its consumer stops, absent from the machine list, gone with the tenant.
- *Built:* the fleet does not forward `GET /v1/tenants/{id}` or `/gateway` yet; a tenant's gateway is set on its daemon.
