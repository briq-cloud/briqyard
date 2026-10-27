# ADR 0016: A tenant's gateway is the daemon's, not a machine of the tenant

Date: 2026-10-20 · Status: accepted (Sylvain, 2026-10-20); amended with the implementation the same day (marked *Built*), and on 2026-10-27 (iron-proxy as the program, boot files on the spec; *Amended 2026-10-27*)

## Context

ADR 0015 lets a machine send only through one machine of its tenant (`egress: via`). briq's credential gateway is that machine: one per team, holding the team's secrets, swapping placeholders into outbound HTTPS. On Fly the control plane runs it as a hidden briq (`briqs.kind = 'credential-gateway'`) and special-cases it in lists, limits, metering, the reconciler and the tenant's deletion, because Fly gives nothing else to run it on. briqyard replaces Fly (`CLAUDE.md`): the host should own it.

Competitors run a shared injector on the host (E2B, SPACE). We keep one per tenant: a proxy bug or a leak stays inside one team, and the root daemon never holds a credential (ADR 0015).

## Decisions

**A tenant may declare one gateway**: `PUT /v1/tenants/{id}/gateway { image, cmd, env, size, port, volume_gb }`, `DELETE` to remove it, `GET /v1/tenants/{id}` shows it (`state`, `ip`, `port`, `machine_id`, `error`). The spec is the subset of a machine's create that a proxy needs; env values are secrets like any machine's (config drive, 0600).

*Built:* `cmd` was missing: a stock proxy image needs its command (the e2e runs one). The tenant's existing `gateway` field (the bridge's `.1`, read by nobody) is now `router`, so `gateway` is this one. A PUT on a tenant with nothing yet makes the tenant; a PUT on an existing gateway keeps its machine, address and volume (`volume_gb` cannot change) and restarts it if it runs. `DELETE` answers 409 `gateway_in_use` while a `via: gateway` machine runs or starts. The spec it has already changes nothing, so a control plane may put it again. `start: true` runs it at once (tenant lock, port wait; `boot_failed` with its console otherwise): briq's program makes its CA on first boot, and the first consumer's create needs that CA as a boot file. The sleeper may stop it again: the CA is on its volume.

**It is a machine of the daemon, not of the tenant.** One record per tenant with `role: gateway`, on the tenant's bridge, with an address of the tenant's /24 and the name `gateway.internal` in the tenant's DNS. Absent from `GET /v1/machines`: the tenant's listing stays the tenant's machines, which is what a control plane reconciles against. Destroyed with the tenant.

*Built:* the machine is named `gateway`, so its DNS name is a machine's like any other and the name is taken in the tenant. Absent from the tenant's `machines` count and the status' `machines`; its memory counts. `GET /v1/machines/{id}`, `/logs`, `/stats` and `/wait` answer for it; every other machine route on its id answers 409 `gateway`, so the tenant's route is the only way to change it.

**`via: "gateway"` names it.** A machine created or patched with it sends through the gateway only (ADR 0015); the policy resolves the gateway's address at apply time.

**It runs while something needs it.** Starting a `via: gateway` machine starts the gateway first and waits for its port, under the tenant's lock; the sleeper stops it when no running machine of the tenant points at it. A gateway that cannot boot fails the start of its consumer with `boot_failed`, the gateway's console in the message. A machine-to-machine connection does not wake a sleeping sibling (only the ingress does), so this rule is what keeps the consumer's first request working.

*Built:* the tenant's lock is held until the consumer is `starting`, and the sleeper counts `starting` as well as `running`: otherwise a tick between the gateway's port answering and the consumer's reservation stops the gateway under it. The sleeper skips a tenant whose lock is held. The `boot_failed` body's `machine` is the consumer, unmoved (`stopped` or `created`), the gateway's reason in its `error`: the provider destroys the machine a failed create names, which must not be the gateway. A gateway whose port does not answer within `boot_timeout_sec` after its boot is ended and left in `error`, like a boot that fails; the next consumer start tries again. A PATCH to `via: gateway` on a running machine runs the gateway before the policy changes. The gateway runs with `restart: always`, so a program that dies while consumers run comes back. A daemon start that adopts a running consumer starts its gateway again if the gateway's process did not survive.

**The program is the tenant's choice.** The daemon knows nothing of credentials: briq passes its credential-gateway image and token; another operator may run any forward proxy.

## Consequences

- briq's control plane, on briqyard, sets the gateway on the tenant and waits for the program to register its CA; it creates no briq for it, and the exceptions for `kind = 'credential-gateway'` stay on the Fly path only, to be removed with Fly.
- The gateway's cost is ours, not the tenant's: nothing meters it (it is not a briq).
- One gateway per tenant; a second kind of system machine would generalize `role`, not before it is needed.
- e2e: a tenant gateway (a forward proxy image), a `via: gateway` machine whose start boots it, a request through it, the gateway stopped by the sleeper once its consumer stops, absent from the machine list, gone with the tenant.
- *Built:* the fleet forwards `GET /v1/tenants/{id}` and `/gateway` to the tenant's host; a PUT for a tenant with no host places it as a first machine would, the gateway's size as the need.

## Amended 2026-10-27: iron-proxy as the program

"The program is the tenant's choice" is checked with a stock program that is not ours: `paradigmxyz/iron-proxy` (Apache-2.0, Go, an egress firewall with secret injection), pinned `ironsh/iron-proxy:0.54.0@sha256:6d074be2…`. The e2e suite runs it as a tenant's gateway: a `via: gateway` machine reaches an allowed host (a sibling HTTPS echo, its certificate signed by the same test CA, which iron-proxy trusts upstream with `SSL_CERT_FILE`) through its CONNECT listener, iron-proxy terminates TLS with that CA, injects a header and swaps a proxy token for the secret; a request without the token and a host off its allowlist get 403; the consumer holds neither secret.

**Finding: the gateway spec had no boot files.** iron-proxy's image is `ENTRYPOINT ["iron-proxy"]`; its allowlist and secrets exist only in a YAML file (`-config`; `IRON_*` variables cover listeners and the CA's paths, not transforms), and its CA is two files. The spec had `cmd` and `env`, so no stock image that reads a file could run. `files` is added to the spec: a machine's boot files, the same field and checks (`SpecChange::check`, now run on every PUT, so a replacement is refused in a create's words), on the config drive at each cold boot; a PUT that changes them restarts a running gateway, as any other field. CLI `tenant gateway set --file /path=local`. Nothing else in the daemon changed.

**Decision: briq keeps its own `credential-gateway`; revisit at iron-proxy 1.0.** What iron-proxy would need to replace it:

| What briq needs | iron-proxy 0.54 |
|---|---|
| A contract that holds across upgrades | pre-1.0: 69 releases since 2026-04; the config moved (README's `proxy_value` on a secret is now `replace.proxy_value`, `inject` is new); pin by digest, the e2e suite is the contract |
| A team's secrets changed while its sandboxes run | a file reread on `POST /v1/reload` (management listener) or `file` sources with a `ttl`, or managed mode, which polls `POST /api/v1/proxy/sync` of iron.sh's control plane (its protocol, not a public API); with boot files, a change is a PUT and a restart, which cuts the consumers' connections |
| A CA per team whose key stays in the team's gateway (briq's program makes it at its first boot, on its volume) | given (`tls.ca_cert`, `tls.ca_key`; `iron-proxy generate-ca` makes one offline): the control plane makes it and holds the key, a wider place for it than one tenant's volume |
| `https_proxy` to `gateway.internal` | through `tunnel_listen`; its DNS mode (everything resolves to the proxy) is off: our resolver answers internal names only under `via` (ADR 0015). A secret rule must name its methods: one that matches CONNECT, which carries no header, refuses the tunnel when `require` is set |

What it would bring: an allowlist with methods and paths, an upstream deny list against DNS rebinding, a per-request JSON audit log, an LLM judge, Postgres role injection. At 1.0, with a documented reload or sync API, the comparison is run again: the e2e section is the starting point.

