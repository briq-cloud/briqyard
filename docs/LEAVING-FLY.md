# Leaving Fly: what is not covered yet

Mid-term goal: briq runs with no Fly at all. This is what Fly gives briq today that briqyard and briq do not cover yet, the options, and whose scope each part is. Written 2026-10-20; items move to an ADR when decided and leave this list when built.

**The split, as for usage and costs (ADR 0017):** briqyard owns mechanisms on a host and across hosts (run, measure, enforce, move). briq owns policy and product (who may, how much, at what price, what a plan includes) and its own apps (the API, the router). Operations (servers, DNS, certificates, CI) is infra code in briq's repo, using briqyard's commands.

**No migration** (Sylvain, 2026-10-20): customers' briqs are not moved from Fly to briqyard; the switch is a rollover per environment, with no period where one environment runs both and no volume copy tool.

Not affected: the control plane (Railway), the monitor (Cloudflare Workers), DNS (Cloudflare). The Provider interface is fully implemented by the briqyard adapter: every gap below is under it.

## Summary

| # | Gap | briqyard | briq | Before |
|---|---|---|---|---|
| 1 | Public edge: hosting, IPs, certificates, DDoS | the hosts' ingress on the vRack, the public interface closed (done, ADR 0028) | the router, edge servers, Cloudflare in front, WebSockets (built: up-lab/briq#277, draft) | staging |
| 2 | Volume durability: Fly's daily snapshots | scheduled backups, retention, delete (done); a run against a real bucket | the schedule and retention per plan | staging |
| 3 | Egress abuse: our servers' IPs and the provider's abuse desk | blocked ports, rate and bandwidth limits per machine (done) | the limits per plan, abuse response | public traffic |
| 4 | Observability and alerts | `/metrics`, JSON logs, host conditions (done) | scraping, log shipping, alerts in the monitor | staging |
| 5 | Host operations: real orders, upgrades, patching | `host add`, the first-host runbook (done, ADR 0028); rolling upgrade (built: ADR 0027), real provisioner runs, OS patching | runbooks, capacity decisions | production |
| 6 | Host loss | evacuate a host from its backups | the briqs' state while it happens | production |
| 7 | Regions | region-aware placement (done) | the team's region to the briqyard adapter (done, #250) | a second region |
| 8 | A team across hosts | WireGuard mesh or vRack (`MESH.md`) | nothing | a team outgrows a host |
| 9 | Encryption at rest | the pool encrypted, one key per host held by the fleet (built: ADR 0026); the registry's backup, which holds every key | nothing | the first real host |
| 10 | Usage and costs | usage buckets (ADR 0017, built) | collection, cost model, billing of disk and network | billing them |
| 11 | Image pulls at scale | a registry mirror per region | nothing | many hosts |
| 12 | CI and staging on real hardware | e2e on a KVM runner (steps written: `OPERATIONS.md`) | the deploy smoke test against briqyard | staging |
| 13 | Fleet availability | the registry backed up, encrypted, and restored (built: ADR 0032); state beyond one JSON file | nothing | production |
| 14 | Legal | nothing | subprocessors, DPA, claims | production |
| 15 | Fly-only code | nothing | remove the hidden gateway briq, `fly-replay`, the Fly adapter | Fly gone |

## 1. Public edge

Fly today: runs the HTTP edge (Caddy + router) and the TCP edge, anycast IPv4/IPv6 in every region, issues and serves `*.briq.run`, delivers by `fly-replay` and Flycast, absorbs floods.

On briqyard: the router's logic (host lookup, `private`/`token`, wake, activity, TCP handshakes, open-database refusal) is provider-free and verified in proxy mode against a daemon. Missing: a home for it, public addresses, the HTTP certificate.

- **Edge hosts of our own** (recommended): two small servers per region running the edge image as a service, `*.briq.run` and `*.tcp.briq.run` in DNS to both. Certificates by Let's Encrypt DNS-01 in CI, as the `*.tcp` one already is. The hosts' `ingress.allowed_clients` lists the edge until the mesh makes it the mesh range. The first region starts with the edge on its first host, beside the daemon (ADR 0028): one firewall, Docker without rules, the fleet behind the edge's Caddy, machines reaching the edge through `network.host_ports`.
- **Cloudflare in front of HTTP**: `*.briq.run` proxied gives anycast, TLS at the edge and flood absorption, with our edge hosts as origin. TCP endpoints cannot go through it without Spectrum (paid): they stay direct.
- The edge never runs inside briqyard (in a machine): tokens, teams and `briq.run` are briq's. Beside it on a host is fine.
- **The path from the edge to the hosts carries customers' traffic** (HTTP in clear, a database's protocol after the edge's TLS). It must ride a private network: OVH's vRack or a Scaleway private network between the edge and the hosts of a region, the mesh (`MESH.md`) across providers. TLS on the daemon's API (ADR 0020) covers the control path only.

## 2. Volume durability

Fly today: a daily block snapshot of every volume, kept 5 days, restorable.

On briqyard (built, ADR 0023): a machine carries `backup: { every, keep }`; the daemon takes and prunes them, so a backup happens even when the control plane is down; `DELETE` of a backup; a destroyed machine's backups kept `keep_destroyed_days`, listed by `GET /v1/backups`. Missing: a run against a real bucket.

- briq sets the values per plan at create (Fly's: `{ every: "1d", keep: 5 }`) and shows `GET /v1/backups?tenant=` in the dashboard.

## 3. Egress abuse

Fly today: its IPs and its abuse desk; one abusive app is Fly's problem first.

On briqyard: every machine of a host leaves through the host's IP. A sandbox that sends spam or scans the internet gets the server's IP blocklisted, and OVH or Scaleway can suspend the server, taking every tenant on it down.

- **briqyard enforces** (built, ADR 0018): blocked destination ports (25 by default), a connection rate and a bandwidth cap per machine, host defaults in `egress_limits`, in nftables beside the egress policy (ADR 0015); drops counted per machine, in its view and in usage.
- briq sets the limits per plan, and owns abuse response (suspend a team, answer the provider's abuse desk).
- Later: a separate egress IP for untrusted sandboxes (an OVH additional IP per host), so their reputation is not the databases'.

## 4. Observability and alerts

Fly today: logs, metrics and dashboards for every app.

On briqyard: `/metrics` (Prometheus, per machine and per host), host conditions in the heartbeat (ADR 0021), `briqyard top`, and one JSON log line per event exist; nothing collects them.

- briq (infra): scrape `/metrics`, ship journald to the same place as Railway's logs, alert from the monitor on host down, `briqyard_host_condition == 1`, error lines.

## 5. Host operations

Fly today: hardware, kernels, the hypervisor, capacity: all Fly's.

On briqyard: provisioners for OVH, Scaleway, Hetzner, stub-tested only. `host upgrade` (ADR 0027): one host or `--all` one at a time, the daemon handing its machines over (no pause, ingress connections reset); verified in the dev VM, not yet on a real host.

- briqyard: a first real order through each provisioner; a first `host upgrade --all` on real hosts; OS patching (a reboot) through the fleet. Built (ADR 0028): `host add` for a server bought by hand, the OVH install layout, the vRack, the runbook (`OPERATIONS.md`, "First OVH host"), and the release's digests checked by the script.
- briq (ops): runbooks, when to order, kernel and Firecracker version bumps through the pinned bootstrap (ADR 0007).

## 6. Host loss

Fly today: a dead host takes its volumes with it too; Fly replaces the hardware.

On briqyard: the fleet marks the host down and refuses its calls; restoring is per machine, by hand.

- briqyard: `host evacuate <id>`: restore each machine of the host's tenants from its latest backup on other hosts, with the tenant's gateway set again.
- briq: shows the briqs as unavailable, then restored with their data as of the last backup, as its docs already say for Fly.

## 7. Regions

Fly today: Paris, Virginia, Singapore, the team's region chosen at signup.

On briqyard (ADR 0025, built): a create's `region` places a new tenant on a host of that region and a tenant never spans regions (400); no host there is 503 `capacity` naming it. The gateway and quota PUTs take `?region=` for a tenant with no host yet.

- briq: the region table gets a `briqyard` column (the hosts' region codes; OVH's `gra`, `vin`, `sgp` if hosts are named after their datacenter), and the adapter sends `region` on each create and `?region=` on the gateway and quota PUTs; the edge per region (item 1).
- briqyard, later: the autoscaler orders in its provisioner's one region; scaling per region once a second region has hosts.

## 8. A team across hosts

Fly today: one private IPv6 network per org, across every host and region.

On briqyard: a tenant lives on one host. `MESH.md` is the design (WireGuard, fleet-allocated slices); on OVH, vRack VLANs instead (ADR 0007). Needed once a team outgrows a host or a draining host must empty itself.

## 9. Encryption at rest

Fly today: volumes are encrypted at rest.

On briqyard (built, ADR 0026): the pool is encrypted at its creation, one key per host made and kept by the fleet, loaded by the daemon at start; everything of a machine is on the pool, and hosts run without swap. Missing: the fleet registry's backup (losing it loses every key, item 13), and backups leave the host decrypted (encrypt the bucket).

## 10. Usage and costs

ADR 0017, built 2026-10-20: briqyard measures compute, disk, object storage and network per machine in hourly buckets, with no price; `GET /v1/usage`, whole or failed through the fleet. briq collects closed hours and owns the cost model and billing (not built). One hole before billing storage: `host retire` takes the host's stored hours with it, and the holders of its destroyed machines' backups (retire should wait until briq has collected the host's last closed hour). A destroyed machine's backups are reported in its buckets until they are deleted (ADR 0023).

## 11. Image pulls at scale

Fly today: its own pull infrastructure and cache.

On briqyard: each host pulls from the registry; a tag's digest is cached (ADR 0009), Docker Hub's anonymous limit is per IP.

- briqyard: a registry mirror per region (a pull-through cache) in the host config; the image cache already avoids repeat builds.

## 12. CI and staging

Fly today: the deploy's smoke test runs a real Fly lifecycle.

On briqyard: the suites run on the Mac; CI runs unit tests only.

- briqyard: e2e on a CI runner with KVM (check whether Ubicloud's runners expose `/dev/kvm`; else a small dedicated runner: the steps and the rule for public pull requests are in `OPERATIONS.md`, "A KVM runner for the suites"). The suites already run against a remote host (ADR 0028).
- briq: a staging environment on briqyard and the smoke test against it.

## 13. Fleet availability

On briqyard: one fleet process, one JSON file, backed up encrypted to the object store and restored with `briqyard-fleet restore` (ADR 0032). Its loss stops placement and forwarding, not machines. Before production: a second process with shared state (Postgres), or a fleet that can be rebuilt from the hosts' heartbeats alone.

## 14. Legal

briq's subprocessor list and DPA name Fly; they will name OVH or Scaleway. Claims about where data lives and how it is protected follow items 2 and 9.

## 15. Fly-only code

Once Fly is gone, briq removes the hidden credential-gateway briq and its exceptions, `fly-replay` delivery, the Fly adapter and its cost formula, and the Fly parts of `infra/`.
