# ADR 0055: "Tenant" is now "namespace"

Date: 2026-10-29 · Status: accepted; renames the word in ADR 0003, 0006, 0016, 0025 and every later one (those keep their text: they are history)

## Context

A tenant is a group of machines with one private network, one DNS, one quota and at most one gateway (ADR 0003, 0016, 0025). Kubernetes has the same object and calls it a namespace; `KUBERNETES-MAP.md` already maps one to the other. "Tenant" says something else: a customer of the control plane. It was the right word while the control plane made one per team. It no longer is: the control plane now makes one network per stack, so several namespaces belong to one team and the word names nothing about who owns them.

The repository goes public with this release. A name that needs a footnote in the first doc a reader opens is cheaper to change now than after others write against it. The staging hosts run v0.1.x with records on disk, and the control plane's adapter speaks `tenant`, so the change must read what exists.

## Decisions

**The word is `namespace` everywhere it is ours:** the API (`namespace` in bodies, responses and queries; `/v1/namespaces`), the error code `namespace_in_use`, the daemon, the fleet's registry and placement, the CLI (`--namespace`, `briqyard namespace`, the `NAMESPACE` and `NAMESPACES` columns), the metric `briqyard_namespaces` and the `namespace` label, the events' `namespace` field, the docs, the dashboards, the alerts and the shell suites. One definition, said once in `README.md`: a namespace is an isolated network whose machines share a host.

**What was written keeps loading.** Every persisted or received field takes the old name as a serde alias: `tenant` on a machine's record, an endpoint's, a backup holder's, a backup's, an event, a usage bucket, a quota, a top row and a create request; `tenants` on a host's heartbeat and on the fleet's registry (its `tenants` map becomes `namespaces`, and the registry's backup, which is the same file, reads either). Written back, they carry the new name only. A unit test per kind writes the old shape and reads it.

**What is on the host keeps its name where renaming would disturb a running machine.** The directory of the namespaces' records stays `state/tenants/` (`store::NAMESPACES`): a rename would need a move at start with a crash window between the two directories, for a name no one sees. The bridges (`by<n>`), the nftables tables and sets, the ZFS datasets and the guest's config never held the word. The Prometheus history under the `tenant` label stays in Prometheus for its 90 days; the dashboards and alerts read `namespace`, so a panel over a longer range shows a gap before the upgrade.

**Input accepts the former name, deprecated.** A body field `tenant`, a query parameter `tenant=` (machines, backups, usage, events, top) and the routes `/v1/tenants…` on the daemon and the fleet answer as their new names. They are not in `openapi.yaml` and are removed in the release after the control plane's adapter has moved. The CLI keeps `--tenant` and `briqyard tenant` as hidden aliases, out of `--help`. Responses carry `namespace` only, with no `tenant` beside it: a client that reads responses must change, one that only writes need not.

**The fleet polls a static host on `/v1/tenants`** while that path is served, so a fleet upgraded before its hosts still reads their namespaces; a host that does not answer keeps the namespaces it had, since a heartbeat's list is the truth and an empty one would drop their pins.

**Daemons and fleet move together.** A new fleet forwards `namespace=` and `/v1/namespaces`, which an old daemon does not know (it would list every machine for a filtered query); an old fleet reads responses by `tenant`, which a new daemon no longer sends. There is no safe mix of the two, so a host upgrade goes through the fleet in one window, as `host upgrade` does (ADR 0027). Records on disk need nothing: the new daemon reads them as they are. A downgrade after the first write is not supported: the old binary refuses records that carry `namespace`.

**Moving a machine to another namespace is not part of this.** It is the next change, on top of the name.

## Rejected

| Alternative | Why not |
|---|---|
| Keep `tenant`, document it | The public repository would say "tenant" while saying it is Kubernetes-shaped; the gap stays in every doc |
| `network` | A namespace also holds the quota, the DNS and the gateway: the network is one of its parts |
| Rename the state directory, with a move at start | Two directories during a crash window, for a name that appears in no API or doc |
| Both names in responses | Doubles every body forever; the only reader is one adapter that changes with it |
| Keep the old routes and parameters for good | A second name for everything, forever; the control plane moves in one change |

## Consequences

- The adapter in the control plane's repository reads `namespace` from machine responses and the error code is `namespace_in_use`; it can keep writing `tenant` until it switches.
- Metrics and alerts that name the `tenant` label are rewritten by the operator: the provisioned dashboards and alerts are, a custom one is not.
- `docs/adr/` keeps "tenant" in its older records; `README.md` there says which word each one means.
