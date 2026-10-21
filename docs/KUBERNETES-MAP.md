# briqyard against Kubernetes

briqyard is the Kubernetes of Firecracker: microVMs for services and sandboxes. This maps what Kubernetes offers the people who run workloads on it to what briqyard offers, and says where each gap belongs.

**The scope test** (Sylvain, 2026-10-20): if briq ran on Kubernetes, would this be provided by Kubernetes, or built in briq? Provided by Kubernetes → briqyard builds it. Built in briq even on Kubernetes → briq. The same line as usage and costs (ADR 0017).

Legend: ✓ equivalent · ◐ partial · ✗ missing · ★ briqyard goes further. Scope: **yard** = briqyard, **briq** = briq's control plane or edge, **—** = not needed. Written 2026-10-20; a row changes when the gap closes.

## The model, side by side

| Kubernetes | briqyard | Note |
|---|---|---|
| Cluster | a fleet (`briqyard-fleet`) | one API across hosts |
| Node | a host (`briqyardd`) | heartbeat, capacity, drain |
| Namespace | a tenant | isolated by default: its own bridge, /24 and DNS |
| Pod | a machine | one microVM: a kernel of its own, one main process, exec for the rest |
| Container image | an OCI image, turned into a root disk once per digest | |
| PersistentVolume + claim | a machine's volume (a zvol, honest `fsync`) | one per machine |
| Service DNS | `<name>.internal`, `<id>.vm.internal` | per machine, no load balancing |
| Ingress / Gateway | endpoints (TCP port, HTTP host) on the host, briq's router in front | |
| NetworkPolicy | egress policy (`open`, `via`, `none`) | ADR 0015 |
| Egress gateway | the tenant's gateway | ADR 0016 |
| kubelet + container runtime | the daemon + Firecracker under the jailer | |
| kube-scheduler | the fleet's placement | a tenant on one host |
| etcd + API server | records on each host, the fleet's registry file | imperative, not declarative |
| kubectl | `briqyard` | |

**One deliberate difference:** Kubernetes is declarative (you write desired state, controllers converge). briqyard is imperative with a few loops of its own (restart policy, sleep, destroy resume, gateway lifecycle). briq's control plane is the declarative layer (stack files, the reconciler). briqyard adds what makes an imperative API safe to drive from a reconciler: versions on records, a watch, events. It does not add CRDs or controllers.

## API machinery

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| REST resources, OpenAPI | ✓ `api/openapi.yaml`, served | | |
| `resourceVersion`, optimistic concurrency (409 on a stale write) | ✓ a machine's `version`, `If-Match` on PATCH, DELETE, start, stop, wake (ADR 0019) | | |
| watch (list + watch, informers) | ✓ `GET /v1/events?watch=true` from a cursor; per host, or a tenant or a machine through the fleet | | |
| Events (`kubectl get events`, `describe`) | ✓ an event log per host, a closed list of reasons, `briqyard events` | events of endpoints and tenants | yard, later |
| Labels and selectors (`-l app=web`) | ✓ metadata as labels, `?label=k=v&label=k` on machine listings, `machine ls -l` (ADR 0025) | `!=` and set-based selectors; selectors on events, top, usage | yard, later |
| Annotations | ✓ metadata | | |
| Namespaces | ✓ tenants | | |
| Finalizers, owner references, garbage collection | ◐ a tenant takes its gateway; forks are independent | | — |
| CRDs, admission webhooks, aggregated APIs | ✗ | briq is the extension layer | briq |
| TLS to the nodes (kubelet serving certificates) | ✓ a self-signed certificate per host, its SHA-256 pinned in the host record at bootstrap (ADR 0020) | | |
| AuthN, RBAC, service accounts | ◐ one API token, a metrics token, one token per host (fleet) | scoped tokens (read-only, per tenant) | yard, later |
| API priority and fairness | ✗ | per-client request limits | yard, later |
| Audit log | ◐ one line per request | the principal and the change on mutating calls | yard, later |

## Workloads

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Pod | ✓ machine | | |
| Change image, env, command, size (`kubectl apply`, `set image`, in-place resize) | ✗ PATCH takes sleep, metadata, egress | a PATCH applied at the next cold boot | yard |
| `kubectl exec -it`, attach | ◐ exec with stdin and streamed output, no TTY | a TTY | yard, later |
| `kubectl cp` | ✓ `/files` | | |
| Pod phases and conditions | ✓ states, `stopped_reason`, exit code, `ready` (ADR 0022) | | |
| Liveness, readiness, startup probes | ✓ in the daemon: exec, TCP, HTTP, Kubernetes's timings, 32 at once per host (ADR 0022) | gRPC probes | yard, later |
| `restartPolicy`, CrashLoopBackOff | ✓ `no`, `on-failure`, `always`, a retry count; 10 s doubling to 5 minutes, reset after 10 minutes, a `crash_loop` event | | |
| Readiness gates traffic (endpoints follow Ready) | ✓ the ingress, `/wait` and the gateway's start wait for `ready` | another replica to send to (groups) | yard, later |
| `terminationGracePeriod` | ✓ stop timeout, SIGTERM then reset | | |
| preStop hook | ✗ | | — |
| Requests, limits | ✓ size (vCPUs, memory) as cgroup limits | | |
| Init containers | ◐ boot steps (briq recipes) | commands the init runs before the main process | yard, later (briq composes them) |
| Sidecars | ✗ one main process; exec for the rest | | — |
| Deployment, ReplicaSet (replicas, rolling update) | ✗ | a group of machines behind one name | yard, later |
| StatefulSet | ◐ identity and a volume, no replicas | with groups | yard, later |
| Job | ✓ `restart: no` + exit code; briq's async exec | | |
| CronJob | ✗ | | briq: a schedule on a workload is briq's; a schedule on what the host owns (its disks: backups) is the host's |
| Ephemeral containers (debug) | ✓ exec | | |
| — | ★ sleep on idle, wake on connect | | |
| — | ★ suspend and resume in 0.2 s | Kubernetes checkpointing is alpha | |
| — | ★ fork with the disk | | |

## Scheduling and nodes

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Fit by resources | ✓ memory and disk, reserved at placement | | |
| Node selectors, node affinity, topology | ✓ a create's `region` places a new tenant on a host of it; a tenant never spans regions (ADR 0025) | autoscaling per region | yard, later |
| Pod affinity | ◐ a tenant's machines share a host, forced | | — |
| Cordon | ✓ drain | | |
| Taints, tolerations | ✗ | | — |
| Drain with eviction | ◐ drain stops placement; machines stay | evacuate a host from backups | yard |
| Node object, heartbeats | ✓ heartbeat every 15 s, `down` after a minute | | |
| Node conditions (MemoryPressure, DiskPressure) | ✓ `memory_pressure`, `disk_pressure` in status and the heartbeat, `host_condition` events; the fleet places nothing new on a host under pressure (ADR 0021) | | |
| Node-pressure eviction | ◐ thresholds and events; unused images removed under disk pressure | stopping machines to free memory or disk | yard |
| Cluster autoscaler | ◐ provisioner autoscaler, stub-tested, dry run by default | a first real order | yard |
| Node upgrades | ✗ by hand | `host upgrade`: drain, upgrade, back | yard |
| `kubectl top node` | ◐ `/v1/status`, committed memory and the pool on `/metrics` | the host's own CPU and memory use | yard |

## Networking

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Pod network (CNI) | ✓ a bridge and a /24 per tenant | | |
| Default isolation | ★ tenants isolated by default (Kubernetes: open) | | |
| Cluster DNS | ✓ `<name>.internal` | | |
| Service, ClusterIP load balancing | ✗ | with groups | yard, later |
| Ingress controller | ✓ L4 ingress per host, private to the edge | | |
| Ingress auth, TLS, hostnames | the router, Cloudflare in front | | briq |
| NetworkPolicy, egress | ✓ `open`, `via`, `none` | | |
| NetworkPolicy, by port and CIDR | ◐ blocked ports, a connection rate, a bandwidth cap per machine (ADR 0018) | allow-lists by CIDR | yard, later |
| NetworkPolicy, ingress between pods | ✗ | | yard, later |
| Egress gateway | ✓ tenant gateway | | |
| Static egress IP (cloud NAT) | ✗ every machine leaves through its host's address | an additional IP per host for a class of machines | yard (mechanism), briq (who gets it) |
| A pod network across nodes | ✗ a tenant on one host | `MESH.md` | yard, later |
| Dual stack | ✗ tenant IPv6 dropped | | yard, later |

## Storage

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| PV, PVC, StorageClass | ✓ a volume per machine | | |
| Volume expansion | ✗ | grow the zvol and the filesystem at boot | yard, later |
| VolumeSnapshot, restore | ◐ local snapshots (list, delete), fork, backups and restore anywhere | rollback to a named local snapshot | yard, later |
| Scheduled backups and retention (Velero) | ✗ on demand only | `backup: { every, keep }`, delete | yard (values from briq) |
| Encryption at rest (CSI, etcd secrets) | ✗ records, config drives and disks in clear (0600) | the pool encrypted at bootstrap, one key per host held by the fleet, handed over TLS at start, never on the host's disk | yard, before the first real host |
| emptyDir, tmpfs | ✓ `/tmp` | | |

## Configuration and images

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| ConfigMap, Secret as env and files | ✓ config drive, 0600, never answered back | | |
| Live update of mounted config | ✗ applied at the next cold boot | | — |
| imagePullSecrets per pod | ◐ registry credentials per host | per machine | yard, later |
| Image pull, cache | ✓ a root disk per digest, the tag's digest cached | a registry mirror | yard |
| Image garbage collection under disk pressure | ✓ unused images removed after `image_keep_days`, and oldest first while the pool is under `disk_free_pct` (ADR 0021) | | |
| Container log rotation | ✓ the console rotated past `console_max_mb` while running, one previous file kept, `/logs` across both (ADR 0021) | | |

## Observability

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| `kubectl logs`, timestamps | ✓ (`since` is a page cursor, not a time) | | |
| `kubectl logs -f` | ✓ `/logs?follow=true` as NDJSON across rotations, `machine logs -f`, through the fleet (ADR 0025) | | |
| `kubectl describe` | ✓ `briqyard machine describe` | | |
| Events | ✓ (API machinery) | | |
| kubelet `/metrics`, cAdvisor (per pod CPU, memory, disk, network) | ✓ per-machine series on `/metrics` from the tick's measure (ADR 0021) | | |
| kube-state-metrics (machines by state, restarts) | ✓ `briqyard_machine_state`, `_restarts_total`, `_boot_seconds` | | |
| metrics-server, `kubectl top pod` | ✓ `briqyard top`, `GET /v1/top` (the last 15 s) | | |
| Usage accounting (OpenCost, outside core) | ★ hourly usage buckets (ADR 0017) | | |
| Cost, billing | | | briq |

## Security and multi-tenancy

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| RuntimeClass (gVisor, Kata) | ★ every machine is a microVM under the jailer | | |
| Pod security, seccomp | ★ Firecracker's own seccomp; the guest is root in its VM only | | |
| ResourceQuota, LimitRange per namespace | ◐ a quota per tenant: machines, memory, vCPUs, disk, set by briq (ADR 0025) | LimitRange (a size per machine): briq's plan check | yard (values from briq) |
| Plans, what a plan allows | | | briq |
| Egress abuse (outside core) | ✗ | (Networking) | yard; the response to abuse is briq's |
| Private endpoints, tokens | | | briq |
| Workload identity (a token to a cloud API) | | the credential gateway | briq |
| PodDisruptionBudget, PriorityClass, HPA, VPA, RWX volumes | weighed, not needed: one machine per briq, no replicas | | — |

## Operations

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Control plane HA (etcd quorum) | ✗ one fleet process, one file | state the fleet can rebuild from the hosts | yard, later |
| etcd backup | ✗ | the registry file copied to the object store on each write | yard |
| Cluster provisioning | ✓ bootstrap script, provisioners | | |
| Version skew, upgrades | ✗ | `host upgrade` | yard |
| Multi-cluster | ◐ regions on hosts, placement by region (ADR 0025) | a fleet per region, or one across | yard, later |

## Order of work

Reviewed by the advisor (2026-10-20); the night's order, each with an ADR, unit tests, Linux CI and the VM suites, the stress driver after the items that touch the manager, the network or the store:

1. **Egress controls**: blocked ports, connection rate, bandwidth per machine. Built: ADR 0018.
2. **Events, watch, versions**, and `describe` from them.
3. **Metrics**: per machine series and machine states on `/metrics`, host conditions, image GC and log rotation under them, `top`.
4. **Probes**: exec, TCP, HTTP; `ready`, which the ingress and `/wait` follow; restart on liveness; a capped backoff with a `crash_loop` reason. Built: ADR 0022.
5. **Backups on a schedule**, retention, delete (closes ADR 0017's storage hole).
6. **TLS between the fleet and the hosts**, the certificate pinned at bootstrap. Built: ADR 0020.
7. **Changes at the next cold boot**: image, env, command, size by PATCH.
8. **Scheduling**: placement by region, hosts under pressure refused, labels on listings; quotas per tenant; logs follow. Built: ADR 0021 (pressure), ADR 0025.
9. **The edge** (briq, in parallel): its servers, Cloudflare in front, client IPs, WebSockets. Built: up-lab/briq#277 (draft).

Decided for the founder (advisor, 2026-10-20): the daemon runs scheduled backups from a policy briq sets; the pool is encrypted with one key per host held by the fleet, built before the first real host (after TLS); events stay per host and are read through the fleet, which keeps nothing; probes run in the daemon and briq's healthcheck moves onto them.

Later, in the tables above: groups and load balancing, the mesh, volume expansion, encryption at rest, scoped tokens, fleet HA, `host upgrade`, evacuation, a TTY for exec.
