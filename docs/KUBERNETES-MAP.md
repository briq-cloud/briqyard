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
| Labels and selectors (`-l app=web`) | ◐ metadata, no selection | `?label=k=v` on listings | yard |
| Annotations | ✓ metadata | | |
| Namespaces | ✓ tenants | | |
| Finalizers, owner references, garbage collection | ◐ a tenant takes its gateway; forks are independent | | — |
| CRDs, admission webhooks, aggregated APIs | ✗ | briq is the extension layer | briq |
| AuthN, RBAC, service accounts | ◐ one API token, a metrics token, one token per host (fleet) | scoped tokens (read-only, per tenant) | yard, later |
| API priority and fairness | ✗ | per-client request limits | yard, later |
| Audit log | ◐ one line per request | the principal and the change on mutating calls | yard, later |

## Workloads

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Pod | ✓ machine | | |
| Pod phases and conditions | ◐ states, `stopped_reason`, exit code | a `ready` condition | yard (probes) |
| Liveness, readiness, startup probes | ◐ the init answers; briq runs its healthcheck by exec from the control plane | probes in the daemon: exec, TCP, HTTP; readiness and restart on liveness | yard |
| `restartPolicy`, CrashLoopBackOff | ◐ `no`, `on-failure`, `always` with a retry count | a backoff between restarts | yard |
| `terminationGracePeriod`, preStop | ✓ stop timeout, SIGTERM then reset | | |
| Requests, limits | ✓ size (vCPUs, memory) as cgroup limits | | |
| Init containers, sidecars | ◐ boot steps (briq recipes) | | briq |
| Deployment, ReplicaSet (replicas, rolling update) | ✗ | a group of machines behind one name | yard, later |
| StatefulSet | ✓ a machine with a volume | | |
| Job | ✓ `restart: no` + exit code; briq's async exec | | |
| CronJob | ✗ | | briq |
| Ephemeral containers (debug) | ✓ exec | | |
| — | ★ sleep on idle, wake on connect | | |
| — | ★ suspend and resume in 0.2 s | Kubernetes checkpointing is alpha | |
| — | ★ fork with the disk | | |

## Scheduling and nodes

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Fit by resources | ✓ memory and disk, reserved at placement | | |
| Node selectors, node affinity, topology | ◐ hosts carry a region, placement ignores it | placement within the asked region | yard |
| Pod affinity | ✓ a tenant's machines share a host | | |
| Taints, cordon | ✓ drain | | |
| Drain with eviction | ◐ drain stops placement; machines stay | evacuate a host from backups | yard |
| Node object, heartbeats | ✓ heartbeat every 15 s, `down` after a minute | | |
| Node conditions (MemoryPressure, DiskPressure) | ✗ | host conditions; placement refuses a host under pressure | yard |
| Node-pressure eviction | ✗ a full pool stops every machine | headroom thresholds, events | yard |
| Cluster autoscaler | ✓ provisioner autoscaler (dry run by default) | real orders | yard |
| Node upgrades | ✗ by hand | `host upgrade`: drain, upgrade, back | yard |
| `kubectl top node` | ◐ `/v1/status` | | yard (metrics) |

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
| NetworkPolicy, by port and CIDR | ✗ | blocked ports, rate and bandwidth limits per machine | yard |
| NetworkPolicy, ingress between pods | ✗ | | yard, later |
| Egress gateway | ✓ tenant gateway | | |
| A pod network across nodes | ✗ a tenant on one host | `MESH.md` | yard, later |
| Dual stack | ✗ tenant IPv6 dropped | | yard, later |

## Storage

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| PV, PVC, StorageClass | ✓ a volume per machine | | |
| Volume expansion | ✗ | grow the zvol and the filesystem at boot | yard, later |
| VolumeSnapshot, restore | ✓ snapshots, fork, backups, restore anywhere | | |
| Scheduled backups and retention (Velero) | ✗ on demand only | `backup: { every, keep }`, delete | yard (values from briq) |
| Encryption at rest (CSI) | ✗ | ZFS native encryption | yard |
| emptyDir, tmpfs | ✓ `/tmp` | | |

## Configuration and images

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| ConfigMap, Secret as env and files | ✓ config drive, 0600, never answered back | | |
| Live update of mounted config | ✗ applied at the next cold boot | | — |
| imagePullSecrets per pod | ◐ registry credentials per host | per machine | yard, later |
| Image pull, cache | ✓ a root disk per digest, the tag's digest cached | a registry mirror | yard |

## Observability

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| `kubectl logs --since`, timestamps | ✓ | | |
| `kubectl logs -f` | ✗ | follow | yard |
| `kubectl describe` | ✓ `briqyard machine describe` | | |
| Events | ✓ (API machinery) | | |
| kubelet `/metrics`, cAdvisor (per pod CPU, memory, disk, network) | ◐ `/v1/machines/{id}/stats`, `/metrics` for the host | per machine series on `/metrics` | yard |
| kube-state-metrics (machines by state, restarts) | ✗ | the same series | yard |
| metrics-server, `kubectl top pod` | ◐ stats | `briqyard top` | yard |
| Usage accounting (OpenCost, outside core) | ★ hourly usage buckets (ADR 0017) | | |
| Cost, billing | | | briq |

## Security and multi-tenancy

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| RuntimeClass (gVisor, Kata) | ★ every machine is a microVM under the jailer | | |
| Pod security, seccomp | ★ Firecracker's own seccomp; the guest is root in its VM only | | |
| ResourceQuota, LimitRange per namespace | ✗ | quotas per tenant (machines, memory, disk) | yard (values from briq) |
| Plans, what a plan allows | | | briq |
| Egress abuse (outside core) | ✗ | (Networking) | yard; the response to abuse is briq's |
| Private endpoints, tokens | | | briq |

## Operations

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Control plane HA (etcd quorum) | ✗ one fleet process, one file | state the fleet can rebuild from the hosts | yard, later |
| Cluster provisioning | ✓ bootstrap script, provisioners | | |
| Version skew, upgrades | ✗ | `host upgrade` | yard |
| Multi-cluster | ◐ regions on hosts | placement by region | yard |

## Order of work

Tonight, in this order, each with unit tests, Linux CI and the VM suites:

1. **Egress controls**: blocked ports, connection rate, bandwidth per machine (NetworkPolicy by port, plus abuse).
2. **Events, watch, versions**: the API machinery an imperative API needs to be driven safely.
3. **Metrics**: per machine series and machine states on `/metrics`, host conditions, `top`.
4. **Probes**: exec, TCP, HTTP; `ready`; restart on liveness; a restart backoff.
5. **Scheduling**: placement by region, refusing hosts under pressure, labels on listings.
6. **Backups on a schedule**, retention, delete.
7. **Quotas per tenant**, logs follow, `describe`.
8. **The edge** (briq): its hosts, Cloudflare in front, client IPs.

Later, in the tables above: groups and load balancing, the mesh, volume expansion, encryption at rest (its keys first), scoped tokens, fleet HA, `host upgrade`, evacuation.
