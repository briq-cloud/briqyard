# briqyard against Kubernetes

briqyard is the Kubernetes of Firecracker: microVMs for services and sandboxes. This maps what Kubernetes offers the people who run workloads on it to what briqyard offers, and says where each gap belongs.

**The scope test** (2026-10-20): if the control plane above ran on Kubernetes, would this be provided by Kubernetes, or built in the control plane? Provided by Kubernetes → briqyard builds it. Built in the control plane even on Kubernetes → the control plane. The same line as usage and prices (ADR 0017).

Legend: ✓ equivalent · ◐ partial · ✗ missing · ★ briqyard goes further. Scope: **yard** = briqyard, **briq** = the control plane above briqyard (briq's API, router and edge), **—** = not needed. Written 2026-10-20; a row changes when the gap closes.

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
| `resourceVersion`, optimistic concurrency (409 on a stale write) | ✓ a machine's `version`, `If-Match` on PATCH, DELETE, start, stop, wake, restart (ADR 0019) | | |
| watch (list + watch, informers) | ✓ `GET /v1/events?watch=true` from a cursor; per host, or a tenant or a machine through the fleet | | |
| Events (`kubectl get events`, `describe`) | ✓ an event log per host, a closed list of reasons, `briqyard events` | events of endpoints and tenants | yard, later |
| Labels and selectors (`-l app=web`) | ✓ metadata as labels, `?label=k=v&label=k` on machine listings, `machine ls -l` (ADR 0025) | `!=` and set-based selectors; selectors on events, top, usage | yard, later |
| Annotations | ✓ metadata | | |
| Namespaces | ✓ tenants | | |
| Finalizers, owner references, garbage collection | ◐ a tenant takes its gateway; forks are independent | | — |
| CRDs, admission webhooks, aggregated APIs | ✗ | briq is the extension layer | briq |
| TLS to the nodes (kubelet serving certificates) | ✓ a self-signed certificate per host, its SHA-256 pinned in the host record at bootstrap (ADR 0020) | | |
| AuthN, RBAC, service accounts | ◐ one API token, a metrics token (daemon and fleet), one token per host (fleet) | scoped tokens (read-only, per tenant) | yard, later |
| API priority and fairness | ✗ | per-client request limits | yard, later |
| Audit log | ◐ one line per request | the principal and the change on mutating calls | yard, later |

## Workloads

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Pod | ✓ machine | | |
| Change image, env, command, size (`kubectl apply`, `set image`, in-place resize) | ✓ PATCH of image, entrypoint, cmd, env, files, size, ports, restart, `pending` until the next start, `POST /restart`; the root disk follows the image, the volume stays (ADR 0024) | a change to a running process (memory hot-plug) | |
| `kubectl exec -it`, attach | ✓ exec sessions over a WebSocket: stdin streamed, a terminal with resize, the exit code, the client's close ends the command, use while open, through the fleet (ADR 0029) | attach to the main process (its output is `logs -f`) | yard, later |
| `kubectl cp` | ✓ `/files` | | |
| Pod phases and conditions | ✓ states, `stopped_reason`, exit code, `ready` (ADR 0022) | | |
| Liveness, readiness, startup probes | ✓ in the daemon: exec, TCP, HTTP, Kubernetes's timings, 32 at once per host (ADR 0022) | gRPC probes | yard, later |
| `restartPolicy`, CrashLoopBackOff | ✓ `no`, `on-failure`, `always`, a retry count; 10 s doubling to 5 minutes, reset after 10 minutes, a `crash_loop` event | | |
| Readiness gates traffic (endpoints follow Ready) | ✓ the ingress, `/wait` and the gateway's start wait for `ready` | another replica to send to (groups) | yard, later |
| `terminationGracePeriod` | ✓ stop timeout, SIGTERM then reset | | |
| preStop hook | ✗ | | — |
| Requests, limits | ✓ size (vCPUs, memory) as cgroup limits; CPU shared by size under contention (`cpu.weight`, ADR 0030) | | |
| Block IO limits (no pod field: cgroup v2 `io.max` set on the node by hand, or a CSI driver's QoS) | ★ `disk_limits` per machine: MB/s and IOPS on each disk with a burst, by size from the host's config, changed live (ADR 0030) | | |
| Init containers | ◐ boot steps (briq recipes) | commands the init runs before the main process | yard, later (briq composes them) |
| Sidecars | ✗ one main process; exec for the rest | | — |
| Deployment, ReplicaSet (replicas, rolling update) | ✗ | a group of machines behind one name | yard, later |
| StatefulSet | ◐ identity and a volume, no replicas | with groups | yard, later |
| Job | ✓ `restart: no` + exit code; briq's async exec | | |
| CronJob | ✗ | | briq: a schedule on a workload is briq's; a schedule on what the host owns (its disks: backups) is the host's |
| Ephemeral containers (debug) | ✓ exec | | |
| — | ★ sleep on idle, wake on connect | | |
| — | ★ suspend and resume in 0.2 s; snapshots with memory, restored to resume where they were (ADR 0031) | Kubernetes checkpointing is alpha | |
| — | ★ fork with the disk | | |

## Scheduling and nodes

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Fit by resources | ✓ memory and disk, held at placement until the host reports them, given back when the host refuses, a destroy's at its answer (the scheduler's assume and forget, ADR 0044) | | |
| Node allocatable (`systemReserved`) | ✓ `capacity.reserved_memory_mb`, `reserved_threads`: what the host keeps for itself and a service beside the daemon (ADR 0028) | | |
| Node selectors, node affinity, topology | ✓ a create's `region` places a new tenant on a host of it; a tenant never spans regions (ADR 0025); each region's room and refusals on `/metrics` (ADR 0042) | | |
| Pod affinity | ◐ a tenant's machines share a host, forced | | — |
| Cordon | ✓ `host drain`, `host undrain`; a drained host is never forgotten (`retire` is its own state, ADR 0027) | | |
| Taints, tolerations | ✗ | | — |
| Drain with eviction | ◐ drain stops placement; machines stay | evacuate a host from backups | yard |
| Node object, heartbeats | ✓ heartbeat every 15 s, `down` after a minute | | |
| Joining a node (`kubeadm join`) | ✓ `host add`: a server bought by hand, bootstrapped over SSH with the fleet's `bootstrap:`, its SSH key and certificate pinned; its API on the private network (ADR 0028) | | |
| Node conditions (MemoryPressure, DiskPressure) | ✓ `memory_pressure`, `disk_pressure` in status and the heartbeat, `host_condition` events; the fleet places nothing new on a host under pressure (ADR 0021) | | |
| Node-pressure eviction | ◐ thresholds and events; unused images removed under disk pressure | stopping machines to free memory or disk | yard |
| Cluster autoscaler | ✓ outside the fleet, as in Kubernetes: a scaler reads the fleet's `/metrics` (`briqyard_fleet_unschedulable_total` by resource and region, `_free_mb`, `_largest_slot_mb`), buys a server and adds it with `host add`; the fleet buys none (ADR 0042) | the scaler itself | briq |
| Node upgrades | ◐ `host upgrade` (`--all` one host at a time): `upgrading`, the bootstrap script with the release, the daemon hands its machines over, back on a heartbeat from the new version (ADR 0027) | OS and kernel patching (a reboot): drain, `systemctl stop`, reboot, undrain by hand | yard |
| `kubectl top node` | ◐ `/v1/status`, committed memory and the pool on `/metrics` | the host's own CPU and memory use | yard |

## Networking

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Pod network (CNI) | ✓ a bridge and a /24 per tenant | | |
| Default isolation | ★ tenants isolated by default (Kubernetes: open) | | |
| Cluster DNS | ✓ `<name>.internal` | | |
| Service, ClusterIP load balancing | ✗ | with groups | yard, later |
| Ingress controller | ✓ L4 ingress per host, private to the edge | | |
| Pods reaching a `hostNetwork` pod (an edge on the node) | ✓ `network.host_ports`, at the host's addresses, for machines with egress (ADR 0028) | | |
| Ingress auth, TLS, hostnames | the control plane's router and edge | | briq |
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
| Volume expansion | ✓ a PATCH grows the zvol at once, never smaller, the quota and the pool checked; the init grows the ext4 filesystem online at the next boot, `pending` until then (ADR 0040) | a growth seen by a running guest | |
| VolumeSnapshot, restore | ★ named snapshots of both disks, restored in place with newer snapshots, forks and the backup chain kept (ADR 0031); fork; backups and restore anywhere | a fork from a named snapshot | yard, later |
| Scheduled backups and retention (Velero) | ✓ `backup: { every, keep }` run by the daemon, whole chains pruned, delete, a destroyed machine's kept `keep_destroyed_days` (ADR 0023) | | yard (values from briq) |
| Encryption at rest (CSI, etcd secrets) | ✓ the pool encrypted at its creation (ZFS, AES-256-GCM), one key per host kept by the fleet and handed to that host at start, or a file on a single host; records, config drives, consoles and the image cache on the pool; no swap (ADR 0026); backups raw, ciphertext in the store, the key asked by its id at a restore (ADR 0035) | key rotation | yard |
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
| kubelet `/metrics`, cAdvisor (per pod CPU, memory, disk, network) | ✓ per-machine series on `/metrics` from the tick's measure (ADR 0021); disk bytes and throttling from Firecracker (ADR 0030) | | |
| kube-state-metrics (machines by state, restarts) | ✓ `briqyard_machine_state`, `_restarts_total`, `_boot_seconds` | | |
| metrics-server, `kubectl top pod` | ✓ `briqyard top`, `GET /v1/top` (the last 15 s) | | |
| Metrics pipeline (Prometheus finding kubelets through the API server) | ✓ the fleet lists every host for Prometheus's HTTP discovery (`/v1/metrics/targets`) and relays each host's `/metrics` over its pinned TLS; Prometheus beside the fleet, optional, 90 days (ADR 0048) | | |
| Dashboards and alerts (kube-prometheus-stack's Grafana and rules) | ✓ Grafana with a fleet, a host and a machines and tenants dashboard, alerts to Slack: a host down, a condition, a pool over 80 %, a crash loop, no room (ADR 0048) | | |
| Usage accounting (OpenCost, outside core) | ★ hourly usage buckets (ADR 0017) | | |
| Prices, billing | | | briq |

## Security and multi-tenancy

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| RuntimeClass (gVisor, Kata) | ★ every machine is a microVM under the jailer | | |
| Pod security, seccomp | ★ Firecracker's own seccomp; the guest is root in its VM only | | |
| ResourceQuota, LimitRange per namespace | ◐ a quota per tenant: machines, memory, vCPUs, disk, set by briq (ADR 0025) | LimitRange (a size per machine): the control plane's check | yard (values from briq) |
| Egress abuse (outside core) | ✓ blocked ports, a connection rate, a bandwidth cap per machine, drops counted (ADR 0018) | | yard; the response to abuse is briq's |
| Private endpoints, tokens | | | briq |
| Workload identity (a token to a cloud API) | | the credential gateway | briq |
| PodDisruptionBudget, PriorityClass, HPA, VPA, RWX volumes | weighed, not needed: one machine per briq, no replicas | | — |

## Operations

| Kubernetes | briqyard | Gap | Scope |
|---|---|---|---|
| Control plane HA (etcd quorum) | ✗ one fleet process, one file | state the fleet can rebuild from the hosts | yard, later |
| etcd backup | ✓ the registry written to the object store once a minute when it changed and before a key is served, encrypted with age to a key kept offline; `briqyard-fleet restore` (ADR 0032) | | |
| Cluster provisioning | ✓ bootstrap script, `host add`; the pool a mirror, the public interface closed to all but SSH (ADR 0028); servers bought outside briqyard (ADR 0042) | | |
| Version skew, upgrades | ✓ every binary and the init say `<version>+<commit>`; the wire is additive, unknown fields and values ignored; the fleet first, a host never newer (ADR 0027) | the init travels in the root disk: old inits live on until an image change | yard |
| Multi-cluster | ◐ regions on hosts, placement by region (ADR 0025) | a fleet per region, or one across | yard, later |

## Built since the map was written

Each with an ADR, unit tests, Linux CI and the VM suites: egress controls (ADR 0018); events, watch and versions (ADR 0019); metrics, host conditions, image GC and log rotation (ADR 0021); probes (ADR 0022); scheduled backups and retention (ADR 0023); TLS between the fleet and the hosts (ADR 0020); changes at the next cold boot (ADR 0024); placement by region, labels, quotas, logs follow (ADR 0025); encryption at rest (ADR 0026); a TTY for exec (ADR 0029).

Decided 2026-10-20: the daemon runs scheduled backups from a policy the control plane sets; the pool is encrypted with one key per host held by the fleet; events stay per host and are read through the fleet, which keeps nothing; probes run in the daemon and a control plane's healthcheck moves onto them.

Later, in the tables above: groups and load balancing, the mesh, scoped tokens, fleet HA, OS patching through the fleet, evacuation.
