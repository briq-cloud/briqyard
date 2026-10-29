# ADR 0051: Upgrades without refused connections: listeners kept by systemd, a bounded drain, use counted in the kernel

Date: 2026-10-29 · Status: proposed; amends ADR 0027 (what a hand-over costs the traffic) and ADR 0017 (how endpoint bytes are counted)

## Context

`host upgrade` hands the machines over (ADR 0027): the old `briqyardd` exits on SIGUSR2, every Firecracker keeps running, the next daemon adopts them. The machines see nothing. Their traffic does: the ingress is the daemon's (a userspace proxy per TCP endpoint and the HTTP listener routing by `Host`, ADR 0003), and so is every listening socket. Measured in the dev VM with `hack/upgrade-probe.sh` (§5), on `main`:

| During | What fails |
|---|---|
| `host upgrade` | for 1.2 s, every new connection to an endpoint (TCP and HTTP) refused, every API call refused, every call through the fleet a 502 `host_unreachable`; every open endpoint connection reset |
| `systemctl restart briqyard-fleet` | the fleet's API refused for 0.2 s |

Read from the code:

| Path | At a hand-over | Why |
|---|---|---|
| TCP endpoint or HTTP, open connection | reset | the proxy's sockets close with the old daemon |
| TCP endpoint or HTTP, new connection | refused for the gap | nothing listens from the signal until the next daemon has unlocked its pool, laid out its datasets, applied its tables, adopted every machine and bound again (`main.rs`, `Manager::new`) |
| The daemon's API | refused for the gap; a request running 30 s after the signal cut | its listener closes at the signal and is bound last at the next start |
| A forwarded call through the fleet | 502 `host_unreachable` | the fleet does not retry a host |
| The fleet's API at its restart | refused; calls in flight cut | a plain `systemctl restart`, no graceful stop |

The install (most of the 6.7–9.6 s a host upgrade takes on a real host) is not the gap: the old daemon serves through it. The gap is the signal to the next daemon's bind.

Nobody in front retries a refusal. briq's router answers a refused upstream with a 502 at once, and its TCP edge closes the client's connection. briq's adapter repeats a GET or a DELETE three times (0.5 s, then 1 s apart) and never repeats a POST that got no answer. Both wait out a slow answer: a few seconds of latency they tolerate, a refusal they pass on.

**How Kubernetes keeps traffic through the same operations:**

| Operation | What keeps traffic | Source |
|---|---|---|
| kubelet restart | The containers keep running: the runtime holds them, and containerd reconnects to its shims at its own start. The kubelet keeps each container's readiness across its restart (it used to reset it to false). | [What happens on a restart](https://kubernetes.io/docs/reference/node/what-happens-on-restart/), [KEP-4781](https://www.kubernetes.dev/resources/keps/4781/), [containerd runtime v2](https://github.com/containerd/containerd/blob/main/docs/runtime-v2.md) |
| kube-proxy restart | The data path is kernel rules (iptables, IPVS, nftables) that kube-proxy writes and only `--cleanup` removes; it rewrites its chains in one transaction, and only a flow's first packet meets the rules: conntrack holds the NAT of established flows. | [Virtual IPs](https://kubernetes.io/docs/reference/networking/virtual-ips/), [kube-proxy](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/), [its nftables proxier](https://github.com/kubernetes/kubernetes/blob/master/pkg/proxy/nftables/proxier.go), [nftables NAT](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)), [atomic replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement) |
| A node port on 127.0.0.1 | Not in the kernel path of the nftables mode: `route_localnet` reopens CVE-2020-8558. It comes back as a userspace TCP proxy (alpha). | [KEP-3866](https://github.com/kubernetes/enhancements/blob/master/keps/sig-network/3866-nftables-proxy/README.md), [KEP-6032](https://www.kubernetes.dev/resources/keps/6032/) |
| External traffic to a node port | Source-NATed to the node by default (`externalTrafficPolicy: Cluster`) | [Source IP](https://kubernetes.io/docs/tutorials/services/source-ip/) |
| Ingress controller reload or upgrade | The listening sockets outlive the process that accepts on them; the old one drains within a bound. nginx: a reload starts new workers on the same sockets, a binary upgrade starts a new master that inherits them; ingress-nginx gives old workers 240 s. Envoy and HAProxy pass the sockets to the next process over a Unix socket. | [nginx](https://nginx.org/en/docs/control.html), [ingress-nginx](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/), [Envoy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart), [HAProxy](https://docs.haproxy.org/3.2/management.html) |
| Scale from zero | Knative's activator, a userspace proxy, takes a revision's traffic only while it lacks capacity: it buffers, asks for a scale-up, and is taken out of the path once pods can take the burst. | [Request flow](https://knative.dev/docs/serving/request-flow/), [target burst capacity](https://knative.dev/docs/serving/load-balancing/target-burst-capacity/) |

The rule they share: **the socket, or the data path, does not live in the process being restarted.** Here, the smallest step that ends refusals is the socket; the data path in the kernel is a later step with costs of its own (§4).

## Decisions

### 1. Every listening socket is kept by systemd while no daemon runs

**The daemon's listeners go into systemd's file descriptor store:** the API (`api`), the HTTP ingress (`http`), and each TCP endpoint's, named by its id (`ep_…`: sd_notify(3) takes a name of up to 255 characters without `:`). A process binds as now, sets its backlog explicitly (4096, `socket2`), and hands the socket to PID 1 (`sd_notify` over `NOTIFY_SOCKET` with the descriptor as `SCM_RIGHTS`: `FDSTORE=1`, `FDNAME=<name>`; a few lines over `nix`, no libsystemd). systemd passes what it stores to the next start of the service ([the file descriptor store](https://systemd.io/FILE_DESCRIPTOR_STORE/)): the next process takes back the names it knows (`LISTEN_FDS`, `LISTEN_FDNAMES`), binds only what it lacks, and closes and removes from the store any name it does not know (an endpoint removed while no daemon ran). A removed endpoint's socket leaves the store (`FDSTOREREMOVE=1`) and the daemon closes its own copy: otherwise PID 1 keeps the port bound, and the next endpoint given that port could not bind. While no daemon runs, the kernel completes each handshake and queues the connection: a client waits for the gap instead of being refused. Outside systemd (tests, a shell) there is no store and nothing changes. The unit: `NotifyAccess=main`, and `FileDescriptorStoreMax=` set by `bootstrap-host.sh` from `ingress.tcp_ports` (the range's ports and two). Past that size systemd refuses the socket, and that one listener closes with the daemon that holds it: refused for the gap, as today. Sources: [systemd.service(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), [sd_notify(3)](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html), [sd_listen_fds(3)](https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html).

**A hand-over ends in an automatic restart, so the store survives it.** systemd keeps the store while a restart is expected (a `Restart=` restart, a `systemctl restart`) and releases it when the unit stops: `FileDescriptorStorePreserve=`'s default, `restart`, documented since systemd 254 (Ubuntu 26.04 ships 259). The daemon now ends its hand-over with status 75, on which the unit starts it again at once (`RestartForceExitStatus=75`) and which is not a failure (`SuccessExitStatus=75`: a hand-over logged as failed would read as one to whoever watches the unit), instead of exiting 0 for `bootstrap-host.sh` to start it. A shutdown that ran past its 60 s cap exits 75 too when it was a hand-over: the machines are still running, and the next daemon adopts them as after a crash. `RestartSec=0`: a crash loop is still bounded by `StartLimitBurst` (5 starts in 10 s); when it trips, the unit stops, the store is released, and the clients it queued are reset. Still ADR 0027's order: the old one exits, then the next one starts. A stopped daemon still refuses, as a stopped service should. The script still sends SIGUSR2 and waits for the main process to change (the fleet's upgrade detects the new start as before); its `systemctl start` runs the restart at once on a unit in `activating (auto-restart)`, and starts a daemon from before this ADR, which exits 0.

**The fleet's listener is kept the same way**, across `systemctl restart briqyard-fleet`.

### 2. The old process drains within 2 s

**At SIGUSR2 the daemon stops accepting at once and finishes what it holds, for 2 s at most**: API requests in flight (30 s before) and open endpoint connections, one bound for both, since every queued client waits it whichever of the two holds the old daemon. 2 s, not the 10 s first proposed: long-lived connections (Postgres pools, WebSockets) are common in briq's traffic, so the bound is paid on nearly every upgrade by every connection and call made during it (10.2 s measured with 4 connections held, §5), and such a connection is cut at the end whatever the bound; 2 s still lets a short request end. It is adjusted after a measurement on a real host. Open endpoint connections keep splicing and counting their bytes meanwhile. ADR 0027 rules out two daemons at once, not two phases at once: the machines' locks are taken and the usage written while the connections drain, so the gap is the longer of the drain and the hand-over, not their sum. Once the drain ends (every connection closed, or the bound), the usage is written again with what the connections passed meanwhile. What runs past the bound is cut, as today: a WebSocket, a database connection of a pool, an exec, a session, a log follow, a watch (which resumes from its cursor, ADR 0019). A stop (SIGTERM) drains first, then suspends the machines: suspending them would end the connections.

**The fleet gets the graceful stop it lacks**: SIGTERM stops accepting, its calls get the same 2 s. A `host upgrade` still waiting then leaves its host `draining`, as a fleet restart does today.

**The daemon logs the gap a client sees**: the old daemon writes the time of the signal with its hand-over, and the next one logs `serving again` with `gap_ms`, from that signal to its listeners accepting, with what took it (pool, tables, adoption).

### 3. Use and endpoint bytes are counted by nftables, per machine

**A new connection through an endpoint is use, counted in the kernel**: a counter set `ingress_conns` in `inet briqyard` beside the internet ones (ADR 0017), whose element per machine counts the first packet of each of the proxy's connections to it (`ct state new` with the proxy's mark, below; a bare SYN is already `new`, before any handshake). The mark is required: readiness and liveness probes are TCP connections to the machine every period (ADR 0022), and counting them would keep every probed machine awake for good. The tick touches a machine whose count grew since its last reading. It replaces the `touch` at the proxy's dial, and keeps working when the proxy is no longer in the path (§4). Bytes are never use: TCP keepalives and a pool's idle connections would keep a machine awake for good too.

**Endpoint bytes too**: `ingress_in` (to the machine) and `ingress_out` (from it). The proxy's connections to a machine start on the host, so they cross the `output` and `input` hooks, not `forward`: the table gets an `output` chain (filter), where the proxy's sockets, marked with `SO_MARK`, copy the mark to their flow (`ct mark set meta mark`), and the counters take the flows with that mark, in `output` toward the machine and in `input` from it. Probes and the daemon's own dials carry no mark. Both are added while the proxy still runs, so the kernel's counts and the proxy's can be compared on the same traffic before the proxy's go.

**The new definition**: `ingress_in_bytes` and `ingress_out_bytes` are IP bytes on the machine's side, headers and retransmits included, as the internet's already are; the proxy counted payload on the client's side. On the probe's traffic the difference is measured and written here.

### 4. The kernel path for ready machines is its own ADR, later

Kernel DNAT from the host port to a ready machine, with today's proxy as the activator for machines asleep, starting or not ready (Knative's proxy/serve split; readiness gating is the absence of a rule), ends the resets as well as the refusals and takes the proxy's copy off the CPU. It is justified by those, not by upgrades alone, and it has to settle:

| | |
|---|---|
| The forward chain assumes internet traffic only | DNAT'd flows need `ct status dnat` carve-outs before `egress_none`, the limits and the internet counters, or replies are dropped for a machine without egress, counted as `internet_out` and throttled |
| `via` machines address only their gateway and `.1` | SNAT to the tenant's `.1`, as Kubernetes's `Cluster` policy does: the guest sees what it sees today |
| Loopback | the default `bind: 127.0.0.1` and a proxy in front dialling it: DNAT of loopback needs `route_localnet` (CVE-2020-8558). The proxy in front moves to the private address; loopback stays on the activator |
| `allowed_clients` is an input rule | it no longer applies after DNAT: checked in prerouting with the rule, or in forward on `ct original proto-dst`; and the host firewall's input chain (ADR 0028) is bypassed the same way |
| Stale flows | conntrack flushed for the machine at sleep, not-ready, move and destroy; at destroy it is a security matter (a reused address and a stale entry deliver an old client's bytes to the next tenant). The swap to the activator before a suspend in one transaction |
| IPv6 | the kernel path is IPv4; IPv6 ends at the proxy in front |
| Across a hand-over | the map, readiness (KEP-4781's behaviour) and the counts carried to the next daemon's render |

Rejected:

- **The HTTP ingress in a process of its own** (an ingress controller beside the kubelet): it moves the problem, since that process needs a lossless restart of its own and ships in the same release, so it restarts with the daemon; and it adds a wake call and a routes stream between the two.
- **`SO_REUSEPORT` and two instances**: two live daemons, while the records and the machines' locks are in one process; and closing a `SO_REUSEPORT` listener drops its queue unless `net.ipv4.tcp_migrate_req` is set ([ip-sysctl](https://docs.kernel.org/networking/ip-sysctl.html), [Cloudflare](https://blog.cloudflare.com/graceful-upgrades-in-go/)).
- **The sockets passed daemon to daemon** (`SCM_RIGHTS` over a Unix socket, Envoy's way): both alive at once, the same objection.
- **`FileDescriptorStorePreserve=yes`** instead of the restart: the store would outlive a stop, and a stopped daemon's clients would queue for a daemon that is not coming.
- **A retry contract for callers**: the router and the adapter would each need one; latency they already tolerate.

### 5. Measured, before and after

`hack/upgrade-probe.sh` (in the VM, through the fleet) makes a machine with an HTTP server and a line echo server, a TCP and an HTTP endpoint to each, and runs `hack/upgrade-probe.py` through them and against both APIs while `host upgrade` runs, twice (with no long-held connection, so the drain ends with the short ones, then with 4 held each way, so it runs to its bound), then while the fleet restarts. The probe opens a new connection per attempt (TCP, HTTP), keeps 4 long connections exchanging a line every 100 ms (TCP, HTTP), and GETs both APIs every 100 ms; an attempt ends `ok`, `refused`, `reset`, `timeout` (30 s, over the longest gap) or `failed`, a long connection broken counts a `cut`, `outage_ms` is the longest time between two `ok`s and `slowest_ms` the slowest `ok` (a queued connection shows here). `hack/e2e.sh` checks that a connection open across a hand-over within the bound survives and that new ones made during it are answered.

The dev VM (fc), 2026-10-29, `main` at 0323a8a against this change. Each probe opens a connection or makes a call every 50 to 100 ms; a cell is what failed of what was tried, then the longest time between two answers.

| Probe | `host upgrade`, before | after | with 4 connections held each way, after (10 s bound) | fleet restart, before | after |
|---|---|---|---|---|---|
| TCP endpoint, new connections | 23 refused of 348; 1.2 s | none of 397; 0.13 s | none of 259; 10.2 s | none | none |
| HTTP ingress, new requests | 23 refused of 348; 1.2 s | none of 397; 0.14 s | none of 259; 10.2 s | none | none |
| Long-held TCP and HTTP connections | 4 and 4 reset, then refused while reconnecting | — | 4 and 4 reset at the drain's end, reconnected at once | none | none |
| The daemon's API (`/v1/status`) | 12 refused of 176; 1.3 s | none of 202; 0.23 s | none of 133; 10.2 s | none | none |
| A call through the fleet | 11 `host_unreachable` of 182; 1.2 s | none of 210; 0.17 s | none of 137; 10.2 s | 1 refused of 99; 0.2 s | none of 99; 0.12 s |

The next daemon's `serving again`: `gap_ms` 129 (its own start 101 ms: 5 ms to the pool, 88 ms to adopt the machines) with nothing long open, 10 158 with the held connections, which kept the old daemon to the drain's bound, then 10 s. That run is why the bound is now 2 s (§2); the run at 2 s is added here before this ADR is accepted.

## What stays

| | After this ADR |
|---|---|
| A new connection, an API call | waits: the longer of the drain (up to 2 s, less when nothing long is open) and the hand-over, then the next daemon's start |
| An open connection | survives when it ends within the 2 s; longer ones are reset |
| A machine whose process exits during the gap | as ADR 0027: its exit report is lost |

Out of scope:

- **A reboot** (OS or host kernel): every machine stops. Keeping traffic through it needs another replica or a live move to another host (`../KUBERNETES-MAP.md`, groups, later).
- A crash: what the process held is reset; its listeners stay in the store, so new connections wait for the restart.
- A Firecracker upgrade for running machines: their process stays until their next start (ADR 0027).

## Consequences

- Every connection and call made during an upgrade is slower by the gap instead of refused; the gap is logged at each start.
- `ingress_*_bytes` change definition (§3) from the change that removes the proxy's counting.
- Built in two changes, each measured with the probe: (1) the store, the drain, the restart and the fleet's stop, with the e2e check; (2) the counters, with the parity test. The kernel path (§4) follows with its own ADR.
- Reopen the ingress process when the daemon's load and the ingress's must be apart, or when a drain longer than a client can wait is wanted.
