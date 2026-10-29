# ADR 0057: The fleet ships as an image, the host daemon does not

Date: 2026-10-29 · Status: accepted; amends ADR 0051 (what keeps the fleet's listener, in a container)

## Context

`briqyard-fleet` is a control process: an HTTP API, a registry file, `ssh` to install hosts, calls to the hosts' APIs. It needs a network, two directories and a few secrets, and it can run anywhere that reaches the hosts (`OPERATIONS.md`, "A fleet"). Today it is a binary and a systemd unit (`hack/briqyard-fleet.service`) copied to the server by hand. Operators who run their other services as containers have to keep one binary and one unit apart, and upgrade it by `scp`.

`briqyardd` is the opposite: it owns the machine it runs on.

| The host daemon needs | A container gives |
|---|---|
| ZFS: the pool's datasets and zvols, `zfs load-key`, `/dev/zfs` | the host's kernel module, but the datasets and the mounts of the pool are the host's namespace |
| `/dev/kvm`, a Firecracker and a jailer per machine, cgroups and `chroot`/mount namespaces per jail | privileged, with the host's cgroup and mount namespaces |
| nftables tables, bridges and TAPs, `ip_forward`, the DNS listener on the bridges | `NET_ADMIN` in the host's network namespace |
| Machines that outlive the daemon at a hand-over (ADR 0027): Firecracker processes stay, the next daemon adopts them | a container's processes end with it; a hand-over is a new container |
| Its listeners kept in systemd's store across the hand-over (ADR 0051) | nothing equivalent |

Run with `--privileged`, `--network host`, `--pid host` and the pool's mounts, a container would be a systemd unit with extra steps, with no isolation and a hand-over that kills what it hands over. Kubernetes draws the same line: the kubelet is a systemd service on the node, and the control plane's components are the pods (`KUBERNETES-MAP.md`).

## Decisions

**The fleet ships as an image: `ghcr.io/briq-cloud/briqyard-fleet:<version>` and `:latest`.** Published by the release workflow on a `v*` tag, one manifest for `linux/amd64` and `linux/arm64`. A tag with a `-` (a pre-release) gets no `:latest`.

**It is built from the release's binaries, not from source.** The `build` job already makes both architectures (a native runner each); the `image` job lays `briqyard-fleet` and `briqyard` out in the build context and runs `docker buildx` with `docker/fleet/Dockerfile`. The image holds exactly the bytes of the release and its `SHA256SUMS`, and the build does not compile twice. The binaries are glibc, built on Ubuntu 24.04 (glibc 2.39), so the base is `debian:trixie-slim` (2.41). A distroless base was rejected: the fleet runs the `ssh` client to install and upgrade hosts (ADR 0028), which distroless has not, and the health check needs a client.

| | |
|---|---|
| Contents | `briqyard-fleet`, `briqyard` (the CLI, for `docker exec`), `openssh-client`, `curl`, CA certificates. The bootstrap script is inside the binary |
| User | uid and gid 10001, no capability |
| Volumes | `/var/lib/briqyard-fleet` (the registry and pinned SSH host keys), `/etc/briqyard` (`fleet.yaml`, the SSH key, TLS files) |
| Configuration | the file, as for the unit; credentials by environment (`--env-file`), as `fleet.env` |
| Health | `HEALTHCHECK` on `/healthz`, at the address `listen` names, TLS or plain |
| Stop | SIGTERM: stop accepting, 2 s for the calls in flight (ADR 0051), exit 0 |

No change to the fleet's code: it already reads its configuration from a path, its credentials from the environment, logs JSON on stdout, handles SIGTERM, and does not touch systemd outside `NOTIFY_SOCKET` and `LISTEN_FDS`, which a container does not set (`Listeners::from_env`).

**The host daemon stays a systemd service installed by `hack/bootstrap-host.sh`.** The fleet does not install it into a container and no image of it is published.

**The unit stays supported.** The docs say both; the image is for operators who want the fleet as a container, not a replacement.

**What replaces the file descriptor store (ADR 0051): nothing; a restart policy and a short gap.** Docker has no equivalent of systemd's store, and socket activation by the runtime is not available. A container's listener closes with its process, so a call made between the stop and the new start is refused instead of queued. The fleet is control only (the data path is each daemon's ingress), and a refusal costs little: a host sends its heartbeat every period, so one missed is followed by the next, a `host upgrade` interrupted leaves its host `draining` (as a fleet restart does under systemd), and any other call is asked again by its caller. The gap is the swap: the new image is pulled before the old container stops. Measured with `docker restart` on a Mac (OrbStack, arm64), polling `/healthz` every 20 ms: refused for 1.25 s. On a Linux server this has not been measured. `--restart unless-stopped` replaces `Restart=on-failure`, with Docker's own backoff.

**On the network: the host's, for the layout of `OPERATIONS.md`.** A host's heartbeat and pool key request are checked against the address they come from (ADR 0026), and an edge's `X-Forwarded-For` is trusted only from a loopback peer. A published port on a bridge network rewrites the peer to the bridge's gateway for traffic from the server itself. The docs give `--network host`, which changes nothing the fleet sees, and name the bridge for a fleet that terminates TLS itself with no proxy of ours in front.

## Rejected

| Alternative | Why not |
|---|---|
| The host daemon in a privileged container | The table above: no isolation gained, a hand-over that ends the machines |
| An image built from source in the Dockerfile | A second compile of the same code, a second set of bytes to trust; the release's checksums would not describe the image |
| Static musl binary and `FROM scratch` or distroless | The release is glibc; a musl build changes the allocator and the DNS resolver for everyone to save a base; and `ssh` is still needed |
| A systemd-style store in the container (an init, `socat`, a sidecar holding the socket) | A second process to keep a socket for a gap of about a second, on a control path callers retry |
| Kubernetes manifests | One replica with a registry file; a Deployment would suggest two, which the registry forbids |

## Consequences

- The release has a second job, and a GHCR package: while the repository is private so is the image, pulled with a token that reads packages (`docker login ghcr.io`).
- An upgrade of the fleet is a pull and a container swap; `scp` of the binary and the unit stay for the unit's operators.
- A file the container reads (the SSH key, `fleet.yaml`) is owned by uid 10001.
- Reopen when a runtime offers listener hand-over to a container, or when the gap matters to a caller that cannot retry: the unit is the answer then.
