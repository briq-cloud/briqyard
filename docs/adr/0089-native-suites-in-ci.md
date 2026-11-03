# 0089 — Native suites on hosted KVM runners

## Decision

Run `hack/e2e.sh` and `hack/fleet-smoke.sh` on a disposable `ubuntu-24.04`
GitHub-hosted runner. Keep the existing required checks and release workflow unchanged.
PRs touching the workspace, API, scripts or native workflow run against the PR head SHA.
Manual dispatch accepts a source ref; the summary records the resolved commit.
No repository credentials persist in the checkout, and the job has read-only permissions.

The host uses the real `bootstrap-host.sh` checked release path with freshly built
workspace binaries and the digest-pinned v0.1.17 checked Firecracker/jailer bundle.
The installer verifies the bundle's provenance and patches before activation. Its
pinned guest kernel, encrypted file-backed ZFS pool and networking are unchanged.
`hack/install-dev.sh`, shared with `hack/vm.sh`, installs systemd units, the mirror,
SSH authorization and a local release directory for the fleet upgrade check.
It replaces the bootstrap-generated `briqyardd.service` with the development unit and
installs the binaries in `/usr/local/bin`, so the suites run under the development unit,
as on the Lima bench, not under the unit a production bootstrap writes.

The harness (`hack/native-ci.sh`, `hack/install-dev.sh`) comes from the workflow's own
revision; `bootstrap-host.sh`, `hack/config.dev.yaml`, the units and the mirror installer
come from the tested source. A dispatch on a source ref much older than the workflow can
therefore fail from script skew, not from a defect: compare such a run with the same
harness on main before reading it as a regression. Dispatches for different refs run
concurrently; each ref has its own concurrency group.
The CI fixture reserves 12 GiB for guest admission and caps the ZFS ARC at 1 GiB;
its 24 virtual CPU admission slots match the development fixture (4 physical
runner cores). The pool is a sparse 40 GiB file. These are suite fixtures,
not production capacity or performance recommendations. The setup script refuses
to run outside a GitHub-hosted runner.

The runner is dedicated to this daemon: stop Docker and remove its host-wide
FORWARD drop policy before bootstrap. briqyard's own nftables chains continue to
apply the suite's egress and isolation checks. Docker documents that its forwarding
policy can drop unrelated routed traffic:
https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-on-a-router.

Each suite retains its complete log as an artifact and prints its final counts and
duration in the job summary. Early termination remains a failure. No checks are
relaxed and no `ALLOW_SKIPPED` override is set.

## Probe, 2026-11-03

[Probe run](https://github.com/briq-cloud/briqyard/actions/runs/41697160433).
Both runners installed `zfsutils-linux`, loaded ZFS and created/destroyed a 1 GiB
file-backed pool.

| Runner | CPU | RAM MiB | Root disk/free | Kernel | KVM |
|---|---|---:|---|---|---|
| ubuntu-24.04 | 4, Intel Xeon 6973P-C | 15982 | 145/86 GiB | 7.0.0-1017-azure | character device 10:232 |
| ubuntu-24.04-arm | 4, Neoverse-N2 | 15941 | 145/107 GiB | 7.0.0-1017-azure | absent |

Choose x86_64 because only it exposes KVM. ARM support requires a runner with KVM;
portable ARM checks continue independently. The probe's branch push trigger bootstraps
the new workflow before it exists on the default branch; it is removed after
the measurements, leaving manual dispatch.

## Qualification

The [first full run](https://github.com/briq-cloud/briqyard/actions/runs/41697866494)
used this branch's unchanged runtime code from main `2ae2ddbc880663a6045d3f381b4b2fe91d4883d5`.
Release build: 283 s. Host installation: 18 s. Alpine's first create, including
image pull, disk preparation and boot: 2.778 s (not a boot-only benchmark).

| Suite | Passed/total | Duration | Result |
|---|---:|---:|---|
| e2e | 270/279 | 732 s | 8 internet/traffic-accounting failures; 1 supplementary-group assertion |
| fleet-smoke | 33/33 | 58 s | full run, including SSH host upgrade and machine handover |

An [explicit main-ref dispatch](https://github.com/briq-cloud/briqyard/actions/runs/41698748711)
confirmed the tested commit `2ae2ddbc880663a6045d3f381b4b2fe91d4883d5`:
e2e 270/279 in 657 s, fleet-smoke 33/33 in 65 s. Build 282 s; installation
19 s; initial Alpine create 2.753 s. It reproduced the same nine failures.

The internet failures motivate the Docker forwarding-policy correction above.
The supplementary-group assertion remains enabled. Both suites reached their final summaries against exact main. This records current
failures; it does not qualify the runtime. The [corrected runner run](https://github.com/briq-cloud/briqyard/actions/runs/41701131348)
is still in progress at review handoff. It uses the same main runtime code (the
branch changes only CI, installation scripts and documentation). Its results must
be checked before treating the Docker correction as validated. The
supplementary-group assertion at `hack/e2e-machines.sh:71` remains an open problem;
no assertion or suite mode is disabled to turn the baseline green.
The older documentation's 263-check count predates the current suite additions.

## Two-host follow-up

The two-host suites assume independent root filesystems: both hard-code
`/etc/briqyard/config.yaml`, the `briqyardd` unit, and a pool named `byard`.
A second process on the same root would mutate the first host's files and pool.
A network namespace alone does not isolate those resources. A second hosted job
also needs an authenticated private transport between ephemeral runners.
Keep `fleet-two-hosts` and `fleet-restore` as a follow-up requiring proper host
isolation rather than rewriting their assertions or faking the second host.

## Additional hosted suites

Stress and monitoring each get an independent runner, in parallel with the original
job. Each builds the dispatched source and uses the harness from the workflow revision.
Actions remain SHA-pinned. Suite output, counts and elapsed seconds are retained even
on failure; the stress driver's exit status, API failures and invariant breaks remain
authoritative (its count varies with the observed resources).

Stress uses four namespaces, two 128 MiB machines each, four workers, two full
rounds, SIGKILL recovery and four churn cycles per namespace. Eight ordinary guests
consume 1 GiB before forks; four workers match the four physical cores. The full
12 GiB admission limit remains: the driver derives its four capacity-race machines
from free capacity, requiring accepted and refused starts without exceeding it.
All feature phases, host invariants and the default 32 MiB RSS-growth bound remain.

Monitoring installs the source's digest-pinned Prometheus/Grafana stack. Its fleet
registers the local daemon and an explicitly unreachable loopback endpoint, then waits
for ready/down states. This exercises all 18 existing checks, including down-host
503 and Prometheus up=0. The unreachable entry is not a simulated second daemon.
A running local machine provides disk/CPU observations; checking waits for at least 12
Prometheus samples (3 minutes at the 15 s scrape interval, capped at 300 s) before querying the dashboards. Credentials stay outside artifacts.

The two-host gate above remains: a second daemon's own state, pool, ports and unit
are insufficient because the unmodified suites address the same absolute config,
unit and pool on both hosts. Mount/systemd isolation would require another host
fixture beyond a second daemon; it is not provided here. Hosted matrix jobs have no
direct private connectivity or shared lifecycle orchestration. No transport or
credentials are provisioned. The harness explicitly logs this environment gate in
each added job and its summary; neither two-host suite is invoked partially or
reported as passing. The existing 29 and 10 checks remain unchanged.

Qualification of the added jobs against main is pending the first dispatch.

## Independent QEMU second-host probe

The [two-host probe](https://github.com/briq-cloud/briqyard/actions/runs/41734138767)
booted the checksum-pinned Ubuntu 24.04 cloud image dated 20261017 with QEMU/KVM,
`-cpu host`, two vCPUs and 6144 MiB on `ubuntu-24.04`. The runner's
`kvm_intel.nested` was `Y`; no reload was needed. SSH was ready after 14 s.
Inside QEMU, `/dev/kvm` exposed API version 12 and `KVM_CREATE_VM` took 0.006195 s.
This establishes a usable VM creation interface, not Firecracker boot qualification.

The native `two-hosts` job now attempts both complete suites with this independent
root, systemd and identically named encrypted `byard` pool. It reuses bootstrap and
`install-dev.sh`; the second host gets its pool key from the runner's fleet.
QEMU user networking forwards its API to 127.0.0.2:27420 and reaches the
fleet through 10.0.2.2. SSH authenticates with an ephemeral key and a pre-pinned
host key. No external rendezvous, secret or service account is used. The runtime
is built once from the selected source and transferred with its verified release
assets. Suite assertions and counts remain unchanged. A cold Alpine create and
exec on the nested host measure actual Firecracker usability before the suites.

Qualification of Firecracker and the 29/10-check suites is pending the native run.
The existing two-host gate remains until both suites actually execute.

The first full-main attempt failed before suites: both host URLs used 127.0.0.1
with different ports, but fleet host identity deliberately compares the address
without the port (`Registry::expecting`). The pool-key call matched the local
host's empty credential and returned 401. Give the second host its own loopback
address, 127.0.0.2, rather than changing authentication. Manual dispatch can select
only the two-host job for targeted fixture validation.
