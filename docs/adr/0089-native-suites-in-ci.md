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
the new workflow before it exists on the default branch; retain manual dispatch only
after the measurements are collected.

## Qualification

Pending the first native suite completion. Record boot timing, suite counts and wall
clock durations here before marking the PR ready.

## Two-host follow-up

The two-host suites assume independent root filesystems: both hard-code
`/etc/briqyard/config.yaml`, the `briqyardd` unit, and a pool named `byard`.
A second process on the same root would mutate the first host's files and pool.
A network namespace alone does not isolate those resources. A second hosted job
also needs an authenticated private transport between ephemeral runners.
Keep `fleet-two-hosts` and `fleet-restore` as a follow-up requiring proper host
isolation rather than rewriting their assertions or faking the second host.
