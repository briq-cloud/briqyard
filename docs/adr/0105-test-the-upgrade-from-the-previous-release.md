# ADR 0105: Test the upgrade from the previous release on a host with state and history

2026-11-04 · Status: accepted; extends ADR 0027 (upgrades with machines running), ADR 0099 (a leaf goes with its VMM) and ADR 0101 (the init's digest)

## Context

v0.1.19 passed native CI and then failed closed on real hosts. CI's hosts are fresh Ubuntu 24.04 with this build installed and nothing before it. Staging's were upgraded in place, on Ubuntu 26.04, with thousands of cgroup leaves left by earlier versions and machines that kept running through the upgrade. `hack/native-ci-scale.sh` covers the leaves. Nothing covered the upgrade itself: the previous release's files on disk, its running machines, its store, its seeds, replaced by the new release's under traffic.

## Decision

**A native CI job does what production does** (`hack/native-ci-upgrade.sh`, workflow `native-upgrade`):

1. **Install the previous release.** Its tag is cloned, and its own `hack/bootstrap-host.sh` installs its published artifacts over HTTPS (`BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/<tag>`), each checked against that release's `SHA256SUMS-x86_64`. The fleet comes from the same release. The repository is public: no secret, `contents: read`.
2. **Give the host state.** A Postgres machine with a volume, an endpoint, 100 rows and a backup (50 more rows after it); a web machine served through an endpoint; a machine with a volume; a stopped machine; a suspended machine with a mark in memory; a sealed seed (its builder stays) with a clone that runs. **History:** 20 machines made and destroyed, 5 whose VMM was killed (`SIGKILL`, 2 of them destroyed), and 6500 idle cgroup leaves (ADR 0099).
3. **Upgrade in place.** The fleet first (binary replaced, restarted), then `briqyard host upgrade local --release file://…` over SSH, the procedure of `docs/OPERATIONS.md#upgrade`. An endpoint and the daemon's API are polled every 50 ms from before the call to after it.
4. **Assert.** The upgrade reports success; the host is `ready` on the new version with a new start that stopped nothing and adopted every running machine; `memory_protection` is clear and no condition says `recovery_unresolved`; each running machine has the same VMM (pid and start time, read from its cgroup); none booted again; data is intact (rows, volume file, endpoint answers); the stopped machine starts; the suspended one resumes with its memory; a seed's clone is accepted when the init's digest is the previous release's and refused with a client error when it is not (ADR 0101); the pre-upgrade backup restores with its rows; a new create runs; the leaves are retired; the next backup works. It reports the longest silence of the API and the longest gap of the endpoint, and fails above 30 s and 10 s (`NATIVE_UPGRADE_API_DOWN_MAX`, `NATIVE_UPGRADE_ENDPOINT_GAP_MAX`).

**When it runs.** It is slow, so not on every PR: on version PRs (`chore/v*` or a changed workspace version), on a PR that changes the test, on dispatch (`previous`, `ref` and `runner` inputs, so any pair can be tried), and in `release.yml` against the candidate's own artifacts (`dist-x86_64`), before `publish` creates the draft. `previous` defaults to the newest published release that is not the head (its tag's commit is not the head's).

**The runner.** `ubuntu-26.04` exists as a hosted label. See Results.

## What this does not cover

- The receiver of the fleet's registrations: one host, the fleet on the same machine.
- Two hosts, a real network between them and a power loss: `native-ci-two-hosts.sh`.
- A host whose pool, backups and machines are months old.
- Seeds sealed with the head: a head built in CI uses the toolchain `stable`, not the release's pin (ADR 0101), so its init digest differs from the previous release's and the clone-refusal branch is the one tested in a PR. The acceptance branch runs when the digests match, as they do for a release built by `release.yml` after one that did not change the init.

## Results

See the pull request that introduced this ADR.
