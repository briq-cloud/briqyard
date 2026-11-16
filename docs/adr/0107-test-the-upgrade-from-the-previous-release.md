# ADR 0107: Test the upgrade from the previous release on a host with state and history

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

**The runner.** `ubuntu-26.04` (Ubuntu 26.04.1, kernel 7.0 azure) is a hosted label with `/dev/kvm` and OpenZFS 2.4.1, and the whole job runs on it, as on 24.04, so the job uses it: it is what staging and production run. `runner` on dispatch picks another. What remains different from a real host: a file-backed pool on the runner's disk, no NVMe, no reboot history, a machine that is 4 vCPUs.

## What this does not cover

- The receiver of the fleet's registrations: one host, the fleet on the same machine.
- Two hosts, a real network between them and a power loss: `native-ci-two-hosts.sh`.
- A host whose pool, backups and machines are months old.
- Seeds sealed with the head: a head built in CI uses the toolchain `stable`, not the release's pin (ADR 0101), so its init digest differs from the previous release's and the clone-refusal branch is the one tested in a PR. The acceptance branch runs when the digests match, as they do for a release built by `release.yml` after one that did not change the init.

## Results

### Mixed-window sibling refusal control (2026-11-16)

Strict `via:gateway` filters both peer IPv4 and ARP (ADR 0064). The native mixed-window
probe returned an unreachable-host error during neighbor resolution, rather than a timeout.
Either can be a policy denial. Before accepting either, the fixture requires a successful
request to the exact server IP and port from an opted-in sibling, a working gateway request
from the strict guest, and the strict guest's on-link route with its expected source address.
Only wget exit 1 with a timeout or recognized neighbor-resolution denial passes. Successful
requests, refused connections, other errors and failed route controls still fail. The
foreign-namespace probe keeps its timeout-only predicate.

### Two-host mixed-version routing

The upgrade job also boots the existing nested-host fixture before starting any VMs.
During the fleet-first window both daemons run the same published previous release;
the fleet and CLI run the candidate artifacts. Two explicit regions place separate
namespaces on each host, and a second create without a region in each namespace checks its host binding.
Every machine must reach running and answer an exec. Fleet reads and namespace lists
prove the expected registered host; candidate CLI reads prove the exact owned ID,
namespace, name and running state. The typed CLI machine omits the fleet-only `host`
response extension. Cleanup deletes only exact owned machines and
leaves an unresolved create as an unconfirmed outcome, without replay.

The receipt binds both installed and running daemon hashes to the previous release,
and installed fleet/CLI and running fleet hashes to the candidate checksums. It checks
those hashes and both configurations again after requests. The original one-host fleet
configuration is restored before the existing daemon upgrade proceeds. Cleanup first
observes the second host empty while static polling remains active. After removing
its static entry and restarting the fleet, it retires that exact empty fixture host
with one POST, then confirms the original one-host inventory. Removing a static
entry alone does not forget its durable registry record. A setup failure before any
contract request can use this same empty-host cleanup without a contract receipt.
The shell marks contract execution started before invoking it; thereafter a missing
or unconfirmed cleanup receipt prevents retirement. The fixture explicitly
preserves `tls: off` as a string when rewriting YAML: PyYAML reads an unquoted `off`
as a boolean, while the fleet correctly refuses `tls: false`. Missing nested
KVM fails the environment gate; it is not passing qualification. This subset does not
exercise regional authority, controlled physical pressure, supported warm/nested machine
classes, or interrupted activation and rollback.

### Nested admission in the mixed window

Exact-artifact runs enable the nested class before any preservation machine starts.
The upgrade job waits for both binary and nested-kernel builds, downloads both artifacts
from the same release run, and assembles the three class checksums exactly as release
publication does. These are assembled checksums over that run's artifacts, not a claim
that the binary artifact already carried the published combined manifest. Missing class
files, checksum mismatches and missing host capability fail the run.

The previous release's own bootstrap installs its published nested assets. While that
daemon remains unchanged and the candidate fleet is running, one direct nested create
and one consumer-only nested admission must start on the registered local host, report
`runtime_class: nested`, and execute a check for `/dev/kvm`, CPU virtualization flags
and the read-only kernel modules mount. The admitted create consumes its exact reserved
identity. Each mutation is submitted once and exact owned machines are deleted; unknown
creates retain unconfirmed cleanup. The existing binary/process/configuration binding
and subsequent daemon upgrade, preservation and rollback checks remain mandatory.
Rollback and return-to-candidate retain the class and use the corresponding class assets.

PR-built native runs remain default-only: they do not rebuild the nested kernel and
retain the explicit nested qualification gap. The second fixture host remains default-only;
this is not multi-host nested or regional-authority qualification. Passing offline tests
establish wire and failure handling only; native exact-artifact evidence is still required.

### Standalone authority against the published source daemon

Before creating the upgrade's protected machines, the job reuses the standalone
part of `scoped-execution-native.sh`. The candidate authority executable comes
from the selected checksum-verified release assets; the running daemon remains
the published previous release. The matching-source testing driver exercises
registration, ownership, discovery, protection, delegation and direct scoped
execution, including duplicate-operation refusal. Its source must match the
harness checkout; building this helper never replaces a runtime asset.

A separate receipt binds the actual authority process executable to the candidate
checksum and the actual daemon executable to the previous checksum. It records
the testing driver's hash and source commit, then requires the original daemon
configuration and binary after fixture cleanup. This fixture temporarily restarts
the source daemon before the upgrade preservation baseline; those restarts are
not upgrade continuity evidence. The full scoped suite retains renewable callback
coverage. This standalone slice does not qualify callbacks, gateways above the
runtime, or a multi-host authority. Offline checks qualify receipt predicates only;
exact-artifact native runs remain necessary. Failure receipts retain only bounded,
allowlisted phases and refusal categories; raw fixture output is not uploaded.

### Initial upgrade result

First pair, v0.1.23 to this head (PR #152), identical on 24.04 and 26.04: 26 checks pass, 2 fail.

| Runner | Host upgrade | API silent | Endpoint gap | Adopted after | Orphan sweep |
|---|---|---|---|---|---|
| ubuntu-24.04 | 195 s | 190.6 s | 190.6 s | 4.6 s | 6500 leaves, ends 190 s after the hand-over |
| ubuntu-26.04 | 248 s | 244.8 s | 245.9 s | about 5 s | 6500 leaves, ends 245 s after the hand-over |

**Defect found (not fixed here):** after SIGUSR2 the new daemon adopts the running machines within five seconds, then runs the start's orphan sweep over the idle cgroup leaves before it serves anything: `orphans swept at start` (6500) is logged 186 s later, and only then the API, the HTTP ingress and every TCP endpoint listen (`serving again`, `gap_ms 190513`, `adopted_ms 190379`). The machines never stopped (same VMM pids, no reboot, data intact), but nothing could reach them for three to four minutes, against ADR 0027's 2 s drain. Staging's 5000 to 6000 leaves meant the same. The check fails above 30 s (API) and 10 s (endpoint) and stays red until the sweep no longer holds the listeners; the bounds are not to be raised to pass it.

The seed check ran its refusal branch: the previous init digest is `7f39e6645c96`, the head's `cee0c0323a8d` (CI builds the init with the `stable` toolchain, not the release pin), the templates turned off, and the clone was refused with HTTP 400 `operator sandbox seed profile unavailable`.

### Scoped authority qualification and retained protection

The standalone authority fixture runs after forward, rollback and return continuity
checks, with the upgrade workload removed. The runner reactivates checksum-verified
published source assets and verifies the running source daemon before exercising the
candidate authority. Failure to reactivate source fails qualification; it is never
silently skipped. The disposable runner finishes on the published source daemon.

The fixture retains execution-protection receipts and the compatibility floor.
Expired legacy receipts still impose a 60-second startup drain. Running this fixture
before upgrade measurements changed their initial state: one native trial measured
65.52 seconds of API silence and 65.72 seconds of endpoint silence, although adoption
was below 80 ms. Those are real protected-restart outages, not clean-upgrade timings.
The existing 30-second API and 10-second endpoint bounds remain unchanged. Separate
receipts report source-reactivation and total authority-fixture durations; neither is
a claim to measure only the restart. No retained protection is erased to pass a test.
