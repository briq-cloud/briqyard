# Balloon reporting qualification

The rollout setting is off by default:

```yaml
balloon:
  enabled: false
```

Enable only on an owned candidate host after source checks. Changing the switch
selects subsequent cold boots; running and resumed devices retain their profile.
Leave existing guests running when selecting the setting. Existing templates must
be qualified against the new profile before publishing a new template generation.

The source candidate is not evidence of native reclaim or performance. Normal CI,
CodeQL, release and native gates below are required for broad default enablement.

## Source validation

Use a clean archive of the candidate commit, set `BRIQYARD_COMMIT` to that full commit
when building outside Git, and retain the archive SHA-256 and command exit statuses.
The existing Linux build/test environment is sufficient:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --workspace --locked
```

The new checks live in the existing Firecracker socket and machine mock suites:
`fc::tests::balloon` and `machine::tests::balloon`. They cover exact configuration,
read timeouts, absent guest counters, FIFO increments, old stores, durable cold
identity, fallback, incompatible schemas, cached metrics and telemetry failures.
They do not qualify Linux/KVM execution or reclaim.

## Native acceptance manifest

Run only disposable owned guests using the existing `hack/e2e.sh` machine/storage
and restart/adoption coverage, plus the assertions below. Preserve the host's other
machines. Do not change capacity, quotas, cgroups or admission. Never exercise host
pressure, overcommit or process-control race experiments.

Record the runtime commit and binary digest, image digests, guest kernel digest,
VMM binary digest and pinned source tree, host kernel, architecture, transport,
configured size/CPU and effective `boot_identity` for every run. Use the patched
Firecracker tree selected by `hack/firecracker/pin.json`, including checked snapshot
preparation. A matching version string alone does not establish the binary's tree.
Verify the guest kernel is the checked bootstrap artifact with VIRTIO_BALLOON and
PAGE_REPORTING enabled; arbitrary custom kernels are not covered.

1. With reporting disabled, create an owned legacy guest, suspend and named memory
   snapshot. After enabling the candidate setting, restore both and assert a
   `resumed` event plus a persistent in-memory process/data marker. GET `/balloon`
   must report no device. A successful cold boot is not a resume pass.
2. Create a new cold guest. GET `/balloon` on its existing Firecracker socket must
   equal the five-field profile from ADR 0071. Confirm the guest balloon driver,
   advisory counters, and reporting FIFO increments after bounded allocate/touch/free.
   `GET /v1/machines/<id>/stats` exposes the effective profile and cached balloon data;
   `memory_status` qualifies cgroup availability. Wait for bounded stage completion
   and the existing tick, not an unbounded poll loop.
3. Suspend/resume and named-memory restore the new guest. Assert the process/data
   marker, `resumed` event, identical identity and continued reporting. Reuse existing
   disk-fork/reset cases and verify their next boot is cold with today's profile.
   Feed a mismatched identity through fixture/store tests and require a refusal
   reason; never count a fallback as a successful memory restore.
4. Reuse the existing handover/restart coverage with owned old/new guests. Their
   VMM PIDs and markers survive and their profiles remain distinct. Crash boundaries
   belong in store/mock tests, without native process-control race experiments.
5. Optional manual balloon control is confined to an owned guest and a modest target
   well below its free memory, then zero. Assert actual converges. OOM deflation is
   configuration coverage only, with no OOM or host-pressure drill.

Use the existing API socket paths and profiling observers; do not add another VMM
controller. `hack/profiling/suspend.py` extracts the existing lifecycle timing stages
without sending lifecycle requests.

## Paired measurements

Predeclare regression bounds before starting. Run at least five disabled/enabled
pairs with identical pinned image, size and CPU allocation for idle base, Python,
Node and bounded allocation/free workloads. Record ready, settled, peak, post-free
and post-resume stages separately. Keep cold, suspended/restored and any future
fork/slot results separate.

Retain raw samples of cgroup current/anon/file, host MemAvailable and ARC, owned VMM
smaps_rollup PSS/RSS, reporting/error FIFO counters, cgroup OOM events, CPU time,
ready latency and workload duration. Report paired medians and ranges with concurrent
host noise. Require host/cgroup reduction after free, correct refault/data checks
and zero new reporting failures to establish reclaim. Repeated reported bytes and
balloon actual alone cannot establish it. Snapshot sharing and page charging also
prevent sums of per-VM file/RSS from proving physical deduplication.

Unexpected errors, cgroup OOM events or material workload regressions block broad
enablement. Keep full reservations and current limits while investigating. These
measurements do not establish sub-300ms named fork, sub-100ms pool claim, host OOM
protection or production migration readiness.
