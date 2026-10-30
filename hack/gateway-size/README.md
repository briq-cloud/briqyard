# Gateway sizing fixture

Run `certificates.sh` here, then `build.sh /path/to/credential-gateway` using the gateway's
resource-limit branch. Certificates and keys are ignored. The build copies sources into a
disposable directory and adds trust for a synthetic upstream CA plus process-memory probes.
The resulting image is a measurement artifact, not a deployable gateway release.

The image includes `/bench-client` and `/bench-server` (the gateway repository's Rust
examples). Copy those into a Python3.12 Alpine fixture image. `server.py` serves only the
synthetic config API when `BENCH_TLS_SERVER=rust`; the Rust binary serves TLS. This removes
the Python interpreter as a bottleneck in high-concurrency stream controls.

`run.py IMAGE_DIGEST OUTPUT_DIRECTORY` runs on a Linux development host with the daemon
on loopback7420, cgroupv2, its normal bridge and a registry from which it can pull the two
images. Run under `hack/vm-lock.sh` in shared development VMs. The source directory must be
visible to the Linux host. The test creates a namespace, a fixture and a gateway machine;
all are deleted on success, failure or handled interruption.

| Variable | Meaning |
| --- | --- |
| `BENCH_FIXTURE_IMAGE` | Python fixture with the two Rust binaries |
| `BENCH_FIXTURE_VCPUS`, `BENCH_FIXTURE_MEMORY_MB` | Fixture resources; keep them identical between controls |
| `BENCH_TLS_SERVER`, `BENCH_STREAM_CLIENT` | `rust` for high-concurrency stream tests; defaults `python` |
| `BENCH_NAMESPACE_GATEWAY` |1 uses the native gateway role and verifies consumer-driven start/stop plus host CPU reservations |
| `BENCH_VCPUS` | Guest CPU topology, default1 |
| `BENCH_NATIVE_CPU_MILLIS` | Set the native API CPU limit at boot; must match a single measured quota |
| `BENCH_MEMORY_MB` | Gateway guest memory, default128 |
| `BENCH_CPU_MILLIS` | Comma-separated quotas applied after boot |
| `BENCH_HELD_BODIES`, `BENCH_MAX_BODY_MB`, `BENCH_MAX_CONNECTIONS` | Gateway resource controls |
| `BENCH_UPLOAD_MB`, `BENCH_BODY_CONCURRENCY` | Offered upload size/concurrency, independent of buffers |
| `BENCH_REPEATS` | Repeat the complete workload sequence, retaining the same gateway process |
| `BENCH_MODES` | Comma-separated `bodies,throughput,streams,overload`, or `idle` |
| `BENCH_STREAM_COUNTS` | Comma-separated simultaneous stream counts |
| `BENCH_DIRECT_CONTROL` |1 adds direct TLS before each proxy stream case |
| `BENCH_CONNECT_LIMIT`, `BENCH_RAMP_PER_SECOND` | Setup admission and ramp rate |

Without `BENCH_NATIVE_CPU_MILLIS`, boot timings use the daemon's full guest CPU reservation. Load quotas are applied to its
cgroup after boot; these timings do not measure boot under a fractional limit. Native CPU
reservation and gateway lifecycle checks live in `hack/e2e.sh`.

Keep offered upload size/concurrency fixed when comparing buffers. Every stream must
complete all events with placeholders scrubbed; all streams must overlap for at least5s.
The direct control must pass before interpreting a proxy concurrency ceiling. Failures
remain failures: no test retries a load, and diagnostics are captured before cleanup.
Host RSS, cgroup memory and guest RSS are distinct. Guest VmHWM and cgroup memory.peak
are lifetime figures; sampled peaks describe their named phase. Inspect host and fixture
scheduler/cgroup counters before attributing a failure to the gateway.

`overload` fills every admission slot with a scrubbed TLS stream, then pauses at an explicit
barrier while the host runs the gateway's local healthcheck. It rejects1,000 excess sockets,
closes all admitted streams and verifies a fresh intercepted request. It uses a Python client
because it measures rejection and recovery, not peak stream throughput.

Native gateway mode respects the runtime's isolation: gateway exec is forbidden. Sampling
uses host RSS, cgroup counters and the read-only machine stats API; guest process RSS is
unavailable in this mode. Ordinary-machine controls still sample guest RSS. A one-second
readiness exec probe checks local health; overload holds its admission barrier until a fresh
successful probe proves health started while all slots were occupied.

`BENCH_REWRITE_BUDGET_MB` sets the estimated matcher budget (default16 for measurements).
`BENCH_SECRET_COUNT`, `BENCH_SECRET_CHARS`, `BENCH_SECRET_CHARSET=ascii|unicode` generate
additional distinct synthetic rules, all named by the fixture consumer. `guard` mode verifies
capacity refusals for an oversized ruleset, switches to the small configuration and requires
recovery on the same TLS session. Use `BENCH_REFRESH_MS=1000` for that recovery test.

`BENCH_STREAM_EVENTS` and `BENCH_STREAM_INTERVAL_MS` customize Rust stream workloads
(default30 events at1Hz). Both fixture and client must use Rust. Keep the same rate in
direct controls. `BENCH_VM_CHAOS=1` kills the recorded native gateway Firecracker process
after the load sequence. An active, verified TLS stream must be interrupted, then one fresh
request must recover using the original CA. The parent checks stable machine ID/IP/size,
CPU quota/weight, host reservations and readiness; the interrupted request is never replayed.
Only a namespace gateway with a native CPU reservation supports this scenario.
