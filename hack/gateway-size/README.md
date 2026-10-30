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
