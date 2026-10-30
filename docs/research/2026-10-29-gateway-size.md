# Gateway resource measurements

Status: preliminary. No resource size chosen. Firecracker 1.17 on nested aarch 64 KVM;
128 MiB guest, one vCPU, host quota 100000/100000 µs. Timings describe this development
host; repeat throughput and latency checks on the target architecture before treating them
as production capacity. The fixture uses synthetic credentials and a local HTTPS upstream.
The gateway image adds a local upstream CA and a process-memory probe for measurement.

| Check | Observed |
| --- | --- |
| Cold start to listening, cached image | 3.10 s |
| Resume to listening | 0.224 s |
| Idle host process RSS after cold start | 42,368 KiB |
| Idle gateway process RSS in guest | 3,096 KiB |
| Initial 1,000-client connection burst | failed: 883 client timeouts; no OOM events |
| Default buffers, eight concurrent 8 MiB uploads | failed: eight request timeouts; no OOM events |
| Two buffers, **two** concurrent 8 MiB uploads | passed; this also reduces offered load |
| Paced direct TLS, 100 streams | passed; 100 streams overlapped for 30.16 s |
| Paced proxy TLS, 100 streams | passed; 100 streams overlapped for 30.17 s |

The eight-upload failure reached 72,464 KiB gateway process high-water RSS and 92,632 KiB
sampled host process RSS. Guest memory available fell to 16,340 KiB. The fixture also
recorded a 10-second event-loop delay: the failure cannot be attributed to memory alone.
A comparison must keep the offered body concurrency fixed. The next fixture splits large
writes and validates bodies incrementally to avoid large synchronous Python operations.

Cgroup memory includes more than process RSS; do not substitute it for the host RSS figure.
`memory.peak` and guest `VmHWM` are lifetime peaks. Sampled cgroup peaks are per phase.
After resume, guest pages are faulted lazily; an immediate RSS sample is not the steady
idle figure and cannot be used to claim reduced memory requirements.

Machine-readable phase results: [data/gateway-size-2026-10-29.json](data/gateway-size-2026-10-29.json).
Still required: matched upload concurrency, 1,000 overlapping streams, 100/250/500m CPU,
64 MiB boot floor, sustained-load recovery, tenant-gateway lifecycle, and capacity accounting.

## Matched follow-up, 2026-10-30

Both upload runs offered eight concurrent 8 MiB bodies with a 5-second final-byte barrier,
at 128 MiB and 1 CPU. The fixture splits writes and validates incrementally.

| Buffered requests | Completed | Elapsed | Host RSS peak | Gateway lifetime HWM | Guest available minimum |
| --- | --- | --- | --- | --- | --- |
| 8 | 8/8 | 15.97 s | 102,648 KiB | 81,576 KiB | 12,356 KiB |
| 2 | 8/8 | 11.77 s | 50,796 KiB |32,716 KiB |63,092 KiB |

The first 1,000-stream proxy plateau was a descriptor limit: the guest inherited soft 1024,
hard 4096, allowing roughly 506 pairs of downstream/upstream sockets. Startup now raises
the soft limit when the hard limit permits it, or refuses to start with a required-limit error.
A fully Rust direct control passed 1,000 streams with 32.33 seconds of complete overlap.
With the descriptor fix, the 128 MiB proxy's process disappeared during the same workload;
the last samples reached 104,652 KiB host RSS, 75,160 KiB application HWM and 6,568 KiB
available guest memory. This is a failed profile. Those samples alone do not prove an OOM
kill; later runs capture failure logs before cleanup. A 256 MiB comparison is pending.

With two 1 MiB buffers, 128 MiB, a 128-connection admission cap and a Rust upstream:

| CPU | Small-response throughput, 16 clients | 100 simultaneous streams | Stream TTFT p95 during ramp |
| --- | --- | --- | --- |
| 100m | 2.26 requests/s |failed deadlines | 50.45 s, failed run |
| 250m | 284.16 requests/s |passed, 30.20 s overlap |3.92 s |
| 500m | 1,026.05 requests/s | passed,30.26 s overlap | 0.306 s |

The fixture paces connections at 25/s and bounds concurrent setup at 16. TTFT includes
connection setup; it is not the latency of an already-open connection. Throughput counts
responses over the entire test elapsed time, including initial setup. These nested-host
numbers define a measured workload, not an architecture-independent capacity guarantee.

Latest-image container fault checks passed: three SIGKILL/restarts with persistent CA;
upstream pause (verified timeout after successful CONNECT/TLS), upstream stop (502), and
recovery. Recovery after fault removal was 0.22–0.39 s. Killing the gateway after the client
observed a scrubbed SSE event interrupted that active stream without exposing the secret;
after restart, a fresh request succeeded. These are container timings, not VM boot timings.

Matched raw summaries: [data/gateway-size-matched-2026-10-30.json](data/gateway-size-matched-2026-10-30.json).

The 250m candidate with the 1MiB threshold also passed eight concurrent 8MiB uploads
in 23.86s. Its buffer threshold is smaller than the offered bodies: they stream after the
threshold. The test did not reduce offered body concurrency or size.

An overload check filled all 128 admission slots with intercepted TLS streams, observed a
scrubbed SSE event on each, then opened 1,000 excess sockets. All excess sockets were
closed, a local healthcheck succeeded while slots were full, and a request succeeded once
the streams closed. This used the latest container image; CPU and memory sizing remain
the separate Firecracker measurements.
