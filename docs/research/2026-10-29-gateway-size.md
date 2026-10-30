# Gateway resource measurements

Status: economy profile chosen after bounded native stress and recovery checks; see ADR 0058. Firecracker 1.17 on nested aarch 64 KVM;
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
kill; later runs capture failure logs before cleanup. The 256 MiB comparisons below also failed their strict completion criteria.

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


## Memory admission and native lifecycle, 2026-10-30

The earlier CPU matrix used a small credential set before explicit matcher memory admission.
Default Aho-Corasick DFA construction consumed about1.58 MiB per response for50 rules of64
bytes,25.1 MiB at1 KiB, and100.4 MiB at4 KiB. Connection and body caps alone did not bound
this allocation. The gateway now pins contiguous NFA matchers and reserves a conservative
weighted estimate before cloning selected secrets or constructing any of its three matchers.
Reservations follow body frames through pending downstream writes. Capacity exhaustion
returns503; matcher construction errors return502. Neither condition disables scrubbing.
The16 MiB estimated rewrite budget is part of the candidate profile, not a kernel RSS limit.

Native role checks use host memory/cgroup counters and read-only machine stats because
exec into a gateway is intentionally forbidden. A1-second readiness exec probe supplies
health evidence. Starting a consumer reserves exactly1,250m for the consumer plus gateway;
stopping it releases that reservation. This is measured through the actual namespace
binding and API size rather than by changing a cgroup after boot.

An adversarial4.60 MiB UTF-8 configuration (50 selected rules) fit the8 MiB API response cap
but exceeded the16 MiB matcher estimate budget. The native128 MiB/250m gateway returned
three503 responses without a process restart or memory-limit event. Replacing it with a
small configuration recovered in1.50s on the same verified TLS connection (1-second refresh
interval for this test). No client reconnection or load retry hid the refusal.

A disposable runtime build allowed64 MiB solely to measure the idle boot floor. The gateway
cold-started in3.03s and resumed in0.237s at1 CPU, with roughly42 MiB cold host RSS. The
public daemon binary was restored and its checksum verified. The public API minimum remains
128 MiB. Passing idle boot is not evidence of safe64 MiB operation under TLS/body load.

A256 MiB/1 CPU run established991 of1,000 streams and completed none before its strict
barrier/deadlines. With256 MiB/2 CPUs, all1,000 established with30.36s overlap, but only830
completed and170 timed out. Neither run hit an OOM or lost its gateway process. These remain
failed capacity tests; increasing memory alone did not demonstrate1,000-stream support.

On the final production source, container fault checks passed three SIGKILL/restarts with
CA continuity, an upstream pause with a verified timeout, an upstream stop with502, and an
active scrubbed SSE stream interrupted by SIGKILL followed by successful recovery. Recovery
after fault removal was0.15–0.40s in containers; these are not native VM recovery timings.

[Native boot, lifecycle and memory-admission summaries](data/gateway-size-native-2026-10-30.json).


Native VM fault injection killed only the recorded Firecracker process after the client
received a scrubbed SSE event. The runtime recovered in 26.45 seconds. Machine ID, IP,
persisted CA, 128 MiB size, 250m quota/weight and full host reservation remained unchanged.
The interrupted request was not replayed; one fresh request succeeded after a new readiness
probe. The client observed a timeout on the interrupted connection, which is an expected
outcome when the entire network stack disappears.

The candidate's credential selection affects useful concurrency. One 64-byte selected value
with a 28-byte placeholder reserves about 75.7 KiB per request; the 128-connection cap
therefore dominates a 16 MiB budget. Fifty applicable 64-byte values reserve about 1.401 MiB
per request, admitting only eleven concurrent reservations. All applicable values are charged,
even if the request uses only one. This estimate depends on locations and metadata. Slow
readers and stalled upstreams retain reservations through cancellation/closure; admission
has no fairness guarantee. TLS, transport, global configuration parsing and guest runtime
memory remain outside this estimate. It is not a formal resident-memory ceiling.

The first repeated native run completed two 100-stream cycles at 600 small events per stream,
50 ms configured interval: 120,000 validated proxy events with no scrub errors, at least
30 seconds of full overlap per cycle, and roughly 1,677–1,701 validated events/s over the
whole ramp-and-stream elapsed time. The first overload cycle admitted all 128 streams,
verified health while full and rejected 1,000 excess sockets. The second overload cycle
failed before the full-admission barrier with a client reset; the gateway remained healthy
with the same PID and no memory-limit event. That run is retained as failed evidence.

A one-second health probe can briefly take an ordinary admission slot while capacity is
available; reserved health slots are used once ordinary admission is full. A probe racing
an exact 128-client fill is a possible cause of a pre-admission rejection, not yet established
by that run. The instrumented harness records the failing worker stage and partial counts
before cleanup and preserves the same offered load and deadlines.


## Final instrumented repetition

The same production source, image, load, connection ramp and deadlines passed all five
instrumented cycles at 128 MiB / 250m: eight 8 MiB uploads per cycle with two 1 MiB buffers,
16 small-response workers, direct and proxied 100-stream controls at 600 events each with
50 ms configured spacing, and 128-stream overload with 1,000 excess connection offers.
All 25 phases passed. Proxy streams validated 300,000 small events without a scrub error;
the five overload phases rejected 5,000 excess offers and verified fresh health while full.
The gateway retained one Firecracker PID through all load phases and recorded no increase
in cgroup OOM, OOM-kill or max-limit events. The earlier failed overload attempt remains
recorded; instrumentation improved diagnostics without changing admission or retrying loads.
Its precise cause is still unproven. Management traffic counts against ordinary admission
while slots are available, and completed client reads do not prove server-side socket teardown.

Peak sampled host process RSS was 63,608 KiB; sampled cgroup peak was 81.21 MiB.
Guest process RSS is unavailable for the isolated native role. Per-run small-response
throughput was 375.9–496.0 requests/s. Stream TTFT p95, including connection
setup during the ramp, ranged from 75.0 to 1036.5 ms. Every 100-stream cycle overlapped
for at least 30.92 seconds. The configured event rate is nominal;
measured event rates include scheduling and ramp overhead and are retained in the raw summaries.

After the fifth cycle, deliberately killing its Firecracker process interrupted an active
verified stream. A new VM PID recovered in 29.15 seconds with the same machine ID, IP,
CA, size, CPU quota/weight and full host reservation. One fresh request succeeded with the
original trust. Together with the separate 26.45-second run, this establishes two successful
native VM-kill recoveries; it does not promise zero downtime or replay interrupted requests.

Choose 128 MiB / 250m as the bounded economy profile with 128 connections, two 1 MiB
body buffers and 16 MiB estimated rewrite admission. The measured normal-load envelope is
100 simultaneous small-event streams with one selected small credential. Treat 128 as an
admission ceiling that includes ordinary management traffic. More applicable credentials
reduce useful concurrency; fifty 64-byte values admit only eleven reservations at this budget.
Use a larger CPU reservation when the latency objective requires it, and remeasure on the
production architecture. The failed 1,000-stream tests remain outside supported capacity.
