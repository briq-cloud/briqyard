# ADR 0058: A small isolated gateway profile

Date: 2026-10-30 · Status: accepted for the measured workload and explicit backpressure

A namespace gateway remains one machine in its own microVM. CPU millis (ADR 0057) lets it
reserve less than a whole CPU without sharing a process or guest with another namespace.
The runtime remains application-independent and does not receive application credentials.

The economy candidate is one guest CPU, 128 MiB and 250m, with 128 connections, at most two
whole request-body buffers of 1 MiB each, and a 16 MiB estimated secret-rewrite memory budget.
Larger bodies stream. A conservative weighted reservation precedes secret cloning and pinned
contiguous NFA construction; capacity exhaustion returns 503. Reservations follow outgoing
bodies and emitted bytes until transport writes release them. Header parsing, rewritten
output, configuration fetches, TLS handshakes and idle sockets are bounded separately.
These application controls belong to its image/configuration, not runtime special cases.

[Measurements](../research/2026-10-29-gateway-size.md) on nested ARM Firecracker found:

| Check | Result |
| --- | --- |
| Idle 128 MiB host/application RSS | 42,368 / 3,096 KiB |
| Cached cold boot / resume at 1 CPU | 3.10 s / 0.224 s |
| Eight 8 MiB uploads, two 8 MiB buffers, 1 CPU | passed; 50,796 KiB peak host RSS |
| Same uploads with eight buffers | passed; 102,648 KiB peak host RSS, only 12,356 KiB guest available |
| Eight 8 MiB uploads, two 1 MiB buffers, 250m | 8/8 passed in 23.86 s |
| Historical 100-stream matrix, 250m / 500m | passed; TTFT p95 3.918 s / 0.306 s |
| Historical small-response throughput, 250m / 500m | 284 / 1,026 requests/s |
| 100m with 100 streams | failed deadlines |
| 1,000 streams at 128 MiB / 1 CPU | failed; process disappeared after guest memory became low |
| 1,000 streams at 256 MiB / 1 CPU or 2 CPUs | failed completion/deadlines; no OOM or process exit |
| 64 MiB idle floor, disposable runtime build | passed; cold 3.03 s, resume 0.237 s |
| Native oversized configuration | three capacity refusals, same-session recovery in 1.50 s |
| Native VM kill during a scrubbed stream | recovered in 26.45 s with identity, CA and reservations intact |

The older CPU matrix precedes explicit matcher memory admission. Final native tests use the
pinned NFA and reservation budget; compare source, fixture and workload before interpreting
latency differences. The 64 MiB check establishes an idle boot floor; the public minimum
remains 128 MiB. Faster resume alone does not justify changing stop/start lifecycle or
configuration freshness semantics. Consumer-driven start/stop verifies the gateway's exact
250m contribution to host reservations.

Connection admission is a ceiling, not guaranteed useful concurrency for every configuration.
One selected 64-byte value with a 28-byte placeholder reserves about 75.7 KiB per request;
the connection cap dominates the 16 MiB budget. Fifty applicable 64-byte values reserve
about 1.401 MiB per request, allowing only eleven simultaneous reservations. Every applicable
value is charged even when a request uses only one. Slow readers and stalled upstreams retain
capacity until cancellation or closure. Admission has no fairness guarantee.

A 4.60 MiB UTF-8 configuration fits the 8 MiB transport cap but exceeds matcher admission.
The native gateway safely refused it, then recovered on the same TLS connection when a small
configuration returned. Configuration transport size alone cannot bound matcher memory.
The budget is conservative accounting, not an RSS ceiling: TLS, global config parsing,
transport buffers, allocator overhead and the guest runtime need separate headroom.

Container checks on final production source passed repeated SIGKILL/restarts with persistent
CA, upstream pause/stop and recovery, and active-stream interruption without secret exposure.
The first native overload cycle filled all 128 slots, served fresh local health and rejected
1,000 excess sockets. A later repeated cycle failed before full admission while the gateway
remained healthy. All five subsequent instrumented cycles passed with unchanged load and deadlines; the failed
run remains recorded, and its precise cause remains unproven.
A health probe can briefly occupy an ordinary slot while capacity is available, so an exact
client fill can race management traffic. That possibility does not yet establish its cause.

Use the smaller reservation only for the measured workload and explicit backpressure.
500m is a latency alternative supported by the older paired matrix; 100m failed its workload.
The 100-stream tests use one selected small credential and small SSE events. They do not
establish arbitrary token bandwidth, fifty-credential concurrency or 1,000-stream support.
Repeat throughput and latency measurements on the production architecture. Five complete native cycles passed, followed by another VM-kill recovery in 29.15 seconds.
The operating recommendation is scoped to that evidence and the admission boundaries above.

Final native repetition: 300,000 validated proxy events, 5,000 excess offers rejected, no
VM restart or memory-limit event during the 25 load phases; peak host RSS 63,608 KiB and
sampled cgroup memory 81.21 MiB. Small-response throughput was
375.9–496.0 requests/s; per-run stream TTFT p95 ranged from
75.0–1036.5 ms, including setup. Native VM-kill recoveries took 26.45 and
29.15 seconds, preserving identity, CA and reservations.
