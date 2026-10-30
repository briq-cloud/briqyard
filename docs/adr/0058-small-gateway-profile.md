# ADR 0058: A small isolated gateway profile

Date: 2026-10-30 · Status: proposed, pending native repeated-load and boot-floor checks

A namespace gateway remains one machine in its own microVM. CPU millis (ADR 0057) lets it
reserve less than a whole CPU without sharing a process or guest with another namespace.
The runtime remains application-independent and does not receive application credentials.

The reference economy profile is one guest CPU, 128 MiB and 250m, with application admission
limited to 128 connections and at most two 1 MiB whole request-body buffers. Larger bodies
stream instead of consuming an unbounded allocation. The application must also bound
header parsing, rewritten output, configuration fetches, handshake waits and idle sockets.
These application controls belong to its image/configuration, not to runtime special cases.

[Measurements](../research/2026-10-29-gateway-size.md) on nested ARM Firecracker found:

| Check | Result |
| --- | --- |
| Idle 128 MiB machine host RSS |42,368 KiB |
| Idle application RSS |3,096 KiB |
| Cached-image cold boot / resume at 1 CPU |3.10 s /0.224 s |
| Eight 8 MiB uploads, two 8 MiB buffers, 1 CPU |passed;50,796 KiB peak host RSS |
| Same uploads with eight buffers |passed;102,648 KiB peak host RSS, 12,356 KiB guest available minimum |
| Eight 8 MiB uploads, two 1 MiB buffers, 250m |8/8 passed in 23.86 s |
|100 concurrent streams, 250m |passed, 30.20 s overlap; TTFT p95 3.918 s |
|100 concurrent streams, 500m |passed, 30.26 s overlap; TTFT p95 0.306 s |
| Small-response throughput, 250m /500m |284 /1,026 requests/s |
|100m with 100 streams |failed deadlines |
|1,000 streams at 128 MiB /1 CPU |failed; process disappeared after guest memory became low |
|1,000 streams at 256 MiB /1 CPU |failed at 991 established; no OOM or process exit |

The admission cap is part of the profile. A container check filled 128 slots with scrubbed
TLS streams, rejected 1,000 excess sockets, served local health while full and served a fresh
request after the streams closed. SIGKILL/restart and upstream outage checks also recovered.
This does not make 1,000 concurrent admitted streams a supported workload for the small VM.

Choose 500m when connection bursts or streamed first-byte latency matter more than the
smaller reservation.100m is below the measured operating range. Retain stop/start lifecycle;
the faster resume measurement alone does not justify changing lifecycle or configuration
freshness semantics. Native gateway lifecycle and CPU accounting are checked by the e 2e
suite at 128 MiB/250m.

Limits of the evidence: short, separate workloads, a small synthetic credential set, nested
virtualization and ARM hardware. Parsed configuration and per-request matcher memory depend
on the credential set. This profile is not a guarantee for arbitrary configurations or every
traffic mix. Repeated native workloads, overload/recovery under quota and a 64 MiB idle boot
check must complete before this ADR is accepted. Production-architecture throughput and
latency should be measured separately.
