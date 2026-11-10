# 0129: Boots at once: one and a half times the threads

Date: 2026-11-10
Status: accepted; amends ADR 0009

## Context

ADR 0009 set `boots_at_once` to half the hardware threads, at least 2. A semaphore holds each
boot from the Firecracker start until the guest answers. The value came from a stress spike that
booted 24 guests at once on 6 threads with a 60 s timeout, where almost all of them missed it.
The timeout is 120 s since then, and a boot waits for its turn before its timeout starts.

On a 24-thread host, half is 12. A burst of 34 cold creates boots in three waves, and the third
wave waits for two others: the gate alone adds about a second to the slowest creates. ADR 0053
saw the same thing on a 6-thread host: three machines woken together waited for three others.

## Measurement

20 cold `alpine:3.20` machines (256 MB) created at once with `briqyard machine run`, from the
create to running, on a nested host with 8 threads (the image already on the host; several rounds
per value):

| `boots_at_once` | p50 | p90 |
|---|---|---|
| 4 (half) | 2.9 s | 4.9 s |
| 8 (1 ×) | 2.9–3.0 s | 3.8–4.0 s |
| 12 (1.5 ×) | 2.6–2.7 s | 3.2–3.3 s |
| 16 (2 ×) | 2.6–2.9 s | 3.25–3.4 s |
| 20 | 2.4–2.55 s | 3.4 s |

One machine alone: 0.7 s. The daemon's events show where the time goes: the work before the boot
takes 150–300 ms per machine and does not grow with the burst. The boot itself takes 0.76 s
alone and 1.5–3.2 s with 20 at once. Past the threads, boots only share the CPUs. Up to about 1.5 ×,
a boot that waits (on its disk, on the guest's first answer) leaves its thread to another.

## Decision

`boots_at_once` defaults to one and a half times the hardware threads, at least 2. An explicit
value still wins. The turn and the whole timeout once a boot holds it are unchanged.

## Consequences

- A 24-thread host boots 36 at once, so a burst of 34 boots in one wave instead of three.
- More than 1.5 × does not make a burst faster: the CPUs are full.
- A slow host shares its CPUs among more boots at once. Each boot is slower, but the burst ends
  sooner. At these numbers, a boot is several seconds, far from the 120 s timeout.
- Only cold boots were measured. Resumes, memory clones, `runs` launches and the starts after
  the daemon comes back take the same gate; they are lighter than a cold boot, but their
  contention at 1.5 × (on the disk, for a resume) is not measured.
- The figures are from a nested host, where a boot costs more CPU than on bare metal. On bare
  metal a boot is expected to wait a larger share of its time, so 1.5 × should be enough there;
  that, and one wave for 34 boots on a 24-thread host, are to be confirmed on a real host after
  the release.
