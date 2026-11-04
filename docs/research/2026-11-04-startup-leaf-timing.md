# Startup with 6500 idle leaves

Source d2aaa2ca9c0d24ca957dc2068d3f92f4cda4bc41, Ubuntu 26.04.
[Upgrade proof](https://github.com/briq-cloud/briqyard/actions/runs/41881432910), v0.1.23
as the old daemon. The artifact is `native-upgrade-log`; no separate full journal artifact
was uploaded. These timestamps are the daemon JSON timestamps in the journal excerpt,
not the later Actions timestamps when the journal was printed.

| Event | UTC |
|---|---|
| Old daemon begins handover (4 VMMs) | 18:00:13.222861 |
| Old daemon handed over | 18:00:13.363117 |
| New daemon complete barrier (6509 identities, 4561 ms) | 18:00:18.168263 |
| First adoption | 18:00:19.159298 |
| Fourth adoption | 18:00:19.311118 |
| Orphan preparation ends (6500, 198770 ms) | 18:03:38.081301 |
| Listening | 18:03:38.143590 |

Old handover: 140.256 ms. Orphan preparation: 198.770 s, 30.58 ms per orphan.
`serving again`: gap 204921 ms, pool 35 ms, adopted/serving 204754 ms.
Probe gaps: API 205.14 s; endpoint 205.21 s. 26 passed, 2 failed (downtime bounds).

Removal was already deferred in this candidate. The remaining orphan loop settled each
empty epoch then read final counters (`Leaf::final_usage`), including checked membership,
`cpu.stat`, `memory.current`, `memory.events.local`, and a final membership check.
The 4.561 s barrier performs full membership/shape checks and inode rechecks; the slow
phase is separate, after adoption. Per-file timing is needed to attribute the counter cost
to an exact syscall. The next candidate moves orphan counters before removal in the
background collector and records cumulative per-file read durations and counts, without
per-leaf journal output. No reduction of the barrier's checks follows from this measurement.
