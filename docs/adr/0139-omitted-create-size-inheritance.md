# ADR 0139: Omitted create size reaches source inheritance

2026-11-16 · Accepted; clarifies ADRs 0057 and 0127

A named memory clone client can omit `size` because the sealed source owns it.
The fleet and daemon already accept `Size::default()` as the inheritance sentinel,
but the shared request required the outer field during deserialization. Requests
without it failed before those rules ran. Backup restore has the same contract.

Default only `CreateMachineRequest.size` when the outer field is absent. Keep the
members of an explicitly supplied `Size` required: `{}` remains invalid. Ordinary
creates still fail resource validation for an absent or all-zero size. Named memory
clones retain their immutable-size mismatch refusal; restores retain backup lookup
and pinning before placement. Resolve the sealed source profile together with its size. The fleet previously accepted
only `init-ready-v1` snapshots although the daemon also supports `service-ready-v1`.
Require the source host's fresh capability for the exact resolved profile during lookup
and placement. Pristine sandbox snapshots still require the separate seed path.
No new resource defaults or override rules are added.

Regression tests cover both supported profiles with a client-shaped named clone with omitted/default/matching
and mismatched size, distinct registered and intrinsic host identities, backup size
inheritance with omitted/default size, and ordinary-create refusal before placement.
The omitted-size API regression fails with `missing field size` without the fix.
