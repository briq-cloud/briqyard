# ADR 0136: External verification before upgrade readmission

2026-11-15 · Accepted; extends ADRs 0027 and 0135

The existing single upgrade call owns preparation, withdrawal, activation and heartbeat
verification under one fleet lock. Add `stay_draining: true` to keep the host draining
on success until an external controller verifies it and explicitly calls undrain.
Omitted or false retains the original completion state, including a manual drain.
`require_ready: true` additionally refuses a non-ready host at ownership, before any
preparation. Controllers without authority to recover manual drains use it to close the
race between their admission read and upgrade dispatch. Omitted/false permits both states
as before. Both fields require the same advertised contract. Preparation retains the original eligibility; operator state or identity changes during
preparation still refuse activation. Failure after withdrawal and interrupted upgrades
remain draining. A failed preparation leaves admission unchanged.

The fleet advertises `prepared_upgrade_v1: true` only with the embedded bootstrap.
Custom scripts retain their legacy contract and refuse this option. The CLI checks the
exact capability before sending it. Direct API callers must also check: older fleets
ignore unknown request fields and could readmit before external checks. A version range
is insufficient. The capability describes the full behavior, not release qualification
or available capacity. No release is enabled or qualified by this source change.

A separate prepare/activate API is unnecessary here: it would add a durable remote
operation identity and another dispatch boundary without changing who owns activation.
Keep one writer and one call. Lost transport is never permission to retry activation;
observe and verify the resulting host before explicit readmission or operator recovery.
This API does not authorize recovering an operator's manual drain.

Portable tests cover completion from ready/draining, unchanged omitted/false behavior,
custom-script refusal, exact CLI capability gating and request serialization. Existing
preparation tests cover unchanged eligibility and operator-change refusal. Native upgrade
and lifecycle qualification remain required before using a released candidate.

Candidate validation on macOS: API 182, CLI 63 and fleet 408 tests passed (2 fleet
tests ignored). Workspace clippy with warnings denied and formatting passed. Linux/native
VM and handover suites were not run; they remain release gates.
