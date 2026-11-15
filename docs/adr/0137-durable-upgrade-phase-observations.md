# 0137: Durable upgrade phase observations

An upgrade's total duration cannot distinguish downloads from time spent withdrawn.
Keep generic phase observations beside the fleet registry, one append-only JSONL file per
attempt in `upgrade-timings/<hex-host-id>/`. File creation is exclusive. Each append is
synced. The fleet records preparation, withdrawal, activation, installed-version lookup,
adoption/readiness and completion using a monotonic clock. UTC timestamps correlate events.
The initial record identifies the host, source version and requested release. Release URL final components such as `v0.2.12` are normalized to a version. Other URLs
are represented as `custom`, never persisted as request URLs.

`GET /v1/hosts/{id}/upgrade` returns the latest attempt, including failures. Older files
remain for operator collection. A synced, atomically replaced latest pointer selects by
attempt creation order, independently of wall-clock changes. An unmatched running event means an ambiguous interruption;
it has no invented duration or successful outcome. A malformed final append is ignored,
leaving the preceding start unresolved. This is observation, never authority to retry.

Creating the initial durable record must succeed before dispatch. Afterward persistence
failure emits a fixed tracing warning and never changes lifecycle results or admission gates.
A missing end is therefore unknown, including after a storage failure. These records do not
replace the registry or its recovery rules. Retain files until archived by the operator.

Activation includes provisioning and daemon handover performed by the installer. Adoption
and readiness share the observed heartbeat boundary. Neither is a claim about individual
internal substeps. Completion can leave a host draining for external verification: no phase
or total is advertised as admission unavailability. A controller must observe readmission
separately and must not subtract UTC timestamps as a monotonic duration.
