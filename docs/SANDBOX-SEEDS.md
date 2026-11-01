# Pristine sandbox seeds

`templates.sandbox_recipes` defaults to an empty list. Keep it empty until native
Firecracker/kernel qualification in ADR 0076 passes. A recipe pins `image` (explicit
registry and manifest digest), `image_config_digest`, `init_sha256`, exact `size` and
`volume_gb`. API authentication, the jailer and matching boot/CPU identities are required;
private registry credentials are rejected for its registry. The operator builder is
`template_build: sandbox-ready-v1` without caller configuration. Its internal raw data
device is never mounted and is charged to the operator namespace. It is not a team source.

After qualification, seal the builder with the existing full-memory template operation.
Snapshot status includes `clone_generation`; the CLI displays it. Normal create may
select `sandbox_seed: {machine_id, snapshot, generation, request_id}` with the exact
approved image/size, `start:true` and a fresh volume at `/work` whose capacity matches
the recipe. Other capacities need separately qualified topology. The admin bearer owns
destination assignment; metadata does not establish tenant authorization.

A request ID is durable within its destination namespace. Preserve it on retries and
preserve the entire create body. A different body conflicts, and destroy does not reset
consumption. A lost response or interrupted bind never authorizes a second slot or
cold fallback. The fleet stores routing intent before dispatch and never sends that
request ID again, including when lookup cannot confirm acceptance. Keep the same
machine/reservation for reconciliation. Empty namespace/network cleanup and host
removal remain available; durable request routing/index tombstones hold no live
resources. A new request ID can place elsewhere after cleanup, while old IDs remain
fenced. Startup/readiness
probes retain normal semantics. Existing configured warm pools are not rebound.

The daemon-only authenticated `POST /v1/sandbox-requests/lookup` reads a client
`{namespace, request_id, create_sha256}` without allocating resources or reading a
source. Matching records return public machine status; changed or consumed/unavailable
records conflict. Only `sandbox_request_unknown` denotes authoritative absence, and an
existing fleet dispatch intent still prohibits another dispatch after that miss.
