# ADR 0138: Observe the central fleet's loaded configuration

2026-11-15 · Accepted

The daemon already reports `RuntimeObservation`. The central fleet now reports the
same optional `observation` in authenticated `GET /v1/status` and CLI status output.
It identifies `fleet`, the runtime version, a random process incarnation and the
Linux boot identifier when available. Repeated reads retain the incarnation;
a replacement process creates another. No registry state is changed.

Capture SHA-256 from the exact UTF-8 file input parsed during configuration load.
Replacing the path afterward cannot change the observation. Explicit defaults report
`defaults`; configurations constructed directly in memory report `unobserved`.
Neither YAML nor API requests can supply the captured identity. Existing legacy YAML
normalization, validation and environment overrides remain unchanged. The hash names
the loaded file input, not external environment values or subsequent mutations of
configuration objects. It exposes no configuration values, tokens or paths.

Reuse the shared daemon types instead of a fleet-specific status contract. An
observation proves neither capacity nor compatibility, and grants no mutation or
maintenance authority. Existing authentication remains required. Tests replace the
configuration path after loading, compare successive process identities, distinguish
default and unobserved sources, and refuse a caller-supplied identity.
