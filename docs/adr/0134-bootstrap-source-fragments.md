# ADR 0134: Assemble the standalone bootstrap from source fragments

2026-11-15 · Accepted

## Decision

Maintain bootstrap source in `hack/bootstrap/`: host setup, runtime installation
helpers, then installation and activation. Join them with a blank line in that order
with `python3 hack/assemble-bootstrap.py`. Commit the result at the existing
`hack/bootstrap-host.sh` path. This split preserves the previous script byte for byte.

The bootstrap test entry point imports suites grouped by runtime, host and tunnel,
with shared fixtures in `hack/bootstrap_tests/support.py`.

## Why

The bootstrap had 1,334 lines and its test harness had 1,109. Source fragments keep
the installation helpers and test classes understandable without changing behavior.
The fleet embeds the standalone file and sends it over SSH or the join endpoint.
Operators download that same file; native suites and development tools read it too.
A loader sourcing adjacent files would break those delivery paths.

## Verification

The existing bootstrap test command checks that the committed artifact equals the
assembly, then exercises installation using that artifact. Delivery tests execute
it from a directory without fragments, as a file and on stdin. Rust tests compare
the embedded bytes with the fragments and execute the embedded script on stdin.
Custom scripts retain the existing verbatim file behavior.
