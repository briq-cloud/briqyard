# ADR 0099: CI token permissions

2026-11-04 · Status: accepted

## Context

GitHub Actions grants a token permissions based on workflow defaults when a workflow does not declare them. The CI workflow only needs to check out source; implicit permissions can be broader than necessary.

## Decisions

**Grant the CI workflow only `contents: read`**: declare workflow-level permissions in `.github/workflows/ci.yml`. Any future job needing more access must declare and justify it explicitly.

## Consequences

CI can read repository contents and cannot use the workflow token for write operations. Workflows that need other permissions must request them explicitly at the narrowest scope.
