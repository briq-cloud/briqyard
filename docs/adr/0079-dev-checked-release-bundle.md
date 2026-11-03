# ADR 0079: Complete checked runtime releases for development

2026-11-02 · Status: accepted

## Context

The local release produced by `hack/vm.sh` contained four runtime binaries. Bootstrap
also requires the checked Firecracker bundle. Fleet smoke therefore failed its upgrade
before activation, despite matching daemon and init builds.

## Decisions

**Development releases consume an explicitly supplied checked bundle and trusted digest.**
Verify the current source pin and reuse bootstrap's provenance, validation and content
checks before installation. Copy the unchanged bundle beside the local binaries and hash
all five assets in the architecture's manifest. No automatic downloads or evidence generation.

## Consequences

A release workflow's authentic bundle can be reused while its source pin matches.
The upgrade activates its verified runtime through bootstrap's existing immutable paths;
lifecycle checks must cover any changed bindings. Portable bundle evidence does not imply
native runtime qualification. Global fleet listing tests still require every registered host.
