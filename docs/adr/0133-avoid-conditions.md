# ADR 0133: A host whose probed service is down is avoided for new namespaces

Date: 2026-11-15 · Status: accepted · Extends ADR 0021 (host conditions) and ADR 0132 (placement by memory share).

## Context

A host can be healthy by its own figures (memory, disk, pool) and still be a bad place for a new namespace: a service the machines on it depend on, such as a local registry mirror or a network gateway, answers nothing. Every true condition is a pressure (ADR 0021): the fleet places nothing new on the host and refuses creates in namespaces pinned to it. That is right for a full disk, and too hard for a service that is down on one host while the others work: a fleet where every host is affected would place nothing.

Kubernetes separates the two: a node-problem-detector sets a node condition, and a `PreferNoSchedule` taint steers the scheduler away without evicting or refusing.

## Decision

- **Probes.** `conditions.probes` in the daemon's config lists services to ask: `name`, `http` (a URL asked with GET), `interval_sec` (15), `timeout_sec` (5), `failures` (3). Absent: no probes, as before.
- **A condition per probe**, of type `name`. It is true after `failures` misses in a row and false on the first success. A miss is anything but a 200: no connection, no answer within `timeout_sec`, another status, a redirect (not followed). The message names the URL and what failed (`connection failed`, `answered 503`, `no answer in 5 s`), never the response body.
- **Validation** refuses: a name that is not a condition type (a letter, then letters, digits and `_`, at most 63), one of the daemon's own condition types, a name used twice, a URL that is not `http(s)` or carries credentials, a query or a fragment (the status shows it), and values outside the bounds (`interval_sec` 1 to 3600, `timeout_sec` 1 to 15, `failures` 1 to 100).
- **`effect: avoid`.** `Condition` gains an optional `effect`. Absent is a pressure, as today, and is not written. A probe's condition carries `avoid`. `under_pressure` ignores it, so `takes_new_namespaces` and the refusal of creates on a pinned host are unchanged.
- **Placement.** `HostRec::avoided()` is true while any `avoid` condition is true. `HostRec::load_order`, which `Registry::place` and the sandbox admission pick (ADR 0128) both end on, puts a host that is not avoided before one that is, then the share of memory used (ADR 0132). Every other key (nested class, a validated seed, boot waves) comes first, as before. When every candidate is avoided, the usual order picks among them, so a fleet-wide outage places as it does today.
- A namespace already pinned to an avoided host stays there and still creates.

## Rollout

The fleet is upgraded before any daemon config adds a probe. A fleet that does not know `effect` reads any true condition as a pressure and would refuse placements on the host.

## Alternatives

- **A pressure for probes**: refuses creates in pinned namespaces and places nothing when all hosts are affected.
- **Draining the host**: moves running machines for a fault that may last seconds.
- **The fleet probes the hosts**: the fleet cannot reach a service bound to the host's own address, and a daemon already ticks locally.
- **Command or TCP probes**: no need yet; a URL covers the services in use.

## Consequences

- A host with a down service still receives work when it is the only one with room, or for namespaces already on it.
- A flapping service flips the condition at most once per `failures` misses; `host_condition` events show each change.
- The avoided order is a preference, not capacity: `shortage` and `largest_slot` are unchanged.
