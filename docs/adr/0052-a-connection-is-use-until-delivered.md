# ADR 0052: A connection is use until it reaches the program

Date: 2026-10-29 · Status: accepted; amends ADR 0005 (what use is)

## Context

`hack/stress.py`'s sleep/wake phase failed 3 of 6 in each round: six machines with a 20 s window asleep, one connection to each machine's TCP endpoint at once. In the daemon's log, all six were woken by their connection within the same second, and the host boots three at a time (`boots_at_once`: half of the six hardware threads). The three that booted first were running 6 s later. 22 s after the wake the sleeper stopped them under the connection, before their program (`python3 -m http.server`) listened; the client timed out at 120 s. The other three booted next, and each answered within 7 s of running.

The code made a use of the connection's arrival only: a touch at the dial, then the wake's start. The ingress then waits for the machine to be ready (ADR 0022) and for its port to accept, up to the boot timeout plus 30 s, and that wait was not use. A wait longer than the window (a cold boot under load, a program slow to start, a startup probe) let the sleeper stop the machine under it. The wait then went on against a stopped machine until its timeout, 5.5 minutes on the dev host. An exec had the same gap: it is use from the guest's answer, after the wake and the wait for ready.

Knative's activator holds a request while its revision scales from zero and sends it once a pod is ready; the held request counts as in flight, so the autoscaler does not scale to zero under it ([request flow](https://knative.dev/docs/serving/request-flow/), [autoscaling](https://knative.dev/docs/serving/autoscaling/)).

## Decisions

**A connection is in use from its arrival until it reaches the program.** The ingress holds the machine in use, as a running exec does (ADR 0029), through the wake, readiness and the wait for the port. The sleeper leaves it running; its last use is the delivery, so the window starts once the program has the connection. TCP and HTTP endpoints alike.

**An open connection after that is not use**, as ADR 0051 §3 has it for the kernel's counters: a pool's idle connections and keepalives would keep a machine awake for good. A machine sleeps under an idle open connection, which is cut; the next connection wakes it. A client that keeps one connection busy past the window touches the machine (`POST /machines/{id}/touch`) or sets `sleep: "never"`.

**A wait ends when its machine stops** (a stop on request, an exit): the client's connection closes then, not at the wake timeout.

**An exec is use from the call**, through its wake and the wait for ready.

Rejected:

- **An open connection as use.** Knative counts an open WebSocket as a request in flight, but it sees requests; a TCP proxy sees connections, and cannot tell a request from an idle pool connection.
- **A longer window after a wake.** A number that does not cover a slower program, and keeps every woken machine up longer.

## Consequences

- With ADR 0051's counters, the hold stays in the proxy for as long as it is the activator (a machine asleep, starting or not ready). The counter's `ct state new` on the proxy's connection to the machine falls at the delivery, where the last use now is.
- An exec that wakes its machine holds it from the call.

## Measured

In the dev VM (6 threads, three boots at once), `stress.py --tenants 6 --per-tenant 4 --rounds 2 --phases endpoints_all,sleep_wake`, wakes through an endpoint that were answered:

| | Round 1 | Round 2 |
|---|---|---|
| Before | 6 of 6 | 4 of 6: one timed out, one closed unanswered as its machine slept |
| After | 6 of 6 | 6 of 6 |

Under that load a cold boot took 5 to 30 s and the program's start more. The full run (`--rounds 2 --crash`), before, failed 3 of 6 in each round.
