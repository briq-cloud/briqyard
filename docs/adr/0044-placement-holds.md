# ADR 0044: Placement holds: given back when the host does not make the machine, a destroy's room at its answer

Date: 2026-10-28 · Status: accepted; amends ADR 0013's reservation

## Context

ADR 0013: placement adds a create's memory to the host's `used` and takes its disk from `disk_free_mb`, until the host's next report (a heartbeat, or the poll of a static host, every 15 s) replaces both. A capacity run on two real hosts (60 creates of 4 GB at once, 24 workers, through the fleet) found what that leaves out:

| What | Seen |
|---|---|
| A create the host refused, or the fleet refused after placing it, stays counted | 9 creates failed: the hosts showed 12 machines' memory used each, 15 machines existed |
| A destroy frees nothing in the fleet | after 4 destroys a create still got 503 `capacity`; after the next heartbeat, 201 |
| A report during a create drops its reservation | the host does not count a machine until its boot reserves the memory: a burst that spans a report lands on the host the report shows emptiest |

The capacity signals (ADR 0042: `free_mb`, `largest_slot_mb`, `/v1/status`'s `regions`, `host ls`) read the same figures, so they were wrong the same way.

## Decisions

**A create holds what it asks until a report counts it.** `Registry::hold` takes the memory and the disk from the host's figures and keeps them as a hold (an id, in memory only: a fleet that restarts has the next report). The create then ends it:

| The host | The hold |
|---|---|
| made the machine (2xx) | `made(at)`: kept until a report received after `at`, then dropped, the report counting the machine |
| refused it, did not answer, or the fleet's write before the forward failed | `release`: what it took is back at once |
| is still making it when the caller hangs up (its handler is dropped) | `release`, by the hold's guard (`Held`): a hold no request ends would stay counted until the fleet restarts |

A report (heartbeat, poll, or the refresh below) replaces the figures, then takes again every hold it does not count yet: the creates not answered, and those answered after it was received. A gateway placed for a new tenant holds and ends the same way.

**A destroy's answer waits for the host's figures.** The daemon answers a destroy 204 with no body, and the fleet does not know the machine's size or state. Once the host answered, the fleet asks its `/v1/status` (five seconds at most) and applies it as a report. The figures are the host's own, with no size to guess and no subtraction that a heartbeat could count twice. Not answering is nothing: the heartbeat comes.

**The signals need nothing new.** They read `used` and `disk_free_mb`, which now hold these figures.

Kubernetes's scheduler does the same with its cache: a pod is assumed on its node at binding, forgotten when the binding fails, and a deleted pod leaves the node's sum at the watch event.

## What is left

- A report the host composed before a create landed but the fleet received after its answer drops the hold early: the host is under-counted until the next report. The host checks its own memory at the start (ADR 0025), so it refuses what does not fit.
- A host counts a machine from its boot: while a create boots, the hold and the host both count it. The fleet over-counts for that long, which refuses too much, never too little.
- A stop also frees memory; the fleet sees it at the next report.
- The disk a create holds is its volume plus 2 GB (ADR 0013): a burst of small creates on a small pool is refused for disk before memory runs out. Seen in the dev VM, 28 GB free: 14 creates at once.
- A host that reports no disk figure reports 0, and placement does not hold it to one; holds that take a host's last free MB leave the same 0 until the next report.
