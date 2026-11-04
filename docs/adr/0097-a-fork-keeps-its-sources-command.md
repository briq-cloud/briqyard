# ADR 0097: A disk fork keeps its source's command unless the request sets one

2026-11-04 · Status: accepted; extends ADR 0031 and 0092

## Context

A restore filled `entrypoint`, `cmd`, `env`, `files` and `ports` from the backup's record. A disk
fork copied the image, volume and class and nothing else, so a fork of a machine started with a
custom command ran the image's own: a fork of a machine running `sleep` ended at once, and
suites set the command by hand after every fork (`hack/e2e-*.sh`, `chaos.py`).

## Decisions

**One rule for a restore and a disk fork** (`inherit_run_config`, `machine/create.rs`):

| Field | Left out of the request | The request sets it |
|---|---|---|
| `entrypoint`, `cmd` | the source's | wins, `[]` (the image's own) included |
| `ports` | the source's when the request's list is empty | the request's list, whole |
| `files` | a restore: the backup's when empty. A disk fork: nothing | the request's list, whole |
| `env` | the source's | the source's variables, under the request's: the request wins per key |

A present `cmd` or `entrypoint` is the request's even when empty; `ports` and `env` cannot tell
empty from left out, and for them empty means left out, as in a restore. An empty `env` cannot
remove the source's variables.

**A disk fork does not inherit `files`.** Every boot writes the record's boot files again, so a
fork that inherited them would undo what the guest changed in them after creation, which the
copied disk holds, and would bring back a file the guest deleted. The fork keeps its disk's copy;
`files` in the request still apply.

**Memory forks do not change.** A fork from a named memory snapshot, a sandbox seed and a warm
slot resume a sealed process: their destination is strict and a request that names any of these
fields is still refused before the fork branch fills anything.

**What is copied.** The source is the caller's own machine (`own_entry`) and its disks already
hold what it wrote. `entrypoint`, `cmd`, `ports` and `env` are copied into the fork's own record.
The control plane delivers boot-only secrets as boot files, never in `env`, and a fork does not
inherit files: they are not rewritten into it. Known property, unchanged here: a restore does
write the backup's boot files, boot-only secret files included, again.

**The control plane is unchanged.** `BriqyardProvider` resends `cmd`, `entrypoint`, `env` and
`files` for a fork from the source's spec; what it sends wins, and a variable it leaves out is
the source's, which is what the fork's disk was initialised with.

## Tests

Unit: a bare fork inherits the four and no files; explicit values win, an empty `cmd` and `entrypoint`
included, and env is merged. Native: a fork of a machine running `sleep` is running with the
same `cmd` (`e2e-machines.sh`, `e2e-storage.sh`), where both suites used to set it by hand;
a fork keeps the source's edited boot file and a deleted one stays deleted (`e2e-machines.sh`).
