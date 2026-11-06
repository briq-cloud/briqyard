# ADR 0115: The console has two views, the program's and the runtime's

Date: 2026-11-06 · Status: accepted

## Context

`GET /v1/machines/{id}/logs` served one stream: the guest's serial console, which carries the program's output, the kernel's, the init's (`[briqyard] …`) and, because Firecracker's stdout is that console, nothing else of Firecracker's. A consumer that shows a customer their program's output had to filter the rest itself, by pattern, on the client.

Three things made that wrong at the source:

- `started pid=… <argv>` (init) prints the program's whole command line, and the kernel and init lines are noise to the program's owner.
- Firecracker ran at its default log level (Info) and logged every API request body: kernel and drive paths, boot args, network settings. The jailer takes the arguments after the first `--` for Firecracker; the daemon passed `-- -- --level Warning`, so the second `--` hid the flag from Firecracker's parser. Firecracker's stderr was also written to the same console file with no mark.
- A runtime line and a program line were indistinguishable once stored.

Env is not in those bodies. The machine's env is written on the config drive the daemon writes (`write_config_drive`), never in boot args or an API request, so Firecracker's log holds no customer secret. Checked in `machine/start.rs`: the boot args hold the init path, the network and the kernel options only.

## Decision

**One endpoint, two views: `GET /v1/machines/{id}/logs?view=app|runtime`, default `app`.** `app` is the program's output. `runtime` is the kernel's, the init's, Firecracker's and the jailer's. An unknown value is `400 invalid`. The CLI takes `--view`. `follow=true` serves the same view.

**The view is stored on the line, in the one console file.** The writer puts a mark after the timestamp: `<ts>! <line>` for a runtime line, `<ts> <line>` for the program's. A line without the mark is the program's. So:

- Rotation (`console.<start>.log`), byte-offset cursors and the `console::grown` notifier (ADRs 0021, 0025) are unchanged: still one file, one offset space.
- A console written before this change has no mark, so it is all program output: `view=app` answers as `logs` does today, `view=runtime` answers an empty page. Neither is an error, and no migration runs.
- A page of one view skips the other's lines but its cursor moves over them, so a cursor covers every byte scanned. `limit` counts the lines of the view.

**Classification happens at capture, by who wrote the line:**

| Source | View | How known |
|---|---|---|
| Guest serial, kernel | runtime | a `[  12.345678] ` stamp; the daemon adds `printk.time=1` to the boot args |
| Guest serial, init | runtime | the `[briqyard] ` prefix, every init line, not only `started` |
| Guest serial, anything else | app | the program |
| Firecracker's stderr (the jailer's errors included) | runtime | the pipe |
| Firecracker's log | runtime | its own pipe, below |

The init is not changed (its digest changes only with the init, ADR 0101) and its line format stays: the daemon still reads `[briqyard] exit code=…`.

**Firecracker runs at `--level Warning` with its own log FIFO.** One `--` after the jailer's arguments, then `--log-path <fifo> --level Warning`. The FIFO is `firecracker.fifo` in the run directory (inside the chroot when jailed), made like the metrics FIFO (ADR 0030): owned by the jail's uid, opened `O_RDWR | O_NONBLOCK` by the daemon before the spawn so Firecracker's open never blocks and never sees a closed reader. A task stamps each line it reads as runtime and appends it to the console. After a daemon restart, adopt reopens the FIFO and a fresh writer, as it does for the metrics.

**No redaction.** Firecracker at Warning logs no request body, and what its bodies held (paths, boot args, network settings) is not secret.

## Alternative considered

A second file, `runtime.log`, with its own rotation and cursors. It cannot order runtime lines against program lines, a cursor would need to name its file, and every follower would watch two files. It also leaves old consoles needing a rule. The mark costs one byte on a runtime line.

Filtering by pattern at read time, as the client does. It cannot tell a program that prints `[briqyard] …` from the init, and Firecracker's lines have no pattern to match.

## Consequences

- The default view changes for existing readers: `[briqyard] …` and kernel lines leave it. A script that greps them uses `--view runtime`. The e2e, fleet and CI suites that did are updated.
- All init lines are runtime, so messages like `volume /data: grown` are not in the app view. A start that failed is still in the machine's `error`, which carries the console's last lines.
- Runtime lines Firecracker writes while no daemon holds the FIFO (between a daemon's death and the next adopt) are lost. They are warnings and errors only.
- A machine booted by an older daemon has no FIFO and no kernel stamps: its console stays mixed and its runtime view holds only what the init printed. The next boot of that machine is separated.
- A program that prints a line shaped like a kernel stamp (`[    1.000000] x`) is classified as runtime. The program's line is not lost: `view=runtime` serves it.
- Pagination (`before`, `after`, a tail default) comes next, on these cursors.
