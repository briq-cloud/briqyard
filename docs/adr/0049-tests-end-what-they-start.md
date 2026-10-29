# ADR 0049: A test ends what it starts, on any exit

Date: 2026-10-29 · Status: accepted

## Context

A `briqyardd` unit-test executable was found running on the Mac after its run, reparented to
launchd: the `cargo test` above it had been killed (a tool's timeout) and the binary ran on.
The shell suites had the same gap: a failed check or a Ctrl-C left their background jobs
running in the VM (exec sessions on `sleep 600`, `events --watch`, `logs -f`), and a run cut
while it had stopped a daemon (fc's own, or fc2's) left it stopped for the next session.

What a test binary starts, read from the code:

| Child | Ends today |
|---|---|
| the fake `zfs`, `udevadm`, `zvol_id` (`sh <script>`, through production `Zfs::call`, `send`, `receive`, `bounded`) | when its script ends; three wait in a loop while a `hold.*` / `hang.*` file is there |
| the init's commands (`sh`, `sleep 60`, `cat`; Linux) | with the exec's group kill, its deadline or `kill_on_drop`; `main_process` within 60 s |
| `cat`, `true` (std) | when their stdin closes |

A test that panics runs its destructors: the temp dir goes, the hold files with it. A binary
that exits (or is killed) runs none: the hold files stay and the fakes spin forever.

## Decision

- **A test binary exits with its parent.** `briqyard-testing` (dev-only, `publish = false`)
  has one function, `exit_with_parent`: a thread that reads `getppid()` every second and exits
  the process once it changed (reparented to init, launchd or a subreaper), or once 6 minutes
  passed: five times the slowest binary (`briqyardd`'s: 70 s on CI, 55 s in the dev VM, 61 s
  on a Mac); the tests not reported above the line it prints were still running. Each crate
  installs it from its test root with `#[ctor]` (dev-only): one line per crate covers every
  test, fixture or none. Linux's
  `PR_SET_PDEATHSIG` follows the thread that forked and macOS has no equivalent; a kqueue or
  pidfd watch is two code paths; a cargo `runner` would wrap `cargo run` too.
- **What a test spawns ends on its own.** The binary's exit runs no destructor, so a child is
  not killed by it: the fakes' wait loops also stop once their parent is gone
  (`kill -0 "$PPID"`). No process group (the binary would leave the terminal's foreground
  group), no child tracking. The fake tools spawn as production does (no `kill_on_drop`:
  a `zfs` running past its caller is `storage_stalled`, ADR 0046).
- **A stand-in that never answers fails its test.** The fixtures that own a wait bound it:
  the CLI's and the fleet's test HTTP clients time out after 10 s, the Firecracker and vsock
  stand-ins give up after 10 s and close their socket. Waits on the code under test keep the
  binary's 6 minutes as their bound.
- **A suite cleans up in one trap.** `trap cleanup EXIT`, and INT, TERM and HUP end the run
  through it (`exit 130`/`143`/`129`). The cleanup ends the shell's own children
  (`pkill -P $$`: a background pipeline's processes are all children of the shell, while
  `jobs -p` names only the first of each), puts back what the run changed (a key, a config,
  a drained host, a stopped daemon) and destroys what it made. A process is signalled by the
  pid the suite recorded, never by a name pattern. `stress.py` turns SIGTERM and SIGHUP into
  its Ctrl-C path and destroys what is left in a `finally`.

## Consequences

- A killed `cargo test` leaves nothing: its test binary exits within a second
  (0.6 s measured on the Mac), its fakes within one loop turn.
- A test hung on the code under test costs at most 6 minutes, and fails then. A binary that
  grows past a fifth of it raises `LIMIT` in the same change.
- `ctor` runs code before `main`: the function it calls only starts a thread.
