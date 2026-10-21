# ADR 0029: Exec sessions: stdin streamed, a terminal, over a WebSocket

Date: 2026-10-21 · Status: accepted; amends ADR 0004 (the exec's input and its end), ADR 0019 (`session_opened`, an event that is not a version)

## Context

`POST /v1/machines/{id}/exec` takes a JSON body with stdin as one string and answers the output once the command ended. A sandbox, the use case briq leads with, needs what `kubectl exec -it` and `docker exec -it` give: a shell with a terminal, input as it is typed, output as it comes, a window that resizes, the exit code at the end, and a command that ends when the person leaves. Kubernetes has it in its API (the scope test, `../KUBERNETES-MAP.md`), so it is briqyard's.

## Decisions

**A session is a WebSocket upgrade of `GET /v1/machines/{id}/exec`.** What it runs is the query: `cmd` once per argument, `env` once per `NAME=VALUE`, `cwd`, `timeout_ms` (0, the default, is none: the command lasts as long as the session), `wake` (true), `tty` (false), `cols` and `rows` (80 by 24). An unknown key or a value that does not parse is 400 `invalid` by name: a mistyped `tty` must not give a session without a terminal. Everything before the upgrade answers as every route does (404, 409 `not_running` with `wake=false`, `boot_failed`, the bearer token in `Authorization`), since the machine is found, woken and waited for (`ready`, as the JSON exec, ADR 0022) and the command started before the `101`. The JSON exec stays as it is for scripted calls; both run through one guest path (below).

**Messages are binary, the first byte a channel, as Kubernetes' `v5.channel.k8s.io`**: 0 stdin (client to server), 1 stdout, 2 stderr (empty on a terminal), 3 the end (`SessionEnd` JSON: `exit_code`, `timed_out`, or `code` and `error` when the session ended without one: `not_running` when the machine went down, `invalid` for a message the server cannot read), 4 a resize (`{"cols","rows"}`), 255 a close (payload `0`: stdin's end). The numbers are Kubernetes', so a client written for one reads the other. Text messages and unknown channels are ignored. One message at most 1 MB: its stdin frame, base64 in JSON, stays under the guest protocol's 4 MB.

**The guest protocol carries the session on the exec's own connection** (ADR 0004): the request gains `interactive` (stdin stays open), `tty`, `cols`, `rows`; after it, the host sends `stdin` (data), `resize` and `close_stdin` frames; the init answers `stdout`, `stderr` and `exit` as before. The JSON exec is one such connection whose stdin is the request's bytes and then closes (`collect` reads it to the exit): one exec path in the init, in `guestc` and in the manager. A `timeout_ms` of 0 is now no deadline in the init; the daemon still sends 5 minutes for a JSON exec that asks for none.

**The host's close ends the command, for every exec.** The init reads the connection while the command runs; its end is the host gone: SIGKILL to the command's process group, or on a terminal SIGHUP first (as a closed window does), then SIGKILL after 5 s. A JSON exec whose caller hung up is killed too, as Kubernetes does; a process detached with `setsid` (briq's async exec) is not in the group and lives on. Stdin goes through a queue in the init, so a command that does not read it never keeps the close from being seen.

**A terminal is the init's**: `openpty` at the size asked, the command in a session of its own (`setsid`) with the terminal as its controlling terminal (`TIOCSCTTY`), stdin, stdout and stderr on it, `TERM` from `env` (`xterm`, as Docker, when absent). A resize is `TIOCSWINSZ` on the master, which sends SIGWINCH to the foreground group; it is applied as its frame is read, before any input after it. `close_stdin` closes a pipe and does nothing on a terminal: a terminal's end of input is ^D, a byte like any other (ssh does the same). The output after the exit is read until the kernel answers EIO (every copy of the command's side closed), 2 s at most, as pipes are. The reaper is unchanged: the command is tracked as every exec's.

**The client's absence is seen.** The daemon pings every 30 s; a client heard from (any message, pongs included) in none of the last 90 s is gone, so a laptop that slept does not hold a machine awake.

**A session is use for its whole life** (ADR 0005): a count of open sessions per machine; the sleeper passes over a machine with one, `sleeps_at` is none while it lasts, and its start and its end are a use, so the window starts again when the person leaves. An open session is not a reason to refuse a stop: the stop goes on and the session ends `not_running`.

**A `session_opened` event** (normal) about the machine: `{command, tty}`, the program and not its arguments (they may hold a secret). It is a use, not a change, so it does not move the machine's version: ADR 0019's "every event about a machine moves it" becomes every event about its spec or its state. The end is a daemon log line with the exit code and the duration.

**The fleet relays the session as bytes.** It finds the machine's host, sends the client's handshake (`Connection`, `Upgrade`, `Sec-WebSocket-*`) with the host's token through the host's pinned client (ADR 0020), answers the host's `101` with the host's handshake headers, then copies both upgraded connections until either closes. Any other answer is relayed as it is. The fleet reads no message and holds no session state.

**The CLI**: `briqyard machine exec -it <id> -- sh` sends the local `TERM` and size, puts the terminal in raw mode once connected and restores it on every way out (an error, a signal, the end), forwards SIGWINCH, sends every key (Ctrl-C included) and exits with the remote exit code; SIGINT, SIGTERM or SIGHUP to the CLI closes the session (128 + the signal). `-t` refuses a stdin that is not a terminal, as Docker. `-i` alone streams a pipe (`echo hi | briqyard machine exec -i m -- cat`); it replaces `--stdin`. Without either, the JSON exec, as before. The suites drive `-it` through `hack/exec-tty.py`, a terminal of a given size scripted with `send`, `expect`, `resize` and `kill`.

Rejected, one line each:

- Docker's raw hijacked stream with an 8-byte multiplex header: no resize or exit on the stream (Docker asks two more endpoints), and a proxy has no frames to see.
- The session's spec as a first message instead of the query: refusals would come after the `101`, in our own envelope, instead of as HTTP answers.
- A second vsock connection for input or resize: two connections to tie together, and nothing a frame on the exec's own does not do.
- A WebSocket client in the fleet: decoding and re-encoding messages it does not read; a byte relay is less code and cannot change them.
- Touching the machine on a timer while a session is open: an approximation of in-use that a count says exactly.
- Writing VEOF to a terminal at `close_stdin`: a guess at what the client meant that a client can send itself.

## Consequences

- A sandbox is a shell away: `briqyard machine exec -it m -- sh`, through a daemon or the fleet.
- briq (out of scope here) would expose it as a WebSocket of its own in front of this one: its API authorizes the team and the briq, then relays to the provider's session as the fleet does (the bearer token stays briq's); the dashboard's terminal (xterm.js) and a `briq exec -it` command speak these messages. MCP has no streaming tool for a terminal: an agent keeps the JSON exec; a person gets the terminal. Audit: briq writes its own row when it opens a session; `session_opened` is the provider's record.
- A JSON exec cut off by its caller now ends; a caller that wants a process to outlive it detaches it (`setsid`, `nohup`), as on any host.
- The init's stdin queue is unbounded: a client may send faster than its command reads, to its own machine's memory; the 1 MB message cap bounds each message, not the sum.
- Not built: attach to the main process (its stdin is closed and its output is the console, `logs -f`); a session that survives the daemon's restart (the vsock connection is the daemon's); `kubectl cp` over a session (the files API does it).
