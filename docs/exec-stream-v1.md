# Finite-input exec stream v1

Upgrade `GET /v1/machines/{id}/exec/stream/v1` using the existing API authentication.
No query parameters are accepted. The fleet locates the machine and forwards the upgrade
and all frames to its daemon. Clients cannot select a backend or namespace through this route.

Send a text JSON object within ten seconds of the upgrade:

```json
{"cmd":["cat"],"env":{},"cwd":"/tmp","timeout_ms":30000,"wake":true,"stdin":"hello\n","interactive":false}
```

`cmd` and `timeout_ms` are required. `env`, `cwd`, and `stdin` default to empty;
`wake` defaults to true and `interactive` to false. Missing and empty stdin both mean EOF.
Unknown or duplicate fields, duplicate environment names, interactive input, and TTY options
are refused. The initial message is limited to 1 MiB including JSON escaping. Stdin is limited
to 512 KiB; command and environment each to 128 KiB and 256 entries. Individual arguments
and environment values are limited to 32 KiB. Cwd must be empty or absolute, up to 4096 bytes.
NUL is forbidden in command, cwd, and environment. Timeout must be 1 through 3600000 ms.

The daemon holds the machine in use while probing the actual running guest's pong for
`exec_stream_v1:true` and throughout execution. A missing capability is unsupported regardless
of version number. This pre-spawn refusal has terminal `code: "unsupported"`; invalid initial
requests use `invalid`, unavailable machines use `not_running`, and other start refusals use
`exec_stream_refused`. Clients must use these codes rather than error prose. Commands use the
distinct guest operation `exec_stream_v1`, so a guest
replaced by an older init between probe and execution rejects the operation before spawning.

After the initial request the only application message is text `{"action":"cancel"}`.
Repeated cancellation is harmless. Later stdin, data, resize, or other application messages
are refused. A cancellation leaves the connection open for its terminal response.

Output uses binary frames: byte 1 prefixes stdout, byte 2 stderr, and byte 3 prefixes the
terminal JSON object. Frames are ordered on the connection. There is exactly one terminal
frame and no later output. Existing `exit_code`, `timed_out`, `code`, and `error` fields retain
their meanings; `cancelled:true` is optional and only reports guest-confirmed cancellation.

On cancellation the guest kills the owned command process group, waits for the direct child,
and checks for remaining live group members within a bounded interval. Zombie members
cannot execute or retain descriptors and are reaped separately. Kill, wait, or inspection
failures produce a failed terminal with `code: "exec_cleanup_failed"`, no `exit_code`, and no confirmed cancellation. An unexpected child-wait failure uses `exec_wait_failed`. Normal exit may win a race
with cancellation. Output readers and the stdin writer are finished or aborted and joined
before the terminal frame. The daemon bounds its output queues and processes cancellation independently of downstream writes. Invalid client messages close the guest connection before reporting an unconfirmed failure.

Transport loss or a missing acknowledgment never confirms cleanup and must not trigger a
retry of execution. This protocol provides no durable session recovery or cancellation journal.
The existing `/exec` session route and shell protocol are unchanged.
