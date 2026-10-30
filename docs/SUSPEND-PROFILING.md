# Profile one suspend

The daemon emits opt-in stage timings (ADR 0063). Use a disposable machine with a known workload;
record its memory size and prepared working set alongside the result. Compare the same workload
and installed runtime commit. Enabling debug logging can itself add overhead.

Run the daemon with `BRIQYARD_LOG=info,briqyardd::profile=debug`. Keep its existing JSON log sink.
Events have `fields.profile=lifecycle` because the normal JSON sink omits tracing targets.
They contain identifiers and durations, no guest data. The normal daemon request log already
contains `request_id`, `status` and `ms`.

## Capture

Set `BRIQYARD_URL`, `BRIQYARD_TOKEN`, `MACHINE_ID`, `RUNTIME_COMMIT` and optionally `CALLER_COMMIT`
for the build that will issue the request. The token stays in the local environment and curl's
stdin config, never in command arguments or the saved result. The machine must be running.

Read `FC_PID` on the daemon host from the machine's private record; the public machine view does
not expose host PIDs. Set `DATA_DIR` to the daemon's configured `data_dir` (default
`/var/lib/briqyard`). Print only the PID, since the rest of the record can contain namespace secrets.
If the caller runs elsewhere, transfer this PID to that shell before issuing the stop request.

```sh
DATA_DIR=/var/lib/briqyard  # the daemon host's configured data_dir
FC_PID=$(sudo jq -er '.pid | select(type == "number" and . > 0)' \
  "$DATA_DIR/state/machines/$MACHINE_ID.json")
PROFILE_REQUEST_ID=$(openssl rand -hex 8)
PROFILE_STARTED_AT=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
printf 'header = "Authorization: Bearer %s"\n' "$BRIQYARD_TOKEN" |
  curl --config - --fail --silent --show-error \
    --header "x-request-id: $PROFILE_REQUEST_ID" \
    --header 'content-type: application/json' \
    --data '{"suspend":true,"timeout_sec":10}' --output /dev/null \
    --write-out '%{time_total}\n' \
    "$BRIQYARD_URL/v1/machines/$MACHINE_ID/stop" >caller-seconds.txt
journalctl --unit briqyardd --since "$PROFILE_STARTED_AT" --output cat >daemon.ndjson
CALLER_MS=$(awk '{printf "%.6f", $1 * 1000}' caller-seconds.txt)
python3 hack/profiling/suspend.py \
  --machine "$MACHINE_ID" --pid "$FC_PID" --runtime-commit "$RUNTIME_COMMIT" \
  --request-id "$PROFILE_REQUEST_ID" --caller-ms "$CALLER_MS" \
  <daemon.ndjson >suspend.json
```

Run journal collection on the daemon's host. The caller can be elsewhere; copy only the intended
log interval for analysis. Add `--caller-commit "$CALLER_COMMIT"` when that caller is a versioned
client or a service. The script reads logs only and never calls the API. It exits 1 with an empty
stage list if debug events are absent. Preserve the caller duration separately when investigating
an API above the daemon: that additional duration includes that API's queues and response handling.

## Read

- `snapshot_durable.pause`: Firecracker's pause request.
- `snapshot_durable.create`: writes, block flushes and durable snapshot syncs together.
- `suspend.record_stopping` / `record_suspended`: event/record persistence before the kill.
- `kill_to_exit_observed_us`: kill dispatch through the watcher observing the exited process,
  including scheduling. Missing or repeated markers produce null rather than a guessed pairing.
- `settle.network`, `exit_report`, `record_stopped`: teardown after the process exits.
- `suspend.kill_to_notify`: teardown until the stop waiter is notified. It can end before the
  final stopped record save. A false completion here means the 15-second deadline expired.
- `suspend.total`: stop-entry wall, including nested snapshot and settlement stages.
- `caller_minus_daemon_ms`: transport, forwarding and caller overhead together. Daemon request
  duration is rounded to milliseconds; small negative differences can be rounding or measurement
  boundaries. It does not identify which external layer spent the time.

Stage times nest: do not add `snapshot` to its `pause`/`create`, or settlement to `kill_to_notify`.
The summarizer uses `finished_us`, a monotonic clock local to one daemon process. Do not combine
logs across daemon restarts as one operation. `completed=false` on `exit_report` can simply mean
that the process closed its report channel after being killed.

If `create` dominates, collect sync syscall durations on the same disposable machine in a separate
run. This trace records no write buffers and needs permission to trace that process:

```sh
strace -f -ttt -T -e trace=fsync,fdatasync -p "$FC_PID" -o snapshot-sync.trace
```

Stop the tracer after the operation and preserve the trace with the runtime commit. Tracing adds
overhead; syscall durations can overlap, so their sum is not a measured file-writing duration.
No durability flag or fsync is changed for profiling.
