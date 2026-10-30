#!/usr/bin/env python3
"""Extract one suspend's opt-in stages from daemon JSON logs; never calls the API."""
import argparse
import json
import math
import re
import sys


def commit(value):
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", value):
        raise argparse.ArgumentTypeError("expected a Git commit hash")
    return value


def summarize(lines, machine, pid, runtime_commit, caller_commit=None,
              request_id=None, caller_ms=None):
    stages = []
    requests = []
    for line in lines:
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        fields = event.get("fields", {})
        if not isinstance(fields, dict):
            continue
        if fields.get("profile") == "lifecycle":
            if fields.get("machine") != machine or fields.get("pid") != pid:
                continue
            keys = ("operation", "stage", "elapsed_us", "finished_us", "completed")
            if all(key in fields for key in keys):
                stages.append({key: fields[key] for key in keys})
        elif request_id and fields.get("request_id") == request_id:
            if fields.get("path") == f"/v1/machines/{machine}/stop":
                requests.append({key: fields.get(key) for key in ("ms", "status")})
    kill = [s for s in stages if s["stage"] == "kill_begin"]
    observed = [s for s in stages if s["stage"] == "exit_observed"]
    # Refuse to pair repeated operations or an exit observed before this kill.
    exit_us = None
    if len(kill) == len(observed) == 1:
        delta = observed[0]["finished_us"] - kill[0]["finished_us"]
        if delta >= 0:
            exit_us = delta
    overhead = None
    if caller_ms is not None and len(requests) == 1:
        daemon_ms = requests[0]["ms"]
        if isinstance(daemon_ms, (int, float)):
            overhead = caller_ms - daemon_ms
    return {
        "runtime_commit": runtime_commit,
        "caller_commit": caller_commit,
        "machine": machine,
        "pid": pid,
        "stages": stages,
        "kill_to_exit_observed_us": exit_us,
        "daemon_requests": requests,
        "caller_ms": caller_ms,
        "caller_minus_daemon_ms": overhead,
        "notes": [
            "Snapshot create includes file writes, disk flushes and durable file syncs.",
            "Stages can nest; do not sum parent and child durations.",
            "Kill-to-exit includes watcher scheduling. Notification can precede record persistence.",
            "Caller-minus-daemon includes transport, forwarding and caller overhead; millisecond resolution applies.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--machine", required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--runtime-commit", type=commit, required=True)
    parser.add_argument("--caller-commit", type=commit)
    parser.add_argument("--request-id")
    parser.add_argument("--caller-ms", type=float)
    args = parser.parse_args()
    if args.pid <= 0 or (args.caller_ms is not None and
                         (not math.isfinite(args.caller_ms) or args.caller_ms < 0)):
        parser.error("pid must be positive and caller-ms finite and nonnegative")
    out = summarize(sys.stdin, args.machine, args.pid, args.runtime_commit,
                    args.caller_commit, args.request_id, args.caller_ms)
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if out["stages"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
