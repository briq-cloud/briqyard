#!/usr/bin/env python3
"""Recovery readiness and a closed, bounded journal summary for qualification."""
import collections
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import time
import urllib.error
import urllib.request

MAX_BYTES = 256 * 1024
MAX_LINES = 256
# Literal contexts owned by these source positions; matches are diagnostic hints,
# not proof that a predicate was the initiating failure.
PREDICATES = {
    "startup service settlement failed; managed spawning stays closed": (
        "service_settlement", "crates/briqyardd/src/fc/recovery/native.rs:77"),
    "domain lock /run/briqyard/cgroup-domain.lock changed": (
        "domain_lock", "crates/briqyardd/src/fc/recovery/native.rs:125"),
    "service cgroup namespace changed": (
        "service_namespace", "crates/briqyardd/src/fc/recovery/native.rs:128"),
    "verifying the configured jailer": (
        "jailer_provenance", "crates/briqyardd/src/fc/recovery/native.rs:131"),
    "daemon service still contains a possible launcher": (
        "service_membership", "crates/briqyardd/src/fc/recovery/native.rs:275"),
    "native recovery barrier unresolved: managed spawning stays closed": (
        "native_recovery_barrier", "crates/briqyardd/src/machine/startup.rs:328"),
    "startup recovery unresolved: managed spawning stays closed": (
        "startup_recovery", "crates/briqyardd/src/machine/startup.rs:328"),
}
ERRNOS = {1: "EPERM", 2: "ENOENT", 5: "EIO", 11: "EAGAIN", 13: "EACCES",
          16: "EBUSY", 22: "EINVAL", 28: "ENOSPC", 110: "ETIMEDOUT"}


def classify(data, truncated=False):
    bounded = data[:MAX_BYTES]
    truncated = truncated or len(data) > MAX_BYTES
    if truncated and not bounded.endswith(b"\n"):
        bounded = bounded.rsplit(b"\n", 1)[0] if b"\n" in bounded else b""
    lines = bounded.splitlines()
    truncated = truncated or len(lines) > MAX_LINES
    counts = collections.Counter()
    errnos = collections.Counter()
    unknown = 0
    for line in lines[:MAX_LINES]:
        try:
            # journal JSON wraps the daemon's tracing JSON in MESSAGE.
            event = json.loads(json.loads(line)["MESSAGE"])
            fields = event["fields"]
            message = fields.get("message", "")
            error = fields.get("err", "")
            if not isinstance(message, str) or not isinstance(error, str):
                raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError):
            unknown += 1
            continue
        matched = False
        for phrase, (category, source) in PREDICATES.items():
            if phrase == message or phrase in error:
                counts[(category, source)] += 1
                matched = True
        if not matched:
            unknown += 1
        for number in re.findall(r"\(os error ([0-9]{1,3})\)", error):
            errnos[ERRNOS.get(int(number), "unknown")] += 1
    return {"predicates": [{"category": category, "source": source, "count": count}
                           for (category, source), count in sorted(counts.items())],
            "errno_counts": dict(sorted(errnos.items())), "unknown": unknown,
            "truncated": truncated}


def journal(since):
    """Bound memory, journal entries and elapsed retrieval time; never persist raw text."""
    data = bytearray()
    truncated = False
    try:
        with subprocess.Popen(
                ["sudo", "-n", "journalctl", "-u", "briqyardd", "--no-pager",
                 "--since", "@" + str(since), "-n", str(MAX_LINES + 1),
                 "-o", "json", "--output-fields=MESSAGE"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            deadline = time.monotonic() + 5
            while len(data) <= MAX_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
                    truncated = True
                    break
                chunk = os.read(proc.stdout.fileno(), min(8192, MAX_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            else:
                truncated = True
            try:
                code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                proc.kill()
                code = proc.wait()
                truncated = True
            truncated = truncated or code != 0
    except OSError:
        truncated = True
    return classify(bytes(data), truncated)


def request(path, timeout):
    req = urllib.request.Request(os.environ.get("BRIQYARD_URL", "http://127.0.0.1:7420") + path)
    if os.environ.get("BRIQYARD_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["BRIQYARD_TOKEN"])
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if path == "/v1/status":
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                return None
            return json.loads(data)
        return True


def wait_ready(seconds, diagnose, probe=request, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    while clock() < deadline:
        try:
            status = probe("/v1/status", min(2, deadline - clock()))
            if (isinstance(status, dict) and status.get("observation") is not None
                    and clock() < deadline
                    and probe("/v1/machines", min(2, deadline - clock()))
                    and clock() <= deadline):
                return True
        except (OSError, ValueError, urllib.error.URLError):
            pass
        remaining = deadline - clock()
        if remaining > 0:
            sleep(min(1, remaining))
    diagnose()
    return False


def main():
    logs, since = sys.argv[1:]
    # One invocation per readiness failure. The shell stops dependent work before cleanup.
    def diagnose():
        summary = journal(int(since))
        Path(logs, "recovery-readiness.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
    return 0 if wait_ready(90, diagnose) else 1


if __name__ == "__main__":
    sys.exit(main())
