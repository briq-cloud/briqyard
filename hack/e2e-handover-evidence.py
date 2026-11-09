#!/usr/bin/env python3
"""Project bounded journal JSON into fixed sealed-restoration evidence categories."""
import json
import re
import sys

LIMIT_BYTES = 128 * 1024
LIMIT_ENTRIES = 128
REFUSALS = {
    "warm catalog maintenance refused: OutstandingWarmState": "maintenance_outstanding_warm_state",
    "warm catalog maintenance refused: StateUnknown": "maintenance_state_unknown",
    "warm catalog maintenance refused: RecoveryUnresolved": "maintenance_recovery_unresolved",
    "warm admission did not settle before handover deadline": "warm_admission_deadline",
    "namespace admission did not settle before handover deadline": "namespace_admission_deadline",
    "replacement cannot preserve destination assignments": "compatibility_capability",
    "assignment compatibility command failed": "compatibility_command",
    "assignment compatibility probe timed out": "compatibility_deadline",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def project(raw, pid, since):
    if len(raw) > LIMIT_BYTES or not re.fullmatch(r"[1-9][0-9]*", pid):
        return "unknown"
    if not re.fullmatch(r"[0-9]+\.[0-9]{6}", since):
        return "unknown"
    lower = int(since.replace(".", ""))
    lines = raw.splitlines()
    if not lines or len(lines) > LIMIT_ENTRIES:
        return "unknown"
    refused = set()
    accepted = set()
    for line in lines:
        entry = json.loads(line, object_pairs_hook=unique_object)
        # These underscore fields are journal-owned, unlike MESSAGE content.
        if any(entry.get(key) != value for key, value in {
            "_PID": pid, "_SYSTEMD_UNIT": "briqyardd.service", "_COMM": "briqyardd",
            "_EXE": "/usr/local/bin/briqyardd", "_TRANSPORT": "stdout",
        }.items()):
            return "unknown"
        stamp = entry.get("__REALTIME_TIMESTAMP", "")
        if not isinstance(stamp, str) or not stamp.isdecimal() or int(stamp) < lower:
            return "unknown"
        event = json.loads(entry["MESSAGE"], object_pairs_hook=unique_object)
        fields = event["fields"]
        message = fields.get("message")
        if message == "handover refused; daemon remains serving" and event.get("level") == "ERROR":
            refused.add("refused_" + REFUSALS.get(fields.get("err"), "unknown"))
        elif event.get("level") == "INFO" and message == "shutting down" and fields.get("hand_over") is True:
            accepted.add("accepted_shutdown")
        elif event.get("level") == "WARN" and message == "the shutdown ran past 60 s: ending without it" and fields.get("hand_over") is True:
            accepted.add("accepted_shutdown_timeout")
        elif event.get("level") == "INFO" and message == "handed over":
            accepted.add("accepted_complete")
    # Ambiguous evidence never chooses a favorable interpretation.
    if refused:
        return next(iter(refused)) if len(refused) == 1 and not accepted else "unknown"
    if "accepted_shutdown_timeout" in accepted and "accepted_complete" in accepted:
        return "unknown"
    for stage in ["accepted_complete", "accepted_shutdown_timeout", "accepted_shutdown"]:
        if stage in accepted:
            return stage
    return "unknown"


if __name__ == "__main__":
    try:
        result = project(sys.stdin.buffer.read(LIMIT_BYTES + 1), *sys.argv[1:])
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        result = "unknown"
    print(result)
