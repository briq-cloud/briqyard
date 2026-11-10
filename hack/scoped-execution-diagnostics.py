#!/usr/bin/env python3
"""Emit only closed installation refusal categories from bounded JSON logs."""
import json
import sys

MAX_BYTES = 64 * 1024
MAX_LINES = 128
STAGES = frozenset((
    "authority_verification", "authority_installation", "host_verification",
    "authority_dependencies", "authority_signed_binding",
    "OwnershipRead", "OwnershipMissing", "RegistrationRead", "RegistrationMissing",
    "Generation", "OwnershipLive", "RegisteredKeys", "Verification", "ProtectionRead",
    "ProtectionMissing", "ProtectionBinding", "JournalInstall", "PolicyInstall",
))
CATEGORIES = frozenset((
    "Encoding", "Signature", "Claims", "Time", "Binding", "HostMismatch", "ClockUnavailable",
    "Journal(Persistence)", "Journal(Ownership)", "Journal(Binding)",
    "Journal(Exhausted)", "Journal(AlreadyAdmitted)", "Journal(Full)",
    "Transport(Configuration)", "Transport(Request)", "Transport(Unconfirmed)",
))

# The native fixture's stderr is private. Export only these source-owned failure
# labels before cleanup; neither error text nor arbitrary JSON fields are output.
FIXTURE_FAILURES = {
    "renewable full guest timeout did not complete": "guest_timeout_result",
    "guest/envelope time bounds differ": "guest_time_bounds",
    "execution did not cross original quota window": "quota_window",
    "source refusal completed a quiet command": "source_refusal_result",
    "quiet I/O did not wake at initial lease expiry": "initial_lease_wakeup",
    "duplicate command was dispatched again": "duplicate_dispatch",
    "operation evidence lost beyond permit expiry": "operation_status",
    "native driver deadline; do not replay": "driver_deadline",
    "native driver failed": "driver_failed",
    "no live initial lease observed": "initial_lease_missing",
    "source refusal returned before earliest qualified lease expiry": "source_refusal_time",
    "no successful durable revoke ACK": "revoke_ack_missing",
    "quiet command did not terminate promptly after revoke ACK": "revoke_wakeup",
    "revocation termination was not distinct from initial lease expiry": "revoke_time",
    "continuation callback was not exercised": "callback_missing",
}
CALLBACK_FAILURES = frozenset((
    "active", "clock", "protect", "continue", "revoke", "not_active", "evidence",
    "sequence", "source_refused", "no_extension", "timer_ack", "duplicate_ack", "unknown",
))
for action in ("identity", "authorization_clock", "register", "discover", "ownership", "protect", "delegation",
               "projection", "projection_lookup", "exec", "observe", "status", "active",
               "continue", "policy", "revoke", "invalidate"):
    for code, phrase in ((400, "Bad Request"), (401, "Unauthorized"), (403, "Forbidden"),
                         (404, "Not Found"), (409, "Conflict"), (422, "Unprocessable Entity"),
                         (500, "Internal Server Error"), (503, "Service Unavailable")):
        FIXTURE_FAILURES[f"authority {action} returned {code} {phrase}"] = (
            f"authority_{action}_http_{code}")


def classify(data):
    """Ignore partial, unknown and nonmatching events; never return arbitrary text."""
    output = []
    # An overlong source might end in a partial event. Never parse that last line.
    bounded = data[:MAX_BYTES]
    if len(data) > MAX_BYTES and not bounded.endswith(b"\n"):
        bounded = bounded.rsplit(b"\n", 1)[0] if b"\n" in bounded else b""
    for line in bounded.splitlines()[:MAX_LINES]:
        if line.startswith(b"scoped native callback failure: "):
            category = line.removeprefix(b"scoped native callback failure: ").decode(
                "ascii", errors="replace")
            if category in CALLBACK_FAILURES:
                output.append("scoped native failure: callback_" + category)
            continue
        if line.startswith(b"Error: "):
            category = FIXTURE_FAILURES.get(line[7:].decode("utf-8", errors="replace"))
            if category:
                output.append("scoped native failure: " + category)
            continue
        try:
            event = json.loads(line)
            fields = event.get("fields", {})
            stage = fields.get("stage")
            category = fields.get("category")
            if (fields.get("diagnostic") != "execution_installation"
                    or fields.get("message") != "execution installation refused"
                    or not isinstance(stage, str) or stage not in STAGES
                    or (category is not None and
                        (not isinstance(category, str) or category not in CATEGORIES))):
                continue
            output.append("scoped installation refusal: " + stage
                          + (" " + category if category is not None else ""))
        except (ValueError, AttributeError, TypeError):
            continue
    return output


if __name__ == "__main__":
    for result in classify(sys.stdin.buffer.read(MAX_BYTES + 1)):
        print(result)
