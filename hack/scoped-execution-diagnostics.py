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


def classify(data):
    """Ignore partial, unknown and nonmatching events; never return arbitrary text."""
    output = []
    # An overlong source might end in a partial event. Never parse that last line.
    bounded = data[:MAX_BYTES]
    if len(data) > MAX_BYTES and not bounded.endswith(b"\n"):
        bounded = bounded.rsplit(b"\n", 1)[0] if b"\n" in bounded else b""
    for line in bounded.splitlines()[:MAX_LINES]:
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
