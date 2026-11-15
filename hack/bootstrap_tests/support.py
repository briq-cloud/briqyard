"""Exercise the actual standalone install section in a temporary host filesystem."""
import hashlib
from pathlib import Path
import sys


HACK = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(HACK / "firecracker"))
from test_package import fixture

SCRIPT = (HACK / "bootstrap-host.sh").read_text()
HELPERS = SCRIPT.split("# Runtime installation helpers.", 1)[1].split("# End runtime installation helpers.", 1)[0]
HELPERS = HELPERS[HELPERS.index("checked_bundle()") :]
# Defined beside the peers operation, which takes it too.
INSTALL_LOCK = "runtime_install_lock() {" + SCRIPT.split("\nruntime_install_lock() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
HELPERS = INSTALL_LOCK + HELPERS
DROPPED = "refuse_dropped_nested() {" + SCRIPT.split("refuse_dropped_nested() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
INSTALL = SCRIPT.split('echo "== binaries', 1)[1].split('echo "== api certificate"', 1)[0]
INSTALL = 'echo "== binaries' + INSTALL


CAPABILITIES = {
    "assignment-capabilities": "destination-assignment-v1",
    "assigned-run-capabilities": "assigned-run-v1",
    "assigned-run-lifecycle-capabilities": "assigned-run-lifecycle-v1",
    "assigned-update-capabilities": "assigned-update-v3",
    "scoped-execution-capabilities": "scoped-execution-v2",
}
FULL_DAEMON = "#!/bin/sh\ncase $1 in\n" + "".join(
    command + ") printf '" + answer + "\\n';;\n" for command, answer in CAPABILITIES.items()
) + "*) exit 2;;\nesac\n"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
