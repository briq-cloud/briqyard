"""Run the actual memory-policy preflight with a bounded fake systemctl."""
import os
from pathlib import Path
import subprocess
import unittest


SCRIPT = (Path(__file__).parent / "bootstrap-host.sh").read_text()
START = "# Memory ancestor policy preflight."
END = "# End memory ancestor policy preflight."
CHECK = SCRIPT.split(START, 1)[1].split(END, 1)[0]


class BootstrapMemoryPolicy(unittest.TestCase):
    def check(self, **overrides):
        # No inherited credentials or real host commands. Only Bash builtins run.
        env = dict(PATH=os.defpath, SWAP_POLICY="auto\n\nauto\n", SWAP_STATUS="0",
                   PRESSURE_POLICY="auto\n\nauto\n", PRESSURE_STATUS="0")
        env.update(overrides)
        prelude = '''set -euo pipefail
fail() { printf '%s\n' "$*" >&2; exit 1; }
systemctl() {
  case "$*" in
    'show --value --property=ManagedOOMSwap -- -.slice system.slice')
      printf '%s' "$SWAP_POLICY"; return "$SWAP_STATUS" ;;
    'show --value --property=ManagedOOMMemoryPressure -- -.slice system.slice')
      printf '%s' "$PRESSURE_POLICY"; return "$PRESSURE_STATUS" ;;
    *) exit 99 ;;
  esac
}
'''
        return subprocess.run(["bash", "-c", prelude + CHECK + '\nprintf maintenance-reached\n'],
                              env=env, capture_output=True, text=True, timeout=5)

    def test_both_ancestors_require_positive_safe_values(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "maintenance-reached")

    def test_missing_unsafe_unknown_or_failed_observation_stops(self):
        for prop in ("SWAP", "PRESSURE"):
            for value, status in (("", "0"), ("auto\n", "0"),
                                  ("auto\nauto\nauto\n", "0"), ("kill\nauto\n", "0"),
                                  ("unknown-policy\nauto\n", "0"),
                                  ("auto\nauto\n", "1"), ("auto\nauto\n", "2")):
                with self.subTest(prop=prop, value=value, status=status):
                    result = self.check(**{prop + "_POLICY": value, prop + "_STATUS": status})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("maintenance-reached", result.stdout)
                    self.assertNotIn("unknown-policy", result.stderr)

    def test_preflight_precedes_package_and_host_policy_changes(self):
        start = SCRIPT.index(START)
        for mutation in ('echo "== packages"', 'echo "== zfs cache"', 'echo "== no swap"'):
            self.assertLess(start, SCRIPT.index(mutation))


if __name__ == "__main__":
    unittest.main()
