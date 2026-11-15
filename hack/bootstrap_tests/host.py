import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import unittest

import yaml

from .support import DROPPED, HACK, HELPERS, SCRIPT


POOL_KEY = "pool_key() {" + SCRIPT.split("\npool_key() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"


class DroppedNestedClass(unittest.TestCase):
    """A run that does not name the class must not turn it off (ADR 0088)."""

    def check(self, config, nested):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.yaml"
            if config is not None:
                path.write_text(yaml.safe_dump(config))
            return subprocess.run(["bash", "-c", DROPPED + 'refuse_dropped_nested "$1"; echo ok', "x", str(path)],
                                  env=dict(os.environ, NESTED=nested), text=True, capture_output=True)

    def test_a_configuration_that_serves_nested_refuses_a_run_without_the_variable(self):
        served = {"token": "t", "runtime_classes": {"nested": {"kernel": "/k", "modules": "/m", "nested": True}}}
        result = self.check(served, "0")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("BRIQYARD_RUNTIME_CLASSES=nested", result.stdout)
        self.assertNotIn("ok", result.stdout.splitlines())

    def test_the_variable_a_plain_config_or_no_config_pass(self):
        served = {"runtime_classes": {"nested": {"kernel": "/k", "modules": "/m", "nested": True}}}
        for config, nested in ((served, "1"), ({"token": "t"}, "0"), (None, "0"),
                               ({"runtime_classes": {"other": {"kernel": "/k", "modules": "/m"}}}, "0")):
            result = self.check(config, nested)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ok", result.stdout.splitlines())


class UnknownClass(unittest.TestCase):
    """A class the release does not build is refused first, before the script touches the host."""

    def test_an_unknown_class_name_refuses_before_anything_runs(self):
        for classes in ("bogus", "nested,bogus"):
            result = subprocess.run(["bash", str(HACK / "bootstrap-host.sh")],
                                    env=dict(os.environ, BRIQYARD_RUNTIME_CLASSES=classes),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("bogus is not a class the release builds", result.stdout)
            self.assertNotIn("==", result.stdout)


class InstallerLock(unittest.TestCase):
    def test_installers_serialize_through_handover_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            private = root / "private"
            staging = root / "staging"
            staging.mkdir()
            first_script = HELPERS + r'''
runtime_install_lock "$1"
new="$2"; candidate=""; rollback=""; activation_pending=0; rollback_ready=0
trap 'set +e; printf "cleanup\n"; read -r gate; false; cleanup_runtime_install' EXIT
printf 'preflight\n'
read -r gate
false
'''
            second_script = HELPERS + r'''
runtime_install_lock "$1"
[ ! -e "$2" ] || exit 3
printf 'second-installed\n'
'''
            first = subprocess.Popen(["bash", "-c", first_script, "first", str(private), str(staging)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            second = None
            try:
                self.assertEqual(first.stdout.readline(), "preflight\n")
                second = subprocess.Popen(["bash", "-c", second_script, "second", str(private), str(staging)],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(select.select([second.stdout], [], [], .15)[0], [])
                first.stdin.write("handover done\n"); first.stdin.flush()
                self.assertEqual(first.stdout.readline(), "cleanup\n")
                self.assertEqual(select.select([second.stdout], [], [], .15)[0], [])
                first.stdin.write("cleanup allowed\n"); first.stdin.flush()
                _, error = first.communicate(timeout=10)
                self.assertEqual(first.returncode, 1, error)
                output, error = second.communicate(timeout=10)
                self.assertEqual(second.returncode, 0, error)
                self.assertEqual(output, "second-installed\n")
                self.assertEqual(private.stat().st_mode & 0o777, 0o700)
                self.assertEqual((private / "runtime-install.lock").stat().st_mode & 0o777, 0o600)
            finally:
                for child in (first, second):
                    if child and child.poll() is None:
                        child.kill()
                        child.communicate(timeout=10)

    def test_symlink_lock_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            target = root / "target"
            target.write_text("unchanged")
            (root / "runtime-install.lock").symlink_to(target)
            result = subprocess.run(["bash", "-c", HELPERS + '\nruntime_install_lock "$1"', "lock", str(root)],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_text(), "unchanged")


class PoolKeyRetry(unittest.TestCase):
    def run_key(self, outcomes):
        """pool_key against a curl which answers one outcome per call: a curl exit status, or an HTTP status."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "script").write_text("\n".join(outcomes) + "\n")
            (tmp / "curl").write_text(
                '#!/bin/bash\ncat >/dev/null\necho x >> "$DIR/calls"\necho "$*" > "$DIR/args"\n'
                'n=$(wc -l < "$DIR/calls"); o=$(sed -n "${n}p" "$DIR/script")\n'
                'case "$o" in\n'
                '  e*) exit "${o#e}" ;;\n'
                '  t*) printf \'{"error":"no"}\\n%s\' "${o#t}"; exit 28 ;;\n'
                '  2*) printf \'{"key":"k"}\\n%s\' "$o" ;;\n'
                '  *) printf \'{"error":"no"}\\n%s\' "$o" ;;\n'
                'esac\n'
            )
            (tmp / "sleep").write_text("#!/bin/bash\n")
            for name in ("curl", "sleep"):
                (tmp / name).chmod(0o755)
            code = POOL_KEY + "\npool_key\n"
            env = {"PATH": f"{tmp}:{os.environ['PATH']}", "DIR": str(tmp), "FLEET_URL": "http://f", "BRIQYARD_TOKEN": "t",
                   "API_TOKEN": "t", "advertise": "https://x"}
            result = subprocess.run(["bash", "-c", code], env=env, capture_output=True, text=True)
            calls = (tmp / "calls").read_text().count("x") if (tmp / "calls").exists() else 0
            self.args = (tmp / "args").read_text() if (tmp / "args").exists() else ""
            return result, calls

    def test_two_timeouts_then_the_key(self):
        result, calls = self.run_key(["e28", "e28", "200"])
        self.assertEqual(result.stdout, "k\n", result.stderr)
        self.assertEqual(calls, 3)

    def test_three_timeouts_fail(self):
        result, calls = self.run_key(["e28", "e28", "e28"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attempt 3 of 3", result.stderr)
        self.assertEqual(calls, 3)

    def test_a_refused_connection_and_a_5xx_are_retried(self):
        result, calls = self.run_key(["e7", "503", "200"])
        self.assertEqual(result.stdout, "k\n", result.stderr)
        self.assertEqual(calls, 3)

    def test_a_4xx_fails_at_once(self):
        for status in ("400", "401", "403", "404", "409"):
            result, calls = self.run_key([status, "200"])
            self.assertNotEqual(result.returncode, 0, status)
            self.assertEqual(result.stdout, "", status)
            self.assertIn(f"HTTP {status}, not retried", result.stderr)
            self.assertEqual(calls, 1, status)

    def test_a_4xx_then_a_body_timeout_is_still_final(self):
        # HTTP 403 seen, then curl gave up on the body: status 403 and exit 28.
        for status in ("t400", "t403", "t404"):
            result, calls = self.run_key([status, "200"])
            self.assertNotEqual(result.returncode, 0, status)
            self.assertIn(f"HTTP {status[1:]}, not retried", result.stderr)
            self.assertEqual(calls, 1, status)

    def test_a_5xx_then_a_body_timeout_is_retried(self):
        result, calls = self.run_key(["t503", "200"])
        self.assertEqual(result.stdout, "k\n", result.stderr)
        self.assertEqual(calls, 2)

    def test_the_limit_outlasts_the_fleets_longest_wait(self):
        # key turn 30 s + publication turn 30 s + the write 30 s (hosts.rs, backup.rs).
        result, _ = self.run_key(["200"])
        limit = int(re.search(r"--max-time (\d+)", self.args).group(1))
        self.assertGreaterEqual(limit, 30 + 30 + 30 + 10)
        self.assertLessEqual(3 * limit, 600)  # three tries stay far under the 1800 s of the SSH session

    def test_a_curl_failure_which_is_not_the_network_fails_at_once(self):
        result, calls = self.run_key(["e60", "200"])  # certificate
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, 1)
