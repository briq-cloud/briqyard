#!/usr/bin/env python3
"""Run suite key comparisons against private fake files, never a host or key store."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class SuiteKeyTransportTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        bindir = root / "bin"
        bindir.mkdir()
        key = "b7" * 32  # Public fake fixture; never load a runtime key.
        key_file = root / "key"
        key_file.write_text(key + "\n")
        capture = root / "argv.jsonl"
        grep = bindir / "grep"
        grep.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "key = Path(os.environ['KEY_FILE']).read_text().strip()\n"
            "leak = any(key in arg for arg in sys.argv[1:])\n"
            "with open(os.environ['CAPTURE'], 'a') as stream:\n"
            "    stream.write(json.dumps({'key_in_argv': leak}) + '\\n')\n"
            "if leak: raise SystemExit(90)\n"
            "if os.environ.get('SCAN_ERROR') and '-f' in sys.argv[1:]: raise SystemExit(2)\n"
            "os.execv(os.environ['REAL_GREP'], [os.environ['REAL_GREP'], *sys.argv[1:]])\n"
        )
        grep.chmod(0o700)
        env = {
            "PATH": str(bindir) + os.pathsep + os.defpath,
            "HOME": str(root),
            "KEY_FILE": str(key_file),
            "CAPTURE": str(capture),
            "REAL_GREP": shutil.which("grep"),
        }
        return root, key, capture, env

    def assert_private(self, result, key, capture):
        self.assertFalse(key in result.stdout + result.stderr, "fake key entered output or tracing")
        records = [json.loads(line) for line in capture.read_text().splitlines()]
        self.assertTrue(records, "real source comparisons must execute")
        self.assertFalse(any(row["key_in_argv"] for row in records), "fake key entered grep argv")

    def test_two_host_comparisons_keep_patterns_private_and_detect_leaks(self):
        source = (ROOT / "hack/fleet-two-hosts.sh").read_text()
        body = re.search(r"seen=\$\(hosts \| as_second '(.*?)'\)\n", source, re.S).group(1)
        preamble = "\n".join(line for line in source.splitlines() if line.startswith("set "))
        for present, scan_error in ((False, False), (True, False), (False, True)):
            with self.subTest(present=present, scan_error=scan_error), tempfile.TemporaryDirectory() as directory:
                root, key, capture, env = self.fixture(directory)
                if scan_error:
                    env["SCAN_ERROR"] = "1"
                etc, var = root / "etc", root / "var"
                etc.mkdir()
                var.mkdir()
                (etc / "observed").write_text(key if present else "safe")
                journal = root / "journal"
                journal.write_text((key if present else "safe") + "\n")
                body_local = body.replace("/etc/briqyard", shlex.quote(str(etc))).replace(
                    "/var/lib/briqyard", shlex.quote(str(var))
                )
                script = preamble + "\n" + f"""
ask_key() {{ printf '{{}}'; }}
jq() {{ cat >/dev/null; cat "$KEY_FILE"; }}
journalctl() {{ cat {shlex.quote(str(journal))}; }}
adv=http://fixture.invalid
{body_local}
"""
                result = subprocess.run(
                    ["bash", "-x", "-c", script], env=env,
                    input=(key if present else "safe") + "\n", capture_output=True, text=True, timeout=10,
                )
                self.assert_private(result, key, capture)
                if scan_error:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout.split(), ["64", *(["1"] * 3 if present else ["0"] * 3)])

    def test_registry_comparison_keeps_pattern_private_and_refuses_plaintext(self):
        source = (ROOT / "hack/fleet-restore.sh").read_text()
        function = "sealed() {" + source.split("sealed() {", 1)[1].split("\ncheck ", 1)[0]
        preamble = "\n".join(line for line in source.splitlines() if line.startswith("set "))
        for payload in ("ciphertext", "key", '"token"', "read-error"):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root, key, capture, env = self.fixture(directory)
                if payload == "read-error":
                    env["SCAN_ERROR"] = "1"
                store = root / "fleet"
                store.mkdir()
                (store / "registry.json.age").write_text(
                    "age-encryption.org/v1\n" + (key if payload == "key" else payload) + "\n"
                )
                script = preamble + "\n" + f"""
key=$(cat "$KEY_FILE")
STORE={shlex.quote(str(root))}
FLEET_SH=env
{function}
sealed
"""
                result = subprocess.run(
                    ["bash", "-x", "-c", script], env=env,
                    capture_output=True, text=True, timeout=10,
                )
                self.assert_private(result, key, capture)
                self.assertEqual(result.returncode == 0, payload == "ciphertext")


if __name__ == "__main__":
    unittest.main()
