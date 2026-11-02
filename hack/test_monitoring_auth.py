#!/usr/bin/env python3
"""Regression for credential-safe curl authentication in monitoring checks."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "hack" / "monitoring-auth.sh"
CHECK = ROOT / "hack" / "monitoring-check.sh"


class MonitoringAuthTests(unittest.TestCase):
    def test_monitoring_check_routes_each_auth_class_through_private_config(self) -> None:
        source = CHECK.read_text(encoding="utf-8")
        self.assertIn('get() { curl_metrics ', source)
        self.assertIn('api_get() { curl_api ', source)
        self.assertIn('curl_grafana -fsS', source)
        self.assertNotIn('auth=(', source)
        self.assertNotIn('api_auth=(', source)
        self.assertNotIn('gauth=(', source)
        self.assertNotIn('Authorization: Bearer $', source)

    def test_credentials_stay_out_of_argv_and_traces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            bindir = temp / "bin"
            bindir.mkdir()
            capture = temp / "capture.jsonl"
            argv_check = temp / "argv-check"
            password_file = temp / "grafana-password"
            secrets = {
                "metrics": 'metrics-"quote\\tail',
                "api": 'api-"quote\\tail',
                "grafana": 'grafana-"quote\\tail:more',
            }
            password_file.write_text(secrets["grafana"] + "\n", encoding="utf-8")
            password_file.chmod(0o600)
            needles = tuple(secrets.values())
            encoded_needles = repr(needles)
            real_python = sys.executable

            python_shim = bindir / "python3"
            python_shim.write_text(
                f"#!{real_python}\n"
                "import os, sys\n"
                f"needles = {encoded_needles}\n"
                "clean = all(not any(needle in arg for needle in needles) for arg in sys.argv)\n"
                "clean = clean and 'BRIQYARD_TOKEN' not in os.environ and 'BRIQYARD_METRICS_TOKEN' not in os.environ\n"
                "with open(os.environ['ARG_CHECK'], 'a', encoding='utf-8') as f: f.write(('clean' if clean else 'leak') + '\\n')\n"
                "if not clean: raise SystemExit(3)\n"
                "os.execv(os.environ['REAL_PYTHON'], [os.environ['REAL_PYTHON'], *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            python_shim.chmod(0o700)

            curl_shim = bindir / "curl"
            curl_shim.write_text(
                f"#!{real_python}\n"
                "import json, os, shlex, sys\n"
                "args = sys.argv[1:]\n"
                f"needles = {encoded_needles}\n"
                "if 'BRIQYARD_TOKEN' in os.environ or 'BRIQYARD_METRICS_TOKEN' in os.environ: raise SystemExit(5)\n"
                "if any(any(needle in arg for needle in needles) for arg in args): raise SystemExit(4)\n"
                "configs = []\n"
                "for i, arg in enumerate(args[:-1]):\n"
                "  if arg == '--config':\n"
                "    for line in open(args[i + 1], encoding='utf-8'):\n"
                "      key, value = line.split('=', 1)\n"
                "      configs.append((key.strip(), shlex.split(value.strip())[0]))\n"
                "with open(os.environ['AUTH_CAPTURE'], 'a', encoding='utf-8') as f: f.write(json.dumps({'url': args[-1], 'config': configs}) + '\\n')\n"
                "print('request sent')\n",
                encoding="utf-8",
            )
            curl_shim.chmod(0o700)

            script = f"""set -x
source {shlex.quote(str(AUTH))}
monitoring_auth_init
curl_metrics https://metrics.invalid/metrics
curl_api https://fleet.invalid/v1/hosts
curl_grafana https://grafana.invalid/api/health
curl https://public.invalid/health
"""
            env = os.environ.copy()
            env.update(
                {
                    "PATH": str(bindir) + os.pathsep + env.get("PATH", ""),
                    "TMPDIR": tmp,
                    "BRIQYARD_METRICS_TOKEN": secrets["metrics"],
                    "BRIQYARD_TOKEN": secrets["api"],
                    "GRAFANA_PASSWORD_FILE": str(password_file),
                    "AUTH_CAPTURE": str(capture),
                    "ARG_CHECK": str(argv_check),
                    "REAL_PYTHON": real_python,
                }
            )
            result = subprocess.run(["bash", "-x", "-c", script], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for secret in secrets.values():
                self.assertNotIn(secret, result.stdout)
                self.assertNotIn(secret, result.stderr)
            self.assertEqual(argv_check.read_text(encoding="utf-8").splitlines(), ["clean", "clean"])
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

            requests = [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(requests), 4)
            self.assertEqual(requests[0]["config"], [["header", "Authorization: Bearer " + secrets["metrics"]]])
            self.assertEqual(requests[1]["config"], [["header", "Authorization: Bearer " + secrets["api"]]])
            self.assertEqual(requests[2]["config"], [["user", "admin:" + secrets["grafana"]]])
            self.assertEqual(requests[3]["config"], [])

    def test_malformed_credentials_are_rejected_without_logging_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            bindir = temp / "bin"
            bindir.mkdir()
            capture = temp / "capture.jsonl"
            password_file = temp / "grafana-password"
            password_file.write_text("first-line\nsecond-line\n", encoding="utf-8")
            password_file.chmod(0o600)
            script = f"source {shlex.quote(str(AUTH))}; monitoring_auth_init"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": str(bindir) + os.pathsep + env.get("PATH", ""),
                    "TMPDIR": tmp,
                    "BRIQYARD_METRICS_TOKEN": "bad\nheader-secret",
                    "BRIQYARD_TOKEN": "",
                    "GRAFANA_PASSWORD_FILE": str(password_file),
                    "AUTH_CAPTURE": str(capture),
                    "ARG_CHECK": str(temp / "argv-check"),
                    "REAL_PYTHON": sys.executable,
                }
            )
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("header-secret", result.stdout + result.stderr)
            self.assertNotIn("second-line", result.stdout + result.stderr)
            self.assertFalse(capture.exists())
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))


if __name__ == "__main__":
    unittest.main()
