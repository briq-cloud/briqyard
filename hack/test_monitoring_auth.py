#!/usr/bin/env python3
"""Regression for credential-safe curl authentication in monitoring checks."""

from __future__ import annotations

import base64
import http.server
import os
import shlex
import shutil
import subprocess
import sys
import threading
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
        self.assertIn('curl_plain -fsS', source)
        self.assertNotIn('curl ', source)
        self.assertNotIn("dirname", source.split("monitoring_auth_init", 1)[0])
        self.assertNotIn('auth=(', source)
        self.assertNotIn('api_auth=(', source)
        self.assertNotIn('gauth=(', source)
        self.assertNotIn('Authorization: Bearer $', source)

    def test_real_curl_sends_auth_without_argv_environment_or_curlrc_leaks(self) -> None:
        real_curl = shutil.which("curl")
        real_mktemp = shutil.which("mktemp")
        real_chmod = shutil.which("chmod")
        self.assertIsNotNone(real_curl)
        self.assertIsNotNone(real_mktemp)
        self.assertIsNotNone(real_chmod)

        class Receiver(http.server.BaseHTTPRequestHandler):
            seen: list[tuple[str, str | None]] = []

            def do_GET(self) -> None:
                self.seen.append((self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        self.addCleanup(self._stop_server, server, server_thread)
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            bindir = temp / "bin"
            bindir.mkdir()
            audit = temp / "child-audit"
            password_file = temp / "grafana-password"
            secrets = {
                "metrics": 'metrics-"quote\\tail',
                "api": 'api-"quote\\tail',
                "grafana": 'grafana-"quote\\tail:more',
                "fallback": 'fallback-"quote\\tail',
            }
            password_file.write_text(secrets["grafana"] + "\n", encoding="utf-8")
            password_file.chmod(0o600)
            needles = tuple(secrets.values())
            encoded_needles = repr(needles)
            real_python = sys.executable
            base_url = f"http://127.0.0.1:{server.server_port}"
            (temp / ".curlrc").write_text("verbose\n", encoding="utf-8")

            audit_wrapper = (
                f"#!{real_python}\n"
                "import os, sys\n"
                f"needles = {encoded_needles}\n"
                "name = os.path.basename(sys.argv[0])\n"
                "args = sys.argv[1:]\n"
                "clean = not any(any(needle in arg for needle in needles) for arg in args)\n"
                "clean = clean and 'BRIQYARD_TOKEN' not in os.environ and 'BRIQYARD_METRICS_TOKEN' not in os.environ\n"
                "if name == 'curl': clean = clean and bool(args) and args[0] == '--disable'\n"
                "if name == 'curl' and '--config' in args:\n"
                "  import pathlib, stat\n"
                "  config = pathlib.Path(args[args.index('--config') + 1])\n"
                "  clean = clean and stat.S_IMODE(config.stat().st_mode) == 0o600 and stat.S_IMODE(config.parent.stat().st_mode) == 0o700\n"
                "with open(os.environ['CHILD_AUDIT'], 'a', encoding='utf-8') as f: f.write(name + ':' + ('clean' if clean else 'leak') + '\\n')\n"
                "if not clean: raise SystemExit(7)\n"
                "target = os.environ.get('REAL_CURL') if name == 'curl' else os.environ.get('REAL_' + name.upper())\n"
                "if not target: raise SystemExit(8)\n"
                "os.execv(target, [target, *args])\n"
            )
            for name, target in (("python3", real_python), ("mktemp", real_mktemp), ("chmod", real_chmod), ("curl", real_curl)):
                wrapper = bindir / name
                wrapper.write_text(audit_wrapper, encoding="utf-8")
                wrapper.chmod(0o700)

            script = f"""set -x
source {shlex.quote(str(AUTH))}
monitoring_auth_init
curl_metrics -fsS {base_url}/metrics
curl_api -fsS {base_url}/api
curl_grafana -fsS {base_url}/grafana
curl_plain -fsS {base_url}/plain
"""
            env = os.environ.copy()
            env.update(
                {
                    "PATH": str(bindir) + os.pathsep + env.get("PATH", ""),
                    "TMPDIR": tmp,
                    "HOME": tmp,
                    "CURL_HOME": tmp,
                    "BRIQYARD_METRICS_TOKEN": secrets["metrics"],
                    "BRIQYARD_TOKEN": secrets["api"],
                    "GRAFANA_PASSWORD_FILE": str(password_file),
                    "CHILD_AUDIT": str(audit),
                    "REAL_CURL": real_curl,
                    "REAL_PYTHON3": real_python,
                    "REAL_MKTEMP": real_mktemp,
                    "REAL_CHMOD": real_chmod,
                    "BASE_URL": base_url,
                }
            )
            result = subprocess.run(["bash", "-x", "-c", script], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            for secret in secrets.values():
                self.assertNotIn(secret, result.stdout)
                self.assertNotIn(secret, result.stderr)
            self.assertNotIn("Authorization:", result.stderr)
            self.assertTrue(audit.read_text(encoding="utf-8").splitlines())
            self.assertTrue(all(line.endswith(":clean") for line in audit.read_text(encoding="utf-8").splitlines()))
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

            expected = {
                "/metrics": "Bearer " + secrets["metrics"],
                "/api": "Bearer " + secrets["api"],
                "/grafana": "Basic " + base64.b64encode(("admin:" + secrets["grafana"]).encode()).decode(),
                "/plain": None,
            }
            self.assertEqual(dict(server.RequestHandlerClass.seen), expected)

            fallback_script = f"""source {shlex.quote(str(AUTH))}
monitoring_auth_init
curl_metrics -fsS {base_url}/fallback-metrics
curl_api -fsS {base_url}/fallback-api
"""
            fallback_env = env.copy()
            fallback_env.pop("BRIQYARD_METRICS_TOKEN")
            fallback_env["BRIQYARD_TOKEN"] = secrets["fallback"]
            fallback_env.pop("GRAFANA_PASSWORD_FILE")
            fallback = subprocess.run(["bash", "-c", fallback_script], env=fallback_env, capture_output=True, text=True, timeout=15)
            self.assertEqual(fallback.returncode, 0, fallback.stderr)
            self.assertNotIn(secrets["fallback"], fallback.stdout + fallback.stderr)
            expected.update(
                {
                    "/fallback-metrics": "Bearer " + secrets["fallback"],
                    "/fallback-api": "Bearer " + secrets["fallback"],
                }
            )
            self.assertEqual(dict(server.RequestHandlerClass.seen), expected)
            self.assertNotIn("Authorization:", fallback.stderr)
            self.assertTrue(all(line.endswith(":clean") for line in audit.read_text(encoding="utf-8").splitlines()))
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

    def test_malformed_bearer_is_rejected_without_logging_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            script = f"source {shlex.quote(str(AUTH))}; monitoring_auth_init"
            env = os.environ.copy()
            env.update(
                {
                    "TMPDIR": tmp,
                    "BRIQYARD_METRICS_TOKEN": "bad\nheader-secret",
                    "BRIQYARD_TOKEN": "",
                }
            )
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("header-secret", result.stdout + result.stderr)
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

    def test_malformed_grafana_password_is_rejected_independently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            password_file = temp / "grafana-password"
            password_file.write_text("first-line\nsecond-line\n", encoding="utf-8")
            password_file.chmod(0o600)
            script = f"source {shlex.quote(str(AUTH))}; monitoring_auth_init"
            env = os.environ.copy()
            env.update({"TMPDIR": tmp, "GRAFANA_PASSWORD_FILE": str(password_file)})
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("first-line", result.stdout + result.stderr)
            self.assertNotIn("second-line", result.stdout + result.stderr)
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

    def _stop_server(self, server: http.server.ThreadingHTTPServer, thread: threading.Thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "loopback HTTP server did not stop")


if __name__ == "__main__":
    unittest.main()
