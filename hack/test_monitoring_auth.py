#!/usr/bin/env python3
"""Regression for credential-safe curl authentication in monitoring checks."""

from __future__ import annotations

import base64
import http.server
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "hack" / "monitoring-auth.sh"
CHECK = ROOT / "hack" / "monitoring-check.sh"


def _signal_process_group(process: subprocess.Popen[str], sig: int) -> None:
    if os.name != "posix":
        process.send_signal(sig)
        return
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def _process_group_exists(process: subprocess.Popen[str]) -> bool:
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for_process_group_exit(
    process: subprocess.Popen[str], timeout: float
) -> tuple[str | None, str | None, bool]:
    deadline = time.monotonic() + timeout
    stdout: str | None = None
    stderr: str | None = None
    while True:
        if not _process_group_exists(process):
            stdout, stderr = process.communicate()
            return stdout, stderr, True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return stdout, stderr, False
        if process.poll() is None:
            try:
                stdout, stderr = process.communicate(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired as exc:
                stdout, stderr = exc.output, exc.stderr
        else:
            time.sleep(min(0.05, remaining))


def _terminate_process_group(process: subprocess.Popen[str]) -> tuple[str | None, str | None]:
    _signal_process_group(process, signal.SIGTERM)
    stdout, stderr, exited = _wait_for_process_group_exit(process, 1)
    if exited:
        return stdout, stderr

    _signal_process_group(process, signal.SIGKILL)
    stdout, stderr, exited = _wait_for_process_group_exit(process, 5)
    if exited:
        return stdout, stderr

    process.kill()
    stdout, stderr, exited = _wait_for_process_group_exit(process, 5)
    if not exited:
        raise RuntimeError("timed-out test process group did not exit after kill")
    return stdout, stderr


def _run_bounded(args: list[str], *, env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = _terminate_process_group(process)
        raise subprocess.TimeoutExpired(args, timeout, output=stdout, stderr=stderr) from None
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


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
            grafana_auth_fixture = temp / "grafana-auth-fixture"
            # Fixed dummy values exercise curl-config quoting; they are not credentials.
            auth_fixtures = {
                "metrics": 'm-"quote\\tail',
                "api": 'a-"quote\\tail',
                "grafana": 'g-"quote\\tail:more',
                "fallback": 'f-"quote\\tail',
            }
            grafana_auth_fixture.write_text(auth_fixtures["grafana"] + "\n", encoding="utf-8")
            grafana_auth_fixture.chmod(0o600)
            needles = tuple(auth_fixtures.values())
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
                    "BRIQYARD_METRICS_TOKEN": auth_fixtures["metrics"],
                    "BRIQYARD_TOKEN": auth_fixtures["api"],
                    "GRAFANA_PASSWORD_FILE": str(grafana_auth_fixture),
                    "CHILD_AUDIT": str(audit),
                    "REAL_CURL": real_curl,
                    "REAL_PYTHON3": real_python,
                    "REAL_MKTEMP": real_mktemp,
                    "REAL_CHMOD": real_chmod,
                    "BASE_URL": base_url,
                }
            )
            result = _run_bounded(["bash", "-x", "-c", script], env=env, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            for fixture_value in auth_fixtures.values():
                self.assertNotIn(fixture_value, result.stdout)
                self.assertNotIn(fixture_value, result.stderr)
            self.assertNotIn("Authorization:", result.stderr)
            self.assertTrue(audit.read_text(encoding="utf-8").splitlines())
            self.assertTrue(all(line.endswith(":clean") for line in audit.read_text(encoding="utf-8").splitlines()))
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

            expected = {
                "/metrics": "Bearer " + auth_fixtures["metrics"],
                "/api": "Bearer " + auth_fixtures["api"],
                "/grafana": "Basic " + base64.b64encode(("admin:" + auth_fixtures["grafana"]).encode()).decode(),
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
            fallback_env["BRIQYARD_TOKEN"] = auth_fixtures["fallback"]
            fallback_env.pop("GRAFANA_PASSWORD_FILE")
            fallback = _run_bounded(["bash", "-c", fallback_script], env=fallback_env, timeout=15)
            self.assertEqual(fallback.returncode, 0, fallback.stderr)
            self.assertNotIn(auth_fixtures["fallback"], fallback.stdout + fallback.stderr)
            expected.update(
                {
                    "/fallback-metrics": "Bearer " + auth_fixtures["fallback"],
                    "/fallback-api": "Bearer " + auth_fixtures["fallback"],
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
            result = _run_bounded(["bash", "-c", script], env=env, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("header-secret", result.stdout + result.stderr)
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

    def test_malformed_grafana_password_is_rejected_independently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            grafana_auth_fixture = temp / "grafana-auth-fixture"
            grafana_auth_fixture.write_text("first-line\nsecond-line\n", encoding="utf-8")
            grafana_auth_fixture.chmod(0o600)
            script = f"source {shlex.quote(str(AUTH))}; monitoring_auth_init"
            env = os.environ.copy()
            env.update({"TMPDIR": tmp, "GRAFANA_PASSWORD_FILE": str(grafana_auth_fixture)})
            result = _run_bounded(["bash", "-c", script], env=env, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("first-line", result.stdout + result.stderr)
            self.assertNotIn("second-line", result.stdout + result.stderr)
            self.assertFalse(any(path.name.startswith("briqyard-monitoring-auth.") for path in temp.iterdir()))

    def _stop_server(self, server: http.server.ThreadingHTTPServer, thread: threading.Thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "loopback HTTP server did not stop")

    def test_auth_files_are_removed_on_termination_signals(self) -> None:
        for sig, expected_status in ((signal.SIGHUP, 129), (signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as tmp:
                env = os.environ.copy()
                env.update({"TMPDIR": tmp, "BRIQYARD_METRICS_TOKEN": "fixture-auth-value"})
                script = f"""source {shlex.quote(str(AUTH))}
monitoring_auth_init
while :; do read -r -t 0.05 _ || :; done
"""
                process = subprocess.Popen(
                    ["bash", "-c", script],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                self.addCleanup(self._cleanup_test_process, process)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    candidates = list(Path(tmp).glob("briqyard-monitoring-auth.*"))
                    if candidates and (candidates[0] / "metrics.curl").exists():
                        break
                    if process.poll() is not None:
                        self.fail("auth test process exited before creating its config")
                    time.sleep(0.02)
                else:
                    self.fail("auth test process did not create its config before the deadline")

                _signal_process_group(process, sig)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, expected_status, (stdout, stderr))
                self.assertFalse(list(Path(tmp).glob("briqyard-monitoring-auth.*")))

    def test_timeout_terminates_and_reaps_child_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "child-ready"
            terminated = Path(tmp) / "child-terminated"
            survived = Path(tmp) / "child-survived"
            child_code = "\n".join(
                (
                    "import pathlib, signal, sys, time",
                    "ready, terminated, survived = map(pathlib.Path, sys.argv[1:])",
                    "def on_term(_signal, _frame):",
                    "    terminated.write_text('terminated', encoding='utf-8')",
                    "    raise SystemExit(0)",
                    "signal.signal(signal.SIGTERM, on_term)",
                    "ready.write_text('ready', encoding='utf-8')",
                    "time.sleep(30)",
                    "survived.write_text('survived', encoding='utf-8')",
                )
            )
            parent_code = "\n".join(
                (
                    "import pathlib, subprocess, sys, time",
                    "ready, terminated, survived = map(pathlib.Path, sys.argv[1:4])",
                    "child = subprocess.Popen(",
                    "    [sys.executable, '-c', sys.argv[4], str(ready), str(terminated), str(survived)]",
                    ")",
                    "time.sleep(30)",
                )
            )
            args = [
                sys.executable,
                "-c",
                parent_code,
                str(ready),
                str(terminated),
                str(survived),
                child_code,
            ]
            self._timeout_after_child_ready(args, ready)
            self.assertEqual(terminated.read_text(encoding="utf-8"), "terminated")
            self.assertFalse(survived.exists())

    def test_timeout_kills_term_ignoring_descendant_with_redirected_streams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "child-ready"
            survived = Path(tmp) / "child-survived"
            child_code = "\n".join(
                (
                    "import pathlib, signal, sys, time",
                    "ready, survived = map(pathlib.Path, sys.argv[1:])",
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                    "ready.write_text('ready', encoding='utf-8')",
                    "time.sleep(30)",
                    "survived.write_text('survived', encoding='utf-8')",
                )
            )
            parent_code = "\n".join(
                (
                    "import pathlib, subprocess, sys, time",
                    "ready, survived = map(pathlib.Path, sys.argv[1:3])",
                    "child = subprocess.Popen(",
                    "    [sys.executable, '-c', sys.argv[3], str(ready), str(survived)],",
                    "    stdout=subprocess.DEVNULL,",
                    "    stderr=subprocess.DEVNULL,",
                    ")",
                    "time.sleep(30)",
                )
            )
            args = [sys.executable, "-c", parent_code, str(ready), str(survived), child_code]
            self._timeout_after_child_ready(args, ready)
            self.assertFalse(survived.exists())

    def _timeout_after_child_ready(self, args: list[str], ready: Path) -> None:
        real_popen = subprocess.Popen
        process = None

        def start_ready(*popen_args, **kwargs):
            nonlocal process
            process = real_popen(*popen_args, **kwargs)
            deadline = time.monotonic() + 5
            while not ready.exists():
                if process.poll() is not None:
                    self.fail("timeout fixture parent exited before child readiness")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.fail("timeout fixture child did not become ready before deadline")
                time.sleep(min(0.01, remaining))
            return process

        try:
            # Start the actual timeout only after the child's signal handler is installed.
            with mock.patch.object(subprocess, "Popen", side_effect=start_ready):
                with self.assertRaises(subprocess.TimeoutExpired):
                    _run_bounded(args, env=os.environ.copy(), timeout=0.2)
            self.assertFalse(_process_group_exists(process), "timeout left an owned process group alive")
        finally:
            if process is not None:
                self._cleanup_test_process(process)

    def _cleanup_test_process(self, process: subprocess.Popen[str]) -> None:
        if _process_group_exists(process):
            _terminate_process_group(process)
        else:
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
