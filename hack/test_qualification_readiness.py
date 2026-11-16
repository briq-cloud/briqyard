#!/usr/bin/env python3
"""Readiness never confuses diagnostic status with recovered protected routes."""
import importlib.util
import json
from pathlib import Path
import unittest
import urllib.error

spec = importlib.util.spec_from_file_location(
    "readiness", Path(__file__).with_name("qualification-readiness.py"))
ready = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ready)


class ReadinessTests(unittest.TestCase):
    def run_gate(self, probe, seconds=3):
        now = [0]
        diagnostics = []
        def sleep(seconds):
            now[0] += seconds
        result = ready.wait_ready(seconds, lambda: diagnostics.append(True), probe,
                                  lambda: now[0], sleep)
        return result, diagnostics, now[0]

    def test_faulted_status_never_passes_or_calls_protected_route(self):
        paths = []
        def probe(path, timeout):
            paths.append(path)
            return {"observation": None, "conditions": [{"status": True}]}
        self.assertEqual(self.run_gate(probe), (False, [True], 3))
        self.assertEqual(paths, ["/v1/status"] * 3)

    def test_recovered_later_passes_despite_unrelated_condition(self):
        statuses = iter([None, {"incarnation": "current"}])
        def probe(path, timeout):
            return ({"observation": next(statuses), "conditions": [{"status": True}]}
                    if path == "/v1/status" else True)
        self.assertEqual(self.run_gate(probe), (True, [], 1))

    def test_protected_refusal_deadline_and_diagnostics_exactly_once(self):
        def probe(path, timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 2)
            if path == "/v1/status":
                return {"observation": {"incarnation": "current"}}
            raise urllib.error.URLError("secret")
        self.assertEqual(self.run_gate(probe), (False, [True], 3))

    def test_missing_or_malformed_status_is_not_ready(self):
        for status in ({}, [], None):
            self.assertEqual(self.run_gate(lambda *_: status), (False, [True], 3))

    def test_only_closed_diagnostic_fields_escape(self):
        def event(message, error=""):
            return (json.dumps({"MESSAGE": json.dumps({"fields": {
                "message": message, "err": error, "secret": "token-private"}})}) + "\n").encode()
        data = event("secret-token") + event(
            "startup recovery unresolved: managed spawning stays closed",
            "private-config: daemon service still contains a possible launcher: (os error 13)")
        result = ready.classify(data)
        self.assertEqual(result["unknown"], 1)
        self.assertEqual(result["errno_counts"], {"EACCES": 1})
        self.assertEqual([p["category"] for p in result["predicates"]],
                         ["service_membership", "startup_recovery"])
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(ready.classify(b'[]\nnull\n{"MESSAGE": 4}\n')["unknown"], 3)

    def test_bounds_are_explicit(self):
        self.assertTrue(ready.classify(b"x" * (ready.MAX_BYTES + 1))["truncated"])
        self.assertTrue(ready.classify(b"{}\n" * (ready.MAX_LINES + 1))["truncated"])
        self.assertTrue(ready.classify(b"", True)["truncated"])

    def test_shell_records_boundary_before_crashes_and_stops_before_dependencies(self):
        shell = Path(__file__).with_name("qualify.sh").read_text()
        self.assertIn('RECOVERY_SINCE=$(date +%s)\n  sudo kill -9 "$pid"', shell)
        self.assertIn('RECOVERY_SINCE=$(date +%s)\nsudo kill -9 "${CUT[@]}"', shell)
        self.assertIn('bad "daemon recovery readiness: observation and protected machine list"\n    exit 1', shell)


if __name__ == "__main__":
    unittest.main()
