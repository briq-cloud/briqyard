#!/usr/bin/env python3
"""The native diagnostic output has no channel for arbitrary log fields."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "diagnostics", Path(__file__).with_name("scoped-execution-diagnostics.py"))
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def event(stage="authority_verification", category="Binding", **extra):
    return (json.dumps({"target": "execution_installation", "fields": {
        "message": "execution installation refused", "diagnostic": "execution_installation", "stage": stage,
        "category": category, **extra}}) + "\n").encode()


class DiagnosticTests(unittest.TestCase):
    def test_native_fixture_failures_are_closed_and_exact(self):
        self.assertEqual(diag.classify(b"Error: renewable full guest timeout did not complete\n"),
                         ["scoped native failure: guest_timeout_result"])
        self.assertEqual(diag.classify(b"scoped native callback failure: protect\n"),
                         ["scoped native failure: callback_protect"])
        self.assertEqual(diag.classify(b"Error: authority exec returned 503 Service Unavailable\n"),
                         ["scoped native failure: authority_exec_http_503"])
        for line in [b"Error: private error", b"Error: native driver failed trailing",
                     b"scoped native callback failure: secret",
                     b"scoped native callback failure: protect trailing",
                     b"Error: authority exec returned 503 Service Unavailable secret"]:
            self.assertEqual(diag.classify(line + b"\n"), [])

    def test_fixed_categories_only(self):
        self.assertEqual(diag.classify(event(secret="never emit this")),
                         ["scoped installation refusal: authority_verification Binding"])
        for value in ["untrusted", {"secret": "value"}, [], 17]:
            self.assertEqual(diag.classify(event(stage=value)), [])
            self.assertEqual(diag.classify(event(category=value)), [])
        self.assertEqual(diag.classify(b"not json\n[]\nnull\n{}\n"), [])
        self.assertEqual(diag.classify(event().replace(b"execution_installation", b"other")), [])

    def test_source_and_output_bounds(self):
        self.assertEqual(len(diag.classify(event() * (diag.MAX_LINES + 1))), diag.MAX_LINES)
        prefix = b"x" * diag.MAX_BYTES + b"\n"
        self.assertEqual(diag.classify(prefix + event()), [])
        self.assertEqual(diag.classify(b" " * (diag.MAX_BYTES - 10) + event()), [])


if __name__ == "__main__":
    unittest.main()
