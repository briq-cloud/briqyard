#!/usr/bin/env python3
"""The decisions of hack/native-suites.py (ADR 0110)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "native-suites.py"
ALL = ["stress", "monitoring", "alerts", "qualification", "restore", "scale"]
LEFT_OUT = ["stress", "qualification", "restore", "scale"]


def run(stdin: str = "", *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], input=stdin, capture_output=True, text=True
    )


def suites(paths: list[str]) -> list[str]:
    done = run("".join(p + "\n" for p in paths))
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


class NativeSuites(unittest.TestCase):
    def test_a_crate_outside_the_list_leaves_out_the_two(self):
        self.assertEqual(suites(["crates/briqyardd/src/machine/start.rs"]), LEFT_OUT)
        self.assertEqual(suites(["crates/briqyard-fleet/src/create.rs", "crates/briqyard/Cargo.toml"]), LEFT_OUT)

    def test_docs_and_other_hack_files_leave_out_the_two(self):
        self.assertEqual(suites(["docs/DEVELOPMENT.md", "README.md"]), LEFT_OUT)
        self.assertEqual(suites(["hack/e2e.sh", "hack/test_native_suites.py"]), LEFT_OUT)
        self.assertEqual(suites([".github/workflows/ci.yml"]), LEFT_OUT)

    def test_each_watched_path_selects_all(self):
        for path in [
            "hack/monitoring/grafana/alerting.yaml",
            "hack/monitoring/dashboards/host.json",
            "hack/monitoring/alert-tests.yaml",
            "hack/install-monitoring.sh",
            "hack/render-alerting.sh",
            "hack/monitoring-check.sh",
            "hack/monitoring-alerts-check.py",
            "hack/monitoring-alert-check.py",
            "hack/monitoring-auth.sh",
            "hack/monitoring-auth.py",
            "hack/monitoring-webhook-check.py",
            "hack/native-ci-more.sh",
            "hack/native-ci.sh",
            ".github/workflows/native.yml",
            "hack/native-suites.py",
            "crates/briqyardd/src/metrics.rs",
            "crates/briqyardd/src/metrics/warm.rs",
            "crates/briqyardd/src/machine/observe.rs",
            "crates/briqyard-api/src/metrics.rs",
            "crates/briqyard-fleet/src/signals.rs",
            "crates/briqyard-fleet/src/scrape.rs",
        ]:
            with self.subTest(path=path):
                self.assertEqual(suites([path]), ALL)

    def test_a_release_selects_all(self):
        self.assertEqual(suites(["CHANGELOG.md", "Cargo.lock", "Cargo.toml", "fuzz/Cargo.lock"]), ALL)
        self.assertEqual(suites(["Cargo.toml"]), ALL)
        self.assertEqual(suites(["Cargo.lock"]), ALL)

    def test_a_crate_manifest_or_look_alike_is_not_watched(self):
        self.assertEqual(suites(["crates/briqyardd/Cargo.toml", "fuzz/Cargo.lock"]), LEFT_OUT)
        self.assertEqual(suites(["hack/monitoringx.sh", "Cargo.toml.orig"]), LEFT_OUT)
        self.assertEqual(suites(["crates/briqyardd/src/metrics.rs.bak"]), LEFT_OUT)

    def test_one_watched_path_among_others_selects_all(self):
        self.assertEqual(suites(["docs/x.md", "hack/monitoring/dashboards/fleet.json", "hack/e2e.sh"]), ALL)

    def test_empty_input_selects_all(self):
        self.assertEqual(suites([]), ALL)
        done = run("\n\n")
        self.assertEqual(json.loads(done.stdout), ALL)

    def test_all_flag(self):
        done = run("", "--all")
        self.assertEqual(done.returncode, 0)
        self.assertEqual(json.loads(done.stdout), ALL)
        done = run("docs/x.md\n", "--all")
        self.assertEqual(json.loads(done.stdout), ALL)

    def test_malformed_use_exits_non_zero(self):
        for args in (["--none"], ["extra"], ["--all", "extra"]):
            with self.subTest(args=args):
                done = run("", *args)
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(done.stdout, "")

    def test_the_workflow_takes_its_matrix_from_the_script(self):
        # Nothing else lists the suites, so a suite added to the script alone runs.
        workflow = (SCRIPT.parent.parent / ".github" / "workflows" / "native.yml").read_text()
        self.assertIn("suite: ${{ fromJSON(needs.changes.outputs.suites) }}", workflow)
        self.assertNotIn("suite: [", workflow)


if __name__ == "__main__":
    unittest.main()
