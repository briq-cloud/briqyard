#!/usr/bin/env python3
"""The decisions of hack/native-suites.py (ADR 0110)."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
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

    def test_only_selects_the_named_suites_in_matrix_order(self):
        for value, expected in [
            ("qualification", ["qualification"]),
            ("scale,stress", ["stress", "scale"]),
            (" restore , qualification ", ["qualification", "restore"]),
            (",".join(ALL), ALL),
            (",".join(reversed(ALL)), ALL),
        ]:
            with self.subTest(value=value):
                done = run("docs/x.md\n", "--only", value)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(json.loads(done.stdout), expected)

    def test_only_rejects_what_is_not_a_known_suite_name(self):
        for value in ["qualfication", "Qualification", "all", "e2e", "two-hosts", "stress,nope", "stress;scale", "stress scale"]:
            with self.subTest(value=value):
                done = run("", "--only", value)
                self.assertEqual(done.returncode, 2)
                self.assertEqual(done.stdout, "")
                self.assertIn("unknown suite", done.stderr)
        self.assertIn("qualfication", run("", "--only", "qualfication").stderr)

    def test_only_rejects_an_empty_selection_or_name(self):
        for value in ["", " ", ",", "qualification,", ",qualification", "stress,,scale", "stress, ,scale"]:
            with self.subTest(value=value):
                done = run("", "--only", value)
                self.assertEqual(done.returncode, 2)
                self.assertEqual(done.stdout, "")
                self.assertIn("empty suite name", done.stderr)

    def test_only_rejects_a_suite_named_twice(self):
        done = run("", "--only", "qualification,qualification")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("twice", done.stderr)

    def test_only_does_not_combine_with_all(self):
        done = run("", "--all", "--only", "qualification")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    def selection_step(self, event: str, only: str = "", exclusive: str = "") -> subprocess.CompletedProcess:
        # Runs the shell of the workflow's "Select the suites" step on a two-commit repository.
        workflow = (SCRIPT.parent.parent / ".github" / "workflows" / "native.yml").read_text()
        body = workflow.split("name: Select the suites", 1)[1].split("run: |\n", 1)[1].split("\n  suites:\n", 1)[0]
        step = textwrap.dedent(body)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hack").mkdir()
            shutil.copy(SCRIPT, root / "hack" / SCRIPT.name)
            (root / "docs").mkdir()
            git = ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@example.com"]
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
            (root / "docs" / "x.md").write_text("changed\n")
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-q", "-m", "change"], check=True)
            output, summary = root / "output", root / "summary"
            output.touch()
            summary.touch()
            env = {
                **os.environ,
                "EVENT": event,
                "ONLY": only,
                "EXCLUSIVE": exclusive,
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
            }
            # GitHub runs a step with bash -e.
            done = subprocess.run(["bash", "-e", "-c", step], cwd=tmp, env=env, capture_output=True, text=True)
            done.output = output.read_text()
            done.summary = summary.read_text()
            return done

    @unittest.skipUnless(shutil.which("jq") and shutil.which("git"), "needs jq and git")
    def test_the_step_keeps_the_pull_request_and_default_selection(self):
        done = self.selection_step("pull_request")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.output, f"suites={json.dumps(LEFT_OUT)}\n")
        self.assertIn("Left out: monitoring, alerts.", done.summary)
        for only in ["", "qualification"]:
            with self.subTest(only=only):
                # A pull request never has the input; whatever it holds, the diff decides.
                self.assertEqual(self.selection_step("pull_request", only).output, done.output)
        for event in ["workflow_dispatch", "push"]:
            with self.subTest(event=event):
                done = self.selection_step(event)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.output, f"suites={json.dumps(ALL)}\n")
                self.assertNotIn("Left out", done.summary)
                self.assertNotIn("Selected by", done.summary)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("git"), "needs jq and git")
    def test_the_step_selects_a_dispatch_subset_and_records_it(self):
        done = self.selection_step("workflow_dispatch", "qualification")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.output, 'suites=["qualification"]\n')
        self.assertIn("Run: qualification", done.summary)
        self.assertIn("Selected by the dispatch input suites_only (`qualification`)", done.summary)
        self.assertIn("Not selected: stress, monitoring, alerts, restore, scale.", done.summary)
        done = self.selection_step("workflow_dispatch", "scale, stress")
        self.assertEqual(done.output, 'suites=["stress", "scale"]\n')
        self.assertIn("Run: stress, scale", done.summary)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("git"), "needs jq and git")
    def test_the_step_fails_instead_of_falling_back(self):
        for only in ["qualfication", "stress,", " ", ",", "scale,scale"]:
            with self.subTest(only=only):
                done = self.selection_step("workflow_dispatch", only)
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(done.output, "")
                self.assertEqual(done.summary, "")
        done = self.selection_step("workflow_dispatch", "qualification", "true")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.output, "")
        self.assertIn("cannot be combined", done.stderr)

    def test_the_dispatch_input_skips_the_jobs_that_are_not_in_the_matrix(self):
        workflow = (SCRIPT.parent.parent / ".github" / "workflows" / "native.yml").read_text()
        jobs = workflow.split("\njobs:\n", 1)[1]
        for job in ["suites", "two-hosts", "measure"]:
            with self.subTest(job=job):
                header = jobs.split(f"\n  {job}:\n", 1)[1].split("runs-on:", 1)[0]
                self.assertIn("inputs.suites_only == ''", header)
        # more-suites keeps its own condition and needs changes, so a failed selection stops it.
        header = jobs.split("\n  more-suites:\n", 1)[1].split("runs-on:", 1)[0]
        self.assertNotIn("suites_only", header)
        self.assertIn("needs: changes", header)
        # The harness still comes from the workflow revision, the suites from the tested source.
        self.assertIn("path: .native-harness", jobs)

    def test_the_workflow_takes_its_matrix_from_the_script(self):
        # Nothing else lists the suites, so a suite added to the script alone runs.
        workflow = (SCRIPT.parent.parent / ".github" / "workflows" / "native.yml").read_text()
        self.assertIn("suite: ${{ fromJSON(needs.changes.outputs.suites) }}", workflow)
        self.assertNotIn("suite: [", workflow)


if __name__ == "__main__":
    unittest.main()
