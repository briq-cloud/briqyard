"""Release metadata must identify exactly the reviewed candidate."""
import importlib.util
from pathlib import Path
import unittest
import os
import shutil
import subprocess
import tempfile
import tomllib

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_notes_select_exact_version_preserving_content(self):
        text = "# Changelog\n\n## 0.1.18 — 2026-11-03\n\n- New.\n\n## 0.1.17 — 2026-11-02\n\n- Previous.\n"
        self.assertEqual(release.notes(text, "v0.1.18"),
                         "## 0.1.18 — 2026-11-03\n\n- New.\n")
        self.assertIn("Previous.", release.notes(text, "0.1.17"))

    def test_notes_reject_missing_empty_duplicate_and_invalid_versions(self):
        for text, version in [
            ("## 0.1.180\n\n- Wrong.\n", "0.1.18"),
            ("## 0.1.18\n\n### Fixes\n", "0.1.18"),
            ("## 0.1.18\n- One.\n## 0.1.18\n- Two.\n", "0.1.18"),
            ("## 0.1.18\n- One.\n", "0.1.18-rc1"),
        ]:
            with self.subTest(text=text, version=version), self.assertRaises(ValueError):
                release.notes(text, version)

    def test_workspace_leaves_out_the_crates_with_their_own_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/a", "crates/init"]\n\n[workspace.package]\nversion = "0.1.20"\n')
            for name, version in (("a", "version.workspace = true"), ("init", 'version = "0.0.0"')):
                (root / "crates" / name).mkdir(parents=True)
                (root / "crates" / name / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n{version}\n')
            cwd = os.getcwd()
            os.chdir(root)
            try:
                version, names = release.workspace()
            finally:
                os.chdir(cwd)
            self.assertEqual((version, names), ("0.1.20", {"a"}))

    def test_lock_updates_only_local_workspace_packages(self):
        text = '''version = 4

[[package]]
name = "briqyard-api"
version = "0.1.17"

[[package]]
name = "another-crate"
version = "0.1.17"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
        updated = release.lock_update(text, {"briqyard-api"}, "0.1.17", "0.1.18")
        self.assertIn('name = "briqyard-api"\nversion = "0.1.18"', updated)
        self.assertIn('name = "another-crate"\nversion = "0.1.17"', updated)
        with self.assertRaises(ValueError):
            release.lock_update(text, {"briqyard-api"}, "0.1.16", "0.1.18")


    @unittest.skipUnless(shutil.which("git-cliff"), "install git-cliff for preparation integration test")
    def test_prepare_updates_candidate_without_tagging_or_rewriting_history(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("Cargo.toml", "Cargo.lock", "fuzz/Cargo.lock", "CHANGELOG.md", "cliff.toml", "hack/release.py"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target)
            version, names = release.workspace()
            manifest = tomllib.loads((source / "Cargo.toml").read_text())
            for member in manifest["workspace"]["members"]:
                target = root / member / "Cargo.toml"
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / member / "Cargo.toml", target)
            env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.com",
                       GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.com")
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, env=env, text=True)
            git("init", "-b", "codex/release-test")
            git("add", ".")
            git("commit", "-m", "chore(release): baseline")
            git("tag", f"v{version}")
            git("commit", "--allow-empty", "-m", "feat: example capability")
            original = (root / "CHANGELOG.md").read_text()
            subprocess.run(["python3", "hack/release.py", "prepare"], cwd=root, env=env, check=True,
                           stdout=subprocess.DEVNULL)
            new = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
            major, minor, patch = map(int, version.split("."))
            self.assertEqual(new, f"{major}.{minor}.{patch + 1}")
            self.assertTrue((root / "CHANGELOG.md").read_text().endswith(original.removeprefix("# Changelog\n\n")))
            self.assertIn("example capability", (root / "CHANGELOG.md").read_text())
            for name in ("Cargo.lock", "fuzz/Cargo.lock"):
                packages = tomllib.loads((root / name).read_text())["package"]
                self.assertTrue(all(p["version"] == new for p in packages
                                    if p["name"] in names and "source" not in p))
            self.assertEqual(git("tag").strip(), f"v{version}")
            subprocess.run(["python3", "hack/release.py", "notes", f"v{new}"], cwd=root, env=env,
                           check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
