"""Exercise the actual standalone install section in a temporary host filesystem."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).parent / "firecracker"))
from test_package import fixture

SCRIPT = (Path(__file__).parent / "bootstrap-host.sh").read_text()
HELPERS = SCRIPT.split("# Runtime installation helpers.", 1)[1].split("# End runtime installation helpers.", 1)[0]
HELPERS = HELPERS[HELPERS.index("checked_bundle()") :]
INSTALL = SCRIPT.split('echo "== binaries', 1)[1].split('echo "== api certificate"', 1)[0]
INSTALL = 'echo "== binaries' + INSTALL


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BootstrapRelease(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, _, _, bundle = fixture(self.root)
        self.release = self.root / "release"
        self.release.mkdir()
        shutil.copyfile(bundle, self.release / bundle.name)
        for name in ("briqyard", "briqyard-fleet", "briqyard-init"):
            (self.release / (name + "-linux-x86_64")).write_text(name + " new\n")
        daemon = self.release / "briqyardd-linux-x86_64"
        # At validation, the live config must still reference the old inputs. Every
        # candidate path must already exist. A rejection must precede activation.
        daemon.write_text('''#!/usr/bin/env python3
from pathlib import Path
import os, sys, yaml
live = Path(os.environ["LIVE_CONFIG"])
assert live.read_bytes() == Path(os.environ["OLD_CONFIG"]).read_bytes()
candidate = yaml.safe_load(Path(sys.argv[2]).read_text())
for key in ("firecracker", "jailer", "kernel", "init"):
    assert Path(candidate[key]).is_file(), key
Path(os.environ["VALIDATED_CONFIG"]).write_text(yaml.safe_dump(candidate))
if os.environ.get("REJECT_CONFIG") == "1":
    sys.exit(1)
''')
        for name in ("briqyardd", "briqyard", "briqyard-fleet"):
            old = self.root / "usr/local/bin" / name
            old.parent.mkdir(parents=True, exist_ok=True)
            old.write_text(name + " old running binary\n")
        self.config = self.root / "etc/briqyard/config.yaml"
        self.config.parent.mkdir(parents=True)
        self.old_paths = {}
        for key, path in (("firecracker", "usr/local/bin/firecracker"),
                          ("jailer", "usr/local/bin/jailer"),
                          ("init", "usr/local/bin/briqyard-init"),
                          ("kernel", "var/lib/briqyard/vmlinux")):
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(("#!/bin/sh\necho 'Firecracker v1.17.0'\n# upstream\n") if key == "firecracker" else key + " old\n")
            self.old_paths[key] = dest
        self.config.write_text(yaml.safe_dump({k: str(v) for k, v in self.old_paths.items()} | {"token": "test", "network": {"tcp_ports": "30000-32767"}}))
        self.original = self.config.read_bytes()
        self.old_config = self.root / "old-config"
        self.old_config.write_bytes(self.original)
        self.kernel_sha = sha(self.old_paths["kernel"])
        self.sums()

    def sums(self):
        entries = [sha(p) + "  " + p.name for p in sorted(self.release.iterdir()) if p.name != "SHA256SUMS-x86_64"]
        (self.release / "SHA256SUMS-x86_64").write_text("\n".join(entries) + "\n")

    def run_install(self, **extra):
        # Rewrite only absolute host destinations. The installer itself, including
        # its checksum, staging, validation and atomic rename sequence, runs unchanged.
        section = INSTALL
        for prefix in ("/usr/local/", "/etc/briqyard", "/var/lib/briqyard"):
            section = section.replace(prefix, str(self.root) + prefix)
        script = '''set -euo pipefail
fail() { echo "$*" >&2; exit 1; }
put() { install -m 0755 "$1" "$2.new"; mv -f "$2.new" "$2"; }
release_file() { cp "$RELEASE/$1" "$2"; }
fetch() { cp "$KERNEL_URL" "$3"; echo "$2  $3" | sha256sum -c --quiet -; }
''' + HELPERS + section + '\nprintf handed-over > "$HANDOVER"\n'
        env = dict(os.environ, RELEASE=str(self.release), RELEASE_TOKEN="", ARCH="x86_64",
                   KERNEL_SHA256=self.kernel_sha, KERNEL_URL=str(self.root / "new-kernel"),
                   LIVE_CONFIG=str(self.config), OLD_CONFIG=str(self.old_config),
                   VALIDATED_CONFIG=str(self.root / "validated"), HANDOVER=str(self.root / "handover"), **extra)
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)

    def assert_untouched(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / "handover").exists())
        self.assertIn("upstream", self.old_paths["firecracker"].read_text())
        self.assertEqual(self.old_paths["init"].read_text(), "init old\n")
        self.assertEqual((self.root / "usr/local/bin/briqyardd").read_text(), "briqyardd old running binary\n")

    def test_same_version_new_digest_atomic_paths_and_idempotence(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = yaml.safe_load(self.config.read_text())
        for key in ("firecracker", "jailer", "init"):
            self.assertNotEqual(current[key], str(self.old_paths[key]))
            self.assertEqual(Path(current[key]).parent.name, sha(Path(current[key])))
        self.assertEqual(current["kernel"], str(self.old_paths["kernel"]))
        self.assertEqual(self.old_paths["init"].read_text(), "init old\n")
        self.assertIn("upstream", self.old_paths["firecracker"].read_text())
        self.assertEqual(yaml.safe_load((self.root / "validated").read_text()), current)
        backups = list(self.config.parent.glob("config.yaml.before-*"))
        self.assertTrue(any(p.read_bytes() == self.original for p in backups))
        before = {key: Path(current[key]).stat().st_ino for key in ("firecracker", "jailer", "init", "kernel")}
        self.old_config.write_bytes(self.config.read_bytes())
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(yaml.safe_load(self.config.read_text()), current)
        self.assertEqual({key: Path(current[key]).stat().st_ino for key in before}, before)

    def test_missing_corrupt_or_unchecksummed_release_assets_preserve_config(self):
        bundle = self.release / "firecracker-checked-linux-x86_64.tar.gz"
        original = bundle.read_bytes()
        for mode in ("missing", "corrupt", "no-checksum"):
            with self.subTest(mode=mode):
                bundle.write_bytes(original)
                self.sums()
                if mode == "missing":
                    bundle.unlink()
                elif mode == "corrupt":
                    bundle.write_bytes(b"corrupt")
                else:
                    (self.release / "SHA256SUMS-x86_64").write_text("")
                self.assert_untouched(self.run_install())

    def test_internal_corruption_and_unsafe_members_fail_closed(self):
        bundle = self.release / "firecracker-checked-linux-x86_64.tar.gz"
        original = bundle.read_bytes()
        for mode in ("binary", "policy", "missing-jailer", "arch", "symlink", "traversal"):
            with self.subTest(mode=mode):
                with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as archive:
                    files = {m.name: archive.extractfile(m).read() for m in archive.getmembers()}
                if mode == "binary":
                    files["firecracker"] = b"bad"
                elif mode == "policy":
                    files["seccomp_filter.bpf"] = b"bad"
                elif mode == "missing-jailer":
                    del files["jailer"]
                elif mode == "arch":
                    p = json.loads(files["provenance.json"])
                    p["architecture"] = "aarch64"
                    files["provenance.json"] = json.dumps(p).encode()
                with tarfile.open(bundle, "w:gz") as archive:
                    for name, data in files.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                    if mode in ("symlink", "traversal"):
                        member = tarfile.TarInfo("extra" if mode == "symlink" else "../escape")
                        member.type = tarfile.SYMTYPE if mode == "symlink" else tarfile.REGTYPE
                        member.linkname = "/etc/passwd" if mode == "symlink" else ""
                        archive.addfile(member, io.BytesIO())
                self.sums()  # Even a checksummed package must pass internal evidence checks.
                self.assert_untouched(self.run_install())

    def test_rejected_config_and_install_failure_do_not_activate(self):
        self.assert_untouched(self.run_install(REJECT_CONFIG="1"))
        tools = self.root / "tools"
        tools.mkdir()
        install = tools / "install"
        install.write_text("#!/bin/sh\nexit 1\n")
        install.chmod(0o755)
        # Remove staged inputs to inject a real install failure at immutable staging.
        shutil.rmtree(self.root / "usr/local/lib/briqyard/runtime")
        self.assert_untouched(self.run_install(PATH=str(tools) + ":" + os.environ["PATH"]))

    def test_binary_install_failure_keeps_old_configuration_and_daemon(self):
        tools = self.root / "tools"
        tools.mkdir()
        target = str(self.root / "usr/local/bin/briqyard.new")
        install = tools / "install"
        real_install = shutil.which("install")
        install.write_text('#!/bin/sh\n[ "$4" != "' + target + '" ] || exit 1\nexec ' + real_install + ' "$@"\n')
        install.chmod(0o755)
        self.assert_untouched(self.run_install(PATH=str(tools) + ":" + os.environ["PATH"]))
        self.assertTrue((self.root / "validated").exists())

    def test_changed_kernel_is_immutable_and_prior_kernel_survives(self):
        new_kernel = self.root / "new-kernel"
        new_kernel.write_text("new kernel\n")
        self.kernel_sha = sha(new_kernel)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = yaml.safe_load(self.config.read_text())
        self.assertEqual(Path(current["kernel"]).parent.name, self.kernel_sha)
        self.assertEqual(self.old_paths["kernel"].read_text(), "kernel old\n")


if __name__ == "__main__":
    unittest.main()
