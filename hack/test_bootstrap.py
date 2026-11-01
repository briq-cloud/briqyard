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
''' + HELPERS + section + '\n[ "${FAULT_AFTER_CONFIG:-0}" != 1 ] || false\nprintf handed-over > "$HANDOVER"\n'
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
        for name in ("briqyard", "briqyard-fleet", "briqyardd"):
            self.assertEqual((self.root / "usr/local/bin" / name).read_text(), name + " old running binary\n")

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

    def test_yaml_credentials_comments_aliases_and_nested_values_are_byte_preserved(self):
        # These scalar spellings are strings to Rust, but YAML 1.1 loaders coerce
        # on and 0123 to a boolean/integer. Only runtime value spans may change.
        unrelated = ("# preserve credentials and comments\r\n"
                     "token: on # keep this exact spelling\r\n"
                     "metrics_token: &credential 0123\r\n"
                     "registries:\r\n"
                     "  - host: ghcr.io\r\n"
                     "    username: *credential\r\n"
                     "    password: 0123 # leading zero is significant\r\n"
                     "registry_mirrors: {docker.io: 'http://10.0.0.2:7440'}\r\n"
                     "templates:\r\n"
                     "  enabled: false\r\n"
                     "  init_ready_init_sha256: '000123'\r\n"
                     "  warm_pools: false # preserve nested rollout settings\r\n")
        original_values = {key: "'" + str(path) + "'" for key, path in self.old_paths.items()}
        runtime = "".join(key + ": " + value + " # runtime " + key + "\r\n"
                          for key, value in original_values.items())
        self.original = (unrelated + runtime + "...\r\n").encode()
        self.config.write_bytes(self.original)
        self.old_config.write_bytes(self.original)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = self.config.read_bytes().decode()
        paths = yaml.safe_load(current)
        restored = current
        for key, value in original_values.items():
            restored = restored.replace(key + ": " + json.dumps(paths[key]) + " # runtime " + key,
                                        key + ": " + value + " # runtime " + key)
        self.assertEqual(restored.encode(), self.original)
        # Existing scalar tokens, aliases and all nested content are unchanged.
        self.assertIn(unrelated.encode(), self.config.read_bytes())

    def test_absent_runtime_fields_are_inserted_before_document_end(self):
        self.original = ("token: on # keep\n" + "kernel: '" + str(self.old_paths["kernel"]) + "'\n...\n").encode()
        self.config.write_bytes(self.original)
        self.old_config.write_bytes(self.original)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.config.read_text().startswith("token: on # keep\n"))
        self.assertTrue(self.config.read_text().endswith("...\n"))
        self.assertEqual(set(yaml.safe_load(self.config.read_text())), {"token", "firecracker", "jailer", "kernel", "init"})

    def test_ambiguous_runtime_aliases_merges_and_duplicate_keys_fail_closed(self):
        base = self.original.decode()
        for suffix in ("init: *credential\n", "init: &runtime_path '/old/init'\n",
                       "init: |\n  /old/init\n", "<<: {init: '/old/init'}\n"):
            with self.subTest(suffix=suffix):
                # Remove the original init line, then supply an unsupported runtime form.
                changed = "metrics_token: &credential 'preserve'\n" + "\n".join(
                    line for line in base.splitlines() if not line.startswith("init:")) + "\n" + suffix
                self.original = changed.encode()
                self.config.write_bytes(self.original)
                self.old_config.write_bytes(self.original)
                self.assert_untouched(self.run_install())
        self.original = (base + "init: '/duplicate'\n").encode()
        self.config.write_bytes(self.original)
        self.old_config.write_bytes(self.original)
        self.assert_untouched(self.run_install())

    def test_complete_verified_rollback_is_retained_before_activation(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rollback, = self.config.parent.glob("rollback.*")
        self.assertEqual((rollback / "config.yaml").read_bytes(), self.original)
        for name in ("briqyard", "briqyard-fleet", "briqyardd"):
            self.assertEqual((rollback / name).read_text(), name + " old running binary\n")
        check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=rollback, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_backup_and_each_late_activation_failure_restore_prior_operation(self):
        tools = self.root / "fault-tools"
        tools.mkdir()
        cases = [
            ("cp", 'case "$3" in */rollback.*/config.yaml) true;; *) false;; esac', False),
            ("cp", 'case "$3" in */rollback.*/briqyardd) true;; *) false;; esac', False),
            ("cp", 'case "$3" in */config.yaml.before-*) true;; *) false;; esac', False),
            ("install", '[ "$4" = "' + str(self.root / "usr/local/bin/briqyard-fleet.new") + '" ]', False),
            ("mv", '[ "$3" = "' + str(self.root / "usr/local/bin/briqyardd") + '" ]', False),
            ("mv", '[ "$3" = "' + str(self.root / "usr/local/bin/briqyardd") + '" ]', True),
            ("mv", '[ "$3" = "' + str(self.config) + '" ]', False),
            ("mv", '[ "$3" = "' + str(self.config) + '" ]', True),
        ]
        for command, condition, after in cases:
            with self.subTest(command=command, condition=condition, after=after):
                for old in tools.iterdir():
                    old.unlink()
                marker = self.root / "fault"
                marker.unlink(missing_ok=True)
                real = shutil.which(command)
                wrapper = tools / command
                wrapper.write_text('#!/bin/bash\nif [ ! -e "$FAULT_MARK" ] && { ' + condition + '; }; then\n'
                                   '  touch "$FAULT_MARK"\n' + ('  ' + real + ' "$@" || exit $?\n' if after else '')
                                   + '  exit 1\nfi\nexec ' + real + ' "$@"\n')
                wrapper.chmod(0o755)
                self.assert_untouched(self.run_install(PATH=str(tools) + ":" + os.environ["PATH"], FAULT_MARK=str(marker)))
                self.assertTrue(marker.exists(), "injection boundary was not reached")
                self.assertTrue((self.root / "validated").exists())
                # Verified rollback sets survive later activation failures; incomplete
                # snapshots are removed before any executable can change.
                for rollback in self.config.parent.glob("rollback.*"):
                    check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=rollback, capture_output=True)
                    self.assertEqual(check.returncode, 0, check.stderr)
                # Let the next case exercise the legacy configuration backup again.
                for backup in self.config.parent.glob("config.yaml.before-*"):
                    backup.unlink()

    def test_failure_after_configuration_switch_restores_prior_operation(self):
        self.assert_untouched(self.run_install(FAULT_AFTER_CONFIG="1"))
        rollback, = self.config.parent.glob("rollback.*")
        check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=rollback, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_path_editor_preserves_nested_warm_policy_and_registry_auth(self):
        # The path editor has no schema for unrelated settings. In particular, it must
        # preserve a future warm policy through the coordinated release source update.
        nested = ("warm_policy: # administrator policy\n"
                  "  memory_mb: 2048\n"
                  "  entries:\n"
                  "    - template: '0123'\n"
                  "      max_instances: 2\n"
                  "registries:\n"
                  "  - host: ghcr.io\n"
                  "    username: &username on\n"
                  "    password: 0123\n"
                  "  - host: registry.internal\n"
                  "    username: *username\n"
                  "    password: 'false' # literal password\n")
        candidate = self.root / "nested-config"
        candidate.write_text(nested)
        result = subprocess.run(["bash", "-c", HELPERS + '\nruntime_config "$@"', "paths", str(candidate),
                                 "/fc", "/jailer", "/kernel", "/init"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(candidate.read_text().startswith(nested))
        self.assertEqual(candidate.read_text()[len(nested):],
                         'firecracker: "/fc"\njailer: "/jailer"\nkernel: "/kernel"\ninit: "/init"\n')

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
