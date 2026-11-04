"""Exercise the actual standalone install section in a temporary host filesystem."""
import hashlib
import select
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
DROPPED = "refuse_dropped_nested() {" + SCRIPT.split("refuse_dropped_nested() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
INSTALL = SCRIPT.split('echo "== binaries', 1)[1].split('echo "== api certificate"', 1)[0]
INSTALL = 'echo "== binaries' + INSTALL


CAPABILITIES = {
    "assignment-capabilities": "destination-assignment-v1",
    "assigned-run-capabilities": "assigned-run-v1",
    "assigned-run-lifecycle-capabilities": "assigned-run-lifecycle-v1",
}
FULL_DAEMON = "#!/bin/sh\ncase $1 in\n" + "".join(
    command + ") printf '" + answer + "\\n';;\n" for command, answer in CAPABILITIES.items()
) + "*) exit 2;;\nesac\n"

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
protocols = {"assignment-capabilities": "destination-assignment-v1", "assigned-run-capabilities": "assigned-run-v1", "assigned-run-lifecycle-capabilities": "assigned-run-lifecycle-v1"}
if sys.argv[1] in protocols:
    print(protocols[sys.argv[1]])
    sys.exit(0)
if os.environ.get("ADVANCE_FLOOR"):
    floor = Path(os.environ["ADVANCE_FLOOR"])
    floor.parent.mkdir(parents=True, exist_ok=True)
    floor.write_text('{"schema":3,"protocol":"assigned-run-lifecycle-v1"}')
if os.environ.get("MUTATE_DAEMON"):
    with Path(__file__).open("a") as changed:
        changed.write("# changed after capability probe\\n")
live = Path(os.environ["LIVE_CONFIG"])
assert live.read_bytes() == Path(os.environ["OLD_CONFIG"]).read_bytes()
candidate = yaml.safe_load(Path(sys.argv[2]).read_text())
for key in ("firecracker", "jailer", "kernel", "init"):
    assert Path(candidate[key]).is_file(), key
Path(os.environ["VALIDATED_CONFIG"]).write_text(yaml.safe_dump(candidate))
if os.environ.get("REJECT_CONFIG") == "1":
    sys.exit(1)
''')
        self.old_binaries = {}
        for name in ("briqyardd", "briqyard", "briqyard-fleet"):
            old = self.root / "usr/local/bin" / name
            old.parent.mkdir(parents=True, exist_ok=True)
            self.old_binaries[name] = FULL_DAEMON if name == "briqyardd" else name + " old running binary\n"
            old.write_text(self.old_binaries[name])
            old.chmod(0o755)
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
                   VALIDATED_CONFIG=str(self.root / "validated"), HANDOVER=str(self.root / "handover"), **({"NESTED": "0"} | extra))
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)

    def assert_untouched(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / "handover").exists())
        self.assertIn("upstream", self.old_paths["firecracker"].read_text())
        self.assertEqual(self.old_paths["init"].read_text(), "init old\n")
        for name in ("briqyard", "briqyard-fleet", "briqyardd"):
            self.assertEqual((self.root / "usr/local/bin" / name).read_text(), self.old_binaries[name])

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

    def nested_assets(self):
        (self.release / "nested-vmlinux-x86_64").write_text("nested kernel\n")
        (self.release / "nested-modules-x86_64.ext4").write_text("nested modules\n")
        (self.release / "nested-versions-x86_64.json").write_text(
            json.dumps({"kernel_release": "6.18.54-briqyard-nested", "openzfs": "2.4.1"}))
        self.sums()

    def test_nested_class_is_installed_by_digest_and_written_to_the_config(self):
        self.nested_assets()
        result = self.run_install(NESTED="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        classes = yaml.safe_load(self.config.read_text())["runtime_classes"]
        self.assertEqual(list(classes), ["nested"])
        written = json.loads(json.dumps(classes))
        nested = classes["nested"]
        self.assertTrue(nested.pop("nested"))
        self.assertEqual(nested.pop("release"), "6.18.54-briqyard-nested")
        for field, name in (("kernel", "vmlinux"), ("modules", "modules.ext4"), ("versions", "versions.json")):
            path = Path(nested.pop(field))
            self.assertEqual(path.name, name)
            self.assertEqual(path.parent.name, sha(path))
            self.assertEqual(path.parent.parent, self.root / "var/lib/briqyard/classes/nested")
        self.assertEqual(nested, {})
        # Run again: the same paths, one class.
        self.old_config.write_bytes(self.config.read_bytes())
        again = self.run_install(NESTED="1")
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(yaml.safe_load(self.config.read_text())["runtime_classes"], written)

    def test_nested_class_asset_with_another_digest_refuses_before_anything_is_activated(self):
        self.nested_assets()
        (self.release / "nested-modules-x86_64.ext4").write_text("tampered\n")
        self.assert_untouched(self.run_install(NESTED="1"))

    def test_no_class_without_the_variable(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("runtime_classes", yaml.safe_load(self.config.read_text()))
        self.assertFalse((self.root / "var/lib/briqyard/classes").exists())

    def test_floor_can_advance_after_probes_before_copy_with_full_candidate(self):
        floor = self.root / "data/state/meta/required-assignment-protocol.json"
        self.config.write_text(yaml.safe_dump(yaml.safe_load(self.config.read_text()) | {"data_dir": str(self.root / "data")}))
        self.original = self.config.read_bytes()
        self.old_config.write_bytes(self.original)
        for prior in (None, {"schema": 2, "protocol": "assigned-run-v1"}):
            with self.subTest(prior=prior):
                floor.unlink(missing_ok=True)
                if prior:
                    floor.parent.mkdir(parents=True, exist_ok=True)
                    floor.write_text(json.dumps(prior))
                result = self.run_install(ADVANCE_FLOOR=str(floor))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(floor.read_text())["schema"], 3)
                self.old_config.write_bytes(self.config.read_bytes())

    def test_weaker_candidate_refused_before_validation_even_without_daemon_state(self):
        (self.release / "briqyardd-linux-x86_64").write_text(FULL_DAEMON.replace(
            "assigned-run-lifecycle-capabilities) printf 'assigned-run-lifecycle-v1\\n';;\n", ""))
        self.sums()
        self.assert_untouched(self.run_install())
        self.assertFalse((self.root / "validated").exists())
        self.assertFalse(any(self.config.parent.glob("rollback.*")))

    def test_staged_daemon_changes_after_probe_are_refused_before_copy(self):
        self.assert_untouched(self.run_install(MUTATE_DAEMON="1"))

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
            self.assertEqual((rollback / name).read_text(), self.old_binaries[name])
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


class DroppedNestedClass(unittest.TestCase):
    """A run that does not name the class must not turn it off (ADR 0088)."""

    def check(self, config, nested):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.yaml"
            if config is not None:
                path.write_text(yaml.safe_dump(config))
            return subprocess.run(["bash", "-c", DROPPED + 'refuse_dropped_nested "$1"; echo ok', "x", str(path)],
                                  env=dict(os.environ, NESTED=nested), text=True, capture_output=True)

    def test_a_configuration_that_serves_nested_refuses_a_run_without_the_variable(self):
        served = {"token": "t", "runtime_classes": {"nested": {"kernel": "/k", "modules": "/m", "nested": True}}}
        result = self.check(served, "0")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("BRIQYARD_RUNTIME_CLASSES=nested", result.stdout)
        self.assertNotIn("ok", result.stdout)

    def test_the_variable_a_plain_config_or_no_config_pass(self):
        served = {"runtime_classes": {"nested": {"kernel": "/k", "modules": "/m", "nested": True}}}
        for config, nested in ((served, "1"), ({"token": "t"}, "0"), (None, "0"),
                               ({"runtime_classes": {"other": {"kernel": "/k", "modules": "/m"}}}, "0")):
            result = self.check(config, nested)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ok", result.stdout)


class InstallerLock(unittest.TestCase):
    def test_installers_serialize_through_handover_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            private = root / "private"
            staging = root / "staging"
            staging.mkdir()
            first_script = HELPERS + r'''
runtime_install_lock "$1"
new="$2"; candidate=""; rollback=""; activation_pending=0; rollback_ready=0
trap 'set +e; printf "cleanup\n"; read -r gate; false; cleanup_runtime_install' EXIT
printf 'preflight\n'
read -r gate
false
'''
            second_script = HELPERS + r'''
runtime_install_lock "$1"
[ ! -e "$2" ] || exit 3
printf 'second-installed\n'
'''
            first = subprocess.Popen(["bash", "-c", first_script, "first", str(private), str(staging)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            second = None
            try:
                self.assertEqual(first.stdout.readline(), "preflight\n")
                second = subprocess.Popen(["bash", "-c", second_script, "second", str(private), str(staging)],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(select.select([second.stdout], [], [], .15)[0], [])
                first.stdin.write("handover done\n"); first.stdin.flush()
                self.assertEqual(first.stdout.readline(), "cleanup\n")
                self.assertEqual(select.select([second.stdout], [], [], .15)[0], [])
                first.stdin.write("cleanup allowed\n"); first.stdin.flush()
                _, error = first.communicate(timeout=10)
                self.assertEqual(first.returncode, 1, error)
                output, error = second.communicate(timeout=10)
                self.assertEqual(second.returncode, 0, error)
                self.assertEqual(output, "second-installed\n")
                self.assertEqual(private.stat().st_mode & 0o777, 0o700)
                self.assertEqual((private / "runtime-install.lock").stat().st_mode & 0o777, 0o600)
            finally:
                for child in (first, second):
                    if child and child.poll() is None:
                        child.kill()
                        child.communicate(timeout=10)

    def test_symlink_lock_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            target = root / "target"
            target.write_text("unchanged")
            (root / "runtime-install.lock").symlink_to(target)
            result = subprocess.run(["bash", "-c", HELPERS + '\nruntime_install_lock "$1"', "lock", str(root)],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_text(), "unchanged")


class AssignmentCompatibility(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "custom-data"
        self.config = self.root / "installed.yaml"
        self.config.write_text(yaml.safe_dump({"data_dir": str(self.data)}))
        self.candidate = self.root / "candidate.yaml"
        self.candidate.write_text(yaml.safe_dump({"data_dir": str(self.root / "empty-new-root")}))
        self.binary = self.root / "replacement"
        self.binary.write_text("#!/bin/sh\nexit 2\n")
        self.binary.chmod(0o700)

    def check(self, binary=None):
        return subprocess.run(["bash", "-c", HELPERS + '\nruntime_assignment_compatible "$@"',
                               "check", str(binary or self.binary), str(self.config), str(self.candidate)],
                              text=True, capture_output=True)

    def evidence(self, kind, value):
        path = self.data / "state" / kind
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def test_unknown_command_refused_even_for_empty_state_and_pure_reads(self):
        self.assertNotEqual(self.check().returncode, 0)
        self.assertFalse(self.data.exists())
        receipt = self.evidence("unbound-requests/request.json", {"schema": 1})
        self.assertNotEqual(self.check().returncode, 0)
        self.assertFalse((self.data / "state/meta").exists())
        receipt.unlink()
        self.assertNotEqual(self.check().returncode, 0)
        self.binary.write_text(FULL_DAEMON)
        self.assertEqual(self.check().returncode, 0)

    def test_installed_custom_root_cannot_be_hidden_by_empty_candidate_root(self):
        self.evidence("meta/required-assignment-protocol.json",
                      {"schema": 1, "protocol": "destination-assignment-v1"})
        self.assertNotEqual(self.check().returncode, 0)
        self.binary.write_text("#!/bin/sh\n[ \"$1\" = assignment-capabilities ] || exit 1\nprintf 'destination-assignment-v1\\n'\n")
        self.assertNotEqual(self.check().returncode, 0)
        self.binary.write_text(FULL_DAEMON)
        self.assertEqual(self.check().returncode, 0)
        self.binary.write_text("#!/bin/sh\nprintf 'destination-assignment-v1\\nextra'\n")
        self.assertNotEqual(self.check().returncode, 0)

    def test_assigned_run_floor_and_missing_floor_evidence_require_all_commands(self):
        for collection in ("meta/required-assignment-protocol.json", "assigned-run-intents/run.json",
                           "assigned-runs/machine.json", "assigned-run-readers/machine.json",
                           "machines/machine.json"):
            with self.subTest(collection=collection):
                shutil.rmtree(self.data, ignore_errors=True)
                value = ({"schema": 2, "protocol": "assigned-run-v1"} if collection.startswith("meta/") else
                         {"assigned_run": {"schema": 1, "sequence": 1, "phase": "reserved"}} if collection.startswith("machines/") else {"schema": 1})
                self.evidence(collection, value)
                self.binary.write_text("#!/bin/sh\n[ \"$1\" = assignment-capabilities ] || exit 2\nprintf 'destination-assignment-v1\\n'\n")
                self.assertNotEqual(self.check().returncode, 0)
                self.binary.write_text("#!/bin/sh\ncase $1 in\nassignment-capabilities) printf 'destination-assignment-v1\\n';;\nassigned-run-capabilities) printf 'assigned-run-v1\\n';;\n*) exit 2;;\nesac\n")
                self.assertNotEqual(self.check().returncode, 0)
                self.binary.write_text(FULL_DAEMON)
                self.assertEqual(self.check().returncode, 0)
                if not collection.startswith("meta/"):
                    self.assertFalse((self.data / "state/meta").exists(), "inspection must not migrate state")

    def test_lifecycle_floor_and_missing_marker_evidence_require_new_probe(self):
        old = "#!/bin/sh\ncase $1 in\nassignment-capabilities) printf 'destination-assignment-v1\\n';;\nassigned-run-capabilities) printf 'assigned-run-v1\\n';;\n*) exit 2;;\nesac\n"
        for collection in ("meta/required-assignment-protocol.json", "assigned-run-intents/run.json",
                           "assigned-runs/machine.json", "assigned-run-readers/machine.json", "machines/machine.json"):
            with self.subTest(collection=collection):
                shutil.rmtree(self.data, ignore_errors=True)
                value = ({"schema": 3, "protocol": "assigned-run-lifecycle-v1"} if collection.startswith("meta/") else
                         {"assigned_run": {"schema": 3, "sequence": 1, "phase": "settled"}} if collection.startswith("machines/") else {"schema": 3})
                self.evidence(collection, value)
                self.binary.write_text(old)
                self.assertNotEqual(self.check().returncode, 0)
                for answer, accepted in (("printf 'assigned-run-lifecycle-v1\\n'", True),
                                         ("printf 'assigned-run-lifecycle-v1\\nextra'", False),
                                         ("printf 'assigned-run-lifecycle-v1\\n'; exit 1", False)):
                    self.binary.write_text(old.replace("*) exit 2;;", "assigned-run-lifecycle-capabilities) " + answer + ";;\n*) exit 2;;"))
                    self.assertEqual(self.check().returncode == 0, accepted)
                if not collection.startswith("meta/"):
                    self.assertFalse((self.data / "state/meta").exists())

    def test_empty_state_requires_exact_successful_bounded_protocol_answers(self):
        for command, answer in CAPABILITIES.items():
            branch = command + ") printf '" + answer + "\\n';;"
            for body in ("exit 2", "printf wrong", "printf '" + answer + "\\n'; exit 1"):
                with self.subTest(command=command, body=body):
                    self.binary.write_text(FULL_DAEMON.replace(branch, command + ") " + body + ";;"))
                    self.assertNotEqual(self.check().returncode, 0)
        branch = "assigned-run-lifecycle-capabilities) printf 'assigned-run-lifecycle-v1\\n';;"
        for body in ("while :; do printf 0123456789; done", "exec sleep 10"):
            self.binary.write_text(FULL_DAEMON.replace(branch, "assigned-run-lifecycle-capabilities) " + body + ";;"))
            self.assertNotEqual(self.check().returncode, 0)
        self.assertFalse(self.data.exists())

    def test_unknown_assignment_floor_cannot_be_overridden_by_new_capability(self):
        self.evidence("meta/required-assignment-protocol.json", {"schema": 3, "protocol": "assigned-run-v1"})
        self.binary.write_text(FULL_DAEMON)
        self.assertNotEqual(self.check().returncode, 0)
        shutil.rmtree(self.data)
        self.evidence("assigned-runs/machine.json", {"schema": 2})
        self.assertNotEqual(self.check().returncode, 0)

    def test_malformed_floor_or_assignment_evidence_fails_closed(self):
        self.binary.write_text(FULL_DAEMON)
        marker = self.evidence("meta/required-assignment-protocol.json", {"schema": 9})
        self.assertNotEqual(self.check().returncode, 0)
        marker.unlink()
        self.evidence("machines/assigned.json", {"launch_identity": {}, "warm_slot": {"claimed": "request"}})
        self.assertEqual(self.check().returncode, 0)
        self.evidence("unbound-assignments/intent.json", []).write_text("invalid JSON")
        self.assertNotEqual(self.check().returncode, 0)

    def test_rollback_refuses_old_binary_after_assignment_appears(self):
        rollback = self.root / "rollback"
        rollback.mkdir()
        shutil.copyfile(self.config, rollback / "config.yaml")
        shutil.copyfile(self.binary, rollback / "briqyardd")
        (rollback / "briqyardd").chmod(0o700)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        replacement = binary_dir / "briqyardd"
        replacement.write_text("compatible replacement")
        self.evidence("meta/required-assignment-protocol.json",
                      {"schema": 1, "protocol": "destination-assignment-v1"})
        staging = self.root / "staging"
        staging.mkdir()
        script = HELPERS + '\nactivation_pending=1; rollback_ready=1; candidate=""; trap cleanup_runtime_install EXIT; false\n'
        env = dict(os.environ, rollback=str(rollback), binary_dir=str(binary_dir),
                   config_path=str(self.config), new=str(staging))
        result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(replacement.read_text(), "compatible replacement")
        self.assertIn("compatible replacement left installed", result.stderr)


    def test_rollback_refuses_schema2_binary_after_lifecycle_floor_appears(self):
        rollback = self.root / "rollback"
        rollback.mkdir()
        shutil.copyfile(self.config, rollback / "config.yaml")
        retained = rollback / "briqyardd"
        retained.write_text("#!/bin/sh\ncase $1 in\nassignment-capabilities) printf 'destination-assignment-v1\\n';;\nassigned-run-capabilities) printf 'assigned-run-v1\\n';;\n*) exit 2;;\nesac\n")
        retained.chmod(0o700)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        replacement = binary_dir / "briqyardd"
        replacement.write_text("lifecycle replacement")
        for floor in (None, {"schema": 2, "protocol": "assigned-run-v1"},
                      {"schema": 3, "protocol": "assigned-run-lifecycle-v1"}):
            with self.subTest(floor=floor):
                shutil.rmtree(self.data, ignore_errors=True)
                if floor:
                    self.evidence("meta/required-assignment-protocol.json", floor)
                staging = self.root / "staging"
                staging.mkdir()
                script = HELPERS + '\nactivation_pending=1; rollback_ready=1; candidate=""; trap cleanup_runtime_install EXIT; false\n'
                env = dict(os.environ, rollback=str(rollback), binary_dir=str(binary_dir),
                           config_path=str(self.config), new=str(staging))
                result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(replacement.read_text(), "lifecycle replacement")
                self.assertIn("compatible replacement left installed", result.stderr)

    def test_compatible_retained_binary_is_restored_with_current_floor(self):
        rollback = self.root / "rollback"
        rollback.mkdir()
        shutil.copyfile(self.config, rollback / "config.yaml")
        retained = rollback / "briqyardd"
        retained.write_text(FULL_DAEMON)
        retained.chmod(0o700)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        replacement = binary_dir / "briqyardd"
        replacement.write_text("replacement")
        self.evidence("meta/required-assignment-protocol.json",
                      {"schema": 1, "protocol": "destination-assignment-v1"})
        staging = self.root / "staging"
        staging.mkdir()
        script = HELPERS + '\nactivation_pending=1; rollback_ready=1; candidate=""; trap cleanup_runtime_install EXIT; false\n'
        env = dict(os.environ, rollback=str(rollback), binary_dir=str(binary_dir),
                   config_path=str(self.config), new=str(staging))
        result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(replacement.read_bytes(), retained.read_bytes())
        self.assertIn("previous executables and configuration restored", result.stderr)


if __name__ == "__main__":
    unittest.main()
