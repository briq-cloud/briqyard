"""Exercise the seal test's actual configuration fixture, outside a native host."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

HACK = Path(__file__).parent


class NativeSealConfig(unittest.TestCase):
    def test_shared_host_setup_does_not_enable_template_recipes(self):
        setup = (HACK / "native-ci.sh").read_text()
        self.assertNotIn("c['templates']", setup)
        self.assertIn("trap 'journal_on_failure $?' EXIT", setup)

    def test_destination_create_explicitly_starts_both_seed_shapes(self):
        source = (HACK / "e2e-seals.sh").read_text()
        query = next(line.strip().split("'", 2)[1] for line in source.splitlines() if "sandbox_seed:{" in line)
        for volume in [None, {"size_gb": 1, "mount": "/work"}]:
            command = ["jq", "-n"]
            for key, value in {"ns": "seal-test", "image": "alpine", "name": "sealed-create-0", "source": "m_seed", "snap": "s_seed", "gen": "g_seed"}.items():
                command.extend(["--arg", key, value])
            command.extend(["--argjson", "volume", json.dumps(volume), query])
            request = json.loads(subprocess.check_output(command, text=True))
            self.assertIs(request.get("start"), True)
            self.assertEqual(request["volume"], volume)
            self.assertEqual(request["sandbox_seed"]["machine_id"], "m_seed")

    def test_seals_precede_the_only_final_summary(self):
        suite = (HACK / "e2e.sh").read_text()
        self.assertGreater(suite.rfind("suite_summary"), suite.index("e2e-seals.sh"))
        self.assertNotIn("suite_summary", (HACK / "e2e-storage.sh").read_text())

    def test_failed_api_response_body_is_printed(self):
        source = (HACK / "e2e-seals.sh").read_text()
        self.assertIn("seal_api() {", source)
        helper = "seal_api() {" + source.split("seal_api() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            curl = Path(directory) / "curl"
            curl.write_text("#!/bin/sh\nprintf '%s\\n' '{\"error\":\"fixture rejection\"}'\nexit 22\n")
            curl.chmod(0o700)
            command = 'CURL=("$1"); auth=();\n' + helper + 'seal_api http://fixture/v1/machines'
            result = subprocess.run(["bash", "-c", command, "fixture", str(curl)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 22)
            self.assertEqual(result.stdout, "")
            self.assertIn('{"error":"fixture rejection"}', result.stderr)

    def test_seal_scope_binds_authentication_and_the_installed_init(self):
        fixture = (HACK / "e2e-seals.sh").read_text().split("<<'PYCONFIG'\n", 1)[1].split("\nPYCONFIG", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.yaml"
            installed = root / "briqyard-init"
            installed.write_bytes(b"installed source init")
            config.write_text("token: ''\n")
            fixture = fixture.replace("'/etc/briqyard/config.yaml'", repr(str(config)))
            fixture = fixture.replace("'/usr/local/bin/briqyard-init'", repr(str(installed)))
            subprocess.run([sys.executable, "-c", fixture], check=True, cwd=root)
            c = yaml.safe_load(config.read_text())
            self.assertTrue(c["token"])
            self.assertTrue(c["templates"]["enabled"])
            digest = hashlib.sha256(installed.read_bytes()).hexdigest()
            self.assertEqual(c["templates"]["init_ready_init_sha256"], digest)
            recipes = c["templates"]["sandbox_recipes"]
            self.assertEqual([r["volume_gb"] for r in recipes], [0, 1])
            for recipe in recipes:
                self.assertEqual(recipe["init_sha256"], digest)
                self.assertRegex(recipe["image"], r"^docker.io/library/alpine@sha256:[0-9a-f]{64}$")
                self.assertRegex(recipe["image_config_digest"], r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
