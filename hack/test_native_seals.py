"""Exercise the seal test's actual configuration fixture, outside a native host."""
import hashlib
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
