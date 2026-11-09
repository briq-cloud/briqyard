"""Exercise the seal test's configuration and identity checks outside a native host."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

HACK = Path(__file__).parent


class NativeSealIdentity(unittest.TestCase):
    def setUp(self):
        self.source = (HACK / "e2e-seals.sh").read_text()
        self.network = self.source.split("<<'PYNETWORK'\n", 1)[1].split("\nPYNETWORK", 1)[0]
        self.views = [
            {"name": name, "hostname": name + ".internal", "ip": f"10.64.1.{n}",
             "memory_origin": {"source_machine": "m_seed", "stage": "active", "snapshot": "s_seed",
                               "generation": "g_seed", "ram_marker": "shared-ram",
                               "identity": {"ip": f"10.64.1.{n}/24", "hostname": name,
                                            "mac": [2, 0, 0, 0, 0, n]}}}
            for n, name in [(3, "first"), (4, "second")]
        ]
        self.observations = [
            f"02:00:00:00:00:{n:02x}\n10.64.1.{n}/24\n{name}\n"
            f"default via 10.64.1.1 dev eth0\n10.64.1.0/24 dev eth0 scope link src 10.64.1.{n}"
            for n, name in [(3, "first"), (4, "second")]
        ]

    def network_check(self, views, observations):
        args = [{"id": "m_seed", "ip": "10.64.1.2", "snapshot": "s_seed", "generation": "g_seed"},
                *views, {"subnet": "10.64.1.0/24", "router": "10.64.1.1"}]
        return subprocess.run([sys.executable, "-c", self.network, *map(json.dumps, args), *observations],
                              capture_output=True, text=True)

    def test_short_guest_hostname_matches_public_dns_name(self):
        result = self.network_check(self.views, self.observations)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_network_contract_rejects_independent_identity_and_route_mismatches(self):
        for field, value in [("ip", "10.64.1.9"), ("hostname", "other.internal"), ("name", "other")]:
            with self.subTest(public_field=field):
                views = copy.deepcopy(self.views)
                views[0][field] = value
                self.assertNotEqual(self.network_check(views, self.observations).returncode, 0)
        for field, value in [("ip", "10.64.1.9/24"), ("ip", "10.64.1.3/25"),
                             ("hostname", "other"), ("mac", [2, 0, 0, 0, 0, 9])]:
            with self.subTest(receipt_field=field, value=value):
                views = copy.deepcopy(self.views)
                views[0]["memory_origin"]["identity"][field] = value
                self.assertNotEqual(self.network_check(views, self.observations).returncode, 0)
        for before, after in [("02:00:00:00:00:03", "06:b1:0a:40:01:02"),
                              ("10.64.1.3/24", "10.64.1.3/25"),
                              ("10.64.1.3/24", "10.64.1.9/24"), ("\nfirst\n", "\nother\n"),
                              ("via 10.64.1.1", "via 10.64.1.9"), ("dev eth0", "dev eth1"),
                              ("src 10.64.1.3", "src 10.64.1.9"),
                              ("10.64.1.0/24", "10.64.2.0/24")]:
            with self.subTest(guest=before, replacement=after):
                observations = self.observations.copy()
                observations[0] = observations[0].replace(before, after)
                self.assertNotEqual(self.network_check(self.views, observations).returncode, 0)

    def test_source_exec_requires_specific_daemon_refusal_without_nonce(self):
        line = next(line for line in self.source.splitlines() if 'check "seed $seal_gb source keeps' in line)
        check = line.split("'", 1)[1].rsplit("'", 1)[0]
        helper = "seal_source_blocked() {" + self.source.split("seal_source_blocked() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        command = helper + 'seal_source_rc=$1; seal_source_reply=$2; seal_source_nonce=source-nonce; ' + check
        refusal = "error: sealed template builder permits status, memory seal and destroy only (conflict)"
        for code, reply, accepted in [(1, refusal, True),
                                      (1, refusal[:-1] + ", request abc-123)", True),
                                      (0, refusal, False), (2, refusal, False),
                                      (1, "error: connection refused", False),
                                      (1, refusal.replace("conflict", "internal"), False),
                                      (1, "error: clone barrier: operation unavailable (internal)", False),
                                      (1, "source-nonce\n" + refusal, False)]:
            with self.subTest(code=code, reply=reply):
                result = subprocess.run(["bash", "-c", command, "fixture", str(code), reply], capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)


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
            self.assertEqual(request["cmd"], ["/bin/sh", "-ec", "sleep infinity"])
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
            config.write_text("token: ''\ninit: " + json.dumps(str(installed)) + "\n")
            fixture = fixture.replace("'/etc/briqyard/config.yaml'", repr(str(config)))
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
