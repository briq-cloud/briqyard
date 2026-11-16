"""Offline wire, ordering and uncertainty checks; these do not qualify a native host."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mixed", Path(__file__).with_name("native-mixed-contract.py"))
mixed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mixed)


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.machines = {"m_seed": {"id": "m_seed", "name": "seed", "namespace": "fixture", "host": "local"},
                         "m_other": {"id": "m_other", "name": "unrelated", "namespace": "fixture"}}
        self.lost = False
        self.wrong_size = False
        self.allow_invalid = False
        self.failed_delete = False
        self.profile = True

    def call(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == "/hosts":
            return 200, [{"id": "local", "state": "ready", "runtime_classes": [],
                          "named_memory_profiles": ["init-ready-v1"] if self.profile else []}], {}
        if method == "GET" and path.startswith("/machines?"):
            return 200, list(self.machines.values()), {}
        if method == "GET" and path.endswith("/snapshots"):
            return 200, [{"id": "s_seed", "source_host": "h_intrinsic"}], {}
        if method == "PUT":
            return 409, {"code": "capability_unsupported"}, {}
        if method == "POST" and path == "/machines":
            size = body.get("size", {})
            if body.get("fork", {}).get("machine_id") == "m_seed":
                return 409, {"code": "capability_unsupported"}, {}
            named = "fork" in body
            invalid = (not named and not size.get("vcpus")) or body.get("runtime_class") == "nested" or body.get("volume", {}).get("size_gb") == 0
            if named and size.get("memory_mb") == 512:
                invalid = True
            if invalid and not self.allow_invalid:
                return 400, {"code": "invalid"}, {}
            if size.get("memory_mb") == 16384:
                return 503, {"code": "capacity"}, {}
            value = {**copy.deepcopy(body), "id": f"m_{len(self.calls)}", "namespace": body["tenant"],
                     "state": "running", "size": copy.deepcopy(mixed.clone.SIZE if named else size)}
            if self.wrong_size:
                value["size"]["cpu_millis"] = 999
            self.machines[value["id"]] = value
            if self.lost:
                raise TimeoutError()
            return 201, value, {"X-Briqyard-Host": "local"}
        if method == "POST" and path.endswith("/snapshots"):
            return 201, {"id": "s_named", "clone_profile": "init-ready-v1", "source_host": "h_intrinsic"}, {}
        machine = path.split("/")[2]
        if method == "DELETE":
            if self.failed_delete:
                raise TimeoutError()
            self.machines.pop(machine, None)
            return 204, None, {}
        return 200, self.machines[machine], {}


class MixedContractTests(unittest.TestCase):
    def test_matrix_wire_shapes_order_and_exact_cleanup(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        runner.run_mixed("m_seed", "s_seed")
        runner.cleanup()
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})
        requests = [body for method, path, body in api.calls if method == "POST" and path == "/machines"]
        direct = [body for body in requests if "-size-" in body["name"]]
        self.assertNotIn("size", direct[0])
        self.assertEqual(direct[1]["size"], {})
        self.assertEqual(direct[2]["size"], {"vcpus": 0, "memory_mb": 0})
        self.assertEqual([body["size"] for body in direct[3:]], [
            {"vcpus": 1, "memory_mb": 2048}, {"vcpus": 1, "memory_mb": 2048, "cpu_millis": 1000},
            {"vcpus": 1, "memory_mb": 128, "cpu_millis": 250},
            {"vcpus": 1, "memory_mb": 256, "cpu_millis": 500},
            {"vcpus": 1, "memory_mb": 512, "cpu_millis": 1000},
            {"vcpus": 2, "memory_mb": 4096, "cpu_millis": 2000},
            {"vcpus": 4, "memory_mb": 8192, "cpu_millis": 4000},
            {"vcpus": 8, "memory_mb": 16384, "cpu_millis": 8000}])
        self.assertNotIn("volume", direct[3])
        self.assertEqual([b["volume"] for b in requests if "volume" in b],
                         [{"size_gb": 0, "mount": "/data"}, {"size_gb": 2, "mount": "/data"}])
        named = [b for b in requests if "fork" in b and b["fork"]["machine_id"] != "m_seed"]
        self.assertNotIn("size", named[0])
        self.assertEqual(named[1]["size"], {"vcpus": 0, "memory_mb": 0})
        self.assertEqual(named[2]["size"], {"vcpus": 1, "memory_mb": 256})
        discovery = next(i for i, c in enumerate(api.calls) if c[:2] == ("GET", "/machines?namespace=fixture"))
        sandbox = next(i for i, c in enumerate(api.calls) if c[2] and c[2].get("fork", {}).get("machine_id") == "m_seed")
        self.assertLess(discovery, sandbox)
        lifecycle = [p.rsplit("/", 1)[1] for m, p, _ in api.calls if m == "POST" and ("/wait?" in p or p.endswith(("/stop", "/start")))]
        self.assertIn(["wait?for=running&timeout=120", "stop", "start", "wait?for=running&timeout=120"],
                      [lifecycle[i:i+4] for i in range(len(lifecycle)-3)])
        shell = Path(__file__).with_name("native-ci-upgrade.sh").read_text()
        self.assertLess(shell.index('native-mixed-contract.py" "$NS"'), shell.index('out=$(fleet host upgrade'))
        workflow = Path(__file__).parents[1].joinpath(".github/workflows/native-upgrade.yml").read_text()
        self.assertIn("native-logs/mixed-contract.json", workflow)

    def test_lost_create_is_unknown_discovered_and_never_replayed(self):
        api = FakeAPI()
        api.lost = True
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(TimeoutError):
            runner.case("lost", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE}, [[201, None]])
        # Metadata alone is insufficient to claim an unrelated name.
        api.machines["m_other"]["metadata"] = {"qualification": runner.prefix}
        runner.cleanup()
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)
        self.assertEqual(runner.receipts[0]["observed"], {"outcome": "unknown"})

    def test_wrong_cpu_and_unexpected_success_fail_and_are_cleaned(self):
        for attr in ("wrong_size", "allow_invalid"):
            api = FakeAPI()
            setattr(api, attr, True)
            runner = mixed.Mixed(api, "fixture")
            with self.assertRaises(mixed.clone.ContractFailure):
                runner.case("bad", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE},
                            [[400, "invalid"]] if attr == "allow_invalid" else [[201, None]])
            runner.cleanup()
            self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_uncertain_delete_fails_cleanup_without_create_replay(self):
        api = FakeAPI()
        api.failed_delete = True
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(TimeoutError):
            runner.case("delete", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE}, [[201, None]])
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)

    def test_missing_profile_is_explicitly_not_exercised(self):
        api = FakeAPI()
        api.profile = False
        runner = mixed.Mixed(api, "fixture")
        runner.run_mixed("m_seed", "s_seed")
        self.assertTrue(any("does not advertise" in gap for gap in runner.gaps))
        self.assertFalse(any(c[2] and "template_build" in c[2] for c in api.calls))
        runner.cleanup()

    def test_response_receipt_drops_untrusted_text(self):
        result = mixed.summary(400, {"code": "token secret", "error": "secret", "env": {"KEY": "secret"},
                                    "size": {"vcpus": "secret", "memory_mb": 256},
                                    "volume": {"size_gb": "secret", "mount": "secret"}},
                               {"x-briqyard-host": "secret"})
        self.assertNotIn("secret", str(result))
        self.assertEqual(result["size"], {"memory_mb": 256})

    def test_failed_run_persists_identity_unknown_case_and_cleanup_receipt(self):
        api = FakeAPI()
        api.lost = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = {"binaries": {"briqyardd": {"version": "briqyardd 1.2.3+abc", "sha256": "a" * 64}},
                        "configurationSha256": {"config.yaml": "b" * 64, "fleet.yaml": "c" * 64}}
            (root / "before").write_text(json.dumps(identity))
            (root / "after").write_text(json.dumps(identity))
            argv = ["native-mixed-contract.py", "fixture", "m_seed", "s_seed",
                    str(root / "before"), str(root / "after"), str(root / "receipt")]
            with patch.object(mixed.sys, "argv", argv), patch.dict(mixed.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted"}), \
                    patch.object(mixed.clone, "API", return_value=api), patch.object(mixed.signal, "alarm"):
                with self.assertRaises(TimeoutError):
                    mixed.main()
            receipt = json.loads((root / "receipt").read_text())
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["cleanup"], "complete")
            self.assertEqual(receipt["source"], identity)
            self.assertEqual(receipt["cases"][0]["observed"], {"outcome": "unknown"})
            self.assertTrue(receipt["notExercised"])
            self.assertEqual(set(api.machines), {"m_seed", "m_other"})
            self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)

    def test_capture_retains_hashes_and_versions_without_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for folder in (root / "usr/local/bin", root / "etc/briqyard"):
                folder.mkdir(parents=True)
            for name in ("briqyardd", "briqyard-fleet", "briqyard"):
                (root / "usr/local/bin" / name).write_bytes(b"exact-binary")
            for name in ("config.yaml", "fleet.yaml"):
                (root / "etc/briqyard" / name).write_text("token: private-value\n")
            def rooted(path):
                return root / str(path).lstrip("/")
            with patch.object(mixed, "Path", side_effect=rooted), \
                    patch.object(mixed.subprocess, "check_output", return_value=b"briqyardd 1.2.3+abc\n"):
                receipt = mixed.capture()
            self.assertNotIn("private-value", str(receipt))
            self.assertEqual(len(receipt["binaries"]), 3)
            self.assertEqual(receipt["configurationSha256"]["fleet.yaml"],
                             mixed.hashlib.sha256(b"token: private-value\n").hexdigest())


if __name__ == "__main__":
    unittest.main()
