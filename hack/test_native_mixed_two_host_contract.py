"""Offline fixture checks; no native or mixed-version qualification is claimed."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

spec = importlib.util.spec_from_file_location("two_host", Path(__file__).with_name("native-mixed-two-host-contract.py"))
two = importlib.util.module_from_spec(spec)
spec.loader.exec_module(two)


class API:
    def __init__(self):
        self.calls = []
        self.machines = {}
        self.wrong_host = False
        self.lose_create = False

    def call(self, method, path, body=None, headers=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == "/hosts":
            return 200, [{"id": "local", "region": "dev", "state": "ready"},
                         {"id": "fc2", "region": "mixed-second", "state": "ready"}], {}
        if method == "POST" and path == "/machines":
            if self.lose_create:
                raise TimeoutError()
            host = next((m["host"] for m in self.machines.values() if m["namespace"] == body["tenant"]),
                        "local" if body["region"] == "dev" else "fc2")
            if self.wrong_host:
                host = "unexpected"
            machine = {"id": "m_" + str(len(self.machines)), "namespace": body["tenant"],
                       "name": body["name"], "metadata": body["metadata"], "host": host,
                       "state": "running", "size": body["size"]}
            self.machines[machine["id"]] = machine
            return 201, copy.deepcopy(machine), {"x-briqyard-host": host}
        if method == "GET" and path.startswith("/machines?"):
            return 200, [copy.deepcopy(m) for m in self.machines.values()
                         if m["namespace"] == path.split("=", 1)[1]], {}
        if path.startswith("/machines/"):
            machine = self.machines[path.split("/")[2]]
            if method == "GET":
                return 200, copy.deepcopy(machine), {"x-briqyard-host": machine["host"]}
            if path.endswith("/exec"):
                return 200, {"exit_code": 0, "stdout": machine["name"] + "\n"}, {}
            if method == "DELETE":
                del self.machines[machine["id"]]
                return 204, None, {}
            return 200, copy.deepcopy(machine), {"x-briqyard-host": machine["host"]}
        if method == "DELETE" and path.startswith("/namespaces/"):
            return 204, None, {}
        raise AssertionError((method, path))


class PairTests(unittest.TestCase):
    def test_fleet_rewrite_preserves_the_explicit_plain_http_setting(self):
        import yaml
        script = Path(__file__).with_name("native-mixed-two-host.sh").read_text()
        block = script.split("sudo python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fleet.yaml"
            config.write_text("listen: 127.0.0.1:7430\ntls: off\n"
                              "hosts:\n  - id: local\n    region: dev\n")
            code = block.replace("Path('/etc/briqyard/fleet.yaml')", "Path(config_path)")
            exec(compile(code, "native-mixed-two-host.sh:config", "exec"),
                 {"config_path": str(config)})
            rewritten = yaml.safe_load(config.read_text())
            self.assertEqual("off", rewritten["tls"])
            self.assertEqual("0.0.0.0:7430", rewritten["listen"])
            self.assertEqual(["local", "fc2"], [host["id"] for host in rewritten["hosts"]])

    def test_two_regions_and_existing_namespaces_reach_both_hosts(self):
        api = API()
        runner = two.TwoHost(api)
        runner.run_pair()
        self.assertEqual(4, len(runner.created))
        creates = [body for method, path, body in api.calls if method == "POST" and path == "/machines"]
        self.assertEqual(["dev", "", "mixed-second", ""], [body["region"] for body in creates])
        runner.cleanup()
        self.assertEqual({}, api.machines)
        self.assertEqual(4, sum(method == "POST" and path == "/machines"
                                for method, path, _ in api.calls))

    def test_candidate_cli_reads_typed_machine_after_exact_route_check(self):
        api = API()
        runner = two.TwoHost(api)
        runner.run_pair()
        def get(argv):
            value = copy.deepcopy(api.machines[argv[-1]])
            value.pop("host")  # CLI serializes Machine, not the fleet response extension.
            return value
        with patch.object(two, "captured_command", side_effect=get) as command:
            runner.check_cli()
            self.assertEqual(4, command.call_count)
        with patch.object(two, "captured_command", return_value={"host": "other"}):
            with self.assertRaises(two.clone.ContractFailure):
                runner.check_cli()
        runner.cleanup()

    def test_fixture_retirement_is_empty_only_and_never_replayed(self):
        calls = []
        class RetireAPI:
            def call(self, method, path, body=None):
                calls.append((method, path))
                if method == "GET":
                    return 200, [{"id": "local"}, {"id": "fc2", "machines": 0, "namespaces": []}], {}
                return 200, {"id": "fc2", "state": "retired"}, {}
        two.retire_fixture_host(RetireAPI())
        self.assertEqual([("GET", "/hosts"), ("POST", "/hosts/fc2/retire")], calls)
        with patch.object(RetireAPI, "call", return_value=(200, [
                {"id": "local"}, {"id": "fc2", "machines": 1, "namespaces": []}], {})), \
                patch.object(two.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaises(two.clone.ContractFailure):
                two.retire_fixture_host(RetireAPI())
        calls.clear()
        def lost(method, path, body=None):
            calls.append((method, path))
            if method == "GET":
                return 200, [{"id": "local"}, {"id": "fc2", "machines": 0, "namespaces": []}], {}
            raise TimeoutError()
        with patch.object(RetireAPI, "call", side_effect=lost):
            with self.assertRaises(TimeoutError):
                two.retire_fixture_host(RetireAPI())
        self.assertEqual(1, sum(method == "POST" for method, _ in calls))

    def test_pre_contract_cleanup_needs_no_receipt_but_started_contract_does(self):
        class EmptyAPI:
            def __init__(self, origin):
                self.posts = 0
            def call(self, method, path, body=None):
                if method == "GET":
                    return 200, [{"id": "local"}], {}
                self.posts += 1
                raise AssertionError("Absent fixture host must not be mutated")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(two.os, "environ", {"RUNNER_ENVIRONMENT": "github-hosted"}), \
                patch.object(two.clone, "API", EmptyAPI), \
                patch.object(two.Path, "read_bytes", side_effect=FileNotFoundError()):
            for mode in ("--fixture-empty", "--retire-fixture-host"):
                with patch.object(two.sys, "argv", ["contract", mode, "--before-contract"]):
                    two.main()
                with patch.object(two.sys, "argv", ["contract", mode]):
                    with self.assertRaises(FileNotFoundError):
                        two.main()

    def test_capture_rejects_excess_output_and_invalid_json(self):
        for script in ("print('x'*16385)", "print('not json')", "raise SystemExit(1)"):
            with self.subTest(script=script), self.assertRaises(Exception):
                two.captured_command([sys.executable, "-c", script])
        self.assertEqual({"ok": True}, two.captured_command([
            sys.executable, "-c", "print('{\"ok\":true}')"]))

    def test_wrong_route_fails_but_retains_exact_cleanup_ownership(self):
        api = API()
        api.wrong_host = True
        runner = two.TwoHost(api)
        with self.assertRaises(two.clone.ContractFailure):
            runner.run_pair()
        runner.cleanup()
        self.assertEqual({}, api.machines)

    def test_lost_create_is_not_replayed_or_claimed_clean(self):
        api = API()
        api.lose_create = True
        runner = two.TwoHost(api)
        with self.assertRaises(TimeoutError):
            runner.run_pair()
        with self.assertRaises(two.clone.ContractFailure):
            runner.cleanup()
        self.assertEqual(1, sum(method == "POST" and path == "/machines"
                                for method, path, _ in api.calls))

    def test_published_and_running_daemon_and_candidate_assets_are_bound(self):
        digest = lambda value: hashlib.sha256(value).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = {name: digest(name.encode()) for name in ("briqyard", "briqyard-fleet", "briqyardd")}
            for name in ("briqyard", "briqyard-fleet"):
                (root / (name + "-linux-x86_64")).write_bytes(name.encode())
            (root / "SHA256SUMS-x86_64").write_text("".join(
                sha + "  " + name + "-linux-x86_64\n" for name, sha in binaries.items()))
            previous = root / "previous.sums"
            previous.write_text(binaries["briqyardd"] + "  briqyardd-linux-x86_64\n")
            local = {"binaries": {name: {"sha256": sha, "version": "briqyardd 0.2.14+source"}
                                  for name, sha in binaries.items()},
                     "processSha256": {name: binaries[name] for name in ("briqyardd", "briqyard-fleet")},
                     "configurationSha256": {"config.yaml": "a" * 64, "fleet.yaml": "b" * 64}}
            second = {"sha256": binaries["briqyardd"], "processSha256": binaries["briqyardd"],
                      "version": "briqyardd 0.2.14+source", "configurationSha256": "c" * 64}
            two.bind_pair(local, second, "v0.2.14", root, previous)
            for field in ("sha256", "processSha256", "version", "configurationSha256"):
                bad = {**second, field: "unexpected"}
                with self.assertRaises(two.clone.ContractFailure):
                    two.bind_pair(local, bad, "v0.2.14", root, previous)
            (root / "briqyard-fleet-linux-x86_64").write_bytes(b"changed")
            with self.assertRaises(two.clone.ContractFailure):
                two.bind_pair(local, second, "v0.2.14", root, previous)


if __name__ == "__main__":
    unittest.main()
