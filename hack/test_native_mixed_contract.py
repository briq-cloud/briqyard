"""Offline wire, ordering and uncertainty checks; these do not qualify a native host."""
import copy
import hashlib
import importlib.util
import json
import io
import os
import subprocess
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
        self.admissions = {}
        self.gateway = False
        self.bad_dispatch = False
        self.bad_decision = False
        self.bad_network = False
        self.bad_route = False
        self.ignore_reservations = False
        self.allow_bad_admission = False
        self.bad_hold_overhead = False
        self.cancel_all_holds = False
        self.double_count_dispatch = False
        self.stale_seed_reports = 0
        self.seed_report_charges = []
        self.nested = False
        self.wrong_class = False
        self.bad_nested_exec = False

    def call(self, method, path, body=None, headers=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == "/hosts":
            stale_seed = (self.seed_report_charges.pop(0) if self.seed_report_charges
                          else 512 if self.stale_seed_reports else 0)
            self.stale_seed_reports = max(0, self.stale_seed_reports - 1)
            overhead = 0 if self.bad_hold_overhead else 256
            held = sum(r["size"]["memory_mb"] + overhead
                       for p, a in self.admissions.items() if "-account-" in p and not a.get("cancelled")
                       and (not a.get("dispatched") or self.double_count_dispatch)
                       for r in a["body"]["requirements"])
            actual = sum(m["size"]["memory_mb"] + 256 for m in self.machines.values()
                         if m.get("name", "").endswith("-holds-dispatch"))
            return 200, [{"id": "local", "state": "ready", "runtime_classes": [{"name": "nested", "nested": True}] if self.nested else [],
                          "named_memory_profiles": ["init-ready-v1", "sandbox-ready-v1"] if self.profile else ["sandbox-ready-v1"],
                          "egress_siblings_v1": True, "warm_pool_profiles": [],
                          "memory_policy": {"version": 1, "vmm_overhead_mb": 256},
                          "last_seen": str(len(self.calls)),
                          "capacity": {"memory_mb": 12288}, "used": {"memory_mb": 4096 + stale_seed + held + actual}}], {}
        if method == "GET" and path.startswith("/machines?"):
            return 200, [v for v in self.machines.values() if v["namespace"] == path.split("=")[1]], {}
        if path == "/namespaces":
            return 200, [{"id": "fixture", "host": "local"}], {}
        if method == "DELETE" and path.startswith("/namespaces/") and path.count("/") == 2:
            return 204, None, {}
        if "/warm-pools/" in path:
            return 409, {"code": "capability_unsupported"}, {}
        if method == "GET" and path.endswith("/snapshots"):
            return 200, [{"id": "s_seed", "source_host": "h_intrinsic"}], {}
        if "/admissions/" in path or "/sandbox-admissions/" in path:
            if method == "DELETE":
                if self.admissions.get(path, {}).get("dispatched"):
                    return 409, {"code": "conflict"}, {}
                if self.cancel_all_holds and "-account-" in path:
                    for item in self.admissions.values():
                        item["cancelled"] = True
                self.admissions[path] = {"cancelled": True}
                return 204, None, {}
            old = self.admissions.get(path)
            if old and (old.get("cancelled") or old["body"] != body):
                return 409, {"code": "conflict"}, {}
            if "requirements" in body:
                r = body["requirements"][-1]
                size = r.get("size", {})
                if not self.allow_bad_admission:
                    if not all(k in size for k in ("vcpus", "memory_mb")):
                        return 422, None, {}
                    cpu, memory = size["vcpus"], size["memory_mb"]
                    if not (1 <= cpu <= 32 and 128 <= memory <= 262144 and
                            1 <= size.get("cpu_millis", cpu * 1000) <= cpu * 1000):
                        return 400, {"code": "invalid"}, {}
                    if sum(r["size"]["memory_mb"] + 256 for r in body["requirements"]) + 4096 > 12288:
                        return 503, {"code": "capacity"}, {}
                if (r.get("runtime_class") == "nested" and not self.nested) or (r.get("memory_profile") and
                        r["memory_profile"] not in (["init-ready-v1", "sandbox-ready-v1"] if self.profile else ["sandbox-ready-v1"])):
                    return 503, {"code": "capacity"}, {}
                if not self.ignore_reservations and any("pressure-0" in p and not a.get("cancelled") for p, a in self.admissions.items()):
                    return 503, {"code": "capacity"}, {}
                value = {"host": "other" if self.bad_decision else "local", "region": "dev", "binding": "existing", "mode": "cold"}
            else:
                value = {"mode": "sandbox-seed"}
            self.admissions[path] = {"body": copy.deepcopy(body), "dispatched": False}
            return 200, value, {}
        if "/gateway" in path:
            if method == "DELETE":
                self.gateway = False
                return 204, None, {}
            self.gateway = True
            self.admissions["/namespaces/fixture/admissions/" + path.split("placement_request_id=")[1]]["dispatched"] = True
            return 200, {}, {"X-Briqyard-Host": "local"}
        if path == "/namespaces/fixture":
            return 200, {"host": "local", "gateway": {} if self.gateway else None}, {}
        if method == "POST" and path == "/machines":
            if headers and headers.get("x-briqyard-placement-request-id"):
                identity = headers["x-briqyard-placement-request-id"]
                if body.get("region") != "dev" and not self.bad_dispatch:
                    return 409, {"code": "conflict"}, {}
                kind = "sandbox-admissions" if "sandbox_seed" in body else "admissions"
                self.admissions[f"/namespaces/fixture/{kind}/{identity}"]["dispatched"] = True
            size = body.get("size", {})
            if body.get("fork", {}).get("machine_id") == "m_seed":
                return 409, {"code": "capability_unsupported"}, {}
            named = "fork" in body
            if named and body["tenant"] != "fixture" and not self.allow_invalid:
                return 400, {"code": "invalid"}, {}
            invalid = (not named and not size.get("vcpus")) or (body.get("runtime_class") == "nested" and not self.nested) or body.get("volume", {}).get("size_gb") == 0
            if named and size.get("memory_mb") == 512:
                invalid = True
            if invalid and not self.allow_invalid:
                return 400, {"code": "invalid"}, {}
            if size.get("memory_mb") == 16384:
                return 503, {"code": "capacity"}, {}
            value = {**copy.deepcopy(body), "id": f"m_{len(self.calls)}", "namespace": body["tenant"],
                     "state": "running", "ready": True, "ip": f"10.64.0.{2 + len(self.calls) % 200}", "host": "local", "size": copy.deepcopy(mixed.clone.SIZE if named else size)}
            if "sandbox_seed" in body:
                value["size"] = copy.deepcopy(size)
            if self.wrong_size:
                value["size"]["cpu_millis"] = 999
            if self.wrong_class:
                value["runtime_class"] = "default"
            self.machines[value["id"]] = value
            if self.lost:
                raise TimeoutError()
            return 201, value, {"X-Briqyard-Host": "local"}
        if method == "POST" and path.endswith("/snapshots"):
            return 201, {"id": "s_named", "clone_profile": "init-ready-v1", "source_host": "h_intrinsic"}, {}
        machine = path.split("/")[2]
        if method == "POST" and path.endswith("/exec"):
            cmd = body["cmd"]
            out = ""
            if cmd == ["sh", "-ec", mixed.NESTED_CHECK]:
                out = "wrong" if self.bad_nested_exec else "nested-ready"
            elif "wget" == cmd[0]:
                out = "mixed-gateway" if "gateway.internal" in cmd[-1] else ("mixed-foreign" if "127.0.0.1" in cmd[-1] else "mixed-sibling")
            elif len(cmd) > 2 and cmd[2] == mixed.ON_LINK_SCRIPT:
                out = "wrong-route" if self.bad_route else "on-link"
            else:
                out = "wrong" if self.bad_network else "denied"
            return 200, {"stdout": out, "exit_code": 0}, {}
        if method == "DELETE":
            if self.failed_delete:
                raise TimeoutError()
            self.machines.pop(machine, None)
            return 204, None, {}
        return 200, self.machines[machine], {}


class MixedContractTests(unittest.TestCase):
    def test_hold_baseline_waits_for_deleted_seed_charge_to_settle(self):
        api = FakeAPI()
        api.stale_seed_reports = 1
        runner = mixed.Mixed(api, "fixture")
        runner.hold_accounting()
        observations = {r["case"]: r["observed"] for r in runner.receipts}
        self.assertEqual(observations["holds-baseline-pending"]["memoryMb"], 4608)
        self.assertEqual(observations["holds-baseline"], {"memoryMb": 4096, "freshHeartbeat": True})
        self.assertEqual(observations["holds-final-release"]["memoryMb"], 4096)

    def test_hold_baseline_drains_poll_started_before_seed_deletion(self):
        api = FakeAPI()
        # DELETE refresh settled usage without moving last_seen. The first new
        # heartbeat is an in-flight poll with a pre-DELETE status snapshot.
        api.seed_report_charges = [0, 512, 0]
        runner = mixed.Mixed(api, "fixture")
        runner.hold_accounting()
        observations = {r["case"]: r["observed"] for r in runner.receipts}
        self.assertEqual(observations["holds-baseline-pending"]["memoryMb"], 4096)
        self.assertEqual(observations["holds-baseline-drain"]["memoryMb"], 4608)
        self.assertEqual(observations["holds-baseline"], {"memoryMb": 4096, "freshHeartbeat": True})
        self.assertEqual(observations["holds-final-release"]["memoryMb"], 4096)

    def test_missing_running_hold_machine_does_not_count_as_tested_deletion(self):
        class MissingMachineAPI(FakeAPI):
            def call(self, method, path, body=None, headers=None):
                machine = self.machines.get(path.rsplit("/", 1)[-1], {})
                if method == "GET" and machine.get("name", "").endswith("-holds-dispatch"):
                    self.calls.append((method, path, copy.deepcopy(body)))
                    return 404, {"code": "not_found"}, {}
                return super().call(method, path, body, headers)
        api = MissingMachineAPI()
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.hold_accounting()
        self.assertEqual(len(runner.created), 1)
        self.assertFalse(any(m == "DELETE" and p.startswith("/machines/") for m, p, _ in api.calls))
        self.assertFalse(any(r["case"] == "holds-final-release" for r in runner.receipts))

    def test_final_release_drains_poll_started_before_machine_deletion(self):
        class StaleDeletionAPI(FakeAPI):
            def call(self, method, path, body=None, headers=None):
                deleting = method == "DELETE" and path.startswith("/machines/")
                result = super().call(method, path, body, headers)
                if deleting:
                    # DELETE refresh settles the dispatched machine's 512+256
                    # charge; one already-running poll can publish it again.
                    self.seed_report_charges = [0, 768, 0]
                return result
        runner = mixed.Mixed(StaleDeletionAPI(), "fixture")
        runner.hold_accounting()
        observations = {r["case"]: r["observed"] for r in runner.receipts}
        self.assertEqual(observations["holds-deletion-pending"]["memoryMb"], 4096)
        self.assertEqual(observations["holds-deletion-drain"]["memoryMb"], 4864)
        self.assertEqual(observations["holds-final-release"]["memoryMb"], 4096)

    def test_independent_hold_charges_release_and_dispatch_reflection(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        runner.hold_accounting()
        self.assertEqual(runner.receipts[-1]["observed"]["memoryMb"], 4096)
        self.assertTrue(all(a.get("cancelled") or a.get("dispatched") for a in api.admissions.values()))
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)
        self.assertFalse(runner.created)

    def test_hold_accounting_detects_wrong_overhead_cross_cancel_and_double_charge(self):
        for fault in ("bad_hold_overhead", "cancel_all_holds", "double_count_dispatch"):
            with self.subTest(fault=fault):
                api = FakeAPI()
                setattr(api, fault, True)
                runner = mixed.Mixed(api, "fixture")
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.hold_accounting()
                runner.cleanup()
    def test_nested_direct_and_admitted_guests_are_consumed_and_checked(self):
        api = FakeAPI()
        api.nested = True
        runner = mixed.Mixed(api, "fixture", nested=True)
        runner.nested_guest()
        runner.nested_guest(admitted=True)
        posts = [(p, b) for m, p, b in api.calls if m == "POST" and p == "/machines"]
        self.assertEqual(len(posts), 2)
        self.assertTrue(all(b["runtime_class"] == "nested" for _, b in posts))
        admission = next(iter(api.admissions.values()))
        self.assertTrue(admission["dispatched"])
        self.assertEqual(admission["body"]["requirements"], [{"role": "consumer", "size": mixed.WIRE_SIZE,
                                                              "runtime_class": "nested"}])
        self.assertEqual(sum(m == "POST" and p.endswith("/exec") for m, p, _ in api.calls), 2)
        self.assertEqual(runner.created, [])
        runner.cleanup()

    def test_nested_fixture_runs_the_full_existing_matrix(self):
        api = FakeAPI()
        api.nested = True
        runner = mixed.Mixed(api, "fixture", nested=True)
        runner.run_mixed("m_seed", "s_seed")
        self.assertTrue(any(r["case"] == "nested-admitted-exec" for r in runner.receipts))
        runner.cleanup()

    def test_nested_capability_is_required_before_any_mutation(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture", nested=True)
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.run_mixed("m_seed", "s_seed")
        self.assertEqual([m for m, _, _ in api.calls], ["GET"])

    def test_nested_misclassification_or_failed_execution_fails_and_cleans(self):
        for fault in ("wrong_class", "bad_nested_exec", "bad_decision"):
            with self.subTest(fault=fault):
                api = FakeAPI()
                api.nested = True
                setattr(api, fault, True)
                runner = mixed.Mixed(api, "fixture", nested=True)
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.nested_guest(admitted=True)
                runner.cleanup()
                self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_nested_lost_create_is_not_replayed_and_cleanup_stays_unconfirmed(self):
        api = FakeAPI()
        api.nested = api.lost = True
        runner = mixed.Mixed(api, "fixture", nested=True)
        with self.assertRaises(TimeoutError):
            runner.nested_guest(admitted=True)
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertTrue(runner.cleanup_unconfirmed)
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_nested_candidate_assets_require_complete_matching_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {name: b"class-file" for name in mixed.NESTED_ASSETS}
            values[mixed.NESTED_ASSETS[-1]] = b'{"arch":"x86_64","kernel_release":"test-kernel"}'
            for name, value in values.items():
                (root / name).write_bytes(value)
            (root / "SHA256SUMS-x86_64").write_text("".join(
                hashlib.sha256(value).hexdigest() + "  " + name + "\n" for name, value in values.items()))
            self.assertEqual(set(mixed.nested_assets(root)), set(mixed.NESTED_ASSETS))
            for name in mixed.NESTED_ASSETS:
                (root / name).write_bytes(b"changed")
                with self.assertRaises(mixed.clone.ContractFailure):
                    mixed.nested_assets(root)
                (root / name).write_bytes(values[name])
            (root / mixed.NESTED_ASSETS[0]).unlink()
            with self.assertRaises(FileNotFoundError):
                mixed.nested_assets(root)

    def test_strict_denial_accepts_neighbor_drop_but_not_other_failures(self):
        cases = [("wget: download timed out", 1, "denied", 0),
                 ("wget: Host is unreachable", 1, "denied", 0),
                 ("wget: No route to host", 1, "denied", 0),
                 ("wget: Connection refused", 1, "unexpected-refusal", 1),
                 ("private-error-detail", 1, "unexpected-refusal", 1),
                 ("mixed-sibling", 0, "unexpected-success", 1),
                 ("wget: Host is unreachable", 2, "unexpected-exit", 1)]
        with tempfile.TemporaryDirectory() as directory:
            wget = Path(directory) / "wget"
            wget.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_WGET_OUTPUT" >&2\nexit "$TEST_WGET_EXIT"\n')
            wget.chmod(0o700)
            for output, status, expected, exit_code in cases:
                with self.subTest(output=output, status=status):
                    result = subprocess.run(["/bin/sh", "-c", mixed.STRICT_DENIAL_SCRIPT, "sh", "http://10.64.0.4:8000/"],
                                            env={**os.environ, "PATH": directory, "TEST_WGET_OUTPUT": output,
                                                 "TEST_WGET_EXIT": str(status)}, capture_output=True, text=True, timeout=5)
                    self.assertEqual((result.stdout.strip(), result.returncode), (expected, exit_code))
                    self.assertEqual(result.stderr, "")

    def test_on_link_control_refuses_wrong_route_source_and_interface(self):
        cases = [("10.64.0.4 dev eth0 src 10.64.0.3 uid 0", True),
                 ("10.64.0.4 via 10.64.0.1 dev eth0 src 10.64.0.3", False),
                 ("10.64.0.5 dev eth0 src 10.64.0.3", False),
                 ("10.64.0.4 dev eth1 src 10.64.0.3", False),
                 ("10.64.0.4 dev eth0 src 10.64.0.9", False), ("", False)]
        with tempfile.TemporaryDirectory() as directory:
            ip = Path(directory) / "ip"
            ip.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_ROUTE"\n')
            ip.chmod(0o700)
            for route, expected in cases:
                result = subprocess.run(["/bin/sh", "-c", mixed.ON_LINK_SCRIPT, "sh", "10.64.0.4", "10.64.0.3"],
                                        env={**os.environ, "PATH": directory, "TEST_ROUTE": route},
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0 and result.stdout.strip() == "on-link", expected)

    def test_strict_denial_requires_same_target_positive_and_route_first(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        runner.placement(api.call("GET", "/hosts")[1][0])
        labels = [case["case"] for case in runner.receipts]
        self.assertLess(labels.index("sibling-allowed"), labels.index("strict-sibling-route"))
        self.assertLess(labels.index("strict-sibling-route"), labels.index("strict-sibling-denied"))
        runner.cleanup()
        api = FakeAPI()
        api.bad_route = True
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.placement(api.call("GET", "/hosts")[1][0])
        self.assertNotIn("strict-sibling-denied", [case["case"] for case in runner.receipts])
        runner.cleanup()

    def test_denial_diagnostics_preserve_timeout_only_acceptance(self):
        cases = [("wget: download timed out", 1, "denied", 0),
                 ("wget: Host is unreachable", 1, "unreachable", 1),
                 ("private-error-detail", 1, "unexpected-refusal", 1),
                 ("mixed-sibling", 0, "unexpected-success", 1),
                 ("private-error-detail", 2, "unexpected-exit", 1)]
        with tempfile.TemporaryDirectory() as directory:
            wget = Path(directory) / "wget"
            wget.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_WGET_OUTPUT" >&2\nexit "$TEST_WGET_EXIT"\n')
            wget.chmod(0o700)
            for output, status, expected, exit_code in cases:
                with self.subTest(expected=expected):
                    result = subprocess.run(["/bin/sh", "-c", mixed.DENIAL_SCRIPT, "sh", "http://127.0.0.1:1/"],
                                            env={**os.environ, "PATH": directory, "TEST_WGET_OUTPUT": output,
                                                 "TEST_WGET_EXIT": str(status)}, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.stdout.strip(), expected)
                    self.assertEqual(result.returncode, exit_code)
                    self.assertEqual(result.stderr, "")
                    self.assertNotIn("private-error-detail", result.stdout)

    def test_denial_receipt_keeps_fixed_reason_and_still_fails(self):
        class Unreachable(FakeAPI):
            def call(self, method, path, body=None, headers=None):
                if path.endswith("/exec"):
                    return 200, {"exit_code": 1, "stdout": "unreachable"}, {}
                return super().call(method, path, body, headers)

        runner = mixed.Mixed(Unreachable(), "fixture")
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.exec_check("strict-sibling-denied", "m_seed", ["unused"], "denied")
        self.assertEqual(runner.receipts[-1]["observed"],
                         {"status": 200, "exitCode": 1, "outputMatches": False, "denialCode": "unreachable"})

    def test_cleanup_refuses_changed_machine_identity(self):
        for field, value in (("id", "m_other"), ("namespace", "foreign"),
                             ("name", "unrelated"), ("metadata", {"qualification": "foreign"})):
            with self.subTest(field=field):
                api = FakeAPI()
                runner = mixed.Mixed(api, "fixture")
                machine = runner.case("owned", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE},
                                      [[201, None]], keep=True)
                api.machines[machine][field] = value
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.cleanup()
                self.assertIn(machine, api.machines)
                self.assertFalse(any(m == "DELETE" and p == "/machines/" + machine for m, p, _ in api.calls))

    def test_create_answer_cannot_authorize_unrelated_machine_deletion(self):
        class WrongID(FakeAPI):
            def call(self, method, path, body=None, headers=None):
                status, value, result_headers = super().call(method, path, body, headers)
                if method == "POST" and path == "/machines" and status == 201:
                    value = {**value, "id": "m_other"}
                return status, value, result_headers

        api = WrongID()
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.case("wrong-id", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE}, [[201, None]])
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertIn("m_other", api.machines)
        self.assertFalse(any(m == "DELETE" and p == "/machines/m_other" for m, p, _ in api.calls))

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
        named = [b for b in requests if "fork" in b and b["fork"]["machine_id"] != "m_seed" and b["tenant"] == "fixture"]
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

    def test_placement_resource_axes_and_exact_refusals(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        runner.placement(api.call("GET", "/hosts")[1][0])
        runner.cleanup()
        receipts = {r["case"]: r for r in runner.receipts}
        for index, size in enumerate(mixed.SIZES):
            receipt = receipts["admit-size-" + str(index)]
            gateway, consumer = receipt["request"]["json"]["requirements"]
            self.assertEqual(gateway, {"role": "gateway", "size": mixed.WIRE_SIZE, "runtime_class": "default"})
            if size is None:
                self.assertNotIn("size", consumer)
            else:
                self.assertEqual(consumer["size"], size)
            self.assertNotIn("volume_gb", consumer)
            self.assertEqual(consumer["runtime_class"], "default")
        self.assertEqual([receipts["admit-size-" + str(i)]["observed"]["status"] for i in range(3)], [422, 422, 400])
        self.assertEqual(receipts["admit-size-10"]["observed"]["status"], 503)
        for label, fields in (("volume-omitted", {}), ("volume-zero", {"volume_gb": 0}),
                              ("volume-two", {"volume_gb": 2}), ("class-omitted", {}),
                              ("class-default", {"runtime_class": "default"}),
                              ("class-nested", {"runtime_class": "nested"})):
            consumer = receipts["admit-" + label]["request"]["json"]["requirements"][1]
            self.assertEqual(consumer["size"], mixed.WIRE_SIZE)
            key = "volume_gb" if label.startswith("volume") else "runtime_class"
            self.assertEqual({key: consumer[key]} if key in consumer else {}, fields)
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_bad_admission_size_acceptance_is_detected_and_cancelled(self):
        for size, expected in ((None, [[422, None]]), ({}, [[422, None]]),
                               ({"vcpus": 0, "memory_mb": 0}, [[400, "invalid"]]),
                               (mixed.SIZES[-1], [[503, "capacity"]])):
            with self.subTest(size=size):
                api = FakeAPI()
                api.allow_bad_admission = True
                runner = mixed.Mixed(api, "fixture")
                path = "/namespaces/fixture/admissions/" + runner.prefix + "-bad"
                runner.admissions.append([path, False])
                consumer = {"role": "consumer"}
                if size is not None:
                    consumer["size"] = size
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.admission_call("bad-size", path, {"regions": ["dev"], "requirements": [consumer]}, expected)
                runner.cleanup()
                self.assertTrue(api.admissions[path]["cancelled"])
                self.assertEqual(sum(m == "PUT" and p == path for m, p, _ in api.calls), 1)

    def test_admission_schema_and_semantic_refusals_are_not_interchangeable(self):
        for status, value, expected in ((400, {"code": "invalid"}, [[422, None]]),
                                        (422, None, [[400, "invalid"]]),
                                        (422, {"code": "invalid"}, [[422, None]]),
                                        (200, {}, [[422, None]])):
            with self.subTest(status=status, value=value):
                class Answer:
                    def call(self, *args):
                        return status, value, {}

                runner = mixed.Mixed(Answer(), "fixture")
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.admission_call("schema", "/admissions/fixture", {}, expected)

    def test_schema_transport_retains_status_without_error_text(self):
        for status, raw in ((422, b"private extractor detail"), (422, b'{"code":"invalid"}'),
                            (400, b"private extractor detail"), (200, b"private extractor detail")):
            with self.subTest(status=status, raw=raw):
                response = io.BytesIO(raw)
                response.status, response.headers = status, {}
                api = mixed.clone.API("http://fixture.invalid")
                with patch.object(mixed.clone, "urlopen", return_value=response):
                    if status != 422:
                        with self.assertRaises(mixed.clone.ContractFailure):
                            api.call("PUT", "/admissions/fixture", {})
                    else:
                        actual, value, _ = api.call("PUT", "/admissions/fixture", {})
                        self.assertEqual(actual, 422)
                        self.assertNotIn("private", str(mixed.summary(actual, value, {})))

    def test_lost_create_is_unknown_discovered_and_never_replayed(self):
        api = FakeAPI()
        api.lost = True
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(TimeoutError):
            runner.case("lost", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE}, [[201, None]])
        # Metadata alone is insufficient to claim an unrelated name.
        api.machines["m_other"]["metadata"] = {"qualification": runner.prefix}
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertTrue(runner.cleanup_unconfirmed)
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)
        self.assertEqual(runner.receipts[0]["observed"], {"outcome": "unknown"})

    def test_lost_create_after_list_cannot_claim_complete_cleanup(self):
        class DelayedCreate(FakeAPI):
            pending = None

            def call(self, method, path, body=None, headers=None):
                if method == "POST" and path == "/machines":
                    self.calls.append((method, path, copy.deepcopy(body)))
                    self.pending = {**body, "id": "m_late", "namespace": body["tenant"]}
                    raise TimeoutError()
                if method == "GET" and path.startswith("/machines?") and self.pending:
                    result = super().call(method, path, body)
                    self.machines["m_late"] = self.pending
                    self.pending = None
                    return result
                return super().call(method, path, body)

        api = DelayedCreate()
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(TimeoutError):
            runner.case("late", {"image": mixed.clone.IMAGE, "size": mixed.clone.SIZE}, [[201, None]])
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)

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
        deletes = [p for m, p, _ in api.calls if m == "DELETE"]
        self.assertEqual(len(deletes), len(set(deletes)))

    def test_missing_profile_is_explicitly_not_exercised(self):
        api = FakeAPI()
        api.profile = False
        runner = mixed.Mixed(api, "fixture")
        runner.run_mixed("m_seed", "s_seed")
        self.assertTrue(any("does not advertise" in gap for gap in runner.gaps))
        self.assertFalse(any(c[2] and "template_build" in c[2] for c in api.calls))
        runner.cleanup()

    def test_foreign_namespace_exact_cleanup_preserves_unrelated_names(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        foreign = runner.prefix + "-foreign"
        api.machines["m_unrelated_foreign"] = {"id": "m_unrelated_foreign", "namespace": foreign,
                "name": "unrelated", "metadata": {"qualification": runner.prefix}}
        runner.named()
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertIn("m_unrelated_foreign", api.machines)
        self.assertNotIn(("DELETE", "/namespaces/" + foreign, None), api.calls)
        self.assertTrue(any(b and b.get("tenant") == foreign for m, p, b in api.calls if p == "/machines"))

    def test_foreign_lost_answer_deletes_exact_id_but_remains_unconfirmed(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        foreign = runner.prefix + "-foreign"
        runner.owned_namespaces.add(foreign)
        api.lost = True
        with self.assertRaises(TimeoutError):
            runner.case("foreign-lost", {"tenant": foreign, "image": mixed.clone.IMAGE,
                        "size": mixed.clone.SIZE}, [[201, None]])
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertTrue(runner.cleanup_unconfirmed)
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})
        self.assertFalse(any(m == "DELETE" and p == "/namespaces/" + foreign for m, p, _ in api.calls))
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)

    def test_mutation_intents_exist_before_each_single_submission(self):
        class IntentAPI(FakeAPI):
            runner = None

            def call(self, method, path, body=None, headers=None):
                if method in ("PUT", "DELETE") or (method == "POST" and not "/wait?" in path and not path.endswith(("/start", "/stop"))):
                    self.runner.check(any(r["request"]["method"] == method and
                        r["request"]["path"] == "/v1" + path and
                        r["observed"].get("outcome") == "unknown" for r in self.runner.receipts))
                return super().call(method, path, body, headers)

        api = IntentAPI()
        runner = mixed.Mixed(api, "fixture")
        api.runner = runner
        runner.run_mixed("m_seed", "s_seed")
        runner.cleanup()

    def test_reservations_must_refuse_and_network_refusal_must_have_control(self):
        for attr in ("bad_network", "ignore_reservations"):
            api = FakeAPI()
            setattr(api, attr, True)
            runner = mixed.Mixed(api, "fixture")
            with self.assertRaises(mixed.clone.ContractFailure):
                runner.run_mixed("m_seed", "s_seed")
            runner.cleanup()
            self.assertEqual(set(api.machines), {"m_seed", "m_other"})

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
                    str(root / "before"), str(root / "after"), str(root / "receipt"),
                    "v1.2.3", str(root), str(root / "sums"), "g_seed"]
            with patch.object(mixed.sys, "argv", argv), patch.dict(mixed.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "BRIQYARD_TOKEN": "fixture-token"}), \
                    patch.object(mixed.clone, "API", return_value=api), patch.object(mixed.signal, "alarm"), \
                    patch.object(mixed, "bind_inputs"), patch.object(mixed.subprocess, "run"):
                with self.assertRaises(TimeoutError):
                    mixed.main()
            receipt = json.loads((root / "receipt").read_text())
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["cleanup"], "unconfirmed")
            self.assertEqual(receipt["source"], identity)
            self.assertEqual(receipt["cases"][0]["observed"], {"outcome": "unknown"})
            self.assertTrue(receipt["notExercised"])
            self.assertEqual(set(api.machines), {"m_seed", "m_other"})
            self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 1)

    def bound_fixture(self, root):
        names = ("briqyardd", "briqyard-fleet", "briqyard")
        old = {name: mixed.hashlib.sha256(("old-" + name).encode()).hexdigest() for name in names}
        head = {}
        for name in names:
            asset = name + "-linux-x86_64"
            (root / asset).write_bytes(("new-" + name).encode())
            head[name] = mixed.hashlib.sha256((root / asset).read_bytes()).hexdigest()
        for path, sums in [(root / "previous", old), (root / "SHA256SUMS-x86_64", head)]:
            path.write_text("".join(digest + "  " + name + "-linux-x86_64\n" for name, digest in sums.items()))
        source = {"binaries": {name: {"sha256": old[name], "version": name + " 0.2.11+abc"} for name in names},
                  "processSha256": {name: old[name] for name in names[:2]},
                  "configurationSha256": {"config.yaml": "a" * 64, "fleet.yaml": "b" * 64}}
        after = copy.deepcopy(source)
        for name in names[1:]:
            after["binaries"][name] = {"sha256": head[name], "version": name + " 0.2.15+def"}
        after["processSha256"]["briqyard-fleet"] = head["briqyard-fleet"]
        return source, after

    def test_exact_release_binding_rejects_stale_or_unverified_inputs_before_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, after = self.bound_fixture(root)
            mixed.bind_inputs(source, after, "v0.2.11", root, root / "previous")
            mutations = [
                lambda a, b: a["binaries"]["briqyardd"].update(version="briqyardd 0.2.14+abc"),
                lambda a, b: b["processSha256"].update({"briqyard-fleet": a["processSha256"]["briqyard-fleet"]}),
                lambda a, b: a["processSha256"].update({"briqyardd": "0" * 64}),
                lambda a, b: b["binaries"]["briqyard"].update(sha256="0" * 64),
                lambda a, b: b["binaries"].update({"briqyard-fleet": a["binaries"]["briqyard-fleet"]}),
                lambda a, b: b["configurationSha256"].update({"fleet.yaml": "0" * 64}),
            ]
            for mutate in mutations:
                a, b = copy.deepcopy(source), copy.deepcopy(after)
                mutate(a, b)
                (root / "before").write_text(json.dumps(a))
                (root / "after").write_text(json.dumps(b))
                argv = ["mixed", "fixture", "m_seed", "s_seed", str(root / "before"), str(root / "after"),
                        str(root / "receipt"), "v0.2.11", str(root), str(root / "previous"), "g_seed"]
                with patch.object(mixed.sys, "argv", argv), patch.dict(mixed.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted"}), \
                        patch.object(mixed.clone, "API") as api:
                    with self.assertRaises(mixed.clone.ContractFailure):
                        mixed.main()
                    api.assert_not_called()
            (root / "briqyard-linux-x86_64").write_bytes(b"unverified")
            with self.assertRaises(mixed.clone.ContractFailure):
                mixed.bind_inputs(source, after, "v0.2.11", root, root / "previous")

    def test_unchanged_fleet_is_not_a_mixed_window_even_with_matching_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, after = self.bound_fixture(root)
            name = "briqyard-fleet"
            after["binaries"][name] = copy.deepcopy(source["binaries"][name])
            after["processSha256"][name] = source["processSha256"][name]
            (root / (name + "-linux-x86_64")).write_bytes(("old-" + name).encode())
            manifest = root / "SHA256SUMS-x86_64"
            manifest.write_text(manifest.read_text().replace(mixed.hashlib.sha256(("new-" + name).encode()).hexdigest(), source["binaries"][name]["sha256"]))
            with self.assertRaises(mixed.clone.ContractFailure):
                mixed.bind_inputs(source, after, "v0.2.11", root, root / "previous")

    def test_admission_wire_matching_dispatch_and_cancellation(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        runner.run_mixed("m_seed", "s_seed", "g_actual")
        runner.cleanup()
        self.assertFalse(api.gateway)
        self.assertTrue(all(a.get("cancelled") or a.get("dispatched") for a in api.admissions.values()))
        admission = next(b for m, p, b in api.calls if m == "PUT" and "/admissions/" in p)
        self.assertEqual(admission, {"regions": ["dev"], "requirements": [
            {"role": "gateway", "size": mixed.WIRE_SIZE, "runtime_class": "default"},
            {"role": "consumer", "size": mixed.WIRE_SIZE, "runtime_class": "default"}]})
        seed = next(b for m, p, b in api.calls if m == "PUT" and "/sandbox-admissions/" in p)
        self.assertEqual(seed["sandbox_seed"], {"machine_id": "m_seed", "snapshot": "s_seed", "generation": "g_actual"})
        creates = [b for m, p, b in api.calls if m == "POST" and p == "/machines"]
        self.assertEqual(len([b for b in creates if "sandbox_seed" in b]), 1)
        self.assertEqual(len([b for b in creates if b["name"].endswith("dispatch-matching")]), 1)
        self.assertTrue(all("Authorization" not in r["request"].get("headers", {}) for r in runner.receipts))

    def test_wrong_decision_and_accepted_conflicting_dispatch_fail(self):
        for attr in ("bad_decision", "bad_dispatch"):
            api = FakeAPI()
            setattr(api, attr, True)
            runner = mixed.Mixed(api, "fixture")
            with self.assertRaises(mixed.clone.ContractFailure):
                runner.placement({"named_memory_profiles": ["init-ready-v1", "sandbox-ready-v1"]})
            if attr == "bad_dispatch":
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.cleanup()
            else:
                runner.cleanup()
            self.assertFalse(api.gateway)
            self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_lost_admission_is_cancelled_without_put_replay(self):
        class Lost(FakeAPI):
            def call(self, method, path, body=None, headers=None):
                result = super().call(method, path, body, headers)
                if method == "PUT" and "/admissions/" in path:
                    raise TimeoutError()
                return result
        api = Lost()
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(TimeoutError):
            runner.placement({})
        runner.cleanup()
        self.assertEqual(sum(m == "PUT" for m, _, _ in api.calls), 1)
        self.assertTrue(next(iter(api.admissions.values()))["cancelled"])

    def test_registry_audit_rejects_only_exact_owned_pending_records(self):
        prefix = "contract-0123456789ab"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry"
            entry = {"namespace": "fixture", "request_id": prefix + "-baseline", "phase": "dispatched",
                     "placement": {"request": {"requirements": [{"role": "gateway"}, {"role": "consumer"}]},
                                   "dispatched": ["gateway", "consumer"]}}
            def audit(item):
                path.write_text(json.dumps({"sandbox_admissions": {"owned": item}}))
                mixed.audit_registry(prefix, "fixture", path)
            audit(entry)
            entry["placement"]["dispatched"] = ["gateway"]
            with self.assertRaises(mixed.clone.ContractFailure):
                audit(entry)
            entry["phase"] = "cancelled"
            audit(entry)
            entry["phase"] = "pending"
            entry["namespace"] = "unrelated"
            audit(entry)

    def test_transport_authenticates_without_receipt_token_and_preserves_placement_header(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"{}"
        response.status = 200
        response.headers = {}
        with patch.dict(mixed.os.environ, {"BRIQYARD_TOKEN": "private-token"}), \
                patch.object(mixed.clone, "urlopen", return_value=response) as open_request:
            mixed.clone.API("http://fixture").call("POST", "/machines", {},
                                                {"x-briqyard-placement-request-id": "req-one"})
            request = open_request.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer private-token")
            self.assertEqual(request.get_header("X-briqyard-placement-request-id"), "req-one")
        shell = Path(__file__).with_name("native-ci-upgrade.sh").read_text()
        self.assertIn("token: $TOKEN\ntls: off", shell)
        self.assertNotIn("env -u BRIQYARD_TOKEN", shell)

    def test_capture_retains_hashes_and_versions_without_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for folder in (root / "usr/local/bin", root / "etc/briqyard"):
                folder.mkdir(parents=True)
            for name in ("briqyardd", "briqyard-fleet", "briqyard"):
                (root / "usr/local/bin" / name).write_bytes(b"exact-binary")
            for name in ("config.yaml", "fleet.yaml"):
                (root / "etc/briqyard" / name).write_text("token: private-value\n")
            (root / "proc/123").mkdir(parents=True)
            (root / "proc/123/exe").write_bytes(b"exact-binary")
            def rooted(path):
                return root / str(path).lstrip("/")
            with patch.object(mixed, "Path", side_effect=rooted), \
                    patch.object(mixed.subprocess, "check_output", side_effect=lambda args, **kw:
                                 b"123\n" if args[0] == "systemctl" else (args[0].rsplit("/", 1)[1] + " 1.2.3+abc\n").encode()):
                receipt = mixed.capture()
            self.assertNotIn("private-value", str(receipt))
            self.assertEqual(len(receipt["binaries"]), 3)
            self.assertEqual(receipt["configurationSha256"]["fleet.yaml"],
                             mixed.hashlib.sha256(b"token: private-value\n").hexdigest())


if __name__ == "__main__":
    unittest.main()
