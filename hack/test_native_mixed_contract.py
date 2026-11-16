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
        self.admissions = {}
        self.gateway = False
        self.bad_dispatch = False
        self.bad_decision = False

    def call(self, method, path, body=None, headers=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == "/hosts":
            return 200, [{"id": "local", "state": "ready", "runtime_classes": [],
                          "named_memory_profiles": ["init-ready-v1", "sandbox-ready-v1"] if self.profile else ["sandbox-ready-v1"]}], {}
        if method == "GET" and path.startswith("/machines?"):
            return 200, list(self.machines.values()), {}
        if method == "GET" and path.endswith("/snapshots"):
            return 200, [{"id": "s_seed", "source_host": "h_intrinsic"}], {}
        if "/admissions/" in path or "/sandbox-admissions/" in path:
            if method == "DELETE":
                if self.admissions.get(path, {}).get("dispatched"):
                    return 409, {"code": "conflict"}, {}
                self.admissions[path] = {"cancelled": True}
                return 204, None, {}
            old = self.admissions.get(path)
            if old and (old.get("cancelled") or old["body"] != body):
                return 409, {"code": "conflict"}, {}
            if "requirements" in body:
                r = body["requirements"][-1]
                if r.get("runtime_class") == "nested" or (r.get("memory_profile") and
                        r["memory_profile"] not in (["init-ready-v1", "sandbox-ready-v1"] if self.profile else ["sandbox-ready-v1"])):
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
            invalid = (not named and not size.get("vcpus")) or body.get("runtime_class") == "nested" or body.get("volume", {}).get("size_gb") == 0
            if named and size.get("memory_mb") == 512:
                invalid = True
            if invalid and not self.allow_invalid:
                return 400, {"code": "invalid"}, {}
            if size.get("memory_mb") == 16384:
                return 503, {"code": "capacity"}, {}
            value = {**copy.deepcopy(body), "id": f"m_{len(self.calls)}", "namespace": body["tenant"],
                     "state": "running", "host": "local", "size": copy.deepcopy(mixed.clone.SIZE if named else size)}
            if "sandbox_seed" in body:
                value["size"] = copy.deepcopy(size)
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
                    str(root / "before"), str(root / "after"), str(root / "receipt"),
                    "v1.2.3", str(root), str(root / "sums"), "g_seed"]
            with patch.object(mixed.sys, "argv", argv), patch.dict(mixed.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "BRIQYARD_TOKEN": "fixture-token"}), \
                    patch.object(mixed.clone, "API", return_value=api), patch.object(mixed.signal, "alarm"), \
                    patch.object(mixed, "bind_inputs"), patch.object(mixed.subprocess, "run"):
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
