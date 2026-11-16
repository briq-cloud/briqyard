"""Failure semantics and exact wire shapes of the disposable native contract suite."""
import copy
import importlib.util
from pathlib import Path
import re
import subprocess
import unittest

spec = importlib.util.spec_from_file_location("contract", Path(__file__).with_name("native-clone-contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.machines = {"m_unrelated": {"id": "m_unrelated", "namespace": "test",
                                        "metadata": {"qualification": "another-run"}}}
        self.profile = "init-ready-v1"
        self.lose_create = False
        self.failed_delete = None

    def call(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == "/machines" and method == "POST":
            if "fork" in body:
                if body["fork"]["machine_id"] == "m_sandbox":
                    return 409, {"code": "capability_unsupported", "error": "snapshot is not a compatible source-host memory template"}, {}
                if body.get("size", {}).get("memory_mb") == 512:
                    return 400, {"code": "invalid", "error": "named memory clone keeps its template size"}, {}
            elif "template_build" not in body:
                return 400, {"code": "invalid", "error": "missing field vcpus" if body.get("size") == {} else "size.vcpus"}, {}
            machine = copy.deepcopy(body)
            machine["namespace"] = body["tenant"]
            machine["id"] = f"m_{len(self.calls)}"
            machine["state"] = "running"
            machine["size"] = contract.SIZE.copy()
            if "fork" in body:
                machine["memory_origin"] = {"stage": "active", "source_machine": body["fork"]["machine_id"]}
            self.machines[machine["id"]] = machine
            if self.lose_create:
                raise TimeoutError()
            return 201, machine, {"X-Briqyard-Host": "local"}
        if method == "GET":
            return 200, list(self.machines.values()), {}
        machine = path.split("/")[2]
        if method == "DELETE":
            if machine == self.failed_delete:
                raise TimeoutError()
            self.machines.pop(machine, None)
            return 204, None, {}
        if path.endswith("/snapshots"):
            return 201, {"id": "s_sealed", "clone_profile": self.profile,
                         "source_host": "h_intrinsic"}, {}
        if path.endswith("/exec"):
            return 200, {"exit_code": 0, "stdout": "contract-ok\n"}, {}
        return 200, self.machines[machine], {}


class DrainingAPI(FakeAPI):
    def __init__(self):
        super().__init__()
        self.state = "ready"
        self.fail_undrain = False
        self.lose_drain = False
        self.allow_unbound = False

    def call(self, method, path, body=None):
        if path == "/hosts":
            return 200, [{"id": "local", "state": self.state}], {}
        if path == "/namespaces" and method == "GET":
            return 200, [{"id": "test", "host": "local"}], {}
        if path.startswith("/hosts/local/"):
            self.calls.append((method, path, body))
            if path.endswith("/drain"):
                self.state = "draining"
                if self.lose_drain:
                    raise TimeoutError()
            else:
                if self.fail_undrain:
                    raise TimeoutError()
                self.state = "ready"
            return 204, None, {}
        if path.startswith("/namespaces/") and method == "DELETE":
            self.calls.append((method, path, body))
            return 204, None, {}
        if path == "/machines" and method == "POST" and body.get("size") == contract.SIZE:
            if body["tenant"] != "test" and self.state == "draining" and not self.allow_unbound:
                self.calls.append((method, path, body))
                return 503, {"code": "capacity"}, {}
            # FakeAPI's cold-create rejection is unrelated to this admission test.
            body = {**body, "template_build": "init-ready-v1"}
        return super().call(method, path, body)


class NativeContract(unittest.TestCase):
    def test_draining_bound_create_and_unbound_refusal_restore_admission(self):
        api = DrainingAPI()
        runner = contract.Contract(api, "test")
        runner.draining_namespace()
        self.assertEqual(runner.checks, 8)
        bound = next(body for method, path, body in api.calls
                     if method == "POST" and path == "/machines")
        self.assertEqual(bound["cmd"], ["/bin/sleep", "3600"])
        self.assertEqual(api.state, "ready")
        runner.cleanup()
        self.assertEqual(list(api.machines), ["m_unrelated"])
        self.assertEqual(sum(p == "/hosts/local/drain" for _, p, _ in api.calls), 1)
        self.assertEqual(sum(p == "/hosts/local/undrain" for _, p, _ in api.calls), 1)

    def test_unexpected_unbound_success_fails_and_cleans_both_namespaces(self):
        api = DrainingAPI()
        api.allow_unbound = True
        runner = contract.Contract(api, "test")
        with self.assertRaises(contract.ContractFailure):
            runner.draining_namespace()
        runner.cleanup()
        self.assertEqual(api.state, "ready")
        self.assertEqual(list(api.machines), ["m_unrelated"])
        self.assertIn(("DELETE", "/namespaces/" + runner.unbound_namespace, None), api.calls)

    def test_initially_draining_host_is_never_mutated(self):
        api = DrainingAPI()
        api.state = "draining"
        runner = contract.Contract(api, "test")
        with self.assertRaises(contract.ContractFailure):
            runner.draining_namespace()
        runner.cleanup()
        self.assertEqual(api.state, "draining")
        self.assertFalse(any(p.startswith("/hosts/local/") for _, p, _ in api.calls))

    def test_lost_bound_create_answer_restores_and_discovers_without_replay(self):
        api = DrainingAPI()
        api.lose_create = True
        runner = contract.Contract(api, "test")
        with self.assertRaises(TimeoutError):
            runner.draining_namespace()
        runner.cleanup()
        self.assertEqual(api.state, "ready")
        self.assertEqual(list(api.machines), ["m_unrelated"])
        self.assertEqual(sum(p == "/machines" and m == "POST" for m, p, _ in api.calls), 1)

    def test_lost_drain_answer_is_observed_then_restored_without_replay(self):
        api = DrainingAPI()
        api.lose_drain = True
        runner = contract.Contract(api, "test")
        with self.assertRaises(TimeoutError):
            runner.draining_namespace()
        runner.cleanup()
        self.assertEqual(api.state, "ready")
        self.assertEqual(sum(p == "/hosts/local/drain" for _, p, _ in api.calls), 1)

    def test_uncertain_undrain_is_not_replayed_and_cleanup_fails(self):
        api = DrainingAPI()
        api.fail_undrain = True
        runner = contract.Contract(api, "test")
        with self.assertRaises(TimeoutError):
            runner.draining_namespace()
        with self.assertRaises(contract.ContractFailure):
            runner.cleanup()
        self.assertEqual(sum(p == "/hosts/local/undrain" for _, p, _ in api.calls), 1)
        self.assertEqual(list(api.machines), ["m_unrelated"])

    def test_daemon_seed_is_discovered_before_the_fleet_profile_refusal(self):
        class SeedAPI(FakeAPI):
            discovered = False

            def call(self, method, path, body=None):
                if method == "GET" and path == "/machines?namespace=test":
                    self.discovered = True
                    return 200, [{"id": "m_sandbox", "namespace": "test", "host": "local"}], {}
                if method == "GET" and path == "/machines/m_sandbox/snapshots":
                    return 200, [{"id": "s_sandbox", "memory": True,
                                  "clone_profile": "sandbox-ready-v1"}], {}
                if body and body.get("fork", {}).get("machine_id") == "m_sandbox":
                    if not self.discovered:
                        return 404, {"code": "not_found"}, {}
                return super().call(method, path, body)

        runner = contract.Contract(SeedAPI(), "test")
        profiles = []
        runner.profile = profiles.append
        runner.draining_namespace = lambda: None
        runner.run("m_sandbox", "s_sandbox")
        self.assertEqual(runner.checks, 6)
        self.assertEqual(profiles, ["init-ready-v1", "service-ready-v1"])

    def test_native_gate_selects_python_caller_changes(self):
        workflow = Path(__file__).parents[1] / ".github/workflows/native-upgrade.yml"
        selector = re.search(r"grep -qxE '([^']+)'", workflow.read_text()).group(1)
        for path, selected in [("hack/native-clone-contract.py", True),
                               ("hack/native-ci-upgrade.sh", True),
                               ("hack/native-clone-contract.py.bak", False)]:
            result = subprocess.run(["grep", "-qxE", selector], input=path + "\n", text=True)
            self.assertEqual(result.returncode == 0, selected)

    def test_configuration_failure_restores_and_stops_before_activation(self):
        shell = Path(__file__).with_name("native-ci-upgrade.sh").read_text()
        start = shell.index("native_clone_contract() (")
        end = shell.index('\nfor id in $RUNNING;', start)
        script = '''
WORK=/tmp; NEW_INIT=digest; HARNESS=/unused; NS=test; SEED=seed; SNAP=snapshot
sudo() {
  case "$1" in
    cp) echo copy ;;
    python3) echo configure; return 7 ;;
    systemctl)
      case "$2" in
        show) echo 101 ;;
        kill) echo handover; return 7 ;;
        *) echo unexpected-restart; return 8 ;;
      esac ;;
  esac
}
die() { echo stopped; exit 1; }
''' + shell[start:end] + '\necho dependent-operation\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines(), ["copy", "configure", "copy", "handover", "stopped"])

    def test_configuration_handover_signals_and_observes_the_new_ready_process(self):
        shell = Path(__file__).with_name("native-ci-upgrade.sh").read_text()
        start = shell.index("  contract_handover() {")
        end = shell.index('\n  sudo cp /etc/briqyard/config.yaml', start)
        helper = shell[start:end]
        script = '''
NS=test; TOKEN=test; signaled=0
sudo() { "$@"; }
systemctl() {
  case "$1" in
    show) if [ "$signaled" = 1 ]; then echo 202; else echo 101; fi ;;
    kill)
      [ "$*" = 'kill --kill-whom=main --signal=SIGUSR2 briqyardd' ] || return 9
      signaled=1; echo handover ;;
    *) echo unexpected-restart; return 8 ;;
  esac
}
curl() { echo readiness >&2; }
sleep() { echo unexpected-sleep; return 9; }
''' + helper + '\ncontract_handover\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ["handover"])
        self.assertEqual(result.stderr.splitlines(), ["readiness"])

    def test_refused_handover_does_not_fall_back_to_restart(self):
        shell = Path(__file__).with_name("native-ci-upgrade.sh").read_text()
        start = shell.index("  contract_handover() {")
        end = shell.index('\n  sudo cp /etc/briqyard/config.yaml', start)
        helper = shell[start:end]
        script = '''
NS=test; TOKEN=test
sudo() { "$@"; }
systemctl() {
  case "$1" in
    show) echo 101 ;;
    kill) echo refused; return 7 ;;
    *) echo unexpected-restart; return 8 ;;
  esac
}
curl() { echo unexpected-readiness; return 9; }
''' + helper + '\ncontract_handover\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines(), ["refused"])

    def test_profile_sends_omitted_default_and_matching_sizes_without_recipe_overrides(self):
        api = FakeAPI()
        runner = contract.Contract(api, "test")
        runner.profile("init-ready-v1")
        clones = [body for method, path, body in api.calls if method == "POST" and path == "/machines" and "fork" in body]
        self.assertNotIn("size", clones[0])
        self.assertEqual(clones[1]["size"], {"vcpus": 0, "memory_mb": 0})
        self.assertEqual(clones[2]["size"], contract.SIZE)
        for body in clones:
            self.assertEqual(set(body) - {"size"}, {"tenant", "name", "metadata", "start", "fork"})
        runner.cleanup()
        self.assertEqual(set(api.machines), {"m_unrelated"})

    def test_wrong_snapshot_profile_stops_before_clone_and_cleans_source(self):
        api = FakeAPI()
        api.profile = "sandbox-ready-v1"
        runner = contract.Contract(api, "test")
        with self.assertRaises(contract.ContractFailure):
            runner.profile("service-ready-v1")
        runner.cleanup()
        self.assertFalse(any(body and "fork" in body for _, _, body in api.calls))
        self.assertEqual(set(api.machines), {"m_unrelated"})

    def test_lost_create_response_is_observed_and_cleaned_without_replay(self):
        api = FakeAPI()
        api.lose_create = True
        runner = contract.Contract(api, "test")
        with self.assertRaises(TimeoutError):
            runner.create("lost", {"template_build": "init-ready-v1"})
        runner.cleanup()
        self.assertEqual(sum(method == "POST" for method, _, _ in api.calls), 1)
        self.assertEqual(set(api.machines), {"m_unrelated"})

    def test_cleanup_continues_after_one_delete_failure_without_deleting_unrelated(self):
        api = FakeAPI()
        runner = contract.Contract(api, "test")
        ids = [runner.create(name, {"template_build": "init-ready-v1"})[1]["id"] for name in ("one", "two")]
        api.failed_delete = ids[-1]
        with self.assertRaises(contract.ContractFailure):
            runner.cleanup()
        self.assertEqual([path for method, path, _ in api.calls if method == "DELETE"],
                         [f"/machines/{machine}" for machine in reversed(ids)])
        self.assertIn("m_unrelated", api.machines)

    def test_http_status_alone_does_not_qualify_a_refusal(self):
        api = FakeAPI()
        runner = contract.Contract(api, "test")
        with self.assertRaises(contract.ContractFailure):
            runner.refuse("wrong", {"image": "alpine"}, "unrelated predicate")

    def test_failure_receipt_identifies_phase_without_remote_error_text(self):
        api = FakeAPI()
        api.profile = "sandbox-ready-v1"
        api.last_status = 201
        api.last_code = "SECRET"
        runner = contract.Contract(api, "test")
        with self.assertRaises(contract.ContractFailure):
            runner.profile("init-ready-v1")
        receipt = runner.failure_receipt()
        self.assertEqual(receipt, {"schema": 1, "phase": "init-ready-v1:seal",
                                  "checksPassed": 2, "httpStatus": 201, "errorCode": None})


if __name__ == "__main__":
    unittest.main()
