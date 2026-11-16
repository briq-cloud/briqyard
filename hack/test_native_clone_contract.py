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


class NativeContract(unittest.TestCase):
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
    systemctl) echo restart ;;
  esac
}
die() { echo stopped; exit 1; }
''' + shell[start:end] + '\necho dependent-operation\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines(), ["copy", "configure", "copy", "restart", "stopped"])

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


if __name__ == "__main__":
    unittest.main()
