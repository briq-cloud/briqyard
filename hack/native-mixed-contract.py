#!/usr/bin/env python3
"""Bounded fleet-first checks on the disposable native upgrade fixture."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

spec = importlib.util.spec_from_file_location("clone_contract", Path(__file__).with_name("native-clone-contract.py"))
clone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clone)

SIZES = [None, {}, {"vcpus": 0, "memory_mb": 0},
         {"vcpus": 1, "memory_mb": 2048},
         {"vcpus": 1, "memory_mb": 2048, "cpu_millis": 1000},
         *[{"vcpus": cpu, "memory_mb": memory, "cpu_millis": millis}
           for cpu, memory, millis in [(1, 128, 250), (1, 256, 500), (1, 512, 1000),
                                       (2, 4096, 2000), (4, 8192, 4000), (8, 16384, 8000)]]]


def capture():
    """Hash exact inputs without serializing configuration or command output."""
    result = {"binaries": {}, "configurationSha256": {}}
    for name in ("briqyardd", "briqyard-fleet", "briqyard"):
        path = Path("/usr/local/bin") / name
        version = subprocess.check_output([str(path), "--version"], timeout=10).decode().strip()
        clone.require(re.fullmatch(r"[a-z-]+ [0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+() _-]*", version))
        result["binaries"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                    "version": version}
    for name in ("config.yaml", "fleet.yaml"):
        result["configurationSha256"][name] = hashlib.sha256(
            (Path("/etc/briqyard") / name).read_bytes()).hexdigest()
    return result


class Mixed(clone.Contract):
    def __init__(self, api, namespace):
        super().__init__(api, namespace)
        self.receipts = []
        self.gaps = ["multi-host placement and regional execution authority",
                     "gateway and consumer traffic; sibling packet allow/deny",
                     "interrupted activation, fleet rollback and drain ABA",
                     "authenticated sandbox admission dispatch",
                     "cross-namespace named-template owner rejection",
                     "nested guest execution (fixture has only the default class)"]

    def case(self, label, fields, expected, lifecycle=False, keep=False, inherited=None):
        self.phase = label
        receipt = {"case": label, "request": {"method": "POST", "path": "/v1/machines",
                   "json": {"tenant": self.namespace, "name": self.prefix + "-" + label,
                            "metadata": {"qualification": self.prefix}, "start": True, **fields}},
                   "expected": expected, "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)  # Intent exists before the one-shot create.
        status, value, headers = self.create(label, fields)
        receipt["observed"] = summary(status, value, headers)
        self.check([status, value.get("code")] in expected)
        if status != 201:
            receipt["observed"]["outcome"] = "refused"
            return
        self.check(headers.get("x-briqyard-host") == "local" and value.get("namespace") == self.namespace)
        size = inherited or fields["size"]
        observed = value["size"]
        self.check(observed["vcpus"] == size["vcpus"] and observed["memory_mb"] == size["memory_mb"] and
                   observed.get("cpu_millis", size["vcpus"] * 1000) == size.get("cpu_millis", size["vcpus"] * 1000))
        self.check(value.get("volume") == fields.get("volume"))
        receipt["observed"]["outcome"] = "accepted"
        if inherited:
            self.transition(receipt, value["id"], "wait?for=running&timeout=120")
        if lifecycle:
            for operation in ("wait?for=running&timeout=120", "stop", "start", "wait?for=running&timeout=120"):
                self.transition(receipt, value["id"], operation)
        if keep:
            return value["id"]
        status, _, _ = self.api.call("DELETE", f"/machines/{value['id']}")
        self.check(status in (200, 204))
        self.created.remove(value["id"])
        receipt["cleanup"] = "deleted"

    def transition(self, receipt, machine, operation):
        item = {"request": {"method": "POST", "path": f"/v1/machines/{machine}/{operation}"},
                "expected": {"status": 200}, "observed": {"outcome": "unknown"}}
        if operation.startswith("wait?"):
            item["expected"]["state"] = "running"
        receipt.setdefault("lifecycle", []).append(item)
        status, value, headers = self.api.call("POST", item["request"]["path"][3:])
        item["observed"] = summary(status, value, headers)
        self.check(status == 200 and (not operation.startswith("wait?") or value.get("state") == "running"))

    def named(self):
        source = self.case("named-source", {"image": clone.IMAGE, "size": clone.SIZE,
                           "template_build": "init-ready-v1", "sleep": "never"},
                           [[201, None]], keep=True)
        self.running(source)
        self.phase = "named-seal"
        request = {"memory": True, "template": True}
        receipt = {"case": self.phase, "request": {"method": "POST", "path":
                   f"/v1/machines/{source}/snapshots", "json": request},
                   "expected": {"status": [200, 201], "profile": "init-ready-v1",
                                "intrinsicIdentityDiffersFromRegistered": True},
                   "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        status, snapshot, _ = self.api.call("POST", f"/machines/{source}/snapshots", request)
        intrinsic = snapshot.get("source_host")
        receipt["observed"] = {"status": status, "profile": snapshot.get("clone_profile")
                               if snapshot.get("clone_profile") == "init-ready-v1" else "unexpected",
                               "intrinsicIdentityDiffersFromRegistered": intrinsic not in (None, "", "local")}
        self.check(status in (200, 201) and snapshot.get("clone_profile") == "init-ready-v1" and
                   intrinsic not in (None, "", "local") and
                   re.fullmatch(r"s_[A-Za-z0-9_-]+", snapshot.get("id", "")))
        fork = {"machine_id": source, "snapshot": snapshot["id"]}
        for label, size in [("omitted", None), ("zero", {"vcpus": 0, "memory_mb": 0}),
                            ("matching", clone.SIZE)]:
            fields = {"fork": fork}
            if size is not None:
                fields["size"] = size
            self.case("named-" + label, fields, [[201, None]], inherited=clone.SIZE)
        self.case("named-mismatch", {"fork": fork, "size": {"vcpus": 1, "memory_mb": 512}},
                  [[400, "invalid"]])

    def cleanup(self):
        self.api.deadline = clone.time.monotonic() + 60
        names = {r["request"]["json"]["name"] for r in self.receipts
                 if r["request"]["path"] == "/v1/machines"}
        failed = False
        try:
            status, machines, _ = self.api.call("GET", "/machines?namespace=" + self.namespace)
            clone.require(status == 200 and isinstance(machines, list))
            for machine in machines:
                if (machine.get("namespace") == self.namespace and machine.get("name") in names and
                        machine.get("metadata", {}).get("qualification") == self.prefix):
                    machine_id = machine.get("id", "")
                    clone.require(re.fullmatch(r"m_[A-Za-z0-9_-]+", machine_id))
                    if machine_id not in self.created:
                        self.created.append(machine_id)
        except Exception:
            failed = True
        for machine in reversed(self.created):
            try:
                status, _, _ = self.api.call("DELETE", f"/machines/{machine}")
                clone.require(status in (200, 204, 404))
            except Exception:
                failed = True
        clone.require(not failed)

    def run_mixed(self, source, snapshot):
        status, hosts, _ = self.api.call("GET", "/hosts")
        self.check(status == 200 and len(hosts) == 1 and hosts[0].get("id") == "local" and
                   hosts[0].get("state") == "ready" and not hosts[0].get("runtime_classes"))
        if "init-ready-v1" in hosts[0].get("named_memory_profiles", []):
            self.named()
        else:
            self.gaps.append("init-ready-v1 named inheritance: source host does not advertise the profile")
        for index, size in enumerate(SIZES):
            fields = {"image": clone.IMAGE, "cmd": ["/bin/sleep", "3600"], "sleep": "never"}
            if size is not None:
                fields["size"] = size
            expected = [[400, "invalid"]] if index < 3 else [[201, None]]
            # Larger requests exercise refusal on this deliberately small fixture.
            if size and size.get("memory_mb", 0) >= 8192:
                expected = [[503, "capacity"]] if size["memory_mb"] == 16384 else [[201, None], [503, "capacity"]]
            self.case("size-" + str(index), fields, expected, lifecycle=index == 5)
        for label, extra, expected in [
                ("volume-zero", {"volume": {"size_gb": 0, "mount": "/data"}}, [[400, "invalid"]]),
                ("volume-two", {"volume": {"size_gb": 2, "mount": "/data"}}, [[201, None]]),
                ("class-default", {"runtime_class": "default"}, [[201, None]]),
                ("class-nested", {"runtime_class": "nested"}, [[400, "invalid"]])]:
            self.case(label, {"image": clone.IMAGE, "size": clone.SIZE,
                              "cmd": ["/bin/sleep", "3600"], **extra}, expected)
        # Discover a daemon-created source under its registered fleet route first.
        self.phase = "source-discovery"
        status, machines, _ = self.api.call("GET", "/machines?namespace=" + self.namespace)
        self.check(status == 200 and any(m.get("id") == source and m.get("host") == "local" and
                   m.get("namespace") == self.namespace for m in machines))
        status, snapshots, _ = self.api.call("GET", f"/machines/{source}/snapshots")
        self.check(status == 200 and any(s.get("id") == snapshot and
                   s.get("source_host") not in (None, "", "local") for s in snapshots))
        self.case("sandbox-named", {"fork": {"machine_id": source, "snapshot": snapshot}},
                  [[409, "capability_unsupported"]])
        # The unauthenticated fixture must fail closed, before admission is persisted.
        self.phase = "sandbox-admission"
        body = {"region": "dev", "size": clone.SIZE,
                "sandbox_seed": {"machine_id": source, "snapshot": snapshot, "generation": "g_probe"}}
        receipt = {"case": self.phase, "request": {"method": "PUT", "path":
                   f"/v1/namespaces/{self.namespace}/sandbox-admissions/{self.prefix}", "json": body},
                   "expected": [[409, "capability_unsupported"]], "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        status, value, _ = self.api.call("PUT", receipt["request"]["path"][3:], body)
        receipt["observed"] = summary(status, value, {})
        self.check([status, value.get("code")] == [409, "capability_unsupported"])


def summary(status, value, headers):
    """Only fixed response fields; never retain errors, guest output or configuration."""
    clone.require(isinstance(value, dict))
    code = value.get("code")
    result = {"status": status, "code": code if code in
              (None, "invalid", "capacity", "capability_unsupported", "conflict", "not_found") else "unexpected",
              "host": "local" if headers.get("x-briqyard-host") == "local" else None}
    if re.fullmatch(r"m_[A-Za-z0-9_-]+", str(value.get("id", ""))):
        result["id"] = value["id"]
    if value.get("state") in ("created", "creating", "starting", "running", "stopping", "stopped", "error"):
        result["state"] = value["state"]
    size = value.get("size")
    if isinstance(size, dict):
        result["size"] = {k: v for k, v in size.items() if k in ("memory_mb", "cpu_millis", "vcpus")
                          and type(v) is int and 0 <= v <= 262144}
    volume = value.get("volume")
    if isinstance(volume, dict):
        result["volume"] = {"size_gb": volume.get("size_gb") if type(volume.get("size_gb")) is int else None,
                            "mountMatches": volume.get("mount") == "/data"}
    return result


def main():
    if sys.argv[1:] == ["--capture"]:
        print(json.dumps(capture(), sort_keys=True))
        return
    clone.require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and len(sys.argv) == 7)
    namespace, source, snapshot, before, after, destination = sys.argv[1:]
    clone.require(all(re.fullmatch(r"[A-Za-z0-9_-]+", v) for v in (namespace, source, snapshot)))
    receipt = {"schema": 1, "scope": "single-host fleet-first mixed-version window",
               "source": json.loads(Path(before).read_text()), "mixed": json.loads(Path(after).read_text())}
    clone.require(receipt["source"]["binaries"]["briqyardd"] == receipt["mixed"]["binaries"]["briqyardd"] and
                  receipt["source"]["configurationSha256"] == receipt["mixed"]["configurationSha256"])
    runner = Mixed(clone.API("http://127.0.0.1:7430"), namespace)
    def interrupted(_sig, _frame):
        raise clone.ContractFailure()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(600)
    success = False
    try:
        runner.run_mixed(source, snapshot)
        success = True
    finally:
        signal.alarm(60)
        try:
            runner.cleanup()
            receipt["cleanup"] = "complete"
        except Exception:
            success = False
            receipt["cleanup"] = "failed"
        finally:
            signal.alarm(0)
            receipt.update(cases=runner.receipts, notExercised=runner.gaps, passed=success,
                           lastPhase=runner.phase, checksPassed=runner.checks)
            Path(destination).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    clone.require(success)
    print(f"native mixed contract: {runner.checks} checks passed (bounded scope)")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("native mixed contract: failed; see bounded receipt", file=sys.stderr)
        sys.exit(1)
