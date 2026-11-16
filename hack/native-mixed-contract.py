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

WIRE_SIZE = {**clone.SIZE, "cpu_millis": 1000}

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
    result["processSha256"] = {}
    for name in ("briqyardd", "briqyard-fleet"):
        pid = subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", name],
                                      timeout=10).decode().strip()
        clone.require(re.fullmatch(r"[1-9][0-9]*", pid))
        result["processSha256"][name] = hashlib.sha256(Path(f"/proc/{pid}/exe").read_bytes()).hexdigest()
    for name in ("config.yaml", "fleet.yaml"):
        result["configurationSha256"][name] = hashlib.sha256(
            (Path("/etc/briqyard") / name).read_bytes()).hexdigest()
    return result


def checksums(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        clone.require(len(fields) == 2 and re.fullmatch(r"[a-f0-9]{64}", fields[0]))
        clone.require(fields[1] not in result)
        result[fields[1]] = fields[0]
    return result


def bind_inputs(source, mixed, previous, head_dir, previous_sums):
    """Fail before opening an API transport when the mixed window is unbound."""
    clone.require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?", previous))
    old = checksums(previous_sums)
    head = checksums(Path(head_dir) / "SHA256SUMS-x86_64")
    for name in ("briqyardd", "briqyard-fleet", "briqyard"):
        asset = name + "-linux-x86_64"
        before, after = source["binaries"][name], mixed["binaries"][name]
        clone.require(before["sha256"] == old[asset] and
                      re.fullmatch(re.escape(name + " " + previous[1:]) + r"(?:\+[^\n]+)?", before["version"]))
        expected = before if name == "briqyardd" else after
        if name != "briqyardd":
            clone.require(after["sha256"] == head[asset] ==
                          hashlib.sha256((Path(head_dir) / asset).read_bytes()).hexdigest())
        else:
            clone.require(before == after)
        if name != "briqyard":
            clone.require(source["processSha256"][name] == before["sha256"] and
                          mixed["processSha256"][name] == expected["sha256"])
    clone.require(source["binaries"]["briqyard-fleet"]["sha256"] !=
                  mixed["binaries"]["briqyard-fleet"]["sha256"] and
                  source["configurationSha256"] == mixed["configurationSha256"])


def audit_registry(prefix, namespace, path="/var/lib/briqyard-fleet/registry.json"):
    """Inspect only the exact run's ownership; emit no registry contents."""
    clone.require(re.fullmatch(r"contract-[a-f0-9]{12}", prefix))
    with Path(path).open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    clone.require(len(raw) <= 16 * 1024 * 1024)
    registry = json.loads(raw)
    for admission in registry["sandbox_admissions"].values():
        if admission["namespace"] != namespace or not admission["request_id"].startswith(prefix + "-"):
            continue
        placed = admission.get("placement")
        complete = placed and all(r["role"] in placed["dispatched"] for r in placed["request"]["requirements"])
        clone.require(admission["phase"] in ("cancelled", "expired") or
                      (admission["phase"] == "dispatched" and (not placed or complete)))


class Mixed(clone.Contract):
    def __init__(self, api, namespace):
        super().__init__(api, namespace)
        self.receipts = []
        self.admissions = []
        self.gateway_owned = False
        self.audit = False
        self.gaps = ["multi-host placement and regional execution authority",
                     "gateway and consumer traffic; sibling packet allow/deny",
                     "interrupted activation, fleet rollback and drain ABA",
                     "nested guest execution (fixture has only the default class)",
                     "new namespace placement and pressure/spill scheduling",
                     "direct in-memory hold accounting (not exposed by the API or registry)",
                     "cross-namespace named-template refusal (cleanup is scoped to the existing namespace)"]

    def case(self, label, fields, expected, lifecycle=False, keep=False, inherited=None, admission=None):
        self.phase = label
        receipt = {"case": label, "request": {"method": "POST", "path": "/v1/machines",
                   "json": {"tenant": self.namespace, "name": self.prefix + "-" + label,
                            "metadata": {"qualification": self.prefix}, "start": True, **fields}},
                   "expected": expected, "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)  # Intent exists before the one-shot create.
        if admission:
            receipt["request"]["headers"] = {"x-briqyard-placement-request-id": admission}
            status, value, headers = self.api.call("POST", "/machines", receipt["request"]["json"],
                                                 receipt["request"]["headers"])
            headers = {k.lower(): v for k, v in headers.items()}
            if status == 201:
                clone.require(re.fullmatch(r"m_[A-Za-z0-9_-]+", value.get("id", "")))
                self.created.append(value["id"])
        else:
            status, value, headers = self.create(label, fields)
        receipt["observed"] = summary(status, value, headers)
        self.check([status, value.get("code")] in expected)
        if status != 201:
            receipt["observed"]["outcome"] = "refused"
            return
        self.check(headers.get("x-briqyard-host") == "local" and value.get("namespace") == self.namespace)
        if admission:
            self.check(value.get("host") == "local")
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
        # A list snapshot cannot prove a timed-out create did not commit later.
        unresolved = {r["request"]["json"]["name"] for r in self.receipts
                      if r["request"]["path"] == "/v1/machines" and
                      r["observed"].get("outcome") == "unknown"}
        discovered = {}
        failed = False
        try:
            status, machines, _ = self.api.call("GET", "/machines?namespace=" + self.namespace)
            clone.require(status == 200 and isinstance(machines, list))
            for machine in machines:
                if (machine.get("namespace") == self.namespace and machine.get("name") in names and
                        machine.get("metadata", {}).get("qualification") == self.prefix):
                    machine_id = machine.get("id", "")
                    clone.require(re.fullmatch(r"m_[A-Za-z0-9_-]+", machine_id))
                    discovered[machine_id] = machine["name"]
                    if machine_id not in self.created:
                        self.created.append(machine_id)
        except Exception:
            failed = True
        for machine in reversed(self.created):
            try:
                status, _, _ = self.api.call("DELETE", f"/machines/{machine}")
                clone.require(status in (200, 204, 404))
                unresolved.discard(discovered.get(machine))
            except Exception:
                failed = True
        if self.gateway_owned:
            try:
                status, _, _ = self.api.call("DELETE", f"/namespaces/{self.namespace}/gateway")
                clone.require(status in (200, 204))
            except Exception:
                failed = True
        for path, dispatched in self.admissions:
            try:
                status, _, _ = self.api.call("DELETE", path)
                clone.require(status == (409 if dispatched else 204))
            except Exception:
                failed = True
        if self.audit:
            try:
                subprocess.run(["sudo", "python3", str(Path(__file__).resolve()), "--audit",
                                self.prefix, self.namespace], check=True, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                failed = True
        clone.require(not failed and not unresolved)

    def run_mixed(self, source, snapshot, generation="g_seed"):
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
        self.placement(hosts[0])
        self.seed_admission(source, snapshot, generation)

    def admission_call(self, label, path, body, expected):
        self.phase = label
        receipt = {"case": label, "request": {"method": "PUT", "path": "/v1" + path, "json": body},
                   "expected": expected, "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        status, value, headers = self.api.call("PUT", path, body)
        receipt["observed"] = summary(status, value, headers)
        self.check([status, value.get("code")] in expected)
        return value

    def placement(self, host):
        base = {"role": "consumer", "size": WIRE_SIZE, "runtime_class": "default"}
        gateway = {**base, "role": "gateway"}
        # Each axis changes from a valid baseline, never a Cartesian product.
        cases = [("baseline", {}, [[200, None]]),
                 ("size", {"size": {**WIRE_SIZE, "memory_mb": 512}}, [[200, None]]),
                 ("volume", {"volume_gb": 2}, [[200, None]]),
                 ("nested", {"runtime_class": "nested"}, [[503, "capacity"]])]
        for profile in ("init-ready-v1", "sandbox-ready-v1", "service-ready-v1"):
            expected = [[200, None]] if profile in host.get("named_memory_profiles", []) else [[503, "capacity"]]
            cases.append(("profile-" + profile, {"memory_profile": profile}, expected))
        for label, extra, expected in cases:
            path = f"/namespaces/{self.namespace}/admissions/{self.prefix}-{label}"
            self.admissions.append([path, False])  # Own the identity before the one-shot PUT.
            body = {"regions": ["dev"], "requirements": [gateway, {**base, **extra}]}
            value = self.admission_call("admit-" + label, path, body, expected)
            if expected != [[200, None]]:
                continue
            self.check(value.get("host") == "local" and value.get("region") == "dev" and
                       value.get("binding") == "existing" and value.get("mode") == "cold")
            if label == "baseline":
                conflict = {**body, "regions": ["absent"]}
                self.admission_call("admit-body-conflict", path, conflict, [[409, "conflict"]])
                fields = {"image": clone.IMAGE, "size": WIRE_SIZE, "region": "absent"}
                self.case("dispatch-conflict", fields, [[409, "conflict"]], admission=path.rsplit("/", 1)[1])
                status, ns, _ = self.api.call("GET", f"/namespaces/{self.namespace}")
                self.check(status == 200 and ns.get("host") == "local" and not ns.get("gateway"))
                self.gateway_owned = True
                self.admissions[-1][1] = True  # A lost gateway dispatch may already have committed.
                gateway_path = f"/namespaces/{self.namespace}/gateway?region=dev&placement_request_id=" + path.rsplit("/", 1)[1]
                gateway_body = {"image": clone.IMAGE, "size": WIRE_SIZE, "port": 8080}
                receipt = {"case": "gateway-dispatch", "request": {"method": "PUT", "path": "/v1" + gateway_path,
                           "json": gateway_body}, "expected": [[200, None]], "observed": {"outcome": "unknown"}}
                self.receipts.append(receipt)
                status, value, headers = self.api.call("PUT", gateway_path, gateway_body)
                headers = {k.lower(): v for k, v in headers.items()}
                receipt["observed"] = summary(status, value, headers)
                self.check(status == 200 and headers.get("x-briqyard-host") == "local")
                self.case("dispatch-matching", {"image": clone.IMAGE, "size": WIRE_SIZE,
                          "region": "dev", "runtime_class": "default", "cmd": ["/bin/sleep", "3600"]},
                          [[201, None]], admission=path.rsplit("/", 1)[1])
            else:
                status, _, _ = self.api.call("DELETE", path)
                self.check(status == 204)
                self.admission_call("cancelled-" + label, path, body, [[409, "conflict"]])

    def seed_admission(self, source, snapshot, generation):
        path = f"/namespaces/{self.namespace}/sandbox-admissions/{self.prefix}-seed"
        selector = {"machine_id": source, "snapshot": snapshot, "generation": generation}
        self.admissions.append([path, False])
        value = self.admission_call("seed-admit", path, {"region": "dev", "size": WIRE_SIZE,
                                   "sandbox_seed": selector}, [[200, None]])
        self.check(value.get("mode") == "sandbox-seed")
        # A timeout at dispatch cannot safely be cancelled or replayed.
        self.admissions[-1][1] = True
        self.case("seed-dispatch", {"image": clone.IMAGE, "size": WIRE_SIZE, "region": "dev",
                  "sleep": "never", "cmd": ["/bin/sh", "-ec", "sleep infinity"],
                  "sandbox_seed": {**selector, "request_id": self.prefix + "-seed"}},
                  [[201, None]], lifecycle=True, admission=self.prefix + "-seed")


def summary(status, value, headers):
    """Only fixed response fields; never retain errors, guest output or configuration."""
    clone.require(isinstance(value, dict))
    code = value.get("code")
    result = {"status": status, "code": code if code in
              (None, "invalid", "capacity", "capability_unsupported", "conflict", "not_found") else "unexpected",
              "host": "local" if headers.get("x-briqyard-host") == "local" or value.get("host") == "local" else None}
    if value.get("binding") in ("new", "existing"):
        result["binding"] = value["binding"]
    if value.get("mode") in ("cold", "sandbox-seed"):
        result["mode"] = value["mode"]
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
    if len(sys.argv) == 4 and sys.argv[1] == "--audit":
        audit_registry(sys.argv[2], sys.argv[3])
        return
    clone.require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and len(sys.argv) == 11)
    namespace, source, snapshot, before, after, destination, previous, head_dir, previous_sums, generation = sys.argv[1:]
    clone.require(all(re.fullmatch(r"[A-Za-z0-9_-]+", v) for v in (namespace, source, snapshot)))
    receipt = {"schema": 1, "scope": "single-host fleet-first mixed-version window",
               "source": json.loads(Path(before).read_text()), "mixed": json.loads(Path(after).read_text())}
    bind_inputs(receipt["source"], receipt["mixed"], previous, head_dir, previous_sums)
    clone.require(os.environ.get("BRIQYARD_TOKEN") and re.fullmatch(r"[A-Za-z0-9_-]+", generation))
    runner = Mixed(clone.API("http://127.0.0.1:7430"), namespace)
    runner.audit = True
    def interrupted(_sig, _frame):
        raise clone.ContractFailure()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(600)
    success = False
    try:
        runner.run_mixed(source, snapshot, generation)
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
