#!/usr/bin/env python3
"""Bounded fleet-first checks on the disposable native upgrade fixture."""
import hashlib
import ipaddress
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
# Same immutable Python HTTP fixture used by qualify.sh.
HTTP_IMAGE = "python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8"

# Emit fixed diagnostics only; non-timeout failures still fail isolation acceptance.
DENIAL_SCRIPT = ('out=$(wget -qO- -T 4 "$1" 2>&1); rc=$?; '
                 'if [ "$rc" = 0 ]; then echo unexpected-success; exit 1; fi; '
                 'if [ "$rc" != 1 ]; then echo unexpected-exit; exit 1; fi; '
                 'case "$out" in *"timed out"*) echo denied;; '
                 '*"Host is unreachable"*|*"No route to host"*) echo unreachable; exit 1;; '
                 '*) echo unexpected-refusal; exit 1;; esac')
DENIAL_CODES = {"denied", "unexpected-success", "unexpected-exit", "unreachable", "unexpected-refusal"}
STRICT_DENIAL_SCRIPT = ('out=$(wget -qO- -T 4 "$1" 2>&1); rc=$?; '
                        'if [ "$rc" = 0 ]; then echo unexpected-success; exit 1; fi; '
                        'if [ "$rc" != 1 ]; then echo unexpected-exit; exit 1; fi; '
                        'case "$out" in *"timed out"*|*"Host is unreachable"*|*"No route to host"*) echo denied;; '
                        '*) echo unexpected-refusal; exit 1;; esac')
ON_LINK_SCRIPT = ('target=$1; source=$2; out=$(ip -4 route get "$target") || exit 1; '
                  'set -- $out; [ "$1" = "$target" ] && [ "$2" = dev ] && '
                  '[ "$3" = eth0 ] && [ "$4" = src ] && [ "$5" = "$source" ] && echo on-link')

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
        self.owned_namespaces = set()
        self.warm_paths = []
        self.cleanup_unconfirmed = False
        self.deletions = {}
        self.machine_owners = {}
        self.gaps = ["multi-host placement and regional execution authority",
                     "interrupted activation, fleet rollback and drain ABA",
                     "nested guest execution (fixture has only the default class)",
                     "boot-pressure spill: one host, no second region or controlled boot queue",
                     "host memory/disk-pressure conditions: fixture retains running upgrade controls",
                     "supported warm claim: native-ci-upgrade.sh leaves templates.warm_pools disabled",
                     "per-hold memory accounting: API exposes aggregate usage; registry does not serialize live holds"]

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
        if status == 201:
            machine_id = value.get("id", "")
            clone.require(re.fullmatch(r"m_[A-Za-z0-9_-]+", machine_id))
            identity = (receipt["request"]["json"]["tenant"], receipt["request"]["json"]["name"])
            clone.require(machine_id not in self.machine_owners or self.machine_owners[machine_id] == identity)
            self.machine_owners[machine_id] = identity
        self.check([status, value.get("code")] in expected)
        if status != 201:
            receipt["observed"]["outcome"] = "refused"
            return
        self.check(headers.get("x-briqyard-host") == "local" and value.get("namespace") == receipt["request"]["json"]["tenant"])
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
        status = self.delete("delete-machine", f"/machines/{value['id']}", [200, 204])
        self.check(status in (200, 204))
        self.created.remove(value["id"])
        receipt["cleanup"] = "deleted"

    def delete(self, label, path, expected):
        if path in self.deletions:
            # Observation is not authority to replay an uncertain mutation.
            if self.deletions[path] is None:
                self.cleanup_unconfirmed = True
                raise clone.ContractFailure()
            self.check(self.deletions[path] in expected)
            return self.deletions[path]
        if path.startswith("/machines/") and path.count("/") == 2:
            machine_id = path.rsplit("/", 1)[1]
            identity = self.machine_owners.get(machine_id)
            clone.require(identity is not None)
            status, machine, _ = self.api.call("GET", path)
            matches = (status == 200 and isinstance(machine, dict) and machine.get("id") == machine_id and
                       (machine.get("namespace"), machine.get("name")) == identity and
                       isinstance(machine.get("metadata"), dict) and
                       machine["metadata"].get("qualification") == self.prefix)
            self.receipts.append({"case": "cleanup-ownership", "request": {"method": "GET", "path": "/v1" + path},
                                  "observed": {"status": status, "ownershipMatches": matches}})
            if status == 404 and 404 in expected:
                self.deletions[path] = 404
                return 404
            clone.require(matches)
        receipt = {"case": label, "request": {"method": "DELETE", "path": "/v1" + path},
                   "expected": {"status": expected}, "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        self.deletions[path] = None
        status, value, headers = self.api.call("DELETE", path)
        self.deletions[path] = status
        receipt["observed"] = summary(status, value, headers)
        self.check(status in expected)
        return status

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
        foreign = self.prefix + "-foreign"
        status, namespaces, _ = self.api.call("GET", "/namespaces")
        self.check(status == 200 and isinstance(namespaces, list) and
                   not any(n.get("id") == foreign for n in namespaces))
        self.owned_namespaces.add(foreign)  # Before submission, even a refusal may pin it.
        self.case("named-foreign", {"tenant": foreign, "fork": fork}, [[400, "invalid"]])
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
        creates = [r for r in self.receipts if r["request"]["path"] == "/v1/machines"]
        names = {(r["request"]["json"]["tenant"], r["request"]["json"]["name"]) for r in creates}
        # A list snapshot cannot prove a timed-out create did not commit later.
        unresolved = {(r["request"]["json"]["tenant"], r["request"]["json"]["name"]) for r in creates
                      if r["observed"].get("outcome") == "unknown"}
        self.cleanup_unconfirmed = self.cleanup_unconfirmed or bool(unresolved)
        failed = False
        for namespace in sorted({self.namespace} | self.owned_namespaces):
            try:
                status, machines, _ = self.api.call("GET", "/machines?namespace=" + namespace)
                clone.require(status == 200 and isinstance(machines, list))
                for machine in machines:
                    identity = (machine.get("namespace"), machine.get("name"))
                    if (identity[0] == namespace and identity in names and
                            machine.get("metadata", {}).get("qualification") == self.prefix):
                        machine_id = machine.get("id", "")
                        clone.require(re.fullmatch(r"m_[A-Za-z0-9_-]+", machine_id))
                        clone.require(machine_id not in self.machine_owners or self.machine_owners[machine_id] == identity)
                        self.machine_owners[machine_id] = identity
                        if machine_id not in self.created:
                            self.created.append(machine_id)
            except Exception:
                failed = True
        for machine in reversed(self.created):
            try:
                status = self.delete("cleanup-machine", f"/machines/{machine}", [200, 204, 404])
                clone.require(status in (200, 204, 404))
            except Exception:
                failed = True
        if self.gateway_owned:
            try:
                status = self.delete("cleanup-gateway", f"/namespaces/{self.namespace}/gateway", [200, 204])
                clone.require(status in (200, 204))
            except Exception:
                failed = True
        for path, dispatched in self.admissions:
            try:
                status = self.delete("cleanup-admission", path, [409 if dispatched else 204])
            except Exception:
                failed = True
        for path in self.warm_paths:
            try:
                status = self.delete("cleanup-warm-pool", path, [200, 204, 404])
            except Exception:
                failed = True
        for namespace in sorted(self.owned_namespaces):
            try:
                # Never delete a namespace with an unresolved submission or any remaining machine.
                clone.require(not failed and not any(n == namespace for n, _ in unresolved))
                status, machines, _ = self.api.call("GET", "/machines?namespace=" + namespace)
                clone.require(status == 200 and machines == [])
                status = self.delete("cleanup-namespace", "/namespaces/" + namespace, [200, 204])
                clone.require(status in (200, 204))
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
        self.reservation_pressure()
        self.warm_refusal(hosts[0], source, snapshot)

    def admission_call(self, label, path, body, expected):
        self.phase = label
        receipt = {"case": label, "request": {"method": "PUT", "path": "/v1" + path, "json": body},
                   "expected": expected, "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        status, value, headers = self.api.call("PUT", path, body)
        receipt["observed"] = summary(status, value, headers)
        self.check([status, value.get("code") if isinstance(value, dict) else None] in expected)
        return value

    def placement(self, host):
        base = {"role": "consumer", "size": WIRE_SIZE, "runtime_class": "default"}
        gateway = {**base, "role": "gateway"}
        # Each axis changes from a valid baseline, never a Cartesian product.
        cases = [("baseline", {}, [[200, None]])]
        # Requirement.size is required (Json extraction: 422), unlike create's default.
        # Size.check rejects zero values after extraction (400 invalid).
        for index, size in enumerate(SIZES):
            expected = [[422, None]] if index < 2 else [[400, "invalid"]] if index == 2 else [[200, None]]
            if size and size.get("memory_mb", 0) >= 8192:
                # Two requirements plus the running controls share the 12 GiB fixture.
                expected = [[503, "capacity"]] if size["memory_mb"] == 16384 else [[200, None], [503, "capacity"]]
            cases.append(("size-" + str(index), {"size": size}, expected))
        # Zero is a valid admission disk estimate; daemon create separately refuses it.
        cases.extend([("volume-omitted", {}, [[200, None]]),
                      ("volume-zero", {"volume_gb": 0}, [[200, None]]),
                      ("volume-two", {"volume_gb": 2}, [[200, None]]),
                      ("class-omitted", {"runtime_class": None}, [[200, None]]),
                      ("class-default", {"runtime_class": "default"}, [[200, None]]),
                      ("class-nested", {"runtime_class": "nested"}, [[503, "capacity"]])])
        for profile in ("init-ready-v1", "sandbox-ready-v1", "service-ready-v1"):
            expected = [[200, None]] if profile in host.get("named_memory_profiles", []) else [[503, "capacity"]]
            cases.append(("profile-" + profile, {"memory_profile": profile}, expected))
        for label, extra, expected in cases:
            path = f"/namespaces/{self.namespace}/admissions/{self.prefix}-{label}"
            self.admissions.append([path, False])  # Own the identity before the one-shot PUT.
            consumer = {**base, **extra}
            for key in ("size", "runtime_class"):
                if consumer.get(key) is None:
                    consumer.pop(key)
            body = {"regions": ["dev"], "requirements": [gateway, consumer]}
            value = self.admission_call("admit-" + label, path, body, expected)
            if self.receipts[-1]["observed"]["status"] != 200:
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
                gateway_body = {"image": HTTP_IMAGE, "size": WIRE_SIZE, "port": 8080,
                                "cmd": ["/bin/sh", "-ec", "mkdir -p /www; echo mixed-gateway > /www/index.html; exec python3 -m http.server 8080 -d /www"],
                                "probes": {"readiness": {"tcp": 8080}}}
                receipt = {"case": "gateway-dispatch", "request": {"method": "PUT", "path": "/v1" + gateway_path,
                           "json": gateway_body}, "expected": [[200, None]], "observed": {"outcome": "unknown"}}
                self.receipts.append(receipt)
                status, value, headers = self.api.call("PUT", gateway_path, gateway_body)
                headers = {k.lower(): v for k, v in headers.items()}
                receipt["observed"] = summary(status, value, headers)
                self.check(status == 200 and headers.get("x-briqyard-host") == "local")
                consumer = self.case("dispatch-matching", {"image": clone.IMAGE, "size": WIRE_SIZE,
                          "region": "dev", "runtime_class": "default", "cmd": ["/bin/sleep", "3600"],
                          "egress": {"mode": "via", "via": "gateway"}},
                          [[201, None]], keep=True, admission=path.rsplit("/", 1)[1])
                self.traffic(consumer, host)
            else:
                status = self.delete("cancel-admission", path, [204])
                self.admission_call("cancelled-" + label, path, body, [[409, "conflict"]])

    def exec_check(self, label, machine, cmd, expected_stdout, expected_code=0):
        self.phase = label
        receipt = {"case": label, "request": {"method": "POST", "path": f"/v1/machines/{machine}/exec",
                   "json": {"cmd": cmd}}, "expected": {"exitCode": expected_code, "outputMatches": True},
                   "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        status, value, _ = self.api.call("POST", f"/machines/{machine}/exec", {"cmd": cmd})
        matches = value.get("stdout", "").strip() == expected_stdout
        receipt["observed"] = {"status": status, "exitCode": value.get("exit_code") if type(value.get("exit_code")) is int else None, "outputMatches": matches}
        if label.endswith("-denied"):
            code = value.get("stdout", "").strip()
            receipt["observed"]["denialCode"] = code if code in DENIAL_CODES else "unclassified"
        self.check(status == 200 and value.get("exit_code") == expected_code and matches)

    def traffic(self, consumer, host):
        # qualify.sh's bounded wget control beside a timeout refusal; e2e-siblings.sh's
        # via:gateway strict default beside explicit sibling opt-in. No external target.
        self.running(consumer)
        self.exec_check("gateway-traffic", consumer,
                        ["wget", "-qO-", "-T", "4", "http://gateway.internal:8080/"], "mixed-gateway")
        server = self.case("traffic-server", {"image": HTTP_IMAGE, "size": clone.SIZE, "sleep": "never",
                           "cmd": ["/bin/sh", "-ec", "mkdir -p /www; echo mixed-sibling > /www/index.html; exec python3 -m http.server 8000 -d /www"],
                           "probes": {"readiness": {"tcp": 8000}}}, [[201, None]], keep=True)
        status, value, _ = self.api.call("POST", f"/machines/{server}/wait?timeout=120")
        self.check(status == 200 and value.get("ready") is True)
        address = str(ipaddress.IPv4Address(value["ip"]))
        url = "http://" + address + ":8000/"
        if not host.get("egress_siblings_v1"):
            self.gaps.append("sibling opt-in traffic: previous daemon does not advertise egress_siblings_v1")
            # Without the same-target positive, retain the stricter timeout-only predicate.
            self.exec_check("strict-sibling-denied", consumer,
                            ["/bin/sh", "-c", DENIAL_SCRIPT, "sh", url], "denied")
            return
        sibling = self.case("traffic-sibling", {"image": clone.IMAGE, "size": clone.SIZE,
                            "sleep": "never", "cmd": ["/bin/sleep", "3600"],
                            "egress": {"mode": "via", "via": "gateway", "siblings": True}},
                            [[201, None]], keep=True)
        self.running(sibling)
        self.exec_check("sibling-allowed", sibling, ["wget", "-qO-", "-T", "4", url], "mixed-sibling")
        status, strict, _ = self.api.call("GET", f"/machines/{consumer}")
        self.check(status == 200 and strict.get("host") == "local" and
                   strict.get("namespace") == self.namespace and
                   strict.get("egress") == {"mode": "via", "via": "gateway"})
        source = str(ipaddress.IPv4Address(strict["ip"]))
        self.check(source != address and ipaddress.IPv4Network(source + "/24", strict=False) ==
                   ipaddress.IPv4Network(address + "/24", strict=False))
        self.exec_check("strict-sibling-route", consumer,
                        ["/bin/sh", "-c", ON_LINK_SCRIPT, "sh", address, source], "on-link")
        # ARP is filtered too: a healthy on-link route can report neighbor-resolution denial.
        # Require the same-target positive above; other wget errors remain failures.
        self.exec_check("strict-sibling-denied", consumer,
                        ["/bin/sh", "-c", STRICT_DENIAL_SCRIPT, "sh", url], "denied")
        self.exec_check("sibling-gateway-traffic", sibling,
                        ["wget", "-qO-", "-T", "4", "http://gateway.internal:8080/"], "mixed-gateway")
        foreign = self.prefix + "-traffic-foreign"
        status, namespaces, _ = self.api.call("GET", "/namespaces")
        self.check(status == 200 and isinstance(namespaces, list) and
                   not any(n.get("id") == foreign for n in namespaces))
        self.owned_namespaces.add(foreign)
        outsider = self.case("traffic-foreign", {"tenant": foreign, "image": HTTP_IMAGE,
                             "size": clone.SIZE, "sleep": "never",
                             "cmd": ["/bin/sh", "-ec", "mkdir -p /www; echo mixed-foreign > /www/index.html; exec python3 -m http.server 8000 -d /www"],
                             "probes": {"readiness": {"tcp": 8000}}}, [[201, None]], keep=True)
        status, value, _ = self.api.call("POST", f"/machines/{outsider}/wait?timeout=120")
        self.check(status == 200 and value.get("ready") is True)
        foreign_url = "http://" + str(ipaddress.IPv4Address(value["ip"])) + ":8000/"
        self.exec_check("foreign-server-control", outsider,
                        ["wget", "-qO-", "-T", "4", "http://127.0.0.1:8000/"], "mixed-foreign")
        self.exec_check("foreign-sibling-denied", sibling,
                        ["/bin/sh", "-c", DENIAL_SCRIPT, "sh", foreign_url], "denied")

    def reservation_pressure(self):
        self.phase = "reservation-preconditions"
        status, hosts, _ = self.api.call("GET", "/hosts")
        self.check(status == 200 and len(hosts) == 1 and hosts[0].get("id") == "local")
        host = hosts[0]
        # The fixture pins physical reservation policy; do not infer it from a version.
        policy = host.get("memory_policy")
        self.check(policy == {"version": 1, "vmm_overhead_mb": 256})
        free = host["capacity"]["memory_mb"] - host["used"]["memory_mb"]
        self.check(512 <= free <= 12288)
        paths = [f"/namespaces/{self.namespace}/admissions/{self.prefix}-pressure-{i}" for i in range(3)]
        small = {"regions": ["dev"], "requirements": [{"role": "consumer", "size": {**WIRE_SIZE, "cpu_millis": 250}}]}
        large = {"regions": ["dev"], "requirements": [{"role": "consumer", "size": {"vcpus": 1, "memory_mb": free - 256, "cpu_millis": 250}}]}
        self.admissions.append([paths[0], False])
        self.admission_call("reservation-fill", paths[0], large, [[200, None]])
        self.admissions.append([paths[1], False])
        self.admission_call("reservation-refused", paths[1], small, [[503, "capacity"]])
        status = self.delete("reservation-cancel", paths[0], [204])
        self.check(status == 204)
        self.admissions.append([paths[2], False])
        self.admission_call("reservation-released", paths[2], small, [[200, None]])
        status = self.delete("reservation-recovered-cancel", paths[2], [204])
        self.check(status == 204)

    def warm_refusal(self, host, source, snapshot):
        # Native upgrade fixture has no warm-pool configuration or budget. Never fill it.
        self.check(not host.get("warm_pool_profiles"))
        path = f"/namespaces/{self.namespace}/warm-pools/{self.prefix}-unsupported"
        self.warm_paths.append(path)
        self.admission_call("warm-profile-unsupported", path,
                            {"source_machine": source, "snapshot": snapshot, "desired": 0},
                            [[409, "capability_unsupported"]])
        self.warm_paths.remove(path)

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
    clone.require(value is None or isinstance(value, dict))
    value = value or {}
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
            receipt["cleanup"] = "unconfirmed" if runner.cleanup_unconfirmed else "failed"
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
