#!/usr/bin/env python3
"""Real fleet/daemon contract checks on the disposable upgrade runner only."""

import json
import os
import re
import signal
import sys
import time
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

IMAGE = "docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"
SIZE = {"vcpus": 1, "memory_mb": 256}


class ContractFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise ContractFailure()


class API:
    def __init__(self, origin):
        self.origin = origin
        self.deadline = time.monotonic() + 600

    def call(self, method, path, body=None):
        request = Request(self.origin + "/v1" + path, method=method,
                          data=None if body is None else json.dumps(body).encode(),
                          headers={"Content-Type": "application/json"})
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        try:
            response = urlopen(request, timeout=min(10 if method == "DELETE" else 125, remaining))
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024)
            value = json.loads(raw) if raw else None
            return response.status, value, dict(response.headers)


class Contract:
    def __init__(self, api, namespace):
        self.api = api
        self.namespace = namespace
        self.created = []
        self.prefix = "contract-" + uuid.uuid4().hex[:12]
        self.checks = 0

    def check(self, condition):
        require(condition)
        self.checks += 1

    def create(self, name, fields):
        body = {"tenant": self.namespace, "name": self.prefix + "-" + name,
                "metadata": {"qualification": self.prefix}, "start": True, **fields}
        status, value, headers = self.api.call("POST", "/machines", body)
        if status == 201:
            require(isinstance(value, dict) and re.fullmatch(r"m_[a-zA-Z0-9_-]+", value.get("id", "")))
            self.created.append(value["id"])
        return status, value, {k.lower(): v for k, v in headers.items()}

    def running(self, machine):
        status, value, _ = self.api.call("POST", f"/machines/{machine}/wait?for=running&timeout=120")
        self.check(status == 200 and value.get("state") == "running")
        return value

    def refuse(self, name, fields, fragment, expected=400, code="invalid"):
        status, value, _ = self.create(name, fields)
        self.check(status == expected and value.get("code") == code and
                   fragment in value.get("error", ""))

    def profile(self, profile):
        fields = {"image": IMAGE, "size": SIZE, "sleep": "never", "template_build": profile}
        if profile == "service-ready-v1":
            fields.update(cmd=["/bin/sleep", "3600"], clone_hooks={
                "park": ["/bin/true"], "resume": ["/bin/true"],
                "park_timeout_s": 5, "resume_timeout_s": 5})
        status, source, headers = self.create(profile, fields)
        self.check(status == 201)
        self.running(source["id"])
        status, snapshot, _ = self.api.call("POST", f"/machines/{source['id']}/snapshots",
                                           {"memory": True, "template": True})
        self.check(status in (200, 201) and snapshot.get("clone_profile") == profile)
        # The inventory registers `local`; the source snapshot carries the intrinsic identity.
        self.check(headers.get("x-briqyard-host") == "local" and
                   snapshot.get("source_host") not in (None, "", "local"))
        fork = {"machine_id": source["id"], "snapshot": snapshot["id"]}
        for label, size in [("omitted", None), ("default", {"vcpus": 0, "memory_mb": 0}),
                            ("matching", SIZE)]:
            body = {"fork": fork}
            if size is not None:
                body["size"] = size
            status, clone, headers = self.create(profile + "-" + label, body)
            self.check(status == 201 and headers.get("x-briqyard-host") == "local")
            view = self.running(clone["id"])
            self.check(view["size"]["vcpus"] == 1 and view["size"]["memory_mb"] == 256 and
                       view.get("memory_origin", {}).get("stage") == "active" and
                       view.get("memory_origin", {}).get("source_machine") == source["id"])
            status, result, _ = self.api.call("POST", f"/machines/{clone['id']}/exec",
                                             {"cmd": ["/bin/echo", "contract-ok"]})
            self.check(status == 200 and result.get("exit_code") == 0 and
                       result.get("stdout", "").strip() == "contract-ok")
            status, _, _ = self.api.call("DELETE", f"/machines/{clone['id']}")
            self.check(status in (200, 204))
            self.created.remove(clone["id"])
        self.refuse(profile + "-mismatch", {"fork": fork, "size": {"vcpus": 1, "memory_mb": 512}},
                    "keeps its template size")

    def run(self, sandbox_source, sandbox_snapshot):
        for label, size in [("omitted", None), ("default", {"vcpus": 0, "memory_mb": 0}),
                            ("empty", {})]:
            body = {"image": IMAGE}
            if size is not None:
                body["size"] = size
            # An empty Size is a wire error; the others reach the resource predicate.
            self.refuse("cold-" + label, body, "missing field" if label == "empty" else "size.vcpus")
        self.refuse("sandbox-named", {"fork": {"machine_id": sandbox_source,
                                                "snapshot": sandbox_snapshot}},
                    "snapshot is not a compatible source-host memory template", 409,
                    "capability_unsupported")
        for profile in ("init-ready-v1", "service-ready-v1"):
            self.profile(profile)

    def cleanup(self):
        self.api.deadline = time.monotonic() + 60
        failed = False
        # Include a create whose response was lost, without dispatching another create.
        try:
            status, machines, _ = self.api.call("GET", "/machines?namespace=" + self.namespace)
            require(status == 200 and isinstance(machines, list))
            for machine in machines:
                if (machine.get("namespace") == self.namespace and
                        machine.get("metadata", {}).get("qualification") == self.prefix):
                    if machine["id"] not in self.created:
                        self.created.append(machine["id"])
        except Exception:
            failed = True
        for machine in reversed(self.created):
            try:
                status, _, _ = self.api.call("DELETE", f"/machines/{machine}")
                require(status in (200, 204, 404))
            except Exception:
                failed = True
        self.created.clear()
        require(not failed)


def main():
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and len(sys.argv) == 4)
    namespace, source, snapshot = sys.argv[1:]
    require(all(re.fullmatch(r"[A-Za-z0-9_-]+", value) for value in (namespace, source, snapshot)))
    contract = Contract(API("http://127.0.0.1:7430"), namespace)
    def interrupted(_signum, _frame):
        raise ContractFailure()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(600)
    try:
        contract.run(source, snapshot)
    finally:
        signal.alarm(60)
        try:
            contract.cleanup()
        finally:
            signal.alarm(0)
    print(f"native clone contract: {contract.checks} checks passed")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("native clone contract: failed", file=sys.stderr)
        sys.exit(1)
