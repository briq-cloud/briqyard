#!/usr/bin/env python3
"""Bounded two-host requests during the fleet-first mixed-version window."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("mixed_contract", Path(__file__).with_name("native-mixed-contract.py"))
mixed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mixed)
clone = mixed.clone


def capture_daemon():
    path = Path("/usr/local/bin/briqyardd")
    version = subprocess.check_output([str(path), "--version"], timeout=10).decode().strip()
    clone.require(re.fullmatch(r"briqyardd [0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+() _-]*", version))
    pid = subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "briqyardd"],
                                  timeout=10).decode().strip()
    clone.require(re.fullmatch(r"[1-9][0-9]*", pid))
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "version": version,
            "processSha256": hashlib.sha256(Path(f"/proc/{pid}/exe").read_bytes()).hexdigest(),
            "configurationSha256": hashlib.sha256(Path("/etc/briqyard/config.yaml").read_bytes()).hexdigest()}


def bind_pair(local, second, previous, head_dir, previous_sums):
    clone.require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?", previous))
    old = mixed.checksums(previous_sums)
    head = mixed.checksums(Path(head_dir) / "SHA256SUMS-x86_64")
    daemon = local["binaries"]["briqyardd"]
    for item in (daemon, second):
        clone.require(item["sha256"] == old["briqyardd-linux-x86_64"] and
                      re.fullmatch(re.escape("briqyardd " + previous[1:]) + r"(?:\+[^\n]+)?", item["version"]))
    clone.require(local["processSha256"]["briqyardd"] == daemon["sha256"] and
                  second["processSha256"] == second["sha256"])
    for name in ("briqyard-fleet", "briqyard"):
        asset = name + "-linux-x86_64"
        clone.require(local["binaries"][name]["sha256"] == head[asset] ==
                      hashlib.sha256((Path(head_dir) / asset).read_bytes()).hexdigest())
    clone.require(local["processSha256"]["briqyard-fleet"] == head["briqyard-fleet-linux-x86_64"])
    for digest in (*local["configurationSha256"].values(), second["configurationSha256"]):
        clone.require(re.fullmatch(r"[a-f0-9]{64}", digest))


def captured_command(argv):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    result = bytearray()
    deadline = time.monotonic() + 30
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            clone.require(remaining > 0)
            events = selector.select(remaining)
            clone.require(bool(events))
            for key, _ in events:
                part = os.read(key.fd, 4096)
                if not part:
                    selector.unregister(key.fileobj)
                else:
                    clone.require(len(result) + len(part) <= 16384)
                    result.extend(part)
        clone.require(process.wait(timeout=max(.001, deadline - time.monotonic())) == 0)
        return json.loads(result)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def remote_capture(helper):
    clone.require(Path(helper).resolve() == (Path(os.environ["RUNNER_TEMP"]) / "two-host-probe/second-host").resolve())
    return captured_command([helper, "python3", "/tmp/mixed-contract/native-mixed-two-host-contract.py", "--capture-daemon"])


class TwoHost(mixed.Mixed):
    def __init__(self, api):
        super().__init__(api, "mixed-two-host")
        self.namespace = self.prefix + "-local"
        self.gaps = ["regional execution authority", "controlled boot and physical pressure",
                     "supported warm and nested execution", "interrupted activation and rollback"]

    def create_on(self, label, namespace, region, host):
        self.phase = label
        body = {"tenant": namespace, "name": self.prefix + "-" + label,
                "metadata": {"qualification": self.prefix}, "image": clone.IMAGE,
                "size": mixed.WIRE_SIZE, "region": region, "start": True,
                "cmd": ["/bin/sleep", "3600"], "sleep": "never"}
        receipt = {"case": label, "request": {"method": "POST", "path": "/v1/machines", "json": body},
                   "expected": {"status": 201, "host": host}, "observed": {"outcome": "unknown"}}
        self.receipts.append(receipt)
        self.owned_namespaces.add(namespace)
        status, value, headers = self.api.call("POST", "/machines", body)
        headers = {key.lower(): val for key, val in headers.items()}
        receipt["observed"] = mixed.summary(status, value, headers)
        if status == 201:
            machine = value.get("id", "")
            clone.require(re.fullmatch(r"m_[A-Za-z0-9_-]+", machine))
            self.created.append(machine)
            clone.require(machine not in self.machine_owners)
            self.machine_owners[machine] = (namespace, body["name"])
        self.check(status == 201 and value.get("namespace") == namespace and
                   headers.get("x-briqyard-host") == host and value.get("host") == host)
        receipt["observed"].update(outcome="accepted", host=host)
        self.transition(receipt, machine, "wait?for=running&timeout=120")
        self.exec_check(label + "-exec", machine, ["/bin/hostname"], body["name"])
        return machine

    def check_cli(self):
        self.phase = "candidate-cli-routing"
        for machine, (namespace, _) in self.machine_owners.items():
            host = "local" if namespace.endswith("-local") else "fc2"
            value = captured_command(["env", "BRIQYARD_URL=http://127.0.0.1:7430",
                                      "briqyard", "machine", "get", machine])
            self.check(value.get("id") == machine and value.get("namespace") == namespace and
                       value.get("host") == host and value.get("state") == "running")
            self.receipts.append({"case": "candidate-cli-get", "request": {"method": "GET",
                                  "path": "/v1/machines/" + machine},
                                  "expected": {"host": host, "state": "running"},
                                  "observed": {"outcome": "accepted", "host": host, "state": "running"}})

    def run_pair(self):
        status, hosts, _ = self.api.call("GET", "/hosts")
        self.check(status == 200 and isinstance(hosts, list) and len(hosts) == 2)
        by_id = {host["id"]: host for host in hosts}
        self.check(set(by_id) == {"local", "fc2"} and
                   all(host.get("state") == "ready" for host in hosts))
        self.check(by_id["local"].get("region") == "dev" and
                   by_id["fc2"].get("region") == "mixed-second")
        for host, region in (("local", "dev"), ("fc2", "mixed-second")):
            namespace = self.prefix + "-" + host
            for ordinal in (1, 2):
                self.create_on(host + "-" + str(ordinal), namespace, region if ordinal == 1 else "", host)
            status, machines, _ = self.api.call("GET", "/machines?namespace=" + namespace)
            owned = {key for key, value in self.machine_owners.items() if value[0] == namespace}
            self.check(status == 200 and isinstance(machines, list) and
                       {machine.get("id") for machine in machines} == owned and
                       all(machine.get("host") == host for machine in machines))


def main():
    if sys.argv[1:] == ["--capture-daemon"]:
        print(json.dumps(capture_daemon(), sort_keys=True))
        return
    clone.require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and len(sys.argv) == 8)
    local_path, second_path, previous, head_dir, sums, helper, destination = sys.argv[1:]
    before = {}
    for label, path in (("local", local_path), ("second", second_path)):
        with Path(path).open("rb") as stream:
            raw = stream.read(65537)
        clone.require(len(raw) <= 65536)
        before[label] = json.loads(raw)
    bind_pair(before["local"], before["second"], previous, head_dir, sums)
    clone.require(os.environ.get("BRIQYARD_TOKEN"))
    receipt = {"schema": 1, "scope": "two-host fleet-first mixed-version requests", "before": before}
    runner = TwoHost(clone.API("http://127.0.0.1:7430"))
    def interrupted(_signal, _frame):
        raise clone.ContractFailure()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(600)
    success = False
    try:
        runner.run_pair()
        runner.check_cli()
        success = True
    finally:
        signal.alarm(60)
        try:
            runner.cleanup()
            receipt["cleanup"] = "complete"
        except Exception:
            success = False
            receipt["cleanup"] = "unconfirmed" if runner.cleanup_unconfirmed else "failed"
        try:
            after = {"local": captured_command(["sudo", "python3", str(Path(__file__).with_name("native-mixed-contract.py")), "--capture"]),
                     "second": remote_capture(helper)}
            bind_pair(after["local"], after["second"], previous, head_dir, sums)
            clone.require(before == after)
            receipt["after"] = after
            receipt["inputsUnchanged"] = True
        except Exception:
            success = False
            receipt["inputsUnchanged"] = False
        finally:
            signal.alarm(0)
            receipt.update(passed=success, cases=runner.receipts, checksPassed=runner.checks,
                           lastPhase=runner.phase, notExercised=runner.gaps)
            Path(destination).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    clone.require(success)
    print(f"native two-host mixed contract: {runner.checks} checks passed (bounded scope)")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("native two-host mixed contract: failed; see bounded receipt", file=sys.stderr)
        sys.exit(1)
