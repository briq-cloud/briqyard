#!/usr/bin/env python3
"""Stress a briqyard daemon or fleet: many namespaces, many machines, every feature at once.

Runs inside the development VM (or anywhere that reaches the API) with the standard library
only. Each phase runs its operations in parallel across every machine, records latencies and
failures, and checks the host's invariants between phases through hack/stress-invariants.sh
(needs sudo on the host; skipped with --no-invariants). After the feature phases come the
races: a client that hangs up mid-create, a start and a snapshot's delete against a destroy of
the same machine, and more starts at once than the host has memory for. The invariants include
no record on disk for a machine the daemon does not hold.

    python3 hack/stress.py --namespaces 6 --per-namespace 4 --rounds 2
    python3 hack/stress.py --url http://127.0.0.1:7430 --crash  # through the fleet, kill the daemon mid-run
    python3 hack/stress.py --phases endpoints_all,sleep_wake  # creates, then those phases, then destroys

Exit code 1 when any operation failed or an invariant broke; the report says which.
"""
import argparse
import base64
import http.client
import json
import os
import random
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))

# A machine that counts as using the host's memory.
LIVE = {"running", "starting", "stopping"}
# The hang-up phase's image, apart from --image: small, so a first run pulls it (the hang-up
# lands in the pull) and later runs find it built (the hang-up lands in the boot).
HANGUP_IMAGE = "alpine:3.20"


class Api:
    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.token = token
        self.lock = threading.Lock()
        self.timings = {}  # op -> [seconds]
        self.failures = []  # (op, target, status, message)

    def request(self, method, path, body=None, op=None, timeout=300):
        """One call, timed; returns (status, text). Status 0: no answer (refused, timed out)."""
        op = op or f"{method} {path.split('/')[2] if path.count('/') > 2 else path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("content-type", "application/json")
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        t0 = time.monotonic()
        status, text = 0, ""
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                status, text = r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode(errors="replace")
        except Exception as e:  # connection refused, timeout
            status, text = 0, f"{type(e).__name__}: {e}"
        dt = time.monotonic() - t0
        with self.lock:
            self.timings.setdefault(op, []).append(dt)
        return status, text

    def call(self, method, path, body=None, op=None, timeout=300, expect=None):
        """A call whose answer must be 2xx (or in `expect`): anything else is a recorded failure."""
        status, text = self.request(method, path, body, op, timeout)
        ok = (200 <= status < 300) if expect is None else (status in expect)
        if not ok:
            with self.lock:
                self.failures.append((op, path, status, text[:200]))
            raise ApiError(op, path, status, text[:200])
        return json.loads(text) if text and text.strip().startswith(("{", "[")) else text


class ApiError(Exception):
    def __init__(self, op, path, status, text):
        super().__init__(f"{op} {path}: {status} {text}")
        self.status = status


def parallel(items, fn, workers):
    """Runs fn over items in parallel; returns (results, errors) by index, without raising."""
    items = list(items)
    results, errors = {}, {}

    def one(i):
        try:
            results[i] = fn(items[i])
        except Exception as e:  # recorded, never fatal: the report counts them
            errors[i] = e

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        list(ex.map(one, range(len(items))))
    finally:
        # An interrupt drops the calls not started yet; those under way finish.
        ex.shutdown(cancel_futures=True)
    return results, errors


def rand_bytes(n):
    return os.urandom(n)


# The phases of a round, in order, between its creates and its destroys (--phases picks some).
PHASES = ["exec_all", "endpoints_all", "stop_start_all", "fork_some", "crash", "sleep_wake", "hangup_mid_create", "start_vs_destroy", "starts_past_capacity"]


class Run:
    def __init__(self, a):
        self.a = a
        self.api = Api(a.url, a.token)
        self.rng = random.Random(a.seed)
        self.prefix = f"st{a.seed % 1000:03d}"
        self.namespaces = [f"{self.prefix}-t{i}" for i in range(a.namespaces)]
        self.machines = {}  # (namespace, name) -> machine dict
        self.endpoints = {}  # machine id -> endpoint dict
        self.broken = []  # invariant breaks
        self.log_lines = []

    # ---- helpers ----
    def log(self, msg):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        self.log_lines.append(line)

    def phase(self, name):
        self.log(f"== {name}")

    def mget(self, mid):
        return self.api.call("GET", f"/v1/machines/{mid}", op="get")

    def mlist(self):
        return self.api.call("GET", "/v1/machines", op="list")

    def mine(self):
        return [m for m in self.mlist() if m["namespace"].startswith(self.prefix)]

    def find_named(self, namespace, name):
        return next((m for m in self.mlist() if m["namespace"] == namespace and m["name"] == name), None)

    def error_code(self, text):
        try:
            return json.loads(text).get("code")
        except ValueError:
            return None

    def wait_state(self, mid, want, timeout=120):
        deadline = time.monotonic() + timeout
        while True:
            m = self.mget(mid)
            if m["state"] in want:
                return m
            if m["state"] == "error":
                raise RuntimeError(f"{mid} errored: {m.get('error')}")
            if m["state"] == "stopped" and m.get("stopped_reason") == "exit" and "stopped" not in want:
                raise RuntimeError(f"{mid} exited: {m.get('exit')}")
            if time.monotonic() > deadline:
                raise RuntimeError(f"{mid} still {m['state']} after {timeout}s")
            time.sleep(0.5)

    def exec(self, mid, cmd, timeout_ms=30000, stdin="", wake=True):
        r = self.api.call(
            "POST",
            f"/v1/machines/{mid}/exec",
            {"cmd": cmd, "timeout_ms": timeout_ms, "stdin": stdin, "wake": wake},
            op="exec",
            timeout=timeout_ms / 1000 + 120,
        )
        if r["exit_code"] != 0:
            raise RuntimeError(f"exec {cmd} exit {r['exit_code']}: {r['stderr'][:120]}")
        return r["stdout"]

    def invariants(self, label):
        if self.a.no_invariants:
            return
        exp = self.expected()
        env = dict(os.environ, EXPECT=json.dumps(exp), BRIQYARD_URL=self.a.invariants_url or self.a.url)
        p = subprocess.run(
            ["bash", os.path.join(HERE, "stress-invariants.sh")],
            capture_output=True,
            text=True,
            env=env,
        )
        out = p.stdout.strip()
        for line in out.splitlines():
            self.log(f"   {line}")
        if p.returncode != 0:
            self.broken.append((label, out.splitlines()[-1] if out else p.stderr[-200:]))
            self.log(f"   INVARIANT BROKEN after {label}")

    def expected(self):
        mine = self.mine()
        by = {}
        for m in mine:
            by[m["state"]] = by.get(m["state"], 0) + 1
        eps = self.api.call("GET", "/v1/endpoints", op="endpoints")
        mine_ids = {m["id"] for m in mine}
        return {
            "prefix": self.prefix,
            "machines": len(mine),
            "by_state": by,
            "running": by.get("running", 0),
            "namespaces": len({m["namespace"] for m in mine}),
            "endpoints": len([e for e in eps if e["machine_id"] in mine_ids]),
        }

    # ---- phases ----
    def create_all(self, round_no):
        self.phase(f"round {round_no}: create {self.a.namespaces} namespaces × {self.a.per_namespace} machines")
        targets = [(t, f"m{i}") for t in self.namespaces for i in range(self.a.per_namespace)]

        def mk(tn):
            t, n = tn
            i = int(n[1:])
            body = {
                "namespace": t,
                "name": n,
                "image": self.a.image,
                # A real threaded web server (Alpine's busybox has no httpd applet).
                "cmd": ["sh", "-c", "mkdir -p /www && echo hello-$(hostname) > /www/index.html && exec python3 -m http.server 8080 --directory /www"],
                "env": {"STRESS_ROUND": str(round_no), "STRESS_SECRET": "s3cr3t"},
                "files": [{"path": "/etc/stress.txt", "base64": base64.b64encode(f"{t}/{n}\n".encode()).decode()}],
                "size": {"vcpus": 1, "memory_mb": self.a.memory},
                "ports": [8080],
                "sleep": "never",
                "metadata": {"stress": self.prefix},
            }
            if i % 4 == 3:  # one in four carries a data volume
                body["volume"] = {"size_gb": 1, "mount": "/data"}
            m = self.api.call("POST", "/v1/machines", body, op="create", timeout=600)
            m = self.wait_state(m["id"], {"running"}, timeout=self.a.boot_timeout)
            return m

        res, errs = parallel(targets, mk, self.a.workers)
        for i, tn in enumerate(targets):
            if i in res:
                self.machines[tn] = res[i]
        self.report_errors("create", errs, targets)
        self.invariants("create")

    def exec_all(self):
        self.phase("exec, files, names on the namespace network")
        items = list(self.machines.items())

        def one(kv):
            (t, n), m = kv
            mid = m["id"]
            out = self.exec(mid, ["sh", "-c", "hostname; cat /etc/stress.txt; echo $STRESS_ROUND"])
            lines = out.strip().splitlines()
            assert lines[0] == n, f"hostname {lines[0]} != {n}"
            assert lines[1] == f"{t}/{n}", f"boot file {lines[1]}"
            # a sibling by name, and its own id name
            # The sibling's web server comes up a moment after its machine reports running.
            sib = f"m{(int(n[1:]) + 1) % self.a.per_namespace}"
            self.exec(mid, ["sh", "-c", f"nslookup {sib}.internal >/dev/null && for i in $(seq 1 60); do wget -qO- -T 5 http://{sib}.internal:8080/ 2>/dev/null | grep -q hello && exit 0; sleep 1; done; exit 1"], timeout_ms=90000)
            # stdin and exit codes
            assert self.exec(mid, ["cat"], stdin="ping") == "ping"
            try:
                self.exec(mid, ["sh", "-c", "exit 7"])
                raise AssertionError("exit 7 not reported")
            except RuntimeError as e:
                assert "exit 7" in str(e), str(e)
            # files: 64 KB round trip
            blob = rand_bytes(64 << 10)
            self.api.call("PUT", f"/v1/machines/{mid}/files", {"path": "/tmp/blob", "base64": base64.b64encode(blob).decode()}, op="put")
            got = self.api.call("GET", f"/v1/machines/{mid}/files?path=/tmp/blob", op="get_file")
            assert base64.b64decode(got["base64"]) == blob, "file round trip differs"
            if "volume" in m and m.get("volume"):
                self.exec(mid, ["sh", "-c", "echo 42 > /data/x && mount | grep -q ' /data '"])
            return True

        _, errs = parallel(items, one, self.a.workers)
        self.report_errors("exec", errs, [k for k, _ in items])

    def endpoints_all(self):
        self.phase("endpoints: a TCP port per machine, connections from many clients")

        def add(kv):
            _, m = kv
            ep = self.api.call("POST", f"/v1/machines/{m['id']}/endpoints", {"port": 8080, "protocol": "tcp"}, op="expose")
            self.endpoints[m["id"]] = ep
            return ep

        _, errs = parallel(list(self.machines.items()), add, self.a.workers)
        self.report_errors("expose", errs)

        def hit(item):
            mid, k = item
            ep = self.endpoints.get(mid)
            if not ep:
                return
            host, port = ep["address"].rsplit(":", 1)
            host = host if host != "0.0.0.0" else "127.0.0.1"
            c = http.client.HTTPConnection(host, int(port), timeout=60)
            c.request("GET", "/")
            r = c.getresponse()
            body = r.read().decode()
            assert r.status == 200 and "hello" in body, f"{r.status} {body[:40]}"

        items = [(mid, k) for mid in self.endpoints for k in range(self.a.hits)]
        self.rng.shuffle(items)
        _, errs = parallel(items, hit, self.a.workers * 2)
        self.report_errors("endpoint hit", errs)
        self.invariants("endpoints")

    def stop_start_all(self):
        self.phase("stop and start half, suspend and resume the other half; data kept")
        items = list(self.machines.items())

        def one(kv):
            (t, n), m = kv
            mid = m["id"]
            suspend = int(n[1:]) % 2 == 1
            # /tmp is a tmpfs in the guest: what must survive a cold boot lives on the root disk.
            self.exec(mid, ["sh", "-c", "echo kept > /root/kept; echo mem > /tmp/mem"])
            self.api.call("POST", f"/v1/machines/{mid}/stop", {"suspend": suspend, "timeout_sec": 10}, op="suspend" if suspend else "stop", timeout=120)
            self.wait_state(mid, {"stopped"}, timeout=120)
            self.api.call("POST", f"/v1/machines/{mid}/start", op="resume" if suspend else "start", timeout=180)
            self.wait_state(mid, {"running"}, timeout=self.a.boot_timeout)
            assert self.exec(mid, ["cat", "/root/kept"]).strip() == "kept"
            if suspend:
                assert self.exec(mid, ["cat", "/tmp/mem"]).strip() == "mem", "memory not kept through the resume"
            # the endpoint still serves after the restart
            ep = self.endpoints.get(mid)
            if ep:
                host, port = ep["address"].rsplit(":", 1)
                host = host if host != "0.0.0.0" else "127.0.0.1"
                c = http.client.HTTPConnection(host, int(port), timeout=90)
                c.request("GET", "/")
                assert c.getresponse().status == 200
            return True

        _, errs = parallel(items, one, self.a.workers)
        self.report_errors("stop/start", errs, [k for k, _ in items])
        self.invariants("stop/start")

    def fork_some(self):
        self.phase("fork one machine per namespace, exec in the fork, destroy it")
        picks = [((t, "m0"), self.machines[(t, "m0")]) for t in self.namespaces if (t, "m0") in self.machines]

        def one(kv):
            (t, n), m = kv
            self.exec(m["id"], ["sh", "-c", "echo forked > /root/forked; sync"])
            # A fork takes its source's disks and image, not its command: without one it runs
            # the image's, which may exit at once.
            f = self.api.call("POST", "/v1/machines", {"namespace": t, "name": f"{n}-fork", "fork": {"machine_id": m["id"], "copy": "disk"}, "cmd": ["sleep", "3600"], "size": {"vcpus": 1, "memory_mb": self.a.memory}, "sleep": "never"}, op="fork", timeout=600)
            try:
                f = self.wait_state(f["id"], {"running"}, timeout=self.a.boot_timeout)
                assert self.exec(f["id"], ["cat", "/root/forked"]).strip() == "forked"
            finally:
                self.api.call("DELETE", f"/v1/machines/{f['id']}", op="destroy", timeout=180)
            return True

        _, errs = parallel(picks, one, self.a.workers)
        self.report_errors("fork", errs, [k for k, _ in picks])
        self.invariants("fork")

    def sleep_wake(self):
        self.phase("sleep on idle (20 s window) on one machine per namespace, wake by exec and by a connection")
        picks = [self.machines[(t, "m1")] for t in self.namespaces if (t, "m1") in self.machines]

        def one(m):
            mid = m["id"]
            self.api.call("PATCH", f"/v1/machines/{mid}", {"sleep": "20s"}, op="set_sleep")
            deadline = time.monotonic() + 120
            while self.mget(mid)["state"] != "stopped":
                if time.monotonic() > deadline:
                    raise RuntimeError("did not sleep")
                time.sleep(2)
            assert self.mget(mid)["stopped_reason"] == "idle"
            # wake by a connection to the endpoint
            ep = self.endpoints.get(mid)
            if ep:
                host, port = ep["address"].rsplit(":", 1)
                host = host if host != "0.0.0.0" else "127.0.0.1"
                c = http.client.HTTPConnection(host, int(port), timeout=120)
                c.request("GET", "/")
                assert c.getresponse().status == 200
                assert self.mget(mid)["state"] == "running"
                while self.mget(mid)["state"] != "stopped":
                    if time.monotonic() > deadline + 120:
                        raise RuntimeError("did not sleep again")
                    time.sleep(2)
            # wake by an exec
            assert self.exec(mid, ["hostname"]).strip() == m["name"]
            self.api.call("PATCH", f"/v1/machines/{mid}", {"sleep": "never"}, op="set_sleep")
            return True

        _, errs = parallel(picks, one, self.a.workers)
        self.report_errors("sleep/wake", errs)
        self.invariants("sleep/wake")

    def crash(self):
        self.phase("kill the daemon with SIGKILL; machines must be adopted")
        p = subprocess.run(["bash", "-c", "sudo kill -9 $(systemctl show -p MainPID --value briqyardd)"], capture_output=True, text=True)
        if p.returncode != 0:
            self.log(f"   cannot kill the daemon here ({p.stderr.strip()[:80]}); skipped")
            return
        # Refused while the daemon is down: polled with `request`, which records no failure.
        deadline = time.monotonic() + 90
        while self.api.request("GET", "/v1/status", op="status", timeout=5)[0] != 200:
            if time.monotonic() > deadline:
                raise RuntimeError("daemon did not come back")
            time.sleep(1)
        _, errs = parallel(list(self.machines.values()), lambda m: self.exec(m["id"], ["hostname"]), self.a.workers)
        self.report_errors("exec after crash", errs)
        bad = [m["id"] for m in self.machines.values() if self.mget(m["id"])["state"] != "running"]
        if bad:
            self.report_errors("adopted", {b: RuntimeError("not running after the crash") for b in bad})
        self.invariants("crash")

    # ---- the races ----
    def hangup_mid_create(self):
        self.phase("hang up on a create after 1 s: the machine settles on its own, the image still builds (a create answers at once since ADR 0048)")
        t, name = self.namespaces[0], "hangup"
        body = {"namespace": t, "name": name, "image": HANGUP_IMAGE, "cmd": ["sleep", "3600"], "size": {"vcpus": 1, "memory_mb": self.a.memory}, "sleep": "never"}
        status, text = self.api.request("POST", "/v1/machines", body, op="create (hang up)", timeout=1)
        self.log(f"   create: {'hung up' if status == 0 else f'answered {status} before the hang-up'}")
        errs = {}
        try:
            # The record, if the create got that far, must leave its pending state by itself.
            deadline = time.monotonic() + self.a.boot_timeout
            m = self.find_named(t, name)
            while m and m["state"] in ("creating", "created", "starting"):
                if time.monotonic() > deadline:
                    raise RuntimeError(f"{m['id']} still {m['state']} {self.a.boot_timeout}s after the hang-up")
                time.sleep(0.5)
                m = self.find_named(t, name)
            self.log(f"   the machine is {m['state']}" if m else "   no machine was made")
            # The image's build must not be left waiting on the dropped request.
            again = self.api.call("POST", "/v1/machines", dict(body, name=f"{name}-again"), op="create (again)", timeout=600)
            self.wait_state(again["id"], {"running"}, timeout=self.a.boot_timeout)
        except Exception as e:
            errs[0] = e
        self.report_errors("hang-up", errs, [f"{t}/{name}"])
        self.invariants("hang-up")

    def start_vs_destroy(self):
        self.phase("start, destroy and a snapshot's delete on one stopped machine per namespace at the same moment: one wins, none stays destroying")
        picks = [(k, m) for k, m in self.machines.items() if k[1] == "m2"]

        def one(kv):
            key, m = kv
            mid = m["id"]
            self.api.call("POST", f"/v1/machines/{mid}/stop", {"timeout_sec": 10}, op="stop", timeout=120)
            self.wait_state(mid, {"stopped"}, timeout=120)
            snap = self.api.call("POST", f"/v1/machines/{mid}/snapshots", {}, op="snapshot", timeout=120)
            go = threading.Barrier(3)
            answers = {}

            def fire(op, method, path):
                go.wait()
                answers[op] = self.api.request(method, path, op=f"{op} (race)", timeout=180)

            threads = [
                threading.Thread(target=fire, args=("start", "POST", f"/v1/machines/{mid}/start")),
                threading.Thread(target=fire, args=("destroy", "DELETE", f"/v1/machines/{mid}")),
                # Behind the destroy, it once wrote the destroyed record back (2026-10-28).
                threading.Thread(target=fire, args=("snapshot rm", "DELETE", f"/v1/machines/{mid}/snapshots/{snap['id']}")),
            ]
            for th in threads:
                th.start()
            for th in threads:
                th.join()
            for op, (status, text) in answers.items():
                if status not in (200, 204, 404, 409):
                    raise RuntimeError(f"{op} answered {status} {text[:80]}")
            # Whatever the answers, the machine ends gone or settled, never `destroying`.
            deadline = time.monotonic() + 120
            while True:
                status, text = self.api.request("GET", f"/v1/machines/{mid}", op="get")
                if status == 404:
                    final = "gone"
                    break
                if status != 200:
                    raise RuntimeError(f"get answered {status} {text[:80]}")
                state = json.loads(text)["state"]
                if state in ("running", "stopped"):
                    final = state
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError(f"still {state} 120s after start {answers['start'][0]} / destroy {answers['destroy'][0]}")
                time.sleep(0.5)
            self.log(f"   {mid}: start {answers['start'][0]}, destroy {answers['destroy'][0]}, then {final}")
            if final == "gone":
                self.machines.pop(key, None)
                self.endpoints.pop(mid, None)
            return final

        _, errs = parallel(picks, one, self.a.workers)
        self.report_errors("start vs destroy", errs, [k for k, _ in picks])
        self.invariants("start vs destroy")

    def starts_past_capacity(self):
        self.phase("start 4 machines at once that cannot all fit: 503 capacity for the rest, live memory never over the host's")
        t = self.namespaces[0]
        s = self.api.call("GET", "/v1/status", op="status")
        cap = s["capacity"]["memory_mb"]
        free = cap - s["used"]["memory_mb"]
        n, mem = 4, free // 3 + 1  # two fit, two do not
        body = {"namespace": t, "image": self.a.image, "cmd": ["sleep", "3600"], "size": {"vcpus": 1, "memory_mb": mem}, "sleep": "never", "start": False}
        self.log(f"   {free} MB free of {cap}: {n} machines of {mem} MB")
        made, errs = parallel([f"cap{i}" for i in range(n)], lambda name: self.api.call("POST", "/v1/machines", dict(body, name=name), op="create (stopped)", timeout=600), n)
        self.report_errors("create stopped", errs)
        ids = [m["id"] for m in made.values()]
        # A create answers at `creating` (ADR 0048): the race is between starts of machines made.
        for mid in ids:
            self.wait_state(mid, {"created"}, timeout=self.a.boot_timeout)
        # A start refused leaves a machine as it was: `created`, never started.
        was = {mid: "created" for mid in ids}

        # Live memory, sampled through the race: it must never exceed the host's.
        worst = {"mb": 0}
        done = threading.Event()

        def sample():
            while not done.is_set():
                live = sum(m["size"]["memory_mb"] for m in self.mlist() if m["state"] in LIVE)
                worst["mb"] = max(worst["mb"], live)
                time.sleep(0.2)

        sampler = threading.Thread(target=sample)
        sampler.start()
        try:
            answers, _ = parallel(ids, lambda mid: self.api.request("POST", f"/v1/machines/{mid}/start", op="start (past capacity)", timeout=300), n)
            started = [ids[i] for i, (st, _) in answers.items() if st == 200]
            refused = [ids[i] for i, (st, text) in answers.items() if st == 503 and self.error_code(text) == "capacity"]
            for mid in started:
                self.wait_state(mid, {"running"}, timeout=self.a.boot_timeout)
        finally:
            done.set()
            sampler.join()
        problems = {}
        for i, (st, text) in answers.items():
            if ids[i] not in started and ids[i] not in refused:
                problems[ids[i]] = f"answered {st} {text[:80]}"
        for mid in refused:
            state = self.mget(mid)["state"]
            if state != was[mid]:
                problems[mid] = f"refused, yet {state} (was {was[mid]})"
        if not started:
            problems["none"] = "no start was accepted"
        if not refused:
            problems["all"] = f"every start was accepted: {n * mem} MB in {free} MB free"
        if worst["mb"] > cap:
            problems["sum"] = f"{worst['mb']} MB live for a host of {cap}"
        self.log(f"   started {len(started)}, refused {len(refused)}, live at most {worst['mb']} MB of {cap}")
        self.report_errors("starts past capacity", {i: RuntimeError(msg) for i, msg in enumerate(problems.values())}, list(problems))
        parallel(ids, lambda mid: self.api.call("DELETE", f"/v1/machines/{mid}", op="destroy", timeout=180), n)
        self.invariants("starts past capacity")

    def destroy_all(self):
        self.phase("destroy everything")

        def one(m):
            self.api.call("DELETE", f"/v1/machines/{m['id']}", op="destroy", timeout=180)

        _, errs = parallel(list(self.machines.values()), one, self.a.workers)
        self.report_errors("destroy", errs)
        # Whatever a failed phase left in these namespaces (a fork, a retry's twin) goes too.
        left = self.mine()
        if left:
            self.log(f"   {len(left)} machine(s) left by failed phases, destroying them")
            parallel(left, one, self.a.workers)
        for t in self.namespaces:
            try:
                self.api.call("DELETE", f"/v1/namespaces/{t}", op="namespace rm", expect={200, 204, 404})
            except ApiError:
                pass
        self.machines.clear()
        self.endpoints.clear()
        self.invariants("destroy")

    # ---- churn: the daemon's memory ----
    def rss(self):
        """The daemon's resident memory in MB, from its /metrics; None when it does not say."""
        url = self.a.invariants_url or self.a.url
        api = Api(url, self.a.token)
        status, text = api.request("GET", "/metrics", op="metrics", timeout=30)
        for line in text.splitlines() if status == 200 else []:
            if line.startswith("process_resident_memory_bytes "):
                return float(line.split()[1]) / (1 << 20)
        return None

    def churn(self):
        """Cycles of everything a machine goes through, each ending with the namespaces empty
        again; the daemon's memory is read after each. What the first cycle settles (caches,
        the allocator's pools) is not growth; what keeps growing after it is."""
        self.phase(f"churn: {self.a.churn} cycles of create, exec, files, an endpoint, snapshot and restore, backup and restore, fork, suspend, destroy")
        backups = {"on": True}
        sizes = []

        def cycle(c, t, i):
            body = {
                "namespace": t,
                "name": f"c{c}",
                "image": self.a.image,
                "cmd": ["sh", "-c", "mkdir -p /www && echo hello > /www/index.html && exec python3 -m http.server 8080 --directory /www"],
                "size": {"vcpus": 1, "memory_mb": self.a.memory},
                "ports": [8080],
                "sleep": "never",
                "env": {"STRESS_SECRET": "s3cr3t"},
            }
            if i % 2 == 0:
                body["volume"] = {"size_gb": 1, "mount": "/data"}
            m = self.api.call("POST", "/v1/machines", body, op="create", timeout=600)
            mid = m["id"]
            made = [mid]
            try:
                self.wait_state(mid, {"running"}, timeout=self.a.boot_timeout)
                # Synced: a snapshot holds what is on the disk, not in the guest's page cache.
                self.exec(mid, ["sh", "-c", "echo one > /root/mark; sync"])
                blob = rand_bytes(256 << 10)
                self.api.call("PUT", f"/v1/machines/{mid}/files", {"path": "/tmp/blob", "base64": base64.b64encode(blob).decode()}, op="put")
                got = self.api.call("GET", f"/v1/machines/{mid}/files?path=/tmp/blob", op="get_file")
                assert base64.b64decode(got["base64"]) == blob, "file round trip differs"
                ep = self.api.call("POST", f"/v1/machines/{mid}/endpoints", {"port": 8080, "protocol": "tcp"}, op="expose")
                host, port = ep["address"].rsplit(":", 1)
                host = host if host != "0.0.0.0" else "127.0.0.1"
                # The ingress opens the port just after the answer: refused until it listens.
                deadline = time.monotonic() + 30
                for _ in range(5):
                    while True:
                        conn = http.client.HTTPConnection(host, int(port), timeout=90)
                        try:
                            conn.request("GET", "/")
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() > deadline:
                                raise
                            time.sleep(0.2)
                    assert conn.getresponse().status == 200
                    conn.close()
                self.api.call("POST", f"/v1/machines/{mid}/snapshots", {"name": "one"}, op="snapshot")
                self.exec(mid, ["sh", "-c", "echo two > /root/mark; sync"])
                self.api.call("POST", f"/v1/machines/{mid}/snapshots/one/restore", op="restore snapshot", timeout=600)
                self.wait_state(mid, {"running"}, timeout=self.a.boot_timeout)
                assert self.exec(mid, ["cat", "/root/mark"]).strip() == "one", "snapshot not restored"
                if backups["on"]:
                    st, text = self.api.request("POST", f"/v1/machines/{mid}/backups", op="backup", timeout=600)
                    if st == 400:
                        backups["on"] = False
                    elif st != 201:
                        raise RuntimeError(f"backup answered {st} {text[:120]}")
                    else:
                        b = json.loads(text)
                        r = self.api.call("POST", "/v1/machines", {"namespace": t, "name": f"r{c}", "restore": {"machine_id": mid, "backup": b["id"]}, "size": {"vcpus": 1, "memory_mb": self.a.memory}, "sleep": "never"}, op="restore backup", timeout=600)
                        made.append(r["id"])
                        self.wait_state(r["id"], {"running"}, timeout=self.a.boot_timeout)
                        assert self.exec(r["id"], ["cat", "/root/mark"]).strip() == "one", "backup not restored"
                f = self.api.call("POST", "/v1/machines", {"namespace": t, "name": f"f{c}", "fork": {"machine_id": mid, "copy": "disk"}, "cmd": ["sleep", "3600"], "size": {"vcpus": 1, "memory_mb": self.a.memory}, "sleep": "never"}, op="fork", timeout=600)
                made.append(f["id"])
                self.wait_state(f["id"], {"running"}, timeout=self.a.boot_timeout)
                self.api.call("POST", f"/v1/machines/{mid}/stop", {"suspend": True, "timeout_sec": 10}, op="suspend", timeout=120)
                self.wait_state(mid, {"stopped"}, timeout=120)
                self.api.call("POST", f"/v1/machines/{mid}/start", op="resume", timeout=180)
                self.wait_state(mid, {"running"}, timeout=self.a.boot_timeout)
            finally:
                for x in reversed(made):
                    self.api.call("DELETE", f"/v1/machines/{x}", op="destroy", timeout=180)
                if backups["on"]:
                    for b in self.api.call("GET", f"/v1/machines/{mid}/backups", op="backups"):
                        self.api.request("DELETE", f"/v1/machines/{mid}/backups/{b['id']}?chain=true", op="delete backup")
            return True

        for c in range(1, self.a.churn + 1):
            _, errs = parallel(list(enumerate(self.namespaces)), lambda it: cycle(c, it[1], it[0]), self.a.workers)
            self.report_errors(f"churn {c}", errs, self.namespaces)
            # Idle first: jemalloc gives freed pages back after 10 s (ADR 0052).
            time.sleep(12)
            mb = self.rss()
            sizes.append(mb)
            self.log(f"   cycle {c}: daemon RSS {'unknown' if mb is None else f'{mb:.1f} MB'}")
        self.invariants("churn")
        if None in sizes:
            self.log("   RSS check skipped: no process_resident_memory_bytes at the daemon (through a fleet, give --invariants-url)")
            return
        if len(sizes) < 3:
            self.log("   RSS check skipped: fewer than 3 cycles")
            return
        # Growth after the first cycle, over the second half against the first: a leak keeps
        # its slope, a pool that settled does not.
        half = len(sizes) // 2
        first, second = sizes[half] - sizes[0], sizes[-1] - sizes[half]
        self.log(f"   RSS {sizes[0]:.1f} MB after cycle 1, {sizes[-1]:.1f} MB after {len(sizes)}: +{first:.1f} MB to cycle {half + 1}, +{second:.1f} MB after it")
        if second > self.a.rss_growth_mb:
            self.broken.append(("churn", f"daemon RSS grew {second:.1f} MB over cycles {half + 1}..{len(sizes)} (bound {self.a.rss_growth_mb} MB)"))

    # ---- reporting ----
    def report_errors(self, phase, errs, names=None):
        for k, e in errs.items():
            who = names[k] if names and k < len(names) else f"#{k}"
            self.log(f"   FAIL {phase} {who}: {str(e)[:200]}")
        if not errs:
            self.log(f"   ok   {phase}")

    def report(self):
        print()
        print("latencies (s)       n     p50     p95     max")
        for op, ts in sorted(self.api.timings.items()):
            ts = sorted(ts)
            p50 = statistics.median(ts)
            p95 = ts[min(len(ts) - 1, int(len(ts) * 0.95))]
            print(f"{op:<18} {len(ts):>5} {p50:>7.2f} {p95:>7.2f} {ts[-1]:>7.2f}")
        print()
        print(f"api failures: {len(self.api.failures)}")
        for op, path, status, text in self.api.failures[:40]:
            print(f"   {op} {path} -> {status} {text}")
        print(f"invariant breaks: {len(self.broken)}")
        for label, line in self.broken:
            print(f"   after {label}: {line}")

    def run(self):
        self.log(f"stress {self.prefix}: {self.a.namespaces} namespaces × {self.a.per_namespace} machines, {self.a.rounds} round(s), {self.a.workers} workers, {self.a.url}")
        self.invariants("start")
        want = set(self.a.phases.split(",")) if self.a.phases else set(PHASES)
        for r in range(1, self.a.rounds + 1):
            self.create_all(r)
            for name in PHASES:
                if name not in want:
                    continue
                if name == "crash" and not (self.a.crash and r == 1):
                    continue
                getattr(self, name)()
            self.destroy_all()
        if self.a.churn:
            self.churn()
            self.destroy_all()
        self.report()
        return 0 if not self.api.failures and not self.broken else 1


def interrupted(signum, frame):
    raise KeyboardInterrupt


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=os.environ.get("BRIQYARD_URL", "http://127.0.0.1:7420"))
    p.add_argument("--token", default=os.environ.get("BRIQYARD_TOKEN", ""))
    p.add_argument("--namespaces", type=int, default=6)
    p.add_argument("--per-namespace", type=int, default=4)
    p.add_argument("--rounds", type=int, default=1)
    p.add_argument("--workers", type=int, default=12)
    p.add_argument("--hits", type=int, default=20, help="connections per endpoint")
    p.add_argument("--memory", type=int, default=128)
    p.add_argument("--image", default="python:3.12-alpine", help="needs python3 (the web server) and busybox (nslookup, wget)")
    p.add_argument("--boot-timeout", type=int, default=300)
    p.add_argument("--seed", type=int, default=int(time.time()) % 100000)
    p.add_argument("--crash", action="store_true", help="SIGKILL the daemon in round 1 (needs sudo on the host)")
    p.add_argument("--churn", type=int, default=0, help="then this many cycles of every feature per namespace, the daemon's RSS read after each")
    p.add_argument("--rss-growth-mb", type=float, default=32, help="churn: the most the daemon's RSS may grow over the second half of the cycles")
    p.add_argument("--phases", default="", help=f"comma-separated, of {','.join(PHASES)} (default: all); endpoints_all relies on exec_all's wait for the web servers")
    p.add_argument("--no-invariants", action="store_true")
    p.add_argument("--invariants-url", default="", help="the daemon to check the host against when --url is a fleet")
    a = p.parse_args()
    unknown = set(filter(None, a.phases.split(","))) - set(PHASES)
    if unknown:
        p.error(f"unknown phases: {','.join(sorted(unknown))}")
    run = Run(a)
    # A kill or a closed terminal ends the run as Ctrl-C does: with the destroy below.
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    code = 1
    try:
        code = run.run()
    except KeyboardInterrupt:
        run.log("interrupted")
        code = 130
    finally:
        # Each round destroys what it made; a failed or interrupted one, its namespaces included,
        # leaves it to this. A daemon that does not answer is logged; the run keeps its code.
        if run.namespaces:
            run.log("destroying what was made")
            try:
                run.destroy_all()
            except ApiError as e:
                run.log(f"cleanup failed: {e}")
    sys.exit(code)


if __name__ == "__main__":
    main()
