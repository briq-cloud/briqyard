#!/usr/bin/env python3
"""Chaos through a briqyard daemon or fleet: owners that check their data, racers that don't.

Standard library only. Each owner thread keeps one machine and a counter on its disks
(`/root/n`, and `/data/n` on a volume for every other owner), and runs a random sequence of
operations, checking after each that the disks hold what they should:

| op         | what it checks                                                                 |
|------------|--------------------------------------------------------------------------------|
| write      | the counter goes up by one (`sync`ed)                                          |
| verify     | the counter reads back                                                         |
| stopstart  | the counter after a stop and a start                                           |
| restart    | the counter after a restart                                                    |
| fork       | a fork of the disks holds the counter                                          |
| snapshot   | snapshot (a third with memory), write, restore: the snapshot's counter; with   |
|            | memory, the same again after a cold boot, so the disks are checked, not only   |
|            | the memory's page cache                                                        |
| backup     | a backup; half restored into a new machine that holds the counter              |
| recreate   | destroy, then a new machine                                                    |

Racers stop, start, restart, snapshot, back up and exec on any machine without coordination.
They check only that the API never answers 5xx (but 503 `capacity`) or an unexpected 4xx.

A write a racer cuts short (the machine stopped under the command: 409 `not_running`) may
have run, in full, in part, or not at all. Its owner reads the counters back once the machine
runs again: each must be its old value or its new one, on its own, since a stop between the two
disks' writes leaves one of each. Never assume the old value: the command often ran.

    python3 hack/chaos.py --minutes 10                        # the VM's daemon
    python3 hack/chaos.py --url http://127.0.0.1:7430 --tenants 8 --racers 8 --backups

Exit code 1 when an integrity check failed or an answer was unexpected; the report says which.
"""
import argparse
import json
import os
import random
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

# Refusals a race explains: nothing was done.
RACE_OK = {"conflict", "bad_state", "not_running", "not_ready", "gone"}
PENDING = {"starting", "stopping", "destroying", "created"}


class Api:
    def __init__(self, url, token, cafile=None):
        self.url, self.token = url.rstrip("/"), token
        self.ctx = ssl.create_default_context(cafile=cafile) if cafile else None
        self.lock = threading.Lock()
        self.stats = {}
        self.unexpected = []

    def req(self, method, path, body=None, timeout=600):
        """(status, json or None, text, error code)."""
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.url + path, data=data, method=method)
        r.add_header("content-type", "application/json")
        if self.token:
            r.add_header("authorization", f"Bearer {self.token}")
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(r, timeout=timeout, context=self.ctx) as resp:
                st, txt = resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            st, txt = e.code, e.read().decode(errors="replace")
        except Exception as e:
            st, txt = 0, f"{type(e).__name__}: {e}"
        dt = time.monotonic() - t0
        try:
            j = json.loads(txt) if txt.strip().startswith(("{", "[")) else None
        except ValueError:
            j = None
        code = j.get("code") if isinstance(j, dict) and st >= 400 else None
        seg = path.split("?")[0].split("/")
        key = f"{method} {seg[4] if len(seg) > 4 else '/'.join(seg[2:3]) + ('/id' if len(seg) > 3 else '')}"
        with self.lock:
            s = self.stats.setdefault(key, {"t": [], "codes": {}})
            s["t"].append(dt)
            c = f"{st}:{code}" if code else str(st)
            s["codes"][c] = s["codes"].get(c, 0) + 1
        return st, j, txt, code

    def note(self, who, what):
        line = f"[{time.strftime('%H:%M:%S')}] {who}: {what}"
        with self.lock:
            self.unexpected.append(line)
        print("UNEXPECTED " + line, flush=True)


class Chaos:
    def __init__(self, a):
        self.a = a
        self.api = Api(a.url, a.token, a.cafile)
        self.prefix = a.prefix or f"ch{a.seed % 1000:03d}"
        self.stop_at = time.monotonic() + a.minutes * 60
        self.machines = {}  # id -> tenant, for the racers
        self.mlock = threading.Lock()
        self.backups = []  # (machine id, tenant, backup id)
        self.counts = {}
        self.integrity = []

    def count(self, k):
        with self.mlock:
            self.counts[k] = self.counts.get(k, 0) + 1

    def exec(self, mid, script, timeout_ms=60000):
        body = {"cmd": ["sh", "-c", script], "timeout_ms": timeout_ms, "wake": True}
        return self.api.req("POST", f"/v1/machines/{mid}/exec", body, timeout=timeout_ms / 1000 + 120)

    def create(self, tenant, name, vol, extra=None):
        body = {"tenant": tenant, "name": name, "image": self.a.image, "cmd": ["sleep", "infinity"],
                "size": {"vcpus": 1, "memory_mb": self.a.memory}, "sleep": "never",
                "metadata": {"chaos": self.prefix}}
        if vol:
            body["volume"] = {"size_gb": 1, "mount": "/data"}
        if extra:
            # A fork or a restore takes the source's disks and image.
            for k in ("image", "cmd", "volume"):
                body.pop(k, None)
            body.update(extra)
        return self.api.req("POST", "/v1/machines", body)

    # ---- owners: integrity ----

    def owner(self, tenant, slot):
        who = f"{tenant}/s{slot}"
        rng = random.Random(f"{self.a.seed}-{tenant}-{slot}")
        vol = slot % 2 == 0
        read_cmd = "cat /root/n 2>/dev/null || echo 0; " + ("cat /data/n 2>/dev/null || echo 0" if vol else "echo 0")
        gen, mid = 0, None
        # The counters (root, data) when known; else `maybe`, the values they came from, each
        # counter any of its own values there.
        val, maybe = (0, 0), set()

        def unknown(*values):
            nonlocal val, maybe
            maybe = {v for v in values if v is not None} | (maybe if val is None else set())
            val = None

        def read(target):
            """The counters, or None when the machine cannot run the command now."""
            st, j, txt, code = self.exec(target, read_cmd)
            if st == 200 and j["exit_code"] == 0:
                got = j["stdout"].split()
                try:
                    return int(got[0]), int(got[1])
                except (ValueError, IndexError):
                    self.api.note(who, f"read {target}: {j['stdout']!r}")
                    return None
            if code not in RACE_OK:
                self.api.note(who, f"read {target}: {st} {txt[:200]}")
            return None

        def fail(label, target, got, want):
            msg = f"{who} INTEGRITY {label} {target}: got {list(got)} want {want}"
            with self.mlock:
                self.integrity.append(msg)
            print(msg, flush=True)

        def verify(target, label, expect):
            got = read(target)
            if got is None:
                self.count(f"skip:{label}")
            elif got != expect:
                fail(label, target, got, list(expect))
            else:
                self.count(f"verify:{label}")

        def resolve():
            """Reads the counters back after a write whose outcome is unknown."""
            nonlocal val, maybe
            st, m, _, _ = self.api.req("GET", f"/v1/machines/{mid}")
            if st == 200 and m["state"] == "stopped":
                self.api.req("POST", f"/v1/machines/{mid}/start")
            got = read(mid)
            if got is None:
                return False
            each = [{c[i] for c in maybe} for i in range(2)]
            if not all(g in e for g, e in zip(got, each)):
                fail("cut-write", mid, got, f"each counter one of {[sorted(e) for e in each]}")
            self.count("resolved")
            val, maybe = got, set()
            return True

        def write():
            n = val[0] + 1
            new = (n, n if vol else 0)
            cmd = f"echo {n} > /root/n" + (f" && echo {n} > /data/n" if vol else "") + " && sync"
            st, j, txt, code = self.exec(mid, cmd)
            if st == 200 and j["exit_code"] == 0:
                self.count("write")
                set_val(new)
                return
            if st == 200:
                self.api.note(who, f"write exit {j['exit_code']}: {j.get('stderr', '')[:200]}")
            elif code not in RACE_OK:
                self.api.note(who, f"write {mid}: {st} {txt[:200]}")
            # Cut short: the command may have run, on either disk or both. Read back once the
            # machine runs.
            self.count("write-cut")
            unknown(val, new)

        def set_val(v):
            nonlocal val, maybe
            val, maybe = v, set()

        def destroy(target, label):
            for _ in range(30):
                st, _, txt, code = self.api.req("DELETE", f"/v1/machines/{target}", timeout=300)
                if st in (200, 204, 404):
                    self.count(label)
                    with self.mlock:
                        self.machines.pop(target, None)
                    return True
                if code not in RACE_OK:
                    self.api.note(who, f"{label} {target}: {st} {txt[:200]}")
                    return False
                time.sleep(1)
            self.api.note(who, f"{label} {target}: still refused after 30 tries")
            return False

        def running(target, label, timeout=300):
            """Waits for the machine to run, starting it again when a racer stopped it."""
            deadline, state = time.monotonic() + timeout, None
            while time.monotonic() < deadline:
                st, m, _, _ = self.api.req("GET", f"/v1/machines/{target}", timeout=60)
                if st == 404:
                    return False
                state = m["state"] if st == 200 else state
                if state == "running":
                    return True
                if state == "error":
                    self.api.note(who, f"{label}: {target} in error: {m.get('error')}")
                    return False
                if state == "stopped":
                    self.api.req("POST", f"/v1/machines/{target}/start")
                time.sleep(0.5)
            self.api.note(who, f"{label}: {target} not running after {timeout}s: {state}")
            return False

        def adopt(target):
            with self.mlock:
                self.machines[target] = tenant

        try:
            while time.monotonic() < self.stop_at:
                if mid is None:
                    gen += 1
                    st, j, txt, code = self.create(tenant, f"s{slot}g{gen}", vol)
                    if st != 201:
                        if not (st == 503 and code == "capacity"):
                            self.api.note(who, f"create: {st} {txt[:200]}")
                        time.sleep(5)
                        continue
                    mid = j["id"]
                    adopt(mid)
                    set_val((0, 0))
                    self.count("create")
                    running(mid, "new machine")
                    write()
                    continue
                if val is None and not resolve():
                    time.sleep(1)
                    continue
                st0, m0, _, _ = self.api.req("GET", f"/v1/machines/{mid}")
                if st0 == 200 and m0["state"] == "stopped":
                    self.api.req("POST", f"/v1/machines/{mid}/start")
                op = rng.choice(["write", "write", "verify", "stopstart", "restart", "fork", "snapshot", "backup", "recreate"])
                if op == "write":
                    write()
                elif op == "verify":
                    verify(mid, "read", val)
                elif op in ("stopstart", "restart"):
                    calls = [("stop", {"timeout_sec": 10}), ("start", None)] if op == "stopstart" else [("restart", None)]
                    for call, body in calls:
                        st, _, txt, code = self.api.req("POST", f"/v1/machines/{mid}/{call}", body)
                        if st != 200 and code not in RACE_OK:
                            self.api.note(who, f"{call}: {st} {txt[:200]}")
                    if running(mid, f"after {op}"):
                        verify(mid, op, val)
                elif op == "fork":
                    expect = val
                    st, j, txt, code = self.create(tenant, f"s{slot}g{gen}-f{rng.randint(0, 99999)}", vol,
                                                   {"fork": {"machine_id": mid, "copy": "disk"}})
                    if st != 201:
                        if code not in RACE_OK and not (st == 503 and code == "capacity"):
                            self.api.note(who, f"fork: {st} {txt[:200]}")
                        continue
                    f = j["id"]
                    adopt(f)
                    # A fork takes the disks, not the command: set it and restart.
                    self.api.req("PATCH", f"/v1/machines/{f}", {"cmd": ["sleep", "infinity"]})
                    self.api.req("POST", f"/v1/machines/{f}/restart")
                    if running(f, f"fork {f}"):
                        verify(f, "fork", expect)
                    destroy(f, "fork-destroy")
                elif op == "snapshot":
                    name, memory = f"c{rng.randint(0, 10**6)}", rng.random() < 0.3
                    before = val
                    st, j, txt, code = self.api.req("POST", f"/v1/machines/{mid}/snapshots", {"name": name, "memory": memory})
                    if st != 201:
                        if code not in RACE_OK:
                            self.api.note(who, f"snapshot: {st} {txt[:200]}")
                        continue
                    write()
                    st, j, txt, code = self.api.req("POST", f"/v1/machines/{mid}/snapshots/{name}/restore")
                    if st == 200:
                        set_val(before)
                    elif code in RACE_OK:
                        pass  # refused: nothing restored
                    else:
                        self.api.note(who, f"snapshot restore: {st} {txt[:200]}")
                        unknown(before, val)
                    if st == 200 and running(mid, "after snapshot restore"):
                        verify(mid, "snaprestore", before)
                        # The read above may come from the restored memory's page cache: a
                        # cold boot reads the disks.
                        if memory:
                            self.api.req("POST", f"/v1/machines/{mid}/restart")
                            if running(mid, "cold boot after a memory restore"):
                                verify(mid, "memrestore-cold", before)
                    self.api.req("DELETE", f"/v1/machines/{mid}/snapshots/{name}")
                    self.count("snapshot")
                elif op == "backup" and self.a.backups:
                    expect = val
                    st, j, txt, code = self.api.req("POST", f"/v1/machines/{mid}/backups", None, timeout=900)
                    if st != 201:
                        if code not in RACE_OK:
                            self.api.note(who, f"backup: {st} {txt[:200]}")
                        continue
                    with self.mlock:
                        self.backups.append((mid, tenant, j["id"]))
                    self.count("backup")
                    if rng.random() < 0.5:
                        st, j2, txt, code = self.create(tenant, f"r{rng.randint(0, 99999)}", vol,
                                                        {"restore": {"machine_id": mid, "backup": j["id"]}})
                        if st != 201:
                            if not (st == 503 and code == "capacity"):
                                self.api.note(who, f"restore {mid}/{j['id']}: {st} {txt[:200]}")
                            continue
                        r = j2["id"]
                        adopt(r)
                        if running(r, f"restore {r}"):
                            verify(r, "backuprestore", expect)
                        destroy(r, "restore-destroy")
                elif op == "recreate":
                    if destroy(mid, "destroy"):
                        mid = None
            if mid and (val is not None or resolve()):
                verify(mid, "final", val)
        except Exception as e:
            self.api.note(who, f"owner crashed: {e}\n{traceback.format_exc()[-600:]}")

    # ---- racers ----

    def racer(self, i):
        rng = random.Random(f"{self.a.seed}-racer-{i}")
        who = f"racer{i}"
        while time.monotonic() < self.stop_at:
            with self.mlock:
                ids = list(self.machines)
            if not ids:
                time.sleep(1)
                continue
            mid = rng.choice(ids)
            op = rng.choice(["stop", "start", "start", "restart", "snap", "exec", "exec", "get", "backup", "events", "logs"])
            if op in ("stop", "start", "restart"):
                st, j, txt, code = self.api.req("POST", f"/v1/machines/{mid}/{op}", {"timeout_sec": 5} if op == "stop" else None)
            elif op == "snap":
                st, j, txt, code = self.api.req("POST", f"/v1/machines/{mid}/snapshots", {"name": f"r{rng.randint(0, 10**6)}"})
                if st == 201:
                    self.api.req("DELETE", f"/v1/machines/{mid}/snapshots/{j['id']}")
            elif op == "exec":
                st, j, txt, code = self.exec(mid, "cat /root/n 2>/dev/null; uptime", 20000)
            elif op == "backup" and self.a.backups and rng.random() < 0.3:
                with self.mlock:
                    t = self.machines.get(mid)
                st, j, txt, code = self.api.req("POST", f"/v1/machines/{mid}/backups", None, timeout=900)
                if st == 201:
                    with self.mlock:
                        self.backups.append((mid, t, j["id"]))
            elif op == "events":
                st, j, txt, code = self.api.req("GET", f"/v1/events?machine={mid}")
            elif op == "logs":
                st, j, txt, code = self.api.req("GET", f"/v1/machines/{mid}/logs?limit=50")
            else:
                op = "get"
                st, j, txt, code = self.api.req("GET", f"/v1/machines/{mid}")
            self.count(f"race:{op}")
            if st == 0 or (st >= 500 and code != "capacity"):
                self.api.note(who, f"{op} {mid}: {st} {txt[:200]}")
            elif st >= 400 and st != 404 and code not in RACE_OK and code != "capacity":
                self.api.note(who, f"{op} {mid}: {st} {txt[:200]}")
            time.sleep(rng.random() * 0.5)

    # ---- the end ----

    def mine(self):
        st, ms, txt, _ = self.api.req("GET", "/v1/machines")
        if st != 200:
            self.api.note("final", f"list: {st} {txt[:200]}")
            return []
        return [m for m in ms if m["tenant"].startswith(self.prefix + "-")]

    def settle_check(self):
        deadline = time.monotonic() + 180
        while True:
            mine = self.mine()
            stuck = [(m["id"], m["state"], m.get("error")) for m in mine if m["state"] in PENDING or m["state"] == "error"]
            if not stuck or time.monotonic() > deadline:
                break
            time.sleep(2)
        by = {}
        for m in mine:
            by[m["state"]] = by.get(m["state"], 0) + 1
        log(f"final: {len(mine)} machines {by}")
        for s in stuck:
            self.api.note("final", f"not settled: {s}")

    def cleanup(self):
        for m in self.mine():
            for _ in range(20):
                st, _, txt, _ = self.api.req("DELETE", f"/v1/machines/{m['id']}", timeout=300)
                if st in (200, 204, 404):
                    break
                time.sleep(2)
            else:
                self.api.note("cleanup", f"destroy {m['id']}: {st} {txt[:200]}")
        seen = set()
        for mid, t, bid in self.backups:
            if (mid, bid) in seen:
                continue
            seen.add((mid, bid))
            st, _, txt, _ = self.api.req("DELETE", f"/v1/machines/{mid}/backups/{bid}?chain=true&tenant={t}", timeout=300)
            if st not in (200, 204, 404):
                self.api.note("cleanup", f"backup rm {mid}/{bid}: {st} {txt[:200]}")
        for t in [f"{self.prefix}-t{i}" for i in range(self.a.tenants)]:
            for _ in range(10):
                st, _, txt, _ = self.api.req("DELETE", f"/v1/tenants/{t}")
                if st in (200, 204, 404):
                    break
                time.sleep(3)
            else:
                self.api.note("cleanup", f"tenant rm {t}: {st} {txt[:200]}")

    def run(self):
        log(f"chaos {self.prefix}: {self.a.tenants} tenants x {self.a.per_tenant} owners, {self.a.racers} racers, {self.a.minutes} min, {self.a.url}")
        threads = [threading.Thread(target=self.owner, args=(f"{self.prefix}-t{t}", s))
                   for t in range(self.a.tenants) for s in range(self.a.per_tenant)]
        threads += [threading.Thread(target=self.racer, args=(i,)) for i in range(self.a.racers)]
        for t in threads:
            t.start()
            time.sleep(0.2)
        last = time.monotonic()
        while any(t.is_alive() for t in threads):
            time.sleep(5)
            if time.monotonic() - last > 60:
                last = time.monotonic()
                with self.mlock:
                    log(f"progress: {len(self.machines)} machines, {dict(sorted(self.counts.items()))}, unexpected {len(self.api.unexpected)}, integrity {len(self.integrity)}")
        self.settle_check()
        if not self.a.keep:
            self.cleanup()
        print("\nop                         n     p50     p95     max   codes")
        for k, s in sorted(self.api.stats.items()):
            t = sorted(s["t"])
            print(f"{k:<24} {len(t):>5} {t[len(t) // 2]:>7.2f} {t[min(len(t) - 1, int(len(t) * 0.95))]:>7.2f} {t[-1]:>7.2f}   {s['codes']}")
        print(f"\ncounts: {dict(sorted(self.counts.items()))}")
        print(f"unexpected: {len(self.api.unexpected)}")
        for u in self.api.unexpected[:80]:
            print("   " + u)
        print(f"integrity errors: {len(self.integrity)}")
        for u in self.integrity:
            print("   " + u)
        return 0 if not self.api.unexpected and not self.integrity else 1


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--url", default=os.environ.get("BRIQYARD_URL", "http://127.0.0.1:7420"))
    p.add_argument("--token", default=os.environ.get("BRIQYARD_TOKEN", ""))
    p.add_argument("--cafile", default=os.environ.get("CURL_CA_BUNDLE"), help="the API's certificate, over https")
    p.add_argument("--tenants", type=int, default=4)
    p.add_argument("--per-tenant", type=int, default=3, help="owners per tenant")
    p.add_argument("--racers", type=int, default=4)
    p.add_argument("--minutes", type=float, default=10)
    p.add_argument("--image", default="alpine:3.20")
    p.add_argument("--memory", type=int, default=128)
    p.add_argument("--seed", type=int, default=int(time.time()) % 100000)
    p.add_argument("--prefix", default="", help="tenant prefix (default ch<seed>)")
    p.add_argument("--backups", action="store_true", help="also back up and restore (needs a backup store)")
    p.add_argument("--keep", action="store_true", help="leave the machines and backups")
    sys.exit(Chaos(p.parse_args()).run())
