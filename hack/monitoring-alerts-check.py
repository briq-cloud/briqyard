#!/usr/bin/env python3
"""Drives the production alerts to firing and resolved, received by a local webhook (ADR 0094).

Grafana loads the rules of hack/monitoring/grafana/alerting.yaml (the same file the install
reads), with a webhook contact point on loopback in place of Slack, and a few timings
shortened (printed below). Real causes then drive each alert and this script waits for a
`firing` and a `resolved` notification naming it. Run it after hack/install-monitoring.sh
on a disposable host (the native CI runner): it breaks the backup store, fills the host's
memory with a machine, and stops the daemon, and puts everything back.

  monitoring-alerts-check.py rules      backup, capacity, host condition and pressure,
                                        largest slot, crash loop
  monitoring-alerts-check.py host-down  not answering (stops the daemon, starts it)

Needs GRAFANA_PASSWORD_FILE (root's, read with sudo), PROMETHEUS_URL, GRAFANA_URL, sudo,
briqyard on PATH, and python3-yaml.
"""
import argparse
import copy
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "hack/monitoring/grafana/alerting.yaml"
PROVISIONED = Path("/etc/briqyard-monitoring/grafana/alerting/briqyard.yaml")
GRAFANA = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
PROMETHEUS = os.environ.get("PROMETHEUS_URL", "http://127.0.0.1:9090")
STORE = "/var/lib/briqyard/backups"

# What this job changes, and nothing else. The rules' expressions, labels, thresholds,
# states and annotations are the file's.
LARGEST_SLOT_MB = 8192  # the install's LARGEST_SLOT_MB knob (16384 by default); the fixture holds 12288 MB
EVALUATION_INTERVAL = "10s"  # the rules' 1m
NOTIFY = {"group_wait": "5s", "group_interval": "10s"}  # the policy's 30s and 5m; repeat_interval stays
FOR_OVERRIDES = {"briqyard-slots-small": "1m"}  # 10m
CONTACT = "briqyard alert test webhook"

START = time.time()
passed = failed = 0


def say(msg):
    print(f"[+{int(time.time() - START):4d}s] {msg}", flush=True)


def ok(name):
    global passed
    passed += 1
    print(f"  ok   {name}", flush=True)


def bad(name):
    global failed
    failed += 1
    print(f"  FAIL {name}", flush=True)


def run(*cmd, timeout=180, check=False):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({p.returncode}): {p.stdout[-400:]}{p.stderr[-400:]}")
    return p


def sudo(*cmd, **kw):
    return run("sudo", *cmd, **kw)


# ---- the rules as the install reads them -------------------------------------------------

def production_rules():
    """The file after the install's substitution (hack/install-monitoring.sh), parsed."""
    text = SOURCE.read_text()
    text = text.replace('"@LARGEST_SLOT_MB@"', str(LARGEST_SLOT_MB)).replace("@LARGEST_SLOT_MB@", str(LARGEST_SLOT_MB))
    return yaml.safe_load(text)


def test_config(prod, url):
    c = copy.deepcopy(prod)
    c["contactPoints"] = [{
        "orgId": 1, "name": CONTACT,
        "receivers": [{"uid": "briqyard-test-webhook", "type": "webhook",
                       "settings": {"url": url, "httpMethod": "POST"}}],
    }]
    for p in c["policies"]:
        p["receiver"] = CONTACT
        p.update(NOTIFY)
    for g in c["groups"]:
        g["interval"] = EVALUATION_INTERVAL
        for r in g["rules"]:
            if r["uid"] in FOR_OVERRIDES:
                r["for"] = FOR_OVERRIDES[r["uid"]]
    return c


def seconds(d):
    if isinstance(d, (int, float)):
        return d / 1e9 if d > 1e6 else d
    total = 0
    for n, unit in re.findall(r"(\d+)([hms])", d):
        total += int(n) * {"h": 3600, "m": 60, "s": 1}[unit]
    return total


def subset(want, have):
    if isinstance(want, dict):
        return isinstance(have, dict) and all(k in have and subset(v, have[k]) for k, v in want.items())
    if isinstance(want, list):
        return isinstance(have, list) and len(want) == len(have) and all(subset(a, b) for a, b in zip(want, have))
    return want == have


# ---- Grafana and Prometheus ----------------------------------------------------------------

password = None


def get(url, auth=False):
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", "Basic " + b64encode(f"admin:{password}".encode()).decode())
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def grafana(path):
    return get(GRAFANA + path, auth=True)


def prom(query):
    q = urllib.parse.quote(query)
    return get(f"{PROMETHEUS}/api/v1/query?query={q}")["data"]["result"]


def wait_for(what, cond, timeout, every=3):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = cond()
            if v:
                return v
        except Exception:
            pass
        time.sleep(every)
    return None


# ---- the receiver --------------------------------------------------------------------------

class Receiver:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                try:
                    doc = json.loads(body)
                except ValueError:
                    doc = {"raw": body.decode(errors="replace")}
                with outer.lock:
                    outer.events.append({"t": time.time(), "path": self.path, "body": doc})
                self.send_response(200)
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/notify"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def alerts(self):
        with self.lock:
            events = list(self.events)
        for e in events:
            for a in e["body"].get("alerts", []):
                yield e["t"], a

    def summary(self):
        return [f"{time.strftime('%H:%M:%S', time.localtime(t))} {a.get('status')} "
                f"{a.get('labels', {}).get('alertname')} "
                f"{ {k: v for k, v in a.get('labels', {}).items() if not k.startswith('__') and k not in ('alertname', 'grafana_folder')} }"
                for t, a in self.alerts()]


rx = None


class Case:
    """One alert: a real cause, `firing` expected, a recovery, `resolved` expected."""

    def __init__(self, name, uid, title, labels, fire_within, resolve_within, action=None):
        self.name, self.uid, self.title, self.labels = name, uid, title, labels
        self.fire_within, self.resolve_within, self.action = fire_within, resolve_within, action
        self.caused = None      # when the cause was made
        self.recovery = None    # when the recovery was made (or the window began to expire)
        self.fired = self.resolved = None
        self.done = False

    def seen(self, status, after):
        for t, a in rx.alerts():
            labels = a.get("labels", {})
            if (t >= after and a.get("status") == status and labels.get("alertname") == self.title
                    and subset(self.labels, labels)):
                return t, a
        return None


class Action:
    def __init__(self, name, needs, fn):
        self.name, self.needs, self.fn, self.at = name, needs, fn, None


def drive(cases, actions, total):
    """Poll the receiver until every case resolved, or a bound passed."""
    end = time.time() + total
    last = 0
    while time.time() < end and not all(c.done for c in cases):
        now = time.time()
        for c in cases:
            if c.done:
                continue
            if c.fired is None:
                hit = c.seen("firing", c.caused)
                if hit:
                    c.fired = hit[0]
                    ok(f"{c.name}: firing received after {int(c.fired - c.caused)} s")
                elif now > c.caused + c.fire_within:
                    bad(f"{c.name}: no firing notification within {c.fire_within} s")
                    c.done = True
        for a in actions:
            if a.at is None and all(n.fired for n in a.needs):
                say(f"recovery: {a.name}")
                a.at = time.time()
                a.fn()
                for c in cases:
                    if c.action is a:
                        c.recovery = a.at
        for c in cases:
            if c.done or c.fired is None or c.recovery is None:
                continue
            hit = c.seen("resolved", c.fired)
            if hit:
                c.resolved = hit[0]
                ok(f"{c.name}: resolved received {int(c.resolved - c.recovery)} s after its recovery")
                c.done = True
            elif now > c.recovery + c.resolve_within:
                bad(f"{c.name}: no resolved notification within {c.resolve_within} s of its recovery")
                c.done = True
        if now - last > 60:
            last = now
            say("waiting: " + "; ".join(
                f"{c.name} [{'resolved' if c.resolved else 'firing' if c.fired else 'not yet firing'}]"
                for c in cases if not c.done))
        time.sleep(3)
    for c in cases:
        if not c.done:
            bad(f"{c.name}: overall bound of {total} s passed")


# ---- setup, and what the rules under test are -------------------------------------------------

def setup():
    global rx, password
    password = sudo("cat", os.environ["GRAFANA_PASSWORD_FILE"], check=True).stdout.strip()
    rx = Receiver()
    prod = production_rules()
    cfg = test_config(prod, rx.url)
    say(f"receiver on {rx.url}")
    print("test-only changes to the production alerting file:", flush=True)
    print(f"  contact point: Slack -> webhook on loopback ({CONTACT})", flush=True)
    print(f"  group interval {EVALUATION_INTERVAL} (production 1m); policy {NOTIFY} (production group_wait 30s, group_interval 5m)", flush=True)
    print(f"  for: {FOR_OVERRIDES} (production Largest slot too small 10m)", flush=True)
    print(f"  LARGEST_SLOT_MB={LARGEST_SLOT_MB} (production default 16384); every other field, every expression, label and threshold is the file's", flush=True)
    tmp = Path("/tmp/briqyard-alerting-test.yaml")
    tmp.write_text(yaml.safe_dump(cfg, sort_keys=False))
    sudo("install", "-m", "0644", str(tmp), str(PROVISIONED), check=True)
    sudo("systemctl", "restart", "briqyard-grafana", check=True)
    if not wait_for("grafana", lambda: get(GRAFANA + "/api/health").get("database") == "ok", 90, 2):
        raise RuntimeError("grafana did not come back")
    rules = wait_for("rules", lambda: len(grafana("/api/v1/provisioning/alert-rules")) == sum(len(g["rules"]) for g in prod["groups"]) and grafana("/api/v1/provisioning/alert-rules"), 60, 2)
    if not rules:
        bad("Grafana loaded every rule of the file")
        raise RuntimeError("rules not loaded")
    verify(prod, rules)


def verify(prod, loaded):
    """What Grafana evaluates is the file's rule: queries, thresholds, labels, states, texts."""
    by_uid = {r["uid"]: r for r in loaded}
    wrong = []
    for g in prod["groups"]:
        for r in g["rules"]:
            got = by_uid.get(r["uid"])
            if got is None:
                wrong.append(f"{r['uid']}: not loaded")
                continue
            for k in ("title", "condition", "noDataState", "execErrState", "labels", "annotations"):
                if got.get(k) != r[k]:
                    wrong.append(f"{r['uid']}.{k}: file {r[k]!r}, Grafana {got.get(k)!r}")
            want_for = seconds(FOR_OVERRIDES.get(r["uid"], r["for"]))
            if seconds(got.get("for", 0)) != want_for:
                wrong.append(f"{r['uid']}.for: want {want_for}, Grafana {got.get('for')!r}")
            for want in r["data"]:
                have = next((d for d in got["data"] if d["refId"] == want["refId"]), None)
                if have is None or have["datasourceUid"] != want["datasourceUid"] or not subset(want["model"], have["model"]) \
                        or not subset(want.get("relativeTimeRange", {}), have.get("relativeTimeRange", {})):
                    wrong.append(f"{r['uid']}.data[{want['refId']}] differs from the file")
    if wrong:
        for w in wrong:
            print("       " + w, flush=True)
        bad("every rule Grafana loaded is the file's (queries, thresholds, labels, states, texts)")
    else:
        ok(f"every rule Grafana loaded is the file's (queries, thresholds, labels, states, texts): {len(loaded)} rules")


def diagnostics():
    print("== diagnostics", flush=True)
    try:
        for g in grafana("/api/prometheus/grafana/api/v1/rules")["data"]["groups"]:
            for r in g["rules"]:
                print(f"  rule {r['name']!r}: state={r['state']} health={r['health']} err={r.get('lastError')!r} "
                      f"alerts={[(a['state'], {k: v for k, v in a['labels'].items() if not k.startswith('__')}) for a in r.get('alerts', [])]}", flush=True)
    except Exception as e:
        print(f"  grafana rules: {e}", flush=True)
    print("  receiver:", flush=True)
    for line in rx.summary():
        print("   ", line, flush=True)
    with rx.lock:
        print(f"  {len(rx.events)} notifications; last: {json.dumps(rx.events[-1]['body'])[:1500] if rx.events else None}", flush=True)
    for q in ("up", "briqyard_host_condition > 0", "briqyard_fleet_largest_slot_mb", 'increase(briqyard_fleet_unschedulable_total[5m]) > 0',
              'briqyard_events_total{reason="backup_failed"}', "increase(briqyard_machine_restarts_total[10m]) > 0"):
        try:
            print(f"  {q}: {json.dumps([(r['metric'], r['value'][1]) for r in prom(q)])[:600]}", flush=True)
        except Exception as e:
            print(f"  {q}: {e}", flush=True)
    print(sudo("journalctl", "-u", "briqyard-grafana", "--no-pager", "-n", "40").stdout[-4000:], flush=True)
    print(run("curl", "-sS", "http://127.0.0.1:7430/v1/hosts").stdout[:1500], flush=True)


# ---- causes -------------------------------------------------------------------------------

machines = []
namespaces = []


def machine(ns, name, memory, *extra, cmd=("sleep", "3600"), detach=False):
    namespaces.append(ns)
    args = ["briqyard", "machine", "run", "--image", "alpine:3.20", "--namespace", ns, "--name", name,
            "--memory", str(memory), "--sleep", "never", *extra]
    if detach:
        args.append("--detach")
    p = run(*args, "--", *cmd, timeout=300)
    if p.returncode != 0:
        raise RuntimeError(f"machine {name}: {p.stdout[-300:]}{p.stderr[-300:]}")
    mid = json.loads(p.stdout)["id"]
    machines.append(mid)
    return mid


def destroy(mid):
    run("briqyard", "machine", "destroy", mid, timeout=120)
    if mid in machines:
        machines.remove(mid)


def cleanup():
    for m in list(machines):
        destroy(m)
    for ns in set(namespaces):
        run("briqyard", "namespace", "rm", ns, timeout=120)
    if sudo("test", "-e", STORE + ".alert-off").returncode == 0:
        sudo("rm", "-rf", STORE)
        sudo("mv", STORE + ".alert-off", STORE)


def rules_set():
    crash_id = machine("alert-crash", "crashy", 128, cmd=("sh", "-c", "sleep 2; exit 1"), detach=True)
    t_crash = time.time()
    say(f"crash-looping machine {crash_id}")
    bk = machine("alert-backup", "bk", 128)
    p = run("briqyard", "machine", "backup", bk, timeout=300)
    (ok if p.returncode == 0 else bad)("a backup into a working store succeeds (no alert for it)")

    # Backup failure: the store path is a file, so nothing can be written under it.
    sudo("mv", STORE, STORE + ".alert-off", check=True)
    sudo("touch", STORE, check=True)
    t_backup = time.time()
    p = run("briqyard", "machine", "backup", bk, timeout=300)
    (ok if p.returncode != 0 else bad)(f"a backup into a store that refuses writes fails ({(p.stderr or p.stdout).strip()[-120:]!r})")
    sudo("rm", "-f", STORE, check=True)
    sudo("mv", STORE + ".alert-off", STORE, check=True)
    p = run("briqyard", "machine", "backup", bk, timeout=300)
    (ok if p.returncode == 0 else bad)("the store put back, a backup succeeds again")

    # Capacity refusal: more memory than the host holds (12288 MB).
    t_room = time.time()
    p = run("briqyard", "machine", "run", "--image", "alpine:3.20", "--namespace", "alert-room", "--name", "toolarge",
            "--memory", "20000", "--detach", "--", "sleep", "60", timeout=120)
    (ok if p.returncode != 0 and "room" in (p.stderr + p.stdout).lower() else bad)(
        f"a create of 20000 MB is refused for capacity ({(p.stderr or p.stdout).strip()[-120:]!r})")
    namespaces.append("alert-room")

    # Host condition, host pressure and the largest slot: one machine takes 11800 of 12288 MB.
    big = machine("alert-big", "big", 11800)
    t_big = time.time()
    if not wait_for("memory_pressure", lambda: prom('briqyard_host_condition{condition="memory_pressure"} == 1'), 240, 5):
        bad("the host reported memory_pressure with 11800 MB committed")
        raise RuntimeError("no memory_pressure")
    ok("the host reported memory_pressure with 11800 MB committed")
    t_pressure = time.time()
    p = run("briqyard", "machine", "run", "--image", "alpine:3.20", "--namespace", "alert-big", "--name", "second",
            "--memory", "128", "--detach", "--", "sleep", "60", timeout=120)
    text = (p.stderr + p.stdout).lower()
    (ok if p.returncode != 0 and "memory_pressure" in text else bad)(
        f"a create into that namespace is refused under pressure ({(p.stderr or p.stdout).strip()[-140:]!r})")

    crash = Case("Machine in a crash loop", "briqyard-crash-loop", "Machine in a crash loop", {"namespace": "alert-crash", "host": "local"}, 480, 300,
                 action=None)
    backup = Case("Backup failure observed", "briqyard-backup-failed", "Backup failure observed", {"host": "local"}, 240, 540)
    room = Case("Creates refused: no room", "briqyard-out-of-room", "Creates refused: no room", {"region": "dev", "resource": "memory"}, 240, 300)
    cond = Case("Host condition", "briqyard-host-condition", "Host condition", {"host": "local", "condition": "memory_pressure"}, 360, 300)
    press = Case("Creates refused: host under pressure", "briqyard-host-pressure", "Creates refused: host under pressure", {"region": "dev"}, 240, 300)
    slot = Case("Largest slot too small", "briqyard-slots-small", "Largest slot too small", {"region": "dev"}, 420, 300)
    crash.caused, backup.caused, room.caused = t_crash, t_backup, t_room
    cond.caused, slot.caused, press.caused = t_big, t_big, t_pressure
    # The window alerts expire by themselves (ten and five minutes of events).
    backup.recovery, room.recovery, press.recovery = t_backup, t_room, t_pressure
    backup.resolve_within = 600 + 240
    room.resolve_within = press.resolve_within = 300 + 240
    destroy_crash = Action("destroy the crash-looping machine", [crash], lambda: destroy(crash_id))
    destroy_big = Action("destroy the machine holding the host's memory", [cond, slot], lambda: destroy(big))
    crash.action, cond.action, slot.action = destroy_crash, destroy_big, destroy_big
    drive([crash, backup, room, cond, press, slot], [destroy_crash, destroy_big], 1500)


def host_down_set():
    case = Case("Not answering", "briqyard-not-answering", "Not answering", {"instance": "local"}, 420, 360)
    already = [1 for _, a in rx.alerts() if a["labels"].get("alertname") == "Not answering" and a["labels"].get("instance") == "local"]
    (ok if not already else bad)("no Not answering for the live daemon before it is stopped")
    case.caused = time.time()
    sudo("systemctl", "stop", "briqyardd", check=True)
    say("daemon stopped")

    def start():
        sudo("systemctl", "start", "briqyardd", check=True)
        if wait_for("host", lambda: any(h["id"] == "local" and h["state"] == "ready" for h in json.loads(run("curl", "-fsS", "http://127.0.0.1:7430/v1/hosts").stdout)), 180, 3):
            ok("the daemon is back and the fleet reads the host ready")
        else:
            bad("the daemon is back and the fleet reads the host ready")

    action = Action("start the daemon", [case], start)
    case.action = action
    drive([case], [action], 900)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("set", choices=["rules", "host-down"])
    args = ap.parse_args()
    try:
        setup()
        if failed == 0:
            {"rules": rules_set, "host-down": host_down_set}[args.set]()
    except Exception as e:
        bad(f"aborted: {e}")
    finally:
        try:
            if args.set == "host-down" and sudo("systemctl", "is-active", "briqyardd").stdout.strip() != "active":
                sudo("systemctl", "start", "briqyardd")
            cleanup()
        except Exception as e:
            print(f"cleanup: {e}", flush=True)
    print("== notifications received", flush=True)
    for line in rx.summary() if rx else []:
        print("   ", line, flush=True)
    if failed:
        try:
            diagnostics()
        except Exception as e:
            print(f"diagnostics: {e}", flush=True)
    print(f"\npassed {passed}, failed {failed}  (wall {int(time.time() - START)} s)", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
