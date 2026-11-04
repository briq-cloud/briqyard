#!/usr/bin/env python3
"""Drives the production alerts to firing and resolved, received by a local webhook (ADR 0094).

The real install (hack/install-monitoring.sh, with an alerting.env whose SLACK_WEBHOOK_URL is
this script's loopback receiver, and LARGEST_SLOT_MB=8192) provisions the rules of
hack/monitoring/grafana/alerting.yaml and its Slack contact point; Grafana posts Slack-shaped
messages to the receiver, which reads each alert's status and labels from them. Only a few
timings are shortened on top of the installed file (printed below). Real causes then drive each alert and this script waits for a
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

# What this job changes on top of the installed file, and nothing else. The rules' expressions,
# labels, thresholds, states and annotations, and the Slack contact point, are the install's.
LARGEST_SLOT_MB = 8192  # given to the install (its knob, 16384 by default); the fixture holds 12288 MB
RECEIVER_PORT = int(os.environ.get("ALERT_RECEIVER_PORT", "18199"))  # in alerting.env, written by the CI script
EVALUATION_INTERVAL = "10s"  # the rules' 1m
NOTIFY = {"group_wait": "5s", "group_interval": "10s"}  # the policy's 30s and 5m; repeat_interval stays
FOR_OVERRIDES = {"briqyard-slots-small": "1m"}  # 10m

# The CLI asks the fleet, not the daemon: placement and its refusals are the fleet's.
os.environ["BRIQYARD_URL"] = os.environ.get("FLEET_URL", "http://127.0.0.1:7430")

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
    """The file as the install renders it (hack/render-alerting.sh, the install's own step), parsed."""
    text = run("bash", str(ROOT / "hack/render-alerting.sh"), str(LARGEST_SLOT_MB), check=True).stdout
    return yaml.safe_load(text)


def test_overrides(installed):
    """The installed file with the job's timings: nothing else."""
    c = copy.deepcopy(installed)
    for p in c["policies"]:
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


def strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from strings(v)


def parse_slack(doc):
    """The alerts of a Slack message as Grafana's default template writes it: a title
    `[FIRING:1] ...`, then `**Firing**` / `**Resolved**` sections, each alert a `Labels:` list."""
    text = "\n".join(strings(doc))
    m = re.search(r"\[(FIRING|RESOLVED)", text, re.I)
    status = m.group(1).lower() if m else None
    alerts, cur, in_labels = [], None, False
    for line in text.splitlines():
        l = line.strip()
        m = re.fullmatch(r"\W*(firing|resolved)\W*", l, re.I)
        if m:
            status, cur, in_labels = m.group(1).lower(), None, False
        elif l.lower().startswith("labels:"):
            cur = {"status": status, "labels": {}}
            alerts.append(cur)
            in_labels = True
        elif in_labels and cur is not None:
            m = re.match(r"[-*\u2022]\s*([A-Za-z_][\w.]*)\s*=\s*(.*)$", l)
            if m:
                if m.group(2).strip():  # Grafana drops empty labels
                    cur["labels"][m.group(1)] = m.group(2).strip()
            else:
                in_labels = False
    return alerts


def episodes(seq):
    """(firing episodes, resolved episodes): a repeated status is a re-send, not a new episode."""
    firing = resolved = 0
    prev = None
    for st in seq:
        firing += st == "firing" and prev != "firing"
        resolved += st == "resolved" and prev != "resolved"
        prev = st
    return firing, resolved


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
                if isinstance(doc, dict) and "alerts" not in doc:
                    doc["alerts"] = parse_slack(doc)
                with outer.lock:
                    outer.events.append({"t": time.time(), "path": self.path, "body": doc})
                self.send_response(200)
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", RECEIVER_PORT), H)
        self.url = f"http://127.0.0.1:{RECEIVER_PORT}/"
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

    def __init__(self, name, uid, title, labels, fire_within, resolve_within, action=None, window=0, absent=()):
        self.name, self.uid, self.title, self.labels = name, uid, title, labels
        self.absent = absent  # labels the alert must not carry (an ask without a region has no region label)
        self.fire_within, self.resolve_within, self.action = fire_within, resolve_within, action
        # An alert over a window of events cannot truly resolve before the window has passed:
        # an earlier `resolved` is a flap, noted but not counted as the recovery.
        self.window = window
        self.caused = None      # when the cause was made
        self.recovery = None    # when the recovery was made (or the window began to expire)
        self.fired = self.resolved = None
        self.done = False

    def seen(self, status, after):
        for t, a in rx.alerts():
            labels = a.get("labels", {})
            if (t >= after and a.get("status") == status and labels.get("alertname") == self.title
                    and subset(self.labels, labels) and not any(k in labels for k in self.absent)):
                return t, a
        return None


class Action:
    def __init__(self, name, needs, fn):
        self.name, self.needs, self.fn, self.at = name, needs, fn, None


EXPR = {}


def sample(cases):
    """What each unfinished rule's own query returns now (the file's expression)."""
    for c in cases:
        if c.done or c.uid not in EXPR:
            continue
        try:
            got = [({k: v for k, v in r["metric"].items() if k not in ("__name__", "job", "instance")}, r["value"][1]) for r in prom(EXPR[c.uid])]
        except Exception as e:
            got = str(e)
        print(f"         {c.name}: query -> {json.dumps(got)[:300]}", flush=True)


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
            hit = c.seen("resolved", max(c.fired, c.caused + max(c.window - 60, 0)))
            if hit:
                c.resolved = hit[0]
                ok(f"{c.name}: resolved received {int(c.resolved - c.recovery)} s after its recovery")
                c.done = True
            elif now > c.recovery + c.resolve_within:
                bad(f"{c.name}: no resolved notification within {c.resolve_within} s of its recovery")
                c.done = True
        if now - last > 60:
            last = now
            sample(cases)
            say("waiting: " + "; ".join(
                f"{c.name} [{'resolved' if c.resolved else 'firing' if c.fired else 'not yet firing'}]"
                for c in cases if not c.done))
        time.sleep(3)
    for c in cases:
        if not c.done:
            bad(f"{c.name}: overall bound of {total} s passed")
        seq = [a.get("status") for _, a in sorted(rx.alerts(), key=lambda x: x[0])
               if a.get("labels", {}).get("alertname") == c.title and subset(c.labels, a.get("labels", {}))
               and not any(k in a.get("labels", {}) for k in c.absent)]
        if c.resolved:
            f, r = episodes(seq)
            (ok if (f, r) == (1, 1) and seq[-1] == "resolved" else bad)(
                f"{c.name}: one firing episode and one resolved, no flap ({f} firing, {r} resolved; received {seq})")


# ---- setup, and what the rules under test are -------------------------------------------------

def setup():
    global rx, password
    password = sudo("cat", os.environ["GRAFANA_PASSWORD_FILE"], check=True).stdout.strip()
    rx = Receiver()
    prod = production_rules()
    for g in prod["groups"]:
        for r in g["rules"]:
            EXPR[r["uid"]] = next(d for d in r["data"] if d["refId"] == "A")["model"]["expr"]
    say(f"receiver on {rx.url}")
    installed = yaml.safe_load(PROVISIONED.read_text())
    (ok if installed == prod else bad)("the install provisioned the file hack/render-alerting.sh renders, with its Slack contact point")
    receivers = [r for c in installed["contactPoints"] for r in c["receivers"]]
    (ok if [r["type"] for r in receivers] == ["slack"] and receivers[0]["settings"]["url"] == "$SLACK_WEBHOOK_URL" else bad)(
        "the contact point is Slack, its URL from SLACK_WEBHOOK_URL (alerting.env)")
    print("test-only changes on top of the installed alerting file:", flush=True)
    print(f"  group interval {EVALUATION_INTERVAL} (production 1m); policy {NOTIFY} (production group_wait 30s, group_interval 5m)", flush=True)
    print(f"  for: {FOR_OVERRIDES} (production Largest slot too small 10m)", flush=True)
    print(f"  the install ran with LARGEST_SLOT_MB={LARGEST_SLOT_MB} (default 16384) and SLACK_WEBHOOK_URL={rx.url}; every expression, label, threshold and the contact point is the file's", flush=True)
    tmp = Path("/tmp/briqyard-alerting-test.yaml")
    tmp.write_text(yaml.safe_dump(test_overrides(installed), sort_keys=False))
    sudo("install", "-m", "0644", str(tmp), str(PROVISIONED), check=True)
    sudo("systemctl", "restart", "briqyard-grafana", check=True)
    if not wait_for("grafana", lambda: get(GRAFANA + "/api/health").get("database") == "ok", 90, 2):
        raise RuntimeError("grafana did not come back")
    rules = wait_for("rules", lambda: len(grafana("/api/v1/provisioning/alert-rules")) == sum(len(g["rules"]) for g in prod["groups"]) and grafana("/api/v1/provisioning/alert-rules"), 60, 2)
    if not rules:
        bad("Grafana loaded every rule of the file")
        raise RuntimeError("rules not loaded")
    verify(prod, rules)
    cps = grafana("/api/v1/provisioning/contact-points")
    (ok if [c["type"] for c in cps] == ["slack"] else bad)(f"Grafana's contact point is Slack ({[c['type'] for c in cps]})")


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
            want_keep = seconds(r.get("keepFiringFor", 0))
            if seconds(got.get("keep_firing_for", got.get("keepFiringFor", 0))) != want_keep:
                wrong.append(f"{r['uid']}.keepFiringFor: want {want_keep}, Grafana {got.get('keep_firing_for')!r}")
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
    print(run("curl", "-sS", "http://127.0.0.1:7430/v1/hosts").stdout[:2500], flush=True)
    print(run("briqyard", "machine", "ls").stdout[:1500], flush=True)


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
    machine("alert-crash", "crashy", 128, cmd=("sh", "-c", "sleep 10; exit 1"))
    t_crash = time.time()
    say("crash-looping machine started")
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

    # Capacity refusals: more memory than the host holds (12288 MB), asking region dev, no region,
    # and a region no host is in. The last two are counted under region "" and "other".
    t_room = time.time()
    for ns, region in (("alert-room", ["--region", "dev"]), ("alert-room-none", []), ("alert-room-other", ["--region", "nowhere"])):
        p = run("briqyard", "machine", "run", "--image", "alpine:3.20", "--namespace", ns, "--name", "toolarge",
                "--memory", "20000", *region, "--detach", "--", "sleep", "60", timeout=120)
        (ok if p.returncode != 0 and "room" in (p.stderr + p.stdout).lower() else bad)(
            f"a create of 20000 MB {' '.join(region) or 'without a region'} is refused for capacity ({(p.stderr or p.stdout).strip()[-100:]!r})")
        namespaces.append(ns)

    # Host condition, host pressure and the largest slot: one machine takes the host's memory
    # up to its last 50 MB (committed memory counts each machine's 256 MB VMM overhead).
    # A new namespace is not placed on a host over the fill ceiling (0.85), so the namespace
    # is made small first and grown into the host it is pinned to.
    machine("alert-big", "anchor", 128)
    time.sleep(20)  # the fleet reads the host's use from its heartbeat
    host = json.loads(run("curl", "-fsS", f"{os.environ['BRIQYARD_URL']}/v1/hosts").stdout)[0]
    free = host["capacity"]["memory_mb"] - host["used"]["memory_mb"]
    say(f"host {host['id']}: {host['used']['memory_mb']} of {host['capacity']['memory_mb']} MB committed before the large machine")
    big = None
    for size in (free - 256 - 50, free - 256 - 600, free - 256 - 1500):
        try:
            big = machine("alert-big", "big", size)
            ok(f"a machine of {size} MB takes the host's memory")
            break
        except RuntimeError as e:
            say(f"{size} MB refused: {e}")
    if big is None:
        raise RuntimeError("no machine could take the host's memory")
    t_big = time.time()
    if not wait_for("memory_pressure", lambda: prom('briqyard_host_condition{condition="memory_pressure"} == 1'), 240, 5):
        bad("the host reported memory_pressure")
        raise RuntimeError("no memory_pressure")
    ok("the host reported memory_pressure")
    if not wait_for("fleet", lambda: any(c["type"] == "memory_pressure" and c["status"] for c in
                    json.loads(run("curl", "-fsS", f"{os.environ['BRIQYARD_URL']}/v1/hosts").stdout)[0]["conditions"]), 120, 3):
        bad("the fleet reads the condition from the host")
    t_pressure = time.time()
    p = run("briqyard", "machine", "run", "--image", "alpine:3.20", "--namespace", "alert-big", "--name", "second",
            "--memory", "128", "--detach", "--", "sleep", "60", timeout=120)
    text = (p.stderr + p.stdout).lower()
    if p.returncode == 0:
        machines.append(json.loads(p.stdout)["id"])
    (ok if p.returncode != 0 and "memory_pressure" in text else bad)(
        f"a create into that namespace is refused under pressure ({(p.stderr or p.stdout).strip()[-140:]!r})")

    crash = Case("Machine in a crash loop", "briqyard-crash-loop", "Machine in a crash loop", {"namespace": "alert-crash", "host": "local"}, 240, 840, window=600)
    backup = Case("Backup failure observed", "briqyard-backup-failed", "Backup failure observed", {"host": "local"}, 240, 540, window=600)
    room = Case("Creates refused: no room", "briqyard-out-of-room", "Creates refused: no room", {"region": "dev", "resource": "memory"}, 240, 300, window=300)
    room_none = Case("Creates refused: no room (no region asked)", "briqyard-out-of-room", "Creates refused: no room", {"resource": "memory"}, 240, 300, window=300, absent=("region",))
    room_other = Case("Creates refused: no room (unknown region)", "briqyard-out-of-room", "Creates refused: no room", {"region": "other", "resource": "memory"}, 240, 300, window=300)
    cond = Case("Host condition", "briqyard-host-condition", "Host condition", {"host": "local", "condition": "memory_pressure"}, 360, 300)
    press = Case("Creates refused: host under pressure", "briqyard-host-pressure", "Creates refused: host under pressure", {"region": "dev"}, 240, 300, window=300)
    slot = Case("Largest slot too small", "briqyard-slots-small", "Largest slot too small", {"region": "dev"}, 420, 300)
    crash.caused, backup.caused, room.caused, room_none.caused, room_other.caused = t_crash, t_backup, t_room, t_room, t_room
    cond.caused, slot.caused, press.caused = t_big, t_big, t_pressure
    # The window alerts expire by themselves: ten minutes of restarts or backup events, five of refusals.
    # (A destroyed machine's restarts stay in the ten-minute window too: destroying it does not resolve the alert.)
    crash.recovery, backup.recovery, room.recovery, press.recovery = t_crash, t_backup, t_room, t_pressure
    room_none.recovery = room_other.recovery = t_room
    crash.resolve_within = 600 + 180 + 240  # the window, then keepFiringFor
    backup.resolve_within = 600 + 240
    room.resolve_within = room_none.resolve_within = room_other.resolve_within = press.resolve_within = 300 + 240
    destroy_big = Action("destroy the machine holding the host's memory", [cond, slot], lambda: destroy(big))
    cond.action = slot.action = destroy_big
    drive([crash, backup, room, room_none, room_other, cond, press, slot], [destroy_big], 1500)


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
