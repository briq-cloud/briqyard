#!/usr/bin/env python3
"""The gateway-policy section of hack/qualify.sh (ADR 0143): its fake control API, the policy
digest, the classification of every raw probe output, the verdict of each check and the
receipt. Everything here is pure logic beside the fake API, so that
hack/test_gateway_policy_qual.py tests it without a host.

  serve --port P --hold S --dir D --token T   the gateway's control API, synthetic values only
  digest POLICY_JSON                          sha256:HEX of the canonical policy
  classify dns|l2|cause [--rc N] [--ignore W] the token for a raw output read on stdin
  obs --file F --check N --criterion C --cls K --role R [--batch B] [--curl S] [--set k=v]...
  count --file F --phase P --kind K [--since T]   loop samples of a kind, for the waits
  derive --file F --phase boot|gateway_kill|daemon_kill   checks derived from samples and marks
  judge --file F --check N                    exit 0 pass, 1 fail, 3 inconclusive, 4 absent, 5 limit
  receipt --file F --meta M --out R           exit 0 only when every C1-C7 check passed
  verify R [--accept-limit NAME]...           the presence check on a receipt (A3)

The fake API is a test double, not a deployment template: it accepts any CA, serves the config
the harness wrote (synthetic briq ids and addresses only) and drops the gateway's reports. It
holds every CA registration HOLD seconds, the window in which the gateway cannot answer a
readback (it binds its port and its status socket only after the registration), so the bridge
gate's closed state can be observed.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PASS, FAIL, INCONCLUSIVE, ABSENT, LIMIT = "pass", "fail", "inconclusive", "absent", "limit"
EXIT = {PASS: 0, FAIL: 1, INCONCLUSIVE: 3, ABSENT: 4, LIMIT: 5}
# A limit is not a pass; absent ranks with inconclusive, both above a limit, below a fail.
RANK = {PASS: 0, LIMIT: 1, INCONCLUSIVE: 2, ABSENT: 2, FAIL: 3}
SCHEMA = "briqyard.gateway-policy.receipt/2"
BLOCKING = ("C1", "C2", "C3", "C4", "C5", "C6", "C7")
CRITERIA = BLOCKING + ("C8",)
CLASSES = {
    "allowed", "proxied_denial", "plain_denial", "direct_denial", "udp_denial",
    "reach", "reach_not403", "dns_answer", "assert", "observed", "measure", "limit",
    "loop_allowed", "loop_direct", "gate", "mark", "admit", "l2",
}
EVIDENCE = {"loop_allowed", "loop_direct", "gate", "mark", "admit", "l2"}
ROLES = {"subject", "control", "bracket_before", "bracket_after", "sample"}
NEEDS_CONTROL = {
    "proxied_denial": "reach",
    "plain_denial": "reach_not403",
    "direct_denial": "reach",
    "udp_denial": "dns_answer",
}
FIELDS = ("check", "criterion", "cls", "role", "batch", "http_code", "http_connect", "rc",
          "ms", "connect_us", "value", "t0", "t1")
INT_FIELDS = ("http_code", "http_connect", "rc", "ms", "connect_us", "t0", "t1")
NAME = re.compile(r"^[a-z0-9_.]{1,80}$")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9:._-]{0,80}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
LOOP_ALIVE = 5
PHASES = ("boot", "mismatch", "gateway_kill", "daemon_kill")
ADMITTED = ("starting", "running")
REFUSED_STATES = ("none", "creating", "error")

C4_OPS = ("stop_start", "sleep_wake", "resize", "suspend_resume")
C5_LOOP = ("alive_before", "alive_after", "direct_never_open", "no_traffic_while_closed",
           "closed_observed", "direct_while_closed")
REQUIRED = {
    "C1": ["c1.readback_challenge", "c1.readback_digest", "c1.readback_identity",
           "c1.readback_live_incarnation", "c1.fresh_challenge", "c1.restart_new_incarnation",
           "c1.legacy_gateway_alive", "c1.legacy_readback_refused", "c1.no_guest_output_in_errors"],
    "C2": ["c2.fake_api_listening", "c2.api_reachable_preflight", "c2.closed_observed", "c2.hold_arp_blocked",
           "c2.hold_icmp_blocked", "c2.no_admission_during_hold", "c2.held_is_readback",
           "c2.open_arp_reached", "c2.open_icmp_reached", "c2.mismatch_gateway_refused",
           "c2.mismatch_readback_refused", "c2.mismatch_arp_blocked", "c2.mismatch_icmp_blocked",
           "c2.mismatch_running_gate_closed", "c2.mismatch_not_admitted",
           "c2.mismatch_gateway_stopped"],
    "C3": ["c3.preresolved", "c3.allowed", "c3.unlisted", "c3.ip_literal_proxied",
           "c3.other_port_proxied", "c3.plain_http_proxied", "c3.direct_allowed_ip",
           "c3.direct_tcp80", "c3.direct_tcp22", "c3.direct_udp_dns", "c3.dns_other_namespace",
           "c3.dns_own_resolver", "c3.iso_host_bridge", "c3.iso_other_bridge", "c3.iso_daemon_ports"],
    "C4": [f"c4.{op}.{k}" for op in C4_OPS for k in ("binding", "allowed", "unlisted", "literal", "direct")],
    "C5": [f"c5.gateway_kill.{k}" for k in C5_LOOP + ("hold_gate_closed", "readback_new_incarnation")]
          + [f"c5.daemon_kill.{k}" for k in C5_LOOP + ("readback_live_incarnation",)]
          + ["c5.isolation_unconfirmed"],
    "C6": [f"c6.{k}" for k in ("fork_bound", "fork_gateway", "template", "warm_claim",
                               "restore_from_backup", "move", "patch_remove_open",
                               "patch_remove_plain", "patch_change", "patch_add")],
    "C7": ["c7.replace_other_spec", "c7.replace_no_policy", "c7.rm_running", "c7.same_spec_noop",
           "c7.rm_stopped", "c7.rm_after_destroy", "c7.cleanup_verified"],
    "C8": ["c8.legacy_gate_empty", "c8.legacy_unbound_reaches"],
}
CRITERION_OF = {n: c for c, ns in REQUIRED.items() for n in ns}
# The limits derive() can emit; the section's own are named by its limit observations.
LIMITABLE = ("c5.daemon_kill.no_traffic_while_closed", "c5.daemon_kill.direct_while_closed")


# ---- the policy digest (credential-gateway README, "Egress policy") ----

def digest(policy: dict) -> str:
    canonical = {
        "policy_format": policy["policy_format"],
        "namespace": policy["namespace"],
        "team_id": policy["team_id"],
        "briq_id": policy["briq_id"],
        "hosts": sorted({h.lower() for h in policy["hosts"]}),
    }
    raw = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ---- raw outputs to tokens ----

def classify_dns(text: str) -> str:
    """busybox nslookup to an explicit server: any answer line is an answer, whatever the rc."""
    lines = [line.strip() for line in text.splitlines()]
    for i, line in enumerate(lines):
        if re.match(r"^Name:\s*\S", line):
            return "answer"
        m = re.match(r"^Address(?:es)?(?:\s+\d+)?:\s*(\S+)", line)
        server_line = i > 0 and lines[i - 1].startswith("Server:")
        if m and not server_line and not re.search(r"[:#]53$", m.group(1)):
            return "answer"
    rc = re.findall(r"^rc=(-?\d+)$", text, re.M)
    if re.search(r"timed out|no servers could be reached", text, re.I) or (rc and rc[-1] in ("124", "143")):
        return "timeout"
    return "other"


def classify_l2(text: str) -> str:
    """arping and ping output, run at once: ARP-ICMP, each reached, blocked or unknown."""
    def token(n):
        return "unknown" if n is None else "blocked" if n == 0 else "reached"
    a = re.search(r"Received (\d+) (?:response|repl)", text)
    i = re.search(r"(\d+) (?:packets )?received", text)
    return f"{token(int(a.group(1)) if a else None)}-{token(int(i.group(1)) if i else None)}"


USAGE = re.compile(r"^(Usage:|error: (unexpected|invalid|unrecognized|the argument|a value|unknown))", re.M)


def classify_cause(text: str, rc: int, ignore=()) -> str:
    """Why an operation was refused: policy (it names the policy, a binding or the gateway),
    usage, timeout or other; ok when it was not refused. The harness's own names are struck
    out first, so that a machine called gp-bound never reads as a binding."""
    if rc == 0:
        return "ok"
    if rc in (124, 137, 143):
        return "timeout"
    # clap refuses its own arguments with exit 2 and its usage; the CLI exits 1 for everything
    # the daemon answers, whose "invalid request: ..." (MError::Invalid) is never a usage error.
    if rc == 2 and USAGE.search(text) and re.search(r"^Usage:|try '--help'", text, re.M):
        return "usage"
    # The client's own refusal, before any request: it names the policy but is not the daemon's.
    if re.search(r"^error: server (does not support|cannot safely)", text, re.M):
        return "other"
    words = [w for w in text.split() if not any(x and x in w for x in ignore)]
    return "policy" if re.search(r"polic|binding|gateway|readback", " ".join(words), re.I) else "other"


def parse_curl(s: str) -> dict:
    """'http_code http_connect time_total time_connect rc', as the probe prints it."""
    parts = s.split()
    if len(parts) != 5:
        return {"rc": -1}
    try:
        return {
            "http_code": int(parts[0]),
            "http_connect": int(parts[1]),
            "ms": int(float(parts[2]) * 1000),
            "connect_us": int(round(float(parts[3]) * 1_000_000)),
            "rc": int(parts[4]),
        }
    except ValueError:
        return {"rc": -1}


# ---- observations ----

def parse_value(s: str):
    if s in ("true", "false"):
        return s == "true"
    if s in ("null", ""):
        return None
    if re.fullmatch(r"-?[0-9]{1,18}", s):
        return int(s)
    if not SAFE_VALUE.match(s):
        return None
    return s


def make_obs(check, criterion, cls, role, batch="", curl=None, sets=()):
    if not NAME.match(check):
        raise ValueError("check name")
    if criterion not in CRITERIA + ("Q7", "RUN"):
        raise ValueError("criterion")
    if cls not in CLASSES or role not in ROLES:
        raise ValueError("class or role")
    if batch and not NAME.match(batch):
        raise ValueError("batch")
    o = {"check": check, "criterion": criterion, "cls": cls, "role": role, "batch": batch or None}
    if curl is not None:
        o.update(parse_curl(curl))
    for kv in sets:
        k, _, v = kv.partition("=")
        if k not in FIELDS or k in ("check", "criterion", "cls", "role", "batch"):
            raise ValueError(f"field {k}")
        val = parse_value(v)
        if k in INT_FIELDS and not (isinstance(val, int) and not isinstance(val, bool)):
            val = None
        o[k] = val
    return {k: o.get(k) for k in FIELDS}


def load(path):
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return out


# ---- verdicts ----

def worst(verdicts):
    vs = list(verdicts)
    if not vs:
        return ABSENT
    return max(vs, key=lambda v: RANK[v])


def connected(o) -> bool:
    return (o.get("connect_us") or 0) > 0


def probe_verdict(o) -> str:
    """One observation, by the rules of the plan's section 1."""
    cls, rc, code, conn = o["cls"], o.get("rc"), o.get("http_code"), o.get("http_connect")
    if cls == "allowed":
        return PASS if rc == 0 and code == 200 else FAIL
    if cls == "proxied_denial":
        if conn == 403:
            return PASS
        if conn == 200:
            return FAIL  # an accepted CONNECT, rc 35/52/60 included: fail-open
        if rc == 0 and code is not None and 200 <= code < 400:
            return FAIL
        return INCONCLUSIVE
    if cls == "plain_denial":
        if rc == 0 and code == 403:
            return PASS
        if rc == 0 and code is not None and 200 <= code < 400:
            return FAIL
        return INCONCLUSIVE
    if cls == "direct_denial":
        if rc == 0 or connected(o):
            return FAIL
        if rc in (7, 28):
            return PASS
        return INCONCLUSIVE  # 5/6 resolution, -1 exec, anything else
    if cls == "udp_denial":
        return {"timeout": PASS, "answer": FAIL}.get(o.get("value"), INCONCLUSIVE)
    if cls == "reach":
        return PASS if rc == 0 or connected(o) else INCONCLUSIVE
    if cls == "reach_not403":
        return PASS if rc == 0 and code not in (None, 0, 403) else INCONCLUSIVE
    if cls == "dns_answer":
        return PASS if o.get("value") == "answer" else INCONCLUSIVE
    if cls == "assert":
        v = o.get("value")
        return PASS if v is True else FAIL if v is False else INCONCLUSIVE
    if cls == "observed":
        return PASS if o.get("value") is True else INCONCLUSIVE
    if cls == "limit":
        return LIMIT
    return INCONCLUSIVE


def batch_state(all_obs, batch):
    before = [o for o in all_obs if batch and o["batch"] == batch and o["role"] == "bracket_before"]
    after = [o for o in all_obs if batch and o["batch"] == batch and o["role"] == "bracket_after"]
    ok = bool(before) and bool(after) and all(probe_verdict(o) == PASS for o in before + after)
    return {"before": len(before), "after": len(after), "ok": ok}


def check_verdict(all_obs, name):
    mine = [o for o in all_obs if o["check"] == name and o["role"] in ("subject", "control")]
    subjects = [o for o in mine if o["role"] == "subject" and o["cls"] not in EVIDENCE | {"measure"}]
    if not subjects:
        return ABSENT, "no observation"
    out = []
    for s in subjects:
        v = probe_verdict(s)
        need = NEEDS_CONTROL.get(s["cls"])
        if need and v == PASS:
            controls = [o for o in mine if o["role"] == "control"]
            if not controls or any(o["cls"] != need or probe_verdict(o) != PASS for o in controls):
                out.append((INCONCLUSIVE, "control did not reach the target"))
                continue
            if not batch_state(all_obs, s["batch"])["ok"]:
                out.append((INCONCLUSIVE, "allowed bracket missing or failed"))
                continue
        why = s["cls"] if s["cls"] != "limit" else f"limit: {s.get('value')}"
        out.append((v, why))
    v = worst(x[0] for x in out)
    return v, next((w for x, w in out if x == v), "")


# ---- derived checks: the boot hold and the probe loop around a kill ----

def sample_kind(o) -> str:
    """A loop sample's kind, from its raw curl fields."""
    rc = o.get("rc")
    if rc is None or rc == -1:
        return "exec_failed"
    if o["cls"] == "loop_allowed":
        return "allowed_ok" if rc == 0 and o.get("http_code") == 200 else "allowed_bad"
    if rc == 0 or connected(o):
        return "direct_open"  # a connection, whatever followed it (35, 52, 56, 60)
    if rc in (7, 28):
        return "direct_denied"
    return "direct_other"


def closed_runs(gates):
    runs, start, last = [], None, None
    for g in sorted(gates, key=lambda g: g["t0"]):
        if g["value"] is True and start is None:
            start = g["t0"]
        if g["value"] is not True and start is not None:
            runs.append((start, last))
            start = None
        last = g["t0"]
    if start is not None:
        runs.append((start, last))
    return runs


def phase_rows(all_obs, phase):
    rows = [o for o in all_obs if o["batch"] == phase]
    marks = {}
    for o in rows:
        if o["cls"] == "mark" and o["t0"] is not None:
            marks.setdefault(o["value"], o["t0"])
    gates = [o for o in rows if o["cls"] == "gate" and o["t0"] is not None and o["value"] in (True, False)]
    return rows, marks, gates


def count(all_obs, phase, kind, since=0):
    return sum(1 for o in all_obs if o["batch"] == phase and o["cls"] in ("loop_allowed", "loop_direct")
               and sample_kind(o) == kind and (o.get("t0") or 0) >= since)


def derive(all_obs, phase):
    rows, marks, gates = phase_rows(all_obs, phase)
    res = []

    def add(name, crit, cls, value):
        v = "true" if value is True else "false" if value is False else "null" if value is None else value
        res.append(make_obs(name, crit, cls, "subject", phase, sets=[f"value={v}"]))

    admits = [o for o in rows if o["cls"] == "admit" and o["t0"] is not None]
    if phase == "boot":
        recv, release = marks.get("hold_recv"), marks.get("release")
        l2 = [o for o in rows if o["cls"] == "l2" and o["t0"] is not None and o["t1"] is not None]
        during = [o for o in l2 if recv is not None and release is not None and recv <= o["t0"] and o["t1"] < release]
        add("c2.closed_observed", "C2", "observed", bool(during))
        for i, name in ((0, "c2.hold_arp_blocked"), (1, "c2.hold_icmp_blocked")):
            if not during:
                add(name, "C2", "assert", None)
                continue
            toks = [str(o["value"] or "unknown-unknown").split("-")[i] for o in during]
            add(name, "C2", "assert", False if "reached" in toks else None if "unknown" in toks else True)
        # Admission follows verification (start.rs: ensure_gateway, then reserve), and the gate
        # opens only on verification: a consumer starting or running at a moment the gate was
        # still read closed afterwards was admitted unverified.
        in_hold = [o for o in admits if recv is not None and release is not None and recv <= o["t0"] <= release]
        closed = [g["t0"] for g in gates if g["value"] is True]
        if not any(o["value"] != "unknown" for o in in_hold) or "readback" not in marks or not gates:
            add("c2.no_admission_during_hold", "C2", "assert", None)
        else:
            early = [o for o in admits if o["value"] in ADMITTED and (o["t0"] <= release or any(o["t0"] <= t for t in closed))]
            add("c2.no_admission_during_hold", "C2", "assert", not early)
        return res

    if phase == "mismatch":
        # A refused create stays in error (create.rs: create_failed_locked), or was never
        # recorded, or is still creating; starting or running is an admission.
        rc = next((o.get("rc") for o in rows if o["cls"] == "mark" and o["value"] == "create"), None)
        readable = [o for o in admits if o["value"] != "unknown"]
        final = next((o["value"] for o in reversed(admits) if o["value"] != "unknown"), None)
        if any(o["value"] in ADMITTED for o in admits):
            value = False
        elif rc is None or rc in (0, 124) or not readable or final not in REFUSED_STATES:
            value = None if rc != 0 else False
        else:
            value = True
        add("c2.mismatch_not_admitted", "C2", "assert", value)
        return res

    kill, reopen = marks.get("kill"), marks.get("reopen")
    samples = [o for o in rows if o["cls"] in ("loop_allowed", "loop_direct") and o["t0"] is not None and o["t1"] is not None]
    pre = f"c5.{phase}"

    def alive(when):
        a = sum(1 for s in samples if sample_kind(s) == "allowed_ok" and when(s))
        d = sum(1 for s in samples if sample_kind(s) == "direct_denied" and when(s))
        return a >= LOOP_ALIVE and d >= LOOP_ALIVE

    add(f"{pre}.alive_before", "C5", "observed", kill is not None and alive(lambda s: s["t1"] <= kill))
    add(f"{pre}.alive_after", "C5", "observed", reopen is not None and alive(lambda s: s["t0"] >= reopen))
    add(f"{pre}.direct_never_open", "C5", "assert",
        None if not samples else not any(sample_kind(s) == "direct_open" for s in samples))
    runs = closed_runs(gates)

    def inside(s):
        return any(a <= s["t0"] and s["t1"] <= b for a, b in runs)

    in_closed = [s for s in samples if inside(s)]
    allowed_closed = [s for s in in_closed if s["cls"] == "loop_allowed" and sample_kind(s) != "exec_failed"]
    denied_closed = [s for s in in_closed if s["cls"] == "loop_direct" and sample_kind(s) == "direct_denied"]
    why = "exec-needs-the-daemon" if in_closed and all(sample_kind(s) == "exec_failed" for s in in_closed) else "no-sample-in-closed-run"
    leak = any(sample_kind(s) == "allowed_ok" for s in allowed_closed)
    if phase == "gateway_kill" and kill is not None and "release" in marks:
        leak = leak or any(sample_kind(s) == "allowed_ok" and kill <= s["t0"] and s["t1"] <= marks["release"] for s in samples)
    if leak:
        add(f"{pre}.no_traffic_while_closed", "C5", "assert", False)
    elif allowed_closed:
        add(f"{pre}.no_traffic_while_closed", "C5", "assert", True)
    elif phase == "daemon_kill":
        add(f"{pre}.no_traffic_while_closed", "C5", "limit", why)
    else:
        add(f"{pre}.no_traffic_while_closed", "C5", "assert", None)
    if denied_closed:
        add(f"{pre}.direct_while_closed", "C5", "observed", True)
    elif phase == "daemon_kill":
        add(f"{pre}.direct_while_closed", "C5", "limit", why)
    else:
        add(f"{pre}.direct_while_closed", "C5", "observed", False)
    add(f"{pre}.closed_observed", "C5", "observed", any(g["value"] is True for g in gates if kill is not None and g["t0"] > kill))
    if phase == "gateway_kill":
        recv, rel = marks.get("hold_recv"), marks.get("release")
        held = [g for g in gates if recv is not None and rel is not None and recv <= g["t0"] <= rel]
        add(f"{pre}.hold_gate_closed", "C5", "assert", all(g["value"] is True for g in held) if held else None)
    return res


# ---- the receipt ----

META = {
    "native_sha": SHA, "harness_sha256": HEX64, "helper_sha256": HEX64, "gateway_image": None,
    "gateway_source_sha": SHA, "briq_sha": SHA, "run_id": re.compile(r"^[0-9]{1,20}$"),
    "kernel": SAFE_VALUE, "boot_timeout_sec": re.compile(r"^[0-9]{1,6}$"),
    "elapsed_sec": re.compile(r"^[0-9]{1,6}$"),
}
IMAGE = re.compile(r"^ghcr\.io/briq-cloud/credential-gateway@sha256:[0-9a-f]{64}$")
PROBE_KEYS = ("cls", "role", "http_code", "http_connect", "rc", "ms", "connect_us", "value")


def clean_meta(meta: dict) -> dict:
    out = {}
    for k, rx in META.items():
        v = meta.get(k)
        rx = IMAGE if k == "gateway_image" else rx
        out[k] = v if isinstance(v, str) and rx.match(v) else None
    return out


def build_receipt(all_obs, meta, accept=()):
    """Only the REQUIRED names are checks; bracket, loop, gate, mark, admit and l2 rows are the
    evidence they consume, summarised per batch and phase."""
    checks, by_crit, limits = [], {c: [] for c in CRITERIA}, []
    for crit in CRITERIA:
        for name in REQUIRED[crit]:
            mine = [o for o in all_obs if o["check"] == name]
            v, why = check_verdict(all_obs, name)
            batches = sorted({o["batch"] for o in mine if o["batch"] and o["cls"] in NEEDS_CONTROL})
            checks.append({"name": name, "criterion": crit, "verdict": v, "reason": why,
                           "observations": len(mine), "batches": batches,
                           "probes": [{k: o.get(k) for k in PROBE_KEYS} for o in mine]})
            by_crit[crit].append(v)
            if v == LIMIT:
                limits.append({"name": name, "criterion": crit, "reason": why, "accepted": name in accept})
    missing = [c["name"] for c in checks if c["verdict"] == ABSENT]
    counts = {k: sum(1 for c in checks if c["verdict"] == k) for k in (PASS, FAIL, INCONCLUSIVE, ABSENT, LIMIT)}
    counts["checks"] = len(checks) - counts[ABSENT]
    criteria = {c: worst(by_crit[c]) for c in CRITERIA}
    presence_ok = not missing and counts["checks"] > 0
    blocking = worst(criteria[c] for c in BLOCKING)
    verdict = blocking if presence_ok else (FAIL if blocking == FAIL else INCONCLUSIVE)
    batch_names = sorted({o["batch"] for o in all_obs if o["role"] in ("bracket_before", "bracket_after") and o["batch"]})
    phases = {}
    for phase in PHASES:
        rows, marks, gates = phase_rows(all_obs, phase)
        samples = [o for o in rows if o["cls"] in ("loop_allowed", "loop_direct")]
        base = marks.get("kill", marks.get("hold_recv"))
        kinds = [sample_kind(o) for o in samples]
        phases[phase] = {
            "samples": len(samples),
            "by_kind": {k: kinds.count(k) for k in sorted(set(kinds))},
            "marks_ms": {k: (t - base if base is not None else None) for k, t in sorted(marks.items())},
            "gate_reads": len(gates),
            "gate_closed_reads": sum(1 for g in gates if g["value"] is True),
            "admit_samples": sum(1 for o in rows if o["cls"] == "admit"),
        }
    measures = [{k: o.get(k) for k in ("check", "criterion", "rc", "http_code", "value")}
                for o in all_obs if o["cls"] == "measure"]
    return {
        "schema": SCHEMA,
        "suite": "qualification",
        "section": "gateway_policy",
        "meta": clean_meta(meta),
        "verdict": verdict,
        "criteria": criteria,
        "presence": {"ok": presence_ok, "required": len(checks), "missing": missing},
        "counts": counts,
        "limits": limits,
        "checks": checks,
        "batches": {b: batch_state(all_obs, b) for b in batch_names},
        "phases": phases,
        "measurements": measures,
    }


def verify(receipt, accept=()) -> list:
    """What makes a receipt unacceptable to A3; empty when it is acceptable. A limit on C1-C7
    passes only when the owner named it with --accept-limit."""
    bad = []
    if receipt.get("schema") != SCHEMA or receipt.get("section") != "gateway_policy":
        bad.append("not a gateway_policy receipt")
    names = {c.get("name"): c for c in receipt.get("checks", [])}
    for c in CRITERIA:
        for n in REQUIRED[c]:
            if n not in names or names[n].get("verdict") == ABSENT or not names[n].get("observations"):
                bad.append(f"absent: {n}")
    if not receipt.get("counts", {}).get("checks"):
        bad.append("zero checks")
    for c in BLOCKING:
        for n in REQUIRED[c]:
            v = names.get(n, {}).get("verdict")
            if v == LIMIT and n in accept:
                continue
            if v not in (PASS, ABSENT, None):
                bad.append(f"{n}: {v}")
    v = receipt.get("verdict")
    if v not in (PASS, LIMIT) or (v == LIMIT and not all(x["name"] in accept for x in receipt.get("limits", []) if x["criterion"] in BLOCKING)):
        bad.append(f"verdict {v}")
    for x in receipt.get("limits", []):
        if x.get("accepted") and x["name"] not in accept:
            bad.append(f"limit accepted by the run but not by this check: {x['name']}")
    return bad


# ---- the diagnostics: what the run uploads besides the receipt ----
# Every row of $LOGS/gateway-policy-diag.jsonl is written here, field by field against a fixed
# pattern: enums, integers and IPv4 addresses only. A value that does not match is written as
# null and its key listed in "refused", so no output text, console line, CA, token, policy,
# digest or hostname can reach the uploaded logs through it.

INT = re.compile(r"^-?[0-9]{1,13}$")
WORD = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$")
TRI = ("true", "false", "null")
GW_ERRORS = ("none", "exited", "port_no_answer", "not_ready", "unverified", "other")
CAUSES = ("ok", "policy", "usage", "timeout", "other")
NS_ROLES = ("main", "legacy", "mismatch")
PEER_ROLES = ("gateway", "legacy", "mismatch", "open", "bound", "other")
API_PATHS = {"/internal/credential-gateway/ca": "ca", "/internal/credential-gateway/config": "config",
             "/internal/credential-gateway/events": "events", "/healthz": "healthz"}
DIAG = {
    "step": {"name": WORD, "ns": NS_ROLES, "rc": INT, "t0": INT, "t1": INT, "cause": CAUSES},
    "gateway": {"step": WORD, "ns": NS_ROLES, "state": WORD, "error_reason": WORD, "error": GW_ERRORS,
                "ip": IPV4, "gate": TRI, "incarnations": INT},
    "events": {"ns": NS_ROLES, "machine": ("gateway", "open", "bound"), "reason": WORD, "count": INT},
    "api": {"method": ("GET", "PUT", "POST", "other"), "path": tuple(API_PATHS.values()) + ("other",),
            "status": INT, "peer": PEER_ROLES, "count": INT, "first_ms": INT, "last_ms": INT},
    "reach": {"uplink_code": INT, "uplink_rc": INT, "bridge_code": INT, "bridge_rc": INT,
              "accept_rule": ("present", "absent", "unknown"), "hostip_in_range": TRI},
    "loop": {"name": WORD, "iterations": INT, "end": ("met", "set_exited", "exhausted", "skipped")},
    "end": {"healthz_rc": INT, "api_out_bytes": INT},
}


def diag_row(kind, sets=()):
    """One diag row, or None for an unknown kind. Unknown keys and unmatched values are refused."""
    schema = DIAG.get(kind)
    if schema is None:
        return None
    row, refused = {"kind": kind}, []
    for k in schema:
        row[k] = None
    for kv in sets:
        k, _, v = kv.partition("=")
        rule = schema.get(k)
        ok = rule is not None and (v in rule if isinstance(rule, tuple) else bool(rule.match(v)))
        if not ok:
            refused.append(k if WORD.match(k) else "?")
            if k in schema:
                row[k] = None
            continue
        row[k] = int(v) if rule is INT else v
    row["refused"] = sorted(set(refused))
    return row


def classify_gwerror(text: str) -> str:
    """A gateway's error, as one class: the daemon's own prefix decides, the console lines it
    appends never do (gateway.rs boot_failed, gateway_policy.rs unverified)."""
    t = text.strip()
    if not t:
        return "none"
    t = re.sub(r"^the namespace's gateway did not come up: ", "", t)
    if t.startswith("the gateway exited"):
        return "exited"
    if re.match(r"port [0-9]+ did not answer", t):
        return "port_no_answer"
    if t.startswith("not ready"):
        return "not_ready"
    if t.startswith("gateway loaded policy not verified"):
        return "unverified"
    return "other"


def in_range(addr: str, cidr: str) -> str:
    try:
        return "true" if ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False) else "false"
    except ValueError:
        return "null"


def api_summary(rows, peers, since):
    """The fake API's log as counts by method, path, status and peer role, with the first and
    last time relative to SINCE (ms). PEERS maps an address to its role; any other is other."""
    groups = {}
    for r in rows:
        if r.get("event") != "done":
            continue
        method = r.get("method") if r.get("method") in ("GET", "PUT", "POST") else "other"
        path = API_PATHS.get(r.get("path"), "other")
        status = r.get("status") if isinstance(r.get("status"), int) else -1
        peer = peers.get(r.get("peer"), "other")
        t = r.get("t") if isinstance(r.get("t"), int) else since
        g = groups.setdefault((method, path, status, peer), [0, t, t])
        g[0] += 1
        g[1], g[2] = min(g[1], t), max(g[2], t)
    return [diag_row("api", [f"method={m}", f"path={p}", f"status={s}", f"peer={pr}", f"count={n}",
                             f"first_ms={a - since}", f"last_ms={b - since}"])
            for (m, p, s, pr), (n, a, b) in sorted(groups.items())]


def write_rows(path, rows):
    with open(path, "a") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


# ---- the fake control API ----

class FakeApi(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hold = 8.0
    dir = "."
    token = ""
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def record(self, event, t_recv, status=None):
        line = {"event": event, "method": self.command, "path": self.path.split("?")[0][:80],
                "peer": self.client_address[0], "t_recv": t_recv, "status": status,
                "t": int(time.time() * 1000)}
        with self.lock, open(os.path.join(self.dir, "api.jsonl"), "a") as f:
            f.write(json.dumps(line) + "\n")

    def answer(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            return None
        return self.rfile.read(n) if n else b""

    def config(self):
        """The harness's config.json: briq ids and addresses only, nothing else is passed on."""
        try:
            with open(os.path.join(self.dir, "config.json")) as f:
                doc = json.load(f)
            briqs = [{"id": str(b["id"]), "host": str(b["host"])} for b in doc.get("briqs", [])
                     if re.fullmatch(r"[a-z0-9_-]{1,64}", str(b.get("id", ""))) and re.fullmatch(r"[0-9.]{7,15}", str(b.get("host", "")))]
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            briqs = []
        return {"secrets": [], "briqs": briqs}

    def handle_any(self):
        t_recv = int(time.time() * 1000)
        path = self.path.split("?")[0]
        if self.command == "GET" and path == "/healthz" and self.client_address[0] == "127.0.0.1":
            return self.answer(200, {"ok": True})
        if self.headers.get("Authorization") != f"Bearer {self.token}":
            self.body()
            self.record("done", t_recv, 401)
            return self.answer(401, {"error": "unauthorized"})
        raw = self.body()
        if raw is None:
            self.record("done", t_recv, 413)
            return self.answer(413, {"error": "too large"})
        if self.command == "PUT" and path == "/internal/credential-gateway/ca":
            try:
                cert = json.loads(raw or b"{}").get("cert", "")
            except (ValueError, AttributeError):
                cert = ""
            if not isinstance(cert, str) or not cert.startswith("-----BEGIN CERTIFICATE-----"):
                self.record("done", t_recv, 400)
                return self.answer(400, {"error": "cert"})
            peer = self.client_address[0]
            if re.fullmatch(r"[0-9.]{7,15}", peer):
                fd = os.open(os.path.join(self.dir, f"ca-{peer}.pem"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(cert)
            self.record("recv", t_recv)
            time.sleep(self.hold)
            self.record("done", t_recv, 200)
            return self.answer(200, {})
        if self.command == "GET" and path == "/internal/credential-gateway/config":
            self.record("done", t_recv, 200)
            return self.answer(200, self.config())
        if self.command == "POST" and path == "/internal/credential-gateway/events":
            self.record("done", t_recv, 200)
            return self.answer(200, {})
        self.record("done", t_recv, 404)
        return self.answer(404, {"error": "not found"})

    do_GET = do_PUT = do_POST = handle_any


def make_server(port, hold, dir, token, bind="0.0.0.0"):
    handler = type("Api", (FakeApi,), {"hold": hold, "dir": dir, "token": token, "lock": threading.Lock()})
    server = ThreadingHTTPServer((bind, port), handler)
    server.daemon_threads = True
    return server


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--hold", type=float, required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--token", required=True)
    s.add_argument("--bind", default="0.0.0.0")
    s = sub.add_parser("digest")
    s.add_argument("policy")
    s = sub.add_parser("classify")
    s.add_argument("kind", choices=["dns", "l2", "cause", "gwerror"])
    s.add_argument("--rc", type=int, default=1)
    s.add_argument("--ignore", default="")
    s = sub.add_parser("inrange")
    s.add_argument("addr")
    s.add_argument("cidr")
    s = sub.add_parser("diag")
    s.add_argument("--file", required=True)
    s.add_argument("--kind", required=True)
    s.add_argument("--set", action="append", default=[])
    s = sub.add_parser("diag-api")
    s.add_argument("--file", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--since", type=int, required=True)
    s.add_argument("--peer", action="append", default=[], help="ROLE=ADDRESS")
    s = sub.add_parser("obs")
    s.add_argument("--file", required=True)
    s.add_argument("--check", required=True)
    s.add_argument("--criterion", required=True)
    s.add_argument("--cls", required=True)
    s.add_argument("--role", default="subject")
    s.add_argument("--batch", default="")
    s.add_argument("--curl")
    s.add_argument("--set", action="append", default=[])
    s = sub.add_parser("count")
    s.add_argument("--file", required=True)
    s.add_argument("--phase", required=True)
    s.add_argument("--kind", required=True)
    s.add_argument("--since", type=int, default=0)
    s = sub.add_parser("derive")
    s.add_argument("--file", required=True)
    s.add_argument("--phase", required=True, choices=PHASES)
    s = sub.add_parser("judge")
    s.add_argument("--file", required=True)
    s.add_argument("--check", required=True)
    s.add_argument("--accept-limit", action="append", default=[])
    s = sub.add_parser("receipt")
    s.add_argument("--file", required=True)
    s.add_argument("--meta", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--accept-limit", action="append", default=[])
    s = sub.add_parser("verify")
    s.add_argument("receipt")
    s.add_argument("--accept-limit", action="append", default=[])
    a = p.parse_args(argv)
    if a.cmd == "serve":
        make_server(a.port, a.hold, a.dir, a.token, a.bind).serve_forever()
        return 0
    if a.cmd == "digest":
        print(digest(json.loads(a.policy)))
        return 0
    if a.cmd == "classify":
        text = sys.stdin.read()
        print({"dns": lambda: classify_dns(text), "l2": lambda: classify_l2(text),
               "cause": lambda: classify_cause(text, a.rc, a.ignore.split()),
               "gwerror": lambda: classify_gwerror(text)}[a.kind]())
        return 0
    if a.cmd == "inrange":
        print(in_range(a.addr, a.cidr))
        return 0
    if a.cmd == "diag":
        # Never fails the caller, never echoes a value: a refused row or key is named, no more.
        row = diag_row(a.kind, a.set)
        if row is None:
            print("   diag row not recorded: unknown kind", file=sys.stderr)
            return 0
        if row["refused"]:
            print(f"   diag {a.kind}: refused {row['refused']}", file=sys.stderr)
        write_rows(a.file, [row])
        return 0
    if a.cmd == "diag-api":
        peers = {}
        for kv in a.peer:
            role, _, addr = kv.partition("=")
            if role in PEER_ROLES and IPV4.match(addr):
                peers.setdefault(addr, role)
        write_rows(a.file, api_summary(load(os.path.join(a.dir, "api.jsonl")), peers, a.since))
        return 0
    if a.cmd == "obs":
        # Never fails the caller: a row it cannot record leaves its check absent, which blocks.
        try:
            o = make_obs(a.check, a.criterion, a.cls, a.role, a.batch, a.curl, a.set)
        except ValueError as err:
            print(f"   observation not recorded: {a.check}: {err}", file=sys.stderr)
            return 0
        with open(a.file, "a") as f:
            f.write(json.dumps(o) + "\n")
        return 0
    if a.cmd == "count":
        print(count(load(a.file), a.phase, a.kind, a.since))
        return 0
    if a.cmd == "derive":
        rows = derive(load(a.file), a.phase)
        with open(a.file, "a") as f:
            for o in rows:
                f.write(json.dumps(o) + "\n")
        return 0
    if a.cmd == "judge":
        v, why = check_verdict(load(a.file), a.check)
        if v == LIMIT and a.check in a.accept_limit:
            print(f"   {a.check}: limit, accepted by the owner ({why})")
            return 0
        if v != PASS:
            print(f"   {a.check}: {v} ({why})")
        return EXIT[v]
    if a.cmd == "receipt":
        try:
            with open(a.meta) as f:
                meta = json.load(f)
        except (OSError, ValueError):
            meta = {}
        r = build_receipt(load(a.file), meta, a.accept_limit)
        raw = json.dumps(r, indent=1, sort_keys=True) + "\n"
        with open(a.out, "w") as f:
            f.write(raw)
        print(f"   receipt {r['verdict']}: {r['counts']}, missing {len(r['presence']['missing'])}, "
              f"limits {[x['name'] for x in r['limits']]}, sha256 {hashlib.sha256(raw.encode()).hexdigest()}")
        bad = verify(r, a.accept_limit)
        for b in bad[:30]:
            print(f"   {b}")
        return 0 if not bad else 1
    if a.cmd == "verify":
        try:
            with open(a.receipt) as f:
                bad = verify(json.load(f), a.accept_limit)
        except (OSError, ValueError):
            bad = ["no readable receipt"]
        for b in bad[:30]:
            print(f"   {b}")
        return 0 if not bad else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
