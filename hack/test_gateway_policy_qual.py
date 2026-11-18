#!/usr/bin/env python3
"""Offline tests of hack/gateway-policy-qual.py: the classification and verdict rules of the
gateway-policy section of hack/qualify.sh, its receipt and its fake control API. No host, VM or
network beyond a socket on 127.0.0.1.

    python3 -I hack/test_gateway_policy_qual.py
"""

import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gpq", HERE / "gateway-policy-qual.py")
gpq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gpq)


def val(v):
    return json.dumps(v) if isinstance(v, bool) else "null" if v is None else str(v)


def o(check, cls, role="subject", batch="b", criterion="C3", **kw):
    return gpq.make_obs(check, criterion, cls, role, batch, sets=[f"{k}={val(v)}" for k, v in kw.items()])


def brackets(batch="b", ok=True):
    return [o("bracket.b", "allowed", "bracket_before", batch, rc=0 if ok else 7, http_code=200 if ok else 0),
            o("bracket.b", "allowed", "bracket_after", batch, rc=0, http_code=200)]


class Digest(unittest.TestCase):
    def test_matches_the_gateways_own_canonical_form(self):
        # credential-gateway src/egress.rs, digest_is_sha256_of_the_compact_canonical_json
        canonical = '{"policy_format":1,"namespace":"ns-1","team_id":"team_1","briq_id":"bq_1","hosts":["a.example.com"]}'
        want = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        got = gpq.digest({"hosts": ["a.example.com"], "briq_id": "bq_1", "team_id": "team_1",
                          "namespace": "ns-1", "policy_format": 1})
        self.assertEqual(got, want)

    def test_hosts_are_lowercased_sorted_and_deduplicated(self):
        base = {"policy_format": 1, "namespace": "n", "team_id": "t", "briq_id": "b"}
        a = gpq.digest({**base, "hosts": ["B.example.com", "a.example.com", "b.EXAMPLE.com"]})
        self.assertEqual(a, gpq.digest({**base, "hosts": ["a.example.com", "b.example.com"]}))
        self.assertNotEqual(a, gpq.digest({**base, "hosts": ["a.example.org"]}))


class Classify(unittest.TestCase):
    def test_dns_any_answer_line_is_an_answer_whatever_the_rc(self):
        ok = "Server:\t\t1.1.1.1\nAddress:\t1.1.1.1:53\n\nNon-authoritative answer:\nName:\texample.com\nAddress: 93.184.215.14\nrc=0\n"
        self.assertEqual(gpq.classify_dns(ok), "answer")
        self.assertEqual(gpq.classify_dns(ok.replace("rc=0", "rc=1")), "answer")
        only_addr = "Server: 1.1.1.1\nAddress: 1.1.1.1#53\n\nAddress: 93.184.215.14\nrc=1\n"
        self.assertEqual(gpq.classify_dns(only_addr), "answer")
        timeout = "Server: 1.1.1.1\nAddress: 1.1.1.1:53\n;; connection timed out; no servers could be reached\nrc=1\n"
        self.assertEqual(gpq.classify_dns(timeout), "timeout")
        self.assertEqual(gpq.classify_dns("rc=124\n"), "timeout")
        self.assertEqual(gpq.classify_dns("** server can't find example.com: NXDOMAIN\nrc=1\n"), "other")
        self.assertEqual(gpq.classify_dns("rc=-1\n"), "other")

    def test_l2_busybox_and_iputils_outputs(self):
        blocked = "ARPING 10.0.0.2 from 10.0.0.3 eth0\nSent 2 probe(s) (2 broadcast(s))\nReceived 0 response(s) (0 request(s), 0 broadcast(s))\nPING 10.0.0.2: 56 data bytes\n--- 10.0.0.2 ping statistics ---\n2 packets transmitted, 0 packets received, 100% packet loss\n"
        self.assertEqual(gpq.classify_l2(blocked), "blocked-blocked")
        reached = "Received 2 response(s)\n2 packets transmitted, 2 packets received, 0% packet loss\n"
        self.assertEqual(gpq.classify_l2(reached), "reached-reached")
        self.assertEqual(gpq.classify_l2("2 packets transmitted, 1 received, 50% packet loss\n"), "unknown-reached")
        self.assertEqual(gpq.classify_l2("sh: arping: not found\n"), "unknown-unknown")

    def test_cause(self):
        names = ("qual-42", "m_abc", "gp-")
        self.assertEqual(gpq.classify_cause("anything", 0, names), "ok")
        self.assertEqual(gpq.classify_cause("", 124, names), "timeout")
        self.assertEqual(gpq.classify_cause("error: unexpected argument '--x' found\n\nUsage: briqyard namespace gateway set", 2, names), "usage")
        self.assertEqual(gpq.classify_cause("Error: 409 machine m_abc is bound to its gateway's loaded policy", 1, names), "policy")
        self.assertEqual(gpq.classify_cause("Error: 409 the namespace's gateway carries a policy", 1, names), "policy")
        # The harness's own names never read as a binding or a gateway.
        self.assertEqual(gpq.classify_cause("Error: 404 no machine gp-bound in qual-42-gp", 1, names), "other")
        self.assertEqual(gpq.classify_cause("Error: 404 warm pool not found", 1, names), "other")
        self.assertEqual(gpq.classify_cause("Error: 409 readback refused: no loaded policy", 1, names), "policy")
        self.assertEqual(gpq.classify_cause("Error: connection refused (os error 111)", 1, names), "other")

    def test_curl_output_is_parsed_with_sub_ms_connect_time(self):
        self.assertEqual(gpq.parse_curl("403 403 0.012 0.000312 56"),
                         {"http_code": 403, "http_connect": 403, "ms": 12, "connect_us": 312, "rc": 56})
        self.assertEqual(gpq.parse_curl("000 000 3.001 0.000000 28")["connect_us"], 0)
        self.assertEqual(gpq.parse_curl("000 000 0 0 -1\n000 000 0 0 -1"), {"rc": -1})
        self.assertEqual(gpq.parse_curl(""), {"rc": -1})


class Probes(unittest.TestCase):
    def verdict(self, obs, name):
        return gpq.check_verdict(obs, name)[0]

    def test_proxied_denial_needs_connect_403_a_control_and_brackets(self):
        ok = brackets() + [o("c3.unlisted", "proxied_denial", http_connect=403, http_code=0, rc=56),
                           o("c3.unlisted", "reach", "control", rc=0, http_code=200)]
        self.assertEqual(self.verdict(ok, "c3.unlisted"), gpq.PASS)

    def test_an_accepted_connect_is_fail_open_whatever_follows(self):
        for rc in (35, 52, 60, 0):
            obs = brackets() + [o("c3.unlisted", "proxied_denial", http_connect=200, http_code=0, rc=rc),
                                o("c3.unlisted", "reach", "control", rc=0)]
            self.assertEqual(self.verdict(obs, "c3.unlisted"), gpq.FAIL, rc)

    def test_a_fail_stays_a_fail_even_when_its_control_failed(self):
        obs = brackets(ok=False) + [o("c3.unlisted", "proxied_denial", http_connect=200, rc=35),
                                    o("c3.unlisted", "reach", "control", rc=7)]
        self.assertEqual(self.verdict(obs, "c3.unlisted"), gpq.FAIL)

    def test_a_proxy_that_does_not_answer_is_inconclusive(self):
        for rc in (7, 28, 5, 6, -1):
            obs = brackets() + [o("c3.unlisted", "proxied_denial", http_connect=0, http_code=0, rc=rc),
                                o("c3.unlisted", "reach", "control", rc=0)]
            self.assertEqual(self.verdict(obs, "c3.unlisted"), gpq.INCONCLUSIVE, rc)

    def test_direct_denial_rc_7_or_28_unconnected_with_a_control(self):
        for rc in (7, 28):
            obs = brackets() + [o("c3.direct_tcp80", "direct_denial", rc=rc, connect_us=0),
                                o("c3.direct_tcp80", "reach", "control", rc=0, connect_us=12)]
            self.assertEqual(self.verdict(obs, "c3.direct_tcp80"), gpq.PASS, rc)

    def test_any_connect_time_is_a_connection_on_both_sides(self):
        obs = brackets() + [o("c3.d", "direct_denial", rc=28, connect_us=1), o("c3.d", "reach", "control", rc=0)]
        self.assertEqual(self.verdict(obs, "c3.d"), gpq.FAIL)
        obs = brackets() + [o("c3.d", "direct_denial", rc=7, connect_us=0), o("c3.d", "reach", "control", rc=28, connect_us=1)]
        self.assertEqual(self.verdict(obs, "c3.d"), gpq.PASS)

    def test_direct_denial_without_a_reaching_control_is_inconclusive(self):
        for control in ([], [o("c3.direct_tcp80", "reach", "control", rc=7, connect_us=0)],
                        [o("c3.direct_tcp80", "reach_not403", "control", rc=0, http_code=200)]):
            obs = brackets() + [o("c3.direct_tcp80", "direct_denial", rc=7, connect_us=0)] + control
            self.assertEqual(self.verdict(obs, "c3.direct_tcp80"), gpq.INCONCLUSIVE)

    def test_resolution_failures_are_inconclusive_and_a_connection_is_a_fail(self):
        for rc, want in ((5, gpq.INCONCLUSIVE), (6, gpq.INCONCLUSIVE), (0, gpq.FAIL), (35, gpq.INCONCLUSIVE)):
            obs = brackets() + [o("c3.d", "direct_denial", rc=rc, connect_us=0), o("c3.d", "reach", "control", rc=0)]
            self.assertEqual(self.verdict(obs, "c3.d"), want, rc)

    def test_brackets_missing_or_failed_make_a_denial_inconclusive(self):
        denial = [o("c3.d", "direct_denial", rc=7), o("c3.d", "reach", "control", rc=0)]
        self.assertEqual(self.verdict(brackets()[:1] + denial, "c3.d"), gpq.INCONCLUSIVE)
        self.assertEqual(self.verdict(brackets(ok=False) + denial, "c3.d"), gpq.INCONCLUSIVE)
        other = [o("bracket.x", "allowed", r, "x", rc=0, http_code=200) for r in ("bracket_before", "bracket_after")]
        self.assertEqual(self.verdict(other + denial, "c3.d"), gpq.INCONCLUSIVE)

    def test_plain_http_403_passes_only_beside_a_non_403_control(self):
        subj = o("c3.p", "plain_denial", rc=0, http_code=403)
        good = o("c3.p", "reach_not403", "control", rc=0, http_code=200)
        same = o("c3.p", "reach_not403", "control", rc=0, http_code=403)
        self.assertEqual(self.verdict(brackets() + [subj, good], "c3.p"), gpq.PASS)
        self.assertEqual(self.verdict(brackets() + [subj, same], "c3.p"), gpq.INCONCLUSIVE)
        served = o("c3.p", "plain_denial", rc=0, http_code=200)
        self.assertEqual(self.verdict(brackets() + [served, good], "c3.p"), gpq.FAIL)

    def test_udp_rule(self):
        ctl = o("c3.u", "dns_answer", "control", value="answer")
        for value, want in (("timeout", gpq.PASS), ("answer", gpq.FAIL), ("other", gpq.INCONCLUSIVE)):
            self.assertEqual(self.verdict(brackets() + [o("c3.u", "udp_denial", value=value), ctl], "c3.u"), want)
        bad_ctl = o("c3.u", "dns_answer", "control", value="timeout")
        self.assertEqual(self.verdict(brackets() + [o("c3.u", "udp_denial", value="timeout"), bad_ctl], "c3.u"), gpq.INCONCLUSIVE)

    def test_allowed_asserts_and_limits(self):
        self.assertEqual(self.verdict([o("c3.allowed", "allowed", rc=0, http_code=200)], "c3.allowed"), gpq.PASS)
        self.assertEqual(self.verdict([o("c3.allowed", "allowed", rc=0, http_code=403)], "c3.allowed"), gpq.FAIL)
        self.assertEqual(self.verdict([o("c1.x", "assert", value=True)], "c1.x"), gpq.PASS)
        self.assertEqual(self.verdict([o("c1.x", "assert", value=False)], "c1.x"), gpq.FAIL)
        self.assertEqual(self.verdict([o("c1.x", "assert", value=None)], "c1.x"), gpq.INCONCLUSIVE)
        self.assertEqual(self.verdict([o("c1.x", "observed", value=False)], "c1.x"), gpq.INCONCLUSIVE)
        self.assertEqual(self.verdict([o("c6.f", "assert", value=True), o("c6.f", "assert", value=False)], "c6.f"), gpq.FAIL)
        self.assertEqual(self.verdict([o("c6.f", "measure", value="policy")], "c6.f"), gpq.ABSENT)
        self.assertEqual(self.verdict([o("c6.w", "limit", value="no-pool"), o("c6.w", "assert", value=True)], "c6.w"), gpq.LIMIT)
        self.assertEqual(self.verdict([o("c6.w", "limit", value="no-pool"), o("c6.w", "assert", value=False)], "c6.w"), gpq.FAIL)
        self.assertEqual(self.verdict([o("c6.w", "limit", value="no-pool"), o("c6.w", "observed", value=False)], "c6.w"), gpq.INCONCLUSIVE)

    def test_absent_keeps_its_rank_above_a_limit(self):
        self.assertEqual(gpq.worst([gpq.LIMIT, gpq.ABSENT]), gpq.ABSENT)
        self.assertEqual(gpq.worst([gpq.PASS, gpq.LIMIT]), gpq.LIMIT)
        self.assertEqual(gpq.worst([gpq.ABSENT, gpq.FAIL]), gpq.FAIL)

    def test_a_bad_value_is_recorded_as_null_and_bad_fields_are_refused(self):
        for bad in ("-----BEGIN CERTIFICATE-----", "a b", "x" * 81, '{"cert":1}'):
            self.assertIsNone(gpq.make_obs("c1.x", "C1", "assert", "subject", sets=[f"value={bad}"])["value"])
        self.assertIsNone(gpq.make_obs("c1.x", "C1", "assert", "subject", sets=["rc=abc"])["rc"])
        for sets in (["token=abc"],):
            with self.assertRaises(ValueError):
                gpq.make_obs("c1.x", "C1", "assert", "subject", sets=sets)
        with self.assertRaises(ValueError):
            gpq.make_obs("C1 x", "C1", "assert", "subject")

    def test_obs_cli_never_fails_its_caller(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "o.jsonl")
            self.assertEqual(gpq.main(["obs", "--file", f, "--check", "BAD NAME", "--criterion", "C1", "--cls", "assert"]), 0)
            self.assertEqual(gpq.main(["obs", "--file", f, "--check", "c1.x", "--criterion", "C1", "--cls", "assert", "--set", "value=a b"]), 0)
            rows = gpq.load(f)
            self.assertEqual(len(rows), 1)
            self.assertIsNone(rows[0]["value"])


def curl(kind, rc, t0, code=200, conn_us=0, phase="gateway_kill"):
    s = f"{code} {200 if kind == 'loop_allowed' else 0} 0.1 {conn_us / 1e6:.6f} {rc}"
    return gpq.make_obs(f"loop.{phase}", "C5", kind, "sample", phase, curl=s, sets=[f"t0={t0}", f"t1={t0 + 400}"])


def gate(t, closed, phase="gateway_kill"):
    return gpq.make_obs(f"gate.{phase}", "C5", "gate", "sample", phase, sets=[f"value={val(closed)}", f"t0={t}"])


def mark(name, t, phase="gateway_kill"):
    return gpq.make_obs(f"mark.{phase}", "C2" if phase == "boot" else "C5", "mark", "sample", phase, sets=[f"value={name}", f"t0={t}"])


class Loop(unittest.TestCase):
    def phase(self, extra=(), gate_hold=True, after=5, phase="gateway_kill", in_closed=True):
        obs = [mark("kill", 10_000, phase), mark("hold_recv", 12_000, phase), mark("release", 20_000, phase), mark("reopen", 22_000, phase)]
        for i in range(5):
            t = 1000 + i * 1000
            obs += [curl("loop_allowed", 0, t, phase=phase), curl("loop_direct", 28, t + 450, code=0, phase=phase)]
        for i in range(after):
            t = 23_000 + i * 1000
            obs += [curl("loop_allowed", 0, t, phase=phase), curl("loop_direct", 7, t + 450, code=0, phase=phase)]
        if in_closed:
            obs += [curl("loop_allowed", 28, 14_000, code=0, phase=phase), curl("loop_direct", 28, 14_500, code=0, phase=phase)]
        else:
            obs += [curl("loop_allowed", -1, 14_000, phase=phase), curl("loop_direct", -1, 14_500, phase=phase)]
        obs += [gate(t, gate_hold, phase) for t in range(12_000, 20_001, 500)]
        obs.append(gate(21_000, False, phase))
        return obs + list(extra)

    def derived(self, obs, phase="gateway_kill"):
        d = obs + gpq.derive(obs, phase)
        names = gpq.C5_LOOP + (("hold_gate_closed",) if phase == "gateway_kill" else ())
        return {k: gpq.check_verdict(d, f"c5.{phase}.{k}")[0] for k in names}

    def test_a_clean_phase_passes(self):
        self.assertEqual(set(self.derived(self.phase()).values()), {gpq.PASS})

    def test_a_loop_not_proven_alive_after_the_reopen_is_inconclusive(self):
        self.assertEqual(self.derived(self.phase(after=4))["alive_after"], gpq.INCONCLUSIVE)

    def test_an_allowed_answer_before_the_new_ca_reply_is_a_fail(self):
        leak = [curl("loop_allowed", 0, 15_000)]
        self.assertEqual(self.derived(self.phase(leak))["no_traffic_while_closed"], gpq.FAIL)

    def test_a_direct_probe_that_connected_is_a_fail_whatever_its_rc(self):
        for rc in (0, 35, 52, 56, 60, 28):
            leak = [curl("loop_direct", rc, 3_000, code=0, conn_us=250)]
            self.assertEqual(self.derived(self.phase(leak))["direct_never_open"], gpq.FAIL, rc)

    def test_no_direct_probe_while_closed_is_inconclusive(self):
        v = self.derived(self.phase(in_closed=False))
        self.assertEqual(v["direct_while_closed"], gpq.INCONCLUSIVE)

    def test_daemon_kill_without_a_probe_in_the_closed_stretch_is_a_limit_never_a_pass(self):
        v = self.derived(self.phase(phase="daemon_kill", in_closed=False), "daemon_kill")
        self.assertEqual(v["no_traffic_while_closed"], gpq.LIMIT)
        self.assertEqual(v["direct_while_closed"], gpq.LIMIT)
        v = self.derived(self.phase(phase="daemon_kill"), "daemon_kill")
        self.assertEqual(set(v.values()), {gpq.PASS})

    def test_a_gate_read_open_during_the_hold_is_a_fail_and_never_closed_is_inconclusive(self):
        v = self.derived(self.phase(gate_hold=False))
        self.assertEqual(v["hold_gate_closed"], gpq.FAIL)
        self.assertEqual(v["closed_observed"], gpq.INCONCLUSIVE)

    def test_no_samples_at_all_is_not_a_pass(self):
        self.assertNotIn(gpq.PASS, self.derived([]).values())

    def test_an_unresolved_direct_probe_is_not_a_denial_in_the_closed_stretch(self):
        # Fable81 repro: the only sample inside the closed run is a direct probe with rc 6.
        obs = [x for x in self.phase(in_closed=False) if not (x["cls"] in ("loop_allowed", "loop_direct") and x["rc"] == -1)]
        obs.append(curl("loop_direct", 6, 14_500, code=0))
        v = self.derived(obs)
        self.assertNotEqual(v["no_traffic_while_closed"], gpq.PASS)
        self.assertNotEqual(v["direct_while_closed"], gpq.PASS)

    def test_no_traffic_needs_an_allowed_probe_in_the_closed_stretch(self):
        obs = [x for x in self.phase() if not (x["cls"] == "loop_allowed" and 12_000 <= x["t0"] <= 20_000)]
        self.assertEqual(self.derived(obs)["no_traffic_while_closed"], gpq.INCONCLUSIVE)
        self.assertEqual(self.derived(obs)["direct_while_closed"], gpq.PASS)

    def test_daemon_kill_limit_reasons_are_what_was_observed(self):
        def reason(obs):
            d = gpq.derive(obs, "daemon_kill")
            return {x["check"]: x["value"] for x in d if x["cls"] == "limit"}
        execs = reason(self.phase(phase="daemon_kill", in_closed=False))
        self.assertEqual(set(execs.values()), {"exec-needs-the-daemon"})
        none = [x for x in self.phase(phase="daemon_kill", in_closed=False) if x.get("rc") != -1]
        self.assertEqual(set(reason(none).values()), {"no-sample-in-closed-run"})

    def test_derive_emits_no_limit_outside_limitable(self):
        emitted = set()
        for phase in ("gateway_kill", "daemon_kill"):
            for obs in (self.phase(phase=phase), self.phase(phase=phase, in_closed=False), [], self.phase(phase=phase, gate_hold=False)):
                emitted |= {x["check"] for x in gpq.derive(obs, phase) if x["cls"] == "limit"}
        for obs in (Boot().rows(), [], Mismatch().rows()):
            emitted |= {x["check"] for x in gpq.derive(obs, "boot") + gpq.derive(obs, "mismatch") if x["cls"] == "limit"}
        self.assertLessEqual(emitted, set(gpq.LIMITABLE))
        self.assertEqual(emitted, set(gpq.LIMITABLE))

    def test_count_feeds_the_waits(self):
        obs = self.phase()
        self.assertEqual(gpq.count(obs, "gateway_kill", "allowed_ok", 22_000), 5)
        self.assertEqual(gpq.count(obs, "gateway_kill", "direct_denied"), 11)


class Boot(unittest.TestCase):
    def rows(self, l2=("blocked-blocked", 13_000, 17_000), admits=(("none", 12_500), ("creating", 18_000), ("running", 24_000)), gates=((13_000, True), (21_000, True), (23_000, False))):
        obs = [mark("hold_recv", 12_000, "boot"), mark("release", 20_000, "boot"), mark("readback", 25_000, "boot")]
        if l2:
            obs.append(gpq.make_obs("l2.boot", "C2", "l2", "sample", "boot", sets=[f"value={l2[0]}", f"t0={l2[1]}", f"t1={l2[2]}"]))
        obs += [gpq.make_obs("admit.boot", "C2", "admit", "sample", "boot", sets=[f"value={s}", f"t0={t}"]) for s, t in admits]
        obs += [gate(t, c, "boot") for t, c in gates]
        return obs

    def verdicts(self, obs):
        d = obs + gpq.derive(obs, "boot")
        return {n: gpq.check_verdict(d, n)[0] for n in ("c2.closed_observed", "c2.hold_arp_blocked", "c2.hold_icmp_blocked", "c2.no_admission_during_hold")}

    def test_a_clean_boot_passes(self):
        self.assertEqual(set(self.verdicts(self.rows()).values()), {gpq.PASS})

    def test_a_probe_that_ended_after_the_release_is_not_during_the_hold(self):
        v = self.verdicts(self.rows(l2=("blocked-blocked", 13_000, 20_500)))
        self.assertEqual((v["c2.closed_observed"], v["c2.hold_arp_blocked"]), (gpq.INCONCLUSIVE, gpq.INCONCLUSIVE))

    def test_a_reached_gateway_during_the_hold_is_a_fail(self):
        v = self.verdicts(self.rows(l2=("reached-blocked", 13_000, 17_000)))
        self.assertEqual((v["c2.hold_arp_blocked"], v["c2.hold_icmp_blocked"]), (gpq.FAIL, gpq.PASS))
        self.assertEqual(self.verdicts(self.rows(l2=("unknown-blocked", 13_000, 17_000)))["c2.hold_arp_blocked"], gpq.INCONCLUSIVE)

    def test_admission_before_a_later_closed_gate_read_is_a_fail(self):
        v = self.verdicts(self.rows(admits=(("none", 12_500), ("running", 19_000))))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.FAIL)
        # Admitted but still booting: starting counts as admitted.
        v = self.verdicts(self.rows(admits=(("none", 12_500), ("starting", 20_500), ("running", 24_000))))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.FAIL)

    def test_a_fast_boot_after_the_last_closed_read_is_not_a_fail(self):
        # Running before the first open read, but after every closed one: the sampler's cadence
        # is not evidence of an unverified admission.
        v = self.verdicts(self.rows(admits=(("none", 12_500), ("creating", 18_000), ("running", 22_000))))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.PASS)

    def test_a_hold_with_only_unreadable_admission_samples_is_inconclusive(self):
        v = self.verdicts(self.rows(admits=(("unknown", 12_500), ("unknown", 18_000), ("running", 24_000))))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.INCONCLUSIVE)

    def test_admission_before_the_release_is_a_fail_without_a_closed_read(self):
        v = self.verdicts(self.rows(admits=(("none", 12_500), ("running", 19_000)), gates=((21_000, False),)))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.FAIL)

    def test_admission_without_any_gate_read_is_inconclusive(self):
        v = self.verdicts(self.rows(gates=()))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.INCONCLUSIVE)

    def test_no_admission_sample_in_the_hold_is_inconclusive(self):
        v = self.verdicts(self.rows(admits=(("running", 24_000),)))
        self.assertEqual(v["c2.no_admission_during_hold"], gpq.INCONCLUSIVE)


class Mismatch(unittest.TestCase):
    def rows(self, states=("none", "creating", "error"), rc=1):
        obs = [gpq.make_obs("admit.mismatch", "C2", "admit", "sample", "mismatch", sets=[f"value={s}", f"t0={1000 + i * 300}"])
               for i, s in enumerate(states)]
        if rc is not None:
            obs.append(gpq.make_obs("mark.mismatch", "C2", "mark", "sample", "mismatch", sets=["value=create", f"rc={rc}", "t0=9000"]))
        return obs

    def verdict(self, obs):
        return gpq.check_verdict(obs + gpq.derive(obs, "mismatch"), "c2.mismatch_not_admitted")[0]

    def test_a_refused_create_left_in_error_none_or_creating_passes(self):
        # create.rs: a start refused while creating goes to create_failed_locked, state error.
        for states in (("none", "creating", "error"), ("none", "none"), ("creating",), ("unknown", "error")):
            self.assertEqual(self.verdict(self.rows(states)), gpq.PASS, states)

    def test_starting_or_running_at_any_sample_is_a_fail(self):
        for states in (("none", "starting", "error"), ("creating", "running", "error")):
            self.assertEqual(self.verdict(self.rows(states)), gpq.FAIL, states)

    def test_a_create_that_succeeded_is_a_fail_and_a_timeout_or_unread_state_inconclusive(self):
        self.assertEqual(self.verdict(self.rows(("none", "creating"), rc=0)), gpq.FAIL)
        self.assertEqual(self.verdict(self.rows(rc=124)), gpq.INCONCLUSIVE)
        self.assertEqual(self.verdict(self.rows(("unknown", "unknown"))), gpq.INCONCLUSIVE)
        self.assertEqual(self.verdict(self.rows(rc=None)), gpq.INCONCLUSIVE)
        self.assertEqual(self.verdict(self.rows(("creating", "stopped"))), gpq.INCONCLUSIVE)


def all_passing():
    return [gpq.make_obs(n, crit, "assert", "subject", sets=["value=true"]) for crit, names in gpq.REQUIRED.items() for n in names]


META = {"native_sha": "4a3ca42ff74861622e90ca2f25201a6516adad8e", "harness_sha256": "a" * 64,
        "helper_sha256": "b" * 64, "gateway_image": "ghcr.io/briq-cloud/credential-gateway@sha256:" + "c" * 64,
        "gateway_source_sha": "e5203d2e4522243355a3280e47343ee8c631222a", "briq_sha": "", "run_id": "123",
        "kernel": "6.8.0-1-azure", "boot_timeout_sec": "300", "elapsed_sec": "812"}


class Receipt(unittest.TestCase):
    def test_every_required_check_passing_is_a_pass(self):
        r = gpq.build_receipt(all_passing(), META)
        self.assertEqual(r["verdict"], gpq.PASS)
        self.assertEqual(gpq.verify(r), [])
        self.assertEqual(r["counts"]["checks"], sum(len(v) for v in gpq.REQUIRED.values()))

    def test_evidence_rows_do_not_become_absent_checks(self):
        # DeepSeek80/Fable81 B1: brackets, loop samples, gate reads and marks beside every required check.
        evidence = brackets("c3") + Loop().phase() + Loop().phase(phase="daemon_kill") + Boot().rows()
        r = gpq.build_receipt(all_passing() + evidence, META)
        self.assertEqual((r["verdict"], r["presence"]["missing"], gpq.verify(r)), (gpq.PASS, [], []))
        self.assertEqual({c["name"] for c in r["checks"]}, set(gpq.CRITERION_OF))
        self.assertTrue(r["batches"]["c3"]["ok"])
        self.assertGreater(r["phases"]["gateway_kill"]["samples"], 0)

    def test_a_missing_required_check_with_evidence_does_not_pass(self):
        evidence = brackets("c3") + Loop().phase()
        obs = [x for x in all_passing() if x["check"] != "c5.gateway_kill.alive_after"] + evidence
        r = gpq.build_receipt(obs, META)
        self.assertNotEqual(r["verdict"], gpq.PASS)
        self.assertEqual(r["presence"]["missing"], ["c5.gateway_kill.alive_after"])
        self.assertIn("absent: c5.gateway_kill.alive_after", gpq.verify(r))

    def test_no_observation_at_all_fails(self):
        r = gpq.build_receipt([], META)
        self.assertNotEqual(r["verdict"], gpq.PASS)
        self.assertIn("zero checks", gpq.verify(r))

    def test_inconclusive_blocks_c1_to_c7_but_c8_is_a_limit_of_phase_a(self):
        obs = all_passing() + [gpq.make_obs("c4.resize.direct", "C4", "observed", "subject", sets=["value=false"])]
        self.assertEqual(gpq.build_receipt(obs, META)["verdict"], gpq.INCONCLUSIVE)
        obs = all_passing() + [gpq.make_obs("c8.legacy_gate_empty", "C8", "observed", "subject", sets=["value=false"])]
        r = gpq.build_receipt(obs, META)
        self.assertEqual((r["verdict"], r["criteria"]["C8"]), (gpq.PASS, gpq.INCONCLUSIVE))

    def test_a_limit_is_visible_and_passes_verify_only_when_accepted(self):
        obs = all_passing() + [gpq.make_obs("c6.warm_claim", "C6", "limit", "subject", sets=["value=refused-for-other-cause"])]
        r = gpq.build_receipt(obs, META)
        self.assertEqual((r["verdict"], r["criteria"]["C6"]), (gpq.LIMIT, gpq.LIMIT))
        self.assertEqual(r["limits"], [{"name": "c6.warm_claim", "criterion": "C6", "reason": "limit: refused-for-other-cause", "accepted": False}])
        self.assertTrue(gpq.verify(r))
        self.assertEqual(gpq.verify(r, accept=["c6.warm_claim"]), [])

    def test_accept_limit_on_the_receipt_and_judge(self):
        with tempfile.TemporaryDirectory() as d:
            obs, meta, out = (os.path.join(d, n) for n in ("o.jsonl", "m.json", "r.json"))
            Path(meta).write_text(json.dumps(META))
            rows = all_passing() + [gpq.make_obs("c6.warm_claim", "C6", "limit", "subject", sets=["value=refused-for-other-cause"])]
            Path(obs).write_text("".join(json.dumps(x) + "\n" for x in rows))
            self.assertEqual(gpq.main(["receipt", "--file", obs, "--meta", meta, "--out", out]), 1)
            self.assertEqual(gpq.main(["receipt", "--file", obs, "--meta", meta, "--out", out, "--accept-limit", "c6.warm_claim"]), 0)
            r = json.loads(Path(out).read_text())
            self.assertEqual((r["verdict"], r["limits"][0]["accepted"]), (gpq.LIMIT, True))
            self.assertEqual(gpq.main(["verify", out, "--accept-limit", "c6.warm_claim"]), 0)
            self.assertEqual(gpq.main(["verify", out]), 1)
            self.assertEqual(gpq.main(["judge", "--file", obs, "--check", "c6.warm_claim", "--accept-limit", "c6.warm_claim"]), 0)
            self.assertEqual(gpq.main(["judge", "--file", obs, "--check", "c6.warm_claim"]), 5)
            # An accepted name does not cover another limit, an absence or an inconclusive.
            rows.append(gpq.make_obs("c6.template", "C6", "limit", "subject", sets=["value=refused-for-other-cause"]))
            rows.append(gpq.make_obs("c3.allowed", "C3", "observed", "subject", sets=["value=false"]))
            Path(obs).write_text("".join(json.dumps(x) + "\n" for x in rows if x["check"] != "c1.fresh_challenge"))
            self.assertEqual(gpq.main(["receipt", "--file", obs, "--meta", meta, "--out", out, "--accept-limit", "c6.warm_claim"]), 1)
            self.assertEqual(gpq.main(["judge", "--file", obs, "--check", "c1.fresh_challenge", "--accept-limit", "c1.fresh_challenge"]), 4)
            self.assertEqual(gpq.main(["judge", "--file", obs, "--check", "c3.allowed", "--accept-limit", "c3.allowed"]), 3)

    def test_a_fail_anywhere_in_c1_to_c7_is_the_verdict(self):
        obs = all_passing() + [gpq.make_obs("c6.move", "C6", "assert", "subject", sets=["value=false"])]
        r = gpq.build_receipt(obs, META)
        self.assertEqual((r["verdict"], r["criteria"]["C6"]), (gpq.FAIL, gpq.FAIL))
        self.assertTrue(gpq.verify(r, accept=["c6.move"]))

    def test_fixed_fields_and_sanitized_meta(self):
        r = gpq.build_receipt(all_passing(), {**META, "kernel": "-----BEGIN PRIVATE KEY-----", "token": "secret"})
        self.assertEqual(set(r), {"schema", "suite", "section", "meta", "verdict", "criteria", "presence", "counts",
                                  "limits", "checks", "batches", "phases", "measurements"})
        self.assertEqual(set(r["meta"]), set(gpq.META))
        self.assertIsNone(r["meta"]["kernel"])
        self.assertIsNone(r["meta"]["briq_sha"])
        self.assertEqual(r["meta"]["elapsed_sec"], "812")
        for c in r["checks"]:
            self.assertEqual(set(c), {"name", "criterion", "verdict", "reason", "observations", "batches", "probes"})
            for p in c["probes"]:
                self.assertEqual(set(p), set(gpq.PROBE_KEYS))

    def test_measurements_are_reported_not_judged(self):
        obs = all_passing() + [gpq.make_obs("q7.host_ports_9443", "Q7", "measure", "subject", sets=["http_code=404"])]
        r = gpq.build_receipt(obs, META)
        self.assertEqual(r["verdict"], gpq.PASS)
        self.assertEqual(r["measurements"][0]["check"], "q7.host_ports_9443")
        self.assertNotIn("q7.host_ports_9443", {c["name"] for c in r["checks"]})

    def test_cli_receipt_and_verify_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            obs, meta, out = (os.path.join(d, n) for n in ("o.jsonl", "m.json", "r.json"))
            Path(meta).write_text(json.dumps(META))
            Path(obs).write_text("".join(json.dumps(x) + "\n" for x in all_passing()))
            self.assertEqual(gpq.main(["receipt", "--file", obs, "--meta", meta, "--out", out]), 0)
            self.assertEqual(gpq.main(["verify", out]), 0)
            self.assertEqual(gpq.main(["judge", "--file", obs, "--check", "c1.readback_digest"]), 0)
            self.assertEqual(gpq.main(["judge", "--file", obs, "--check", "c1.nothing"]), 4)
            Path(obs).write_text("")
            self.assertEqual(gpq.main(["receipt", "--file", obs, "--meta", meta, "--out", out]), 1)
            self.assertEqual(gpq.main(["verify", out]), 1)
            self.assertEqual(gpq.main(["verify", os.path.join(d, "missing.json")]), 1)


class FakeApi(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.server = gpq.make_server(0, 0.6, self.dir.name, "tok", bind="127.0.0.1")
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.dir.cleanup()

    def call(self, method, path, body=None, token="tok"):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                return res.status, json.loads(res.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, None

    def log(self):
        return [json.loads(line) for line in Path(self.dir.name, "api.jsonl").read_text().splitlines()]

    def test_ca_is_held_and_config_answers_meanwhile(self):
        got = {}
        t = threading.Thread(target=lambda: got.update(ca=self.call("PUT", "/internal/credential-gateway/ca", {"cert": "-----BEGIN CERTIFICATE-----\nsynthetic\n"})))
        start = time.monotonic()
        t.start()
        time.sleep(0.1)
        self.assertEqual(self.call("GET", "/internal/credential-gateway/config"), (200, {"secrets": [], "briqs": []}))
        self.assertLess(time.monotonic() - start, 0.5)
        t.join()
        self.assertGreaterEqual(time.monotonic() - start, 0.6)
        self.assertEqual(got["ca"], (200, {}))
        ca = Path(self.dir.name, "ca-127.0.0.1.pem")
        self.assertTrue(ca.read_text().startswith("-----BEGIN CERTIFICATE-----"))
        self.assertEqual(stat.S_IMODE(ca.stat().st_mode), 0o600)
        puts = [e for e in self.log() if e["method"] == "PUT"]
        self.assertEqual([e["event"] for e in puts], ["recv", "done"])
        self.assertGreaterEqual(puts[1]["t"] - puts[0]["t"], 550)
        self.assertNotIn("synthetic", Path(self.dir.name, "api.jsonl").read_text())

    def test_config_serves_only_the_harness_ids_and_addresses(self):
        Path(self.dir.name, "config.json").write_text(json.dumps({"briqs": [
            {"id": "qual-m-abc", "host": "10.0.3.5", "secrets": ["X"], "own": [{"value": "leak"}]},
            {"id": "Bad Id", "host": "10.0.3.6"}, {"id": "qual-x", "host": "example.com"}]}))
        self.assertEqual(self.call("GET", "/internal/credential-gateway/config"),
                         (200, {"secrets": [], "briqs": [{"id": "qual-m-abc", "host": "10.0.3.5"}]}))
        Path(self.dir.name, "config.json").write_text("not json")
        self.assertEqual(self.call("GET", "/internal/credential-gateway/config"), (200, {"secrets": [], "briqs": []}))

    def test_token_cert_events_and_unknown_paths(self):
        self.assertEqual(self.call("GET", "/internal/credential-gateway/config", token="nope")[0], 401)
        self.assertEqual(self.call("GET", "/internal/credential-gateway/config", token=None)[0], 401)
        self.assertEqual(self.call("PUT", "/internal/credential-gateway/ca", {"cert": "not a cert"})[0], 400)
        self.assertEqual(self.call("POST", "/internal/credential-gateway/events", {"events": []}), (200, {}))
        self.assertEqual(self.call("GET", "/internal/credential-gateway/events")[0], 404)
        self.assertEqual(self.call("GET", "/anything")[0], 404)
        self.assertEqual(self.call("GET", "/healthz", token=None), (200, {"ok": True}))
        self.assertFalse(any(p.name.startswith("ca-") for p in Path(self.dir.name).iterdir()))


class Harness(unittest.TestCase):
    """hack/qualify.sh emits and judges every required check, and keeps the CA out of $LOGS."""

    src = (HERE / "qualify.sh").read_text()

    def test_every_required_check_is_named_in_qualify(self):
        for op in gpq.C4_OPS:
            self.assertRegex(self.src, rf'c4_after {op} "\$okr"')
        for phase in gpq.PHASES:
            self.assertIn(f"gq derive --file \"$GWP_OBS\" --phase {phase}", self.src)
        for n in gpq.CRITERION_OF:
            if not n.startswith("c4."):
                self.assertRegex(self.src, rf"(?<![\w.]){re.escape(n)}(?![\w.])", n)

    def test_every_required_check_is_judged(self):
        judged = set()
        for m in re.finditer(r"^\s*judged ((?:[^\n\\]|\\\n)+)", self.src, re.M):
            judged |= set(m.group(1).replace("\\\n", " ").split())
        missing = [n for n in gpq.CRITERION_OF if not n.startswith("c4.") and n not in judged]
        self.assertEqual(missing, [])

    def test_the_accepted_limits_are_exactly_the_limits_the_section_can_emit(self):
        m = re.search(r'^GWP_ACCEPTED_LIMITS="([^"]*)"$', self.src, re.M)
        accepted = set(m.group(1).split())
        emitted = set(re.findall(r"^\s*refused (c\d\.\w+) C\d limit ", self.src, re.M))
        emitted |= set(re.findall(r'obs (c\d[\w.]+) C\d limit ', self.src))
        emitted |= set(gpq.LIMITABLE)
        self.assertEqual(accepted, emitted)
        self.assertIn('"$' + '{GWP_ACCEPT[@]}"', self.src.split("gq receipt", 1)[1].split("\n", 1)[0])
        self.assertIn('judge() { gq judge --file "$GWP_OBS" --check "$1" "$' + '{GWP_ACCEPT[@]}"; }', self.src)

    def test_the_gateway_image_is_pinned_by_digest(self):
        self.assertIn("GWP_IMAGE=ghcr.io/briq-cloud/credential-gateway@sha256:a9c2a13b03d256c50a0eb166d771cceb797f2f4078f960e33e736bbab793b352\n", self.src)

    def test_the_fake_apis_files_are_outside_the_uploaded_logs(self):
        self.assertIn("GWP=$(mktemp -d /tmp/qual-gwp-XXXXXX)", self.src)
        self.assertNotRegex(self.src, r"GWP=\$LOGS")


class Diag(unittest.TestCase):
    """The writer of $LOGS/gateway-policy-diag.jsonl: enums, integers and addresses, nothing else."""

    CA = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"
    KEY = "-----BEGIN PRIVATE KEY-----"
    TOKEN = "qual-synthetic-gateway-token"
    POLICY = '{"policy_format":1,"namespace":"q-gp","team_id":"qual-team","briq_id":"qual-briq","hosts":["example.com"]}'
    DIGEST = "sha256:" + "ab" * 32
    CONSOLE = "[    2.104] credential-gateway: listening on 0.0.0.0:3128"
    HOST = "example.com"

    def test_secret_and_text_values_are_refused_in_every_field(self):
        for kind, schema in gpq.DIAG.items():
            for key in schema:
                for bad in (self.CA, self.KEY, self.TOKEN, self.POLICY, self.DIGEST, self.CONSOLE, self.HOST,
                            self.DIGEST[7:]):
                    row = gpq.diag_row(kind, [f"{key}={bad}"])
                    raw = json.dumps(row)
                    self.assertIsNone(row[key], (kind, key, bad))
                    self.assertIn(key, row["refused"])
                    for piece in (bad, bad[:20], "BEGIN", "sha256", "synthetic", "example.com"):
                        self.assertNotIn(piece, raw, (kind, key))

    def test_values_that_match_are_kept_typed(self):
        row = gpq.diag_row("gateway", ["step=set_boot", "ns=main", "state=running", "error_reason=none",
                                       "error=port_no_answer", "ip=10.64.3.2", "gate=false", "incarnations=1"])
        self.assertEqual(row["refused"], [])
        self.assertEqual((row["ip"], row["gate"], row["incarnations"]), ("10.64.3.2", "false", 1))
        self.assertEqual(gpq.diag_row("reach", ["uplink_code=401", "bridge_code=000", "bridge_rc=28"])["bridge_code"], 0)

    def test_unknown_kinds_keys_and_addresses(self):
        self.assertIsNone(gpq.diag_row("console", ["text=x"]))
        row = gpq.diag_row("step", ["name=set_boot", "output=" + self.CONSOLE, self.TOKEN + "=1"])
        self.assertNotIn("output", row)
        self.assertEqual(row["refused"], ["?", "output"])
        self.assertNotIn(self.TOKEN, json.dumps(row))
        for ip in ("10.64.3.256", "10.64.3", "::1", "10.64.3.2 "):
            self.assertIsNone(gpq.diag_row("gateway", [f"ip={ip}"])["ip"], ip)

    def test_cli_writes_one_row_and_never_echoes_a_value(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "diag.jsonl")
            r = subprocess.run([sys.executable, "-I", str(HERE / "gateway-policy-qual.py"), "diag", "--file", f,
                                "--kind", "step", "--set", "name=set_boot", "--set", "cause=" + self.POLICY],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("qual-team", r.stdout + r.stderr)
            rows = [json.loads(x) for x in open(f)]
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["name"], rows[0]["cause"], rows[0]["refused"]), ("set_boot", None, ["cause"]))
            r = subprocess.run([sys.executable, "-I", str(HERE / "gateway-policy-qual.py"), "diag", "--file", f,
                                "--kind", "console", "--set", "text=" + self.CONSOLE], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("listening", r.stdout + r.stderr)
            self.assertEqual(len(open(f).readlines()), 1)

    def test_gateway_errors_are_classed_by_the_daemons_prefix_only(self):
        pre = "the namespace's gateway did not come up: "
        cases = {
            "": "none",
            pre + "the gateway exited: port 3128 did not answer": "exited",
            pre + "port 3128 did not answer: deadline elapsed: [ 1.2] not ready": "port_no_answer",
            "port 3128 did not answer: x": "port_no_answer",
            pre + "not ready: the gateway exited": "not_ready",
            "gateway loaded policy not verified: the gateway did not become ready": "unverified",
            pre + self.CONSOLE: "other",
            "[ 1.2] the gateway exited": "other",
        }
        for text, want in cases.items():
            self.assertEqual(gpq.classify_gwerror(text), want, text)

    def test_in_range(self):
        self.assertEqual(gpq.in_range("10.64.0.1", "10.64.0.0/10"), "true")
        self.assertEqual(gpq.in_range("10.128.0.1", "10.64.0.0/10"), "false")
        self.assertEqual(gpq.in_range("", "10.64.0.0/10"), "null")
        self.assertEqual(gpq.in_range("10.0.0.1", "nonsense"), "null")

    def test_api_summary_counts_by_method_path_status_and_role(self):
        t = 1_000_000
        rows = [
            {"event": "recv", "method": "PUT", "path": "/internal/credential-gateway/ca", "peer": "10.64.0.2", "t": t + 10},
            {"event": "done", "method": "PUT", "path": "/internal/credential-gateway/ca", "peer": "10.64.0.2", "status": 200, "t": t + 8010},
            {"event": "done", "method": "GET", "path": "/internal/credential-gateway/config", "peer": "10.64.0.2", "status": 200, "t": t + 9000},
            {"event": "done", "method": "GET", "path": "/internal/credential-gateway/config", "peer": "10.64.0.2", "status": 200, "t": t + 9500},
            {"event": "done", "method": "GET", "path": "/", "peer": "10.64.0.5", "status": 401, "t": t + 5},
            {"event": "done", "method": "DELETE", "path": "/" + self.TOKEN, "peer": "10.9.9.9", "status": 401, "t": t + 7},
        ]
        out = gpq.api_summary(rows, {"10.64.0.2": "gateway", "10.64.0.5": "open"}, t)
        raw = json.dumps(out)
        self.assertNotIn(self.TOKEN, raw)
        self.assertNotIn("10.9.9.9", raw)
        got = {(r["method"], r["path"], r["status"], r["peer"]): (r["count"], r["first_ms"], r["last_ms"]) for r in out}
        self.assertEqual(got, {
            ("PUT", "ca", 200, "gateway"): (1, 8010, 8010),
            ("GET", "config", 200, "gateway"): (2, 9000, 9500),
            ("GET", "other", 401, "open"): (1, 5, 5),
            ("other", "other", 401, "other"): (1, 7, 7),
        })
        self.assertTrue(all(r["refused"] == [] for r in out))


def shell_function(src, name):
    start = src.index(f"\n{name}() {{\n") + 1
    return src[start:src.index("\n}\n", start) + 3]


class HarnessShell(unittest.TestCase):
    """The section's API address, its preflight, its early exits and its diag rows."""

    src = (HERE / "qualify.sh").read_text()

    def section(self):
        return self.src[self.src.index("\ngateway_policy() {\n"):self.src.index("\ngateway_policy || bad")]

    def test_the_gateways_api_url_is_the_uplink_address_never_a_bridge(self):
        self.assertIn('-e "BRIQ_API_URL=$GWP_API"', self.src)
        self.assertIn("  GWP_API=http://$hostip:9443\n", self.section())
        self.assertIn("hostip=$(ip -4 route get 1.1.1.1 |", self.src)
        self.assertNotRegex(shell_function(self.src, "gwargs"), r"\$br")
        calls = re.findall(r"gwargs ([^;]*);", self.src)
        self.assertGreaterEqual(len(calls), 6)
        for c in calls:
            self.assertNotRegex(c, r'"\$br[lm]?"', c)

    def test_the_preflight_is_required_emitted_judged_and_gates_every_boot(self):
        self.assertIn("c2.api_reachable_preflight", gpq.REQUIRED["C2"])
        sec = self.section()
        emit = sec.index('obs c2.api_reachable_preflight C2 assert subject ""')
        self.assertIn("judged c2.api_reachable_preflight\n", sec)
        self.assertIn('[ "$upc" = 401 ] && [ "$uprc" = 0 ]', sec)
        self.assertIn('[ "$bpc" = 000 ] && [ "$bprc" = 28 ]', sec)
        for step in ("set_boot", "set_legacy", "set_mismatch"):
            at = sec.index(f"gstep {step} ")
            self.assertLess(emit, at, step)
            guard = sec.rindex("\n  if ", 0, at)
            self.assertIn('[ "$GWP_UPLINK" = ok ]', sec[guard:sec.index("\n", guard + 1)], step)

    def run_bash(self, script, timeout=20):
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout)

    def test_wait_set_ends_once_its_set_has_exited(self):
        fn = shell_function(self.src, "wait_set")
        pre = 'gdiag() { shift; echo "$*" >>"$D"; }\nD=$(mktemp)\n' + fn
        cases = [
            ('sleep 0 & p=$!; wait $p; wait_set w 50 "$p" false "" 0.01', 1, "name=w --set iterations=1 --set end=set_exited"),
            ('sleep 0 & p=$!; wait $p; wait_set w 5 "$p" false false 0.01', 1, "iterations=5 --set end=exhausted"),
            ('sleep 5 & p=$!; wait_set w 3 "$p" false "" 0.01; r=$?; kill $p; wait $p 2>/dev/null; (exit $r)', 1, "iterations=3 --set end=exhausted"),
            ('wait_set w 3 "" false "" 0.01', 1, "iterations=3 --set end=exhausted"),
            ('(sleep 0.3; touch "$D.ok") & p=$!; wait_set w 500 "$p" "[ -e \\"$D.ok\\" ]" "" 0.01; rm -f "$D.ok"', 0, "end=met"),
            ('wait_set w 3 "" true', 0, "iterations=1 --set end=met"),
        ]
        for body, rc, want in cases:
            r = self.run_bash(pre + body + '\nrc=$?; cat "$D"; rm -f "$D"; exit $rc')
            self.assertEqual(r.returncode, rc, (body, r.stdout, r.stderr))
            self.assertIn(want, r.stdout, body)

    def test_gstep_passes_output_and_rc_and_keeps_its_diag_out_of_a_capture(self):
        script = ("GWP=$(mktemp -d); GWP_T0=0; T=q; GWP_DIAG=$GWP/d\n"
                  "now_ms() { echo 5; }\n"
                  'gq() { echo "gateway policy readback noise" >&2; [ "$1" = classify ] && echo ok; return 0; }\n'
                  + re.search(r"^gdiag\(\) \{.*\}$", self.src, re.M).group(0) + "\n"
                  + "gwp_view() { echo 'gateway policy view noise' >&2; }\n"
                  + shell_function(self.src, "gstep")
                  + "out=$(gstep x main sh -c 'echo out; echo err >&2; exit 3' 2>&1); rc=$?\n"
                  + 'printf "%s|%s" "$out" "$rc"; rm -rf "$GWP"')
        r = self.run_bash(script)
        self.assertEqual(r.stdout, "out\nerr|3", r.stderr)

    def test_every_diag_row_comes_from_the_helpers_writer(self):
        self.assertEqual(self.src.count("gateway-policy-diag.jsonl"), 1)
        allowed = (
            "GWP_DIAG=$LOGS/gateway-policy-diag.jsonl; : >\"$GWP_DIAG\"",
            'gdiag() { local k=$1; shift; gq diag --file "$GWP_DIAG" --kind "$k" "$@" 2>/dev/null; }',
            'gq diag-api --file "$GWP_DIAG" --dir "$GWP" --since',
            "done < <(jq -r 'select(.kind == \"gateway\" and .ip != null) | \"\\(.ns) \\(.ip)\"' \"$GWP_DIAG\" 2>/dev/null | sort -u)",
        )
        for line in self.src.splitlines():
            if "GWP_DIAG" in line and "GWP_DIAG_PENDING" not in line.replace("GWP_DIAG\"", ""):
                self.assertTrue(any(a in line for a in allowed), line)
        self.assertIn("[ -z \"$" + "{GWP_DIAG_PENDING:-}\" ] || gwp_diag_end", shell_function(self.src, "cleanup"))
        self.assertRegex(self.section(), r'cp "\$GWP_OBS" "\$LOGS/gateway-policy-observations.jsonl"\n  gwp_diag_end\n')


if __name__ == "__main__":
    unittest.main()
