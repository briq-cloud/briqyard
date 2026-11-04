import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("alerts", Path(__file__).with_name("monitoring-alerts-check.py"))
alerts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(alerts)


class TestConfig(unittest.TestCase):
    def test_only_the_declared_timings_differ(self):
        prod = alerts.production_rules()
        test = alerts.test_overrides(prod)
        for g, tg in zip(prod["groups"], test["groups"]):
            self.assertEqual(tg["interval"], alerts.EVALUATION_INTERVAL)
            for r, tr in zip(g["rules"], tg["rules"]):
                want = dict(r)
                if r["uid"] in alerts.FOR_OVERRIDES:
                    want["for"] = alerts.FOR_OVERRIDES[r["uid"]]
                self.assertEqual(tr, want, r["uid"])
        self.assertEqual(test["contactPoints"], prod["contactPoints"])

    def test_slack_message(self):
        doc = {"attachments": [{"title": "[FIRING:1] Not answering briqyard (local)", "text":
               "**Firing**\n\nValue: A=0\nLabels:\n - alertname = Not answering\n - instance = local\n - region = \nAnnotations:\n - summary = x\n"
               "\n**Resolved**\n\nValue: A=1\nLabels:\n - alertname = Not answering\n - instance = other\n"}]}
        got = alerts.parse_slack(doc)
        self.assertEqual([a["status"] for a in got], ["firing", "resolved"])
        self.assertEqual(got[0]["labels"], {"alertname": "Not answering", "instance": "local", "region": ""})
        self.assertEqual(got[1]["labels"]["instance"], "other")

    def test_episodes(self):
        self.assertEqual(alerts.episodes(["firing", "firing", "resolved"]), (1, 1))
        self.assertEqual(alerts.episodes(["firing", "resolved", "firing", "firing", "resolved"]), (2, 2))

    def test_threshold_is_substituted_as_a_number(self):
        prod = alerts.production_rules()
        rule = next(r for g in prod["groups"] for r in g["rules"] if r["uid"] == "briqyard-slots-small")
        cond = next(d for d in rule["data"] if d["refId"] == "C")["model"]["conditions"][0]["evaluator"]
        self.assertEqual(cond["params"], [alerts.LARGEST_SLOT_MB])

    def test_every_rule_has_a_case_or_a_reason(self):
        covered = {"briqyard-not-answering", "briqyard-host-condition", "briqyard-crash-loop", "briqyard-backup-failed",
                   "briqyard-out-of-room", "briqyard-host-pressure", "briqyard-slots-small"}
        uncovered = {"briqyard-pool-full"}  # ADR 0094: a pool over 80 % needs tens of GB of disk
        uids = {r["uid"] for g in alerts.production_rules()["groups"] for r in g["rules"]}
        self.assertEqual(uids, covered | uncovered)

    def test_seconds(self):
        self.assertEqual(alerts.seconds("2m"), 120)
        self.assertEqual(alerts.seconds("1m30s"), 90)
        self.assertEqual(alerts.seconds(0), 0)
        self.assertEqual(alerts.seconds(120_000_000_000), 120)


if __name__ == "__main__":
    unittest.main()
