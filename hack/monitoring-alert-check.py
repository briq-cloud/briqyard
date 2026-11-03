#!/usr/bin/env python3
"""Bind synthetic promtool fixtures to Grafana rules; optionally execute promtool."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "hack/monitoring/alert-tests.yaml"
SOURCE = ROOT / "hack/monitoring/grafana/alerting.yaml"
UIDS = {"briqyard-out-of-room", "briqyard-backup-failed"}


def check_binding(source, fixture):
    rules = {rule["uid"]: rule for group in source["groups"] for rule in group["rules"]}
    covered = set()
    count = 0
    for test in fixture["tests"]:
        uid = test["name"].split(":", 1)[0]
        if uid not in UIDS:
            raise ValueError(f"unexpected fixture rule: {uid}")
        rule = rules[uid]
        data = {item["refId"]: item["model"] for item in rule["data"]}
        evaluator = data["C"]["conditions"][0]["evaluator"]
        if (rule["condition"] != "C" or data["C"]["type"] != "threshold"
                or data["C"]["expression"] != "A" or not data["A"]["instant"]
                or len(data["C"]["conditions"]) != 1
                or evaluator != {"type": "gt", "params": [0]}
                or rule["for"] != "0s" or rule["noDataState"] != "OK"
                or rule["execErrState"] != "Error"):
            raise ValueError(f"review changed Grafana evaluation policy: {uid}")
        expected = f'({data["A"]["expr"]}) > bool {evaluator["params"][0]}'
        for query in test["promql_expr_test"]:
            if query["expr"] != expected:
                raise ValueError(f"fixture expression/threshold differs from Grafana: {test['name']}")
            count += 1
        covered.add(uid)
    if covered != UIDS:
        raise ValueError("fixtures must cover both operational alert rules")
    return count


def main():
    import yaml  # python3-yaml, also used by the existing packaging checks in CI.

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-source", action="store_true")
    mode.add_argument("--promtool", type=Path, help="explicit, already-verified executable")
    args = parser.parse_args()
    count = check_binding(yaml.safe_load(SOURCE.read_text()), yaml.safe_load(FIXTURE.read_text()))
    print(f"Grafana source binding: {count} expression expectations", flush=True)
    if args.promtool:
        executable = args.promtool.resolve(strict=True)
        subprocess.run([str(executable), "test", "rules", str(FIXTURE)], check=True)


if __name__ == "__main__":
    main()
