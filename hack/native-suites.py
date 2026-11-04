#!/usr/bin/env python3
"""The suites of the `more-suites` matrix in .github/workflows/native.yml to run (ADR 0110).

Changed paths on stdin, one per line; prints the JSON list of suites. `--all` prints every
suite, for a run with no diff to read. `monitoring` and `alerts` run only when a path they
read changed, or when nothing says what changed. Every other suite always runs.
"""

import argparse
import json
import sys

# The matrix order of native.yml.
SUITES = ["stress", "monitoring", "alerts", "qualification", "restore", "scale"]
SELECTED = ("monitoring", "alerts")

# What the two suites read, beyond the build they share with the others.
WATCHED_PATHS = {
    "Cargo.toml",  # a release changes it (and Cargo.lock): the release PR runs everything
    "Cargo.lock",
    ".github/workflows/native.yml",
    "hack/native-suites.py",
    "hack/native-ci.sh",
    "hack/native-ci-more.sh",
    "hack/install-monitoring.sh",
    "hack/render-alerting.sh",
    "crates/briqyardd/src/metrics.rs",  # the host's series, with metrics/ below
    "crates/briqyard-fleet/src/signals.rs",  # the fleet's series
    "crates/briqyard-fleet/src/scrape.rs",  # what Prometheus scrapes
}
WATCHED_PREFIXES = (
    "hack/monitoring/",  # dashboards, alert rules, fixtures
    "hack/monitoring-",  # the check scripts
    "crates/briqyardd/src/metrics/",  # the warm pool, copies and backup series
)


def watched(path: str) -> bool:
    return path in WATCHED_PATHS or path.startswith(WATCHED_PREFIXES)


def select(paths: list[str]) -> list[str]:
    if not paths or any(watched(p) for p in paths):
        return SUITES
    return [s for s in SUITES if s not in SELECTED]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--all", action="store_true", help="print every suite; read no input")
    args = parser.parse_args()
    if args.all:
        suites = SUITES
    else:
        suites = select([line.strip() for line in sys.stdin if line.strip()])
    print(json.dumps(suites))
    return 0


if __name__ == "__main__":
    sys.exit(main())
