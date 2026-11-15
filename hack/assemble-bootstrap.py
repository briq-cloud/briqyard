#!/usr/bin/env python3
"""Assemble the checked-in standalone bootstrap from its ordered source fragments."""
import argparse
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARTS = ("host.sh", "runtime.sh", "install.sh")


def assemble():
    return b"\n".join((HERE / "bootstrap" / name).read_bytes() for name in PARTS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a stale standalone script")
    args = parser.parse_args()
    output = HERE / "bootstrap-host.sh"
    script = assemble()
    if args.check:
        if output.read_bytes() != script:
            parser.exit(1, "bootstrap-host.sh is stale; run python3 hack/assemble-bootstrap.py\n")
    else:
        output.write_bytes(script)


if __name__ == "__main__":
    main()
