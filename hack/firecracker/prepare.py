"""Verify and apply the complete patch series to a clean pinned checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent

def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()

def prepare(source, artifacts=HERE):
    source = Path(source).resolve()
    pin = json.loads((artifacts / "pin.json").read_text())
    if git(source, "rev-parse", "HEAD") != pin["base"]:
        raise ValueError("upstream revision mismatch")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("upstream checkout must be clean")
    series_bytes = (artifacts / "series").read_bytes()
    if hashlib.sha256(series_bytes).hexdigest() != pin["series_file_sha256"]:
        raise ValueError("series digest mismatch")
    names = series_bytes.decode("ascii").splitlines()
    if names != [item["path"] for item in pin["series"]] or len(set(names)) != len(names):
        raise ValueError("series order mismatch")
    patches = []
    for item in pin["series"]:
        name = item["path"]
        if not re.fullmatch(r"[0-9]{2}-[a-z-]+\.patch", name):
            raise ValueError("invalid patch name")
        data = (artifacts / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("patch digest mismatch")
        patches.append(data)
    if hashlib.sha256(b"".join(patches)).hexdigest() != pin["series_concatenated_sha256"]:
        raise ValueError("aggregate digest mismatch")
    # All digests are checked before the first write. The pair is one logical change.
    paths = [str(artifacts / name) for name in names]
    subprocess.run(["git", "-C", str(source), "apply", "--check", "--index", "--whitespace=error-all", *paths], check=True)
    subprocess.run(["git", "-C", str(source), "apply", "--index", "--whitespace=error-all", *paths], check=True)
    subprocess.run(["git", "-C", str(source), "diff", "--cached", "--check"], check=True)
    if git(source, "write-tree") != pin["tree"]:
        raise ValueError("patched tree mismatch")
    return pin

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    pin = prepare(args.source)
    print(json.dumps({"base": pin["base"], "tree": pin["tree"], "series": "verified"}))
