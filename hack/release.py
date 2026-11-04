#!/usr/bin/env python3
"""Prepare a version PR locally, or extract its reviewed release notes."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tomllib


VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def workspace():
    manifest = tomllib.loads(Path("Cargo.toml").read_text())
    names = set()
    for member in manifest["workspace"]["members"]:
        package = tomllib.loads(Path(member, "Cargo.toml").read_text())["package"]
        # The init's crates keep their own version, so the init's bytes do not follow the
        # release (ADR 0101).
        if package["version"] == {"workspace": True}:
            names.add(package["name"])
    return manifest["workspace"]["package"]["version"], names


def notes(text, version):
    if not VERSION.fullmatch(version):
        raise ValueError("expected a stable semantic version")
    version = version.removeprefix("v")
    sections = re.split(r"(?m)^(## .*)$", text)
    matches = []
    for heading, body in zip(sections[1::2], sections[2::2]):
        if re.match(rf"## v?{re.escape(version)}(?:\s|$)", heading):
            if not re.search(r"(?m)^[-*] \S", body):
                raise ValueError(f"empty changelog entry for {version}")
            matches.append(heading + body.rstrip() + "\n")
    if len(matches) != 1:
        raise ValueError(f"expected one changelog entry for {version}")
    return matches[0]


def lock_update(text, names, old, new):
    def update(match):
        block = match.group(0)
        package = tomllib.loads(block)["package"][0]
        if package["name"] in names and "source" not in package:
            if package["version"] != old:
                raise ValueError(f"inconsistent lock version for {package['name']}")
            return block.replace(f'version = "{old}"', f'version = "{new}"', 1)
        return block
    return re.sub(r"(?ms)^\[\[package\]\].*?(?=^\[\[package\]\]|\Z)", update, text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "notes", "check"])
    parser.add_argument("version", nargs="?")
    args = parser.parse_args()
    old, names = workspace()
    changelog = Path("CHANGELOG.md").read_text()
    if args.command != "prepare":
        if args.command == "check":
            args.version = old
        if args.version is None or args.version.removeprefix("v") != old:
            raise ValueError("release tag must match the workspace version")
        for path in ("Cargo.lock", "fuzz/Cargo.lock"):
            lock_update(Path(path).read_text(), names, old, old)
        print(notes(changelog, args.version), end="")
        return
    if args.version:
        parser.error("prepare calculates the version from Conventional Commits")
    if run("git", "status", "--porcelain"):
        raise ValueError("prepare requires a clean worktree")
    branch = run("git", "branch", "--show-current")
    if not branch or branch in ("main", "master"):
        raise ValueError("prepare requires a release task branch")
    if run("git", "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*") != f"v{old}":
        raise ValueError("fetch tags; latest reachable release must match the workspace")
    new = run("git-cliff", "--bumped-version", "--unreleased", "--use-branch-tags")
    if not VERSION.fullmatch(new):
        raise ValueError("git-cliff did not propose a stable version")
    new = new.removeprefix("v")
    if tuple(map(int, new.split("."))) <= tuple(map(int, old.split("."))):
        raise ValueError("no version increase proposed")
    entry = run("git-cliff", "--unreleased", "--use-branch-tags", "--tag", f"v{new}",
                "--strip", "header")
    notes(entry, new)
    updates = {
        path: lock_update(Path(path).read_text(), names, old, new)
        for path in ("Cargo.lock", "fuzz/Cargo.lock")
    }
    manifest = Path("Cargo.toml").read_text()
    updates["Cargo.toml"] = manifest.replace(f'version = "{old}"', f'version = "{new}"', 1)
    updates["CHANGELOG.md"] = "# Changelog\n\n" + entry + "\n\n" + changelog.removeprefix("# Changelog\n\n")
    for path, content in updates.items():
        Path(path).write_text(content)
    print(f"Prepared v{new}; review and commit Cargo.toml, both lockfiles and CHANGELOG.md.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
