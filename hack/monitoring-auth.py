#!/usr/bin/env python3
"""Write private curl config files from stdin credentials without exposing them in argv."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


def quote_config(value: str) -> str:
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("control character")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def read_fields() -> tuple[str, str, str]:
    fields = sys.stdin.buffer.read().split(b"\0")
    if len(fields) != 4 or fields[-1] != b"":
        raise ValueError("invalid input framing")
    decoded = [field.decode("utf-8", errors="strict") for field in fields[:-1]]
    return decoded[0], decoded[1], decoded[2]


def write_private(path: Path, contents: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(contents)


def load_password(path_text: str) -> str:
    path = Path(path_text)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unsafe password file")
        data = stream.read()
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data or b"\n" in data or b"\r" in data or b"\0" in data:
        raise ValueError("invalid password framing")
    value = data.decode("utf-8", errors="strict")
    quote_config("admin:" + value)
    return value


def initialize(directory: Path) -> None:
    metrics_token, api_token, password_path = read_fields()
    for token in (metrics_token, api_token):
        quote_config("Authorization: Bearer " + token)
    configs = {
        "metrics.curl": f"header = {quote_config('Authorization: Bearer ' + metrics_token)}\n" if metrics_token else "",
        "api.curl": f"header = {quote_config('Authorization: Bearer ' + api_token)}\n" if api_token else "",
        "grafana.curl": f"user = {quote_config('admin:' + load_password(password_path))}\n" if password_path else "",
    }
    for name, contents in configs.items():
        write_private(directory / name, contents)


def cleanup(directory: Path) -> None:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("unsafe auth directory")
    expected = {"metrics.curl", "api.curl", "grafana.curl"}
    names = set(os.listdir(directory))
    if not names <= expected:
        raise ValueError("unexpected auth directory contents")
    for name in sorted(names):
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unsafe auth config")
        path.unlink()
    directory.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--dir", required=True)
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    try:
        directory = Path(args.dir)
        if args.command == "init":
            initialize(directory)
        else:
            cleanup(directory)
    except (OSError, UnicodeError, ValueError):
        print("monitoring auth: rejected credential input or private-file state", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
