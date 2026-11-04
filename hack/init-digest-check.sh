#!/usr/bin/env bash
# The init's digest changes only when the init does (ADR 0098): build the musl init twice, the
# second time as another release and another commit, and fail if its SHA-256 differs.
#   hack/init-digest-check.sh            # x86_64-unknown-linux-musl, as the release builds it
#   TARGET=aarch64-unknown-linux-musl hack/init-digest-check.sh
# Edits the workspace version in Cargo.toml and Cargo.lock for the second build and restores
# both on exit; needs them unmodified.
set -euo pipefail
cd "$(dirname "$0")/.."
target=${TARGET:-x86_64-unknown-linux-musl}
git diff --quiet -- Cargo.toml Cargo.lock || { echo "Cargo.toml or Cargo.lock has changes" >&2; exit 2; }
trap 'git checkout -q -- Cargo.toml Cargo.lock' EXIT

sha() { # <commit> -> the digest of the init built as that commit
  BRIQYARD_COMMIT=$1 cargo build --release --locked -p briqyard-init --target "$target" >&2
  shasum -a 256 "target/$target/release/briqyard-init" | cut -d' ' -f1
}

old=$(python3 - <<'PY'
import tomllib
print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])
PY
)
new=$old-digest-check
a=$(sha 000000000000)

python3 - "$old" "$new" <<'PY'
import sys
sys.path.insert(0, "hack")
import release
from pathlib import Path
old, new = sys.argv[1:]
_, names = release.workspace()
Path("Cargo.lock").write_text(release.lock_update(Path("Cargo.lock").read_text(), names, old, new))
Path("Cargo.toml").write_text(Path("Cargo.toml").read_text().replace(f'version = "{old}"', f'version = "{new}"', 1))
PY
b=$(sha ffffffffffff)

echo "release $old, commit 000000000000: $a"
echo "release $new, commit ffffffffffff: $b"
[ "$a" = "$b" ] || { echo "the init's digest follows the release or the commit (ADR 0098)" >&2; exit 1; }
echo "same digest"
