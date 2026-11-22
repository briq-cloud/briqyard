#!/usr/bin/env bash
# Runs both standalone conformance consumers against testdata/sealed_v3_1/vectors.json.
# Needs Node >= 22.18 (built-in TypeScript stripping) and Python 3 with `cryptography`.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "$here/conformance.ts"
python3 -I "$here/conformance.py"
