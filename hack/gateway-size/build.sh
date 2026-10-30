#!/usr/bin/env bash
# A disposable measurement image, never a production gateway image.
set -euo pipefail
[ $# = 1 ] || { echo 'usage: build.sh PATH_TO_GATEWAY_SOURCE' >&2; exit 2; }
gateway=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT INT TERM HUP
cp "$gateway/Cargo.toml" "$gateway/Cargo.lock" "$here/Dockerfile" "$context/"
cp -R "$gateway/src" "$gateway/examples" "$context/"
python3 - "$context/src/main.rs" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
assert 'BENCH_UPSTREAM_CA' not in s
assert s.count('    let gateway = Gateway::new(')==1
s=s.replace('let opts = match body_options','let mut opts = match body_options')
s=s.replace('    let gateway = Gateway::new(','''    if let Some(path) = env("BENCH_UPSTREAM_CA") {
        opts.upstream_ca = pem::parse_many(std::fs::read(path).unwrap()).unwrap()
            .into_iter().map(|p| p.into_contents().into()).collect();
    }
    let gateway = Gateway::new(''')
open(p,'w').write(s)
PY
docker build -t credential-gateway:system-size-bench "$context"
