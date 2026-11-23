#!/usr/bin/env bash
# Owner-layer qualification on a disposable Linux host (ADR 0149). Never a shared dev VM,
# never a host serving anything. It runs the native owner suites as root against the real
# kernel, checks the shared golden against B's copy, and checks ordinary-path parity.
#
#   BRIQYARD_DISPOSABLE=1                 required: this host is thrown away after the run
#   OWNER_B_GOLDEN=/path/sealed_owner_v1.golden   B's copy of the golden (optional, compared)
#   OWNER_BASE=origin/main                base the parity check compares against
#
# The live joint phase (R and B reading a running target over their separate SSH identities) is
# listed as NOT RUN: it needs the unit-commitment preimages ADR 0149 leaves open.
set -euo pipefail
[ "${BRIQYARD_DISPOSABLE:-}" = 1 ] || { echo 'owner-qualify.sh needs BRIQYARD_DISPOSABLE=1 on a throwaway host' >&2; exit 2; }
[ "$(uname -s)" = Linux ] || { echo 'owner-qualify.sh is Linux only' >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'owner-qualify.sh must run as root: the owner measures real processes' >&2; exit 2; }
if systemctl is-active --quiet briqyardd.service 2>/dev/null || systemctl is-active --quiet briqyard-fleet.service 2>/dev/null; then
  echo 'a briqyard service is active here: this is not a disposable qualification host' >&2; exit 2
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
BASE=${OWNER_BASE:-origin/main}
GOLDEN=crates/briqyard-api/testdata/owner_v1/sealed_owner_v1.golden
WANT=3e14f6a769042dae6e17fbea5c83ca8ac99d3c6057c5cd7fd5624a577aae9337
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/owner-qualify.XXXXXX")
cleanup() { rm -rf -- "$SCRATCH"; }
trap cleanup EXIT INT TERM HUP
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$SCRATCH/target}
pass=0
step() { echo "== $*"; }
ok() { pass=$((pass + 1)); echo "ok: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step 'golden: the shared bytes'
[ "$(sha256sum "$GOLDEN" | cut -d' ' -f1)" = "$WANT" ] || fail 'native golden differs from the agreed hash'
ok "native golden is $WANT"
if [ -n "${OWNER_B_GOLDEN:-}" ]; then
  cmp -s "$GOLDEN" "$OWNER_B_GOLDEN" || fail "B's golden differs byte for byte"
  ok "B's golden is the same bytes"
else
  echo 'skipped: OWNER_B_GOLDEN not set (B-side bytes not compared)'
fi

step 'wire: records decode, re-encode, verify'
cargo test -p briqyard-api --features execution-admission --lib sealed::tests::owner
ok 'api owner tests'

step 'native: one private attempt, receipts, versions, handoff lineage, negatives (real uid and /proc)'
cargo test -p briqyardd --lib local_owner
ok 'local_owner suite'

step 'ordinary parity: no ordinary-path file differs from the base'
changed=$(git diff --name-only "$BASE"...HEAD -- crates/briqyardd/src | grep -v '/local_owner/' || true)
allowed='crates/briqyardd/src/execution_custody/mod.rs crates/briqyardd/src/execution_custody/plan_reader.rs crates/briqyardd/src/execution_custody/plan_reader/owner.rs'
for f in $changed; do
  case " $allowed " in *" $f "*) ;; *) fail "ordinary file changed: $f" ;; esac
done
ok 'only the three allowed wiring files differ outside local_owner'
cargo test -p briqyardd --lib execution_custody
cargo test -p briqyardd --lib guarded
ok 'ordinary execution_custody and guarded tests'

echo "NOT RUN: live joint B/native read of a running target (R and B over separate read-only SSH identities)"
echo "NOT RUN: one-host exit-75 handover with the enrolled guard (needs the production unit facts)"
echo "$pass checks passed"
