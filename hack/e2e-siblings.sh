#!/usr/bin/env bash
# Sourced by e2e.sh; its trap owns every namespace/file made here.
echo "== explicit via-mode namespace peers (ADR 0064)"
ST="$T-siblings"
STREAM_FILES=${STREAM_FILES:-$(mktemp -d)}
cat > "$STREAM_FILES/sibling-proxy.py" <<'PY'
import http.server
class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # A controlled gateway fixture: the caller presents a placeholder; only the gateway
        # owns the replacement. No request leaves this namespace or loads a public service.
        if self.headers.get('X-Fixture-Token') != 'placeholder':
            self.send_error(403)
            return
        replacement = 'gateway-only-fixture'
        body = ('injected=' + str(replacement == 'gateway-only-fixture')).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
http.server.HTTPServer(('0.0.0.0',3128),Proxy).serve_forever()
PY
briqyard namespace gateway set "$ST" --image python:3.12-alpine --memory 128 --port 3128 \
  --file /srv/proxy.py="$STREAM_FILES/sibling-proxy.py" -- python3 /srv/proxy.py >/dev/null
SD=$(briqyard machine run --namespace "$ST" --name database --image postgres:17-alpine \
  --memory 256 -e POSTGRES_PASSWORD=fixture -- postgres -c shared_buffers=16MB | jq -r .id)
SC=$(briqyard machine run --namespace "$ST" --name consumer --image postgres:17-alpine \
  --memory 128 --egress via:gateway+siblings -- sleep 3600 | jq -r .id)
SS=$(briqyard machine run --namespace "$ST" --name strict --image postgres:17-alpine \
  --memory 128 --egress via:gateway -- sleep 3600 | jq -r .id)
SX=$(briqyard machine run --namespace "$ST-other" --name other --image postgres:17-alpine \
  --memory 256 -e POSTGRES_PASSWORD=fixture -- postgres -c shared_buffers=16MB | jq -r .id)
sibling_sql() { briqyard machine exec "$1" -- env PGPASSWORD=fixture PGCONNECT_TIMEOUT=2 psql -h "${2:-database.internal}" -U postgres -tAc 'select 6 * 7'; }
sibling_proxy() { briqyard machine exec "$1" -- wget -qO- -T 3 --header 'X-Fixture-Token: placeholder' http://gateway.internal:3128/check; }
# The database owns readiness; an image's startup time is not a fixed delay in the policy test.
sibling_ready() { for i in $(seq 1 30); do briqyard machine exec "$SD" -- pg_isready -U postgres >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
sibling_ready
check "siblings: real database query" '[ "$(sibling_sql "$SC")" = 42 ]'
check "siblings: selected synthetic gateway still works" '[ "$(sibling_proxy "$SC")" = injected=True ]'
check "siblings: strict default denies database" '! sibling_sql "$SS" >/dev/null 2>&1'
check "siblings: strict default still reaches gateway" '[ "$(sibling_proxy "$SS")" = injected=True ]'
sxip=$(briqyard machine get "$SX" | jq -r .ip)
check "siblings: another namespace is denied" '! sibling_sql "$SC" "$sxip" >/dev/null 2>&1'
check "siblings: explicit server capability" 'briqyard status | jq -e ".egress_siblings_v1 == true" >/dev/null'
briqyard machine set-egress "$SC" via:gateway >/dev/null
check "siblings: live opt-out denies database" '! sibling_sql "$SC" >/dev/null 2>&1'
check "siblings: live opt-out retains gateway" '[ "$(sibling_proxy "$SC")" = injected=True ]'
briqyard machine set-egress "$SC" via:gateway+siblings >/dev/null
check "siblings: live opt-in restores database" '[ "$(sibling_sql "$SC")" = 42 ]'
briqyard machine stop "$SD" >/dev/null
check "siblings: stopped peer is revoked" '! sibling_sql "$SC" >/dev/null 2>&1'
briqyard machine start "$SD" >/dev/null
sibling_ready
check "siblings: restarted peer is admitted" '[ "$(sibling_sql "$SC")" = 42 ]'
if [ -n "$UNIT" ]; then
  handover
  check "siblings: daemon adoption rebuilds membership" '[ "$(sibling_sql "$SC")" = 42 ] && [ "$(sibling_proxy "$SC")" = injected=True ]'
fi
briqyard machine move "$SD" --namespace "$ST-other" >/dev/null
check "siblings: a peer moved out is revoked" '! sibling_sql "$SC" >/dev/null 2>&1'
briqyard machine move "$SD" --namespace "$ST" >/dev/null
sibling_ready
check "siblings: a peer moved back is admitted" '[ "$(sibling_sql "$SC")" = 42 ]'
for id in "$SC" "$SS" "$SD" "$SX"; do briqyard machine rm "$id" >/dev/null; done
briqyard namespace gateway rm "$ST" >/dev/null
