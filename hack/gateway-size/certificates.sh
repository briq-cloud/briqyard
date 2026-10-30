#!/usr/bin/env bash
# Synthetic certificates for the isolated benchmark; never commit the keys.
set -euo pipefail
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-key.pem -out ca.pem -days 2 -subj /CN=benchmark-ca
openssl req -newkey rsa:2048 -nodes -keyout key.pem -out server.csr -subj /CN=bench.internal
cat > extensions <<'EOF'
subjectAltName=DNS:bench.internal
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -days 2 -extfile extensions
rm server.csr extensions ca.srl
