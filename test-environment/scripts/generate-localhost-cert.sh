#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"
CERT_FILE="${CERT_DIR}/localhost.crt"
KEY_FILE="${CERT_DIR}/localhost.key"
OPENSSL_CONFIG="${CERT_DIR}/localhost-openssl.cnf"

mkdir -p "${CERT_DIR}"

cat > "${OPENSSL_CONFIG}" <<'EOF'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[ dn ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -config "${OPENSSL_CONFIG}"

cat <<EOF
Generated certificate:
  ${CERT_FILE}

Generated key:
  ${KEY_FILE}

Use them with Keycloak HTTPS on https://localhost:8443
EOF
