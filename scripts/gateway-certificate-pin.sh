#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
  echo "Usage: gateway-certificate-pin.sh GATEWAY_CLIENT_CERT.pem" >&2
  exit 2
fi
cast_binary="${CAST_BIN:-cast}"
certificate_hex="$(openssl x509 -in "$1" -outform DER | xxd -p -c 999999)"
"$cast_binary" keccak "0x${certificate_hex}"
