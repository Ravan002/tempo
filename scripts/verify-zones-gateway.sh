#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ZONES_GATEWAY_TEST_DATABASE_URL:?Set a disposable PostgreSQL database URL}"
export ZONES_GATEWAY_TEST_DELIVERY_KEY=0707070707070707070707070707070707070707070707070707070707070707
rg --files crates/zones/auth crates/zones/gateway bin/zones-gateway -g '*.rs' |
  xargs rustfmt +nightly --edition 2024 --check
cargo test -p zone-auth -p zone-gateway
cargo clippy -p zone-auth -p zone-gateway -p zones-gateway --all-targets -- -D warnings
cargo run -p zones-gateway -- --help
