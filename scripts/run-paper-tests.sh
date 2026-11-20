#!/usr/bin/env bash
# Build and launch the Rust paper campaign runner from this checkout.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export RUSTUP_AUTO_INSTALL=0
exec cargo run --locked --offline -p test-harness --bin test-campaign -- --paper "$@"
