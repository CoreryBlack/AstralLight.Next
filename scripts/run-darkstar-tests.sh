#!/usr/bin/env bash
# Build and launch the unified Rust DarkStar campaign from this checkout.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
umask 077
export RUSTUP_AUTO_INSTALL=0
exec cargo run --locked --offline -p test-harness --bin test-campaign -- --darkstar "$@"
