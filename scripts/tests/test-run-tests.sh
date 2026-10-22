#!/usr/bin/env bash
# Compatibility command for the Rust fake-Cargo shell-entrypoint contracts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec cargo test --locked --manifest-path "$ROOT/Cargo.toml" -p test-harness --lib shell_entrypoints_ -- --test-threads=1
