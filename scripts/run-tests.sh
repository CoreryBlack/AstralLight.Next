#!/usr/bin/env bash
# Compatibility aliases only; every collection is owned by the manifest runner.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:---all}"
if [ "$#" -gt 0 ]; then shift; fi
case "$MODE" in
    --all) ARGS=(--run --verify-items) ;;
    --full) ARGS=(--run --verify-items --all-profiles) ;;
    --campaign) ARGS=() ;;
    --list-series) ARGS=(--list) ;;
    unit|--unit) ARGS=(--run --profile native-kernel) ;;
    --check) ARGS=(--run --suite workspace-fmt --suite workspace-check --suite workspace-clippy) ;;
    --integration) ARGS=(--run --profile native-single-node) ;;
    --rabbit) ARGS=(--run --profile standalone-rabbit) ;;
    --identity-mapping) ARGS=(--run --suite dedicated-identity-mapping) ;;
    --mt-extreme) ARGS=(--run --profile native-single-node --suite mt-isolation --suite mt-churn --suite mt-cross-storm --suite mt-failclosed --suite mt-capacity) ;;
    --mt-matrix) exec bash "$SCRIPT_DIR/../tests-suite/matrix/run-mt-matrix.sh" "$@" ;;
    --bench) ARGS=(--run --profile performance-kernel) ;;
    *) printf '[BLOCKED] unknown test mode: %s\n' "$MODE" >&2; exit 2 ;;
esac
if [ "${#ARGS[@]}" -gt 0 ]; then
    exec cargo run --quiet --locked --manifest-path "$SCRIPT_DIR/../Cargo.toml" -p test-harness --bin test-campaign -- "${ARGS[@]}" "$@"
else
    exec cargo run --quiet --locked --manifest-path "$SCRIPT_DIR/../Cargo.toml" -p test-harness --bin test-campaign -- "$@"
fi
