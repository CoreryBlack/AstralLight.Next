#!/usr/bin/env bash
set -euo pipefail

exec cargo test --locked -p test-harness --bin cargo-no-warnings "$@"
