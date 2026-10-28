#!/usr/bin/env bash
set -euo pipefail

exec cargo run --quiet --locked -p test-harness --bin cargo-no-warnings -- "$@"
