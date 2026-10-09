#!/usr/bin/env bash
# Wrapper contracts execute temporary stubs only, never services or migrations.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
            PYTHON_BIN="$candidate"
            break
        fi
    done
fi
if [ -z "$PYTHON_BIN" ]; then
    printf '[BLOCKED] a working Python interpreter is required for runner contracts\n' >&2
    exit 2
fi
"$PYTHON_BIN" -B -m unittest discover -s scripts/tests -p test_entrypoints.py
printf 'runner contracts: entrypoints passed\n'
