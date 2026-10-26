#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
    printf 'usage: %s <cargo-subcommand> [arguments...]\n' "$0" >&2
    exit 2
fi

log_file="$(mktemp "${TMPDIR:-/tmp}/cargo-no-warnings.XXXXXX")"
trap 'rm -f "$log_file"' EXIT

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
    target_dir="$PWD/$target_dir"
fi
mkdir -p "$target_dir"
rm -f "$target_dir/.future-incompat-report.json"

printf '+ cargo --color never'
printf ' %q' "$@"
printf '\n'

set +e
cargo --color never "$@" 2>&1 | tee "$log_file"
statuses=("${PIPESTATUS[@]}")
set -e

cargo_status="${statuses[0]}"
tee_status="${statuses[1]}"

if grep -Eiq '(^|[[:space:]])warning(\[[^]]+\])?:|cargo:warning=' "$log_file"; then
    printf 'error: Cargo emitted a warning; this CI gate requires zero warnings.\n' >&2
    exit 1
fi

if [[ -f "$target_dir/.future-incompat-report.json" ]]; then
    if ! python3 - "$target_dir/.future-incompat-report.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report_file:
    report = json.load(report_file)

packages = {
    package
    for item in report.get("reports", [])
    for package in item.get("per_package", {})
}
if packages:
    print("error: future-incompatibility warnings reported for: " + ", ".join(sorted(packages)))
    sys.exit(1)
PY
    then
        exit 1
    fi
fi

if ((cargo_status != 0)); then
    exit "$cargo_status"
fi

if ((tee_status != 0)); then
    printf 'error: failed to capture the complete Cargo output.\n' >&2
    exit "$tee_status"
fi
