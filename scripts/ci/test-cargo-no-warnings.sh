#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/cargo-no-warnings-probe.XXXXXX")"
trap 'rm -rf "$probe_dir"' EXIT
mkdir -p "$probe_dir/bin" "$probe_dir/target"

cat > "$probe_dir/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$FAKE_CARGO_MODE" in
    warning)
        printf 'warning: deliberate warning probe\n'
        ;;
    cargo-warning)
        printf 'cargo:warning=deliberate build-script warning\n'
        ;;
    future-incompat)
        printf '{"reports":[{"per_package":{"probe@0.1.0":"future warning"}}]}' > "$CARGO_TARGET_DIR/.future-incompat-report.json"
        ;;
    failure)
        printf 'error: deliberate command failure\n' >&2
        exit 42
        ;;
esac
SH
chmod +x "$probe_dir/bin/cargo"

expect_failure() {
    local mode="$1"
    local expected="$2"
    local output status

    set +e
    output="$(PATH="$probe_dir/bin:$PATH" CARGO_TARGET_DIR="$probe_dir/target" FAKE_CARGO_MODE="$mode" bash "$root/scripts/ci/cargo-no-warnings.sh" check 2>&1)"
    status=$?
    set -e

    if ((status == 0)) || ! grep -Fq "$expected" <<<"$output"; then
        printf 'expected %s probe to fail with %s (exit %s):\n%s\n' "$mode" "$expected" "$status" "$output" >&2
        exit 1
    fi
}

expect_failure warning 'Cargo emitted a warning'
expect_failure cargo-warning 'Cargo emitted a warning'
expect_failure future-incompat 'future-incompatibility warnings reported'
expect_failure failure 'deliberate command failure'

printf '{"reports":[{"per_package":{"stale@0.1.0":"old warning"}}]}' > "$probe_dir/target/.future-incompat-report.json"
output="$(PATH="$probe_dir/bin:$PATH" CARGO_TARGET_DIR="$probe_dir/target" FAKE_CARGO_MODE=success bash "$root/scripts/ci/cargo-no-warnings.sh" check 2>&1)"
if grep -Fq 'future-incompatibility warnings reported' <<<"$output"; then
    printf 'stale future-incompatibility report was not cleared:\n%s\n' "$output" >&2
    exit 1
fi

output="$(PATH="$probe_dir/bin:$PATH" CARGO_TARGET_DIR="$probe_dir/target" FAKE_CARGO_MODE=success bash "$root/scripts/ci/cargo-no-warnings.sh" check 2>&1)"
if ! grep -Fq '+ cargo --color never check' <<<"$output"; then
    printf 'warning-free success probe had unexpected output:\n%s\n' "$output" >&2
    exit 1
fi

printf 'Cargo warning gate probes passed\n'
