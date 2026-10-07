#!/usr/bin/env bash
# MySQL tenant suites by default; Redis compatibility is an explicit opt-in.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."
PROFILE=default
SUITES=(mt_extreme_isolation mt_extreme_churn mt_extreme_cross_storm mt_extreme_failclosed mt_extreme_capacity)
while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile) [ "$#" -ge 2 ] || exit 2; PROFILE="$2"; shift 2 ;;
        --suites) [ "$#" -ge 2 ] || exit 2; read -r -a SUITES <<<"$2"; shift 2 ;;
        *) printf '[error] unknown matrix argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ "${#SUITES[@]}" -gt 0 ] || { printf '[error] no suites selected\n' >&2; exit 2; }
for suite in "${SUITES[@]}"; do
    case "$suite" in mt_extreme_isolation|mt_extreme_churn|mt_extreme_cross_storm|mt_extreme_failclosed|mt_extreme_capacity) ;;
        *) printf '[error] unknown suite: %s\n' "$suite" >&2; exit 2 ;;
    esac
done
: "${DATABASE_URL:?DATABASE_URL is required}"
[ "${ASTRAL_MIGRATION_ENV:-}" = isolated ] || exit 2
[ "${RUST_INTEGRATION_REQUIRED:-}" = 1 ] || exit 2
FEATURES=()
case "$PROFILE" in
    default) unset REDIS_URL; export ASTRAL_REDIS_PROJECTION_COMPAT=false ;;
    redis-compat) : "${REDIS_URL:?explicit compatibility profile requires REDIS_URL}"; export ASTRAL_REDIS_PROJECTION_COMPAT=true; FEATURES=(--features redis-compat) ;;
    *) printf '[error] unknown profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac
export ASTRAL_MESSAGE_TRANSPORT=local
printf '[matrix] profile=%s suites=%s\n' "$PROFILE" "${SUITES[*]}"
FAILED=0
for suite in "${SUITES[@]}"; do
    if ! cargo test -p testsuite "${FEATURES[@]}" --test "$suite" -- --ignored --nocapture --test-threads=1; then
        FAILED=1
    fi
done
exit "$FAILED"
