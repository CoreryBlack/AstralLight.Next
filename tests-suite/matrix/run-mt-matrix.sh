#!/usr/bin/env bash
# Tenant matrix selection only; isolation, evidence and fail-fast live in one runner.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE=native-single-node
SUITES=(mt_extreme_isolation mt_extreme_churn mt_extreme_cross_storm mt_extreme_failclosed mt_extreme_capacity)
EXTRA=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile)
            [ "$#" -ge 2 ] || exit 2
            case "$2" in
                default|native-single-node) PROFILE=native-single-node ;;
                redis-compat)
                    printf '[BLOCKED] tenant matrix uses the native MySQL path; Redis has a dedicated compatibility suite\n' >&2
                    exit 2
                    ;;
                *) printf '[BLOCKED] unknown matrix profile: %s\n' "$2" >&2; exit 2 ;;
            esac
            shift 2
            ;;
        --suites) [ "$#" -ge 2 ] || exit 2; read -r -a SUITES <<<"$2"; shift 2 ;;
        --run-id|--artifact-root) [ "$#" -ge 2 ] || exit 2; EXTRA+=("$1" "$2"); shift 2 ;;
        *) printf '[BLOCKED] unknown matrix argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ "${#SUITES[@]}" -gt 0 ] || { printf '[BLOCKED] no suites selected\n' >&2; exit 2; }
ARGS=(--run --profile "$PROFILE")
for suite in "${SUITES[@]}"; do
    case "$suite" in
        mt_extreme_isolation) ARGS+=(--suite mt-isolation) ;;
        mt_extreme_churn) ARGS+=(--suite mt-churn) ;;
        mt_extreme_cross_storm) ARGS+=(--suite mt-cross-storm) ;;
        mt_extreme_failclosed) ARGS+=(--suite mt-failclosed) ;;
        mt_extreme_capacity) ARGS+=(--suite mt-capacity) ;;
        *) printf '[BLOCKED] unknown suite: %s\n' "$suite" >&2; exit 2 ;;
    esac
done
command -v python >/dev/null 2>&1 || { printf '[BLOCKED] Python 3.11+ is required\n' >&2; exit 2; }
exec python -B "$SCRIPT_DIR/../../scripts/test_campaign.py" "${ARGS[@]}" "${EXTRA[@]}"
