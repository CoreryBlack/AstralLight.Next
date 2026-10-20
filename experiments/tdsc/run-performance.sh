#!/usr/bin/env bash
set -euo pipefail

# Compatibility entrypoint for the standard-library Python performance driver.
# The driver is executed inside the in-network protocol-runner container and
# writes only non-sensitive performance evidence below /evidence.
#
# TDSC_PERF_CONCURRENCIES defaults to 1,4,8,16,32. TDSC_PERF_REPS defaults to
# 5. TDSC_PERF_WARMUP and TDSC_PERF_SAMPLES are requests per worker for each
# independent (concurrency, replicate) workload. Summary metrics use replicate
# observations, not raw requests. It does not estimate external client latency,
# host resource saturation, or fault-injection availability behavior.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER_PATH="${TDSC_PERF_DRIVER_PATH:-${SCRIPT_DIR}/run-performance.py}"
exec python3 "${DRIVER_PATH}"
