#!/usr/bin/env bash
# Offered-load campaign entrypoint; execution requires separate approval.
# Rust 客户端按 offered RPS 阶梯测量；未对齐的 SUT 资源轮询不作为容量证据。
# 用法: LOADGEN_HMAC_SECRET=... bash bench_matrix.sh [biz|health|all] [RPS 列表，空格分隔]
# 必填环境变量: LOADGEN_HMAC_SECRET、P99_SLO_MS、ERROR_RATE_SLO。
# HMAC 仅通过环境变量传给 loadgen，不写入 provenance 或命令行。
# 非零 loadgen 测点仍保留 JSON 与 summary；缺失/损坏 artifact 时停止。
# 此脚本不是离线模拟器；调用它会运行 loadgen 并访问 BASE。
# 系统容量仍需批准的 SUT 侧资源、队列采样与独立运行级 CI，不由本脚本声称。
set -euo pipefail

LG=${LG:-$HOME/astral-e2e/loadgen/target/release/loadgen}
BASE=${BASE:-http://127.0.0.1:9005}
OUT=${OUT:-$HOME/astral-e2e/tg-run/real_limit}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_ROOT=$(git -C "$SCRIPT_DIR/../../.." rev-parse --show-toplevel)
DUR=${DUR:-20}
P99_SLO_MS=${P99_SLO_MS:?P99_SLO_MS required}
ERROR_RATE_SLO=${ERROR_RATE_SLO:?ERROR_RATE_SLO required}
LOADGEN_HMAC_SECRET=${LOADGEN_HMAC_SECRET:?LOADGEN_HMAC_SECRET required}
MAX_IN_FLIGHT=${MAX_IN_FLIGHT:-4096}
CONCURRENCY=${CONCURRENCY:-1}
THREADS=${THREADS:-1}
RUN_ID=${RUN_ID:-loadgen-matrix-$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$ ]] || { echo "RUN_ID contains unsupported characters" >&2; exit 2; }
MODE=${1:-all}
BIZ_LIST=${2:-"1 8 32 64 128 256 512"}
[ "$#" -le 2 ] || { echo "unexpected positional arguments" >&2; exit 2; }
case "$MODE" in biz|all|health) ;; *) echo "unknown mode: $MODE" >&2; exit 2 ;; esac
for value_name in DUR P99_SLO_MS ERROR_RATE_SLO; do
  value=${!value_name}
  [[ "$value" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || { echo "$value_name must be numeric" >&2; exit 2; }
done
awk -v value="$DUR" 'BEGIN { exit !(value + 0 > 0) }' || { echo "DUR must be positive" >&2; exit 2; }
awk -v value="$P99_SLO_MS" 'BEGIN { exit !(value + 0 > 0) }' || { echo "P99_SLO_MS must be positive" >&2; exit 2; }
awk -v value="$ERROR_RATE_SLO" 'BEGIN { exit !(value + 0 >= 0 && value + 0 <= 1) }' || { echo "ERROR_RATE_SLO must be between zero and one" >&2; exit 2; }
for value_name in MAX_IN_FLIGHT CONCURRENCY THREADS; do
  value=${!value_name}
  [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ] || { echo "$value_name must be a positive integer" >&2; exit 2; }
done
[ "$MAX_IN_FLIGHT" -le 1000000 ] && [ "$CONCURRENCY" -le 1000000 ] && [ "$THREADS" -le 256 ] || { echo "loadgen concurrency/thread setting exceeds supported bounds" >&2; exit 2; }
BASE_TARGET=$(python3 - "$BASE" <<'PY'
import sys
from urllib.parse import urlsplit
url = urlsplit(sys.argv[1])
if url.scheme not in ("http", "https") or not url.hostname:
    raise SystemExit("BASE must be an http(s) origin")
if url.username is not None or url.password is not None or url.path not in ("", "/") or url.query or url.fragment:
    raise SystemExit("BASE must not contain userinfo, path, query, or fragment")
try:
    url.port
except ValueError as error:
    raise SystemExit(f"BASE contains an invalid port: {error}")
print(f"{url.scheme}://{url.netloc}")
PY
) || { echo "invalid BASE origin" >&2; exit 2; }
read -r -a RATES <<<"$BIZ_LIST"
if [ "$MODE" = biz ] || [ "$MODE" = all ]; then
  [ "${#RATES[@]}" -gt 0 ] || { echo "empty RPS list" >&2; exit 2; }
  for rate in "${RATES[@]}"; do
    [[ "$rate" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || { echo "invalid offered rate: $rate" >&2; exit 2; }
    awk -v rate="$rate" 'BEGIN { exit !(rate + 0 > 0) }' || { echo "offered rate must be positive: $rate" >&2; exit 2; }
  done
fi
mkdir "$OUT"
CSV="$OUT/summary.csv"
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required to identify loadgen" >&2; exit 2; }
loadgen_sha256=$(sha256sum "$LG" | awk '{print $1}')
revision=$(git -C "$REPOSITORY_ROOT" rev-parse HEAD 2>/dev/null || true)
dirty=false
[ -z "$(git -C "$REPOSITORY_ROOT" status --porcelain 2>/dev/null || true)" ] || dirty=true
jq -n \
  --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg host "$(hostname)" --arg loadgen_path "$LG" --arg loadgen_sha256 "$loadgen_sha256" \
  --arg target "$BASE_TARGET" --arg duration "$DUR" --arg run_id "$RUN_ID" \
  --arg p99_slo_ms "$P99_SLO_MS" --arg error_rate_slo "$ERROR_RATE_SLO" \
  --arg revision "$revision" --argjson dirty "$dirty" \
  --argjson max_in_flight "$MAX_IN_FLIGHT" --argjson concurrency "$CONCURRENCY" --argjson threads "$THREADS" \
  '{started_at_utc:$started_at_utc,host:$host,loadgen:{path:$loadgen_path,sha256:$loadgen_sha256},target_scheme_host:$target,duration_s:($duration|tonumber),run_id:$run_id,workload:{mode:"open_loop",max_in_flight:$max_in_flight,concurrency_metadata:$concurrency,tokio_threads:$threads},slo:{p99_ms:($p99_slo_ms|tonumber),error_rate:($error_rate_slo|tonumber)},git:{rev:$revision,dirty:$dirty},credentials_recorded:false}' \
  > "$OUT/provenance.json"
echo "provenance: $OUT/provenance.json"

BIZ_PATH='/main/api/v1/rule-sets/9071/entries'
echo 'label,offered_rps,loadgen_exit,status,success_rps,scheduled,started,missed,dropped,aborted,completed,ok,failures,request_error_rate,cohort_error_rate,cohort_error_ci_lower,cohort_error_ci_upper,p99_ns,p99_ci95_lower_ns,p99_ci95_upper_ns,p99_sample_ci95_relative_half_width,measurement_window_s,drain_ms,client_measurement_in_flight_end,client_in_flight_snapshot_reliable' > "$CSV"

run_point() {
  local label=$1 rate=$2 dur=$3 path=$4
  local stem="${label}_r${rate}"
  local artifact="$OUT/${stem}.json"
  local raw="$OUT/${stem}.stdout"
  local stderr="$OUT/${stem}.stderr"
  local exit_code=0
  [ ! -e "$artifact" ] && [ ! -e "$raw" ] && [ ! -e "$stderr" ] || { echo "artifact exists for $stem" >&2; return 2; }
  if LOADGEN_HMAC_SECRET="$LOADGEN_HMAC_SECRET" "$LG" --url "$BASE" --path "$path" \
    --concurrency "$CONCURRENCY" --rate "$rate" --max-inflight "$MAX_IN_FLIGHT" \
    --threads "$THREADS" --duration "$dur" --warmup 30 --output json \
    --run-id "${RUN_ID}-${stem}" --output-file "$artifact" \
    --p99-slo-ms "$P99_SLO_MS" --error-rate-slo "$ERROR_RATE_SLO" \
    > "$raw" 2> "$stderr"; then
    :
  else
    exit_code=$?
  fi
  [ -s "$artifact" ] || { echo "missing artifact for $stem (loadgen exit $exit_code)" >&2; return 2; }
  jq -e '.schema_version == 2 and (.measurement | type == "object")' "$artifact" >/dev/null \
    || { echo "invalid report artifact for $stem" >&2; return 2; }
  if [ "$exit_code" -ne 0 ]; then
    echo "retaining $stem report from nonzero loadgen exit $exit_code" >&2
  fi
  jq -r --arg label "$label" --arg rate "$rate" --argjson exit_code "$exit_code" '
    .measurement as $m | $m.observed as $o | $m.counters as $c |
    [$label, $rate, $exit_code, $m.status, $o.success_rps, $c.scheduled, $c.started,
     $c.missed, $c.dropped, $c.aborted, $c.completed, $c.ok, $c.failures,
     $o.measurement_cohort_error_rate, ($o.measurement_cohort_error_rate_ci95[0] // null),
     ($o.measurement_cohort_error_rate_ci95[1] // null), $o.p99_ns,
     ($o.p99_ci95_ns[0] // null), ($o.p99_ci95_ns[1] // null),
     $o.p99_sample_ci95_relative_half_width, $o.measurement_window_seconds,
     $o.drain_duration_ms, $c.client_measurement_in_flight_end,
     $m.timing.client_in_flight_snapshot_reliable] | @csv' "$artifact" >> "$CSV"
  echo "done: $stem (loadgen exit $exit_code, status $(jq -r '.measurement.status' "$artifact"))"
  return 0
}

if [ "$MODE" = biz ] || [ "$MODE" = all ]; then
  for rate in "${RATES[@]}"; do
    run_point biz "$rate" "$DUR" "$BIZ_PATH"
  done
fi
if [ "$MODE" = health ] || [ "$MODE" = all ]; then
  echo "[skip] health scenario retired: /api/health is not mounted by trustgraph :9005"
fi

echo "=== summary ==="
cat "$CSV"
