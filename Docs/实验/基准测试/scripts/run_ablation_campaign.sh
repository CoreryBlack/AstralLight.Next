#!/usr/bin/env bash
#
# 架构消融 campaign（专用环境，允许 destructive cleanup）
#
# 协议：RQ4-A cache-failure（nativeRq1Default，3000 迭代），对比：
#   baseline           —— 默认（共享 rule set + snapshot 读路径）
#   force-runtime-eval —— -Dbenchmark.ablation.force-runtime-eval=true
#                          （checkRuleSetEffect 改为源表直读，跳过快照路径）
#   per-card-rule-sets —— -Dbenchmark.ablation.per-card-rule-sets=true
#                          （每卡独立 rule set，关闭模板级共享）
#
# skipProjectionGate / skipGenerationFence 不做数值消融：benchmark 数据不写
# authorization_projection_head（adapter 返回 legacyCompatible，门本就放行），
# 关闭后行为不变，无法测出差异——如实报告而不伪造。
#
# 环境要求与 run_native_campaign.sh 一致；仅对专用容器执行 destructive cleanup。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASTRA_DIR="${REPO_DIR}/evaluation/benchmark-java"
JAR_PATH="${ASTRA_DIR}/target/AstralBenchmark-0.0.1-SNAPSHOT.jar"

ABLATION="baseline"
REPLICATES=3
CAMPAIGN_DIR=""
FIXED_CLOCK="2026-01-01T00:00:00Z"

usage() {
    cat <<EOF
Usage: $0 --ablation baseline|force-runtime-eval|per-card-rule-sets
       [--replicates N] [--campaign-dir DIR] [--fixed-clock TS]

Runs the RQ4-A cache-failure benchmark under one ablation configuration with
N fresh-state replicates on the dedicated host.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ablation) ABLATION="$2"; shift 2 ;;
        --replicates) REPLICATES="$2"; shift 2 ;;
        --campaign-dir) CAMPAIGN_DIR="$2"; shift 2 ;;
        --fixed-clock) FIXED_CLOCK="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
done

case "$ABLATION" in
    baseline) ABLATION_PROP=() ;;
    force-runtime-eval) ABLATION_PROP=(-Dbenchmark.ablation.force-runtime-eval=true) ;;
    per-card-rule-sets) ABLATION_PROP=(-Dbenchmark.ablation.per-card-rule-sets=true) ;;
    *)
        printf 'Unsupported ablation: %s (use baseline, force-runtime-eval, or per-card-rule-sets)\n' "$ABLATION" >&2
        exit 2
        ;;
esac

: "${BENCH_JWT_SECRET:?BENCH_JWT_SECRET is required}"
: "${DB_PASSWORD:?DB_PASSWORD is required for the dedicated benchmark database}"
: "${DB_HOST:?DB_HOST must identify the dedicated benchmark database}"
: "${DB_PORT:?DB_PORT must identify the dedicated benchmark database}"
: "${DB_NAME:?DB_NAME must identify the dedicated benchmark database}"
: "${REDIS_HOST:?REDIS_HOST must identify the dedicated benchmark Redis}"
: "${REDIS_PORT:?REDIS_PORT must identify the dedicated benchmark Redis}"
: "${BENCHMARK_ENV_ID:?BENCHMARK_ENV_ID must identify the dedicated benchmark environment}"

if [[ "${BENCHMARK_DESTRUCTIVE_CLEANUP_APPROVED:-}" != "true" ]]; then
    printf 'Set BENCHMARK_DESTRUCTIVE_CLEANUP_APPROVED=true only after confirming the DB/Redis targets are dedicated.\n' >&2
    exit 1
fi

if [[ ! -f "$JAR_PATH" ]]; then
    printf 'Benchmark JAR not found: %s\nBuild it before starting a campaign.\n' "$JAR_PATH" >&2
    exit 1
fi
if ! [[ "$REPLICATES" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Replicates must be a positive integer: %s\n' "$REPLICATES" >&2
    exit 2
fi

if [[ -z "$CAMPAIGN_DIR" ]]; then
    CAMPAIGN_DIR="$REPO_DIR/Docs/实验/复现运行/ablation-${ABLATION}-$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [[ "$CAMPAIGN_DIR" != /* ]]; then
    CAMPAIGN_DIR="$REPO_DIR/$CAMPAIGN_DIR"
fi
CAMPAIGN_DIR="$(cd "$(dirname "$CAMPAIGN_DIR")" && pwd)/$(basename "$CAMPAIGN_DIR")"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        openssl dgst -sha256 "$1" | sed 's/^.*= //'
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

printf 'Ablation=%s campaign dir: %s\n' "$ABLATION" "$CAMPAIGN_DIR"
mkdir -p "$CAMPAIGN_DIR/$ABLATION"

for rep in $(seq 1 "$REPLICATES"); do
    attempt=1
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    run_id="ablation-${ABLATION}-rep$(printf '%03d' "$rep")-attempt$(printf '%03d' "$attempt")-${timestamp}-$$"
    attempt_dir="$CAMPAIGN_DIR/$ABLATION/rep-$(printf '%03d' "$rep")__attempt-$(printf '%03d' "$attempt")__${timestamp}__${run_id##*-}"
    mkdir -p "$attempt_dir/logs" "$attempt_dir/raw/native-output" "$attempt_dir/derived" "$attempt_dir/environment"
    start_epoch="$(date +%s)"
    start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat > "$attempt_dir/manifest.json" <<EOF
{
  "formatVersion": 1,
  "campaignProtocol": "ablation-$ABLATION",
  "ablation": "$ABLATION",
  "replicate": $rep,
  "attempt": $attempt,
  "runId": "$(json_escape "$run_id")",
  "startedAtUtc": "$(json_escape "$start_utc")",
  "jarSha256": "$(json_escape "$(sha256_file "$JAR_PATH")")",
  "javaVersion": "$(json_escape "$(java -version 2>&1 | head -1)")",
  "seed": 42,
  "fixedBenchmarkClock": "$(json_escape "$FIXED_CLOCK")",
  "benchmarkType": "native",
  "nativeAutoRun": true,
  "destructiveCleanupApproved": true,
  "secretConfigured": true,
  "benchmarkEnvironmentId": "$(json_escape "$BENCHMARK_ENV_ID")",
  "ablationProperties": [$(
      for p in "${ABLATION_PROP[@]}"; do printf '"%s"' "$(json_escape "$p")"; done
  )],
  "arguments": ["--only-rq4", "--start-from-rq4=A", "--skip-decision-performance"]
}
EOF
    {
        printf 'campaign=%s\nprotocol=ablation-%s\nreplicate=%s\nattempt=%s\nrun_id=%s\n' "$CAMPAIGN_DIR" "$ABLATION" "$rep" "$attempt" "$run_id"
        printf 'db_host_configured=true\ndb_port_configured=true\ndb_name_configured=true\nredis_host_configured=true\nredis_port_configured=true\n'
        printf 'benchmark_environment_id=%s\nablation=%s\n' "$BENCHMARK_ENV_ID" "$ABLATION"
        printf 'bench_jwt_secret_configured=true\ndb_password_configured=true\n'
    } > "$attempt_dir/environment/connection-metadata.txt"
    cp "$attempt_dir/manifest.json" "$attempt_dir/environment/manifest-copy.json"

    printf '[%s] Starting ablation %s replicate %s/%s in %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ABLATION" "$rep" "$REPLICATES" "$attempt_dir" \
        | tee "$attempt_dir/logs/runner.log"

    benchmark_output="$attempt_dir/raw/native-output"
    cd "$ASTRA_DIR"
    set +e
    java -Xms4G -Xmx8G -XX:+UseZGC -XX:+ZGenerational \
        -Dbenchmark.type=native \
        -Dbenchmark.native.auto-run=true \
        -Dbenchmark.allow-destructive-cleanup=true \
        -Dbenchmark.fixed-clock="$FIXED_CLOCK" \
        -Dbenchmark.output-dir="$benchmark_output" \
        "${ABLATION_PROP[@]}" \
        -jar "$JAR_PATH" \
        --spring.profiles.active=benchmark \
        --only-rq4 --start-from-rq4=A --skip-decision-performance \
        > "$attempt_dir/logs/benchmark.log" 2>&1
    rc=$?
    set -e
    end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    duration=$(( $(date +%s) - start_epoch ))
    printf '[%s] Benchmark exit code=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" | tee -a "$attempt_dir/logs/runner.log"

    completed=false
    if [[ -f "$benchmark_output/COMPLETED" ]]; then
        completed=true
    fi
    if [[ "$rc" -eq 0 && "$completed" == true ]]; then
        classification="complete"
    elif find "$attempt_dir/raw" -type f -print -quit 2>/dev/null | grep -q .; then
        classification="partial"
    else
        classification="failed_execution"
    fi

    cat > "$attempt_dir/status.json" <<EOF
{
  "runId": "$(json_escape "$run_id")",
  "replicate": $rep,
  "attempt": $attempt,
  "protocol": "ablation-$ABLATION",
  "startedAtUtc": "$(json_escape "$start_utc")",
  "endedAtUtc": "$(json_escape "$end_utc")",
  "durationSeconds": $duration,
  "exitCode": $rc,
  "completedMarker": $completed,
  "classification": "$classification"
}
EOF
    find "$attempt_dir" -type f ! -name checksums.sha256 -print0 \
        | sort -z \
        | xargs -0 sha256sum > "$attempt_dir/checksums.sha256"
    printf '[%s] Attempt %s classified as %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run_id" "$classification" \
        | tee -a "$attempt_dir/logs/runner.log"
done

printf 'Ablation %s campaign complete. Attempts retained under %s\n' "$ABLATION" "$CAMPAIGN_DIR"
