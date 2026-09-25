#!/usr/bin/env bash
#
# Redis 真实故障注入 campaign（专用环境，允许 destructive cleanup）
#
# 协议（与 NativeCacheFailureBenchmark 的 external-fault marker 协议配合）：
#   1. 后台启动 benchmark：--only-rq4 --start-from-rq4=A --skip-decision-performance
#      -Dbenchmark.fault.external-marker-dir=<attempt>/fault
#   2. benchmark 到达 REDIS_DOWN 阶段，写 fault/phase-REDIS_DOWN-requested 后阻塞
#   3. 本脚本 docker stop astral_bench_redis（真实停 Redis 进程）
#   4. 写 fault/fault-ack（内容含 REDIS_DOWN）→ benchmark 在真实连接失败下测回退/熔断
#   5. benchmark 到达 RECOVERY 阶段，写 fault/phase-RECOVERY-requested 后阻塞
#   6. 本脚本 docker start astral_bench_redis，等 healthy 后写 fault-ack（含 RECOVERY）
#   7. benchmark 在已恢复的 Redis 上重建快照并测 recovery
#
# 环境要求（与 run_native_campaign.sh 一致）：
#   BENCH_JWT_SECRET / DB_PASSWORD / DB_HOST / DB_PORT / DB_NAME
#   REDIS_HOST / REDIS_PORT / BENCHMARK_ENV_ID
#   BENCHMARK_DESTRUCTIVE_CLEANUP_APPROVED=true
#   REDIS_CONTAINER=astral_bench_redis （默认）
#
# 仅可对已确认的专用 Redis 容器执行 docker stop/start。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASTRA_DIR="${REPO_DIR}/evaluation/benchmark-java"
JAR_PATH="${ASTRA_DIR}/target/AstralBenchmark-0.0.1-SNAPSHOT.jar"

REPLICATES=3
CAMPAIGN_DIR=""
FIXED_CLOCK="2026-01-01T00:00:00Z"
REDIS_CONTAINER="${REDIS_CONTAINER:-astral_bench_redis}"
# The benchmark runs REDIS_DOWN (3000 evals with a real connection timeout
# before the circuit breaker opens) followed by CB_OPEN and error-rate
# sampling before it writes phase-RECOVERY-requested. With a 3s connection
# timeout and 50 failed evals needed to open the resilience4j breaker, that
# window can exceed 4 minutes. 900s leaves ample margin without affecting
# normal runs.
FAULT_ACK_TIMEOUT_SECONDS=900
REDIS_HEALTH_TIMEOUT_SECONDS=120

usage() {
    cat <<EOF
Usage: $0 [--replicates N] [--campaign-dir DIR] [--fixed-clock TS] [--redis-container NAME]

Runs the RQ4-A cache-failure benchmark with REAL Redis stop/start fault
injection, N fresh-state replicates, on a dedicated Redis container.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --replicates) REPLICATES="$2"; shift 2 ;;
        --campaign-dir) CAMPAIGN_DIR="$2"; shift 2 ;;
        --fixed-clock) FIXED_CLOCK="$2"; shift 2 ;;
        --redis-container) REDIS_CONTAINER="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
done

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

if ! command -v docker >/dev/null 2>&1; then
    printf 'docker is required on the host running this campaign.\n' >&2
    exit 1
fi
if ! docker inspect "${REDIS_CONTAINER}" >/dev/null 2>&1; then
    printf 'Redis container not found: %s\n' "$REDIS_CONTAINER" >&2
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
    CAMPAIGN_DIR="$REPO_DIR/Docs/实验/复现运行/redis-fault-campaign-$(date -u +%Y%m%dT%H%M%SZ)"
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

wait_for_marker() {
    local marker_dir="$1" marker="$2"
    local deadline=$(( $(date +%s) + FAULT_ACK_TIMEOUT_SECONDS ))
    while (( $(date +%s) < deadline )); do
        if [[ -f "$marker_dir/$marker" ]]; then
            return 0
        fi
        sleep 2
    done
    printf '[%s] Timed out waiting for marker %s in %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$marker" "$marker_dir" >&2
    return 1
}

wait_redis_healthy() {
    local deadline=$(( $(date +%s) + REDIS_HEALTH_TIMEOUT_SECONDS ))
    while (( $(date +%s) < deadline )); do
        if docker exec "${REDIS_CONTAINER}" redis-cli ping >/dev/null 2>&1; then
            return 0
        fi
        sleep 3
    done
    printf '[%s] Redis %s did not become healthy within %ss\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REDIS_CONTAINER" "$REDIS_HEALTH_TIMEOUT_SECONDS" >&2
    return 1
}

write_ack() {
    local marker_dir="$1" phase="$2"
    printf '%s\n' "$phase" > "$marker_dir/fault-ack"
    printf '[%s] Ack written for phase %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$phase"
}

append_fault_event() {
    local marker_dir="$1" event="$2" result="$3"
    printf '{"timestampUtc":"%s","event":"%s","result":"%s","redisContainer":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$(json_escape "$event")" "$(json_escape "$result")" \
        "$(json_escape "$REDIS_CONTAINER")" >> "$marker_dir/events.jsonl"
}

# 无论成功失败都恢复 Redis 容器，避免遗留停机状态。
cleanup_fault() {
    local marker_dir="$1"
    if docker inspect "${REDIS_CONTAINER}" >/dev/null 2>&1 \
            && [[ "$(docker inspect -f '{{.State.Running}}' "${REDIS_CONTAINER}" 2>/dev/null || printf 'false')" != "true" ]]; then
        printf '[%s] Restoring Redis container %s after campaign phase\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REDIS_CONTAINER" >&2
        docker start "${REDIS_CONTAINER}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${marker_dir:-}" && -d "$marker_dir" ]]; then
        rm -f "$marker_dir/phase-REDIS_DOWN-requested" "$marker_dir/phase-RECOVERY-requested" "$marker_dir/fault-ack"
    fi
}

printf 'Campaign dir: %s\n' "$CAMPAIGN_DIR"
mkdir -p "$CAMPAIGN_DIR/rq4-fault"

for rep in $(seq 1 "$REPLICATES"); do
    attempt=1
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    run_id="rq4-fault-rep$(printf '%03d' "$rep")-attempt$(printf '%03d' "$attempt")-${timestamp}-$$"
    attempt_dir="$CAMPAIGN_DIR/rq4-fault/rep-$(printf '%03d' "$rep")__attempt-$(printf '%03d' "$attempt")__${timestamp}__${run_id##*-}"
    mkdir -p "$attempt_dir/logs" "$attempt_dir/raw/native-output" "$attempt_dir/derived" "$attempt_dir/environment" "$attempt_dir/fault"
    start_epoch="$(date +%s)"
    start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    marker_dir="$attempt_dir/fault"

    redis_image_id="$(docker inspect -f '{{.Image}}' "$REDIS_CONTAINER")"
    redis_image_ref="$(docker inspect -f '{{.Config.Image}}' "$REDIS_CONTAINER")"
    source_commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
    source_dirty="$(git -C "$REPO_DIR" status --porcelain | wc -l | tr -d ' ')"
    jvm_options="-Xms4G -Xmx8G -XX:+UseZGC -XX:+ZGenerational"

    cat > "$attempt_dir/manifest.json" <<EOF
{
  "formatVersion": 2,
  "campaignProtocol": "rq4-fault",
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
  "faultInjection": "docker-stop-start",
  "redisContainer": "$(json_escape "$REDIS_CONTAINER")",
  "redisImageReference": "$(json_escape "$redis_image_ref")",
  "redisImageId": "$(json_escape "$redis_image_id")",
  "sourceCommit": "$(json_escape "$source_commit")",
  "sourceDirtyFileCount": $source_dirty,
  "jvmOptions": "$(json_escape "$jvm_options")",
  "secretConfigured": true,
  "benchmarkEnvironmentId": "$(json_escape "$BENCHMARK_ENV_ID")",
  "arguments": ["--only-rq4", "--start-from-rq4=A", "--skip-decision-performance"]
}
EOF
    {
        printf 'campaign=%s\nprotocol=rq4-fault\nreplicate=%s\nattempt=%s\nrun_id=%s\n' "$CAMPAIGN_DIR" "$rep" "$attempt" "$run_id"
        printf 'db_host_configured=true\ndb_port_configured=true\ndb_name_configured=true\nredis_host_configured=true\nredis_port_configured=true\n'
        printf 'benchmark_environment_id=%s\nredis_container=%s\n' "$BENCHMARK_ENV_ID" "$REDIS_CONTAINER"
        printf 'bench_jwt_secret_configured=true\ndb_password_configured=true\n'
    } > "$attempt_dir/environment/connection-metadata.txt"
    cp "$attempt_dir/manifest.json" "$attempt_dir/environment/manifest-copy.json"

    printf '[%s] Starting Redis-fault replicate %s/%s in %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rep" "$REPLICATES" "$attempt_dir" \
        | tee "$attempt_dir/logs/runner.log"

    benchmark_output="$attempt_dir/raw/native-output"
    cd "$ASTRA_DIR"
    set +e
    java -Xms4G -Xmx8G -XX:+UseZGC -XX:+ZGenerational \
        -Dbenchmark.type=native \
        -Dbenchmark.native.auto-run=true \
        -Dbenchmark.allow-destructive-cleanup=true \
        -Dbenchmark.fixed-clock="$FIXED_CLOCK" \
        -Dbenchmark.fault.external-marker-dir="$marker_dir" \
        -Dbenchmark.output-dir="$benchmark_output" \
        -jar "$JAR_PATH" \
        --spring.profiles.active=benchmark \
        --spring.data.redis.timeout=2s \
        --only-rq4 --start-from-rq4=A --skip-decision-performance \
        > "$attempt_dir/logs/benchmark.log" 2>&1 &
    bench_pid=$!
    set -e

    # 阶段 1：等待 REDIS_DOWN 请求，真实停止 Redis
    fault_ok=true
    if wait_for_marker "$marker_dir" "phase-REDIS_DOWN-requested"; then
        append_fault_event "$marker_dir" "REDIS_DOWN_REQUESTED" "observed"
        printf '[%s] Stopping Redis container %s (real fault injection)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REDIS_CONTAINER" \
            | tee -a "$attempt_dir/logs/runner.log"
        if docker stop "${REDIS_CONTAINER}" >/dev/null 2>&1; then
            append_fault_event "$marker_dir" "REDIS_STOPPED" "success"
            write_ack "$marker_dir" "REDIS_DOWN"
            append_fault_event "$marker_dir" "REDIS_DOWN_ACKNOWLEDGED" "success"
        else
            fault_ok=false
            append_fault_event "$marker_dir" "REDIS_STOPPED" "failure"
        fi
    else
        fault_ok=false
        append_fault_event "$marker_dir" "REDIS_DOWN_REQUESTED" "timeout"
        printf '[%s] REDIS_DOWN marker timeout; continuing without real stop.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            | tee -a "$attempt_dir/logs/runner.log"
    fi

    # 阶段 2：等待 RECOVERY 请求，真实启动 Redis 并等 healthy
    if [[ "$fault_ok" == true ]] && wait_for_marker "$marker_dir" "phase-RECOVERY-requested"; then
        append_fault_event "$marker_dir" "RECOVERY_REQUESTED" "observed"
        printf '[%s] Starting Redis container %s and waiting for healthy\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REDIS_CONTAINER" \
            | tee -a "$attempt_dir/logs/runner.log"
        if docker start "${REDIS_CONTAINER}" >/dev/null 2>&1; then
            append_fault_event "$marker_dir" "REDIS_STARTED" "success"
        else
            fault_ok=false
            append_fault_event "$marker_dir" "REDIS_STARTED" "failure"
        fi
        if [[ "$fault_ok" == true ]] && wait_redis_healthy; then
            append_fault_event "$marker_dir" "REDIS_HEALTHY" "success"
            # Give the benchmark's Lettuce connection pool time to recover from
            # the down period; otherwise the first FLUSHDB in the recovery
            # rebuild can hit a stale-broken connection and time out at 3s.
            sleep 15
            write_ack "$marker_dir" "RECOVERY"
            append_fault_event "$marker_dir" "RECOVERY_ACKNOWLEDGED" "success"
        else
            fault_ok=false
            append_fault_event "$marker_dir" "REDIS_HEALTHY" "failure"
        fi
    else
        fault_ok=false
        append_fault_event "$marker_dir" "RECOVERY_REQUESTED" "timeout-or-prior-failure"
    fi

    set +e
    wait "$bench_pid"
    rc=$?
    set -e
    end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    duration=$(( $(date +%s) - start_epoch ))
    printf '[%s] Benchmark exit code=%s (fault_ok=%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" "$fault_ok" \
        | tee -a "$attempt_dir/logs/runner.log"

    completed=false
    if [[ -f "$benchmark_output/COMPLETED" ]]; then
        completed=true
    fi

    decision_valid=false
    validity_file="$benchmark_output/rq4a_native_decision_validity.txt"
    if [[ -f "$validity_file" ]] && grep -q '^valid=true$' "$validity_file"; then
        decision_valid=true
    fi
    decision_rows=false
    outcomes_file="$benchmark_output/rq4a_native_decision_outcomes.csv"
    if [[ -f "$outcomes_file" ]] \
            && [[ "$(wc -l < "$outcomes_file")" -gt 1 ]] \
            && awk -F, 'NR > 1 && $2 == "REDIS_DOWN" && $12 ~ /^POLICY_ENGINE/' "$outcomes_file" \
                | grep -q .; then
        decision_rows=true
    fi
    fault_ledger=false
    if [[ -f "$marker_dir/events.jsonl" ]] \
            && grep -q '"event":"REDIS_STOPPED".*"result":"success"' "$marker_dir/events.jsonl" \
            && grep -q '"event":"REDIS_HEALTHY".*"result":"success"' "$marker_dir/events.jsonl"; then
        fault_ledger=true
    fi
    if [[ "$rc" -eq 0 && "$completed" == true && "$fault_ok" == true \
            && "$decision_valid" == true && "$decision_rows" == true && "$fault_ledger" == true ]]; then
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
  "protocol": "rq4-fault",
  "startedAtUtc": "$(json_escape "$start_utc")",
  "endedAtUtc": "$(json_escape "$end_utc")",
  "durationSeconds": $duration,
  "exitCode": $rc,
  "completedMarker": $completed,
  "faultInjection": "$([[ "$fault_ok" == true ]] && printf 'docker-stop-start' || printf 'fault-incomplete')",
  "decisionValid": $decision_valid,
  "decisionRowsPresent": $decision_rows,
  "faultLedgerPresent": $fault_ledger,
  "classification": "$classification"
}
EOF
    cleanup_fault "$marker_dir"
    printf '[%s] Attempt %s classified as %s (decision_valid=%s, decision_rows=%s, fault_ledger=%s)\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run_id" "$classification" \
        "$decision_valid" "$decision_rows" "$fault_ledger" \
        | tee -a "$attempt_dir/logs/runner.log"
    # The checksum manifest is emitted last so it covers the final runner log
    # and all retained decision/fault artifacts.
    find "$attempt_dir" -type f ! -name checksums.sha256 -print0 \
        | sort -z \
        | xargs -0 sha256sum > "$attempt_dir/checksums.sha256"
done

printf 'Redis fault campaign complete. Attempts retained under %s\n' "$CAMPAIGN_DIR"
