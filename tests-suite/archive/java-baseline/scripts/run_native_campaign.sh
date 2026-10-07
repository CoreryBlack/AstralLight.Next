#!/usr/bin/env bash
# Run fresh-state native benchmark replicates and retain every attempt.
# This script intentionally does not delete existing benchmark archives.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASTRA_DIR="${REPO_DIR}/evaluation/benchmark-java"
JAR_PATH="${ASTRA_DIR}/target/AstralBenchmark-0.0.1-SNAPSHOT.jar"

REPLICATES=3
PROTOCOL="rq1"
CAMPAIGN_DIR="${REPO_DIR}/Docs/实验/复现运行/native-campaign-$(date +%Y%m%d_%H%M%S)"
FIXED_CLOCK="2026-01-01T00:00:00Z"
RUN_ARGS=()

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --replicates)
            REPLICATES="$2"
            shift 2
            ;;
        --protocol)
            PROTOCOL="$2"
            shift 2
            ;;
        --campaign-dir)
            CAMPAIGN_DIR="$2"
            shift 2
            ;;
        --fixed-clock)
            FIXED_CLOCK="$2"
            shift 2
            ;;
        --run-arg)
            RUN_ARGS+=("$2")
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$PROTOCOL" in
    rq1) DEFAULT_ARGS=(--only-rq1 --skip-decision-performance) ;;
    rq2) DEFAULT_ARGS=(--only-rq2 --skip-decision-performance) ;;
    rq3) DEFAULT_ARGS=(--only-rq3 --skip-decision-performance) ;;
    rq4) DEFAULT_ARGS=(--only-rq4 --skip-decision-performance) ;;
    rq5) DEFAULT_ARGS=(--only-rq5 --skip-decision-performance) ;;
    suite) DEFAULT_ARGS=(--skip-decision-performance) ;;
    *)
        printf 'Unsupported protocol: %s (use rq1, rq2, rq3, rq4, rq5, or suite)\n' "$PROTOCOL" >&2
        exit 2
        ;;
esac

if [[ "$CAMPAIGN_DIR" != /* ]]; then
    CAMPAIGN_DIR="$REPO_DIR/$CAMPAIGN_DIR"
fi
CAMPAIGN_DIR="$(cd "$(dirname "$CAMPAIGN_DIR")" && pwd)/$(basename "$CAMPAIGN_DIR")"

if ! [[ "$REPLICATES" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Replicates must be a positive integer: %s\n' "$REPLICATES" >&2
    exit 2
fi

PRECHECK_MISSING=()
for required_var in BENCH_JWT_SECRET DB_PASSWORD DB_HOST DB_PORT DB_NAME REDIS_HOST REDIS_PORT BENCHMARK_ENV_ID; do
    if [[ -z "${!required_var:-}" ]]; then
        PRECHECK_MISSING+=("$required_var")
    fi
done
if [[ "${BENCHMARK_DESTRUCTIVE_CLEANUP_APPROVED:-}" != "true" ]]; then
    PRECHECK_MISSING+=("BENCHMARK_DESTRUCTIVE_CLEANUP_APPROVED=true")
fi
if [[ ! -f "$JAR_PATH" ]]; then
    PRECHECK_MISSING+=("JAR_PATH")
fi

mkdir -p "$CAMPAIGN_DIR/$PROTOCOL"
if [[ "${#PRECHECK_MISSING[@]}" -gt 0 ]]; then
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    attempt_dir="$CAMPAIGN_DIR/$PROTOCOL/preflight__${timestamp}__$$"
    start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$attempt_dir/logs" "$attempt_dir/raw" "$attempt_dir/derived" "$attempt_dir/environment"
    missing_json=""
    for missing in "${PRECHECK_MISSING[@]}"; do
        [[ -n "$missing_json" ]] && missing_json+=", "
        missing_json+="\"$missing\""
    done
    cat > "$attempt_dir/manifest.json" <<EOF
{
  "formatVersion": 1,
  "campaignProtocol": "$(printf '%s' "$PROTOCOL" | sed 's/\\/\\\\/g; s/"/\\"/g')",
  "replicate": null,
  "attempt": null,
  "runId": "preflight-$$-$timestamp",
  "startedAtUtc": "$start_utc",
  "benchmarkType": "native",
  "nativeAutoRun": true,
  "destructiveCleanupApproved": false,
  "secretConfigured": $([[ -n "${BENCH_JWT_SECRET:-}" ]] && printf true || printf false),
  "benchmarkEnvironmentIdConfigured": $([[ -n "${BENCHMARK_ENV_ID:-}" ]] && printf true || printf false),
  "preflightMissing": [$missing_json]
}
EOF
    cat > "$attempt_dir/status.json" <<EOF
{
  "runId": "preflight-$$-$timestamp",
  "protocol": "$(printf '%s' "$PROTOCOL" | sed 's/\\/\\\\/g; s/"/\\"/g')",
  "startedAtUtc": "$start_utc",
  "endedAtUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "durationSeconds": 0,
  "exitCode": 1,
  "phase": "preflight",
  "completedMarker": false,
  "artifactState": "preflight-blocked",
  "classification": "failed_setup"
}
EOF
    printf 'Preflight blocked; missing prerequisites: %s\n' "${PRECHECK_MISSING[*]}" | tee "$attempt_dir/logs/runner.log"
    find "$attempt_dir" -type f ! -name checksums.sha256 -print0 | sort -z | xargs -0 sha256sum > "$attempt_dir/checksums.sha256"
    exit 1
fi


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

write_manifest() {
    local attempt_dir="$1" run_id="$2" rep="$3" attempt="$4" start_utc="$5"
    local commit dirty jar_hash
    commit="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    if [[ -n "$(git -C "$REPO_DIR" status --porcelain 2>/dev/null)" ]]; then
        dirty=true
    else
        dirty=false
    fi
    jar_hash="$(sha256_file "$JAR_PATH")"
    local args_json=""
    local arg
    for arg in "${DEFAULT_ARGS[@]}" "${RUN_ARGS[@]}"; do
        if [[ -n "$args_json" ]]; then
            args_json+=", "
        fi
        args_json+="\"$(json_escape "$arg")\""
    done
    cat > "$attempt_dir/manifest.json" <<EOF
{
  "formatVersion": 1,
  "campaignProtocol": "$(json_escape "$PROTOCOL")",
  "replicate": $rep,
  "attempt": $attempt,
  "runId": "$(json_escape "$run_id")",
  "startedAtUtc": "$(json_escape "$start_utc")",
  "sourceCommit": "$(json_escape "$commit")",
  "workingTreeDirty": $dirty,
  "jarSha256": "$(json_escape "$jar_hash")",
  "javaVersion": "$(json_escape "$(java -version 2>&1 | head -1)")",
  "jvmOptions": "$(json_escape "${JAVA_OPTS:--Xms8G -Xmx16G -XX:+UseZGC -XX:+ZGenerational}")",
  "seed": 42,
  "fixedBenchmarkClock": "$(json_escape "$FIXED_CLOCK")",
  "benchmarkType": "native",
  "nativeAutoRun": true,
  "destructiveCleanupApproved": true,
  "secretConfigured": true,
  "benchmarkEnvironmentId": "$(json_escape "$BENCHMARK_ENV_ID")",
  "database": {"configured": true, "user": "$(json_escape "${DB_USER:-}")"},
  "redis": {"configured": true, "passwordConfigured": $([[ -n "${REDIS_PASSWORD:-}" ]] && printf true || printf false)},
  "arguments": [$args_json]
}
EOF
    cp "$attempt_dir/manifest.json" "$attempt_dir/environment/manifest-copy.json"
}

write_status() {
    local attempt_dir="$1" run_id="$2" rep="$3" attempt="$4" start_epoch="$5" start_utc="$6" exit_code="$7" phase="$8"
    local end_utc duration output_dir completed artifact_state classification has_artifacts
    end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    duration=$(( $(date +%s) - start_epoch ))
    output_dir="$attempt_dir/raw/native-output"
    if [[ -f "$output_dir/COMPLETED" ]]; then
        completed=true
        artifact_state="completed-marker-present"
    else
        completed=false
        artifact_state="completed-marker-missing"
    fi
    if find "$output_dir" -type f -print -quit 2>/dev/null | grep -q .; then
        has_artifacts=true
    else
        has_artifacts=false
    fi
    if [[ "$phase" == "preflight" ]]; then
        classification="failed_setup"
    elif [[ "$exit_code" -eq 0 && "$completed" == true ]]; then
        classification="complete"
    elif [[ "$has_artifacts" == true ]]; then
        classification="partial"
    else
        classification="failed_execution"
    fi
    cat > "$attempt_dir/status.json" <<EOF
{
  "runId": "$(json_escape "$run_id")",
  "replicate": $rep,
  "attempt": $attempt,
  "protocol": "$(json_escape "$PROTOCOL")",
  "startedAtUtc": "$(json_escape "$start_utc")",
  "endedAtUtc": "$(json_escape "$end_utc")",
  "durationSeconds": $duration,
  "exitCode": $exit_code,
  "phase": "$(json_escape "$phase")",
  "completedMarker": $completed,
  "artifactState": "$artifact_state",
  "classification": "$classification"
}
EOF
}

for rep in $(seq 1 "$REPLICATES"); do
    attempt=1
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    run_id="${PROTOCOL}-rep$(printf '%03d' "$rep")-attempt$(printf '%03d' "$attempt")-${timestamp}-$$"
    attempt_dir="$CAMPAIGN_DIR/$PROTOCOL/rep-$(printf '%03d' "$rep")__attempt-$(printf '%03d' "$attempt")__${timestamp}__${run_id##*-}"
    mkdir -p "$attempt_dir/logs" "$attempt_dir/raw" "$attempt_dir/derived" "$attempt_dir/environment"
    start_epoch="$(date +%s)"
    start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    phase="preflight"

    {
        printf 'campaign=%s\nprotocol=%s\nreplicate=%s\nattempt=%s\nrun_id=%s\n' "$CAMPAIGN_DIR" "$PROTOCOL" "$rep" "$attempt" "$run_id"
        printf 'db_host_configured=true\ndb_port_configured=true\ndb_name_configured=true\nredis_host_configured=true\nredis_port_configured=true\n'
        printf 'benchmark_environment_id=%s\n' "$BENCHMARK_ENV_ID"
        printf 'bench_jwt_secret_configured=true\ndb_password_configured=true\n'
    } > "$attempt_dir/environment/connection-metadata.txt"

    write_manifest "$attempt_dir" "$run_id" "$rep" "$attempt" "$start_utc"
    printf '[%s] Starting %s replicate %s/%s in %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROTOCOL" "$rep" "$REPLICATES" "$attempt_dir" | tee "$attempt_dir/logs/runner.log"

    benchmark_output="$attempt_dir/raw/native-output"
    mkdir -p "$benchmark_output"
    phase="execution"
    cd "$ASTRA_DIR"
    set +e
    java ${JAVA_OPTS:--Xms8G -Xmx8G -XX:+UseZGC -XX:+ZGenerational} \
        -Dbenchmark.type=native \
        -Dbenchmark.native.auto-run=true \
        -Dbenchmark.allow-destructive-cleanup=true \
        -Dbenchmark.fixed-clock="$FIXED_CLOCK" \
        -Dbenchmark.output-dir="$benchmark_output" \
        -jar "$JAR_PATH" \
        --spring.profiles.active=benchmark \
        "${DEFAULT_ARGS[@]}" "${RUN_ARGS[@]}" \
        > "$attempt_dir/logs/benchmark.log" 2>&1
    rc=$?
    set -e
    printf '[%s] Benchmark exit code=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" | tee -a "$attempt_dir/logs/runner.log"

    write_status "$attempt_dir" "$run_id" "$rep" "$attempt" "$start_epoch" "$start_utc" "$rc" "$phase"
    find "$attempt_dir" -type f ! -name checksums.sha256 -print0 \
        | sort -z \
        | xargs -0 sha256sum > "$attempt_dir/checksums.sha256"
    printf '[%s] Attempt retained with classification from status.json\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$attempt_dir/logs/runner.log"
done

printf 'Campaign complete. Attempts retained under %s\n' "$CAMPAIGN_DIR"
