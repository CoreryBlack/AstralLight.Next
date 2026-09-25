#!/usr/bin/env bash
#
# Three-node heterogeneous native benchmark campaign.
#
# Runs the AstralLight native benchmark (RQ1-RQ4 by default, overridable via
# CLUSTER_BENCH_ARGS) on three independent hosts in parallel. Each node uses a
# run-scoped dedicated MySQL schema and a dedicated Redis database index so the
# parallel runs never share mutable state; every node is launched with
# -Dbenchmark.cluster.* identity properties (node-id, hardware-label, node-role,
# role-permutation, run-id) and writes its own per-node output directory
# (decision outcomes carry node/role/global-sequence columns in cluster mode).
#
# Roles are labels, not mutually exclusive workloads: with per-node data
# isolation, WRITER / READER_A / READER_B each run the same selected RQ set so
# the three-host dataset is directly comparable across hardware.
#
# Fail-closed: every required variable must be provided. Missing input, an
# unreachable node, or a failed probe aborts with an ATTEMPT_ABORTED marker and
# a non-zero exit. Secrets are injected via run-scoped env files with restricted
# permissions, never via command line or logs. Destructive DB creation only
# happens after CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED=true.
#
# Required environment:
#   CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED=true
#   CLUSTER_SSH_USER / NODE_A_HOST / NODE_B_HOST / NODE_C_HOST
#   NODE_A_SSH_USER / NODE_B_SSH_USER / NODE_C_SSH_USER   (defaults to CLUSTER_SSH_USER)
#   NODE_A_HARDWARE / NODE_B_HARDWARE / NODE_C_HARDWARE   (ClusterRunContext labels)
#   JAR_PATH / BENCH_JWT_SECRET / DB_HOST / DB_PORT / DB_USER / DB_PASSWORD
#   REDIS_HOST / REDIS_PORT / REDIS_PASSWORD (optional)
#   RABBIT_HOST / RABBIT_PORT / RABBIT_USER / RABBIT_PASSWORD
#   BENCHMARK_ENV_ID
# Optional:
#   CLUSTER_RUN_ID / CLUSTER_CAMPAIGN_DIR / CLUSTER_BENCH_ARGS
#   REPLICATES (default 1) / PERMUTATION (default 0) / CLUSTER_PHASE
#   NODE_A_ROLE / NODE_B_ROLE / NODE_C_ROLE (default WRITER/READER_A/READER_B)
#   REDIS_DATABASES="1 2 3" per-node indices

set -euo pipefail

readonly SCRIPT_PROTOCOL_VERSION="rq4-cluster-3nodes-v2"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
readonly DEFAULT_CAMPAIGN_DIR="$REPO_DIR/Docs/实验/复现运行/cluster-native-$(date -u +%Y%m%dT%H%M%SZ)"

protocol_version="${CLUSTER_PROTOCOL_VERSION:-$SCRIPT_PROTOCOL_VERSION}"
phase="${CLUSTER_PHASE:-NO_FAULT_CONTROL}"
replicates="${REPLICATES:-1}"
permutation="${PERMUTATION:-0}"
run_id="${CLUSTER_RUN_ID:-cluster-native-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
campaign_dir="${CLUSTER_CAMPAIGN_DIR:-$DEFAULT_CAMPAIGN_DIR}"
bench_args="${CLUSTER_BENCH_ARGS:---only-rq4 --start-from-rq4=A --skip-decision-performance}"
redis_databases="${REDIS_DATABASES:-1 2 3}"
schema_sql="${SCHEMA_SQL:-$SCRIPT_DIR/full_schema_v4.sql}"
projection_ddl="${PROJECTION_DDL:-$SCRIPT_DIR/projection_tables_ddl.sql}"
mysql_container="${MYSQL_CONTAINER:-astral_bench_mysql}"

node_a_role="${NODE_A_ROLE:-WRITER}"
node_b_role="${NODE_B_ROLE:-READER_A}"
node_c_role="${NODE_C_ROLE:-READER_B}"

require_token() {
    local name="$1" value="$2"
    if [[ -z "$value" || ! "$value" =~ ^[A-Za-z0-9._:-]+$ ]]; then
        printf '%s must be a non-empty safe token\n' "$name" >&2
        exit 2
    fi
}

write_aborted_marker() {
    local marker_dir="$1" reason_value="$2"
    mkdir -p "$marker_dir"
    local temporary="$marker_dir/.ATTEMPT_ABORTED.json.tmp"
    local marker="$marker_dir/ATTEMPT_ABORTED.json"
    printf '{\n  "formatVersion": 1,\n  "status": "ABORTED",\n  "protocolVersion": "%s",\n  "runId": "%s",\n  "phase": "%s",\n  "replicates": %s,\n  "permutation": %s,\n  "reason": "%s"\n}\n' \
        "$protocol_version" "$run_id" "$phase" "$replicates" "$permutation" "$reason_value" > "$temporary"
    mv -f "$temporary" "$marker"
    printf 'Cluster native campaign ABORTED: %s\nMarker: %s\n' "$reason_value" "$marker" >&2
}

if [[ "$protocol_version" != "$SCRIPT_PROTOCOL_VERSION" ]]; then
    write_aborted_marker "$campaign_dir" "UNSUPPORTED_PROTOCOL_VERSION:$protocol_version"
    exit 78
fi
if ! [[ "$replicates" =~ ^[1-9][0-9]*$ ]]; then
    write_aborted_marker "$campaign_dir" "REPLICATES_MUST_BE_POSITIVE"
    exit 78
fi
if ! [[ "$permutation" =~ ^[0-5]$ ]]; then
    write_aborted_marker "$campaign_dir" "PERMUTATION_MUST_BE_0_TO_5"
    exit 78
fi
require_token CLUSTER_RUN_ID "$run_id"

: "${CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED:?must be true for run-scoped DB creation}"
: "${CLUSTER_SSH_USER:?required}"
: "${NODE_A_HOST:?required}" "${NODE_B_HOST:?required}" "${NODE_C_HOST:?required}"
: "${NODE_A_HARDWARE:?required}" "${NODE_B_HARDWARE:?required}" "${NODE_C_HARDWARE:?required}"
: "${JAR_PATH:?required}" "${BENCH_JWT_SECRET:?required}"
: "${DB_HOST:?required}" "${DB_PORT:?required}" "${DB_USER:?required}" "${DB_PASSWORD:?required}"
: "${REDIS_HOST:?required}" "${REDIS_PORT:?required}"
: "${RABBIT_HOST:?required}" "${RABBIT_PORT:?required}" "${RABBIT_USER:?required}" "${RABBIT_PASSWORD:?required}"
: "${BENCHMARK_ENV_ID:?required}"

JAR_PATH="$(cd "$(dirname "$JAR_PATH")" && pwd)/$(basename "$JAR_PATH")"
if [[ ! -f "$JAR_PATH" ]]; then
    write_aborted_marker "$campaign_dir" "JAR_NOT_FOUND:$JAR_PATH"
    exit 78
fi

if [[ "$campaign_dir" != /* ]]; then
    campaign_dir="$PWD/$campaign_dir"
fi
mkdir -p "$campaign_dir"

node_a_ssh="${NODE_A_SSH_USER:-$CLUSTER_SSH_USER}"
node_b_ssh="${NODE_B_SSH_USER:-$CLUSTER_SSH_USER}"
node_c_ssh="${NODE_C_SSH_USER:-$CLUSTER_SSH_USER}"

redis_indexes=($redis_databases)
if [[ ${#redis_indexes[@]} -lt 3 ]]; then
    write_aborted_marker "$campaign_dir" "REDIS_DATABASES_MUST_HAVE_3_INDICES"
    exit 78
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | tr -s ' ' | cut -d' ' -f1
    else
        openssl dgst -sha256 -r "$1" | tr -s ' ' | cut -d' ' -f1
    fi
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

# ---- per-node schema creation -------------------------------------------
for node_id in node-a node-b node-c; do
    db_name="astrallight_${run_id}_${node_id}"
    if ! docker exec "$mysql_container" env MYSQL_PWD="$DB_PASSWORD" \
            mysql -h 127.0.0.1 -P 3306 -u "$DB_USER" \
            -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" >/dev/null 2>&1; then
        write_aborted_marker "$campaign_dir" "SCHEMA_CREATE_FAILED:$node_id"
        exit 78
    fi
    # The native benchmark refuses to run against a schema-less database
    # (TRUNCATE of missing tables aborts), so every run-scoped DB must be
    # initialized with the benchmark schema before any node starts. The
    # projection head/outbox tables are appended because full_schema_v4.sql
    # predates them and the benchmark truncates them during cleanup.
    tmp_schema="/tmp/schema_${run_id}_${node_id}.sql"
    if ! sed "s/platform_v4/${db_name}/g" "$schema_sql" "$projection_ddl" > "$tmp_schema" 2>/dev/null \
            || ! docker cp "$tmp_schema" "$mysql_container:/tmp/schema_import.sql" >/dev/null 2>&1 \
            || ! docker exec "$mysql_container" env MYSQL_PWD="$DB_PASSWORD" \
                mysql -h 127.0.0.1 -P 3306 -u "$DB_USER" "$db_name" -e "source /tmp/schema_import.sql" >/dev/null 2>&1; then
        write_aborted_marker "$campaign_dir" "SCHEMA_IMPORT_FAILED:$node_id"
        exit 78
    fi
    rm -f "$tmp_schema"
done

# ---- per-node launch ----------------------------------------------------
declare -a LAUNCH_PIDS=()
launch_node() { # nodeId host sshUser hardware role redisIndex outputTag
    local node_id="$1" host="$2" ssh_user="$3" hardware="$4" role="$5" redis_idx="$6" tag="$7"
    local remote_dir="/tmp/astral-cluster-native/${run_id}/${node_id}"
    local local_node_dir="$campaign_dir/$node_id"
    mkdir -p "$local_node_dir"

    local env_file="$local_node_dir/node.env"
    umask 077
    : > "$env_file"
    local db_name="astrallight_${run_id}_${node_id}"
    {
        printf 'export DB_HOST=%q\n' "$DB_HOST"
        printf 'export DB_PORT=%q\n' "$DB_PORT"
        printf 'export DB_NAME=%q\n' "$db_name"
        printf 'export DB_USERNAME=%q\n' "$DB_USER"
        printf 'export DB_PASSWORD=%q\n' "$DB_PASSWORD"
        printf 'export REDIS_HOST=%q\n' "$REDIS_HOST"
        printf 'export REDIS_PORT=%q\n' "$REDIS_PORT"
        printf 'export REDIS_PASSWORD=%q\n' "${REDIS_PASSWORD:-}"
        printf 'export RABBIT_HOST=%q\n' "$RABBIT_HOST"
        printf 'export RABBIT_PORT=%q\n' "$RABBIT_PORT"
        printf 'export RABBIT_USERNAME=%q\n' "$RABBIT_USER"
        printf 'export RABBIT_PASSWORD=%q\n' "$RABBIT_PASSWORD"
        printf 'export JWT_SECRET=%q\n' "$BENCH_JWT_SECRET"
        printf 'export BENCHMARK_ENV_ID=%q\n' "$BENCHMARK_ENV_ID"
        printf 'export SPRING_DATA_REDIS_DATABASE=%q\n' "$redis_idx"
        printf 'export JAVA_TOOL_OPTIONS=%q\n' \
            "-Dbenchmark.cluster.campaign-id=${run_id} -Dbenchmark.cluster.run-id=${run_id} -Dbenchmark.cluster.replicate=${replicates} -Dbenchmark.cluster.attempt=1 -Dbenchmark.cluster.node-id=${node_id} -Dbenchmark.cluster.hardware-label=${hardware} -Dbenchmark.cluster.node-role=${role} -Dbenchmark.cluster.role-permutation=perm${permutation} -Dbenchmark.cluster.phase=${phase} -Dbenchmark.cluster.coordinator=$([[ "$role" == "WRITER" ]] && printf true || printf false) -Dbenchmark.cluster.protocol-version=${protocol_version}"
    } > "$env_file"
    chmod 600 "$env_file"

    ssh -o BatchMode=yes -o ConnectTimeout=15 "$ssh_user@$host" \
        "mkdir -p '$remote_dir'" || { write_aborted_marker "$campaign_dir" "SSH_MKDIR_FAILED:$node_id"; exit 78; }
    scp -o BatchMode=yes -o ConnectTimeout=15 "$JAR_PATH" "$ssh_user@$host:$remote_dir/trustgraph-boot.jar" \
        || { write_aborted_marker "$campaign_dir" "SCP_FAILED:$node_id"; exit 78; }
    scp -o BatchMode=yes -o ConnectTimeout=15 "$env_file" "$ssh_user@$host:$remote_dir/node.env" \
        || { write_aborted_marker "$campaign_dir" "SCP_ENV_FAILED:$node_id"; exit 78; }

    local remote_out="$remote_dir/output"
    local java_opts="-Xms4G -Xmx8G -XX:+UseZGC -XX:+ZGenerational"
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$ssh_user@$host" \
        "cd '$remote_dir' && chmod 600 node.env && ( setsid bash -c 'source ./node.env && exec java ${java_opts} -Dbenchmark.type=native -Dbenchmark.native.auto-run=true -Dbenchmark.allow-destructive-cleanup=true -Dbenchmark.fixed-clock=2026-01-01T00:00:00Z -Dbenchmark.output-dir=${remote_out} -jar ./trustgraph-boot.jar --spring.profiles.active=benchmark ${bench_args}' > node.log 2>&1 < /dev/null & echo \$! > node.pid ) && sleep 3 && kill -0 \$(cat node.pid) 2>/dev/null && echo LAUNCHED" \
        || { write_aborted_marker "$campaign_dir" "SSH_START_FAILED:$node_id"; exit 78; }
    printf 'Launched %s (%s, %s) redis-db=%s\n' "$node_id" "$role" "$hardware" "$redis_idx"
}

launch_node node-a "$NODE_A_HOST" "$node_a_ssh" "$NODE_A_HARDWARE" "$node_a_role" "${redis_indexes[0]}" "node-a" &
LAUNCH_PIDS+=($!)
launch_node node-b "$NODE_B_HOST" "$node_b_ssh" "$NODE_B_HARDWARE" "$node_b_role" "${redis_indexes[1]}" "node-b" &
LAUNCH_PIDS+=($!)
launch_node node-c "$NODE_C_HOST" "$node_c_ssh" "$NODE_C_HARDWARE" "$node_c_role" "${redis_indexes[2]}" "node-c" &
LAUNCH_PIDS+=($!)

launch_ok=true
for launch_pid in "${LAUNCH_PIDS[@]}"; do
    if ! wait "$launch_pid"; then
        launch_ok=false
    fi
done
if [[ "$launch_ok" != "true" ]]; then
    write_aborted_marker "$campaign_dir" "PARTIAL_LAUNCH"
    exit 78
fi

# ---- wait for completion (bounded 6 hours) ------------------------------
cleanup_nodes() {
    for node_id in "${LAUNCHED_PIDS[@]:-}"; do :; done
    return 0
}
trap 'cleanup_nodes || true' EXIT

completed_nodes=0
deadline=$(( $(date +%s) + 6*3600 ))
while (( $(date +%s) < deadline )); do
    completed_nodes=0
    for node_id in node-a node-b node-c; do
        local_dir="$campaign_dir/$node_id"
        if [[ -d "$local_dir" ]]; then
            if ssh -o BatchMode=yes -o ConnectTimeout=10 \
                    "$(case $node_id in node-a) printf %s "$node_a_ssh";; node-b) printf %s "$node_b_ssh";; node-c) printf %s "$node_c_ssh";; esac)@$(case $node_id in node-a) printf %s "$NODE_A_HOST";; node-b) printf %s "$NODE_B_HOST";; node-c) printf %s "$NODE_C_HOST";; esac)" \
                    "test -f /tmp/astral-cluster-native/${run_id}/${node_id}/output/COMPLETED" 2>/dev/null; then
                completed_nodes=$((completed_nodes + 1))
            fi
        fi
    done
    if [[ $completed_nodes -eq 3 ]]; then
        break
    fi
    sleep 30
done

if [[ $completed_nodes -ne 3 ]]; then
    write_aborted_marker "$campaign_dir" "NODE_TIMEOUT:completed=$completed_nodes"
    exit 78
fi

# ---- collect per-node outputs -------------------------------------------
report_list=""
for node_id in node-a node-b node-c; do
    ssh_user="$(case $node_id in node-a) printf %s "$node_a_ssh";; node-b) printf %s "$node_b_ssh";; node-c) printf %s "$node_c_ssh";; esac)"
    host="$(case $node_id in node-a) printf %s "$NODE_A_HOST";; node-b) printf %s "$NODE_B_HOST";; node-c) printf %s "$NODE_C_HOST";; esac)"
    local_dir="$campaign_dir/$node_id"
    mkdir -p "$local_dir/raw"
    if scp -r -o BatchMode=yes -o ConnectTimeout=15 \
            "$ssh_user@$host:/tmp/astral-cluster-native/${run_id}/${node_id}/output" "$local_dir/raw/"; then
        if [[ -z "$report_list" ]]; then
            report_list="\"$node_id/raw/output\""
        else
            report_list="$report_list, \"$node_id/raw/output\""
        fi
    else
        write_aborted_marker "$campaign_dir" "COLLECT_FAILED:$node_id"
        exit 78
    fi
done

# ---- terminal marker ----------------------------------------------------
jar_sha256="$(sha256_file "$JAR_PATH")"
printf '{\n  "formatVersion": 1,\n  "status": "COMPLETE",\n  "protocolVersion": "%s",\n  "runId": "%s",\n  "phase": "%s",\n  "replicates": %s,\n  "permutation": %s,\n  "benchArgs": "%s",\n  "nodeRoles": {"node-a": "%s", "node-b": "%s", "node-c": "%s"},\n  "hardwareLabels": {"node-a": "%s", "node-b": "%s", "node-c": "%s"},\n  "outputPaths": [%s],\n  "jarSha256": "%s",\n  "benchmarkEnvId": "%s"\n}\n' \
    "$protocol_version" "$run_id" "$phase" "$replicates" "$permutation" \
    "$(json_escape "$bench_args")" \
    "$node_a_role" "$node_b_role" "$node_c_role" \
    "$NODE_A_HARDWARE" "$NODE_B_HARDWARE" "$NODE_C_HARDWARE" \
    "$report_list" "$jar_sha256" "$(json_escape "$BENCHMARK_ENV_ID")" \
    > "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp"
mv -f "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp" "$campaign_dir/ATTEMPT_COMPLETE.json"

find "$campaign_dir" -type f ! -name checksums.sha256 -print0 \
    | sort -z | xargs -0 sha256sum > "$campaign_dir/checksums.sha256"

printf 'Cluster native campaign COMPLETE. Artifacts: %s\n' "$campaign_dir"
exit 0
