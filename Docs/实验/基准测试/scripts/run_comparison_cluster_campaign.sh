#!/usr/bin/env bash
#
# Three-node distributed multi-system comparison benchmark campaign.
#
# Runs the AstralLight comparison benchmark (vs Casbin/OPA/Cedar) on three
# independent hosts in parallel. Each node uses a run-scoped MySQL schema and a
# dedicated Redis index for AstralLight, runs its own OPA container (Casbin and
# Cedar are in-JVM adapters that ship with the JAR), and launches the benchmark
# from a run-scoped working directory so every node's output is collected
# separately. Cluster identity properties attribute every node's results.
#
# Fail-closed: missing inputs abort with ATTEMPT_ABORTED. Secrets are injected
# via run-scoped env files, never via command line or logs.
#
# Required environment:
#   CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED=true
#   CLUSTER_SSH_USER / NODE_A_HOST / NODE_B_HOST / NODE_C_HOST
#   NODE_A_SSH_USER / NODE_B_SSH_USER / NODE_C_SSH_USER (defaults CLUSTER_SSH_USER)
#   NODE_A_HARDWARE / NODE_B_HARDWARE / NODE_C_HARDWARE
#   NODE_A_OPA_PORT / NODE_B_OPA_PORT / NODE_C_OPA_PORT (per-node OPA, default 8181/8182/8181)
#   JAR_PATH / DB_HOST / DB_PORT / DB_USER / DB_PASSWORD
#   REDIS_HOST / REDIS_PORT / REDIS_PASSWORD (optional)
#   BENCHMARK_ENV_ID
# Optional:
#   CLUSTER_RUN_ID / CLUSTER_CAMPAIGN_DIR / OPA_IMAGE

set -euo pipefail

readonly SCRIPT_PROTOCOL_VERSION="comparison-cluster-3nodes-v1"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
readonly DEFAULT_CAMPAIGN_DIR="$REPO_DIR/Docs/实验/复现运行/cluster-comparison-$(date -u +%Y%m%dT%H%M%SZ)"

protocol_version="${CLUSTER_PROTOCOL_VERSION:-$SCRIPT_PROTOCOL_VERSION}"
replicates="${REPLICATES:-1}"
permutation="${PERMUTATION:-0}"
run_id="${CLUSTER_RUN_ID:-cluster-comparison-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
campaign_dir="${CLUSTER_CAMPAIGN_DIR:-$DEFAULT_CAMPAIGN_DIR}"
opa_image="${OPA_IMAGE:-openpolicyagent/opa:latest}"
node_a_opa_port="${NODE_A_OPA_PORT:-8181}"
node_b_opa_port="${NODE_B_OPA_PORT:-8182}"
node_c_opa_port="${NODE_C_OPA_PORT:-8181}"

node_a_role="${NODE_A_ROLE:-WRITER}"
node_b_role="${NODE_B_ROLE:-READER_A}"
node_c_role="${NODE_C_ROLE:-READER_B}"

write_aborted_marker() {
    local marker_dir="$1" reason_value="$2"
    mkdir -p "$marker_dir"
    local temporary="$marker_dir/.ATTEMPT_ABORTED.json.tmp"
    local marker="$marker_dir/ATTEMPT_ABORTED.json"
    printf '{\n  "formatVersion": 1,\n  "status": "ABORTED",\n  "protocolVersion": "%s",\n  "runId": "%s",\n  "replicates": %s,\n  "permutation": %s,\n  "reason": "%s"\n}\n' \
        "$protocol_version" "$run_id" "$replicates" "$permutation" "$reason_value" > "$temporary"
    mv -f "$temporary" "$marker"
    printf 'Cluster comparison campaign ABORTED: %s\nMarker: %s\n' "$reason_value" "$marker" >&2
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

: "${CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED:?must be true}"
: "${CLUSTER_SSH_USER:?required}" "${NODE_A_HOST:?required}" "${NODE_B_HOST:?required}" "${NODE_C_HOST:?required}"
: "${NODE_A_HARDWARE:?required}" "${NODE_B_HARDWARE:?required}" "${NODE_C_HARDWARE:?required}"
: "${JAR_PATH:?required}" "${DB_HOST:?required}" "${DB_PORT:?required}" "${DB_USER:?required}" "${DB_PASSWORD:?required}"
: "${REDIS_HOST:?required}" "${REDIS_PORT:?required}" "${BENCHMARK_ENV_ID:?required}"

JAR_PATH="$(cd "$(dirname "$JAR_PATH")" && pwd)/$(basename "$JAR_PATH")"
if [[ ! -f "$JAR_PATH" ]]; then
    write_aborted_marker "$campaign_dir" "JAR_NOT_FOUND:$JAR_PATH"
    exit 78
fi
mkdir -p "$campaign_dir"

node_a_ssh="${NODE_A_SSH_USER:-$CLUSTER_SSH_USER}"
node_b_ssh="${NODE_B_SSH_USER:-$CLUSTER_SSH_USER}"
node_c_ssh="${NODE_C_SSH_USER:-$CLUSTER_SSH_USER}"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | tr -s ' ' | cut -d' ' -f1
    else
        openssl dgst -sha256 -r "$1" | tr -s ' ' | cut -d' ' -f1
    fi
}
json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"; value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"; value="${value//$'\r'/\\r}"; value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

mysql_container="${MYSQL_CONTAINER:-astral_bench_mysql}"
schema_sql="${SCHEMA_SQL:-$SCRIPT_DIR/full_schema_v4.sql}"
projection_ddl="${PROJECTION_DDL:-$SCRIPT_DIR/projection_tables_ddl.sql}"

# ---- per-node schema creation -------------------------------------------
for node_id in node-a node-b node-c; do
    db_name="astrallight_${run_id}_${node_id}"
    if ! docker exec "$mysql_container" env MYSQL_PWD="$DB_PASSWORD" \
            mysql -h 127.0.0.1 -P 3306 -u "$DB_USER" \
            -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" >/dev/null 2>&1; then
        write_aborted_marker "$campaign_dir" "SCHEMA_CREATE_FAILED:$node_id"
        exit 78
    fi
    tmp_schema="/tmp/schema_cmp_${run_id}_${node_id}.sql"
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
launch_node() { # nodeId host sshUser hardware role opaPort redisIndex
    local node_id="$1" host="$2" ssh_user="$3" hardware="$4" role="$5" opa_port="$6" redis_idx="$7"
    local remote_dir="/tmp/astral-cluster-comparison/${run_id}/${node_id}"
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
        printf 'export RABBIT_HOST=%q\n' "${RABBIT_HOST:-$DB_HOST}"
        printf 'export RABBIT_PORT=%q\n' "${RABBIT_PORT:-5673}"
        printf 'export RABBIT_USERNAME=%q\n' "${RABBIT_USER:-}"
        printf 'export RABBIT_PASSWORD=%q\n' "${RABBIT_PASSWORD:-}"
        printf 'export BENCHMARK_ENV_ID=%q\n' "$BENCHMARK_ENV_ID"
        printf 'export SPRING_DATA_REDIS_DATABASE=%q\n' "$redis_idx"
        printf 'export JAVA_TOOL_OPTIONS=%q\n' \
            "-Dbenchmark.cluster.campaign-id=${run_id} -Dbenchmark.cluster.run-id=${run_id} -Dbenchmark.cluster.replicate=${replicates} -Dbenchmark.cluster.attempt=1 -Dbenchmark.cluster.node-id=${node_id} -Dbenchmark.cluster.hardware-label=${hardware} -Dbenchmark.cluster.node-role=${role} -Dbenchmark.cluster.role-permutation=perm${permutation} -Dbenchmark.cluster.phase=COMPARISON -Dbenchmark.cluster.coordinator=false -Dbenchmark.cluster.protocol-version=${protocol_version}"
    } > "$env_file"
    chmod 600 "$env_file"

    # Deploy JAR + env
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$ssh_user@$host" "mkdir -p '$remote_dir'" \
        || { write_aborted_marker "$campaign_dir" "SSH_MKDIR_FAILED:$node_id"; exit 78; }
    scp -o BatchMode=yes -o ConnectTimeout=15 "$JAR_PATH" "$ssh_user@$host:$remote_dir/astralbench.jar" \
        || { write_aborted_marker "$campaign_dir" "SCP_FAILED:$node_id"; exit 78; }
    scp -o BatchMode=yes -o ConnectTimeout=15 "$env_file" "$ssh_user@$host:$remote_dir/node.env" \
        || { write_aborted_marker "$campaign_dir" "SCP_ENV_FAILED:$node_id"; exit 78; }

    # Start per-node OPA container (node-local port)
    local opa_name="astral_bench_opa_${run_id}_${node_id}"
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$ssh_user@$host" \
        "docker rm -f '$opa_name' >/dev/null 2>&1 || true; docker run -d --name '$opa_name' -p ${opa_port}:8181 '$opa_image' run --server --addr :8181 --log-level error >/dev/null 2>&1 && echo OPA-STARTED || (docker pull '$opa_image' >/dev/null 2>&1 && docker run -d --name '$opa_name' -p ${opa_port}:8181 '$opa_image' run --server --addr :8181 --log-level error >/dev/null 2>&1 && echo OPA-STARTED || echo OPA-FAILED)" \
        | grep -q OPA-STARTED \
        || { write_aborted_marker "$campaign_dir" "OPA_START_FAILED:$node_id"; exit 78; }

    # Launch comparison JAR from a run-scoped cwd so its output directory
    # (benchmark-results/comparison-*) is per-node.
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$ssh_user@$host" \
        "cd '$remote_dir' && chmod 600 node.env && rm -rf benchmark-results && ( setsid bash -c 'source ./node.env && exec /usr/bin/java -Xms6G -Xmx6G -XX:+UseG1GC -Dbenchmark.type=comparison -Dbenchmark.allow-destructive-cleanup=true -Dbenchmark.opa.url=http://127.0.0.1:${opa_port} -jar ./astralbench.jar --spring.profiles.active=benchmark' > node.log 2>&1 < /dev/null & echo \$! > node.pid ) && sleep 3 && kill -0 \$(cat node.pid) 2>/dev/null && echo LAUNCHED" \
        || { write_aborted_marker "$campaign_dir" "SSH_START_FAILED:$node_id"; exit 78; }
    printf 'Launched %s (%s, %s) opa=127.0.0.1:%s redis-db=%s\n' "$node_id" "$role" "$hardware" "$opa_port" "$redis_idx"
}

launch_node node-a "$NODE_A_HOST" "$node_a_ssh" "$NODE_A_HARDWARE" "$node_a_role" "$node_a_opa_port" "${REDIS_DATABASES_0:-1}" &
LAUNCH_PIDS+=($!)
launch_node node-b "$NODE_B_HOST" "$node_b_ssh" "$NODE_B_HARDWARE" "$node_b_role" "$node_b_opa_port" "${REDIS_DATABASES_1:-2}" &
LAUNCH_PIDS+=($!)
launch_node node-c "$NODE_C_HOST" "$node_c_ssh" "$NODE_C_HARDWARE" "$node_c_role" "$node_c_opa_port" "${REDIS_DATABASES_2:-3}" &
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

# ---- wait for completion (bounded 5h; signal = layer1/comparison_results.csv) ----
completed_nodes=0
deadline=$(( $(date +%s) + 5*3600 ))
while (( $(date +%s) < deadline )); do
    completed_nodes=0
    for node_id in node-a node-b node-c; do
        ssh_user="$(case $node_id in node-a) printf %s "$node_a_ssh";; node-b) printf %s "$node_b_ssh";; node-c) printf %s "$node_c_ssh";; esac)"
        host="$(case $node_id in node-a) printf %s "$NODE_A_HOST";; node-b) printf %s "$NODE_B_HOST";; node-c) printf %s "$NODE_C_HOST";; esac)"
        if ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_user@$host" \
                "ls /tmp/astral-cluster-comparison/${run_id}/${node_id}/benchmark-results/comparison-*/layer1/comparison_results.csv >/dev/null 2>&1" 2>/dev/null; then
            completed_nodes=$((completed_nodes + 1))
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
            "$ssh_user@$host:/tmp/astral-cluster-comparison/${run_id}/${node_id}/benchmark-results" "$local_dir/raw/"; then
        if [[ -z "$report_list" ]]; then
            report_list="\"$node_id/raw/benchmark-results\""
        else
            report_list="$report_list, \"$node_id/raw/benchmark-results\""
        fi
    else
        write_aborted_marker "$campaign_dir" "COLLECT_FAILED:$node_id"
        exit 78
    fi
done

jar_sha256="$(sha256_file "$JAR_PATH")"
printf '{\n  "formatVersion": 1,\n  "status": "COMPLETE",\n  "protocolVersion": "%s",\n  "runId": "%s",\n  "replicates": %s,\n  "permutation": %s,\n  "nodeRoles": {"node-a": "%s", "node-b": "%s", "node-c": "%s"},\n  "hardwareLabels": {"node-a": "%s", "node-b": "%s", "node-c": "%s"},\n  "opaPorts": {"node-a": "%s", "node-b": "%s", "node-c": "%s"},\n  "outputPaths": [%s],\n  "jarSha256": "%s",\n  "benchmarkEnvId": "%s"\n}\n' \
    "$protocol_version" "$run_id" "$replicates" "$permutation" \
    "$node_a_role" "$node_b_role" "$node_c_role" \
    "$NODE_A_HARDWARE" "$NODE_B_HARDWARE" "$NODE_C_HARDWARE" \
    "$node_a_opa_port" "$node_b_opa_port" "$node_c_opa_port" \
    "$report_list" "$jar_sha256" "$(json_escape "$BENCHMARK_ENV_ID")" \
    > "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp"
mv -f "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp" "$campaign_dir/ATTEMPT_COMPLETE.json"

find "$campaign_dir" -type f ! -name checksums.sha256 -print0 \
    | sort -z | xargs -0 sha256sum > "$campaign_dir/checksums.sha256"

printf 'Cluster comparison campaign COMPLETE. Artifacts: %s\n' "$campaign_dir"
exit 0
