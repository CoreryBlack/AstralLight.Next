#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"
RUN_ID="${TDSC_RUN_ID:?}"
RESULT_DIR="${SCRIPT_DIR}/results/${RUN_ID}"
RUN_MODE="${1:-protocol}"

if [[ "${RUN_MODE}" != "protocol" && "${RUN_MODE}" != "comparison" \
    && "${RUN_MODE}" != "fault" && "${RUN_MODE}" != "performance" && "${RUN_MODE}" != "lease" ]]; then
  printf 'Usage: %s [protocol|comparison|fault|performance|lease]\n' "$0" >&2
  exit 2
fi

if [[ "${RUN_MODE}" == "comparison" ]]; then
  printf 'Comparison mode has no versioned comparison workload; refusing to create completed evidence.\n' >&2
  exit 2
fi

"${SCRIPT_DIR}/preflight.sh"

if [[ -e "${RESULT_DIR}" ]]; then
  printf 'Evidence directory already exists: %s\n' "${RESULT_DIR}" >&2
  exit 4
fi

mkdir -p "${RESULT_DIR}"
INIT_DIR="${RESULT_DIR}/mysql-init"
mkdir -p "${INIT_DIR}"
python3 - "${REPO_DIR}/Docs/sql/full_schema_v4.sql" "${INIT_DIR}/00-full-schema.sql" "${TDSC_DB_NAME}" <<'PY'
import pathlib
import sys

source, target, database = map(pathlib.Path, sys.argv[1:4])
if not str(database).replace("_", "").isalnum():
    raise SystemExit("TDSC_DB_NAME must be alphanumeric with optional underscores")
target.write_text(source.read_text(encoding="utf-8").replace("platform_v4", str(database)), encoding="utf-8")
PY
cp "${REPO_DIR}/Docs/sql/migration_auth_session_resilience.sql" "${INIT_DIR}/10-session-resilience.sql"
export TDSC_SCHEMA_INIT_DIR="${INIT_DIR}"
status_file="${RESULT_DIR}/status.txt"
printf 'RUNNING\n' > "${status_file}"

cleanup() {
  local exit_code=$?
  if [[ "${TDSC_KEEP_CONTAINERS:-false}" != "true" ]]; then
    docker compose --project-name "${TDSC_COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
      --profile "${RUN_MODE}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ ${exit_code} -eq 0 ]]; then
    printf 'COMPLETED\n' > "${status_file}"
  else
    printf 'FAILED exit_code=%s\n' "${exit_code}" > "${status_file}"
  fi
  find "${RESULT_DIR}" -type f ! -name sha256sums.txt -print0 | sort -z \
    | xargs -0 sha256sum > "${RESULT_DIR}/sha256sums.txt"
  exit "${exit_code}"
}
trap cleanup EXIT

write_manifest() {
  python3 - "${RESULT_DIR}/run-manifest.json" <<'PY'
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone

manifest_path = sys.argv[1]
repo = os.environ["REPO_DIR"]
images = {
    name: os.environ[name]
    for name in (
        "TDSC_MYSQL_IMAGE", "TDSC_REDIS_IMAGE", "TDSC_RABBITMQ_IMAGE", "TDSC_OPA_IMAGE",
        "TDSC_IDENTITY_IMAGE", "TDSC_TRUSTGRAPH_IMAGE", "TDSC_LEARN_IMAGE",
        "TDSC_GATEWAY_IMAGE", "TDSC_PROTOCOL_RUNNER_IMAGE",
    )
}

def command(*args):
    return subprocess.check_output(args, cwd=repo, text=True).strip()

manifest = {
    "formatVersion": 1,
    "runId": os.environ["TDSC_RUN_ID"],
    "runMode": os.environ["RUN_MODE"],
    "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
    "seed": int(os.environ["TDSC_SEED"]),
    "gitCommit": command("git", "rev-parse", "HEAD"),
    "gitDirty": bool(command("git", "status", "--porcelain")),
    "images": images,
    "resources": {
        "serviceCpuset": os.environ["TDSC_SERVICE_CPUSET"],
        "runnerCpuset": os.environ["TDSC_RUNNER_CPUSET"],
        "memoryLimits": {
            "mysql": os.environ["TDSC_MYSQL_MEMORY_LIMIT"],
            "redis": os.environ["TDSC_REDIS_MEMORY_LIMIT"],
            "rabbitmq": os.environ["TDSC_RABBITMQ_MEMORY_LIMIT"],
            "identity": os.environ["TDSC_IDENTITY_MEMORY_LIMIT"],
            "trustgraph": os.environ["TDSC_TRUSTGRAPH_MEMORY_LIMIT"],
            "learn": os.environ["TDSC_LEARN_MEMORY_LIMIT"],
            "gateway": os.environ["TDSC_GATEWAY_MEMORY_LIMIT"],
            "runner": os.environ["TDSC_RUNNER_MEMORY_LIMIT"],
            "opa": os.environ["TDSC_OPA_MEMORY_LIMIT"],
        },
    },
    "host": {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpuCount": os.cpu_count(),
    },
    "inputSha256": {},
}
for relative_path in (
    "experiments/tdsc/compose.yml",
    "experiments/tdsc/protocol-runner/Dockerfile",
    "experiments/tdsc/protocol-runner/run-protocol.sh",
    "experiments/tdsc/protocol-runner/run-performance.py",
    "experiments/tdsc/run-performance.sh",
    "experiments/tdsc/run-fault.sh",
    "experiments/tdsc/run-fault-host.sh",
    "experiments/tdsc/run-lease-probe.sh",
    "experiments/tdsc/run-lease-host.sh",
    "Docs/sql/full_schema_v4.sql",
    "Docs/sql/migration_auth_session_resilience.sql",
):
    manifest["inputSha256"][relative_path] = command("git", "hash-object", relative_path)
with open(manifest_path, "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

export REPO_DIR RUN_MODE
write_manifest

COMPOSE_PROFILES=(--profile workload)
if [[ "${RUN_MODE}" == "lease" ]]; then
  : "${TDSC_POST_CLAIM_GATE_NONCE:?TDSC_POST_CLAIM_GATE_NONCE is required for lease mode}"
  export TDSC_IDENTITY_PROJECTION_JOB_ENABLED=false
  export TDSC_IDENTITY_PROJECTION_INLINE_ENABLED=false
  COMPOSE_PROFILES+=(--profile multi-node)
fi

docker compose --project-name "${TDSC_COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
  "${COMPOSE_PROFILES[@]}" pull --quiet

docker compose --project-name "${TDSC_COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
  "${COMPOSE_PROFILES[@]}" up --detach --wait --wait-timeout "${TDSC_WAIT_TIMEOUT_SECONDS:-240}"

docker compose --project-name "${TDSC_COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
  "${COMPOSE_PROFILES[@]}" ps --format json > "${RESULT_DIR}/compose-status.json"

if [[ "${RUN_MODE}" == "protocol" ]]; then
  docker compose --project-name "${TDSC_COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
    --profile workload run --rm protocol-runner
elif [[ "${RUN_MODE}" == "fault" ]]; then
  TDSC_RESULT_DIR="${RESULT_DIR}" "${SCRIPT_DIR}/run-fault-host.sh"
elif [[ "${RUN_MODE}" == "performance" ]]; then
  cp "${SCRIPT_DIR}/run-performance.sh" "${RESULT_DIR}/run-performance.sh"
  cp "${SCRIPT_DIR}/protocol-runner/run-performance.py" "${RESULT_DIR}/run-performance.py"
  docker compose --project-name "${TDSC_COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
    --profile workload run --rm \
    -v "${RESULT_DIR}/run-performance.sh:/usr/local/bin/run-performance:ro" \
    -v "${RESULT_DIR}/run-performance.py:/usr/local/bin/run-performance.py:ro" \
    -e TDSC_PERF_DRIVER_PATH=/usr/local/bin/run-performance.py \
    --entrypoint /usr/local/bin/run-performance \
    protocol-runner
elif [[ "${RUN_MODE}" == "lease" ]]; then
  TDSC_RESULT_DIR="${RESULT_DIR}" "${SCRIPT_DIR}/run-lease-host.sh"
fi
