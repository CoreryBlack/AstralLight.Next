#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TLC_IMAGE="${TDSC_TLC_IMAGE:?TDSC_TLC_IMAGE must reference an immutable TLC image digest}"
RUN_ID="${TDSC_TLC_RUN_ID:-$(git -C "${REPO_DIR}" rev-parse --short=12 HEAD)-$(date -u +%Y%m%dT%H%M%SZ)}"
RESULT_DIR="${SCRIPT_DIR}/results/${RUN_ID}"

if [[ "${TLC_IMAGE}" != *@sha256:* ]]; then
  printf 'TDSC_TLC_IMAGE must be pinned by immutable image digest.\n' >&2
  exit 2
fi

if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  printf 'TDSC_TLC_RUN_ID has invalid characters.\n' >&2
  exit 2
fi

if [[ -e "${RESULT_DIR}" ]]; then
  printf 'Result directory already exists: %s\n' "${RESULT_DIR}" >&2
  exit 2
fi

mkdir -p "${RESULT_DIR}"
cp "${SCRIPT_DIR}/DualCard.tla" "${RESULT_DIR}/DualCard.tla"
cp "${SCRIPT_DIR}/DualCard.cfg" "${RESULT_DIR}/DualCard.cfg"

command=(java -XX:+UseParallelGC -cp /opt/tla2tools.jar tlc2.TLC -config DualCard.cfg DualCard.tla)
printf '%q ' "${command[@]}" > "${RESULT_DIR}/command.txt"
printf '\n' >> "${RESULT_DIR}/command.txt"
printf '%s\n' "${TLC_IMAGE}" > "${RESULT_DIR}/image.txt"
git -C "${REPO_DIR}" rev-parse HEAD > "${RESULT_DIR}/git-commit.txt"
git -C "${REPO_DIR}" status --porcelain > "${RESULT_DIR}/git-status.txt"

set +e
docker run --rm \
  --mount "type=bind,src=${RESULT_DIR},dst=/spec,readonly" \
  --workdir /spec \
  "${TLC_IMAGE}" \
  -config DualCard.cfg DualCard.tla \
  > "${RESULT_DIR}/tlc.stdout" 2> "${RESULT_DIR}/tlc.stderr"
exit_code=$?
set -e
printf '%s\n' "${exit_code}" > "${RESULT_DIR}/exit-code.txt"
sha256sum "${RESULT_DIR}"/* > "${RESULT_DIR}/sha256sums.txt"

if [[ ${exit_code} -ne 0 ]]; then
  printf 'TLC failed; inspect %s.\n' "${RESULT_DIR}" >&2
  exit "${exit_code}"
fi

printf 'TLC completed successfully: %s\n' "${RESULT_DIR}"
