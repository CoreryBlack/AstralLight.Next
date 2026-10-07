#!/usr/bin/env bash
# 多租户混合极限套件 —— 部署形态矩阵驱动(按需)。
#
# 诚实边界(不要为覆盖面好看而虚报维度):
#   可在测试层参数化的维度只有 **部署形态**:
#     default       默认特性构建 + 基线 env(Redis-free 语义)
#     redis-compat  redis-compat 联合特性构建 + compat 旗标开启
#   其余架构开关不可在测试层参数化:
#     - astral-single-node 的 memory hub 安装是代码路径(组合进程启动期);
#     - ASTRAL_ORG_SCOPE_ENABLED 是仓储构造期旗标(MT 套件不构造仓储);
#     上述两者的专项覆盖见 MANIFEST 中 unit-inline 与 security 条目。
#
# 用法:
#   source 与 run-tests.sh 相同的 env(DATABASE_URL 等),然后:
#   bash tests-suite/matrix/run-mt-matrix.sh                     # 两个形态全跑
#   bash tests-suite/matrix/run-mt-matrix.sh --profile default   # 仅默认形态
#   bash tests-suite/matrix/run-mt-matrix.sh \
#        --suites "mt_extreme_isolation mt_extreme_churn"        # 指定套件
#
# 失败语义:任一套件任一形态非零 → 脚本非零退出(不吞错、不折算 PASS)。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_DIR"

PROFILE_FILTER=""
SUITES="mt_extreme_isolation mt_extreme_churn mt_extreme_cross_storm mt_extreme_failclosed mt_extreme_capacity"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE_FILTER="$2"; shift 2 ;;
    --suites)  SUITES="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${ASTRAL_MIGRATION_ENV:=isolated}"
: "${RUST_INTEGRATION_REQUIRED:=1}"
export ASTRAL_MIGRATION_ENV RUST_INTEGRATION_REQUIRED

run_profile() {
  local profile="$1"
  local features=""
  local envs=(env "RUST_INTEGRATION_REQUIRED=1")
  if [ "$profile" = "redis-compat" ]; then
    : "${REDIS_URL:?REDIS_URL is required for the redis-compat profile}"
    : "${ASTRAL_REDIS_PROJECTION_COMPAT:=true}"
    features="--features redis-compat"
    envs+=("ASTRAL_REDIS_PROJECTION_COMPAT=$ASTRAL_REDIS_PROJECTION_COMPAT")
  fi
  echo "=== profile=$profile suites=[$SUITES] ==="
  # shellcheck disable=SC2086
  env "${envs[@]}" cargo test -p testsuite $features --test '*' -- --ignored --nocapture --test-threads=1
}

declare -a FAILED=()
for profile in default redis-compat; do
  if [ -n "$PROFILE_FILTER" ] && [ "$PROFILE_FILTER" != "$profile" ]; then
    continue
  fi
  if ! run_profile "$profile"; then
    FAILED+=("$profile")
  fi
done

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "[mt-matrix] FAILED profiles: ${FAILED[*]}" >&2
  exit 1
fi
echo "[mt-matrix] all requested profiles passed"
