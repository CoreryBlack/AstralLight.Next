#!/usr/bin/env bash
# ORG_SCOPE 行政授权链 preflight / rollback（DB owner 切片，多租户改造 Phase 2）。
#
# 用途：
#   preflight — 应用/校验 20260922000001_org_scope_authority.sql 前后的只读检查：
#               1) 汇报 `_sqlx_migrations` 是否记录版本 20260922000001；
#               2) 校验全部 13 张 org_scope_* 表存在/缺失的一致性（部分 schema = 失败）；
#               3) 汇报受管租户数与 org outbox 各状态计数（PENDING/LEASED/FAILED/DONE）。
#               只读：不应用迁移、不执行任何 DDL/DML、不产生 durable 副作用。
#   rollback  — 破坏性操作：DROP 全部 org_scope_* 表及其数据。发出任何 DROP 之前，
#               必须校验每一张 org_scope_* 表均为空（受管租户为 0、outbox 无
#               PENDING/LEASED 事件——行计数覆盖全部表，不止 org_scope_node）；
#               任一表有数据即整体拒绝。**不会**删除 `_sqlx_migrations` 的迁移
#               历史行：回滚后直接重跑同一 version 会被 sqlx 跳过，绝不把它当作
#               "重新迁移"。恢复只能走备份恢复，或另立、审查并应用新的 forward
#               migration。仅在满足 Exec-L3 批准、备份/恢复演练完成等全部安全前置时
#               允许执行，且必须显式传入 --i-understand-data-loss。
#
# 凭据一律经环境变量注入（禁止硬编码，规范 §16.1）：
#   ORG_MYSQL_URL  TCP URI，例如 mysql://user:pass@host:3306/dbname。
#                  用户名、密码或库名中的保留字符必须 percent-encode；query/fragment
#                  不被本脚本静默忽略，而是 fail-closed 拒绝。
#
# 用法：
#   ORG_MYSQL_URL=... bash scripts/org_scope_preflight.sh preflight
#   ORG_MYSQL_URL=... bash scripts/org_scope_preflight.sh rollback --i-understand-data-loss
#
# 依赖：mysql 客户端（执行 preflight/rollback）；self-test 只需 Bash。
# 本脚本不应用迁移；应用迁移是 Exec-L3 运维动作，必须走既有显式迁移入口。
# 详见 Docs/迁移/ORG_SCOPE迁移与回滚操作手册_V0.1.md。

set -euo pipefail

# 迁移版本：与 migrations/20260922000001_org_scope_authority.sql 一致。源码侧同名
# 基准是 astral-db/src/migration.rs 测试模块（#[cfg(test)]）中的
# ORG_SCOPE_AUTHORITY_VERSION——它仅由测试用于断言内嵌 migrator 的链尾与迁移在列，
# 不是生产代码常量；生产侧应用入口仍是 apply_migrations（sqlx 内嵌 migrator，
# 成功记录写入 _sqlx_migrations，由本脚本 preflight 只读核验）。
readonly ORG_MIGRATION_VERSION=20260922000001
readonly SQLX_MIGRATIONS_TABLE="_sqlx_migrations"

# 表名只允许来自这份硬编码清单；所有 SQL 均为固定语句，除清单内表名外
# 不拼接任何用户输入。
ORG_TABLES=(
  org_scope_node
  org_scope_request
  org_scope_grant
  org_scope_revision
  org_scope_mask
  org_scope_membership
  org_scope_publication
  org_scope_segment
  org_scope_current
  org_scope_outbox
  org_scope_dependency
  org_scope_operation
  org_scope_audit
)

die() { echo "org_scope_preflight: $*" >&2; exit 1; }

MYSQL_ARGS=()
MYSQL_PASSWORD=""

require_client() {
  command -v mysql >/dev/null 2>&1 || die "mysql client not available; refusing to run"
}

decode_uri_component() {
  local encoded="$1" decoded="" char hex byte decimal
  while [[ -n "${encoded}" ]]; do
    char="${encoded:0:1}"
    if [[ "${char}" == "%" ]]; then
      [[ ${#encoded} -ge 3 ]] || return 1
      hex="${encoded:1:2}"
      [[ "${hex}" =~ ^[[:xdigit:]]{2}$ ]] || return 1
      decimal=$((16#${hex}))
      (( decimal != 0 && decimal >= 32 && decimal != 127 )) || return 1
      printf -v byte '%b' "\\x${hex}"
      decoded+="${byte}"
      encoded="${encoded:3}"
    else
      [[ "${char}" =~ ^[A-Za-z0-9._~-]$ ]] || return 1
      decoded+="${char}"
      encoded="${encoded:1}"
    fi
  done
  printf '%s' "${decoded}"
}

parse_mysql_uri() {
  local raw="${ORG_MYSQL_URL:-}" rest authority credentials hostport path
  local user_encoded password_encoded database_encoded host port port_number tail
  local user password database

  [[ "${raw}" == mysql://* ]] || return 1
  rest="${raw#mysql://}"
  [[ "${rest}" != *"?"* && "${rest}" != *"#"* && "${rest}" == */* ]] || return 1
  authority="${rest%%/*}"
  path="${rest#*/}"
  [[ -n "${authority}" && -n "${path}" && "${path}" != */* && "${authority}" == *@* && "${authority#*@}" != *@* ]] || return 1

  credentials="${authority%%@*}"
  hostport="${authority#*@}"
  [[ "${hostport}" != *@* && "${credentials}" == *:* ]] || return 1
  user_encoded="${credentials%%:*}"
  password_encoded="${credentials#*:}"
  database_encoded="${path}"
  [[ "${password_encoded}" != *:* ]] || return 1

  user=$(decode_uri_component "${user_encoded}") || return 1
  password=$(decode_uri_component "${password_encoded}") || return 1
  database=$(decode_uri_component "${database_encoded}") || return 1
  [[ -n "${user}" && -n "${database}" && "${database}" != */* ]] || return 1
  case "${database}" in
    astral_test|astral_rehearsal) ;;
    *) return 1 ;;
  esac

  if [[ "${hostport}" == \[* ]]; then
    host="${hostport#\[}"
    [[ "${host}" == *"]"* ]] || return 1
    tail="${host#*]}"
    host="${host%%]*}"
    [[ -n "${host}" && "${host}" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    if [[ -n "${tail}" ]]; then
      [[ "${tail}" == :* ]] || return 1
      port="${tail#:}"
    else
      port=3306
    fi
  else
    if [[ "${hostport}" == *:* ]]; then
      host="${hostport%:*}"
      port="${hostport##*:}"
    else
      host="${hostport}"
      port=3306
    fi
    [[ -n "${host}" && "${host}" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  fi

  case "${host}" in
    localhost|LOCALHOST|Localhost|127.0.0.1|::1) ;;
    *) return 1 ;;
  esac
  [[ "${port}" =~ ^[0-9]{1,5}$ ]] || return 1
  port_number=$((10#${port}))
  (( port_number >= 1 && port_number <= 65535 )) || return 1

  MYSQL_ARGS=(
    --protocol=TCP
    "--host=${host}"
    "--port=${port}"
    "--user=${user}"
    "--database=${database}"
  )
  MYSQL_PASSWORD="${password}"
}

load_mysql_connection() {
  ((${#MYSQL_ARGS[@]} == 0)) || return
  parse_mysql_uri || die "ORG_MYSQL_URL must be a valid mysql://user:percent-encoded-password@host:port/database URI without query or fragment"
}

self_test_connection_parser() {
  local invalid
  ORG_MYSQL_URL='mysql://test%40user:p%40ss%3Aword@127.0.0.1:3308/astral_test'
  MYSQL_ARGS=()
  MYSQL_PASSWORD=""
  parse_mysql_uri || die "connection parser self-test rejected a valid URI"
  [[ "${MYSQL_ARGS[*]}" == "--protocol=TCP --host=127.0.0.1 --port=3308 --user=test@user --database=astral_test" ]] \
    || die "connection parser self-test produced incorrect client arguments"
  [[ "${MYSQL_PASSWORD}" == "p@ss:word" ]] || die "connection parser self-test produced incorrect password"

  for invalid in \
    'mysql://user:pass@localhost/db?ssl-mode=REQUIRED' \
    'mysql://user:pass@db.example:3308/astral_test' \
    'mysql://user:pass@localhost:3308/production' \
    'mysql://user:bad%0apass@localhost/db' \
    'mysql://user:pass@localhost/db/child' \
    'mysql://user:pass:word@localhost/db' \
    'mysql://user:p@ss@localhost/db' \
    'postgres://user:pass@localhost/db'; do
    MYSQL_ARGS=()
    MYSQL_PASSWORD=""
    if ORG_MYSQL_URL="${invalid}" parse_mysql_uri; then
      die "connection parser self-test accepted an invalid URI"
    fi
  done
  echo "org_scope_preflight: connection parser self-test passed"
}

run_sql() {
  # Password is supplied through MYSQL_PWD, never as a mysql process argument.
  load_mysql_connection
  MYSQL_PWD="${MYSQL_PASSWORD}" mysql --batch --skip-column-names \
    "${MYSQL_ARGS[@]}" -e "$1"
}


table_exists() {
  # $1 必须是脚本内固定表名（ORG_TABLES 清单或 SQLX_MIGRATIONS_TABLE）。
  local count
  count=$(run_sql "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '$1'")
  [[ "${count}" -gt 0 ]]
}

table_row_count() {
  # 仅接受 ORG_TABLES 硬编码清单内的表名，防止拼接任意表名。
  local table="$1" known t
  known=0
  for t in "${ORG_TABLES[@]}"; do
    if [[ "${t}" == "${table}" ]]; then
      known=1
    fi
  done
  if [[ "${known}" -ne 1 ]]; then
    die "internal error: '${table}' is not in the hardcoded ORG_TABLES list"
  fi
  run_sql "SELECT COUNT(*) FROM ${table}"
}

membership_cap_index_present() {
  # 固定索引名/列序：per-user active membership cap 的 user-range lock 依赖该索引，
  # 缺失或列序漂移均不得报告 schema 可用于启用。
  local columns
  columns=$(run_sql "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',') FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_scope_membership' AND INDEX_NAME = 'idx_osmem_user_active'")
  [[ "${columns}" == "user_id,active" ]]
}

membership_card_index_present() {
  # 卡级唯一性检查必须走 card-leading index；容量锁与卡锁不能因优化器选错索引而
  # 退化成未证明的扫描。
  local columns
  columns=$(run_sql "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',') FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_scope_membership' AND INDEX_NAME = 'idx_osmem_card'")
  [[ "${columns}" == "card_id,active" ]]
}

identity_card_user_anchor_present() {
  # `uk_ic_user(user_id)` 是 active-membership cap 的单行同用户串行锚点；只有
  # 精确唯一形状才可使 READ COMMITTED 下的容量检查独立于 gap-lock 语义。
  local count unique_count columns
  count=$(run_sql "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'identity_card' AND INDEX_NAME = 'uk_ic_user'")
  unique_count=$(run_sql "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'identity_card' AND INDEX_NAME = 'uk_ic_user' AND NON_UNIQUE = 0")
  columns=$(run_sql "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',') FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'identity_card' AND INDEX_NAME = 'uk_ic_user'")
  [[ "${count}" == "1" && "${unique_count}" == "1" && "${columns}" == "user_id" ]]
}

migration_recorded() {
  # 只读汇报：`_sqlx_migrations` 是否记录 ORG_MIGRATION_VERSION。
  # 输出 recorded / missing / unknown（unknown = _sqlx_migrations 表不存在）。
  if ! table_exists "${SQLX_MIGRATIONS_TABLE}"; then
    echo "unknown"
    return 0
  fi
  local count
  count=$(run_sql "SELECT COUNT(*) FROM ${SQLX_MIGRATIONS_TABLE} WHERE version = ${ORG_MIGRATION_VERSION}")
  if [[ "${count}" -gt 0 ]]; then
    echo "recorded"
  else
    echo "missing"
  fi
}

managed_tenant_count() {
  run_sql "SELECT COUNT(*) FROM org_scope_node"
}

outbox_status_counts() {
  # 单行固定 SQL，恒返回四个状态计数（MySQL 布尔求和；空表 COALESCE 归 0）。
  # 表外出现未知状态时由 unknown= 尾列暴露，不静默吞掉。
  run_sql "SELECT CONCAT('PENDING=', COALESCE(SUM(status = 'PENDING'), 0), \
' LEASED=', COALESCE(SUM(status = 'LEASED'), 0), \
' FAILED=', COALESCE(SUM(status = 'FAILED'), 0), \
' DONE=', COALESCE(SUM(status = 'DONE'), 0), \
' unknown=', COALESCE(SUM(status NOT IN ('PENDING', 'LEASED', 'FAILED', 'DONE')), 0)) \
FROM org_scope_outbox"
}

outbox_pending_or_leased() {
  run_sql "SELECT COUNT(*) FROM org_scope_outbox WHERE status IN ('PENDING', 'LEASED')"
}

preflight() {
  require_client
  echo "== ORG_SCOPE preflight (read-only) =="
  local record
  record=$(migration_recorded)
  case "${record}" in
    recorded) echo "  [ok]      ${SQLX_MIGRATIONS_TABLE} records version ${ORG_MIGRATION_VERSION}" ;;
    missing)  echo "  [missing] ${SQLX_MIGRATIONS_TABLE} does not record version ${ORG_MIGRATION_VERSION} (not applied via the embedded migrator)" ;;
    unknown)  echo "  [unknown] ${SQLX_MIGRATIONS_TABLE} table absent; migration record unknown" ;;
  esac
  local missing=0 table
  for table in "${ORG_TABLES[@]}"; do
    if table_exists "${table}"; then
      echo "  [ok]      ${table} present"
    else
      echo "  [missing] ${table}"
      missing=$((missing + 1))
    fi
  done
  if [[ ${missing} -eq ${#ORG_TABLES[@]} ]]; then
    if [[ "${record}" == "recorded" ]]; then
      die "incoherent state: migration ${ORG_MIGRATION_VERSION} is recorded but all ${#ORG_TABLES[@]} org_scope_* tables are absent; investigate before continuing"
    fi
    echo "  schema state: UNMANAGED (feature never activated; legacy behavior is correct)"
    echo "== preflight complete =="
    exit 0
  fi
  if [[ ${missing} -gt 0 ]]; then
    die "partial schema state detected (${missing}/${#ORG_TABLES[@]} tables missing); repair via migration before continuing"
  fi
  if ! membership_cap_index_present; then
    die "org_scope_membership missing required idx_osmem_user_active(user_id,active); refusing to treat schema as managed-capable"
  fi
  if ! membership_card_index_present; then
    die "org_scope_membership missing required idx_osmem_card(card_id,active); refusing to treat schema as managed-capable"
  fi
  if ! identity_card_user_anchor_present; then
    die "identity_card missing required unique uk_ic_user(user_id) membership-cap serialization anchor; refusing to treat schema as managed-capable"
  fi
  echo "  [ok]      org_scope_membership idx_osmem_user_active(user_id,active)"
  echo "  [ok]      org_scope_membership idx_osmem_card(card_id,active)"
  echo "  [ok]      identity_card uk_ic_user(user_id) unique membership-cap anchor"
  echo "  schema state: MANAGED-CAPABLE"
  if [[ "${record}" != "recorded" ]]; then
    echo "  [warn]    org_scope_* tables exist but ${SQLX_MIGRATIONS_TABLE} record is ${record}; schema may have been created out-of-band"
  fi
  local managed
  managed=$(managed_tenant_count)
  echo "  managed tenants: ${managed}"
  local statuses backlog
  statuses=$(outbox_status_counts)
  echo "  org outbox status counts: ${statuses}"
  backlog=$(outbox_pending_or_leased)
  echo "  org outbox backlog (PENDING/LEASED): ${backlog}"
  if [[ "${managed}" -gt 0 ]]; then
    echo "  note: managed tenants exist — ASTRAL_ORG_SCOPE_ENABLED=false must DENY their branches (no legacy fallback)"
  fi
  echo "== preflight complete =="
}

rollback() {
  require_client
  [[ "${1:-}" == "--i-understand-data-loss" ]] || die "rollback requires the explicit flag --i-understand-data-loss"
  echo "== ORG_SCOPE rollback (DESTRUCTIVE) =="
  echo "  preconditions: Exec-L3 approval + completed backup/recovery rehearsal; see Docs/迁移/ORG_SCOPE迁移与回滚操作手册_V0.1.md"
  # 第一步：发出任何 DROP 之前，校验全部 13 张表（存在的那些）行数均为 0。
  # 不只检查 org_scope_node：grants/masks/memberships/outbox（含 PENDING/LEASED
  # 事件）等任何残留数据都必须先撤离/排水，否则整体拒绝。
  local dirty=0 table count
  for table in "${ORG_TABLES[@]}"; do
    if table_exists "${table}"; then
      count=$(table_row_count "${table}")
      echo "  guard ${table}: ${count} row(s)"
      if [[ "${count}" -gt 0 ]]; then
        dirty=$((dirty + 1))
      fi
    else
      echo "  guard ${table}: absent"
    fi
  done
  if table_exists "org_scope_outbox"; then
    echo "  guard org_scope_outbox status counts: $(outbox_status_counts)"
    echo "  guard outbox pending/leased events: $(outbox_pending_or_leased)"
  fi
  if [[ ${dirty} -gt 0 ]]; then
    die "refusing to drop: ${dirty} org_scope_* table(s) still hold rows; managed tenants and pending/leased outbox events must be zero — evacuate and drain first"
  fi
  # 第二步：全部表初检为空后逐表重新计数，再允许 DROP。第一次全表扫描
  # 防止部分 schema 的数据被遗漏；每次 DROP 前的第二次检查缩短检查与破坏动作
  # 之间的窗口。DDL 不能纳入事务，因此 Exec-L3 前置仍要求关闭所有 ORG writer /
  # projector / 服务实例，禁止并发 source mutation；脚本绝不把该运维约束伪装成
  # 数据库原子性。
  for table in "${ORG_TABLES[@]}"; do
    if table_exists "${table}"; then
      count=$(table_row_count "${table}")
      echo "  recheck ${table}: ${count} row(s)"
      if [[ "${count}" -gt 0 ]]; then
        die "refusing to drop: ${table} gained rows after the rollback guard; stop all ORG writers/workers and re-run preflight"
      fi
      echo "  dropping ${table}"
      run_sql "DROP TABLE IF EXISTS ${table}"
    else
      echo "  absent  ${table}"
    fi
  done
  echo "== rollback complete; migration version remains recorded; keep ASTRAL_ORG_SCOPE_ENABLED=false. Do not rerun 20260922000001: restore a backup or use a newly reviewed forward migration for recovery =="
}

case "${1:-}" in
  preflight) preflight ;;
  rollback) shift; rollback "$@" ;;
  self-test) self_test_connection_parser ;;
  *) die "usage: $0 preflight | rollback --i-understand-data-loss | self-test" ;;
esac
