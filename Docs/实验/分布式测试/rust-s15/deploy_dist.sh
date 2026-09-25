#!/usr/bin/env bash
# Deploy a run-scoped 3-node Rust trustgraph cluster for S1-S15 consistency +
# 3-node performance testing. Runs ON node-b (which also hosts the shared
# docker infra). All three nodes run the same release binary with a shared
# run-scoped application.yml (shared DB/Redis/RabbitMQ endpoints) and their
# own LISTEN_ADDR; each node has a pidfile + idempotent start helper.
#
# Contract (fail-closed): every secret is required from the caller env or
# freshly generated per run; nothing is echoed; config files are 0600.
# Fresh-run only: an existing run directory, database, Redis container, Rabbit
# vhost, or occupied target port is a hard preflight failure. A partial failure
# must be reconciled explicitly before any retry.
#
# Required env:
#   MYSQL_ROOT        shared mysql root password (container astral_bench_mysql)
#   RABBIT_USER       rabbit user for the run vhost
#   RABBIT_PASS       rabbit password for the run vhost
#   SNAP_BIN          source release binary (explicit, no implicit default —
#                     provenance requires pinning exactly which binary is measured)
#   BOOTSTRAP_BIN     e2e-bootstrap binary (explicit, no implicit default and
#                     NO silent skip — card evidence bootstrap is mandatory for
#                     the readiness probe; SHA-256 recorded in provenance)
#   SOURCE_SNAPSHOT_SHA256  source snapshot identity provided by the build
#                     mainline (sha256 over the source snapshot that produced
#                     SNAP_BIN；最终构建使用 git ls-files 白名单快照).
#                     REQUIRED — 本脚本不在 node-b 上自行推算（run
#                     source snapshot 由主线负责）；缺失即失败退出。
#   SOURCE_GIT_REV    source git rev the snapshot was built from（主线显式
#                     提供；tracked-only 溯源字段，不得由无 .git 的解压目录
#                     猜测为空）。REQUIRED。
#   SOURCE_DIRTY_PATCH_SHA256  脏树快照必填：dirty diff/patch 的 sha256（64
#                     hex）；干净树传 none/null/clean（存储为 null）。REQUIRED，
#                     缺失即失败退出（不猜测）。
#   NODE_A_SSH        node-a 的 ssh 目标 [user@]host。REQUIRED（L1：不得内置
#                     服务器 IP / ssh 用户默认值）。
#   NODE_C_SSH        node-c 的 ssh 目标 [user@]host。REQUIRED（L1）。
#   MYSQL_HOST        共享 mysql host:port。REQUIRED（L1：无默认 IP；仅允许单
#                     冒号，host 段 [A-Za-z0-9._-]，端口为数字）。
#   NODE_A_ADVERTISE_HOST  node-b -> node-a 的 HTTP host。REQUIRED（L1）。
#   NODE_C_ADVERTISE_HOST  node-b -> node-c 的 HTTP host。REQUIRED（L1）。
#                     （node-b 本机运行，无需 NODE_B_SSH。）
# Optional env (defaults):
#   RUN_ID            rust3n-dist-<date>（shape 校验：字母/数字开头，其后仅
#                     [A-Za-z0-9._-] —— RUN_ID 会进入容器名、远端路径与 ssh
#                     命令串，先白名单再使用）
#   DIST_DB_NAME      run database name (default contains "test" per migration
#                     gate; explicit overrides are validated the same way —
#                     先过 [A-Za-z0-9_] 白名单再拼任何 SQL)
#   REDIS_PORT        host port for the run-scoped redis (default 16382 — do
#                     not squat 16381, which belongs to a preserved old run;
#                     显式传 16381 会被拒绝; exported to the run_config writer)
#   PORT_A/PORT_B/PORT_C  节点 HTTP 端口（默认 9115/9116/9117；显式传旧 run 的
#                     9105/9106/9107 会被拒绝 —— 旧进程在保留窗口内仍在运行）
#
# Secret handling (M-A/H): MYSQL_ROOT/RABBIT_PASS/REDIS_PASS never appear in
# any process argv — docker client argv included. MySQL access from this script
# goes through a run-scoped 0600 defaults-extra-file written INTO the shared
# container (随机文件名由容器内 mktemp 生成；removed on EXIT/INT/TERM/HUP via
# trap); passwords reach the container only via stdin pipes. The e2e-bootstrap
# DATABASE_URL is passed via child env (env is the sanctioned channel, not
# argv).
#
# Secret charset gate（preflight，绝不回显值）：所有秘钥拒绝 换行/CR/控制字符/
# 双引号/反斜杠；被直接插进 URL 的值（RABBIT_USER/RABBIT_PASS -> amqp://、生成
# 的 REDIS_PASS -> redis://）额外限定 URL 安全字符集 [A-Za-z0-9._~-]。已知残余：
# MYSQL_ROOT 仅做上述字符拒绝（cnf 双引号写法因此安全），其余 URL 特殊字符
# （@ : / # ? % 空格等）不做转义，DATABASE_URL/amqp 插值要求调用方使用受限
# 字符集；如需彻底解决请改为上游全量 URL 编码方案。
#
# application.yml: ONLY the run-scoped application.yml freshly generated into
# $BASE is written and distributed; the source tree's own application.yml (repo
# root / config dir) is never copied into $BASE — the bootstrap runs with
# cwd=$BASE and a marker guard refuses to distribute anything but the freshly
# generated run-scoped file.
#
# Outputs: $HOME/$RUN_ID/ (binary, application.yml, hmac.txt, jwt.env,
# scopes.env, redis.conf, node_start.sh, node_{a,b,c}.pid, server_{a,b,c}.log,
# provenance.json — binary sha256 + git rev(local best-effort) + source
# snapshot sha256 + source_git_rev + source dirty patch sha256 + bootstrap
# sha256 + redis preflight method (degraded marked), NO secrets)
# plus run_config.json for s15_coordinator.py / s15_perf.py (0600, node-b only,
# carries the run-scoped redis password so the harness can authenticate — the
# password is never printed or archived).
#
# Rabbit vhost: each run creates a dedicated vhost derived from RUN_ID. The
# preserved shared vhost "rust3n_dist" is never modified or deleted.
set -euo pipefail

RUN_ID="${RUN_ID:-rust3n-dist-$(date +%Y%m%d)}"
# L3 shape gate：RUN_ID 会拼接进容器名、远端 run 目录、/tmp 文件名与
# ssh 命令串 —— 仅允许以字母/数字开头、字符集 [A-Za-z0-9._-]（防命令注入与
# 路径穿越，如 ".."、带空格/分号的值）。
case "$RUN_ID" in
  *[!A-Za-z0-9._-]*|[!A-Za-z0-9]*)
    echo "RUN_ID 仅允许以字母/数字开头，字符集 [A-Za-z0-9._-]: $RUN_ID"; exit 1 ;;
esac
BASE="$HOME/$RUN_ID"
# SNAP_BIN 必须显式给出（provenance 要求钉死被测二进制；不再有隐式默认路径）。
SNAP_BIN="${SNAP_BIN:?SNAP_BIN required: path to release astral-trustgraph binary}"
[ -x "$SNAP_BIN" ] || { echo "SNAP_BIN 不存在或不可执行: $SNAP_BIN"; exit 1; }
# BOOTSTRAP_BIN 必须显式给出且必须可执行：缺失即失败，绝不静默 skip
# （全新 run 库无已发布指针，就绪探针依赖卡级 gen-1 证据）。
BOOTSTRAP_BIN="${BOOTSTRAP_BIN:?BOOTSTRAP_BIN required: path to e2e-bootstrap binary (e.g. \$(dirname SNAP_BIN)/e2e-bootstrap)}"
[ -x "$BOOTSTRAP_BIN" ] || { echo "BOOTSTRAP_BIN 不存在或不可执行: $BOOTSTRAP_BIN"; exit 1; }
# Source snapshot identity 由构建主线提供（本脚本不在 node-b 上推算；
# 最终构建使用 git ls-files 白名单快照，tracked-only）。
SOURCE_SNAPSHOT_SHA256="${SOURCE_SNAPSHOT_SHA256:?SOURCE_SNAPSHOT_SHA256 required: 由构建主线提供的源码快照身份（sha256）}"
SOURCE_SNAPSHOT_METHOD="mainline-env"
# tracked-only 溯源字段（主线显式提供，禁止由无 .git 的解压目录猜测为空）：
#   SOURCE_GIT_REV            快照对应 git rev（必填）
#   SOURCE_DIRTY_PATCH_SHA256 脏树必填 64-hex patch sha；干净树传 none/null/clean
SOURCE_GIT_REV="${SOURCE_GIT_REV:?SOURCE_GIT_REV required: 主线提供的快照源 git rev}"
SOURCE_DIRTY_PATCH_SHA256="${SOURCE_DIRTY_PATCH_SHA256:?SOURCE_DIRTY_PATCH_SHA256 required: 脏树=64hex patch sha；干净树=none/null/clean}"
SOURCE_DIRTY="false"
case "$SOURCE_DIRTY_PATCH_SHA256" in
  none|NONE|null|NULL|clean|CLEAN)
    SOURCE_DIRTY_PATCH_SHA256_NORM=""   # 干净树 → 存储为 null
    ;;
  *)
    if ! printf '%s' "$SOURCE_DIRTY_PATCH_SHA256" | grep -qE '^[0-9a-fA-F]{64}$'; then
      echo "SOURCE_DIRTY_PATCH_SHA256 必须为 64 位 sha256（脏树）或 none/null/clean（干净树）"
      exit 1
    fi
    SOURCE_DIRTY="true"
    SOURCE_DIRTY_PATCH_SHA256_NORM="$SOURCE_DIRTY_PATCH_SHA256"
    ;;
esac
# 二进制 provenance：sha256 + 从二进制所在目录向上找 .git 取 rev——此值仅为
# 本地 best-effort 参照（binary_git_rev_local），源码身份权威是主线显式传入的
# SOURCE_GIT_REV / SOURCE_SNAPSHOT_SHA256 / SOURCE_DIRTY_PATCH_SHA256；两者
# 同时可得时在 provenance 中如实记录是否一致，不一致不静默。
BIN_SHA256=$(sha256sum "$SNAP_BIN" | awk '{print $1}')
BOOTSTRAP_SHA256=$(sha256sum "$BOOTSTRAP_BIN" | awk '{print $1}')
GIT_REV=""
if command -v git >/dev/null 2>&1; then
  _prov_dir="$(cd "$(dirname "$SNAP_BIN")" && pwd)"
  while [ "$_prov_dir" != "/" ]; do
    if [ -e "$_prov_dir/.git" ]; then
      GIT_REV=$(git -C "$_prov_dir" rev-parse HEAD 2>/dev/null || true)
      break
    fi
    _prov_dir="$(dirname "$_prov_dir")"
  done
fi
# 迁移门禁：run 库名必须包含 "test"（默认名已含；显式覆盖同门禁校验）。
# L3：库名先过 [A-Za-z0-9_] 白名单，再拼进 DROP/CREATE/information_schema SQL。
DIST_DB_NAME="${DIST_DB_NAME:-astral_f4rust_dist_test_$(date +%Y%m%d)}"
case "$DIST_DB_NAME" in
  ''|*[!A-Za-z0-9_]*)
    echo "DIST_DB_NAME 仅允许字符 [A-Za-z0-9_]（SQL 拼接前置校验）"; exit 1 ;;
esac
case "$DIST_DB_NAME" in
  *test*) : ;;
  *) echo "DIST_DB_NAME 必须包含 \"test\"（迁移门禁）: $DIST_DB_NAME"; exit 1 ;;
esac
# L1：共享 mysql 地址改为必填 env（不得内置服务器 IP 默认），并做 host:port
# 形状校验（所有 mysql://、URL 构造依赖该拆分结果）。
MYSQL_HOST="${MYSQL_HOST:?MYSQL_HOST required: 共享 mysql host:port（无默认值）}"
MYSQL_HOST_ONLY="${MYSQL_HOST%%:*}"; MYSQL_PORT="${MYSQL_HOST##*:}"
case "$MYSQL_HOST" in
  *:*:*) echo "MYSQL_HOST 必须为 host:port 形式（仅一个冒号）"; exit 1 ;;
esac
case "$MYSQL_HOST_ONLY" in
  ''|*[!A-Za-z0-9._-]*) echo "MYSQL_HOST host 段仅允许 [A-Za-z0-9._-]"; exit 1 ;;
esac
case "$MYSQL_PORT" in
  ''|*[!0-9]*) echo "MYSQL_HOST port 段必须为数字"; exit 1 ;;
esac
# REDIS_PORT 可由环境显式指定；默认 16382，保留旧 run 的 16381 容器不挤占。
# L2：显式拒绝 16381 —— 该端口属于保留的旧 run，禁止新 run 复用/挤占。
REDIS_PORT="${REDIS_PORT:-16382}"
case "$REDIS_PORT" in
  16381) echo "REDIS_PORT=16381 属于保留旧 run 的端口，本脚本拒绝占用（默认 16382）"; exit 1 ;;
  ''|*[!0-9]*) echo "REDIS_PORT 必须为数字端口"; exit 1 ;;
esac
REDIS_CNAME="astral_dist_redis_${RUN_ID}"
VHOST="rust3n_dist_${RUN_ID}"
case "$VHOST" in
  *[!A-Za-z0-9._-]*|'') echo "derived VHOST shape invalid"; exit 1 ;;
  rust3n_dist) echo "shared rust3n_dist vhost is reserved"; exit 1 ;;
esac
# 派生标识与 run 级秘钥必须导出：步骤 [5/9]/[9/9] 的 python 经 os.environ 读取
# （历史缺陷：普通 shell 变量未导出 → KeyError；L1：REDIS_PORT 同样导出）。
# REDIS_PASS 为每次部署随机生成的 requirepass，仅写入 0600 的 redis.conf /
# run_config.json / 联通 application.yml，绝不打印、绝不入 provenance。
export RUN_ID REDIS_CNAME VHOST REDIS_PORT
REDIS_PASS=$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(48)))')
export REDIS_PASS
# L1：节点 ssh 目标与 node-b -> 节点 HTTP host 全部改为必填 env，不提供任何
# 服务器 IP / ssh 用户默认值；节点标签仍为 node-a/node-b/node-c。
NODE_A_SSH="${NODE_A_SSH:?NODE_A_SSH required: node-a ssh 目标 [user@]host}"
NODE_C_SSH="${NODE_C_SSH:?NODE_C_SSH required: node-c ssh 目标 [user@]host}"
NODE_A_ADVERTISE_HOST="${NODE_A_ADVERTISE_HOST:?NODE_A_ADVERTISE_HOST required: node-b -> node-a HTTP host}"
NODE_C_ADVERTISE_HOST="${NODE_C_ADVERTISE_HOST:?NODE_C_ADVERTISE_HOST required: node-b -> node-c HTTP host}"
case "$NODE_A_SSH" in
  *[!A-Za-z0-9._@-]*) echo "NODE_A_SSH 必须为 [user@]host，字符集 [A-Za-z0-9._@-]"; exit 1 ;;
esac
case "$NODE_C_SSH" in
  *[!A-Za-z0-9._@-]*) echo "NODE_C_SSH 必须为 [user@]host，字符集 [A-Za-z0-9._@-]"; exit 1 ;;
esac
case "$NODE_A_ADVERTISE_HOST" in
  ''|*[!A-Za-z0-9._-]*) echo "NODE_A_ADVERTISE_HOST 仅允许 [A-Za-z0-9._-]（URL host 段）"; exit 1 ;;
esac
case "$NODE_C_ADVERTISE_HOST" in
  ''|*[!A-Za-z0-9._-]*) echo "NODE_C_ADVERTISE_HOST 仅允许 [A-Za-z0-9._-]（URL host 段）"; exit 1 ;;
esac
# 节点 HTTP 端口可覆盖（默认 9115-9117）。旧 run 的 9105-9107 进程在保留窗口内
# 仍在运行，显式拒绝这三个端口，防止新 run 挤占旧 run 的服务。
PORT_A="${PORT_A:-9115}"; PORT_B="${PORT_B:-9116}"; PORT_C="${PORT_C:-9117}"
for _pvar in PORT_A PORT_B PORT_C; do
  eval "_p=\${$_pvar}"
  case "$_p" in
    9105|9106|9107) echo "$_pvar=$_p 属于保留旧 run 的端口，拒绝占用（默认 9115-9117）"; exit 1 ;;
    ''|*[!0-9]*) echo "$_pvar 必须为数字端口"; exit 1 ;;
  esac
  if [ "$_p" -lt 1024 ] || [ "$_p" -gt 65535 ]; then echo "$_pvar 超出 1024-65535"; exit 1; fi
done
MYSQL_ROOT="${MYSQL_ROOT:?MYSQL_ROOT required}"
RABBIT_USER="${RABBIT_USER:?RABBIT_USER required}"
RABBIT_PASS="${RABBIT_PASS:?RABBIT_PASS required}"
export MYSQL_ROOT RABBIT_USER RABBIT_PASS
# 秘钥字符集门禁（preflight，全部副作用发生前执行；失败即退出，绝不回显值）：
#  - 所有秘钥拒绝 换行/CR/控制字符/双引号/反斜杠 —— 否则无法安全写入 MySQL cnf
#    的 password="..." 双引号写法、redis.conf 行式配置或子进程 env；
#  - 被直接插进 URL 的值（RABBIT_USER/RABBIT_PASS -> amqp://、REDIS_PASS ->
#    redis://）额外限定 URL 安全字符集 [A-Za-z0-9._~-]，避免插值破坏 URL 解析。
#  已知残余：MYSQL_ROOT 仅做上述字符拒绝，其余 URL 特殊字符（@ : / # ? % 空格）
#  未转义 —— DATABASE_URL/amqp 插值要求调用方使用受限字符集（见头部说明）。
check_secret_charset() { # $1=名称（只回显名称） $2=值
  case "$2" in
    ''|*[![:print:]]*)
      echo "$1 为空或含换行/CR/不可打印字符，拒绝写入配置"; exit 1 ;;
    *\"*|*\\*)
      echo "$1 含双引号或反斜杠，无法安全写入配置，拒绝"; exit 1 ;;
  esac
}
require_scannable_secret() { # $1=名称 $2=秘密值
  check_secret_charset "$1" "$2"
  if [ "${#2}" -lt 6 ]; then
    echo "$1 长度小于 6，无法进行低噪声 exact-secret 扫描，拒绝"; exit 1
  fi
}
require_url_safe() { # $1=名称（只回显名称） $2=值
  check_secret_charset "$1" "$2"
  case "$2" in
    *[!A-Za-z0-9._~-]*)
      echo "$1 含 URL 不安全字符（仅允许 [A-Za-z0-9._~-]），拒绝直接插 URL"; exit 1 ;;
  esac
}
require_scannable_secret "MYSQL_ROOT" "$MYSQL_ROOT"
require_url_safe "RABBIT_USER" "$RABBIT_USER"
require_scannable_secret "RABBIT_PASS" "$RABBIT_PASS"
require_url_safe "RABBIT_PASS" "$RABBIT_PASS"
require_scannable_secret "REDIS_PASS" "$REDIS_PASS"
require_url_safe "REDIS_PASS" "$REDIS_PASS"   # 生成值本为字母数字，断言兜底
HERE="$(cd "$(dirname "$0")" && pwd)"   # rust-s15/ dir (contains seed_f4rust.sql)

require_port_free() { # $1=label $2=ssh target or local $3=port
  _label="$1"; _target="$2"; _port="$3"
  if [ "$_target" = local ]; then
    command -v ss >/dev/null 2>&1 \
      || { echo "ss unavailable on node-b"; exit 1; }
    _owners=$(ss -H -ltn "sport = :$_port")
  else
    _owners=$(ssh -o BatchMode=yes "$_target" "
      command -v ss >/dev/null 2>&1 || exit 127
      ss -H -ltn 'sport = :$_port'")
  fi
  if [ -n "${_owners//[[:space:]]/}" ]; then
    echo "target port occupied: $_label:$_port (fresh-run preflight refuses kill)"
    exit 1
  fi
}

# Fresh-run preflight before any durable mutation. Never delete/reuse old runs.
[ ! -e "$BASE" ] || { echo "run directory already exists: $BASE"; exit 1; }
ssh -o BatchMode=yes "$NODE_A_SSH" "test ! -e ~/$RUN_ID" \
  || { echo "run directory already exists on node-a"; exit 1; }
ssh -o BatchMode=yes "$NODE_C_SSH" "test ! -e ~/$RUN_ID" \
  || { echo "run directory already exists on node-c"; exit 1; }
_container_names=$(docker ps -a --format '{{.Names}}')
if printf '%s\n' "$_container_names" | grep -Fxq "$REDIS_CNAME"; then
  echo "run Redis container already exists: $REDIS_CNAME"; exit 1
fi
_existing_vhosts=$(docker exec astral_bench_rabbitmq rabbitmqctl -q list_vhosts name)
if printf '%s\n' "$_existing_vhosts" | grep -Fxq "$VHOST"; then
  echo "run Rabbit vhost already exists: $VHOST"; exit 1
fi
require_port_free node-a "$NODE_A_SSH" "$PORT_A"
require_port_free node-b local "$PORT_B"
require_port_free node-c "$NODE_C_SSH" "$PORT_C"
require_port_free redis local "$REDIS_PORT"

umask 077   # 所有 run 配置（含 redis.conf）默认 0600

# M-A：共享 mysql 容器内写入 run 专属 0600 defaults-extra-file（口令经 stdin
# 管道进入容器，任何进程 argv 都不含口令）；本脚本全部 mysql/mysqldump 调用
# 经该 cnf 认证。M4：文件名由容器内 mktemp 随机生成（不可预测，替代原先可预测
# 的 /tmp/.my_client_${RUN_ID}.cnf），umask 077 建档消除 644 窗口；cleanup 挂在
# EXIT/INT/TERM/HUP 四类事件上，幂等可重入（rm -f + || true），信号处理先清理、
# 清空 trap 再退出（退出码 128+sig，避免与 EXIT trap 双执行）。口令含换行/CR/
# 双引号/反斜杠已在 preflight 拒绝，cnf 双引号写法因此安全。
cleanup_mysql_temp() {
  [ -z "${MYSQL_CNF_REMOTE:-}" ] \
    || docker exec astral_bench_mysql rm -f "$MYSQL_CNF_REMOTE" >/dev/null 2>&1 || true
  [ -z "${SCHEMA_REMOTE:-}" ] \
    || docker exec astral_bench_mysql rm -f "$SCHEMA_REMOTE" >/dev/null 2>&1 || true
  [ -z "${BOOTSTRAP_LOG:-}" ] || rm -f "$BOOTSTRAP_LOG"
}
on_signal_exit() { # $1 = 信号编号；先清理再退出
  cleanup_mysql_temp
  trap - EXIT INT TERM HUP
  exit $((128 + $1))
}
trap 'on_signal_exit 2' INT    # SIGINT  -> 130
trap 'on_signal_exit 15' TERM  # SIGTERM -> 143
trap 'on_signal_exit 1' HUP    # SIGHUP  -> 129
trap cleanup_mysql_temp EXIT
MYSQL_CNF_REMOTE=$(docker exec astral_bench_mysql sh -c 'umask 077; mktemp /tmp/.mycnf_XXXXXXXX') \
  || { echo "无法在共享 mysql 容器创建 0600 临时 cnf（mktemp 失败，fail-closed）"; exit 1; }
docker exec -i astral_bench_mysql sh -c "cat > '$MYSQL_CNF_REMOTE' && chmod 600 '$MYSQL_CNF_REMOTE'" <<EOF
[client]
user=root
password="$MYSQL_ROOT"
EOF
MYSQLX="mysql --defaults-extra-file=$MYSQL_CNF_REMOTE"
MYSQLDUMPX="mysqldump --defaults-extra-file=$MYSQL_CNF_REMOTE"

DB_EXISTS=$(docker exec astral_bench_mysql sh -c "exec $MYSQLX -uroot -N -e 'SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=\"$DIST_DB_NAME\"' 2>/dev/null")
[ "$DB_EXISTS" = "0" ] || { echo "run database already exists: $DIST_DB_NAME"; exit 1; }
mkdir -p "$BASE"

SCHEMA_REMOTE=$(docker exec astral_bench_mysql sh -c 'umask 077; mktemp /tmp/.final_schema_XXXXXXXX.sql') \
  || { echo "无法创建 run-scoped schema 临时文件"; exit 1; }

echo "[1/9] canonical schema -> $DIST_DB_NAME"
docker exec astral_bench_mysql sh -c "exec $MYSQLDUMPX -uroot --no-data --single-transaction --skip-lock-tables --no-tablespaces astral_test 2>/dev/null > '$SCHEMA_REMOTE'"
# 迁移历史随克隆库携带：schema 契约解析器以 _sqlx_migrations 已记录版本判定
# 后创建期索引（如 10.D-2 的 idx_ade_grant_chain）是"待应用（容忍）"还是
# "已记录（必需）"。纯 schema 克隆无历史行会把已存在的索引反向判成漂移。
docker exec astral_bench_mysql sh -c "exec $MYSQLDUMPX -uroot --no-create-info --skip-lock-tables --no-tablespaces astral_test _sqlx_migrations 2>/dev/null >> '$SCHEMA_REMOTE'"
docker exec astral_bench_mysql sh -c "exec $MYSQLX -uroot -e 'CREATE DATABASE $DIST_DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci' 2>/dev/null"
docker exec astral_bench_mysql sh -c "exec $MYSQLX -uroot $DIST_DB_NAME 2>/dev/null < '$SCHEMA_REMOTE'"
docker exec -i astral_bench_mysql sh -c "exec $MYSQLX -uroot $DIST_DB_NAME 2>/dev/null" < "$HERE/seed_f4rust.sql"
docker exec astral_bench_mysql rm -f "$SCHEMA_REMOTE"
SCHEMA_REMOTE=""
echo "  tables: $(docker exec astral_bench_mysql sh -c "exec $MYSQLX -uroot -N -e 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\"$DIST_DB_NAME\"' 2>/dev/null")"

echo "[2/9] bootstrap e2e card evidence (BOOTSTRAP_BIN required, sha256=$BOOTSTRAP_SHA256)"
# 全新 run 库无已发布指针，就绪探针依赖卡级 gen-1 证据；使用生产
# stage/claim/finalize/publish 原语，幂等跳过已发布卡。绝不静默 skip。
# cwd 固定为 $BASE：避免从源码根运行时拾取仓库内 application.yml（源码根
# 配置绝不进入本 run）。DATABASE_URL 经子进程 env 传递（env 为许可通道，
# 口令不出现在任何 argv）。stdout/stderr 先进入 0600 临时文件，在本机按实际
# MYSQL_ROOT 做 exact-secret 扫描；原文无论成功失败均不转发到 deploy 日志。
BOOTSTRAP_LOG=$(mktemp "$BASE/.bootstrap-output.XXXXXXXX")
set +e
( cd "$BASE" && DATABASE_URL="mysql://root:$MYSQL_ROOT@$MYSQL_HOST_ONLY:$MYSQL_PORT/$DIST_DB_NAME" \
  exec "$BOOTSTRAP_BIN" ) >"$BOOTSTRAP_LOG" 2>&1
BOOTSTRAP_RC=$?
set -e
python3 - "$BOOTSTRAP_LOG" <<'PY'
import os
import sys

secret = os.environ.get("MYSQL_ROOT", "").encode()
if len(secret) < 6:
    raise SystemExit("bootstrap exact-secret scan has no valid credential candidate")
data = open(sys.argv[1], "rb").read()
if secret in data:
    raise SystemExit("bootstrap output rejected by exact-secret scan")
print("bootstrap output exact-secret scan PASS values=1")
PY
rm -f "$BOOTSTRAP_LOG"
BOOTSTRAP_LOG=""
if [ "$BOOTSTRAP_RC" -ne 0 ]; then
  echo "bootstrap failed rc=$BOOTSTRAP_RC (stdout/stderr withheld)"; exit 1
fi
echo "bootstrap completed (stdout/stderr withheld)"

echo "[3/9] run-scoped redis container ($REDIS_CNAME :$REDIS_PORT, random requirepass)"
# 密码只进 0600 的 redis.conf（requirepass 行）；redis-server argv 不含秘钥，
# 容器内进程参数不可见。端口发布在宿主所有接口（三节点跨机可达），匿名访问
# 被 requirepass 阻断（protected-mode + requirepass）。
printf 'bind 0.0.0.0\nprotected-mode yes\nrequirepass %s\n' "$REDIS_PASS" > "$BASE/redis.conf"
chmod 600 "$BASE/redis.conf"
# 用 root shell 绕过官方 entrypoint 的 gosu 降权：redis uid(999) 无法读取宿主
# 挂载的 0600 配置（实测 Fatal error Permission denied）。run-scoped 容器、
# 只读挂载、宿主文件保持 0600；容器内以 root 运行 redis 属已知权衡。
docker run -d --name "$REDIS_CNAME" -p "${REDIS_PORT}:6379" \
  -v "$BASE/redis.conf":/usr/local/etc/redis/redis.conf:ro \
  --entrypoint sh redis:7 -c "exec redis-server /usr/local/etc/redis/redis.conf" >/dev/null
sleep 2
# 本机认证 PING（密码经 stdin 注入 REDISCLI_AUTH，不出现在任何 argv）
printf '%s' "$REDIS_PASS" | docker exec -i "$REDIS_CNAME" sh -c 'REDISCLI_AUTH=$(cat) redis-cli ping' | grep -q PONG

echo "[3.5/9] redis reachability preflight from node-a/node-c (auth via stdin)"
rm -f "$BASE/redis_preflight.jsonl"
# provenance/log 只记录节点标签（node-a/node-c），不记录 ssh 目标 —— provenance
# 会随 $BASE 分发到全部节点；ssh 目标仅保留在 node-b 私有的 run_config.json 中。
for _label in node-a node-c; do
  case "$_label" in
    node-a) target="$NODE_A_SSH" ;;
    node-c) target="$NODE_C_SSH" ;;
  esac
  # 远端：redis-cli 可用则带 AUTH PING（密码经 $(cat) 从 stdin 读取，不进 argv）；
  # 无 redis-cli 则退化为 TCP 连通性检查（认证由服务端 requirepass 强制）。
  # L4：检查方式记录进 provenance——TCP 退化节点如实标 degraded，不冒充
  # 已认证探测。
  _probe="RHOST='$MYSQL_HOST_ONLY' RPORT='$REDIS_PORT' sh -c 'if command -v redis-cli >/dev/null 2>&1; then REDISCLI_AUTH=\$(cat) redis-cli -h \$RHOST -p \$RPORT PING 2>/dev/null; else timeout 5 bash -c \"exec 3<>/dev/tcp/\$RHOST/\$RPORT\" 2>/dev/null && echo TCP_OK; fi'"
  _probe_out=$(printf '%s' "$REDIS_PASS" | ssh -o BatchMode=yes "$target" "$_probe" || true)
  if printf '%s' "$_probe_out" | grep -q PONG; then
    _method="authenticated-ping"
  elif printf '%s' "$_probe_out" | grep -q TCP_OK; then
    _method="tcp-only-degraded"
  else
    echo "redis preflight FAILED from $_label ($MYSQL_HOST_ONLY:$REDIS_PORT)"; exit 1
  fi
  printf '{"%s": "%s"}\n' "$_label" "$_method" >> "$BASE/redis_preflight.jsonl"
  echo "  $_label -> redis $MYSQL_HOST_ONLY:$REDIS_PORT reachable ($_method)"
done

echo "[4/9] create dedicated Rabbit vhost $VHOST (shared rust3n_dist untouched)"
docker exec astral_bench_rabbitmq rabbitmqctl add_vhost "$VHOST" >/dev/null
docker exec astral_bench_rabbitmq rabbitmqctl set_permissions -p "$VHOST" "$RABBIT_USER" ".*" ".*" ".*" >/dev/null

echo "[5/9] config + start helper + provenance (fresh secrets, 0600)"
# 源码根 application.yml 绝不进入分发：先清除 $BASE 下任何同名旧文件，
# python 只写本 run 生成的 run-scoped 配置；写完后 marker 守卫复核。
rm -f "$BASE/application.yml"
# M5：重跑同 RUN_ID 时，$BASE 可能残留上一 run 的 run_config.json / nodes.json
# （分别在 [9/9]、[8/9] 才重建）。[6/9] 的 scp -rpq "$BASE" 会把它们同步到
# node-a/node-c —— 这两份是 node-b 专属文件。分发前先删除本地当前 run 目录中的
# 旧副本（仅清本地当前 run 的旧 config，不触碰任何远端现存文件）；run_config.json
# 之后仍仅在 node-b 重建并保持 0600。
rm -f "$BASE/run_config.json" "$BASE/nodes.json"
# H-1：RABBIT_PASS 不再作为 python 位置参数传递（历史缺陷：secret 进 argv）；
# python 侧经 os.environ["RABBIT_PASS"] 读取（env 为许可通道）。
python3 - "$BASE" "$DIST_DB_NAME" "$MYSQL_HOST_ONLY" "$MYSQL_PORT" "$REDIS_PORT" "$VHOST" "$RABBIT_USER" "$RUN_ID" <<'PY'
import os, secrets, string, sys
base, db, mh, mp, rport, vhost, ru, run_id = sys.argv[1:9]
def gen(n=48):
    a = string.ascii_letters + string.digits
    return "".join(secrets.choice(a) for _ in range(n))
hmac_secret, jwt_secret, internal_secret = gen(), gen(), gen()
l2_secret = gen(48)
redis_pass = os.environ["REDIS_PASS"]
yml = f"""# run-scoped dist config {db}
database_url: "mysql://root:__MYSQL_ROOT__@{mh}:{mp}/{db}"
redis_url: "redis://:{redis_pass}@{mh}:{rport}/0"
rabbitmq_url: "amqp://{ru}:__RABBIT_PASS__@{mh}:5673/{vhost}"
internal_service_secret: "{internal_secret}"
jwt:
  secret: "{jwt_secret}"
  expiry_seconds: 86400
gateway:
  hmac_secret: "{hmac_secret}"
  internal_service_secret: "{internal_secret}"
  timestamp_tolerance_secs: 30
rate_limit:
  enabled: false
  requests_per_second: 100000
  burst_size: 200000
cors:
  allowed_origins:
    - "https://{run_id}.invalid"
  allow_credentials: true
public_paths:
  - "/api/health"
learn_service_uri: "http://127.0.0.1:9002"
chat_service_uri: "http://127.0.0.1:9003"
identity_service_uri: "http://127.0.0.1:9004"
trust_graph_uri: "http://127.0.0.1:9005"
monitor_service_uri: "http://127.0.0.1:9006"
"""
yml = yml.replace("__MYSQL_ROOT__", os.environ["MYSQL_ROOT"])
yml = yml.replace("__RABBIT_PASS__", os.environ["RABBIT_PASS"])
open(f"{base}/application.yml", "w").write(yml)
open(f"{base}/hmac.txt", "w").write(hmac_secret + "\n")
jwt = (f"JWT_ACCESS_SECRET={gen()}\nJWT_REFRESH_SECRET={gen()}\n"
       f"JWT_ACCESS_ISSUER={run_id}\nJWT_REFRESH_ISSUER={run_id}\n"
       f"JWT_ACCESS_AUDIENCE={run_id}\nJWT_REFRESH_AUDIENCE={run_id}\n")
open(f"{base}/jwt.env", "w").write(jwt)
open(f"{base}/scopes.env", "w").write(
    f"ASTRAL_PROJECTOR_TENANTS=9001,9002\nASTRAL_L2_EVIDENCE_HMAC_SECRET={l2_secret}\nRUST_ENV=test\n")
print("config written")
PY
# marker 守卫：确认分发的 application.yml 就是本 run 生成的 run-scoped 配置
grep -q "run-scoped dist config" "$BASE/application.yml" \
  || { echo "application.yml marker guard failed（拒绝分发非本 run 生成的配置）"; exit 1; }
cat > "$BASE/node_start.sh" <<'EOF'
#!/usr/bin/env bash
# current run pidfile owner only; a foreign listener is never killed.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="$1"; PORT="$2"
cd "$DIR"
PIDFILE="$DIR/node_${LABEL}.pid"
if [ -f "$PIDFILE" ]; then
  OLD=$(cat "$PIDFILE" 2>/dev/null || true)
  owned_pid() {
    [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null \
      && [ "$(readlink -f "/proc/$1/cwd" 2>/dev/null || true)" = "$DIR" ] \
      && [ "$(sha256sum "/proc/$1/exe" 2>/dev/null | cut -d' ' -f1)" \
           = "$(sha256sum "$DIR/astral-trustgraph" | cut -d' ' -f1)" ]
  }
  if [ -n "${OLD:-}" ] && kill -0 "$OLD" 2>/dev/null; then
    if ! owned_pid "$OLD"; then
      echo "pidfile process is not owned by this run; refusing to kill" >&2
      exit 1
    fi
    kill -TERM "$OLD" 2>/dev/null || true
    for i in $(seq 1 20); do kill -0 "$OLD" 2>/dev/null || break; sleep 0.5; done
    if kill -0 "$OLD" 2>/dev/null; then
      owned_pid "$OLD" || {
        echo "pid identity changed before KILL; refusing escalation" >&2
        exit 1
      }
      kill -KILL "$OLD"
    fi
  fi
  rm -f "$PIDFILE"
fi
if command -v fuser >/dev/null 2>&1; then
  OWNER=$(fuser -n tcp "$PORT" 2>/dev/null || true)
  if [ -n "${OWNER//[[:space:]]/}" ]; then
    echo "foreign listener owns ${PORT}/tcp; refusing to kill" >&2
    exit 1
  fi
fi
set -a; . "$DIR/jwt.env"; . "$DIR/scopes.env"; set +a
export LISTEN_ADDR="0.0.0.0:${PORT}"
nohup ./astral-trustgraph >> "server_${LABEL}.log" 2>&1 &
echo $! > "$PIDFILE"
echo "started ${LABEL} pid=$(cat "$PIDFILE") port=${PORT}"
EOF
chmod +x "$BASE/node_start.sh"
# provenance（不含任何秘钥——只有 sha256/rev/快照身份/redis 预检方式；随
# $BASE 分发到全部节点，供 harness 记录与复核）
python3 - "$BASE" "$RUN_ID" "$SNAP_BIN" "$BIN_SHA256" "$GIT_REV" "$SOURCE_SNAPSHOT_SHA256" "$SOURCE_SNAPSHOT_METHOD" "$BOOTSTRAP_BIN" "$BOOTSTRAP_SHA256" "$SOURCE_GIT_REV" "$SOURCE_DIRTY_PATCH_SHA256_NORM" "$SOURCE_DIRTY" "$VHOST" "$REDIS_CNAME" "$REDIS_PORT" "$PORT_A" "$PORT_B" "$PORT_C" <<'PY'
import datetime, json, os, sys
(base, run_id, snap, sha, rev, snap_sha, snap_method, boot, boot_sha,
 src_rev, dirty_patch, dirty, vhost, redis_container, redis_port,
 port_a, port_b, port_c) = sys.argv[1:19]
redis_preflight = None
pf_path = os.path.join(base, "redis_preflight.jsonl")
if os.path.isfile(pf_path):
    redis_preflight = {}
    with open(pf_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                redis_preflight.update(json.loads(line))
json.dump({
    "run_id": run_id,
    "created_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
    "binary_source": snap,
    "binary_sha256": sha,
    # 本地 best-effort 参照（binary 目录向上找 .git；非源码身份权威）
    "git_rev": rev or None,
    "git_rev_source_match": (rev == src_rev) if (rev and src_rev) else None,
    # tracked-only 源码身份（主线显式提供；无 .git 环境不得猜测为空）
    "source_snapshot_sha256": snap_sha,
    "source_snapshot_method": snap_method,
    "source_git_rev": src_rev,
    "source_dirty": dirty == "true",
    "source_dirty_patch_sha256": dirty_patch or None,
    "bootstrap_bin_source": boot,
    "bootstrap_bin_sha256": boot_sha,
    "rabbit_vhost": vhost,
    "redis_container": redis_container,
    "redis_port": int(redis_port),
    "node_ports": {"node-a": int(port_a), "node-b": int(port_b),
                   "node-c": int(port_c)},
    "redis_preflight": redis_preflight,
}, open(base + "/provenance.json", "w"), indent=1)
print("provenance: binary_sha256=%s source_git_rev=%s dirty=%s source_snapshot=%s "
      "bootstrap_sha256=%s git_rev_source_match=%s redis_preflight=%s"
      % (sha[:16], src_rev[:12], dirty, snap_sha[:16], boot_sha[:16],
         (rev == src_rev) if (rev and src_rev) else "n/a",
         "degraded" if redis_preflight and "tcp-only-degraded" in redis_preflight.values()
         else (redis_preflight or "n/a")))
PY
rm -f "$BASE/redis_preflight.jsonl"
# 先删旧 inode 再 cp：旧的 node-b 进程可能仍在运行该二进制（[7/9] 才会
# 重启它），直接覆盖会 "Text file busy"；rm 后 cp 让运行中进程保留旧 inode。
rm -f "$BASE/astral-trustgraph"
cp "$SNAP_BIN" "$BASE/astral-trustgraph"
COPY_SHA=$(sha256sum "$BASE/astral-trustgraph" | awk '{print $1}')
[ "$COPY_SHA" = "$BIN_SHA256" ] || { echo "binary copy sha256 mismatch: $COPY_SHA != $BIN_SHA256"; exit 1; }

echo "[6/9] distribute to node-a/node-c + copy sha256 recheck"
for target in "$NODE_A_SSH" "$NODE_C_SSH"; do
  # Fresh-only remote ownership: preflight proved the directory absent.
  scp -rpq "$BASE" "$target":~/
  # 复制后逐节点复核二进制 sha256（传输完整性证明，不只是源端校验）
  REMOTE_SHA=$(ssh -o BatchMode=yes "$target" "sha256sum ~/$RUN_ID/astral-trustgraph" | awk '{print $1}')
  [ "$REMOTE_SHA" = "$BIN_SHA256" ] || { echo "node copy sha256 mismatch on $target: $REMOTE_SHA != $BIN_SHA256"; exit 1; }
  echo "  $target binary sha256 OK (${REMOTE_SHA:0:16})"
  ssh -o BatchMode=yes "$target" "chmod 600 ~/$RUN_ID/application.yml ~/$RUN_ID/jwt.env ~/$RUN_ID/scopes.env ~/$RUN_ID/hmac.txt ~/$RUN_ID/redis.conf"
done

echo "[7/9] start nodes (serial + serve-wait: fresh-DB superadmin init races across nodes)"
# 全新库首次启动时 superadmin 模板初始化（SELECT-then-INSERT）存在跨节点竞速：
# 先启动的节点插入 platform domain，其余节点若先查询会 SUPERADMIN_INIT_FAILED
# fail-closed 退出（实测 node-b 输）。因此串行启动，每节点等到任意 HTTP 响应
# （403/404/200 都证明已越过初始化并绑定端口）再启动下一个；失败有界重启 3 次。
start_and_wait() { # $1=label $2=start-cmd $3=base-url $4=pid-probe-cmd（在目标机上解析监听 pid）
  for _i in 1 2 3; do
    _out=$(eval "$2") || { echo "  $1 start cmd failed (attempt $_i)"; sleep 5; continue; }
    # node_start.sh 输出 "started <label> pid=<N>"：本次启动的 pid 是唯一可信的
    # 新进程身份。曾出现旧进程逃过 kill 继续监听端口、对新进程返回 403 的形态
    # （陈旧监听连着旧库 → readiness 永远 PENDING）——serving 必须同时满足
    # HTTP 可达 且监听 pid == 本次启动 pid；不同 PID 占用端口时直接失败，
    # 绝不跨 run 强制回收监听者。
    _want=$(printf '%s' "$_out" | sed -n 's/.*started .* pid=\([0-9]*\).*/\1/p' | tail -n 1)
    for _t in $(seq 1 60); do
      _code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$3/main/api/v1/rule-sets" || true)
      _listen=$(eval "$4" 2>/dev/null || true)
      if [ -n "$_code" ] && [ "$_code" != "000" ] && [ -n "$_want" ] \
         && [ "$_listen" = "$_want" ]; then
        echo "  $1 serving (http=$_code pid=$_listen)"
        return 0
      fi
      if [ -n "$_listen" ] && [ -n "$_want" ] && [ "$_listen" != "$_want" ]; then
        echo "  $1 foreign listener $_listen != started $_want; refusing to kill"
        return 1
      fi
      sleep 3
    done
    echo "  $1 not serving after 180s (attempt $_i); restarting"
  done
  echo "  $1 failed to serve after 3 attempts"; return 1
}
start_and_wait node-a "ssh -o BatchMode=yes \"$NODE_A_SSH\" \"bash ~/$RUN_ID/node_start.sh a $PORT_A\"" "http://$NODE_A_ADVERTISE_HOST:$PORT_A" \
  "ssh -o BatchMode=yes \"$NODE_A_SSH\" \"fuser -n tcp $PORT_A 2>/dev/null | tr ' ' '\\n' | grep -E '^[0-9]+\$' | tail -n 1\""
start_and_wait node-b "bash \"$BASE/node_start.sh\" b $PORT_B" "http://127.0.0.1:$PORT_B" \
  "fuser -n tcp $PORT_B 2>/dev/null | tr ' ' '\\n' | grep -E '^[0-9]+\$' | tail -n 1"
start_and_wait node-c "ssh -o BatchMode=yes \"$NODE_C_SSH\" \"bash ~/$RUN_ID/node_start.sh c $PORT_C\"" "http://$NODE_C_ADVERTISE_HOST:$PORT_C" \
  "ssh -o BatchMode=yes \"$NODE_C_SSH\" \"fuser -n tcp $PORT_C 2>/dev/null | tr ' ' '\\n' | grep -E '^[0-9]+\$' | tail -n 1\""
sleep 4

echo "[8/9] readiness (signed rule-sets probe via coordinator signer)"
python3 - "$BASE" "$NODE_A_ADVERTISE_HOST" "$PORT_A" "$NODE_C_ADVERTISE_HOST" "$PORT_C" "$PORT_B" <<'PY'
import hashlib, hmac, sys, time, uuid
import requests
base, a_addr, pa, c_addr, pc, pb = sys.argv[1:7]
secret = open(base + "/hmac.txt").read().strip()
actors = {"user_id": "9031", "icard": "9041", "card": "9061", "domain": "9011", "tenant": "9001"}
def hdr(method, path):
    ts = str(int(time.time() * 1000))
    payload = "\n".join(["astral-gateway-v3", method, path.split("?")[0], actors["user_id"],
                         "PLATFORM_USER", "", actors["icard"], actors["card"], actors["domain"],
                         actors["tenant"], "", "", "", "", ts])
    return {"x-request-id": str(uuid.uuid4()), "x-user-id": actors["user_id"],
            "x-principal-kind": "PLATFORM_USER", "x-identity-card-id": actors["icard"],
            "x-user-card-id": actors["card"], "x-user-card-domain-id": actors["domain"],
            "x-user-card-tenant-id": actors["tenant"], "x-gateway-ts": ts,
            "x-gateway-signature": hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest(),
            "x-gateway-auth": "verified"}
nodes = {"node-a": "http://%s:%s" % (a_addr, pa), "node-b": "http://127.0.0.1:%s" % pb,
         "node-c": "http://%s:%s" % (c_addr, pc)}
# bootstrap 在节点启动前提交，发布收敛发生在节点启动之后（projector 冷启动 +
# delta worker 领取）；实测可超过 60s，预算放宽到 240s 并记录逐轮状态码。
deadline, alive = time.time() + 240, set()
last_codes = {}
while time.time() < deadline and len(alive) < 3:
    for n, url in nodes.items():
        if n in alive:
            continue
        try:
            code = requests.get(url + "/main/api/v1/rule-sets?page=1&size=1", headers=hdr("GET", "/main/api/v1/rule-sets"), timeout=5).status_code
        except Exception:
            code = None
        last_codes[n] = code
        if code == 200:
            alive.add(n)
    time.sleep(2)
missing = set(nodes) - alive
assert not missing, "nodes not ready: %s last_codes=%s" % (missing, last_codes)
open(base + "/nodes.json", "w").write(__import__("json").dumps(nodes))
print("all nodes ready: %s" % sorted(alive))
PY

echo "[9/9] write run_config.json (0600, node-b only; carries redis_password)"
python3 - "$BASE" "$DIST_DB_NAME" "$NODE_A_SSH" "$NODE_C_SSH" "$NODE_A_ADVERTISE_HOST" "$NODE_C_ADVERTISE_HOST" "$BIN_SHA256" "$GIT_REV" "$SOURCE_SNAPSHOT_SHA256" "$BOOTSTRAP_SHA256" "$SOURCE_GIT_REV" "$SOURCE_DIRTY_PATCH_SHA256_NORM" "$SOURCE_DIRTY" "$PORT_A" "$PORT_B" "$PORT_C" <<'PY'
import json, os, sys
(base, db, a_ssh, c_ssh, a_addr, c_addr, bin_sha, git_rev,
 snap_sha, boot_sha, src_rev, dirty_patch, dirty, pa, pb, pc) = sys.argv[1:17]
cfg = {
    "nodes": {"node-a": "http://%s:%s" % (a_addr, pa), "node-b": "http://127.0.0.1:%s" % pb,
              "node-c": "http://%s:%s" % (c_addr, pc)},
    "ssh": {"node-a": a_ssh, "node-c": c_ssh},
    "base_dir": "~/%s" % os.environ["RUN_ID"],
    "run_id": os.environ["RUN_ID"],
    "db": db,
    "binary_sha256": bin_sha,
    "git_rev": git_rev or None,
    "source_snapshot_sha256": snap_sha,
    "source_git_rev": src_rev,
    "source_dirty": dirty == "true",
    "source_dirty_patch_sha256": dirty_patch or None,
    "bootstrap_bin_sha256": boot_sha,
    "mysql_container": "astral_bench_mysql",
    "mysql_root": os.environ["MYSQL_ROOT"],
    "redis_container": os.environ["REDIS_CNAME"],
    "redis_port": int(os.environ["REDIS_PORT"]),   # L1：REDIS_PORT 已导出
    # run 级 redis requirepass：仅写入本 0600 文件供 harness 认证；
    # 不得打印/归档/复制到任何其他 artifact。
    "redis_password": os.environ["REDIS_PASS"],
    "rabbit_mgmt": "http://127.0.0.1:15673",
    "rabbit_vhost": os.environ["VHOST"],
    "rabbit_user": os.environ["RABBIT_USER"],
    "rabbit_pass": os.environ["RABBIT_PASS"],
    "hmac_secret_file": "%s/hmac.txt" % base,
    "ports": {"node-a": int(pa), "node-b": int(pb), "node-c": int(pc)}
}
p = base + "/run_config.json"
open(p, "w").write(json.dumps(cfg, indent=1))
os.chmod(p, 0o600)
print("run_config.json written")
PY

# The coordinator owns the scanner transport contract used again after every
# campaign step. Output is constrained to counts/status; secret values, matching
# lines, and third-party error text are never relayed.
RUN_CONFIG_PATH="$BASE/run_config.json" python3 - "$HERE" <<'PY'
import json
import sys

sys.path.insert(0, sys.argv[1])
import s15_coordinator as coordinator

result = coordinator.runtime_secret_scan()
print("runtime secret scan: %s" % json.dumps(result, sort_keys=True))
raise SystemExit(0 if result.get("ok") else 1)
PY

echo "DEPLOY_DONE RUN_ID=$RUN_ID base=$BASE redis_port=$REDIS_PORT db=$DIST_DB_NAME"
