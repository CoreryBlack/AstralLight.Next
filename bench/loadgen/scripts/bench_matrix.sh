#!/usr/bin/env bash
# 真实系统上限测量矩阵（node-b 上运行）。
# Rust GIL-free 客户端按并发阶梯压测，同时采样 MySQL/Redis 每请求命令数
# 与 trustgraph 进程 CPU（核数），定位吞吐拐点与饱和组件。
# 用法: MYSQL_ROOT=... bash bench_matrix.sh [biz|health|all] [并发列表，空格分隔]
# 必填环境变量（不落盘、不入库、不出现在任何进程 argv）:
#   MYSQL_ROOT   共享 MySQL root 口令（容器名可用 MYSQL_CNAME 覆盖）
# 凭据通道（M-A 修正：与实际实现一致）：
#   - mysql 采样：口令+查询均经 stdin 管道（首行被远端 `read` 消费为
#     MYSQL_PWD，其余 stdin 作为 mysql 查询输入）——docker 客户端 argv 与
#     容器内 mysql argv 都不含口令值；
#   - loadgen HMAC：经 loadgen 支持的 LOADGEN_HMAC_SECRET 环境变量注入
#     （env 为许可通道），不再使用 --hmac-secret argv。
# 失败语义（fail-closed）：set -euo pipefail；loadgen 非零、单点 ok=0、
# 基础设施采样失败任一发生 → 立即非零退出，不产出半截 summary。
set -euo pipefail

LG=${LG:-$HOME/astral-e2e/loadgen/target/release/loadgen}
BASE=${BASE:-http://127.0.0.1:9005}
YML=${YML:-$HOME/astral-e2e/tg-run/application.yml}
OUT=${OUT:-$HOME/astral-e2e/tg-run/real_limit}
DUR=${DUR:-20}
# 凭据一律来自调用方环境（历史版本硬编码口令，已按仓库秘密约束移除）。
MYSQL_ROOT=${MYSQL_ROOT:?MYSQL_ROOT required (shared mysql root password)}
MYSQL_CNAME=${MYSQL_CNAME:-astral_bench_mysql}
REDIS_CNAME=${REDIS_CNAME:-astral_bench_redis}
mkdir -p "$OUT"
CSV="$OUT/summary.csv"

SECRET=$(grep -oP 'hmac_secret: "\K[^"]+' "$YML" | head -1 || true)
[ -z "$SECRET" ] && { echo "无法从 $YML 提取 hmac_secret"; exit 1; }
[ -x "$LG" ] || { echo "loadgen 不存在: $LG"; exit 1; }

TG_PID=$(ss -ltnp "sport = :9005" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1 || true)
[ -z "$TG_PID" ] && { echo "trustgraph 未运行"; exit 1; }

# provenance（零秘钥）：本次测量矩阵的身份信息（utc/host/loadgen sha256/git 状态/
# 参数），落 $OUT/provenance.json。
python3 - "$OUT" "$LG" "$BASE" "$DUR" "$MYSQL_CNAME" "$REDIS_CNAME" <<'PY'
import hashlib, json, os, socket, subprocess, sys, time
out, lg, base, dur, mc, rc = sys.argv[1:8]
def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()
def git_info():
    d = os.getcwd()
    while True:
        if os.path.isdir(os.path.join(d, ".git")):
            try:
                rev = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                                     capture_output=True, text=True, timeout=10)
                dirty = subprocess.run(["git", "-C", d, "status", "--porcelain"],
                                       capture_output=True, text=True, timeout=10)
                if rev.returncode == 0:
                    return {"rev": rev.stdout.strip(), "dirty": bool(dirty.stdout.strip())}
            except Exception:
                pass
            return None
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
json.dump({
    "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "host": socket.gethostname(),
    "loadgen": {"path": lg, "sha256": sha256(lg)},
    "base_url": base,
    "duration_s": dur,
    "mysql_container": mc,
    "redis_container": rc,
    "git": git_info(),
    "secrets_recorded": False,
}, open(os.path.join(out, "provenance.json"), "w"), indent=1)
print("provenance: %s" % os.path.join(out, "provenance.json"))
PY

mysql_questions() {
  # 口令与查询均经 stdin（首行被远端 read 消费为 MYSQL_PWD，其余 stdin 作为
  # mysql 查询输入）——docker 客户端与容器内 mysql argv 均不含口令值。
  printf '%s\n%s\n' "$MYSQL_ROOT" "SHOW GLOBAL STATUS LIKE 'Questions';" \
    | docker exec -i "$MYSQL_CNAME" sh -c 'IFS= read -r _pw; MYSQL_PWD="$_pw" exec mysql -uroot -N' 2>/dev/null \
    | awk '{print $2}'
}
redis_cmds() {
  docker exec "$REDIS_CNAME" redis-cli INFO stats 2>/dev/null \
    | grep total_commands_processed | tr -d '\r' | cut -d: -f2
}
tg_cpu_ticks() { awk '{print $14+$15}' "/proc/$TG_PID/stat" 2>/dev/null; }

BIZ_PATH='/main/api/v1/rule-sets/9071/entries'
HEALTH_PATH='/api/health'

echo "label,concurrency,qps,p50_us,p90_us,p99_us,p999_us,max_us,ok,err,mysql_per_req,redis_per_req,cpu_cores" > "$CSV"

run_point() {
  local label=$1 conc=$2 dur=$3 path=$4
  local mq0 rq0 cpu0 t0 t1 mq1 rq1 cpu1
  mq0=$(mysql_questions); rq0=$(redis_cmds); cpu0=$(tg_cpu_ticks)
  t0=$(date +%s.%N)
  # HMAC 经 loadgen 支持的 LOADGEN_HMAC_SECRET env 注入（env 前缀赋值是
  # shell 内部机制，不进入 loadgen argv）；loadgen 失败 → 立即非零退出。
  LOADGEN_HMAC_SECRET="$SECRET" "$LG" --url "$BASE" --path "$path" \
    --concurrency "$conc" --duration "$dur" --warmup 30 --output json \
    > "$OUT/${label}_c${conc}.json"
  t1=$(date +%s.%N); mq1=$(mysql_questions); rq1=$(redis_cmds); cpu1=$(tg_cpu_ticks)
  python3 - "$OUT/${label}_c${conc}.json" "$t0" "$t1" \
    "$mq0" "$mq1" "$rq0" "$rq1" "$cpu0" "$cpu1" "$label" "$conc" <<'PY' >> "$CSV"
import json, sys
path, t0, t1, mq0, mq1, rq0, rq1, cpu0, cpu1, label, conc = sys.argv[1:12]
d = json.load(open(path, encoding='utf-8'))
if d['ok'] <= 0:
    sys.stderr.write("BUSINESS FAIL: ok=0 for %s c=%s（不产出伪测量行）\n" % (label, conc))
    sys.exit(3)
wall = float(t1) - float(t0)
ok = d['ok']
# loadgen JSON 契约漂移兼容:当前版本输出 failures/http_fail/transport_err,
# 无聚合 'err' 键;三者求和等价旧语义(ok=成功,其余=失败)。
err = d.get('err')
if err is None:
    err = d.get('failures', 0) + d.get('http_fail', 0) + d.get('transport_err', 0)
mq = (int(mq1) - int(mq0)) / ok
rq = (int(rq1) - int(rq0)) / ok
cpu = (int(cpu1) - int(cpu0)) / 100.0 / wall  # CLK_TCK=100, 相对单核
print(f"{label},{conc},{d['qps']:.1f},{d['p50_us']},{d['p90_us']},{d['p99_us']},{d['p999_us']},{d['max_us']},{d['ok']},{err},{mq:.1f},{rq:.1f},{cpu:.2f}")
PY
  echo "done: $label c=$conc"
}

MODE=${1:-all}
BIZ_LIST=${2:-"1 8 32 64 128 256 512"}
HEALTH_LIST=${2:-"8 64 256"}

if [ "$MODE" = biz ] || [ "$MODE" = all ]; then
  for c in $BIZ_LIST; do run_point biz "$c" "$DUR" "$BIZ_PATH"; done
fi
if [ "$MODE" = health ] || [ "$MODE" = all ]; then
  # health 场景退役(2026-10-07):/api/health 是 Monitor(9006) 的路径,
  # trustgraph(9005) 未挂载该路由(实测 404)。基线吞吐由 biz 场景的
  # 低并发点承载;若需恢复,先把 HEALTH_PATH 指向真实挂载的路由。
  echo "[skip] health scenario retired: /api/health is not mounted by trustgraph :9005 (404 measured 2026-10-06)"
fi

echo "=== summary ==="
cat "$CSV"
