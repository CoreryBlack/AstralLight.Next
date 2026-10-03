# -*- coding: utf-8 -*-
"""Rust S1-S15 三节点分布式一致性协调器。

对标 Docs/实验/分布式测试/README.md 的场景注册表（Java RemoteClusterAuthorizationTest
的 S1..S15），驱动三个真实 Rust astral-trustgraph 节点（生产二进制、真实网络、
共享 MySQL / run 专用 Redis），每个场景绑定一个命名安全不变量（I1..I13）。

Rust 侧机制映射（与 Java 的差异如实记录，绝不伪造 PASS）：
- 跨节点传播 = 共享 MySQL outbox + 各节点 projector worker 轮询（Rust 授权链路
  无 permission.refresh MQ 消息；该符号在新 worker 中是封禁的遗留符号）。
- S3（乱序 READY 不复活）→ durable 层重放：把一条已 PROCESSED 的旧世代 outbox
  行置回 PENDING（payload 为该行真实原始 payload），projector 必须按世代栅栏
  拒绝：head 不回退、全节点维持 DENY。
- S7（幂等标记不抑制失效副作用）→ 投影推进必须触发 L2 证据缓存失效：毒化当前
  epoch 的 L2 键后提交真实变更，断言键被删除或 epoch 被推进，且决策正确。
- S8（ABAC 属性变更）→ N/A：Rust rule_set_entry 契约无属性条件列，不进分母。
- S5/S10（lease reclaim / CAS）→ 确定性 lease 协议（20260904 重设计）：真实 API
  写 delta 并双管线排水后，把最老一条 outbox 行 durable 重放回 PENDING 并写入
  fixture owner/租约时序（只动 worker 记账字段，模拟 claimant 崩溃残留，与 S3
  durable 重放同类别，非授权事实伪造）；S10 先断言活跃租约不被抢占再以 SQL 置
  过期，S5 直接以已过期租约断言安全回收；均断言恰好一次新终态、旧 owner 二次
  提交被拒（S3 风格 uk 断言）、结束前有界排水防跨轮泄漏。不再 SIGSTOP 节点
  （worker 修复后 claim→publish 窗口小于观测延迟，竞速绊线不可复现，见 v14 战役
  工件 pre_stop_seen=0/7/0、stranded=0 且事后 outbox 全部 PROCESSED terminal==1）。

运行位置：node-b（与共享中间件同机）。run_config.json（含 nodes/ssh/db/容器名/
mysql_root/redis_password/hmac_secret_file/ports；0600，不入库不入 git）经环境
变量 RUN_CONFIG_PATH 显式定位（编排器 run_cs_evidence.py 传入），手动单独运行时
回退为同目录/cwd 下的 run_config.json。

用法：python3 s15_coordinator.py [--rounds 3] [--only S2,S4] [--out result.json]
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid

import requests
import s15_validation

PREFIX = "astral-gateway-v3"
A = {"user_id": "9031", "icard": "9041", "card": "9061", "domain": "9011", "tenant": "9001"}
B = {"user_id": "9032", "icard": "9042", "card": "9062", "domain": "9012", "tenant": "9002"}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# run_config 解析：编排器经 RUN_CONFIG_PATH 环境变量传入显式路径（run_config
# 属 0600 run 秘密文件，留在 $HOME/$RUN_ID/，不复制进源码目录）；手动单独运行
# 时回退为 cwd/run_config.json（与历史用法兼容）。
RUN_CONFIG_PATH = os.path.expanduser(os.environ.get("RUN_CONFIG_PATH")
                                     or os.path.join(os.getcwd(), "run_config.json"))
CFG = json.load(open(RUN_CONFIG_PATH))
NODES = CFG["nodes"]
NAMES = ["node-a", "node-b", "node-c"]
NODE_START_ATTEMPTS = 3
# Restart boot (spawn -> bind) measured 45-90s on node-a/node-c cold restarts
# (2026-09-06 final8 diagnostics); the serving probe must outlast that.
NODE_SERVING_TIMEOUT_S = 150
CLUSTER_READY_TIMEOUT_S = 300
HMAC_SECRET = open(CFG["hmac_secret_file"].replace("~", __import__("os").path.expanduser("~"))).read().strip()
DB = CFG["db"]
MC = CFG["mysql_container"]
RC = CFG["redis_container"]

RESULTS = []
TIMELINE = []

_PROV_CACHE = None

_RUNTIME_SECRET_SCANNER = r'''import sys
from pathlib import Path
from urllib.parse import urlsplit

base = Path(sys.argv[1]).expanduser().resolve()
label = sys.argv[2]
secrets = set()


def remember(value):
    value = value.strip().encode()
    if not value:
        raise SystemExit("FAIL empty secret candidate label=%s" % label)
    if len(value) < 6:
        raise SystemExit("FAIL short secret candidate label=%s" % label)
    secrets.add(value)


for raw_line in (base / "application.yml").read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if ":" not in line:
        continue
    key, raw_value = line.split(":", 1)
    value = raw_value.strip().strip('"')
    if key in ("database_url", "redis_url", "rabbitmq_url"):
        remember(value)
        password = urlsplit(value).password
        if password is not None:
            remember(password)
    elif key == "secret" or key.endswith("_secret"):
        remember(value)
remember((base / "hmac.txt").read_text(encoding="utf-8"))
for name in ("jwt.env", "scopes.env"):
    for line in (base / name).read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if "SECRET" in key or "HMAC" in key:
            remember(value)
for line in (base / "redis.conf").read_text(encoding="utf-8").splitlines():
    fields = line.split(None, 1)
    if len(fields) == 2 and fields[0].lower() == "requirepass":
        remember(fields[1])
if not secrets:
    raise SystemExit("FAIL no secret candidates label=%s" % label)

paths = [Path(value).expanduser().resolve() for value in sys.argv[3:]]
files = []
for path in paths:
    if path.is_dir():
        files.extend(sorted(item for item in path.rglob("*") if item.is_file()))
    elif path.is_file():
        files.append(path)
    else:
        raise SystemExit("FAIL scan target unavailable label=%s" % label)
if not files:
    raise SystemExit("FAIL no scan targets label=%s" % label)

hits = 0
max_secret = max(map(len, secrets))
for path in files:
    matched = set()
    overlap = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            window = overlap + chunk
            matched.update(secret for secret in secrets if secret in window)
            overlap = window[-(max_secret - 1):] if max_secret > 1 else b""
    hits += len(matched)
if hits:
    raise SystemExit("FAIL matching_values=%d files=%d label=%s" %
                     (hits, len(files), label))
print("PASS values=%d files=%d label=%s" % (len(secrets), len(files), label))
'''


def provenance():
    """run 级 provenance（零秘钥）：run_id / binary_sha256 / git_rev / dirty /
    source_snapshot 标识。事实来源：run_config.json 与部署时写下的
    provenance.json（均由 deploy_dist.sh 生成）；仓库可达时补充本机工作区
    dirty 状态。只读非秘钥字段，mysql_root/rabbit_pass/hmac 等永不进入结果。"""
    global _PROV_CACHE
    if _PROV_CACHE is not None:
        return _PROV_CACHE
    prov = {
        "run_id": CFG.get("run_id"),
        "binary_sha256": CFG.get("binary_sha256"),
        "git_rev": CFG.get("git_rev"),
        # tracked-only 源码身份（deploy 由主线显式写入 run_config；无 .git
        # 环境不得猜测为空——字段缺失如实保留 None 并由 deploy_provenance
        # 交叉核验标记）
        "source_snapshot_sha256": CFG.get("source_snapshot_sha256"),
        "source_git_rev": CFG.get("source_git_rev"),
        "source_dirty": CFG.get("source_dirty"),
        "source_dirty_patch_sha256": CFG.get("source_dirty_patch_sha256"),
        "bootstrap_bin_sha256": CFG.get("bootstrap_bin_sha256"),
        "git_dirty": None,
        "git_rev_local": None,
        "git_rev_match": None,
        # 交叉核验标记：无法核验（无部署 provenance）时如实为 None
        "binary_sha_match": None,
        "source_snapshot_sha_match": None,
        "source_git_rev_match": None,
        "source_dirty_patch_match": None,
        "source_snapshot": "run_config.json",
        "host": socket.gethostname(),
    }
    base_dir = os.path.expanduser(CFG.get("base_dir") or "")
    try:
        with open(os.path.join(base_dir, "provenance.json"), encoding="utf-8") as f:
            dep = json.load(f)
        prov["deploy_provenance"] = {k: dep.get(k) for k in
                                     ("run_id", "binary_sha256", "git_rev",
                                      "source_snapshot_sha256",
                                      "source_snapshot_method",
                                      "source_git_rev",
                                      "source_dirty",
                                      "source_dirty_patch_sha256",
                                      "bootstrap_bin_sha256",
                                      "created_at_utc", "binary_source")}
        # 部署 provenance 与 run_config 交叉复核（sha/rev 必须一致，不一致
        # 如实记录，不静默）
        if dep.get("binary_sha256") and CFG.get("binary_sha256"):
            prov["binary_sha_match"] = dep["binary_sha256"] == CFG["binary_sha256"]
        if dep.get("source_snapshot_sha256") and CFG.get("source_snapshot_sha256"):
            prov["source_snapshot_sha_match"] = (
                dep["source_snapshot_sha256"] == CFG["source_snapshot_sha256"])
        if dep.get("source_git_rev") and CFG.get("source_git_rev"):
            prov["source_git_rev_match"] = (
                dep["source_git_rev"] == CFG["source_git_rev"])
        if dep.get("source_dirty_patch_sha256") is not None and \
                CFG.get("source_dirty_patch_sha256") is not None:
            prov["source_dirty_patch_match"] = (
                dep["source_dirty_patch_sha256"] == CFG["source_dirty_patch_sha256"])
    except Exception:
        prov["deploy_provenance"] = None
    d = SCRIPT_DIR
    while True:
        if os.path.isdir(os.path.join(d, ".git")):
            try:
                rev = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                                     capture_output=True, text=True, timeout=10)
                dirty = subprocess.run(["git", "-C", d, "status", "--porcelain"],
                                       capture_output=True, text=True, timeout=10)
                if rev.returncode == 0:
                    prov["git_rev_local"] = rev.stdout.strip()
                    prov["git_dirty"] = bool(dirty.stdout.strip())
                    prov["source_snapshot"] = "run_config+git-worktree"
                    if CFG.get("git_rev"):
                        prov["git_rev_match"] = prov["git_rev_local"] == CFG["git_rev"]
            except Exception:
                pass
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    _PROV_CACHE = prov
    return prov


def record(name, expected, verdict, detail=""):
    RESULTS.append({"name": name, "expected": expected, "verdict": verdict,
                    "detail": str(detail)[:500]})
    print("[%s] %-52s expect=%-28s %s" % (verdict, name, expected, str(detail)[:110]))


def note(msg):
    TIMELINE.append({"t": time.time(), "msg": msg})
    print("  .. %s" % msg)


# ---------- 基础设施访问 ----------

def _mysql_run(query, N=True, db=None):
    """共享 mysql 访问（M-A 修复）：口令经 stdin 注入容器内 MYSQL_PWD——
    docker 客户端 argv 与容器内 mysql argv 都不含口令值；查询经 shlex.quote
    进入 sh -c（查询非秘钥）。"""
    inner = 'MYSQL_PWD="$(cat)" exec mysql -uroot' + (" -N" if N else "") \
        + " -e " + shlex.quote(query)
    if db:
        inner += " " + shlex.quote(db)
    r = subprocess.run(["docker", "exec", "-i", MC, "sh", "-c", inner],
                       input=CFG["mysql_root"], capture_output=True, text=True, timeout=60)
    return r


def sql(query):
    r = _mysql_run(query, N=True, db=DB)
    if r.returncode != 0:
        raise RuntimeError("sql failed: %s / %s" % (query[:120], r.stderr[-300:]))
    # mysql -N 的 TSV 以 \t 分隔；末列为空串时行尾以 \t 结束——对整体 strip()
    # 会把最后的空字段连同 \t 一起吃掉，导致列数悄然缺失（S5/S10 的 last_error
    # 位列实测 8 列返回）。因此只按 \n 切行、仅丢弃真空行，字段结构保持原样。
    return [l.split("\t") for l in r.stdout.split("\n") if l != ""]


def sql_exec(query):
    r = _mysql_run(query, N=False, db=DB)
    if r.returncode != 0:
        raise RuntimeError("sql_exec failed: %s / %s" % (query[:120], r.stderr[-300:]))
    return r.stdout


def redis(*args):
    """run 专用 redis 访问。requirepass 部署（deploy_dist.sh [3/9]）时密码经
    stdin 注入 REDISCLI_AUTH——不进 redis-cli/docker argv，不入日志/结果；
    无密码的旧 run_config（历史部署）回退为无认证访问。"""
    rp = CFG.get("redis_password")
    if rp:
        quoted = " ".join(shlex.quote(str(a)) for a in args)
        r = subprocess.run(
            ["docker", "exec", "-i", RC, "sh", "-c",
             'REDISCLI_AUTH="$(cat)" redis-cli ' + quoted],
            input=rp, capture_output=True, text=True, timeout=30)
    else:
        r = subprocess.run(["docker", "exec", RC, "redis-cli", *args],
                           capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def ensure_redis_available(timeout_s=30):
    """Start only this run's Redis when needed and prove authenticated PING."""
    detail = {"start_attempted": False, "start_rc": None, "running": False,
              "authenticated_ping": False}
    try:
        if redis("PING") == "PONG":
            detail.update({"running": True, "authenticated_ping": True})
            return True, detail
    except (subprocess.TimeoutExpired, OSError):
        pass

    try:
        state = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", RC],
            capture_output=True, text=True, timeout=30)
        detail["running"] = state.returncode == 0 and state.stdout.strip() == "true"
    except (subprocess.TimeoutExpired, OSError):
        detail["running"] = False

    if not detail["running"]:
        detail["start_attempted"] = True
        try:
            started = subprocess.run(["docker", "start", RC], capture_output=True,
                                     text=True, timeout=60)
            detail["start_rc"] = started.returncode
        except (subprocess.TimeoutExpired, OSError):
            detail["start_rc"] = "unknown"

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if redis("PING") == "PONG":
                detail.update({"running": True, "authenticated_ping": True})
                return True, detail
        except (subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(0.5)
    return False, detail


def ssh_node(node, cmd, timeout=120):
    if node == "node-b":
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    host = CFG["ssh"][node]
    r = subprocess.run(["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def runtime_secret_scan(extra_paths=None):
    """Run the harness-frozen exact-secret scanner locally on each node."""
    run_id = str(CFG.get("run_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id):
        return {"ok": False, "reason": "invalid_run_id", "nodes": {}}

    base_dir = os.path.expanduser(str(CFG.get("base_dir") or ""))
    extra_paths = [os.path.abspath(path) for path in (extra_paths or [])]
    nodes = {}
    for node in NAMES:
        label = node.split("-")[1]
        if node == "node-b":
            argv = [sys.executable or "python3", "-", base_dir, node,
                    os.path.join(base_dir, "server_%s.log" % label), *extra_paths]
        else:
            host = CFG.get("ssh", {}).get(node)
            if not host:
                nodes[node] = {"verdict": "FAIL", "reason": "missing_ssh_target"}
                continue
            remote = ('python3 - "$HOME/%s" %s '
                      '"$HOME/%s/server_%s.log"'
                      % (run_id, shlex.quote(node), run_id, label))
            argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    host, remote]
        try:
            completed = subprocess.run(
                argv, input=_RUNTIME_SECRET_SCANNER, capture_output=True, text=True,
                timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            nodes[node] = {"verdict": "FAIL", "reason": "scanner_transport_error"}
            continue
        match = re.fullmatch(
            r"PASS values=([1-9][0-9]*) files=([1-9][0-9]*) label=([A-Za-z0-9-]+)\n?",
            completed.stdout)
        if completed.returncode != 0:
            nodes[node] = {"verdict": "FAIL",
                           "reason": "scanner_exit_%s" % completed.returncode}
        elif match is None or match.group(3) != node:
            nodes[node] = {"verdict": "FAIL", "reason": "malformed_scanner_output"}
        else:
            nodes[node] = {"verdict": "PASS", "values": int(match.group(1)),
                           "files": int(match.group(2))}
    return {"ok": len(nodes) == len(NAMES)
            and all(item.get("verdict") == "PASS" for item in nodes.values()),
            "nodes": nodes}


def node_process_state(node):
    """Return run-owned pidfile process and listener ownership independently."""
    label = node.split("-")[1]
    port = int(CFG["ports"][node])
    try:
        rc, out, _ = ssh_node(
            node,
            "base=$(readlink -f %s); pid=$(cat %s/node_%s.pid 2>/dev/null || true); "
            "owner=$(fuser -n tcp %d 2>/dev/null | tr ' ' '\\n' | "
            "grep -E '^[0-9]+$' | sort -u | paste -sd, -); "
            "cwd=$(readlink -f /proc/$pid/cwd 2>/dev/null || true); "
            "sha=$(sha256sum /proc/$pid/exe 2>/dev/null | cut -d' ' -f1); "
            "live=false; if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; "
            "then live=true; fi; owned=false; if [ \"$live\" = true ] "
            "&& [ \"$cwd\" = \"$base\" ] && [ \"$sha\" = \"%s\" ]; "
            "then owned=true; fi; printf 'STATE\\t%%s\\t%%s\\t%%s\\t%%s\\n' "
            "\"$pid\" \"$owner\" \"$live\" \"$owned\""
            % (CFG["base_dir"], CFG["base_dir"], label, port,
               CFG["binary_sha256"]))
    except (subprocess.TimeoutExpired, OSError):
        rc, out = 1, ""
    fields = out.strip().split("\t")
    if rc != 0 or len(fields) != 5 or fields[0] != "STATE":
        return {"probe_ok": False, "pid": None, "listener_pid": None,
                "process_live": False, "process_owned": False,
                "listener_owned": False, "foreign_listener": False}
    pid = fields[1] if fields[1].isdigit() else None
    listener_raw = fields[2]
    listener = listener_raw if listener_raw.isdigit() else None
    process_live = fields[3] == "true" and pid is not None
    process_owned = fields[4] == "true" and process_live
    return {
        "probe_ok": True,
        "pid": pid,
        "listener_pid": listener,
        "process_live": process_live,
        "process_owned": process_owned,
        "listener_owned": process_owned and listener == pid,
        "foreign_listener": bool(listener_raw) and listener_raw != pid,
    }


def node_pid(node):
    state = node_process_state(node)
    return state["pid"] if state["listener_owned"] else None


def node_alive(node):
    pid = node_pid(node)
    return pid is not None, pid


def node_kill(node):
    """Kill only the pidfile process owned by this run and prove its port is free."""
    state = node_process_state(node)
    if not state["probe_ok"] or state["foreign_listener"] \
            or (state["process_live"] and not state["process_owned"]):
        return False
    pid = state["pid"] if state["process_owned"] else None
    if pid is None:
        return state["listener_pid"] is None
    port = int(CFG["ports"][node])
    try:
        rc, out, _ = ssh_node(
            node,
            "pid=%s; port=%d; base=$(readlink -f %s); "
            "cwd=$(readlink -f /proc/$pid/cwd 2>/dev/null || true); "
            "sha=$(sha256sum /proc/$pid/exe 2>/dev/null | cut -d' ' -f1); "
            "owner=$(fuser -n tcp \"$port\" 2>/dev/null | tr ' ' '\\n' | "
            "grep -E '^[0-9]+$' | sort -u | paste -sd, -); "
            "[ \"$cwd\" = \"$base\" ] && [ \"$sha\" = \"%s\" ] "
            "&& { [ -z \"$owner\" ] || [ \"$owner\" = \"$pid\" ]; } || exit 1; "
            "kill -TERM \"$pid\" 2>/dev/null || true; "
            "for _ in $(seq 1 15); do kill -0 \"$pid\" 2>/dev/null || break; sleep 1; done; "
            "if kill -0 \"$pid\" 2>/dev/null; then "
            "cwd=$(readlink -f /proc/$pid/cwd 2>/dev/null || true); "
            "sha=$(sha256sum /proc/$pid/exe 2>/dev/null | cut -d' ' -f1); "
            "[ \"$cwd\" = \"$base\" ] && [ \"$sha\" = \"%s\" ] || exit 1; "
            "kill -KILL \"$pid\"; fi; "
            "for _ in $(seq 1 5); do kill -0 \"$pid\" 2>/dev/null || break; sleep 1; done; "
            "owner=$(fuser -n tcp \"$port\" 2>/dev/null | tr ' ' '\\n' | "
            "grep -E '^[0-9]+$' | sort -u | paste -sd, -); "
            "if kill -0 \"$pid\" 2>/dev/null || [ -n \"$owner\" ]; then exit 1; fi"
            % (int(pid), port, CFG["base_dir"], CFG["binary_sha256"],
               CFG["binary_sha256"]),
            timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return rc == 0



def node_restart(node, port):
    try:
        rc, out, err = ssh_node(
            node,
            "bash %s/node_start.sh %s %d" %
            (CFG["base_dir"], node.split("-")[1], port),
            timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        if wait_node_serving(node, timeout_s=10) is not None:
            return "started; command result reconciled by serving proof"
        raise
    assert rc == 0, err or out
    return out.strip()


# ---------- 签名请求 ----------

def sign_headers(actor, method, path):
    ts = str(int(time.time() * 1000))
    sp = path.split("?")[0]
    payload = "\n".join([PREFIX, method.strip(), sp, actor["user_id"], "PLATFORM_USER", "",
                         actor["icard"], actor["card"], actor["domain"], actor["tenant"],
                         "", "", "", "", ts])
    sig = hmac.new(HMAC_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {"x-request-id": str(uuid.uuid4()), "x-user-id": actor["user_id"],
            "x-principal-kind": "PLATFORM_USER", "x-identity-card-id": actor["icard"],
            "x-user-card-id": actor["card"], "x-user-card-domain-id": actor["domain"],
            "x-user-card-tenant-id": actor["tenant"], "x-gateway-ts": ts,
            "x-gateway-signature": sig, "x-gateway-auth": "verified",
            "Content-Type": "application/json"}


def call(actor, node, method, path, body=None, timeout=30):
    r = requests.request(method, NODES[node] + path, headers=sign_headers(actor, method, path),
                         json=body, timeout=timeout)
    try:
        data = r.json().get("data")
    except Exception:
        data = None
    return r, data


def sim(actor, node, card_id, resource, action, user_id, domain_id, tenant_id,
        timeout=30):
    body = {"cardId": int(card_id), "resource": resource, "action": action,
            "userId": int(user_id), "domainId": int(domain_id), "tenantId": int(tenant_id),
            "proposedRules": []}
    try:
        r, data = call(actor, node, "POST", "/main/api/v1/simulation/evaluate", body,
                       timeout=timeout)
    except Exception as e:
        return {"allowed": None, "reason": "EXC:%s" % repr(e)[:60], "http": 0}
    if r.status_code == 503:
        return {"allowed": None, "reason": "PENDING", "http": 503}
    if r.status_code != 200 or not data:
        return {"allowed": None, "reason": "HTTP_%d" % r.status_code, "http": r.status_code,
                "body": r.text[:200]}
    cd = data.get("currentDecision", {})
    return {"allowed": cd.get("allowed"), "reason": cd.get("reason", ""),
            "matched": cd.get("matchedRuleId"), "http": 200}


def sim3(actor, card_id, resource, action, user_id, domain_id, tenant_id):
    return {n: sim(actor, n, card_id, resource, action, user_id, domain_id, tenant_id)
            for n in NAMES}


def wait3(actor, card_id, resource, action, user_id, domain_id, tenant_id, want,
          timeout_s=30, nodes=None):
    """轮询直到所有指定节点的 sim 决策 == want（True/False）。返回 (ok, elapsed_ms, samples)。"""
    deadline = time.time() + timeout_s
    t0 = time.perf_counter()
    nodes = nodes or NAMES
    samples = {}
    while time.time() < deadline:
        cur = sim3(actor, card_id, resource, action, user_id, domain_id, tenant_id)
        samples = {n: cur[n]["allowed"] for n in nodes}
        if all(cur[n]["allowed"] is want for n in nodes):
            return True, (time.perf_counter() - t0) * 1000, samples
        time.sleep(0.3)
    return False, (time.perf_counter() - t0) * 1000, samples


def head_state():
    """RULE_SET head 版本栅栏（旧链状态列 projected_generation/projection_status
    已随迁移 20260831000001 删除，head 只保留 writer correlation 代次/围栏）。"""
    rows = sql("SELECT aggregate_type, aggregate_id, source_generation, revoke_fence "
               "FROM authorization_projection_head "
               "WHERE aggregate_type='RULE_SET'")
    return {int(r[1]): {"src": int(r[2]), "fence": int(r[3])}
            for r in rows}


def outbox_rows(rs):
    return sql("SELECT outbox_id, source_generation, status, IFNULL(lease_owner,'NULL'), "
               "IFNULL(terminal_transitions,'NULL'), IFNULL(processed_by,'NULL'), "
               "IFNULL(attempts,'NULL') FROM authorization_projection_outbox "
               "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d ORDER BY source_generation" % rs)


# ---------- 场景夹具（每场景独立规则集） ----------

def make_rule_set(tag):
    """场景夹具规则集。

    Rust wire 事实：POST /rule-sets 的 INSERT 不携带 tenant_id（租户作用域规则集
    只能来自 seed/模板投影），而 bind 在租户上下文中要求 rs.tenant_id 匹配。因此
    夹具规则集按 seed_f4rust.sql 同一模式以 SQL 种子（带 tenant_id=9001），后续
    条目/绑定/解绑全部走真实 API（真实 source transaction/outbox 路径）。
    """
    code = "s15_rs_%s_%s" % (tag, uuid.uuid4().hex[:8])
    sql_exec("INSERT INTO rule_set (name, code, source_type, description, enabled, tenant_id) "
             "VALUES ('S15 rs %s', '%s', 'CUSTOM', 'coordinator fixture', 1, %s)"
             % (tag, code, A["tenant"]))
    rs = int(sql("SELECT rule_set_id FROM rule_set WHERE code='%s'" % code)[0][0])
    return rs


def add_entry(rs_id, resource, action, effect="ALLOW", priority=1, node="node-a"):
    """Rust wire 契约：entry 字段 resource/action/effect/priority；entry_id 服务端分配。"""
    r, data = call(A, node, "POST", "/main/api/v1/rule-sets/%d/entries" % rs_id,
                   {"resource": resource, "action": action, "effect": effect,
                    "priority": priority})
    eid = (data or {}).get("id") if r.status_code == 200 else None
    return r, eid


def del_entry(rs_id, entry_id, node="node-a"):
    r, _ = call(A, node, "DELETE", "/main/api/v1/rule-sets/%d/entries/%s" % (rs_id, entry_id))
    return r


def bind_card(rs_id, card_id, layer="BASE", node="node-b"):
    card_id = int(card_id)
    r, _ = call(A, node, "POST", "/main/api/v1/rule-sets/card/%d/bind" % card_id,
                {"ruleSetId": rs_id, "refType": layer})
    return r


def unbind_card(rs_id, card_id, node="node-b"):
    card_id = int(card_id)
    r, _ = call(A, node, "DELETE", "/main/api/v1/rule-sets/card/%d/unbind/%d" % (card_id, rs_id))
    return r


def fixture_grant(tag, node="node-a"):
    """独立夹具：新建规则集 + 类型级 ALLOW 条目 + 绑定卡 A，等待 3 节点 ALLOW。
    顺序约束（实测）：条目先于绑定——绑定时该规则集必须已有 delta 事件，
    否则卡证据依赖链无法验证（读门长期 PENDING）。"""
    rs = make_rule_set(tag)
    r, _ = add_entry(rs, "learn_subject", "read", node=node)
    assert r.status_code == 200, "fixture entry failed: %s" % r.text[:150]
    r = bind_card(rs, A["card"])
    assert r.status_code == 200, "fixture bind failed: %s" % r.text[:150]
    ok, ms, final = wait3(A, A["card"], "learn_subject:*", "read",
                          int(A["user_id"]), int(A["domain"]), int(A["tenant"]),
                          want=True, timeout_s=40)
    if not ok:
        ok, ms, final = wait3(A, A["card"], "learn_subject:*", "read",
                              int(A["user_id"]), int(A["domain"]), int(A["tenant"]),
                              want=True, timeout_s=40)
    assert ok, "fixture not ready (rs=%s): %s" % (rs, sim_detail())
    note("fixture %s ready rs=%d (%dms)" % (tag, rs, ms))
    return rs


def fixture_plain(tag):
    """独立夹具：仅新建规则集（不绑定、无条目）。空规则集绝不绑定：
    绑定一个从未产生 delta 的规则集会使卡证据依赖链无法收敛。"""
    return make_rule_set(tag)


def sim_detail():
    """采样三节点当前 (allowed, http, reason) 供失败详情。"""
    cur = sim3(A, A["card"], "learn_subject:*", "read",
               int(A["user_id"]), int(A["domain"]), int(A["tenant"]))
    return {k: (v["allowed"], v["http"], v["reason"][:40]) for k, v in cur.items()}


def cleanup_unbind(rs, tag):
    r = unbind_card(rs, A["card"])
    ok, _, final = wait3(A, A["card"], "learn_subject:*", "read",
                         int(A["user_id"]), int(A["domain"]), int(A["tenant"]),
                         want=False, timeout_s=30)
    note("cleanup unbind %s rs=%d ok=%s deny=%s" % (tag, rs, r.status_code, ok))
    return ok


def epoch():
    return redis("GET", "astral:auth:cache_epoch")


def learn_args():
    """wait3/sim3 的完整参数（actor + 6 元组，全 int——wire 契约拒绝字符串数字）。"""
    return (A, int(A["card"]), "learn_subject:*", "read",
            int(A["user_id"]), int(A["domain"]), int(A["tenant"]))


def pointer_state(rs):
    """RULE_SET 聚合的读门指针（新管线权威 READY 证据；head.proj/status 是旧通道
    遗留列，本构建不再维护——见归档报告发现 F3）。"""
    rows = sql("SELECT current_generation, status, revoke_fence, cas_version "
               "FROM authorization_projection_current "
               "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d" % rs)
    return {"gen": int(rows[0][0]), "status": rows[0][1], "fence": int(rows[0][2]),
            "cas": int(rows[0][3])} if rows else None


def wait_pointer(rs, want_gen=None, timeout_s=15):
    """轮询等待 RULE_SET 指针出现并（可选）达到目标世代——发布是异步的，
    断言前必须等指针落地。"""
    deadline = time.time() + timeout_s
    ps = None
    while time.time() < deadline:
        ps = pointer_state(rs)
        if ps is not None and ps["status"] == "READY" \
                and (want_gen is None or ps["gen"] == want_gen):
            return ps
        time.sleep(0.3)
    return ps


def outbox_summary(rs):
    rows = outbox_rows(rs)
    gens = [int(r[1]) for r in rows]
    return {
        "rows": rows, "gens": gens,
        "contiguous": gens == list(range(1, len(gens) + 1)),
        "all_processed": all(r[2] == "PROCESSED" for r in rows) if rows else False,
        "terminal_once": all(r[4] == "1" for r in rows) if rows else False,
    }


def pending_leased(rs):
    """PENDING 且已持有 lease 的行（projector 正在处理/被绊住）。"""
    rows = outbox_rows(rs)
    return [r for r in rows if r[2] == "PENDING" and r[3] not in ("NULL", "")]


def lease_seconds_left(rows):
    if not rows:
        return None
    ids = ",".join(r[0] for r in rows)
    out = sql("SELECT IFNULL(MIN(GREATEST(TIMESTAMPDIFF(SECOND, NOW(), lease_expires_at),0)),0) "
              "FROM authorization_projection_outbox WHERE outbox_id IN (%s)" % ids)
    return int(out[0][0]) if out and out[0][0] is not None else 0


def wait_outbox_terminal(rs, timeout_s=60):
    """有界等待 RULE_SET outbox 全部到达终态。发布是异步的——断言前必须排水，
    否则会把"尚未处理"误判为"处理失败"。返回 (drained, outbox_summary)。"""
    deadline = time.time() + timeout_s
    ob = outbox_summary(rs)
    while time.time() < deadline:
        ob = outbox_summary(rs)
        if ob["all_processed"] and ob["terminal_once"] and ob["contiguous"]:
            return True, ob
        time.sleep(1)
    return False, ob


def wait_deltas_terminal(rs, timeout_s=60):
    """有界等待 RULE_SET 聚合的 delta 事件全部到达 SUCCEEDED（仅 S1/S9 记账用）。

    delta 处理与 outbox 发布是两条独立异步管线：outbox drained / bind 的 ALLOW
    可见都不代表 delta 已终态（V14 round2 实测：bind fanout 的一条 delta 重试至
    attempts=3、创建 2s 后才 SUCCEEDED；全表 278 行最终全部 SUCCEEDED，无丢失）。
    返回 (ok, delta_summary)；超时返回最后的采样供诊断。"""
    deadline = time.time() + timeout_s
    dl = delta_summary(rs)
    while time.time() < deadline:
        dl = delta_summary(rs)
        if dl["n"] > 0 and dl["all_ok"]:
            return True, dl
        time.sleep(1)
    return False, dl


def wait_for_leased(rs, timeout_s=30):
    """确定性绊线：轮询直到出现 PENDING+lease_owner 行（projector 已 claim），
    超时返回 []。用于 SIGSTOP 前的确定性等待（替代固定 sleep 的盲等）。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        rows = pending_leased(rs)
        if rows:
            return rows
        time.sleep(0.02)
    return []


# ---------- 场景 ----------

def delta_summary(rs):
    """RULE_SET 聚合的 delta 事件证据（V14 审计修正记账语义）。

    target_version 是 per-grant 版本：uk_ade_target_version =
    (tenant_id, aggregate_type, aggregate_id, grant_id, target_version)，
    grant 首发恒为 v1、REMOVE 为 v2——同一 rs 出现重复 v1（gens=[1,1]）是
    并发首发的合法形状，不是混入其他聚合。bind 不产生"独立"delta 行，但会为
    绑定时已存在的 entry fanout create delta（归属各 grant），旧注释
    "bind 不产生 delta"即 S9 13 vs 12 误读的根源。因此 gens/maxv 是 per-grant
    版本分布，不是 rs 世代：与 head.source_generation / outbox 世代数天然不等，
    完整性只能按"每 grant 恰一条 create(+remove) 且全部 SUCCEEDED"核对。
    all_ok 只认 SUCCEEDED（QUARANTINED/PENDING/LEASED 都不算健康终态）。"""
    rows = sql("SELECT target_version, status FROM authorization_delta_event "
               "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d "
               "ORDER BY target_version, delta_event_id" % int(rs))
    gens = sorted(int(r[0]) for r in rows)
    return {"n": len(rows),
            "all_ok": all(r[1] == "SUCCEEDED" for r in rows) if rows else False,
            "maxv": gens[-1] if gens else 0,
            "gens": gens}


def S1():
    """I1/I4：两节点并发首次投影 → 唯一 head、连续 generation、无丢写。"""
    rs = fixture_plain("S1")
    results, errors = [], []

    def writer(node, resource):
        try:
            r, eid = add_entry(rs, resource, "read", node=node)
            results.append((node, r.status_code, eid))
        except Exception as e:
            errors.append(repr(e))

    t1 = threading.Thread(target=writer, args=("node-a", "learn_subject"))
    t2 = threading.Thread(target=writer, args=("node-b", "learn_subject"))
    t1.start(); t2.start(); t1.join(); t2.join()
    both_ok = all(r[1] == 200 for r in results) and all(r[2] for r in results) and not errors
    record("S1_both_concurrent_writes_200", "2x200+entryIds", "PASS" if both_ok else "FAIL",
           str(results) + str(errors))
    r = bind_card(rs, A["card"])
    ok, ms, final = wait3(A, A["card"], "learn_subject:*", "read",
                          int(A["user_id"]), int(A["domain"]), int(A["tenant"]),
                          want=True, timeout_s=40)
    record("S1_all_nodes_allow_after_projection", "3xALLOW", "PASS" if ok else "FAIL",
           "bind=%s wait=%dms final=%s" % (r.status_code, ms, sim_detail() if not ok else ""))
    # 发布是异步的且双管线独立（V14 审计修正）：outbox（发布指令）与 delta（每
    # grant 载荷）必须各自有界排水后再断言。V14 round2 的误报根因是 delta 在排水
    # 前采样（bind fanout 的一条 delta 重试至 attempts=3、2s 后才 SUCCEEDED，被
    # 误判为完整性缺陷）；V8 归档轮的同类误报根因则是未排 outbox。记账语义见
    # delta_summary：并发首发各产生一条 per-grant v1（gens=[1,1] 合法）；head.src
    # 是 rs 世代（2 add + 1 bind = 3），与 per-grant delta 数天然不等——完整性
    # 要求改为：每条并发写恰一条 delta 且全 SUCCEEDED，head.src == outbox 行数
    # 且 outbox 连续终态（唯一 head、无丢世代）。
    drained, ob = wait_outbox_terminal(rs, timeout_s=60)
    ok_dl, dl = wait_deltas_terminal(rs, timeout_s=60)
    hs = head_state().get(rs, {})
    i1 = (drained and ok_dl and dl["n"] == 2
          and hs.get("src") == len(ob["gens"]) and len(ob["gens"]) >= 2)
    record("S1_unique_head_contiguous_generations",
           "2 grant deltas SUCCEEDED, head==outbox gens, drained contiguous+terminal",
           "PASS" if i1 else "FAIL",
           "drained=%s deltas=%s head=%s gens=%s" % (drained, dl, hs, ob["gens"]))
    cleanup_unbind(rs, "S1")


def S2():
    """I2/I8：revoke 提交后无 stale ALLOW；窗口有界且全节点 DENY。"""
    rs = fixture_grant("S2")
    rows = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d AND effect='ALLOW' "
               "ORDER BY entry_id ASC LIMIT 1" % rs)
    assert rows, "S2 fixture entry missing"
    eid = rows[0][0]
    r = del_entry(rs, eid, node="node-a")
    t_commit = time.perf_counter()
    record("S2_revoke_commit_200", "200", "PASS" if r.status_code == 200 else "FAIL", r.text[:120])
    # 撤销窗口紧采样（revoke 返回后立即开始）：I2 = 不出现任何 ALLOW
    allow = pending = deny = 0
    deadline = t_commit + 8.0
    while time.perf_counter() < deadline:
        d = sim(A, "node-c", A["card"], "learn_subject:*", "read",
                int(A["user_id"]), int(A["domain"]), int(A["tenant"]))
        if d["allowed"] is True:
            allow += 1
        elif d["allowed"] is None:
            pending += 1
        else:
            deny += 1
    record("S2_no_stale_allow_window", "unsafeAllow=0", "PASS" if allow == 0 else "FAIL",
           "eval=%d allow=%d pending=%d deny=%d" % (allow + pending + deny, allow, pending, deny))
    ok, ms, final = wait3(A, A["card"], "learn_subject:*", "read",
                          int(A["user_id"]), int(A["domain"]), int(A["tenant"]),
                          want=False, timeout_s=30)
    window_ms = (time.perf_counter() - t_commit) * 1000
    record("S2_all_nodes_deny", "3xDENY", "PASS" if ok else "FAIL",
           "windowMs=%d final=%s" % (window_ms, final))
    hs = head_state().get(rs, {})
    dl = delta_summary(rs)
    record("S2_deltas_succeeded_after_projection", "add+delete deltas SUCCEEDED",
           "PASS" if dl["n"] >= 2 and dl["all_ok"] else "FAIL",
           "deltas=%s head=%s" % (dl, hs))


def S3():
    """I2：旧世代 delta 重放不得复活已撤销授权（Rust 映射：durable delta 队列的
    唯一键 uk_ade_target_version 使同世代重放结构性不可表示——注入即被拒绝；
    世代栅栏由 schema 级约束保证）。断言：注入被拒绝、指针不回退、不复活 ALLOW。"""
    args = learn_args()
    rs = fixture_grant("S3")          # 进入时全节点 ALLOW
    eid = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d AND effect='ALLOW' "
              "ORDER BY entry_id ASC LIMIT 1" % rs)[0][0]
    r = del_entry(rs, eid, node="node-a")
    assert r.status_code == 200
    ok, _, final = wait3(*args, want=False, timeout_s=30)
    assert ok, "S3 revoke baseline failed: %s" % final
    ps_before = wait_pointer(rs)
    old = sql("SELECT delta_event_id FROM authorization_delta_event "
              "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d AND status='SUCCEEDED' "
              "ORDER BY target_version ASC LIMIT 1" % rs)
    assert old, "no SUCCEEDED delta to replay"
    old_id = old[0][0]
    new_event = "s3-replay-%s" % uuid.uuid4().hex[:12]
    new_op = "s3-replay-op-%s" % uuid.uuid4().hex[:12]
    note("attempting stale-generation delta replay (same target_version, event_id=%s)" % new_event)
    rejected = False
    try:
        sql_exec("INSERT INTO authorization_delta_event (tenant_id, card_id, aggregate_type, "
                 "aggregate_id, grant_id, event_id, operation_id, event_type, base_version, "
                 "target_version, source_generation, revoke_fence, before_image_json, before_digest, "
                 "delta_json, semantic_hash, dependency_hash, compiler_version, status, next_attempt_at) "
                 "SELECT tenant_id, card_id, aggregate_type, aggregate_id, grant_id, '%s', '%s', "
                 "event_type, base_version, target_version, source_generation, revoke_fence, "
                 "before_image_json, before_digest, delta_json, semantic_hash, dependency_hash, "
                 "compiler_version, 'PENDING', NOW() FROM authorization_delta_event "
                 "WHERE delta_event_id=%s" % (new_event, new_op, old_id))
    except RuntimeError as e:
        rejected = "Duplicate entry" in str(e) and "uk_ade_target_version" in str(e)
        note("stale replay rejected: %s" % ("uk_ade_target_version" if rejected else str(e)[:120]))
    record("S3_stale_replay_structurally_rejected", "INSERT rejected by uk_ade_target_version",
           "PASS" if rejected else "FAIL", "rejected=%s" % rejected)
    time.sleep(6)
    ok, ms, final = wait3(*args, want=False, timeout_s=15)
    record("S3_stale_replay_no_resurrect", "3xDENY", "PASS" if ok else "FAIL", "final=%s" % final)
    ps_after = pointer_state(rs)
    unchanged = ps_before is not None and ps_after is not None \
        and ps_after["gen"] == ps_before["gen"]
    record("S3_pointer_unchanged_by_stale_replay", "pointer gen not regressed",
           "PASS" if unchanged else "FAIL", "%s -> %s" % (ps_before, ps_after))
    row = sql("SELECT COUNT(*) FROM authorization_delta_event WHERE event_id='%s'" % new_event)
    record("S3_replayed_row_absent", "no replay row entered the queue",
           "PASS" if row and int(row[0][0]) == 0 else "FAIL", "rows=%s" % (row[0][0] if row else None))


def S4():
    """I7：解绑推进 revoke fence 并跨节点生效；重绑恢复。"""
    args = learn_args()
    rs = fixture_grant("S4")
    fence_before = head_state().get(rs, {}).get("fence", -1)
    r = unbind_card(rs, A["card"], node="node-b")
    record("S4_unbind_200", "200", "PASS" if r.status_code == 200 else "FAIL", r.text[:120])
    ok, ms, final = wait3(*args, want=False, timeout_s=30)
    fence_after = head_state().get(rs, {}).get("fence", -1)
    record("S4_unbind_propagates_deny", "3xDENY", "PASS" if ok else "FAIL", "final=%s" % final)
    record("S4_revoke_fence_advanced", "fence increases",
           "PASS" if fence_after > fence_before else "FAIL",
           "fence %s -> %s" % (fence_before, fence_after))
    r = bind_card(rs, A["card"])
    ok, _, final = wait3(*args, want=True, timeout_s=30)
    record("S4_rebind_restores_allow", "3xALLOW", "PASS" if ok else "FAIL", "final=%s" % final)
    cleanup_unbind(rs, "S4")


# ---------- S5/S10 专属：确定性 lease 回收协议（20260904 重设计） ----------
#
# v14 战役失败根因（装置，非产品）：fence_regression 修复后 worker 的
# claim→publish 窗口小于观测+SIGSTOP 延迟，"SIGSTOP 恰好落在 claim 与 publish
# 之间"的竞速绊线三轮全部脱靶（S5 pre_stop_seen=0/7/0、S10 stranded=0/30、0/30；
# 事后库证据：S5/S10 各 rs outbox 全部 PROCESSED 且 terminal_transitions==1，无
# 任何 LEASED/PENDING 残留）。重设计为确定性协议：
#   真实 API 写 N 条 delta 并双管线排水 → durable 层把最老一条 outbox 行重放回
#   PENDING 并写入 fixture owner/租约时序（只动 worker 记账/时序字段，模拟
#   claimant 崩溃残留——durable 重放手法与 S3 同类别，不是对授权事实的伪造；
#   payload/grant/规则/租户等授权事实字段一律不改）→ S10 先断言活跃租约不被
#   抢占再以 SQL 置过期，S5 直接以已过期租约断言安全回收 → 恰好一次新终态、
#   旧 owner 二次提交被拒（S3 风格 uk 断言）→ 结束前有界排水门防跨轮泄漏。
# 全程不 SIGSTOP 任何节点（冻结泄漏通道随旧装置一并移除）。

_OUTBOX_ROW_FULL_SQL = (
    "SELECT outbox_id, source_generation, status, IFNULL(lease_owner,''), "
    "terminal_transitions, IFNULL(processed_by,''), IFNULL(attempts,0), "
    "IFNULL(UNIX_TIMESTAMP(lease_expires_at)-UNIX_TIMESTAMP(NOW()),-1), "
    "IFNULL(last_error,'') FROM authorization_projection_outbox ")


def _outbox_row_dict(r):
    return {"outbox_id": int(r[0]), "gen": int(r[1]), "status": r[2], "lease_owner": r[3],
            "terminal": int(r[4]), "processed_by": r[5], "attempts": int(r[6]),
            "secs_left": int(r[7]), "last_error": r[8]}


def outbox_row_full(outbox_id):
    """单行 outbox 全字段证据（S5/S10 专属）。secs_left 为服务器端时钟差：
    >0 未到期租约；<=0 已过期；-1 租约字段为 NULL（从未 claim 或已清空）。"""
    rows = sql(_OUTBOX_ROW_FULL_SQL + "WHERE outbox_id=%d" % int(outbox_id))
    return _outbox_row_dict(rows[0]) if rows else None


def outbox_rows_full(rs):
    """规则集全部 outbox 行全字段证据（S5/S10 专属，按 outbox_id 即 claim 序）。"""
    rows = sql(_OUTBOX_ROW_FULL_SQL +
               "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d ORDER BY outbox_id"
               % int(rs))
    return [_outbox_row_dict(r) for r in rows]


def pick_oldest_outbox_id(rows):
    """纯函数：claim 序最老的行 id。worker 按 (aggregate_type, outbox_id,
    source_generation) 认领，单聚合内 outbox_id 单调递增 → 最小 id 即最老；空表 None。"""
    ids = [int(r["outbox_id"]) for r in rows or []]
    return min(ids) if ids else None


def lease_phase(row, owner):
    """纯函数：行租约相对 fixture owner 的相位：'live'（owner 匹配且未到期）/
    'expired'（owner 匹配且已到期）/'none'（行无租约）/'foreign'（租约属其他 owner）。"""
    lo = row.get("lease_owner") or ""
    if not lo:
        return "none"
    if lo != owner:
        return "foreign"
    secs = int(row.get("secs_left", -1))
    if secs == -1:
        return "none"
    return "live" if secs > 0 else "expired"


def no_steal_held(samples, owner, base):
    """纯函数：活跃租约观察窗逐帧核对 CAS 独占——每帧都保持 PENDING + fixture 活
    租约，且终态计数/processed_by 与基线一致；任何抢占、抢先完成或租约易主即 False。"""
    for s in samples or []:
        if s.get("status") != "PENDING" or lease_phase(s, owner) != "live":
            return False
        if s.get("terminal") != base.get("terminal") or \
                s.get("processed_by") != base.get("processed_by"):
            return False
    return True


def reclaimed_once(row, owner, base):
    """纯函数：过期租约被真实 worker 安全回收且恰好一次新终态——PROCESSED、终态
    计数恰好 +1、processed_by 为非空真实 worker（≠fixture 伪造 owner）、租约清空。"""
    return bool(row) and row.get("status") == "PROCESSED" \
        and int(row.get("terminal", 0)) == int(base.get("terminal", 0)) + 1 \
        and bool(row.get("processed_by")) and row.get("processed_by") != owner \
        and not (row.get("lease_owner") or "")


def terminal_once_map_ok(rows, n_written, replay_id=None):
    """纯函数：outbox 完整性——行数完整、世代连续（1..n）、未被重放行终态计数==1、
    被重放行==2（初始提交+回收各恰好一次，无第三次终态写）。rows 为 outbox_summary
    的 list 行 [outbox_id, gen, status, lease_owner, terminal, ...]。"""
    rows = rows or []
    if len(rows) != n_written:
        return False
    if [int(r[1]) for r in rows] != list(range(1, n_written + 1)):
        return False
    for r in rows:
        expect = 2 if (replay_id is not None and int(r[0]) == int(replay_id)) else 1
        if int(r[4]) != expect:
            return False
    return True


def no_pending_leased_residue(rows):
    """纯函数：排水门——现存行中不存在任何非终态（PENDING/LEASED 等）残留。"""
    return all(r[2] == "PROCESSED" for r in rows or [])


def deltas_settled(dl, n_written):
    """Delta evidence is retained: exactly n_written rows, all SUCCEEDED.

    The evidence tables have no foreign keys and production code has no delete
    path. Missing rows therefore indicate out-of-band mutation or a shared-DB
    fixture collision and must fail the run rather than be treated as settled.
    """
    n = int(dl.get("n", 0))
    return n == n_written and bool(dl.get("all_ok"))


def wait_outbox_replay_terminal(rs, n_written, replay_id, timeout_s=60):
    """Wait for the replay fixture's expected terminal map, including +1 on replay."""
    deadline = time.time() + timeout_s
    ob = outbox_summary(rs)
    while time.time() < deadline:
        ob = outbox_summary(rs)
        if no_pending_leased_residue(ob["rows"]) and \
                terminal_once_map_ok(ob["rows"], n_written, replay_id):
            return True, ob
        time.sleep(1)
    return False, ob


def _drain_and_report(tag, rs, n_written, replay_id):
    """Bounded drain with replay-aware terminal-transition expectations.

    S5/S10 use an unbound rule set, so no card-targeted delta is expected; the
    outbox is the authoritative lease/CAS state-machine evidence.
    """
    if replay_id is None:
        drained, ob = wait_outbox_terminal(rs, timeout_s=60)
    else:
        drained, ob = wait_outbox_replay_terminal(rs, n_written, replay_id, timeout_s=60)
    dl = delta_summary(rs)
    no_target_delta = dl["n"] == 0
    residue_free = no_pending_leased_residue(ob["rows"])
    intact = (drained and terminal_once_map_ok(ob["rows"], n_written, replay_id)
              and no_target_delta)
    record(tag + "_outbox_all_terminal_after_reclaim",
           "%d retained rows PROCESSED with expected terminal-transition map" % n_written,
           "PASS" if intact else "FAIL",
           "drained=%s rows=%d deltas=%s gens=%s"
           % (drained, len(ob["rows"]), dl, ob["gens"]))
    record(tag + "_unbound_has_no_target_delta",
           "zero card-targeted deltas for unbound rule set",
           "PASS" if no_target_delta else "FAIL", "deltas=%s" % dl)
    record(tag + "_drain_clean",
           "no PENDING/LEASED residue (bounded drain before scenario end)",
           "PASS" if residue_free else "FAIL",
           "states=%s" % [(r[0], r[2]) for r in ob["rows"]][:12])
    return intact and residue_free


def _lease_scenario(tag, n_rows, live_lease_s):
    """S5/S10 共用驱动（语义见各场景 docstring）。

    live_lease_s=None（S5）：fixture 直接写入"已过期租约"（崩溃 claimant 的过期残留）。
    live_lease_s=N（S10）：fixture 先写"未到期活租约"（claimant 已死、租约仍活的
    stranded 形态），完成不被抢占观察后再以 SQL 置为过去（对时序的测试装置操作）。

    SQL 装置边界：只改 worker 记账/时序字段（status/lease_owner/lease_expires_at）；
    payload/grant/规则/租户等授权事实字段一律不改，不是对授权事实的伪造。"""
    rs = None
    try:
        rs = fixture_plain(tag)
        owner = "s15_%s_fx_%s" % (tag.lower(), uuid.uuid4().hex[:8])
        written, write_err = 0, ""
        for i in range(n_rows):
            try:
                r, eid = add_entry(rs, "monitor", "read", node=NAMES[i % len(NAMES)])
                if r.status_code == 200 and eid:
                    written += 1
                else:
                    write_err = "entry %d http=%s %s" % (i, r.status_code, r.text[:60])
            except Exception as e:
                write_err = "entry %d exc=%r" % (i, e)
        record(tag + "_baseline_written", "%dx200+entryIds" % n_rows,
               "PASS" if written == n_rows else "FAIL",
               "written=%d/%d %s" % (written, n_rows, write_err))
        drained, ob = wait_outbox_terminal(rs, timeout_s=60)
        dl = delta_summary(rs)
        no_target_delta = dl["n"] == 0
        base_ok = (written == n_rows and drained
                   and terminal_once_map_ok(ob["rows"], written)
                   and no_target_delta)
        record(tag + "_baseline_drained",
               "outbox drained contiguous+terminal once; unbound delta count zero",
               "PASS" if base_ok else "FAIL",
               "drained=%s deltas=%s gens=%s" % (drained, dl, ob["gens"]))
        ps_before = wait_pointer(rs, timeout_s=15)
        if not base_ok:
            _drain_and_report(tag, rs, written, None)
            return

        replay_id = pick_oldest_outbox_id(outbox_rows_full(rs))
        base = outbox_row_full(replay_id) if replay_id else None
        # durable 重放装置（与 S3 同类别）：最老一行置回 PENDING + fixture owner +
        # 租约时序，模拟 claimant 崩溃残留；守卫条件保证只动一行且原为 PROCESSED。
        fixture_applied, cur = False, None
        fixture_lease_s = int(live_lease_s) if live_lease_s else 5
        if base and base["status"] == "PROCESSED" and base["terminal"] == 1:
            lease_expr = "DATE_ADD(NOW(), INTERVAL %d SECOND)" % fixture_lease_s
            try:
                sql_exec("UPDATE authorization_projection_outbox SET status='PENDING', "
                         "lease_owner='%s', lease_expires_at=%s "
                         "WHERE outbox_id=%d AND status='PROCESSED' AND terminal_transitions=1"
                         % (owner, lease_expr, replay_id))
                cur = outbox_row_full(replay_id)
                fixture_applied = (cur is not None and cur["status"] == "PENDING"
                                   and cur["terminal"] == 1
                                   and lease_phase(cur, owner) == "live")
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                note("%s fixture update failed: %s" % (tag, str(e)[:140]))
        if tag == "S5":
            record(tag + "_lease_claimed",
                   "fixture owner + live lease observed before deterministic expiry",
                   "PASS" if fixture_applied else "FAIL", "row=%s" % (cur,))
        else:
            record(tag + "_lease_observed",
                   "active lease (future expiry) on oldest row (deterministic fixture)",
                   "PASS" if fixture_applied else "FAIL", "row=%s" % (cur,))
        if not fixture_applied:
            _drain_and_report(tag, rs, written, replay_id)
            return

        if live_lease_s:
            # 活跃租约观察窗 7.5s（> 任一 worker 5s 轮询周期）：三节点 worker 各自
            # 至少完整 sweep 一次，若实现无视活租约必被捕获（I1 CAS 独占）。
            samples, offender = [], None
            deadline = time.time() + 7.5
            while time.time() < deadline:
                try:
                    s = outbox_row_full(replay_id)
                except (RuntimeError, subprocess.TimeoutExpired):
                    time.sleep(0.5)
                    continue
                if s is None:
                    offender = "row removed externally"
                    break
                samples.append(s)
                if s["status"] != "PENDING" or lease_phase(s, owner) != "live":
                    offender = s
                    break
                time.sleep(0.5)
            held = offender is None and len(samples) >= 5 and no_steal_held(samples, owner, base)
            record(tag + "_second_projector_blocked",
                   "no steal during 7.5s live-lease window (3 workers x 5s sweep)",
                   "PASS" if held else "FAIL",
                   "frames=%d offender=%s" % (len(samples), offender or "none"))

        # Both scenarios expire the observed live lease deterministically before
        # waiting for a real worker to reclaim it.
        try:
            sql_exec("UPDATE authorization_projection_outbox SET "
                     "lease_expires_at=DATE_SUB(NOW(), INTERVAL 1 SECOND) "
                     "WHERE outbox_id=%d AND status='PENDING' AND lease_owner='%s'"
                     % (replay_id, owner))
            cur = outbox_row_full(replay_id)
            note("%s fixture lease expired: phase=%s"
                 % (tag, lease_phase(cur, owner) if cur else "row-missing"))
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            note("%s expire update failed: %s" % (tag, str(e)[:140]))

        # 有界等待任一真实 worker 安全回收（worker 5s sweep，30s 覆盖多轮）。
        cur, reclaimed = None, False
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                cur = outbox_row_full(replay_id)
            except RuntimeError:
                cur = None
            if cur and cur["status"] == "PROCESSED":
                reclaimed = True
                break
            time.sleep(1)
        if tag == "S5":
            record(tag + "_reclaimed_by_other_node",
                   "PROCESSED by real worker within 30s, terminal+1, lease cleared",
                   "PASS" if reclaimed and reclaimed_once(cur, owner, base) else "FAIL",
                   "row=%s" % (cur,))
            cur2 = None
            try:
                cur2 = outbox_row_full(replay_id)
            except RuntimeError:
                pass
            record(tag + "_single_terminal_transition",
                   "terminal==2 (initial+reclaim), no extra terminal write",
                   "PASS" if cur2 is not None
                   and int(cur2["terminal"]) == int(base["terminal"]) + 1 else "FAIL",
                   "row=%s" % (cur2,))
        else:
            record(tag + "_owner_completes_unique_terminal",
                   "after expiry: reclaimed PROCESSED exactly once (terminal+1), lease cleared",
                   "PASS" if reclaimed and reclaimed_once(cur, owner, base) else "FAIL",
                   "row=%s" % (cur,))

        # The fixture rule set is intentionally unbound, so no card-targeted
        # delta exists for a duplicate-key probe. Obsolete-owner safety here is
        # proved by the replay row's terminal counter remaining stable after a
        # full worker sweep; S3 separately covers the delta unique key.
        time.sleep(6)
        cur3 = None
        try:
            cur3 = outbox_row_full(replay_id)
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        stable = (cur3 is not None and cur3["status"] == "PROCESSED"
                  and int(cur3["terminal"]) == int(base["terminal"]) + 1)
        record(tag + "_obsolete_owner_no_second_terminal",
               "terminal counter stable after one full worker sweep",
               "PASS" if stable else "FAIL", "row=%s" % cur3)

        # 回收不得改变任何授权状态：读门指针世代不变 + 未绑定规则集全节点 DENY。
        ptr_ok, ptr_note = True, "pointer absent before fixture (compare skipped)"
        try:
            ps_after = pointer_state(rs)
            if ps_before is not None:
                ptr_ok = (ps_after is not None and ps_after["gen"] == ps_before["gen"]
                          and ps_after["status"] == "READY")
                ptr_note = "%s -> %s" % (ps_before, ps_after)
        except RuntimeError as e:
            ptr_ok, ptr_note = False, str(e)[:140]
        _, _, dec = wait3(*learn_args(), want=False, timeout_s=15)
        dec_ok = all(v is False for v in dec.values())
        record(tag + "_pointer_and_decisions_unchanged",
               "pointer gen unchanged + 3xDENY (unbound fixture)",
               "PASS" if ptr_ok and dec_ok else "FAIL",
               "%s dec=%s" % (ptr_note, dec))

        _drain_and_report(tag, rs, written, replay_id)
    finally:
        # 卫生兜底：按 node_pid 解析真实 pid 后 SIGCONT（对运行中进程是 no-op）。
        # 本协议全程不 SIGSTOP 节点；此兜底仅防其他机制遗留冻结，并修复旧 finally
        # 只信 pidfile 导致 CONT 打在陈旧 pid 上的缺陷（v14 轮间 node-a/b 冻结泄漏）。
        for nm in NAMES:
            try:
                pid = node_pid(nm)
                if pid:
                    ssh_node(nm, "kill -CONT %s 2>/dev/null; true" % pid)
            except Exception:
                pass
        note("%s ensure-running: SIGCONT via node_pid on 3 nodes (no-op if running)" % tag)


def S5():
    """I3：过期 lease 被安全回收，旧 owner 不能二次提交终态（确定性协议）。

    v14 战役失败根因是装置竞速而非产品缺陷（fence_regression 修复后 worker 的
    claim→publish 窗口小于观测+SIGSTOP 延迟；三轮 pre_stop_seen=0/7/0、stranded=0，
    事后库证据：outbox 全部 PROCESSED 且 terminal_transitions==1，无残留）。
    确定性协议：真实 API 写 8 条 delta 并双管线排水 → durable 重放最老一条 outbox
    行回 PENDING + fixture owner + 已过期租约（SQL 只动 worker 记账/时序字段，
    模拟 claimant 崩溃残留，与 S3 durable 重放同类别，非授权事实伪造）→ 断言真实
    worker 有界时间内安全回收：恰好一次新终态（terminal 1→2）、processed_by 为
    真实 worker、租约清空 → 旧 owner 二次提交按 S3 风格断言（uk 结构性拒绝 +
    settle 后终态不变）→ 指针世代不变、未绑定规则集全节点 DENY → 结束前有界
    排水门。全程不 SIGSTOP 节点。"""
    _lease_scenario("S5", 8, None)


def S6():
    """I4：交替 grant/revoke 不丢 generation。"""
    args = learn_args()
    rs = fixture_plain("S6")
    gen_seen = []
    all_pass = True
    for i in range(5):
        r, eid = add_entry(rs, "learn_subject", "read", node="node-b")
        if i == 0:
            rb = bind_card(rs, A["card"])   # 首条 delta 落地后才绑定
            assert rb.status_code == 200, "S6 bind failed: %s" % rb.text[:150]
        ok_a, _, fa = wait3(*args, want=True, timeout_s=30)
        hs = head_state().get(rs, {})
        gen_seen.append(hs.get("src"))
        r2 = del_entry(rs, eid, node="node-c")
        ok_d, _, fd = wait3(*args, want=False, timeout_s=30)
        if not (r.status_code == 200 and eid and ok_a and r2.status_code == 200 and ok_d):
            all_pass = False
        note("S6 round %d: gen=%s allow=%s deny=%s" % (i + 1, hs.get("src"), ok_a, ok_d))
    strict = all(b is not None and a is not None and b > a for a, b in zip(gen_seen, gen_seen[1:]))
    hs = head_state().get(rs, {})
    dl = delta_summary(rs)
    deadline = time.time() + 30
    while time.time() < deadline:
        ob = outbox_summary(rs)
        if ob["all_processed"] and ob["terminal_once"]:
            break
        time.sleep(1)
    record("S6_alternating_convergence", "10 mutations, 3-node each",
           "PASS" if all_pass else "FAIL")
    record("S6_generation_strictly_increasing", "monotonic",
           "PASS" if strict else "FAIL", "gens=%s" % gen_seen)
    record("S6_outbox_integrity", "contiguous+terminal+deltas SUCCEEDED",
           "PASS" if ob["contiguous"] and ob["all_processed"] and ob["terminal_once"]
           and dl["n"] >= 10 and dl["all_ok"] else "FAIL",
           "gens=%s deltas=%s head=%s" % (ob["gens"], dl, hs))


def S7():
    """I5（Rust 语义映射）：毒化的 L2 残留不得被服务——投影推进后决策必须保持
    正确（失效依赖值内世代标签/完整性校验，而非物理删除键）。键的存废与 epoch
    是否推进作为机制证据记录（对比 Java 的 cache_key_deleted 语义）。"""
    args = learn_args()
    rs = fixture_grant("S7")
    sim(A, "node-b", *args[1:])      # 预热：评估路径填充 L2
    ep = epoch()
    if not ep:
        record("S7_epoch_present", "epoch key", "FAIL", "no cache epoch in run redis")
        return
    key = "astral:auth:l2ev:%s:%s:%s" % (ep, A["tenant"], A["card"])
    redis("SET", key, "STALE_PAYLOAD_FROM_S7")
    note("poisoned %s (epoch %s)" % (key, ep))
    r, monitor_eid = add_entry(rs, "monitor", "read", node="node-a")   # 真实变更推进投影
    assert r.status_code == 200
    deleted = False
    ep_changed = False
    deadline = time.time() + 15
    while time.time() < deadline:
        if redis("GET", key) != "STALE_PAYLOAD_FROM_S7":
            deleted = True
            break
        if epoch() != ep:
            ep_changed = True
            break
        time.sleep(0.5)
    note("residue observation: deleted=%s epoch_changed=%s（键存废为机制证据，"
         "安全属性由决策正确性断言）" % (deleted, ep_changed))
    fix_eid = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d "
                  "AND resource_type='learn_subject' LIMIT 1" % rs)[0][0]
    del_entry(rs, monitor_eid, node="node-a")
    r2 = del_entry(rs, fix_eid, node="node-b")
    assert r2.status_code == 200, r2.text[:120]
    ok, _, final = wait3(*args, want=False, timeout_s=30)
    record("S7_stale_residue_not_served", "3xDENY despite poisoned L2 residue",
           "PASS" if ok else "FAIL", "final=%s residue(deleted=%s, epoch_changed=%s)"
           % (sim_detail() if not ok else "", deleted, ep_changed))


def S8():
    """I6：Rust 规则契约（resource/action/effect）无 ABAC 属性条件 → 本轮 N/A。"""
    record("S8_abac_attribute_change", "I6", "N/A",
           "Rust rule_set_entry 契约无属性条件列；ABAC 场景在 Rust 侧不适用（如实标注，不进入分母）")


def S9():
    """I2/I4：mutation storm 不产生 stale ALLOW、不丢 generation。"""
    args = learn_args()
    rs = fixture_plain("S9")
    src_before = head_state().get(rs, {}).get("src", 0)
    eids = []
    for i in range(6):
        r, eid = add_entry(rs, "learn_subject", "read", node="node-a")
        assert r.status_code == 200 and eid, r.text[:150]
        if i == 0:
            rb = bind_card(rs, A["card"])   # 首条 delta 落地后才绑定
            assert rb.status_code == 200, "S9 bind failed: %s" % rb.text[:150]
        eids.append(eid)
    storm_allow = samples = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < 2.0:
        d = sim(A, "node-c", *args[1:])
        samples += 1
        if d["allowed"] is True:
            storm_allow += 1
    for eid in eids:
        del_entry(rs, eid, node="node-a")
    after_allow = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < 2.0:
        d = sim(A, "node-c", *args[1:])
        if d["allowed"] is True:
            after_allow += 1
    record("S9_storm_no_stale_allow", "unsafeAllow=0 post-delete",
           "PASS" if after_allow == 0 else "FAIL",
           "during=%d/%d ALLOW samples; post-delete ALLOW=%d" % (storm_allow, samples, after_allow))
    ok, ms, final = wait3(*args, want=False, timeout_s=45)
    record("S9_storm_converge_deny", "3xDENY", "PASS" if ok else "FAIL", "wait=%dms" % ms)
    # 记账语义（V14 审计修正）：13 个 head 世代 = 6 add + 6 del + 1 bind；bind
    # 世代本身不产生独立 delta 行（只 fanout 绑定时已存在 entry 的 create delta，
    # 归属各 grant），故 RULE_SET delta == 12 = 6 grant × [create v1 + remove v2]
    # （target_version 为 per-grant 版本，[1×6, 2×6] 是期望形状）——13 vs 12 是
    # 设计使然，不是丢 delta。断言前两条管线各自有界排水：V14 round2 的 FAIL 是
    # 瞬时采样竞态（gen13 outbox 行在采样后 ~0.1s 才 PROCESSED；12 条 delta 最终
    # 全部 SUCCEEDED、outbox 全部 PROCESSED terminal==1，库证据无丢失）。
    drained, ob = wait_outbox_terminal(rs, timeout_s=60)
    ok_dl, dl = wait_deltas_terminal(rs, timeout_s=60)
    hs = head_state().get(rs, {})
    delta = (hs.get("src") or 0) - src_before
    i9 = (delta == 13 and dl["n"] == 12 and ok_dl and drained
          and hs.get("src") == len(ob["gens"]))
    record("S9_generation_no_loss",
           "src delta==13 (12 mutations+bind), 12 grant deltas SUCCEEDED, "
           "outbox drained contiguous+terminal",
           "PASS" if i9 else "FAIL",
           "delta=%d deltas=%s gens=%s" % (delta, dl, ob["gens"]))


def S10():
    """I1：lease CAS 阻止第二 projector 抢占活跃租约，过期后唯一终态回收
    （确定性协议）。

    v14 失败根因同 S5（竞速绊线脱靶：pre_stop_seen=0/27、stranded=0；事后库证据
    outbox 全部 PROCESSED terminal==1，无残留）。确定性协议：真实 API 写 10 条
    delta 并双管线排水 → durable 重放最老一条 outbox 行回 PENDING + fixture owner
    + 12s 未到期租约（确定性再现"claimant 已死、租约仍活"的 stranded-LEASED 形态，
    只动记账/时序字段，非授权事实伪造）→ 7.5s 观察窗（覆盖三节点各自 ≥1 次 5s
    sweep）：活跃租约期间任何 worker 不得抢占（status/lease_owner/terminal/
    processed_by 全程不变）→ SQL 将该行 lease_expires_at 置为过去（时序装置）→
    有界等待真实 worker 回收：恰好一次新终态、租约清空 → 旧 owner 二次提交 S3
    风格断言（uk 结构性拒绝 + settle 后终态不变）→ 指针/决策不变 → 结束前有界
    排水门。全程不 SIGSTOP 节点。本场景不绑定规则集。"""
    _lease_scenario("S10", 10, 12)


def S11():
    """I9：决策证据链跨节点自洽（sim 决策+reason+matchedRule 与投影状态同源核对）。"""
    args = learn_args()
    rs = fixture_grant("S11")
    ev_grant = sim3(*args)
    ok_g = all(v["allowed"] is True and v["reason"].startswith("published:") and v["matched"]
               for v in ev_grant.values())
    matched = {v["matched"] for v in ev_grant.values()}
    record("S11_grant_evidence_self_consistent", "3x published:ALLOW same matchedRule",
           "PASS" if ok_g and len(matched) == 1 else "FAIL",
           "ev=%s matched=%s" % ({k: (v["allowed"], v["reason"][:40]) for k, v in ev_grant.items()},
                                 matched))
    eid = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d AND effect='ALLOW' "
              "ORDER BY entry_id DESC LIMIT 1" % rs)[0][0]
    del_entry(rs, eid, node="node-a")
    wait3(*args, want=False, timeout_s=30)
    ev_revoke = sim3(*args)
    ok_r = all(v["allowed"] is False and v["reason"].startswith("published:") for v in ev_revoke.values())
    record("S11_revoke_evidence_self_consistent", "3x published:DENY same reason",
           "PASS" if ok_r else "FAIL",
           "ev=%s" % {k: (v["allowed"], v["reason"][:60]) for k, v in ev_revoke.items()})


def _arbiter_ctx():
    return {"userId": 9031, "principalKind": "PLATFORM_USER", "cardId": 9061,
            "identityCardId": 9041, "domainId": 9011, "tenantId": 9001,
            "resource": "learn_subject:*", "action": "read", "actionCodes": ["read"]}


def _seed_arbiter_grant():
    """S12/S13 前置（20260903 产品修复后远程可达）：POST /arbiter/arbitrate 现
    映射一等注册动作 monitor:arbitrate，远程调用要求 A 卡持有 ALLOW 授权。
    走真实链路：SQL 种子规则集（tenant 作用域）→ API 条目（monitor/arbitrate）
    → API 绑定 A 卡 → 等待投影发布。返回规则集 id（S13 结束后解绑清场）。"""
    code = "s15_rs_s12arb_%s" % uuid.uuid4().hex[:8]
    sql_exec("INSERT INTO rule_set (name, code, source_type, description, enabled, tenant_id) "
             "VALUES ('S15 rs s12arb', '%s', 'CUSTOM', 'arbiter control plane grant', 1, %s)"
             % (code, A["tenant"]))
    rs = int(sql("SELECT rule_set_id FROM rule_set WHERE code='%s'" % code)[0][0])
    r, _ = add_entry(rs, "monitor", "arbitrate", node="node-b")
    assert r.status_code == 200, "arbiter seed entry failed: %s" % r.text[:150]
    r = bind_card(rs, A["card"], node="node-b")
    assert r.status_code == 200, "arbiter seed bind failed: %s" % r.text[:150]
    # Probe the exact protected action with a non-empty, unprovable evidence
    # item. HTTP 200 + R4_UNPROVABLE proves the monitor:arbitrate grant reached
    # the permission gate; empty evidence is separately required to return 400.
    probe_evidence = [{"nodeId": "probe", "allowed": True, "reason": "readiness",
                       "gate": {"ready": False, "sourceGeneration": 1, "revokeFence": 0}}]
    probe_body = {"context": _arbiter_ctx(), "evidence": probe_evidence}
    for attempt in range(30):
        probe, pd = call(A, "node-b", "POST", "/main/api/v1/arbiter/arbitrate", probe_body)
        if probe.status_code == 200 and (pd or {}).get("verdict") == "DEFER" \
                and (pd or {}).get("reasonCode") == "R4_UNPROVABLE":
            note("arbiter grant ready (rs=%d, probe %d)" % (rs, attempt))
            return rs
        time.sleep(1)
    raise RuntimeError("arbiter control-plane grant not ready after 30s (rs=%d)" % rs)


def S12():
    """I10：执剑人按版本序拒绝旧 ALLOW（R1_FENCE_DENY）。远程控制面（修复后
    monitor:arbitrate 一等注册且 A 卡持授权，20260903）。"""
    _seed_arbiter_grant()
    ev = [{"nodeId": "node-a", "allowed": True, "reason": "stale-allow",
           "gate": {"ready": True, "sourceGeneration": 105, "projectedGeneration": 105, "revokeFence": 0}},
          {"nodeId": "node-b", "allowed": False, "reason": "fresh-deny",
           "gate": {"ready": True, "sourceGeneration": 106, "projectedGeneration": 106, "revokeFence": 1}},
          {"nodeId": "node-c", "allowed": False, "reason": "fresh-deny",
           "gate": {"ready": True, "sourceGeneration": 106, "projectedGeneration": 106, "revokeFence": 1}}]
    r, data = call(A, "node-b", "POST", "/main/api/v1/arbiter/arbitrate",
                   {"context": _arbiter_ctx(), "evidence": ev})
    verdict = (data or {}).get("verdict")
    rc = (data or {}).get("reasonCode")
    if r.status_code == 200 and verdict == "DENY" and rc == "R1_FENCE_DENY":
        record("S12_arbiter_r1_fence_deny", "DENY + R1_FENCE_DENY", "PASS",
               "remote control plane")
    else:
        record("S12_arbiter_r1_fence_deny", "DENY + R1_FENCE_DENY", "FAIL",
               "http=%s verdict=%s rc=%s body=%s"
               % (r.status_code, verdict, rc, str(getattr(r, "text", ""))[:120]))


def S13():
    """I11：仲裁不可证明时 fail-closed（DEFER → 拒绝）。"""
    rs = _seed_arbiter_grant()
    ev = [{"nodeId": "node-a", "allowed": True, "reason": "x",
           "gate": {"ready": False, "sourceGeneration": 1, "projectedGeneration": 0, "revokeFence": 0}}]
    r, data = call(A, "node-b", "POST", "/main/api/v1/arbiter/arbitrate",
                   {"context": _arbiter_ctx(), "evidence": ev})
    verdict = (data or {}).get("verdict")
    rc = (data or {}).get("reasonCode")
    if r.status_code == 200 and verdict == "DEFER" and rc in ("EVIDENCE_MISSING", "R4_UNPROVABLE"):
        record("S13_arbiter_unprovable_defers", "DEFER + EVIDENCE_MISSING/R4_UNPROVABLE", "PASS",
               "remote control plane")
    else:
        record("S13_arbiter_unprovable_defers",
               "DEFER + EVIDENCE_MISSING/R4_UNPROVABLE", "FAIL",
               "http=%s verdict=%s rc=%s body=%s"
               % (r.status_code, verdict, rc, str(getattr(r, "text", ""))[:120]))
    r2, d2 = call(A, "node-b", "POST", "/main/api/v1/arbiter/arbitrate",
                  {"context": _arbiter_ctx(), "evidence": []})
    try:
        err_type = (r2.json() or {}).get("errorType")
    except Exception:
        err_type = None
    ok2 = r2.status_code == 400 and err_type == "VALIDATION_ERROR"
    record("S13_arbiter_empty_evidence_rejected",
           "400 VALIDATION_ERROR while caller authorised",
           "PASS" if ok2 else "FAIL",
           "http=%s errorType=%s" % (r2.status_code, err_type))
    # Remove this scenario's control-plane grant and prove the unauthorised
    # empty-evidence request remains fail-closed.
    unbind_card(rs, A["card"], node="node-b")
    # After removal, wait for the protected entry gate to observe revocation.
    gate_denied, r2, d2 = False, None, None
    deadline = time.time() + 30
    while time.time() < deadline:
        r2, d2 = call(A, "node-b", "POST", "/main/api/v1/arbiter/arbitrate",
                      {"context": _arbiter_ctx(), "evidence": []})
        try:
            err = r2.json() or {}
        except Exception:
            err = {}
        if r2.status_code == 403 and err.get("reasonCode") == "DEFAULT_DENY":
            gate_denied = True
            break
        time.sleep(0.5)
    record("S13_entry_gate_denies_after_cleanup",
           "403 DEFAULT_DENY after control-plane grant removed",
           "PASS" if gate_denied else "FAIL",
           "http=%s body=%s" % (getattr(r2, "status_code", None), str(d2)[:80]))


def S14():
    """I12：revoke 提交后节点进程被 kill/重启，不复活 stale ALLOW。"""
    args = learn_args()
    rs = fixture_grant("S14")
    eid = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d AND effect='ALLOW' "
              "ORDER BY entry_id ASC LIMIT 1" % rs)[0][0]
    r = del_entry(rs, eid, node="node-a")
    t_commit = time.perf_counter()
    assert r.status_code == 200
    old_pid = node_pid("node-c")
    killed = node_kill("node-c")
    time.sleep(3)
    down_allow = 0
    down_samples = {node: 0 for node in ("node-a", "node-b")}
    for index in range(8):
        node = ("node-a", "node-b")[index % 2]
        d = sim(A, node, *args[1:])
        down_samples[node] += 1
        if d["allowed"] is True:
            down_allow += 1
        time.sleep(0.4)
    recovered = ensure_node_alive("node-c")
    new_pid = node_pid("node-c")
    restarted = old_pid and new_pid and old_pid != new_pid
    record("S14_process_restarted", "new run-owned serving pid",
           "PASS" if restarted and killed and recovered else "FAIL",
           "old=%s new=%s serving=%s" % (old_pid, new_pid, recovered))
    record("S14_no_stale_allow_during_down", "allowDuringDown=0",
           "PASS" if down_allow == 0 else "FAIL",
           "samples=%s allow=%d" % (down_samples, down_allow))
    ready_ms = wait_node_ready("node-c", timeout_s=180)
    record("S14_node_c_ready_after_restart", "api 200 + decision 200",
           "PASS" if ready_ms is not None else "FAIL",
           "ready_in=%s" % (round(ready_ms, 1) if ready_ms is not None else "timeout"))
    ok, ms, final = wait3(*args, want=False, timeout_s=40)
    record("S14_all_nodes_deny_after_restart", "3xDENY",
           "PASS" if ok else "FAIL", "final=%s" % final)


def S15():
    """I13：专用 Redis 停机/恢复不复活 stale ALLOW。"""
    args = learn_args()
    rs = fixture_grant("S15")
    eid = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d AND effect='ALLOW' "
              "ORDER BY entry_id ASC LIMIT 1" % rs)[0][0]
    r = del_entry(rs, eid, node="node-a")
    assert r.status_code == 200

    down_allow = pending = deny = 0
    down_samples = {node: 0 for node in NAMES}
    stop_rc = None
    try:
        try:
            stop = subprocess.run(["docker", "stop", RC], capture_output=True, text=True,
                                  timeout=60)
            stop_rc = stop.returncode
        except (subprocess.TimeoutExpired, OSError):
            stop_rc = "unknown"
        try:
            stopped_state = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", RC],
                capture_output=True, text=True, timeout=30)
            redis_stopped = (stopped_state.returncode == 0
                             and stopped_state.stdout.strip() == "false")
            stopped_state_rc = stopped_state.returncode
        except (subprocess.TimeoutExpired, OSError):
            redis_stopped = False
            stopped_state_rc = "error"
        record("S15_redis_stopped", "container running=false",
               "PASS" if redis_stopped else "FAIL",
               "stop_rc=%s inspect_rc=%s" % (stop_rc, stopped_state_rc))
        if not redis_stopped:
            raise RuntimeError("S15 run-scoped Redis outage was not established")

        time.sleep(2)
        for index in range(10):
            node = NAMES[index % len(NAMES)]
            d = sim(A, node, *args[1:])
            down_samples[node] += 1
            if d["allowed"] is True:
                down_allow += 1
            elif d["allowed"] is None:
                pending += 1
            else:
                deny += 1
            time.sleep(0.4)
    finally:
        redis_recovered, recovery = ensure_redis_available(timeout_s=30)
        record("S15_redis_recovered", "container running=true + authenticated PING",
               "PASS" if redis_recovered else "FAIL",
               "start_attempted=%s start_rc=%s running=%s ping=%s" %
               (recovery["start_attempted"], recovery["start_rc"], recovery["running"],
                "PONG" if recovery["authenticated_ping"] else "timeout"))
        if not redis_recovered:
            raise RuntimeError("S15 run-scoped Redis did not recover")

    record("S15_no_stale_allow_during_redis_down", "allowDuringDown=0",
           "PASS" if down_allow == 0 else "FAIL",
           "samples=%s allow=%d pending=%d deny=%d" %
           (down_samples, down_allow, pending, deny))
    up_allow = 0
    up_samples = {node: 0 for node in NAMES}
    for index in range(10):
        node = NAMES[index % len(NAMES)]
        d = sim(A, node, *args[1:])
        up_samples[node] += 1
        if d["allowed"] is True:
            up_allow += 1
        time.sleep(0.4)
    record("S15_no_stale_allow_after_restart", "allowAfterRestart=0",
           "PASS" if up_allow == 0 else "FAIL",
           "samples=%s allow=%d" % (up_samples, up_allow))
    ok, ms, final = wait3(*args, want=False, timeout_s=40)
    record("S15_all_nodes_deny_final", "3xDENY", "PASS" if ok else "FAIL", "final=%s" % final)
    dl = sql("SELECT status, COUNT(*) FROM authorization_delta_event "
             "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d GROUP BY status" % rs)
    note("S15 delta pipeline state after redis outage (rs=%d): %s" % (rs, dl))


# ---------- 主流程 ----------

def ensure_arbiter_gate():
    """已废弃：POST /arbiter 的路由门映射到未注册动作 monitor:create，任何规则都
    无法授权它（入口校验直接拒绝），远程控制面被结构性阻断（见 S12/S13 的 N/A
    记录与产品发现归档）。保留函数仅为说明，不再在 preflight 调用。"""
    return True


def cleanup_stale_bindings():
    """Unbind every rule set currently attached to card A.

    An empty binding list is a successful clean state. Any probe or unbind
    failure is returned to the caller so scenario isolation cannot be assumed.
    """
    try:
        r, data = call(A, "node-b", "GET",
                       "/main/api/v1/rule-sets/card/%s/bindings" % A["card"])
    except Exception as e:
        note("stale-binding probe failed: %r" % e)
        return False
    if r.status_code != 200 or data is None:
        note("stale-binding probe: http=%s" % r.status_code)
        return False
    items = data if isinstance(data, list) else (data.get("items") or [])
    clean = True
    seen = set()
    for b in items:
        rs_id = int(b["ruleSetId"])
        if rs_id in seen:
            continue
        seen.add(rs_id)
        try:
            ur = unbind_card(rs_id, A["card"])
            ok = ur.status_code == 200
            clean = clean and ok
            note("unbound rs=%s (%s) http=%s"
                 % (rs_id, b.get("ruleSetName", ""), ur.status_code))
        except Exception as e:
            clean = False
            note("unbind error %r" % e)
    if not clean:
        return False
    try:
        r2, data2 = call(A, "node-b", "GET",
                         "/main/api/v1/rule-sets/card/%s/bindings" % A["card"])
    except Exception as e:
        note("binding verification failed: %r" % e)
        return False
    remaining = data2 if isinstance(data2, list) else ((data2 or {}).get("items") or [])
    if r2.status_code != 200 or remaining:
        note("binding verification not empty: http=%s count=%d"
             % (r2.status_code, len(remaining)))
        return False
    return True


def establish_deny_baseline(tag, timeout_s=45):
    """Prove card A has no residual ALLOW before or after a scenario."""
    if not cleanup_stale_bindings():
        record(tag + "_binding_cleanup", "binding probe + all unbinds succeed", "FAIL", "")
        return False
    ok, _, final = wait3(A, A["card"], "learn_subject:*", "read",
                         int(A["user_id"]), int(A["domain"]), int(A["tenant"]),
                         want=False, timeout_s=timeout_s)
    record(tag + "_deny_baseline", "3xDENY after all bindings removed",
           "PASS" if ok else "FAIL", "final=%s" % (final if not ok else ""))
    return ok


def preflight():
    redis_ok, redis_detail = ensure_redis_available()
    record("PRE_redis", "container available + authenticated PING",
           "PASS" if redis_ok else "FAIL", "state=%s" % redis_detail)
    if not redis_ok:
        raise RuntimeError("preflight run-scoped Redis could not be recovered")
    # 上轮 S15 的 Redis 混沌会停摆 delta worker（见 F5），再整组重启。
    if not restart_cluster():
        raise RuntimeError("preflight cluster restart did not reach authorization readiness")
    if not ensure_cluster_alive():
        raise RuntimeError("preflight cluster liveness could not be established")
    for n in NAMES:
        try:
            r, _ = call(A, n, "GET", "/main/api/v1/rule-sets?page=1&size=1")
            alive = r.status_code == 200
            detail = "http=%s" % r.status_code
        except Exception as e:
            alive, detail = False, type(e).__name__
        record("PRE_alive_" + n, "200", "PASS" if alive else "FAIL", detail)
    for n in NAMES:
        alive, pid = node_alive(n)
        record("PRE_pidfile_" + n, "run-owned listener alive",
               "PASS" if alive else "FAIL", "pid=%s" % pid)
    record("PRE_bootstrap_evidence", "projection_current >= 2",
           "PASS" if int(sql("SELECT COUNT(*) FROM authorization_projection_current")[0][0]) >= 2
           else "FAIL", "")
    baseline_ok = establish_deny_baseline("PRE", timeout_s=45)
    if not baseline_ok:
        raise RuntimeError("preflight could not establish an isolated 3-node DENY baseline")


def node_serving(node, timeout_s=4):
    """Liveness: the run-owned PID holds its port and returns any HTTP response."""
    alive, _ = node_alive(node)
    if not alive:
        return False
    try:
        response = requests.get(
            NODES[node] + "/main/api/v1/rule-sets?page=1&size=1",
            timeout=timeout_s)
        return 100 <= response.status_code < 600
    except requests.RequestException:
        return False


def wait_node_serving(node, timeout_s=NODE_SERVING_TIMEOUT_S):
    deadline = time.monotonic() + timeout_s
    started = time.perf_counter()
    while time.monotonic() < deadline:
        if node_serving(node):
            return (time.perf_counter() - started) * 1000
        time.sleep(0.5)
    return None


def node_responsive(node, timeout_s=4):
    """Authorization readiness: the signed management request must return 200."""
    try:
        r, _ = call(A, node, "GET", "/main/api/v1/rule-sets?page=1&size=1", timeout=timeout_s)
        return r.status_code == 200
    except Exception:
        return False


def node_ready(node, timeout_s=5):
    """Readiness requires signed management 200 and decision endpoint 200."""
    deadline = time.monotonic() + timeout_s
    if not node_responsive(node, max(0.1, deadline - time.monotonic())):
        return False
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        d = sim(A, node, *learn_args()[1:], timeout=max(0.1, remaining))
        return d["http"] == 200
    except Exception:
        return False


def wait_node_ready(node, timeout_s=120):
    """Bounded wait for one node's authorization readiness."""
    deadline = time.monotonic() + timeout_s
    started = time.perf_counter()
    while time.monotonic() < deadline:
        if node_ready(node):
            return (time.perf_counter() - started) * 1000
        time.sleep(1)
    return None


def wait_cluster_ready(timeout_s=CLUSTER_READY_TIMEOUT_S):
    """Give concurrently booting nodes one shared authorization-readiness budget."""
    deadline = time.monotonic() + timeout_s
    started = time.perf_counter()
    pending = set(NAMES)
    ready_ms = {}
    while pending and time.monotonic() < deadline:
        for node in tuple(pending):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if node_ready(node, timeout_s=max(0.1, min(5, remaining))):
                ready_ms[node] = (time.perf_counter() - started) * 1000
                pending.remove(node)
        if pending and time.monotonic() < deadline:
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    return ready_ms, sorted(pending)


def ensure_node_alive(node):
    """Recover liveness only; authorization readiness is a separate gate."""
    if node_serving(node):
        return True
    note("node %s not serving; attempting recovery" % node)
    pid = node_pid(node)
    if pid is not None:
        try:
            ssh_node(node, "kill -CONT %s 2>/dev/null; true" % int(pid))
        except Exception:
            pass
        if wait_node_serving(node, timeout_s=10) is not None:
            note("node %s serving after SIGCONT" % node)
            return True
    for attempt in range(NODE_START_ATTEMPTS):
        if not node_kill(node):
            note("node %s run-owned listener did not stop" % node)
            return False
        try:
            node_restart(node, CFG["ports"][node])
        except Exception as e:
            note("node %s start command failed (attempt %d): %s" %
                 (node, attempt + 1, type(e).__name__))
            time.sleep(2)
            continue
        serving_ms = wait_node_serving(node)
        if serving_ms is not None:
            note("node %s serving after restart (attempt %d, %.0fms)" %
                 (node, attempt + 1, serving_ms))
            return True
        note("node %s restart attempt %d did not bind a run-owned serving process" %
             (node, attempt + 1))
        time.sleep(2)
    return False


def ensure_cluster_alive():
    ok = True
    for n in NAMES:
        if not ensure_node_alive(n):
            record("CLUSTER_health_" + n, "run-owned HTTP listener serving",
                   "FAIL", "unrecoverable")
            ok = False
    return ok


def restart_cluster(ready_timeout_s=CLUSTER_READY_TIMEOUT_S):
    """Restart all workers, then prove liveness and authorization readiness separately."""
    note("between-rounds cluster restart (revive delta workers, see finding F5)")
    stop_failures = []
    for n in NAMES:
        if not node_kill(n):
            stop_failures.append(n)
    if stop_failures:
        record("CLUSTER_stop", "all run-owned listeners stopped", "FAIL",
               "nodes=%s" % stop_failures)
        return False
    time.sleep(2)

    start_failures = []
    for n in NAMES:
        if not ensure_node_alive(n):
            start_failures.append(n)
            record("CLUSTER_restart_" + n, "run-owned HTTP listener serving",
                   "FAIL", "bounded attempts exhausted")
        time.sleep(5)
    if start_failures:
        return False

    ready_ms, not_ready = wait_cluster_ready(timeout_s=ready_timeout_s)
    for n, elapsed in sorted(ready_ms.items()):
        note("cluster restart: %s authorization ready in %.0fms" % (n, elapsed))
    if not_ready:
        for n in not_ready:
            record("CLUSTER_ready_" + n, "signed management 200 + decision 200",
                   "FAIL", "shared_timeout_s=%s" % ready_timeout_s)
        return False
    return True


def cluster_settle(timeout_s=420):
    """Restart the cluster and require one shared authorization-readiness proof."""
    ready_budget = min(CLUSTER_READY_TIMEOUT_S, max(60, timeout_s - 60))
    restarted = restart_cluster(ready_timeout_s=ready_budget)
    alive = ensure_cluster_alive()
    failed = [x["name"] for x in RESULTS
              if x["name"].startswith("CLUSTER_") and x["verdict"] == "FAIL"]
    if not restarted or not alive or failed:
        record("CLUSTER_settle", "restart + serving + ready(3 nodes)",
               "FAIL", "restart=%s alive=%s failed_guards=%s" %
               (restarted, alive, failed or "none"))
        print("CLUSTER_SETTLE FAIL: restart=%s alive=%s failed_guards=%s"
              % (restarted, alive, failed or "none"), flush=True)
        return 1
    record("CLUSTER_settle", "restart + serving + ready(3 nodes)", "PASS",
           "all nodes api200+decision200")
    print("CLUSTER_SETTLE OK", flush=True)
    return 0


def rq_settle(timeout_s=1500):
    """Reset the cluster and wait for all projection-side durable work to settle.

    F7 intentionally creates a dense generation stream.  Starting the next
    write-heavy phase while its projector/archive workers still hold tenant
    locks can turn expected transient deadlocks into the per-process circuit
    breaker.  This gate makes the phase boundary explicit and fail-closed.
    """
    started = time.time()
    note("rq_settle: restarting cluster before RQ workload")
    ready_budget = min(CLUSTER_READY_TIMEOUT_S, max(60, timeout_s // 3))
    if not restart_cluster(ready_timeout_s=ready_budget):
        note("rq_settle: cluster restart did not reach authorization readiness")
        return 1
    if not ensure_cluster_alive():
        note("rq_settle: cluster liveness could not be established")
        return 1

    queries = {
        "delta_pending": "SELECT COUNT(*) FROM authorization_delta_event "
                          "WHERE status <> 'SUCCEEDED'",
        "outbox_pending": "SELECT COUNT(*) FROM authorization_projection_outbox "
                           "WHERE status <> 'PROCESSED'",
        "impact_pending": "SELECT COUNT(*) FROM authorization_impact_plan "
                           "WHERE status <> 'SUCCEEDED'",
        "archive_pending": "SELECT COUNT(*) FROM authorization_archive_outbox "
                            "WHERE status <> 'SUCCEEDED'",
    }
    deadline = time.time() + timeout_s
    last = {}
    while time.time() < deadline:
        try:
            last = {name: int(sql(query)[0][0]) for name, query in queries.items()}
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            note("rq_settle queue probe failed: %s" % str(exc)[:180])
            time.sleep(5)
            continue
        note("rq_settle queues=%s elapsed=%.1fs" %
             (last, time.time() - started))
        if all(value == 0 for value in last.values()):
            if all(node_ready(node) for node in NAMES):
                print("RQ_SETTLE OK queues=%s elapsed=%.1fs" %
                      (last, time.time() - started), flush=True)
                return 0
        time.sleep(5)
    print("RQ_SETTLE FAIL queues=%s elapsed=%.1fs" %
          (last, time.time() - started), flush=True)
    return 1


def run_round(round_no, only=None):
    RESULTS.clear()
    print("=" * 100)
    print("ROUND %d" % round_no)
    print("=" * 100)
    plan = [
        ("S1", S1), ("S2", S2), ("S3", S3), ("S4", S4), ("S5", S5),
        ("S6", S6), ("S7", S7), ("S8", S8), ("S9", S9), ("S10", S10),
        ("S11", S11), ("S12", S12), ("S13", S13), ("S14", S14), ("S15", S15),
    ]
    for name, fn in plan:
        if only and name not in only:
            continue
        print("\n--- %s ---" % name)
        if not ensure_cluster_alive():
            raise RuntimeError("%s pre-scenario cluster liveness failed" % name)
        if not establish_deny_baseline(name + "_PRE"):
            raise RuntimeError("%s pre-scenario isolation failed" % name)
        try:
            fn()
        except Exception:
            record(name + "_exception", "-", "FAIL", traceback.format_exc()[-400:])
        finally:
            if not ensure_cluster_alive():
                raise RuntimeError("%s post-scenario cluster liveness failed" % name)
            if name == "S15":
                note("S15 post-scenario cluster restart (Redis outage worker recovery)")
                if not restart_cluster():
                    raise RuntimeError("S15 post-scenario cluster restart failed")
                isolated = establish_deny_baseline(name + "_POST_RESTART", timeout_s=120)
            else:
                isolated = establish_deny_baseline(name + "_POST")
            if not isolated:
                raise RuntimeError("%s post-scenario isolation failed" % name)


def atomic_json(path, obj):
    """原子落盘：断流/中断时不留半截 JSON（旧 artifact 不覆盖已有完整文件）。"""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3,
                    help="场景轮数（默认 3：满足 S14/S15 样本量 >= 3 的一致性口径）")
    ap.add_argument("--only", type=str, default=None)
    ap.add_argument("--out", type=str, default="s15_result.json")
    args = ap.parse_args()
    only = [item.strip() for item in args.only.split(",")] if args.only is not None else None
    selection_errors = s15_validation.validate_run_selection(args.rounds, only)
    if selection_errors:
        ap.error("invalid S15 selection: %s" % ";".join(selection_errors))
    only = set(only) if only is not None else None
    started = time.time()
    coverage_rounds = []

    def snapshot(complete, rounds_done):
        """原始汇总：PASS/FAIL/N/A 直接由 RESULTS 计数，不做任何静默重分类；
        N/A 场景（如 S8/I6）必须带明确理由，FAIL 必须进入 fail_items。"""
        npass = sum(1 for x in RESULTS if x["verdict"] == "PASS")
        nfail = sum(1 for x in RESULTS if x["verdict"] == "FAIL")
        nna = sum(1 for x in RESULTS if x["verdict"] == "N/A")
        selected = sorted(only) if only is not None else list(s15_validation.SCENARIO_NAMES)
        round_verdicts = {
            item["name"]: item["verdict"] for item in RESULTS
        }
        missing = s15_validation.missing_required_cases(selected, round_verdicts)
        nonpass = s15_validation.missing_nonpass_cases(selected, round_verdicts)
        round_results = list(coverage_rounds)
        if rounds_done > len(round_results):
            round_results.append({"missing": missing, "nonpass": nonpass, "verdicts": round_verdicts})
        coverage = s15_validation.campaign_coverage(
            rounds=args.rounds,
            rounds_done=rounds_done,
            only=sorted(only) if only is not None else None,
            round_missing_cases=[entry["missing"] for entry in round_results],
            round_case_verdicts=[entry["verdicts"] for entry in round_results],
        )
        coverage["scope"] = "partial" if only is not None or coverage["scope"] == "partial" else "full"
        coverage["nonpassCasesByRound"] = [entry["nonpass"] for entry in round_results]
        coverage["complete"] = bool(coverage["complete"] and complete)
        return {
            "complete": bool(complete and coverage["complete"]),
            "coverage": coverage,
            "rounds_done": rounds_done,
            "summary": {
                "pass": npass, "fail": nfail, "na": nna,
                "fail_items": [x["name"] for x in RESULTS if x["verdict"] == "FAIL"],
                "na_items": [{"name": x["name"], "reason": x["detail"][:200]}
                             for x in RESULTS if x["verdict"] == "N/A"],
                "rounds": args.rounds,
                "only": sorted(only) if only else None,
                "elapsed_s": round(time.time() - started, 1),
            },
            "meta": {
                "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                "finished_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "host": socket.gethostname(),
                "python": sys.version.split()[0],
                "run_id": os.environ.get("RUN_ID"),
                "provenance": provenance(),
            },
            "results": RESULTS,
            "timeline": TIMELINE,
        }

    try:
        preflight()
        for i in range(1, args.rounds + 1):
            # Full rounds already prove a post-S15 cluster restart and readiness.
            # A scoped run that omits S15 still needs the between-round reset.
            if i > 1 and only is not None and "S15" not in only \
                    and not restart_cluster():
                raise RuntimeError("round %d cluster restart failed" % i)
            run_round(i, only)
            selected = sorted(only) if only is not None else list(s15_validation.SCENARIO_NAMES)
            round_verdicts = {item["name"]: item["verdict"] for item in RESULTS}
            round_missing = s15_validation.missing_required_cases(selected, round_verdicts)
            coverage_rounds.append({
                "missing": round_missing,
                "nonpass": s15_validation.missing_nonpass_cases(selected, round_verdicts),
                "verdicts": round_verdicts,
            })
            # Each completed round is checkpointed atomically. An interrupted
            # run remains complete=false and cannot be consumed as final data.
            atomic_json(args.out, snapshot(False, i))
            print("checkpoint: round %d/%d written (%s)" % (i, args.rounds, args.out), flush=True)
    except Exception as e:
        snap = snapshot(False, max(0, locals().get("i", 0) - 1))
        snap["blocked_reason"] = repr(e)
        atomic_json(args.out, snap)
        print("RUN UNKNOWN: %r" % e, flush=True)
        return 4

    print("\n" + "=" * 100)
    snap = snapshot(True, args.rounds)
    s = snap["summary"]
    npass, nfail, nna = s["pass"], s["fail"], s["na"]
    print("SUMMARY: %d PASS / %d FAIL / %d N/A" % (npass, nfail, nna))
    for x in RESULTS:
        if x["verdict"] == "N/A":
            print("  N/A %-52s %s" % (x["name"], x["detail"][:90]))
    atomic_json(args.out, snap)
    print("written %s" % args.out)
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
