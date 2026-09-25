# -*- coding: utf-8 -*-
"""Rust 三节点分布式性能测试（与 s15_coordinator.py 同一 run 部署）。

在真实三节点 astral-trustgraph 部署（共享 MySQL、run 专用 Redis、独立端口）上采集：

P1  授权评估基线（read path）      每节点串行延迟分布 + 8 线程 10s 吞吐
P2  变更传播收敛时间（ε）          30 个交替轮次（grant/revoke 各 15），写节点轮转 a/b/c，
                                   commit→全节点稳定可见且 durable terminal 的分布
P3  并发变更吞吐（write path）     3 节点各 1 写线程持续 20s（id 级条目，
                                   不扰动通配决策），吞吐 + 提交延迟 + 完整性
P4  跨节点读扩展                   3 线程各打不同节点 10s，聚合 QPS vs 单节点

必须在没有其他负载时运行（先跑完 s15_coordinator.py）。结果写 perf_result.json。

退出码：0 = PASS；1 = FAIL（含 P2 initial ALLOW 预热超时）；2 = BLOCKED
（如 HMAC secret 文件缺失/权限异常——preflight 即失败，仍写可判定 artifact）。
"""
import argparse
import concurrent.futures as futures
import hashlib
import hmac
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
import uuid

import requests

PREFIX = "astral-gateway-v3"
A = {"user_id": "9031", "icard": "9041", "card": "9061", "domain": "9011", "tenant": "9001"}

_CONFIG_PATH = os.path.expanduser(os.environ.get("RUN_CONFIG_PATH")
                                   or os.path.join(os.getcwd(), "run_config.json"))
_CONFIG_ERROR = None
try:
    with open(_CONFIG_PATH, encoding="utf-8") as _config_stream:
        CFG = json.load(_config_stream)
    if not isinstance(CFG, dict):
        raise ValueError("run_config root must be an object")
except (OSError, ValueError, TypeError) as _exc:
    # Keep import safe so main() can write a BLOCKED artifact instead of
    # terminating before the evidence path exists.  Never retain file content.
    CFG = {}
    _CONFIG_ERROR = "%s: %s" % (type(_exc).__name__, str(_exc)[:180])

NODES = CFG.get("nodes", {})
NAMES = ["node-a", "node-b", "node-c"]
DB = CFG.get("db")
MC = CFG.get("mysql_container")

SUMMARY = {}
ACTIVE_PERF_RULESETS = []

PREFLIGHT_NODE_TIMEOUT_S = 120
P2_DECISION_TIMEOUT_S = 30
P2_STABILITY_HOLD_S = 1.0
CLEANUP_DECISION_TIMEOUT_S = 45
CLEANUP_DRAIN_TIMEOUT_S = 1200
CLEANUP_MAX_BINDING_ATTEMPTS = 4
CLEANUP_MAX_PASSES = 4
CLEANUP_POLL_S = 5
CLEANUP_DECISION_SAMPLE_S = 0.3
CLEANUP_MAX_DECISION_GAP_S = 3.0
CLEANUP_DURABLE_POLL_S = 1.0


class CleanupReconciliationError(RuntimeError):
    """A source-state probe failed, so a mutation result is not replayable."""

    def __init__(self, message, evidence=None):
        super().__init__(message)
        self.evidence = evidence


# ---------- M3：HMAC secret 进程内单次加载 ----------
# secret 文件仅在启动/preflight 读取一次，保存为进程内 bytes；逐请求
# sign_headers 只使用内存副本，不再 open/read 磁盘。秘密值绝不进入
# 日志/artifact/argv/provenance（错误信息只含异常类型与路径，不含文件内容）。
_HMAC_SECRET = None          # bytes | None
_HMAC_SECRET_ERROR = None    # str | None（无秘密内容）


def load_hmac_secret():
    """启动/preflight 调用一次；之后命中进程内缓存，不再读盘。"""
    global _HMAC_SECRET, _HMAC_SECRET_ERROR
    if _HMAC_SECRET is not None or _HMAC_SECRET_ERROR is not None:
        return _HMAC_SECRET
    try:
        path = os.path.expanduser(CFG["hmac_secret_file"])
        with open(path, "rb") as f:
            data = f.read().strip()
        if not data:
            raise ValueError("hmac secret file is empty")
        _HMAC_SECRET = data
    except Exception as e:   # 路径缺失/权限异常等 → BLOCKED，不伪造继续跑
        _HMAC_SECRET_ERROR = "%s: %s" % (type(e).__name__, e)
    return _HMAC_SECRET


def _hmac_key():
    """返回进程内缓存的 secret bytes；未加载时兜底单次加载（正常路径由
    main preflight 先行加载）。失败抛 RuntimeError（不含秘密内容）。"""
    global _HMAC_SECRET_ERROR
    if _HMAC_SECRET is None:
        load_hmac_secret()
    if _HMAC_SECRET is None:
        raise RuntimeError("hmac secret unavailable (%s)" % _HMAC_SECRET_ERROR)
    return _HMAC_SECRET


def atomic_json(path, obj):
    """原子落盘：断流/中断时不留半截 JSON。"""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


_PROV_CACHE = None


def provenance():
    """run 级 provenance（零秘钥；L9 与 s15_coordinator.provenance 字段对齐）。

    事实来源：run_config.json 与部署时写下的 <base_dir>/provenance.json；
    交叉核验字段 binary_sha_match / source_snapshot_sha_match /
    source_git_rev_match / source_dirty_patch_match 为三态：
    True（一致）/ False（不一致）/ None（任一侧缺失、无法核验）——
    缺失不得伪造为 true。只读非秘钥字段，mysql_root/rabbit_pass/hmac
    等秘密永不进入结果。"""
    global _PROV_CACHE
    if _PROV_CACHE is not None:
        return _PROV_CACHE
    d = os.path.dirname(os.path.abspath(__file__))
    prov = {"run_id": CFG.get("run_id"), "binary_sha256": CFG.get("binary_sha256"),
            "git_rev": CFG.get("git_rev"),
            "source_snapshot_sha256": CFG.get("source_snapshot_sha256"),
            "source_git_rev": CFG.get("source_git_rev"),
            "source_dirty": CFG.get("source_dirty"),
            "source_dirty_patch_sha256": CFG.get("source_dirty_patch_sha256"),
            "bootstrap_bin_sha256": CFG.get("bootstrap_bin_sha256"),
            "git_dirty": None, "git_rev_local": None, "git_rev_match": None,
            # 交叉核验标记：无法核验（无部署 provenance 或单侧缺失）时如实为 None
            "binary_sha_match": None,
            "source_snapshot_sha_match": None,
            "source_git_rev_match": None,
            "source_dirty_patch_match": None,
            "source_snapshot": "run_config.json", "host": socket.gethostname()}
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
        # 如实记录 False，单侧缺失保持 None，不静默也不伪造）
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


def sql(query):
    """共享 mysql 访问（M-A 修复）：口令经 stdin 注入容器内 MYSQL_PWD，
    docker 客户端 argv 与容器内 mysql argv 均不含口令值。"""
    import shlex
    import subprocess
    inner = 'MYSQL_PWD="$(cat)" exec mysql -uroot -N -e ' + shlex.quote(query) \
        + " " + shlex.quote(DB)
    r = subprocess.run(["docker", "exec", "-i", MC, "sh", "-c", inner],
                       input=CFG["mysql_root"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("sql failed: %s / %s" % (query[:120], r.stderr[-200:]))
    return [line.split("\t") for line in r.stdout.split("\n") if line != ""]


def sql_exec(query):
    import shlex
    import subprocess
    inner = 'MYSQL_PWD="$(cat)" exec mysql -uroot -e ' + shlex.quote(query) \
        + " " + shlex.quote(DB)
    r = subprocess.run(["docker", "exec", "-i", MC, "sh", "-c", inner],
                       input=CFG["mysql_root"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("sql_exec failed: %s / %s" % (query[:120], r.stderr[-200:]))


def sign_headers(method, path, request_id=None, idempotency_key=None):
    ts = str(int(time.time() * 1000))
    sp = path.split("?")[0]
    payload = "\n".join([PREFIX, method.strip(), sp, A["user_id"], "PLATFORM_USER", "",
                         A["icard"], A["card"], A["domain"], A["tenant"],
                         "", "", "", "", ts])
    # M3 修复：旧实现逐请求 open/read secret 文件；现改用进程内单次加载的
    # 字节副本（load_hmac_secret/_hmac_key），sign_headers 不再有磁盘读。
    # 旧实现把 ~ 硬编码替换为 "/home/xg"（只在该特定部署布局下可运行），
    # 已改为标准 expanduser（仅在启动加载时执行一次）。
    sig = hmac.new(_hmac_key(), payload.encode(), hashlib.sha256).hexdigest()
    headers = {"x-request-id": request_id or str(uuid.uuid4()), "x-user-id": A["user_id"],
               "x-principal-kind": "PLATFORM_USER", "x-identity-card-id": A["icard"],
               "x-user-card-id": A["card"], "x-user-card-domain-id": A["domain"],
               "x-user-card-tenant-id": A["tenant"], "x-gateway-ts": ts,
               "x-gateway-signature": sig, "x-gateway-auth": "verified",
               "Content-Type": "application/json"}
    if idempotency_key:
        headers["x-idempotency-key"] = idempotency_key
    return headers


_tls = threading.local()


def _session():
    if not hasattr(_tls, "s"):
        _tls.s = requests.Session()
    return _tls.s


def sim(node, card_id, resource, action, user_id, domain_id, tenant_id, timeout=10):
    body = {"cardId": int(card_id), "resource": resource, "action": action,
            "userId": int(user_id), "domainId": int(domain_id), "tenantId": int(tenant_id),
            "proposedRules": []}
    try:
        r = _session().post(NODES[node] + "/main/api/v1/simulation/evaluate",
                            headers=sign_headers("POST", "/main/api/v1/simulation/evaluate"),
                            json=body, timeout=timeout)
    except Exception as exc:
        return {"allowed": None, "http": 0,
                "reason": "EXC:%s" % type(exc).__name__, "body": ""}
    if r.status_code != 200:
        text = str(getattr(r, "text", ""))[:200]
        reason = "PENDING" if (r.status_code == 503 or
                                "AUTHORIZATION_PENDING" in text) else "HTTP_%d" % r.status_code
        return {"allowed": None, "http": r.status_code, "reason": reason, "body": text}
    try:
        data = r.json().get("data") or {}
        cd = data.get("currentDecision") or {}
    except Exception as exc:
        return {"allowed": None, "http": 200, "reason": "PARSE_%s" % type(exc).__name__,
                "body": str(getattr(r, "text", ""))[:200]}
    return {"allowed": cd.get("allowed"), "http": 200,
            "reason": cd.get("reason", ""), "body": ""}


SIM_ARGS = (int(A["card"]), "learn_subject:*", "read", int(A["user_id"]),
            int(A["domain"]), int(A["tenant"]))


def pct(sorted_samples, p):
    if not sorted_samples:
        return None
    k = min(len(sorted_samples) - 1, max(0, int(round(p / 100.0 * (len(sorted_samples) + 1)) - 1)))
    return sorted_samples[k]


def dist(samples):
    s = sorted(samples)
    return {"n": len(s), "mean_ms": round(statistics.mean(s), 3) if s else None,
            "p50_ms": pct(s, 50), "p95_ms": pct(s, 95), "p99_ms": pct(s, 99),
            "max_ms": round(s[-1], 3) if s else None, "min_ms": round(s[0], 3) if s else None}


# ---------- P1 授权评估基线 ----------

def p1_sequential(node, n=300):
    lat, errs = [], 0
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            d = sim(node, *SIM_ARGS)
            if not _decision_matches(d, False):
                errs += 1
        except Exception:
            errs += 1
        lat.append((time.perf_counter() - t0) * 1000)
    return {"node": node, "decision_resource": SIM_ARGS[1],
            "expected_allowed": False, "errors": errs, **dist(lat)}


def p1_concurrent(node, threads=8, seconds=10):
    lat, errs, count = [], [0], [0]
    stop = time.time() + seconds
    lock = threading.Lock()

    def worker():
        while time.time() < stop:
            t0 = time.perf_counter()
            try:
                d = sim(node, *SIM_ARGS)
                ok = _decision_matches(d, False)
            except Exception:
                ok = False
            dt = (time.perf_counter() - t0) * 1000
            with lock:
                lat.append(dt)
                count[0] += 1
                if not ok:
                    errs[0] += 1

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    elapsed = time.perf_counter() - t0
    return {"node": node, "threads": threads, "seconds": round(elapsed, 2),
            "decision_resource": SIM_ARGS[1], "expected_allowed": False,
            "ops": count[0], "qps": round(count[0] / elapsed, 1), "errors": errs[0],
            "latency": dist(lat)}


# ---------- P2 传播收敛（ε） ----------

def make_perf_rs(tag, with_grant=False):
    """perf 夹具规则集。契约约束：条目资源必须是已注册类型（用 monitor）；
    绑定前必须已有 delta（先条目后绑定），否则卡证据依赖链无法收敛。"""
    code = "s15_perf_%s_%s" % (tag, uuid.uuid4().hex[:8])
    sql_exec("INSERT INTO rule_set (name, code, source_type, description, enabled, tenant_id) "
             "VALUES ('perf %s', '%s', 'CUSTOM', 'perf fixture', 1, %s)" % (tag, code, A["tenant"]))
    rs = int(sql("SELECT rule_set_id FROM rule_set WHERE code='%s'" % code)[0][0])
    ACTIVE_PERF_RULESETS.append(rs)
    eid = None
    if with_grant:
        path = "/main/api/v1/rule-sets/%d/entries" % rs
        operation_id = "s15-perf-fixture-%s-entry" % rs
        r = _session().post(
            NODES["node-b"] + path,
            headers=sign_headers("POST", path, request_id=operation_id,
                                 idempotency_key=operation_id),
            json={"resource": "monitor", "action": "read", "effect": "ALLOW",
                  "priority": 1}, timeout=15)
        assert r.status_code == 200, "perf entry failed: %s" % r.text[:150]
        eid = r.json()["data"]["id"]
    path = "/main/api/v1/rule-sets/card/%s/bind" % A["card"]
    operation_id = "s15-perf-fixture-%s-bind" % rs
    r = _session().post(
        NODES["node-b"] + path,
        headers=sign_headers("POST", path, request_id=operation_id,
                             idempotency_key=operation_id),
        json={"ruleSetId": rs, "refType": "BASE"}, timeout=15)
    assert r.status_code == 200, "perf bind failed: %s" % r.text[:150]
    return rs, eid


def add_perf_entry_result(rs, resource, node, operation_id=None):
    path = "/main/api/v1/rule-sets/%d/entries" % rs
    operation_id = operation_id or "s15-perf-entry-%s-%s-%s" % (rs, resource, uuid.uuid4().hex[:12])
    try:
        r = _session().post(NODES[node] + path,
                            headers=sign_headers("POST", path, request_id=operation_id,
                                                 idempotency_key=operation_id),
                            json={"resource": resource, "action": "read", "effect": "ALLOW",
                                  "priority": 1}, timeout=15)

    except Exception as exc:
        return None, None, type(exc).__name__
    try:
        data = r.json().get("data") or {}
        eid = data.get("id")
    except Exception:
        eid = None
    return r, eid, None


def add_perf_entry(rs, resource, node):
    r, eid, error = add_perf_entry_result(rs, resource, node)
    if error:
        raise AssertionError("add entry request failed: %s" % error)
    if r is None or r.status_code != 200 or eid is None:
        raise AssertionError("add entry failed: http=%s eid=%s" %
                             (getattr(r, "status_code", None), eid))
    return eid


def del_perf_entry_result(rs, eid, node, operation_id=None):
    path = "/main/api/v1/rule-sets/%d/entries/%s" % (rs, eid)
    operation_id = operation_id or "s15-perf-delete-%s-%s-%s" % (rs, eid, uuid.uuid4().hex[:12])
    try:
        return _session().delete(
            NODES[node] + path,
            headers=sign_headers("DELETE", path, request_id=operation_id,
                                 idempotency_key=operation_id), timeout=15), None
    except Exception as exc:
        return None, type(exc).__name__


def del_perf_entry(rs, eid, node):
    r, error = del_perf_entry_result(rs, eid, node)
    if error:
        raise AssertionError("delete entry request failed: %s" % error)
    if r is None or r.status_code != 200:
        raise AssertionError("del entry failed: http=%s" % getattr(r, "status_code", None))
    return r


def classify_write_result(resp, eid, error=None):
    """Keep expected fail-closed pending responses separate from real errors."""
    if error:
        return "non_pending"
    if resp is not None and getattr(resp, "status_code", None) == 200 and eid is not None:
        return "ok"
    text = str(getattr(resp, "text", "") or "") if resp is not None else ""
    if (resp is not None and getattr(resp, "status_code", None) == 403
            and "AUTHORIZATION_PENDING" in text):
        return "pending_403"
    return "non_pending"


def write_error_sample(resp, eid, error=None):
    if error:
        return {"kind": "exception", "status": None, "error_type": error}
    status = getattr(resp, "status_code", None) if resp is not None else None
    text = str(getattr(resp, "text", "") or "")[:160] if resp is not None else ""
    if status == 200 and eid is None:
        text = "http 200 without entry id"
    return {"kind": classify_write_result(resp, eid), "status": status, "body": text}


MONITOR_ARGS = (int(A["card"]), "monitor:*", "read", int(A["user_id"]),
                int(A["domain"]), int(A["tenant"]))


def _source_entry_ids(rs):
    rows = sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d "
               "AND effect='ALLOW' AND enabled=1 ORDER BY entry_id" % int(rs))
    return [int(row[0]) for row in rows if row and row[0]]


def _p2_mutation(rs, eid, kind, writer, round_no):
    baseline = _source_entry_ids(rs)
    if kind == "revoke" and (eid is None or int(eid) not in baseline):
        return {"ok": False, "reconciled": False, "error": "source_entry_missing_before_revoke",
                "baseline_entry_ids": baseline, "attempts": []}, eid
    if kind == "grant" and baseline:
        return {"ok": False, "reconciled": False,
                "error": "source_not_empty_before_grant",
                "baseline_entry_ids": baseline, "attempts": []}, eid

    operation_id = "s15-perf-p2-%s-%s-%d" % (kind, int(rs), int(round_no))
    attempts = []
    since_id = _card_delta_watermark(A["card"])
    for attempt in range(1, 4):
        mutation_started = time.perf_counter()
        if kind == "revoke":
            response, error = del_perf_entry_result(
                rs, eid, writer, operation_id=operation_id)
            returned_eid = None
        else:
            response, returned_eid, error = add_perf_entry_result(
                rs, "monitor", writer, operation_id=operation_id)
        request_returned_at = time.perf_counter()
        request_ms = (request_returned_at - mutation_started) * 1000
        status = getattr(response, "status_code", None) if response is not None else None
        body = str(getattr(response, "text", "") or "")[:160]
        result_eid = eid if kind == "revoke" else returned_eid
        result_kind = classify_write_result(response, result_eid, error)
        try:
            current = _source_entry_ids(rs)
        except Exception as exc:
            attempts.append({"attempt": attempt, "http": status, "kind": result_kind,
                             "error": error, "source_error": type(exc).__name__})
            return {"ok": False, "reconciled": False, "error": "source_reconcile_failed",
                    "baseline_entry_ids": baseline, "attempts": attempts}, eid

        if kind == "revoke":
            committed = not current
            next_eid = None
        else:
            new_ids = [value for value in current if value not in baseline]
            committed = bool(new_ids)
            next_eid = (returned_eid if returned_eid in current else max(new_ids, default=None))
        attempts.append({"attempt": attempt, "http": status, "kind": result_kind,
                         "error": error, "request_ms": round(request_ms, 2),
                         "source_entry_ids": current,
                         "source_committed": committed, "body": body})
        if committed:
            commit_return_proven = status == 200 and error is None
            return {"ok": commit_return_proven, "source_committed": True,
                    "reconciled": True,
                    "error": None if commit_return_proven else "commit_time_unknown",
                    "baseline_entry_ids": baseline,
                    "final_entry_ids": current, "attempts": attempts,
                    "request_id": operation_id, "delta_since_id": since_id,
                    "commit_return_perf": request_returned_at if commit_return_proven else None,
                    "commit_request_ms": round(request_ms, 2)}, next_eid

        # The source is unchanged, so retrying this exact mutation is safe.  A
        # source probe is mandatory before every retry; an unknown probe stops.
        if error:
            return {"ok": False, "reconciled": False, "error": "mutation_outcome_unknown",
                    "baseline_entry_ids": baseline, "final_entry_ids": current,
                    "attempts": attempts, "request_id": operation_id}, eid
        retryable = _retryable_unbind_status(response) \
            or (status == 200 and returned_eid is None and kind == "grant")
        if not retryable:
            return {"ok": False, "reconciled": True, "error": "mutation_nonretryable",
                    "baseline_entry_ids": baseline, "final_entry_ids": current,
                    "attempts": attempts, "request_id": operation_id}, eid
        if kind == "grant":
            safety = _wait_no_allow(A["card"])
            attempts[-1]["safety"] = safety
            if not safety["ok"]:
                return {"ok": False, "reconciled": False, "error": "no_allow_window_timeout",
                        "baseline_entry_ids": baseline, "final_entry_ids": current,
                        "attempts": attempts, "request_id": operation_id}, eid
        drain = _wait_ruleset_drain(rs, A["card"], 0, timeout_s=120)
        api_ready = _wait_binding_api_ready(A["card"], timeout_s=120)
        attempts[-1]["drain"] = drain
        attempts[-1]["api_ready"] = api_ready
        if not drain["ok"] or not api_ready["ok"]:
            return {"ok": False, "reconciled": False, "error": "mutation_retry_precondition_timeout",
                    "baseline_entry_ids": baseline, "final_entry_ids": current,
                    "attempts": attempts, "request_id": operation_id}, eid
        after_wait = _source_entry_ids(rs)
        attempts[-1]["source_after_wait"] = after_wait
        changed_after_unknown = (not after_wait) if kind == "revoke" else bool(after_wait)
        if changed_after_unknown:
            return {"ok": False, "source_committed": True, "reconciled": True,
                    "error": "commit_time_unknown", "baseline_entry_ids": baseline,
                    "final_entry_ids": after_wait, "attempts": attempts,
                    "request_id": operation_id}, (max(after_wait) if after_wait else None)
    return {"ok": False, "reconciled": True, "error": "mutation_retry_budget_exhausted",
            "baseline_entry_ids": baseline, "final_entry_ids": _source_entry_ids(rs),
            "attempts": attempts, "request_id": operation_id}, eid


def p2_propagation(rs, eid, rounds=30, checkpoint=None):
    """Measure alternating revoke/grant convergence with source reconciliation.

    A round is never treated as successful from an HTTP response alone.  The
    source entry set must prove the intended mutation before decision latency is
    sampled; an ambiguous round is retained and the sequence stops safely.
    """
    results = {"grant": [], "revoke": []}
    aborted = False

    def snapshot(complete):
        summary = {}
        for kind in ("grant", "revoke"):
            cs = sorted(x["converge_ms"] for x in results[kind]
                        if x.get("converge_ms") is not None)
            summary[kind] = {**dist(cs),
                             "unconverged": sum(1 for x in results[kind]
                                                 if x.get("converge_ms") is None)}
        return {"complete": bool(complete), "rounds_requested": int(rounds),
                "rounds_done": len(results["grant"]) + len(results["revoke"]),
                "aborted": bool(aborted), "rounds": results, "summary": summary}

    for i in range(rounds):
        writer = NAMES[i % 3]
        kind = "revoke" if i % 2 == 0 else "grant"
        record = {"round": i + 1, "writer": writer, "kind": kind,
                  "converge_ms": None}
        try:
            pre_round = _wait_ruleset_drain(
                rs, A["card"], 0, timeout_s=120)
            record["pre_round_drain"] = pre_round
            if not pre_round.get("ok"):
                record["error"] = "pre_round_drain_timeout"
                results[kind].append(record)
                aborted = True
                if checkpoint:
                    checkpoint(snapshot(False))
                break
            mutation, eid = _p2_mutation(rs, eid, kind, writer, i + 1)
            record["mutation"] = mutation
            if not mutation.get("ok"):
                record["error"] = mutation.get("error", "mutation_not_reconciled")
                results[kind].append(record)
                aborted = True
                if checkpoint:
                    checkpoint(snapshot(False))
                break
            t_commit = mutation.get("commit_return_perf")
            if t_commit is None:
                record["error"] = "commit_time_unknown"
                results[kind].append(record)
                aborted = True
                if checkpoint:
                    checkpoint(snapshot(False))
                break
            want = kind == "grant"
            convergence = _wait_p2_convergence(
                rs, A["card"], mutation.get("delta_since_id", 0), want,
                t_commit, timeout_s=P2_DECISION_TIMEOUT_S,
                hold_s=P2_STABILITY_HOLD_S)
            record.update(convergence)
            if not convergence.get("ok"):
                record["error"] = convergence.get(
                    "error", "decision_or_durable_state_not_stable")
                aborted = True
            results[kind].append(record)
        except Exception as exc:
            record["error"] = "%s:%s" % (type(exc).__name__, str(exc)[:160])
            record["source_reconciled"] = False
            results[kind].append(record)
            aborted = True
        print("  P2 %-6s round %2d writer=%s converge=%s" %
              (kind, i + 1, writer, record.get("converge_ms")), flush=True)
        if checkpoint:
            checkpoint(snapshot(False))
        if aborted:
            break

    return snapshot(not aborted and
                    len(results["grant"]) + len(results["revoke"]) == rounds)


# ---------- P3 并发变更吞吐 ----------

def p3_storm(rs, seconds=20):
    ops = [0]
    errors = {"pending_403": 0, "non_pending": 0, "api_total": 0}
    samples = []
    lat = []
    error_lat = []
    lock = threading.Lock()
    stop = time.time() + seconds

    def writer(idx, node):
        while time.time() < stop:
            t0 = time.perf_counter()
            response, eid, error = add_perf_entry_result(rs, "monitor", node)
            dt = (time.perf_counter() - t0) * 1000
            kind = classify_write_result(response, eid, error)
            with lock:
                if kind == "ok":
                    lat.append(dt)
                    ops[0] += 1
                else:
                    error_lat.append(dt)
                    errors["api_total"] += 1
                    errors["pending_403" if kind == "pending_403" else "non_pending"] += 1
                    if len(samples) < 5:
                        samples.append(write_error_sample(response, eid, error))

    ts = [threading.Thread(target=writer, args=(i, n)) for i, n in enumerate(NAMES)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    elapsed = time.perf_counter() - t0
    # 收敛 + 完整性；source outbox 与 published frontier 分域证明。
    deadline = time.time() + 60
    total = processed = terminal = 0
    frontier = {"terminal": False}
    drain_timed_out = True
    while time.time() < deadline:
        rows = sql("SELECT COUNT(*), SUM(status='PROCESSED'), SUM(terminal_transitions=1) "
                   "FROM authorization_projection_outbox WHERE tenant_id=%d "
                   "AND aggregate_type='RULE_SET' AND aggregate_id=%d" %
                   (int(A["tenant"]), int(rs)))
        total = int(rows[0][0]) if rows else 0
        processed = int(rows[0][1] or 0) if rows else 0
        terminal = int(rows[0][2] or 0) if rows else 0
        frontier = _published_frontier_sample(rs)
        if (total >= ops[0] and processed == total and terminal == total
                and frontier.get("terminal") is True):
            drain_timed_out = False
            break
        time.sleep(1)
    head = sql("SELECT source_generation FROM authorization_projection_head "
               "WHERE aggregate_type='RULE_SET' AND aggregate_id=%d" % rs)
    source_generations = sql(
        "SELECT DISTINCT source_generation FROM authorization_projection_outbox "
        "WHERE tenant_id=%d AND aggregate_type='RULE_SET' AND aggregate_id=%d "
        "ORDER BY source_generation" % (int(A["tenant"]), int(rs)))
    source_generations = [int(row[0]) for row in source_generations]
    head_source_generation = int(head[0][0]) if head else None
    source_generation_matches_outbox = bool(
        head_source_generation is not None and source_generations
        and head_source_generation == max(source_generations))
    source_generations_contiguous = bool(
        head_source_generation is not None
        and source_generations == list(range(1, head_source_generation + 1)))
    integrity = {
        "outbox_rows": total,
        "all_processed": bool(total > 0 and processed == total),
        "terminal_once": bool(total > 0 and terminal == total),
        "drain_timed_out": drain_timed_out,
        "head": {"source_generation": head_source_generation} if head else None,
        "source_generation_matches_outbox": source_generation_matches_outbox,
        "source_generations_contiguous": source_generations_contiguous,
        "source_generation_count": len(source_generations),
        "frontier_terminal": frontier.get("terminal") is True,
        "frontier": frontier,
    }
    return {"seconds": round(elapsed, 2), "ops": ops[0],
            "qps": round(ops[0] / elapsed, 1) if elapsed else 0,
            "errors": errors["api_total"], "pending_403": errors["pending_403"],
            "non_pending_errors": errors["non_pending"], "error_samples": samples,
            "commit_latency": dist(lat), "error_latency": dist(error_lat),
            "integrity": integrity}


# ---------- P3.5 有界排水（P4 读基线的前置） ----------

def bounded_drain(rs_list, card_id, timeout_s=300):
    """P4 前有界排水：等待 RULE_SET outbox、impact/archive 与卡级 delta
    （含 card_id NULL fan-out）全部进入可证明终态，并核对指针 READY。"""
    t0 = time.time()
    deadline = t0 + timeout_s
    ids = ",".join(str(int(r)) for r in rs_list) or "0"
    last = {}
    while time.time() < deadline:
        rows = sql("SELECT COUNT(*), COALESCE(SUM(status='PROCESSED'), 0) "
                   "FROM authorization_projection_outbox WHERE tenant_id=%d "
                   "AND aggregate_type='RULE_SET' AND aggregate_id IN (%s)" %
                   (int(A["tenant"]), ids))
        impact = sql("SELECT COUNT(*) FROM authorization_impact_plan "
                     "WHERE tenant_id=%d AND aggregate_type='RULE_SET' "
                     "AND aggregate_id IN (%s) AND status <> 'SUCCEEDED'" %
                     (int(A["tenant"]), ids))
        archive = sql("SELECT COUNT(*) FROM authorization_archive_outbox "
                      "WHERE tenant_id=%d AND aggregate_type='RULE_SET' "
                      "AND aggregate_id IN (%s) AND status <> 'SUCCEEDED'" %
                      (int(A["tenant"]), ids))
        delta = sql("SELECT COUNT(*) FROM authorization_delta_event WHERE tenant_id=%d "
                    "AND (card_id=%d OR card_id IS NULL) AND status <> 'SUCCEEDED'" %
                    (int(A["tenant"]), int(card_id)))
        frontiers = {str(int(rs)): _published_frontier_sample(rs) for rs in rs_list}
        total = int(rows[0][0]) if rows else 0
        processed = int(rows[0][1]) if rows else 0
        last = {"outbox_total": total, "outbox_processed": processed,
                "impact_pending": int(impact[0][0]) if impact else None,
                "archive_pending": int(archive[0][0]) if archive else None,
                "card_delta_pending": int(delta[0][0]) if delta else None,
                "frontiers": frontiers,
                "frontiers_terminal": all(
                    frontier.get("terminal") is True for frontier in frontiers.values()),
                "rulesets": len(rs_list)}
        outbox_ok = total > 0 and total == processed
        if (outbox_ok and last["impact_pending"] == 0 and last["archive_pending"] == 0
                and last["card_delta_pending"] == 0
                and last["frontiers_terminal"]):
            last["drained"] = True
            break
        time.sleep(2)
    else:
        last["drained"] = False
    last.update({"timeout_s": timeout_s, "elapsed_s": round(time.time() - t0, 2),
                 "outbox_terminal": bool(last.get("outbox_total", 0) > 0 and
                                          last.get("outbox_total") == last.get("outbox_processed")),
                 "card_deltas_terminal": last.get("card_delta_pending") == 0})
    print("  pre-P4 drain: %s" % last)
    return last


# ---------- P4 跨节点读扩展 ----------

def p4_read_scaling(seconds=10):
    lat, errs, count = [], [0], [0]
    lock = threading.Lock()
    stop = time.time() + seconds

    def worker(node):
        while time.time() < stop:
            t0 = time.perf_counter()
            try:
                ok = _decision_matches(sim(node, *SIM_ARGS), False)
            except Exception:
                ok = False
            dt = (time.perf_counter() - t0) * 1000
            with lock:
                lat.append(dt)
                count[0] += 1
                if not ok:
                    errs[0] += 1

    ts = [threading.Thread(target=worker, args=(n,)) for n in NAMES]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    elapsed = time.perf_counter() - t0
    return {"threads": len(NAMES), "seconds": round(elapsed, 2),
            "decision_resource": SIM_ARGS[1], "expected_allowed": False,
            "ops": count[0],
            "qps_aggregate": round(count[0] / elapsed, 1), "errors": errs[0],
            "latency": dist(lat)}


def _binding_api_path(card_id):
    return "/main/api/v1/rule-sets/card/%s/bindings" % int(card_id)


def _binding_source_ids(card_id):
    rows = sql("SELECT rule_set_id FROM card_rule_set_ref WHERE card_id=%d "
               "AND tenant_id=%d ORDER BY rule_set_id" %
               (int(card_id), int(A["tenant"])))
    return [int(row[0]) for row in rows if row and row[0]]


def _binding_probe(card_id):
    """Read the API view and source binding table as one reconciliation unit."""
    path = _binding_api_path(card_id)
    try:
        response = _session().get(NODES["node-b"] + path,
                                  headers=sign_headers("GET", path), timeout=15)
    except Exception as exc:
        raise CleanupReconciliationError("binding_probe_request:%s" % type(exc).__name__)
    if response.status_code != 200:
        raise CleanupReconciliationError("binding_probe_http:%s" % response.status_code)
    try:
        payload = response.json()
        data = payload.get("data")
    except Exception as exc:
        raise CleanupReconciliationError("binding_probe_json:%s" % type(exc).__name__)
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and isinstance(data.get("items"), list):
        items = data["items"]
    else:
        raise CleanupReconciliationError("binding_probe_shape")
    api_ids = []
    normalized = []
    for item in items:
        if not isinstance(item, dict) or item.get("ruleSetId") is None:
            raise CleanupReconciliationError("binding_probe_missing_rule_set_id")
        rs_id = int(item["ruleSetId"])
        if rs_id not in api_ids:
            api_ids.append(rs_id)
            normalized.append({"rule_set_id": rs_id,
                               "rule_set_name": str(item.get("ruleSetName", ""))[:120],
                               "ref_type": str(item.get("refType", ""))[:16]})
    source_ids = _binding_source_ids(card_id)
    if sorted(api_ids) != sorted(source_ids):
        raise CleanupReconciliationError(
            "binding_probe_source_api_mismatch:api=%s source=%s" %
            (sorted(api_ids), sorted(source_ids)))
    return {"items": normalized, "api_ids": sorted(api_ids),
            "source_ids": sorted(source_ids), "count": len(source_ids)}


def _card_delta_watermark(card_id):
    rows = sql("SELECT COALESCE(MAX(delta_event_id), 0) "
               "FROM authorization_delta_event WHERE tenant_id=%d "
               "AND (card_id=%d OR card_id IS NULL)" %
               (int(A["tenant"]), int(card_id)))
    return int(rows[0][0]) if rows else 0


def _card_delta_sample(card_id, since_id, rule_set_id=None):
    aggregate_scope = (" AND aggregate_type='RULE_SET' AND aggregate_id=%d" %
                       int(rule_set_id)) if rule_set_id is not None else ""
    rows = sql("SELECT COUNT(*), COALESCE(SUM(status='SUCCEEDED'), 0), "
               "COALESCE(SUM(status <> 'SUCCEEDED'), 0), COALESCE(MAX(attempts), 0), "
               "COALESCE(MAX(delta_event_id), 0) "
               "FROM authorization_delta_event WHERE tenant_id=%d "
               "AND (card_id=%d OR card_id IS NULL) AND delta_event_id > %d%s" %
               (int(A["tenant"]), int(card_id), int(since_id), aggregate_scope))
    if not rows:
        return {"total": 0, "succeeded": 0, "pending": 0,
                "max_attempts": 0, "max_delta_event_id": 0}
    return {"total": int(rows[0][0]), "succeeded": int(rows[0][1]),
            "pending": int(rows[0][2]), "max_attempts": int(rows[0][3]),
            "max_delta_event_id": int(rows[0][4])}


def _wait_card_delta_drain(card_id, since_id, timeout_s=CLEANUP_DRAIN_TIMEOUT_S,
                           forbid_allow=False):
    started = time.perf_counter()
    deadline = started + timeout_s
    last = _card_delta_sample(card_id, since_id)
    next_delta_probe = started
    decision_samples = 0
    last_decision = None
    while time.perf_counter() < deadline:
        now = time.perf_counter()
        if now >= next_delta_probe:
            last = _card_delta_sample(card_id, since_id)
            next_delta_probe = now + CLEANUP_POLL_S
        if forbid_allow:
            last_decision = _decision_snapshot(timeout=2)
            decision_samples += 1
            if _snapshot_has_allow(last_decision):
                return {"ok": False, "unsafe_allow": True, "since_id": int(since_id),
                        **last, "decision_samples": decision_samples,
                        "last_decision": last_decision,
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
        if last["pending"] == 0:
            return {"ok": True, "unsafe_allow": False, "since_id": int(since_id), **last,
                    "decision_samples": decision_samples, "last_decision": last_decision,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
        time.sleep(0.3 if forbid_allow else min(CLEANUP_POLL_S, 1.0))
    return {"ok": False, "unsafe_allow": False, "since_id": int(since_id), **last,
            "decision_samples": decision_samples, "last_decision": last_decision,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def _decision_is_available(decision):
    reason = "".join(str(decision.get("reason") or "").split()).casefold()
    return (decision.get("http") == 200
            and isinstance(decision.get("allowed"), bool)
            and not reason.startswith("published:unavailable"))


def _decision_matches(decision, want):
    return _decision_is_available(decision) and decision.get("allowed") is want


def _published_frontier_is_terminal(frontier):
    """Validate one published RULE_SET frontier without mixing generation domains."""
    generation = frontier.get("pointer_generation")
    if not isinstance(generation, int) or generation <= 0:
        return False
    return bool(
        frontier.get("pointer_status") == "READY"
        and frontier.get("pointer_revoke_fence_proven") == 1
        and frontier.get("manifest_status") == "COMMITTED"
        and frontier.get("manifest_generation") == generation
        and frontier.get("manifest_source_generation", 0) > 0
        and frontier.get("manifest_projected_generation") ==
            frontier.get("manifest_source_generation")
        and frontier.get("pointer_manifest_match") is True
        and frontier.get("tip_plan_delta_match") is True
        and frontier.get("impact_total") == generation
        and frontier.get("impact_succeeded") == generation
        and frontier.get("impact_chained") == generation
        and frontier.get("impact_scope_match") == generation
        and frontier.get("impact_min_generation") == 1
        and frontier.get("impact_max_generation") == generation
        and frontier.get("impact_distinct_generations") == generation
        and frontier.get("impact_extra_succeeded") == 0
        and frontier.get("mapped_total") == generation
        and frontier.get("mapped_succeeded") == generation
        and frontier.get("mapped_missing") == 0
        and frontier.get("mapped_distinct_events") == generation
        and frontier.get("mapped_scope_match") == generation
        and frontier.get("mapped_contract_match") == generation
        and frontier.get("aggregate_delta_pending") == 0
        and frontier.get("aggregate_unmapped_succeeded") == 0
        and frontier.get("grant_chain_gaps") == 0
        and frontier.get("grant_target_duplicates") == 0)


def _published_frontier_sample(rs):
    tenant = int(A["tenant"])
    aggregate = int(rs)
    rows = sql(
        "SELECT p.current_generation, p.status, p.revoke_fence_proven, "
        "m.generation, m.status, m.source_generation, m.projected_generation, "
        "COALESCE(h.source_generation, 0), "
        "(p.card_id <=> m.card_id AND p.event_id=m.event_id "
        "AND p.operation_id=m.operation_id AND p.semantic_hash=m.semantic_hash "
        "AND p.dependency_hash=m.dependency_hash "
        "AND p.compiler_version=m.compiler_version "
        "AND p.revoke_fence=m.revoke_fence), "
        "(SELECT COUNT(*) FROM authorization_impact_plan i "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(i.status='SUCCEEDED'),0) "
        "FROM authorization_impact_plan i WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(i.base_generation=i.target_generation-1),0) "
        "FROM authorization_impact_plan i WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(i.card_id <=> p.card_id),0) "
        "FROM authorization_impact_plan i WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(MIN(i.target_generation),0) "
        "FROM authorization_impact_plan i WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(MAX(i.target_generation),0) "
        "FROM authorization_impact_plan i WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COUNT(DISTINCT i.target_generation) "
        "FROM authorization_impact_plan i WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COUNT(*) FROM authorization_impact_plan i "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation>p.current_generation AND i.status='SUCCEEDED'), "
        "(SELECT COUNT(*) FROM authorization_impact_plan i "
        "LEFT JOIN authorization_delta_event d ON d.tenant_id=i.tenant_id "
        "AND d.aggregate_type=i.aggregate_type AND d.aggregate_id=i.aggregate_id "
        "AND d.event_id=i.event_id WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(d.status='SUCCEEDED'),0) "
        "FROM authorization_impact_plan i LEFT JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(d.event_id IS NULL),0) "
        "FROM authorization_impact_plan i LEFT JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COUNT(DISTINCT d.event_id) "
        "FROM authorization_impact_plan i LEFT JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(d.tenant_id=i.tenant_id "
        "AND d.card_id <=> i.card_id AND i.card_id <=> p.card_id "
        "AND d.aggregate_type=i.aggregate_type AND d.aggregate_id=i.aggregate_id),0) "
        "FROM authorization_impact_plan i LEFT JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COALESCE(SUM(d.operation_id=i.operation_id "
        "AND i.base_version>=0 AND i.target_version>i.base_version "
        "AND d.base_version=i.base_version AND d.target_version=i.target_version "
        "AND d.source_generation>0 AND d.revoke_fence<=d.source_generation "
        "AND CAST(d.grant_id AS BINARY)=CAST(LOWER(d.grant_id) AS BINARY) "
        "AND d.grant_id REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
        "AND d.grant_id<>'00000000-0000-0000-0000-000000000000' "
        "AND d.semantic_hash=i.semantic_hash AND d.dependency_hash=i.dependency_hash "
        "AND d.compiler_version=i.compiler_version),0) "
        "FROM authorization_impact_plan i LEFT JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=p.tenant_id AND i.aggregate_type=p.aggregate_type "
        "AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation<=p.current_generation), "
        "(SELECT COUNT(*) FROM authorization_delta_event d "
        "WHERE d.tenant_id=p.tenant_id AND d.aggregate_type=p.aggregate_type "
        "AND d.aggregate_id=p.aggregate_id AND d.status<>'SUCCEEDED'), "
        "(SELECT COUNT(*) FROM authorization_delta_event d "
        "WHERE d.tenant_id=p.tenant_id AND d.aggregate_type=p.aggregate_type "
        "AND d.aggregate_id=p.aggregate_id AND d.status='SUCCEEDED' "
        "AND NOT EXISTS (SELECT 1 FROM authorization_impact_plan i "
        "WHERE i.tenant_id=d.tenant_id AND i.aggregate_type=d.aggregate_type "
        "AND i.aggregate_id=d.aggregate_id AND i.event_id=d.event_id)), "
        "(SELECT COUNT(*) FROM (SELECT q.base_version, "
        "LAG(q.target_version) OVER (PARTITION BY q.grant_id "
        "ORDER BY q.target_generation) previous_target FROM ("
        "SELECT i.target_generation,d.grant_id,d.base_version,d.target_version "
        "FROM authorization_impact_plan i JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=%d AND i.aggregate_type='RULE_SET' "
        "AND i.aggregate_id=%d AND i.target_generation<=(SELECT current_generation "
        "FROM authorization_projection_current WHERE tenant_id=%d "
        "AND aggregate_type='RULE_SET' AND aggregate_id=%d)) q) chain "
        "WHERE chain.previous_target IS NOT NULL "
        "AND chain.base_version<>chain.previous_target), "
        "(SELECT COUNT(*) FROM (SELECT d.grant_id,d.target_version,COUNT(*) n "
        "FROM authorization_impact_plan i JOIN authorization_delta_event d "
        "ON d.tenant_id=i.tenant_id AND d.aggregate_type=i.aggregate_type "
        "AND d.aggregate_id=i.aggregate_id AND d.event_id=i.event_id "
        "WHERE i.tenant_id=%d AND i.aggregate_type='RULE_SET' "
        "AND i.aggregate_id=%d AND i.target_generation<=(SELECT current_generation "
        "FROM authorization_projection_current WHERE tenant_id=%d "
        "AND aggregate_type='RULE_SET' AND aggregate_id=%d) "
        "GROUP BY d.grant_id,d.target_version HAVING COUNT(*)>1) duplicates), "
        "(SELECT COUNT(*) FROM authorization_impact_plan i "
        "JOIN authorization_delta_event d ON d.tenant_id=i.tenant_id "
        "AND d.aggregate_type=i.aggregate_type AND d.aggregate_id=i.aggregate_id "
        "AND d.event_id=i.event_id WHERE i.tenant_id=p.tenant_id "
        "AND i.aggregate_type=p.aggregate_type AND i.aggregate_id=p.aggregate_id "
        "AND i.target_generation=p.current_generation AND i.status='SUCCEEDED' "
        "AND d.status='SUCCEEDED' AND i.card_id <=> p.card_id "
        "AND d.card_id <=> p.card_id AND i.operation_id=d.operation_id "
        "AND i.base_version=d.base_version AND i.target_version=d.target_version "
        "AND i.semantic_hash=d.semantic_hash AND i.dependency_hash=d.dependency_hash "
        "AND i.compiler_version=d.compiler_version "
        "AND m.revoke_fence>=d.revoke_fence "
        "AND m.source_generation=d.source_generation AND m.event_id=d.event_id "
        "AND m.operation_id=d.operation_id AND m.semantic_hash=d.semantic_hash "
        "AND m.dependency_hash=d.dependency_hash "
        "AND m.compiler_version=d.compiler_version) "
        "FROM authorization_projection_current p "
        "JOIN authorization_projection_manifest m ON m.manifest_id=p.manifest_id "
        "AND m.tenant_id=p.tenant_id AND m.aggregate_type=p.aggregate_type "
        "AND m.aggregate_id=p.aggregate_id "
        "LEFT JOIN authorization_projection_head h ON h.aggregate_type=p.aggregate_type "
        "AND h.aggregate_id=p.aggregate_id "
        "WHERE p.tenant_id=%d AND p.aggregate_type='RULE_SET' "
        "AND p.aggregate_id=%d" % (
            tenant, aggregate, tenant, aggregate,
            tenant, aggregate, tenant, aggregate,
            tenant, aggregate))
    if not rows:
        return {"terminal": False, "pointer_generation": None,
                "pointer_status": None, "manifest_status": None}
    row = rows[0]
    sample = {
        "pointer_generation": int(row[0]),
        "pointer_status": row[1],
        "pointer_revoke_fence_proven": int(row[2]),
        "manifest_generation": int(row[3]),
        "manifest_status": row[4],
        "manifest_source_generation": int(row[5]),
        "manifest_projected_generation": int(row[6]),
        "head_source_generation": int(row[7]),
        "pointer_manifest_match": bool(int(row[8])),
        "impact_total": int(row[9]),
        "impact_succeeded": int(row[10]),
        "impact_chained": int(row[11]),
        "impact_scope_match": int(row[12]),
        "impact_min_generation": int(row[13]),
        "impact_max_generation": int(row[14]),
        "impact_distinct_generations": int(row[15]),
        "impact_extra_succeeded": int(row[16]),
        "mapped_total": int(row[17]),
        "mapped_succeeded": int(row[18]),
        "mapped_missing": int(row[19]),
        "mapped_distinct_events": int(row[20]),
        "mapped_scope_match": int(row[21]),
        "mapped_contract_match": int(row[22]),
        "aggregate_delta_pending": int(row[23]),
        "aggregate_unmapped_succeeded": int(row[24]),
        "grant_chain_gaps": int(row[25]),
        "grant_target_duplicates": int(row[26]),
        "tip_plan_delta_match": int(row[27]) == 1,
    }
    sample["terminal"] = _published_frontier_is_terminal(sample)
    return sample


def _ruleset_auxiliary_sample(rs, card_id, since_id):
    tenant = int(A["tenant"])
    aggregate = int(rs)
    card = int(card_id)
    watermark = int(since_id)
    rows = sql(
        "SELECT "
        "(SELECT COUNT(*) FROM authorization_projection_outbox o "
        "WHERE o.tenant_id=%d AND o.aggregate_type='RULE_SET' "
        "AND o.aggregate_id=%d), "
        "(SELECT COALESCE(SUM(o.status='PROCESSED'),0) "
        "FROM authorization_projection_outbox o WHERE o.tenant_id=%d "
        "AND o.aggregate_type='RULE_SET' AND o.aggregate_id=%d), "
        "(SELECT COALESCE(MAX(o.source_generation),0) "
        "FROM authorization_projection_outbox o WHERE o.tenant_id=%d "
        "AND o.aggregate_type='RULE_SET' AND o.aggregate_id=%d), "
        "(SELECT COUNT(*) FROM authorization_impact_plan i "
        "WHERE i.tenant_id=%d AND i.aggregate_type='RULE_SET' "
        "AND i.aggregate_id=%d AND i.status<>'SUCCEEDED'), "
        "(SELECT COUNT(*) FROM authorization_archive_outbox a "
        "WHERE a.tenant_id=%d AND a.aggregate_type='RULE_SET' "
        "AND a.aggregate_id=%d AND a.status<>'SUCCEEDED'), "
        "(SELECT COUNT(*) FROM authorization_delta_event d "
        "WHERE d.tenant_id=%d AND (d.card_id=%d OR d.card_id IS NULL) "
        "AND d.delta_event_id>%d AND d.aggregate_type='RULE_SET' "
        "AND d.aggregate_id=%d), "
        "(SELECT COALESCE(SUM(d.status='SUCCEEDED'),0) "
        "FROM authorization_delta_event d WHERE d.tenant_id=%d "
        "AND (d.card_id=%d OR d.card_id IS NULL) AND d.delta_event_id>%d "
        "AND d.aggregate_type='RULE_SET' AND d.aggregate_id=%d), "
        "(SELECT COALESCE(SUM(d.status<>'SUCCEEDED'),0) "
        "FROM authorization_delta_event d WHERE d.tenant_id=%d "
        "AND (d.card_id=%d OR d.card_id IS NULL) AND d.delta_event_id>%d "
        "AND d.aggregate_type='RULE_SET' AND d.aggregate_id=%d), "
        "(SELECT COALESCE(MAX(d.attempts),0) FROM authorization_delta_event d "
        "WHERE d.tenant_id=%d AND (d.card_id=%d OR d.card_id IS NULL) "
        "AND d.delta_event_id>%d AND d.aggregate_type='RULE_SET' "
        "AND d.aggregate_id=%d), "
        "(SELECT COALESCE(MAX(d.delta_event_id),0) "
        "FROM authorization_delta_event d WHERE d.tenant_id=%d "
        "AND (d.card_id=%d OR d.card_id IS NULL) AND d.delta_event_id>%d "
        "AND d.aggregate_type='RULE_SET' AND d.aggregate_id=%d)" % (
            tenant, aggregate, tenant, aggregate, tenant, aggregate,
            tenant, aggregate, tenant, aggregate,
            tenant, card, watermark, aggregate,
            tenant, card, watermark, aggregate,
            tenant, card, watermark, aggregate,
            tenant, card, watermark, aggregate,
            tenant, card, watermark, aggregate))
    row = rows[0]
    return {
        "outbox_total": int(row[0]),
        "outbox_processed": int(row[1]),
        "outbox_generation": int(row[2]),
        "impact_pending": int(row[3]),
        "archive_pending": int(row[4]),
        "delta": {
            "total": int(row[5]),
            "succeeded": int(row[6]),
            "pending": int(row[7]),
            "max_attempts": int(row[8]),
            "max_delta_event_id": int(row[9]),
        },
    }


def _ruleset_durable_sample(rs, card_id, since_id, require_delta=True):
    auxiliary = _ruleset_auxiliary_sample(rs, card_id, since_id)
    total = auxiliary["outbox_total"]
    processed = auxiliary["outbox_processed"]
    outbox_generation = auxiliary["outbox_generation"]
    delta = auxiliary["delta"]
    frontier = _published_frontier_sample(rs)
    head_source_generation = frontier.get("head_source_generation", 0)
    sample = {
        "outbox_total": total,
        "outbox_processed": processed,
        "outbox_pending": max(total - processed, 0),
        "outbox_generation": outbox_generation,
        "head_source_generation": head_source_generation,
        "source_generation_matches_outbox": bool(
            (total == 0 and head_source_generation == 0)
            or (total > 0 and head_source_generation == outbox_generation)),
        "impact_pending": auxiliary["impact_pending"],
        "archive_pending": auxiliary["archive_pending"],
        "delta": delta,
        "frontier": frontier,
        "pointer_generation": frontier.get("pointer_generation"),
        "pointer_status": frontier.get("pointer_status"),
    }
    sample["terminal"] = bool(
        total == processed
        and sample["source_generation_matches_outbox"]
        and sample["impact_pending"] == 0
        and sample["archive_pending"] == 0
        and delta["pending"] == 0
        and (not require_delta or delta["total"] > 0)
        and frontier.get("terminal") is True)
    return sample


def _wait_ruleset_drain(rs, card_id, since_id, timeout_s=120,
                        forbid_allow=False, require_api_ready=False,
                        require_delta=True):
    """Observe durable drain and the decision safety window under one deadline."""
    started = time.perf_counter()
    deadline = started + timeout_s
    last = {"terminal": False}
    last_decision = None
    last_api = None
    decision_samples = 0
    durable_samples = 0
    api_samples = 0
    next_durable = started
    next_api = started
    while time.perf_counter() < deadline:
        now = time.perf_counter()
        if forbid_allow:
            last_decision = _decision_snapshot(timeout=2)
            decision_samples += 1
            if _snapshot_has_allow(last_decision):
                return {
                    "ok": False,
                    "unsafe_allow": True,
                    "since_id": int(since_id),
                    "decision_samples": decision_samples,
                    "durable_samples": durable_samples,
                    "api_samples": api_samples,
                    "last_decision": last_decision,
                    "last_api": last_api,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    **last,
                }
        if now >= next_durable:
            last = _ruleset_durable_sample(
                rs, card_id, since_id, require_delta=require_delta)
            durable_samples += 1
            next_durable = now + CLEANUP_DURABLE_POLL_S
        if require_api_ready and now >= next_api:
            try:
                last_api = {"ok": True, "state": _binding_probe(card_id)}
            except CleanupReconciliationError as exc:
                last_api = {"ok": False, "error": str(exc)[:180]}
            api_samples += 1
            next_api = now + CLEANUP_DURABLE_POLL_S
        api_ok = not require_api_ready or bool(last_api and last_api.get("ok"))
        if last.get("terminal") and api_ok:
            if forbid_allow:
                final_decision = _decision_snapshot(timeout=2)
                decision_samples += 1
                last_decision = final_decision
                if _snapshot_has_allow(final_decision):
                    return {
                        "ok": False,
                        "unsafe_allow": True,
                        "since_id": int(since_id),
                        "decision_samples": decision_samples,
                        "durable_samples": durable_samples,
                        "api_samples": api_samples,
                        "last_decision": last_decision,
                        "last_api": last_api,
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                        **last,
                    }
            return {
                "ok": True,
                "unsafe_allow": False,
                "since_id": int(since_id),
                "decision_samples": decision_samples,
                "durable_samples": durable_samples,
                "api_samples": api_samples,
                "last_decision": last_decision,
                "last_api": last_api,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                **last,
            }
        sleep_s = (CLEANUP_DECISION_SAMPLE_S if forbid_allow
                   else min(CLEANUP_DURABLE_POLL_S, 1.0))
        time.sleep(min(sleep_s, max(0.0, deadline - time.perf_counter())))
    return {
        "ok": False,
        "unsafe_allow": False,
        "since_id": int(since_id),
        "decision_samples": decision_samples,
        "durable_samples": durable_samples,
        "api_samples": api_samples,
        "last_decision": last_decision,
        "last_api": last_api,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        **last,
    }


def _wait_p2_convergence(rs, card_id, since_id, want, t_commit,
                         timeout_s=P2_DECISION_TIMEOUT_S,
                         hold_s=P2_STABILITY_HOLD_S):
    started = time.perf_counter()
    deadline = started + timeout_s
    first_seen = {node: None for node in NAMES}
    resets = {node: 0 for node in NAMES}
    last_state = {}
    last_durable = {"terminal": False}
    decision_samples = 0
    durable_samples = 0
    next_durable = started
    stable_since = None
    while time.perf_counter() < deadline:
        all_match = True
        for node in NAMES:
            decision = sim(node, *MONITOR_ARGS)
            observed_at = time.perf_counter()
            last_state[node] = {key: decision.get(key)
                                for key in ("allowed", "http", "reason")}
            decision_samples += 1
            if _decision_matches(decision, want):
                if first_seen[node] is None:
                    first_seen[node] = (observed_at - t_commit) * 1000
            else:
                all_match = False
                if first_seen[node] is not None:
                    resets[node] += 1
                    first_seen[node] = None
        now = time.perf_counter()
        if now >= next_durable:
            last_durable = _ruleset_durable_sample(rs, card_id, since_id)
            durable_samples += 1
            next_durable = now + 0.25
        fully_observed = all_match and all(value is not None for value in first_seen.values())
        if fully_observed and last_durable.get("terminal"):
            if stable_since is None:
                stable_since = time.perf_counter()
            if time.perf_counter() - stable_since >= hold_s:
                converge_ms = max(first_seen.values())
                return {
                    "ok": True,
                    "first_seen_ms": {key: round(value, 1)
                                      for key, value in first_seen.items()},
                    "converge_ms": round(converge_ms, 1),
                    "decision_converged": True,
                    "durable_terminal": True,
                    "stability_hold_ms": round(hold_s * 1000, 1),
                    "verification_ms": round((time.perf_counter() - t_commit) * 1000, 1),
                    "decision_samples": decision_samples,
                    "durable_samples": durable_samples,
                    "state_resets": resets,
                    "last_state": last_state,
                    "durable": last_durable,
                }
        else:
            stable_since = None
        time.sleep(0.015)
    return {
        "ok": False,
        "error": "decision_or_durable_state_not_stable_within_%ss" % timeout_s,
        "first_seen_ms": {key: (round(value, 1) if value is not None else None)
                          for key, value in first_seen.items()},
        "converge_ms": None,
        "decision_converged": False,
        "durable_terminal": bool(last_durable.get("terminal")),
        "stability_hold_ms": 0,
        "verification_ms": round((time.perf_counter() - t_commit) * 1000, 1),
        "decision_samples": decision_samples,
        "durable_samples": durable_samples,
        "state_resets": resets,
        "last_state": last_state,
        "durable": last_durable,
    }


def _decision_snapshot(timeout=10):
    probes = {"learn_subject": SIM_ARGS, "monitor": MONITOR_ARGS}
    jobs = [(label, node, probe_args)
            for label, probe_args in probes.items() for node in NAMES]
    snapshot = {label: {} for label in probes}

    def evaluate(job):
        label, node, probe_args = job
        value = sim(node, *probe_args, timeout=timeout)
        return label, node, {key: value.get(key)
                             for key in ("allowed", "http", "reason")}

    with futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        for label, node, value in pool.map(evaluate, jobs):
            snapshot[label][node] = value
    return snapshot


def _snapshot_has_allow(snapshot):
    return any(value.get("allowed") is True
               for resources in snapshot.values() for value in resources.values())


def _snapshot_is_exact_deny(snapshot):
    return all(_decision_matches(value, False)
               for resources in snapshot.values() for value in resources.values())


class _DecisionSafetyMonitor:
    """Periodically sample both protected resources until cleanup is terminal."""

    def __init__(self, interval_s=CLEANUP_DECISION_SAMPLE_S):
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._armed = threading.Event()
        self._closed = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._samples = 0
        self._armed_samples = 0
        self._started = None
        self._armed_at = None
        self._finished = None
        self._last_sample_at = None
        self._max_gap_ms = 0.0
        self._last = None
        self._closed_at = None
        self._closed_sample = None
        self._unsafe = None
        self._error = None
        self._result = None

    def _run(self):
        try:
            while not self._stop.is_set():
                sample_started = time.perf_counter()
                snapshot = _decision_snapshot(timeout=2)
                sample_finished = time.perf_counter()
                with self._lock:
                    armed_sample = (self._armed_at is not None
                                    and sample_started >= self._armed_at)
                    self._last = snapshot
                    self._samples += 1
                    if armed_sample:
                        if self._last_sample_at is None:
                            self._max_gap_ms = max(
                                self._max_gap_ms,
                                (sample_finished - self._armed_at) * 1000)
                        else:
                            self._max_gap_ms = max(
                                self._max_gap_ms,
                                (sample_finished - self._last_sample_at) * 1000)
                        self._last_sample_at = sample_finished
                        self._armed_samples += 1
                    has_allow = _snapshot_has_allow(snapshot)
                    if armed_sample and not self._closed.is_set() and not has_allow:
                        self._closed_at = sample_finished
                        self._closed_sample = self._samples
                        self._closed.set()
                    elif (armed_sample and self._closed.is_set()
                          and self._unsafe is None and has_allow):
                        self._unsafe = {
                            "sample": self._samples,
                            "elapsed_ms": round((sample_finished - self._started) * 1000, 2),
                            "state": snapshot,
                        }
                remaining = self.interval_s - (time.perf_counter() - sample_started)
                if remaining > 0:
                    self._stop.wait(remaining)
        except Exception as exc:
            with self._lock:
                self._error = "%s:%s" % (type(exc).__name__, str(exc)[:160])
            self._stop.set()

    def start(self):
        self._started = time.perf_counter()
        self._thread = threading.Thread(
            target=self._run, name="s15-perf-cleanup-safety", daemon=True)
        self._thread.start()
        return self

    def arm(self):
        with self._lock:
            self._armed_at = time.perf_counter()
            self._last_sample_at = None
            self._max_gap_ms = 0.0
        self._armed.set()
        return self

    def stop(self):
        if self._result is not None:
            return self._result
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=15)
        self._finished = time.perf_counter()
        with self._lock:
            if self._last_sample_at is not None:
                self._max_gap_ms = max(
                    self._max_gap_ms,
                    (self._finished - self._last_sample_at) * 1000)
            self._result = {
                "ok": self._armed.is_set() and self._closed.is_set()
                      and self._unsafe is None
                      and self._error is None and self._armed_samples > 0
                      and self._max_gap_ms <= CLEANUP_MAX_DECISION_GAP_S * 1000
                      and not (self._thread and self._thread.is_alive()),
                "armed": self._armed.is_set(),
                "armed_samples": self._armed_samples,
                "safe_direction_closed": self._closed.is_set(),
                "safe_direction_closed_sample": self._closed_sample,
                "safe_direction_closed_ms": (
                    round((self._closed_at - self._started) * 1000, 2)
                    if self._closed_at is not None else None),
                "unsafe_allow": self._unsafe,
                "error": self._error,
                "samples": self._samples,
                "max_gap_ms": round(self._max_gap_ms, 2),
                "last_state": self._last,
                "thread_stopped": not (self._thread and self._thread.is_alive()),
                "elapsed_ms": round((self._finished - self._started) * 1000, 2),
            }
            return self._result

    def wait_until_closed(self, timeout_s=CLEANUP_DECISION_TIMEOUT_S):
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self._closed.wait(min(0.1, max(0.0, deadline - time.perf_counter()))):
                self.assert_safe()
                return True
            self.assert_safe()
        return False

    def assert_safe(self):
        with self._lock:
            unsafe = self._unsafe
            error = self._error
        if error is not None:
            raise CleanupReconciliationError("cleanup_safety_monitor_error:%s" % error)
        if unsafe is not None:
            raise CleanupReconciliationError("cleanup_unsafe_allow_observed")


def _wait_no_allow(card_id, timeout_s=CLEANUP_DECISION_TIMEOUT_S):
    """The safety window accepts PENDING, but never an unsafe ALLOW."""
    started = time.perf_counter()
    deadline = time.time() + timeout_s
    last = {}
    while time.time() < deadline:
        last = _decision_snapshot()
        if not _snapshot_has_allow(last):
            return {"ok": True,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    "state": last}
        time.sleep(0.3)
    return {"ok": False, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "state": last}


def _unbind_once(rs_id, operation_id):
    path = "/main/api/v1/rule-sets/card/%s/unbind/%s" % (A["card"], int(rs_id))
    try:
        response = _session().delete(
            NODES["node-b"] + path,
            headers=sign_headers("DELETE", path, request_id=operation_id), timeout=15)
        return response, None
    except Exception as exc:
        return None, type(exc).__name__


def _retryable_unbind_status(response):
    status = getattr(response, "status_code", None) if response is not None else None
    text = str(getattr(response, "text", "") or "") if response is not None else ""
    pending = status == 403 and "AUTHORIZATION_PENDING" in text
    return pending or status in (408, 409, 425, 429) or (status is not None and status >= 500)


def _wait_binding_api_ready(card_id, timeout_s=PREFLIGHT_NODE_TIMEOUT_S):
    started = time.perf_counter()
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            state = _binding_probe(card_id)
            return {"ok": True,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    "state": state}
        except CleanupReconciliationError as exc:
            last = str(exc)[:180]
        time.sleep(1)
    return {"ok": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": last}


def cleanup_bindings():
    """Unbind one source binding at a time and prove the final DENY state.

    During a revoke fan-out the management API can legitimately return
    AUTHORIZATION_PENDING. Source state is the immediate commit oracle. Once
    the last binding's unsafe ALLOW direction closes, an independent periodic
    sampler remains active through durable drain, API/source reconciliation, and
    exact available-DENY verification; its observed maximum sample gap is saved.
    """
    started = time.perf_counter()
    evidence = {"started_at": time.time(), "attempts": [], "passes": 0,
                "initial": None, "final": None, "ok": False}
    safety_monitor = None
    try:
        initial = _binding_probe(A["card"])
        evidence["initial"] = initial
        remaining = list(initial["source_ids"])
        for pass_no in range(1, CLEANUP_MAX_PASSES + 1):
            evidence["passes"] = pass_no
            if not remaining:
                break
            for rs_id in list(remaining):
                since_id = _card_delta_watermark(A["card"])
                operation_id = "s15-perf-cleanup-%s-%s" % (A["card"], rs_id)
                committed = False
                for attempt in range(1, CLEANUP_MAX_BINDING_ATTEMPTS + 1):
                    monitor_candidate = None
                    before_ids = _binding_source_ids(A["card"])
                    if before_ids == [rs_id]:
                        monitor_candidate = _DecisionSafetyMonitor().start()
                    response, error = _unbind_once(rs_id, operation_id)
                    status = getattr(response, "status_code", None) if response is not None else None
                    text = str(getattr(response, "text", "") or "")
                    try:
                        source_ids = _binding_source_ids(A["card"])
                    except Exception as exc:
                        monitor_evidence = monitor_candidate.stop() if monitor_candidate else None
                        evidence["attempts"].append({"rs": rs_id, "attempt": attempt,
                                                     "http": status, "error": error,
                                                     "source_error": type(exc).__name__,
                                                     "precommit_monitor": monitor_evidence})
                        raise CleanupReconciliationError("unbind_source_reconcile_failed", evidence)
                    pending_403 = status == 403 and "AUTHORIZATION_PENDING" in text
                    item = {"rs": rs_id, "attempt": attempt, "http": status,
                            "error": error, "pending_403": pending_403,
                            "source_still_bound": rs_id in source_ids}
                    evidence["attempts"].append(item)
                    if rs_id not in source_ids:
                        committed = True
                        if not source_ids:
                            safety_monitor = (monitor_candidate or
                                              _DecisionSafetyMonitor().start())
                            safety_monitor.arm()
                        elif monitor_candidate is not None:
                            item["precommit_monitor"] = monitor_candidate.stop()
                        break
                    if monitor_candidate is not None:
                        item["precommit_monitor"] = monitor_candidate.stop()
                    if error:
                        raise CleanupReconciliationError(
                            "unbind_outcome_unknown:rs=%s" % rs_id, evidence)
                    if not _retryable_unbind_status(response):
                        raise CleanupReconciliationError(
                            "unbind_nonretryable:rs=%s:http=%s" % (rs_id, status), evidence)
                    # No source mutation occurred. Drain older card work, wait for
                    # the management read gate to recover, then retry the same id.
                    drain = _wait_card_delta_drain(A["card"], since_id)
                    ready = _wait_binding_api_ready(A["card"])
                    item["drain"] = drain
                    item["api_ready"] = ready
                    if not drain["ok"] or not ready["ok"]:
                        raise CleanupReconciliationError(
                            "unbind_retry_precondition_timeout:rs=%s" % rs_id, evidence)
                if not committed:
                    raise CleanupReconciliationError(
                        "unbind_retry_budget_exhausted:rs=%s" % rs_id, evidence)

                # The source mutation is durable.  A no-ALLOW gate is meaningful
                # only after the last binding is gone; earlier bindings may
                # legitimately keep the same resource allowed.
                remaining_after_commit = _binding_source_ids(A["card"])
                item = evidence["attempts"][-1]
                item["remaining_after_commit"] = remaining_after_commit
                if not remaining_after_commit:
                    if safety_monitor is None:
                        safety_monitor = _DecisionSafetyMonitor().start().arm()
                    if not safety_monitor.wait_until_closed():
                        item["safety_monitor"] = safety_monitor.stop()
                        safety_monitor = None
                        raise CleanupReconciliationError(
                            "cleanup_stale_allow_timeout:rs=%s" % rs_id, evidence)
                    safety_monitor.assert_safe()
                else:
                    item["decision_sample"] = _decision_snapshot()
                drain = _wait_ruleset_drain(
                    rs_id, A["card"], since_id,
                    timeout_s=CLEANUP_DRAIN_TIMEOUT_S,
                    forbid_allow=not remaining_after_commit,
                    require_api_ready=True)
                item["drain"] = drain
                if safety_monitor is not None:
                    safety_monitor.assert_safe()
                if not drain["ok"]:
                    raise CleanupReconciliationError(
                        "cleanup_drain_or_api_timeout:rs=%s" % rs_id, evidence)
                remaining = list(drain["last_api"]["state"]["source_ids"])
            remaining = _binding_source_ids(A["card"])
        if remaining:
            raise CleanupReconciliationError("cleanup_pass_budget_exhausted", evidence)
        final_ready = _wait_binding_api_ready(A["card"])
        evidence["final"] = final_ready
        if safety_monitor is not None:
            safety_monitor.assert_safe()
        if not final_ready["ok"] or final_ready["state"]["count"] != 0:
            raise CleanupReconciliationError("binding_verify_nonempty", evidence)
        deny = _exact_deny(A["card"])
        evidence["final_deny"] = deny
        if safety_monitor is not None:
            safety_monitor.assert_safe()
        if not deny["ok"]:
            raise CleanupReconciliationError("binding_cleanup_final_deny_timeout", evidence)
        if safety_monitor is not None:
            evidence["safety_monitor"] = safety_monitor.stop()
            safety_monitor = None
            if not evidence["safety_monitor"]["ok"]:
                raise CleanupReconciliationError("cleanup_safety_monitor_failed", evidence)
        evidence["ok"] = True
        evidence["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return evidence
    except CleanupReconciliationError as exc:
        if safety_monitor is not None:
            evidence["safety_monitor"] = safety_monitor.stop()
            safety_monitor = None
        evidence["error"] = str(exc)[:240]
        evidence["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        exc.evidence = evidence
        raise
    except Exception as exc:
        if safety_monitor is not None:
            evidence["safety_monitor"] = safety_monitor.stop()
            safety_monitor = None
        evidence["error"] = "%s:%s" % (type(exc).__name__, str(exc)[:200])
        evidence["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        raise CleanupReconciliationError("cleanup_unexpected_error", evidence) from exc


def _management_probe(node):
    path = "/main/api/v1/rule-sets?page=1&size=1"
    try:
        response = _session().get(NODES[node] + path,
                                  headers=sign_headers("GET", path), timeout=5)
        return {"http": response.status_code}
    except Exception as exc:
        return {"http": 0, "error": type(exc).__name__}


def _preflight_node(node):
    started = time.perf_counter()
    last = None
    deadline = time.time() + PREFLIGHT_NODE_TIMEOUT_S
    while time.time() < deadline:
        management = _management_probe(node)
        decision = sim(node, *SIM_ARGS)
        last = {"management": management,
                "decision": {k: decision.get(k) for k in ("http", "allowed", "reason")}}
        # A decision endpoint returning 403/PENDING is live and fail-closed,
        # but it is not a usable performance baseline.
        if management.get("http") == 200 and _decision_is_available(decision):
            return {"node": node, "ok": True,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    "last": last}
        time.sleep(1)
    return {"node": node, "ok": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "last": last}


def _exact_deny(card_id, timeout_s=CLEANUP_DECISION_TIMEOUT_S):
    started = time.perf_counter()
    deadline = time.time() + timeout_s
    last = {}
    while time.time() < deadline:
        last = _decision_snapshot()
        if _snapshot_is_exact_deny(last):
            return {"ok": True,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    "state": last}
        time.sleep(0.3)
    return {"ok": False, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "state": last}


def _teardown_perf_rulesets(rs_list):
    if not rs_list:
        return {"ok": True, "rulesets": []}
    out = {"ok": True, "rulesets": []}
    try:
        state = _binding_probe(A["card"])
        targets_present = [int(rs) for rs in rs_list if int(rs) in state["source_ids"]]
        if not targets_present:
            out["rulesets"] = [{"rs": int(rs), "already_absent": True} for rs in rs_list]
        else:
            cleanup = cleanup_bindings()
            out["rulesets"] = [{"rs": int(rs), "cleanup_owned": int(rs) in targets_present}
                               for rs in rs_list]
            out["cleanup"] = cleanup
            out["ok"] = cleanup.get("ok") is True
    except Exception as exc:
        out["ok"] = False
        out["error"] = "%s:%s" % (type(exc).__name__, str(exc)[:180])
        partial = getattr(exc, "evidence", None)
        if partial is not None:
            out["cleanup"] = partial
    try:
        final = _binding_probe(A["card"])
        out["final_binding_count"] = final["count"]
        out["ok"] = out["ok"] and final["count"] == 0
    except Exception as exc:
        out["ok"] = False
        out["final_error"] = "%s:%s" % (type(exc).__name__, str(exc)[:180])
    return out


def performance_verdict(summary):
    p1 = summary.get("P1_read_baseline") or {}
    p2 = summary.get("P2_propagation") or {}
    p3 = summary.get("P3_storm") or {}
    p4 = summary.get("P4_read_scaling") or {}
    drain = summary.get("pre_P4_drain") or {}
    integ = p3.get("integrity") or {}
    p2_summary = p2.get("summary") or {}
    p2_rounds = [entry for kind in ("grant", "revoke")
                 for entry in ((p2.get("rounds") or {}).get(kind) or [])]
    p2_requested = p2.get("rounds_requested", 0)
    p2_rounds_ok = bool(
        p2_requested >= 2 and p2_requested % 2 == 0
        and p2.get("rounds_done") == p2_requested
        and len(p2_rounds) == p2_requested
        and all(entry.get("decision_converged") is True
                and entry.get("durable_terminal") is True
                and entry.get("stability_hold_ms", 0) >= P2_STABILITY_HOLD_S * 1000
                and entry.get("converge_ms") is not None
                for entry in p2_rounds))
    unconverged = sum((p2_summary.get(kind) or {}).get("unconverged", 0)
                      for kind in ("grant", "revoke"))
    p1_errors = sum((p1.get(node, {}).get("sequential") or {}).get("errors", 0)
                    + (p1.get(node, {}).get("concurrent_1t") or {}).get("errors", 0)
                    + (p1.get(node, {}).get("concurrent_8t") or {}).get("errors", 0)
                    for node in NAMES)
    p1_condition_ok = all(
        block.get("decision_resource") == SIM_ARGS[1]
        and block.get("expected_allowed") is False
        for node in NAMES
        for block in (
            p1.get(node, {}).get("sequential") or {},
            p1.get(node, {}).get("concurrent_1t") or {},
            p1.get(node, {}).get("concurrent_8t") or {},
        ))
    p4_condition_ok = bool(
        p4.get("decision_resource") == SIM_ARGS[1]
        and p4.get("expected_allowed") is False
        and (p4.get("single_node_baseline") or {}).get("decision_resource") == SIM_ARGS[1]
        and (p4.get("single_node_baseline") or {}).get("expected_allowed") is False)
    p4_errors = p4.get("errors", 0)
    integrity_ok = bool(
        integ.get("all_processed") and integ.get("terminal_once")
        and integ.get("source_generation_matches_outbox")
        and integ.get("source_generations_contiguous")
        and integ.get("frontier_terminal")
        and not integ.get("drain_timed_out"))
    reasons = [reason for reason, bad in [
        ("P3_integrity", not integrity_ok),
        ("P3_zero_ops", p3.get("ops", 0) <= 0),
        ("P3_non_pending_errors", p3.get("non_pending_errors", 0) != 0),
        ("P2_incomplete_or_unconverged_%d" % unconverged,
         not p2.get("complete") or unconverged > 0 or not p2_rounds_ok),
        ("pre_P4_drain_incomplete", drain.get("drained") is not True),
        ("P1_errors_%d" % p1_errors, p1_errors != 0),
        ("P1_decision_condition", not p1_condition_ok),
        ("P4_errors_%d" % p4_errors, p4_errors != 0),
        ("P4_decision_condition", not p4_condition_ok),
        ("teardown_incomplete", (summary.get("teardown") or {}).get("ok") is not True),
    ] if bad]
    return not reasons, reasons


def _write_terminal_artifact(path, verdict, reasons, phase, **extra):
    prov = provenance() if CFG else {"run_id": None, "source_snapshot": "unavailable"}
    SUMMARY.update({"verdict": verdict, "fail_reasons": list(reasons),
                    "terminal_phase": phase, "provenance": prov})
    SUMMARY.update(extra)
    atomic_json(path, SUMMARY)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="perf_result.json")
    ap.add_argument("--p2-rounds", type=int, default=30)
    ap.add_argument("--p3-seconds", type=int, default=20)
    args = ap.parse_args()

    SUMMARY.clear()
    SUMMARY["started_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    SUMMARY["config_path"] = _CONFIG_PATH

    if (args.p2_rounds < 2 or args.p2_rounds % 2 != 0
            or args.p3_seconds <= 0):
        _write_terminal_artifact(
            args.out, "BLOCKED", ["invalid_measurement_budget"], "arguments",
            p2_rounds=args.p2_rounds, p3_seconds=args.p3_seconds)
        print("preflight BLOCKED: p2-rounds must be positive/even and >=2; "
              "p3-seconds must be positive (rc=2)", flush=True)
        return 2

    # Configuration and HMAC are pre-gate conditions.  Keep import-time parsing
    # failures observable as BLOCKED artifacts rather than uncaught tracebacks.
    if (_CONFIG_ERROR or not CFG or not isinstance(NODES, dict)
            or any(node not in NODES for node in NAMES) or not DB or not MC
            or not CFG.get("mysql_root")):
        _write_terminal_artifact(
            args.out, "BLOCKED", ["run_config_unavailable"], "config",
            config_error=_CONFIG_ERROR or "required_fields_missing")
        print("preflight BLOCKED: run_config unavailable (rc=2)", flush=True)
        return 2

    load_hmac_secret()
    if _HMAC_SECRET is None:
        _write_terminal_artifact(args.out, "BLOCKED", ["hmac_secret_unavailable"],
                                 "hmac", error=_HMAC_SECRET_ERROR)
        print("preflight BLOCKED: %s (rc=2)" % _HMAC_SECRET_ERROR, flush=True)
        return 2

    print("== preflight: 3-node decision readiness ==")
    node_evidence = [_preflight_node(node) for node in NAMES]
    SUMMARY["preflight_nodes"] = node_evidence
    for result in node_evidence:
        print("  %s %s" % (result["node"], "OK" if result["ok"] else "NOT_READY"),
              flush=True)
    bad_nodes = [item["node"] for item in node_evidence if not item["ok"]]
    if bad_nodes:
        _write_terminal_artifact(args.out, "BLOCKED", ["node_decision_not_ready"],
                                 "node_readiness", bad_nodes=bad_nodes)
        print("preflight BLOCKED: decision readiness failed for %s (rc=2)" % bad_nodes,
              flush=True)
        return 2

    print("== preflight: cleanup + source reconciliation ==")
    try:
        SUMMARY["preflight_cleanup"] = cleanup_bindings()
    except Exception as exc:
        evidence = getattr(exc, "evidence", None)
        if evidence is not None:
            SUMMARY["preflight_cleanup"] = evidence
        _write_terminal_artifact(
            args.out, "FAIL", ["preflight_cleanup_failed"], "cleanup",
            error="%s:%s" % (type(exc).__name__, str(exc)[:240]))
        print("preflight FAIL: cleanup reconciliation failed (rc=1)", flush=True)
        return 1
    if not SUMMARY["preflight_cleanup"].get("ok"):
        _write_terminal_artifact(args.out, "FAIL", ["preflight_cleanup_failed"], "cleanup")
        return 1
    SUMMARY["preflight_deny"] = SUMMARY["preflight_cleanup"].get("final_deny")
    if not (SUMMARY["preflight_deny"] or {}).get("ok"):
        _write_terminal_artifact(args.out, "FAIL", ["preflight_exact_deny_missing"],
                                 "deny_baseline")
        return 1
    atomic_json(args.out, SUMMARY)

    print("== P1 read baseline ==")
    p1 = {}
    for n in NAMES:
        p1[n] = {"sequential": p1_sequential(n),
                 "concurrent_1t": p1_concurrent(n, threads=1, seconds=10),
                 "concurrent_8t": p1_concurrent(n)}
        print("  %s seq_p50=%.2fms 1t_qps=%.1f 8t_qps=%.1f" % (
            n, p1[n]["sequential"]["p50_ms"],
            p1[n]["concurrent_1t"]["qps"], p1[n]["concurrent_8t"]["qps"]))
    SUMMARY["P1_read_baseline"] = p1
    SUMMARY["provenance"] = provenance()
    atomic_json(args.out, SUMMARY)   # phase checkpoint（原子）

    print("== P2 propagation convergence (epsilon) ==")
    rs_prop, eid_prop = make_perf_rs("prop", with_grant=True)
    # 等初始 ALLOW 在三节点可见（新管线收敛后再开始测量）；30s 未收敛 →
    # 直接 FAIL（L3：不产出在未就绪基线上测得的无效传播分布）。
    converged = False
    deadline = time.time() + 30
    while time.time() < deadline:
        if all(_decision_matches(sim(n, *MONITOR_ARGS), True) for n in NAMES):
            converged = True
            break
        time.sleep(0.5)
    if not converged:
        SUMMARY["P2_propagation"] = {
            "complete": False, "error": "initial ALLOW not converged within 30s"}
        SUMMARY["teardown"] = _teardown_perf_rulesets([rs_prop])
        _write_terminal_artifact(args.out, "FAIL", ["P2_initial_allow_timeout"],
                                 "P2_initial_allow")
        print("P2 preflight FAIL: initial ALLOW not converged in 30s (rc=1)",
              flush=True)
        return 1
    SUMMARY["P2_propagation"] = p2_propagation(
        rs_prop, eid_prop, rounds=args.p2_rounds,
        checkpoint=lambda snapshot: (
            SUMMARY.__setitem__("P2_propagation", snapshot),
            SUMMARY.__setitem__("provenance", provenance()),
            atomic_json(args.out, SUMMARY)))
    print("  grant p50=%sms p95=%sms | revoke p50=%sms p95=%sms" % (
        SUMMARY["P2_propagation"]["summary"]["grant"]["p50_ms"],
        SUMMARY["P2_propagation"]["summary"]["grant"]["p95_ms"],
        SUMMARY["P2_propagation"]["summary"]["revoke"]["p50_ms"],
        SUMMARY["P2_propagation"]["summary"]["revoke"]["p95_ms"]))
    atomic_json(args.out, SUMMARY)
    if not SUMMARY["P2_propagation"].get("complete"):
        SUMMARY["teardown"] = _teardown_perf_rulesets([rs_prop])
        _write_terminal_artifact(
            args.out, "FAIL", ["P2_incomplete"], "P2_propagation")
        print("P2 FAIL: incomplete propagation sequence (rc=1)", flush=True)
        return 1

    print("== P3 concurrent mutation storm ==")
    rs_storm, _ = make_perf_rs("storm", with_grant=True)
    SUMMARY["P3_storm"] = p3_storm(rs_storm, seconds=args.p3_seconds)
    print("  qps=%s ops=%s integrity=%s" % (
        SUMMARY["P3_storm"]["qps"], SUMMARY["P3_storm"]["ops"],
        {k: v for k, v in SUMMARY["P3_storm"]["integrity"].items() if k != "head"}))
    atomic_json(args.out, SUMMARY)

    print("== P3.5 bounded drain before P4 ==")
    SUMMARY["pre_P4_drain"] = bounded_drain(
        [rs_prop, rs_storm], int(A["card"]), timeout_s=CLEANUP_DRAIN_TIMEOUT_S)
    atomic_json(args.out, SUMMARY)

    print("== P4 read scaling (1 thread per node) ==")
    SUMMARY["P4_read_scaling"] = p4_read_scaling()
    print("  aggregate_qps=%s" % SUMMARY["P4_read_scaling"]["qps_aggregate"])

    single = max(p1[n]["concurrent_1t"]["qps"] for n in NAMES)
    SUMMARY["P4_read_scaling"]["single_node_1t_qps_max"] = single
    SUMMARY["P4_read_scaling"]["single_node_baseline"] = {
        "decision_resource": SIM_ARGS[1], "expected_allowed": False,
        "selection": "max_node_concurrent_1t", "qps": single,
    }
    SUMMARY["P4_read_scaling"]["scaling_ratio_vs_single_node_1t"] = round(
        SUMMARY["P4_read_scaling"]["qps_aggregate"] / single, 2) if single else None

    try:
        SUMMARY["teardown"] = _teardown_perf_rulesets([rs_prop, rs_storm])
    except Exception as exc:
        SUMMARY["teardown"] = {"ok": False, "error": "%s:%s" %
                                (type(exc).__name__, str(exc)[:180])}
    atomic_json(args.out, SUMMARY)

    ok, reasons = performance_verdict(SUMMARY)
    SUMMARY["verdict"] = "PASS" if ok else "FAIL"
    SUMMARY["fail_reasons"] = reasons
    SUMMARY["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_json(args.out, SUMMARY)
    print("written %s (verdict=%s fail_reasons=%s)" %
          (args.out, SUMMARY["verdict"], reasons))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:
        try:
            if CFG and ACTIVE_PERF_RULESETS:
                SUMMARY["teardown_after_exception"] = _teardown_perf_rulesets(
                    list(ACTIVE_PERF_RULESETS))
        except Exception as teardown_exc:
            SUMMARY["teardown_after_exception"] = {
                "ok": False, "error": "%s:%s" %
                (type(teardown_exc).__name__, str(teardown_exc)[:180])}
        try:
            out_path = "perf_result.json"
            for index, arg in enumerate(sys.argv):
                if arg == "--out" and index + 1 < len(sys.argv):
                    out_path = sys.argv[index + 1]
                elif arg.startswith("--out="):
                    out_path = arg.split("=", 1)[1]
            _write_terminal_artifact(
                out_path, "FAIL", ["unhandled_exception"], "exception",
                error="%s:%s" % (type(exc).__name__, str(exc)[:240]))
        except Exception:
            pass
        print("S15_PERF FAIL: unhandled %s (rc=1)" % type(exc).__name__, flush=True)
        sys.exit(1)
