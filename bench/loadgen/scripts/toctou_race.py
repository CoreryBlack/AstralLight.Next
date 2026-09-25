# -*- coding: utf-8 -*-
"""RQ5 TOCTOU 实验：撤销→决策传播窗口实证（模式 A 零越权窗口验证）。

协议（每周期）：
  1. POST  /main/api/v1/rule-sets/{RS}/entries   新增 ALLOW 条目
  2. 轮询 sim 端点确认 ALLOW 已生效
  3. R 个读线程以 keep-alive 连续轰击 sim 决策端点，记录 (t_send, t_recv, allowed)
  4. 主线程 DELETE 该条目，记录 t_ack（撤销 ACK 返回时刻）
  5. 读线程持续到周期结束
不变量判定（定义保持不变）：
  - hard_stale：t_send > t_ack 且 allowed=True 的样本——**硬违规，必须为 0**
  - in_flight：t_send ≤ t_ack < t_recv 的 ALLOW——撤销前已发出的合法请求（单独计量）
输出（2026-09-04 重测 harness 审计修复）：
  - first_non_allow_ms：t_ack 后首个**非 ALLOW 观测**（DENY / PENDING / HTTP 或
    解析错误的完成时刻）；first_deny_ms：t_ack 后首个**明确 DENY**。两者分开
    输出——错误样本是 unknown，不得冒充 DENY，也不得计入安全窗口。
  - 逐周期计数 total_samples / allow / default_deny / pending / network_errors /
    http_errors / parse_errors / in_flight / hard_stale / ready_probe_errors /
    hung_threads；ALLOW ready 探测错误与网络/解析错误一样纳入错误口径（不再
    静默 continue）；撤销后仍有 reader 线程未结束 → verdict=UNKNOWN（exit 4）。
  - verdict：PASS（stale=0、零错误、无线程挂起）/ PASS_WITH_ERRORS（stale=0
    但有错误样本，退出码 3）/ UNKNOWN（线程未结束，exit 4）/ FAIL（stale>0，
    退出码 1）。
  - provenance：runId / git rev / binary sha256 / source_snapshot_sha256 /
    host / 参数（--run-id、run_config.json 的 run_id/binary_sha256/
    source_snapshot_sha256、--binary 均可注入）。
  - 结果按周期原子落盘（tmp + os.replace），断流不丢已完成周期的证据；
    逐样本默认原子落盘到 run-scoped raw artifact（<out>.samples.json，随周期
    checkpoint；--no-sample-dump 关闭；--dump-samples 额外内嵌进主结果）。

fixture 参数化：--base | --run-config（rust-s15 run_config.json，含 nodes 与
hmac_secret_file）/ --hmac-secret-file / --gateway-yml（从 application.yml 提取
hmac_secret，兼容旧部署）/ --actor。模块导入期不再读取任何文件。

运行（node-b）：python3 toctou_race.py [--run-config run_config.json | --base URL]
    [--cycles 30] [--readers 12] [--phase 3.0] [--out toctou_result.json]
退出码：0=PASS，1=FAIL（hard_stale>0），2=fixture/preflight/清理失败（FIXTURE_ERROR），
3=PASS_WITH_ERRORS，4=UNKNOWN（线程未结束或写结果无法对账）。
fixture 自持（2026-09-04）：种子规则集（默认 9071，自带无关 anchor entry）+ 本进程
专属绑定；启动时验证未绑定才 bind，结束时 try/finally 解绑并只清理本进程创建的
entry；写操作携带稳定 x-request-id（uuid5(run_id:label)），PENDING 仅按 GET 对账
结果有限重试，不盲重放；预期 PENDING 单列计数，不进入错误预算。
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import uuid

import requests

DEFAULT_BASE = "http://127.0.0.1:9005"
DEFAULT_ACTOR = {"user_id": "9031", "icard": "9041", "card": "9061",
                 "domain": "9011", "tenant": "9001"}
PREFIX = "astral-gateway-v3"


# ---------- fixture 装配（全部参数化，导入期零副作用） ----------

class Fixture:
    """base / hmac secret / actor / 规则集 的解析结果。"""

    def __init__(self, base, secret, actor, rs, resource, sim_resource, run_id,
                 run_config_path, binary_sha, source_snapshot_sha256=None,
                 source_git_rev=None, source_dirty=None):
        self.base = base.rstrip("/")
        self.secret = secret
        self.actor = actor
        self.rs = rs
        self.resource = resource
        self.sim_resource = sim_resource
        self.run_id = run_id
        self.run_config_path = run_config_path
        self.binary_sha = binary_sha
        self.source_snapshot_sha256 = source_snapshot_sha256
        self.source_git_rev = source_git_rev
        self.source_dirty = source_dirty
        self.owned_entry_ids = set()


def load_run_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def pick_node_url(cfg, node):
    nodes = cfg.get("nodes") or {}
    if node in nodes:
        return nodes[node]
    if nodes:
        return next(iter(nodes.values()))
    raise SystemExit("run_config.json 无可用 nodes 条目")


def secret_from_yml(yml_path):
    text = open(yml_path, encoding="utf-8").read()
    m = re.search(r'hmac_secret: "([^"]+)"', text)
    if not m:
        raise SystemExit("无法从 %s 提取 hmac_secret" % yml_path)
    return m.group(1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_fixture(args):
    cfg = load_run_config(args.run_config) if args.run_config else None
    if args.base:
        base = args.base
    elif cfg:
        base = pick_node_url(cfg, args.node)
    else:
        base = os.environ.get("TOCTOU_BASE", DEFAULT_BASE)

    if args.hmac_secret_file:
        secret = open(os.path.expanduser(args.hmac_secret_file), encoding="utf-8").read().strip()
    elif cfg and cfg.get("hmac_secret_file"):
        secret = open(os.path.expanduser(cfg["hmac_secret_file"]), encoding="utf-8").read().strip()
    elif args.gateway_yml:
        secret = secret_from_yml(os.path.expanduser(args.gateway_yml))
    elif os.environ.get("TOCTOU_HMAC_FILE"):
        secret = open(os.path.expanduser(os.environ["TOCTOU_HMAC_FILE"]), encoding="utf-8").read().strip()
    else:
        raise SystemExit("缺少 hmac fixture：用 --run-config / --hmac-secret-file / "
                         "--gateway-yml / TOCTOU_HMAC_FILE 之一提供（不再硬编码路径）")

    actor = dict(DEFAULT_ACTOR)
    if args.actor:
        actor.update(json.loads(args.actor))

    run_id = (args.run_id or os.environ.get("RUN_ID")
              or (cfg.get("run_id") if cfg else None) or "toctou-%d" % int(time.time()))
    binary_sha = args.binary_sha256
    if not binary_sha and args.binary:
        binary_sha = sha256_file(os.path.expanduser(args.binary))
    if not binary_sha and cfg:
        binary_sha = cfg.get("binary_sha256")
    source_snapshot = (cfg.get("source_snapshot_sha256") if cfg else None) \
        or args.source_snapshot_sha256
    source_git_rev = cfg.get("source_git_rev") if cfg else None
    source_dirty = cfg.get("source_dirty") if cfg else None
    return Fixture(base, secret, actor, args.rule_set, args.resource,
                   args.resource + ":42", run_id, args.run_config, binary_sha,
                   source_snapshot, source_git_rev, source_dirty)


# ---------- provenance ----------

def git_info(start_dir):
    """从 start_dir 向上找 .git，返回 {rev, dirty}（找不到则 None，不硬失败）。"""
    d = os.path.abspath(start_dir)
    while True:
        if os.path.isdir(os.path.join(d, ".git")):
            try:
                rev = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                                     capture_output=True, text=True, timeout=10)
                dirty = subprocess.run(["git", "-C", d, "status", "--porcelain"],
                                       capture_output=True, text=True, timeout=10)
                if rev.returncode == 0:
                    return {"rev": rev.stdout.strip(),
                            "dirty": bool(dirty.stdout.strip())}
            except Exception:
                pass
            return None
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def provenance(fx, args):
    return {
        "run_id": fx.run_id,
        "git": git_info(os.path.dirname(os.path.abspath(__file__))),
        "binary_sha256": fx.binary_sha,
        "source_snapshot_sha256": fx.source_snapshot_sha256,
        "source_git_rev": fx.source_git_rev,
        "source_dirty": fx.source_dirty,
        "binary_source": args.binary,
        "host": socket.gethostname(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "base": fx.base,
        "run_config": fx.run_config_path,
        "hmac_source": ("run_config" if args.run_config and not args.hmac_secret_file
                        else ("file:" + args.hmac_secret_file if args.hmac_secret_file
                              else ("yml:" + args.gateway_yml if args.gateway_yml else "env"))),
        "args": {k: v for k, v in vars(args).items()
                 if k not in ("hmac_secret_file", "gateway_yml", "actor")},
    }


# ---------- 签名与请求 ----------

def sign(fx, method, path, ts):
    a = fx.actor
    payload = "\n".join([PREFIX, method, path, a["user_id"], "PLATFORM_USER", "",
                         a["icard"], a["card"], a["domain"], a["tenant"],
                         "", "", "", "", ts])
    return hmac.new(fx.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def headers(fx, method, path, request_id=None):
    ts = str(int(time.time() * 1000))
    return {"Content-Type": "application/json", "x-request-id": request_id or str(uuid.uuid4()),
            "x-user-id": fx.actor["user_id"], "x-principal-kind": "PLATFORM_USER",
            "x-identity-card-id": fx.actor["icard"], "x-user-card-id": fx.actor["card"],
            "x-user-card-domain-id": fx.actor["domain"], "x-user-card-tenant-id": fx.actor["tenant"],
            "x-gateway-auth": "verified", "x-gateway-ts": ts,
            "x-gateway-signature": sign(fx, method, path, ts)}


def stable_request_id(fx, label):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "%s:toctou:%s" % (fx.run_id, label)))


def call(fx, method, path, body=None, timeout=30, request_id=None):
    return requests.request(method, fx.base + path,
                            headers=headers(fx, method, path, request_id),
                            json=body, timeout=timeout)


class FixtureError(RuntimeError):
    """Precondition or cleanup failure; the race result is not admissible."""


class FixtureUnknown(RuntimeError):
    """A write outcome could not be reconciled without unsafe replay."""


def response_data(resp):
    try:
        payload = resp.json()
        return payload.get("data") if isinstance(payload, dict) else None
    except Exception:
        return None


def is_pending_response(resp):
    return (resp is not None and resp.status_code == 403
            and "AUTHORIZATION_PENDING" in (resp.text or ""))


def is_retriable_write(resp):
    """Outcomes that may have committed server-side: reconcile via GET, bounded retry."""
    return is_pending_response(resp) or (resp is not None and resp.status_code in (503, 504))


def is_definitive_rejection(resp):
    return (resp is not None and 400 <= resp.status_code < 500
            and resp.status_code not in (404, 408, 429)
            and not is_pending_response(resp))


def list_entries(fx):
    path = "/main/api/v1/rule-sets/%d/entries" % fx.rs
    try:
        resp = call(fx, "GET", path, timeout=15)
    except Exception as exc:
        raise FixtureUnknown("entry reconciliation request failed: %s" % type(exc).__name__)
    if resp.status_code != 200:
        raise FixtureUnknown("entry reconciliation returned HTTP_%d" % resp.status_code)
    data = response_data(resp) or []
    return data if isinstance(data, list) else (data.get("items") or [])


def matching_entries(fx):
    matches = []
    for item in list_entries(fx):
        resource = item.get("resource") or item.get("resourceType")
        action = item.get("action") or item.get("actionCode")
        effect = str(item.get("effect") or "").upper()
        if resource == fx.resource and action == "read" and effect == "ALLOW":
            matches.append(item)
    return matches


def binding_present(fx):
    card_id = int(fx.actor["card"])
    path = "/main/api/v1/rule-sets/card/%d/bindings" % card_id
    try:
        resp = call(fx, "GET", path, timeout=15)
    except Exception as exc:
        raise FixtureUnknown("binding reconciliation request failed: %s" % type(exc).__name__)
    if resp.status_code != 200:
        raise FixtureUnknown("binding reconciliation returned HTTP_%d" % resp.status_code)
    data = response_data(resp) or []
    items = data if isinstance(data, list) else (data.get("items") or [])
    return any(int(item.get("ruleSetId", -1)) == fx.rs for item in items)


def ensure_fixture_bound(fx):
    # The seeded set already has an unrelated anchor entry. Binding an empty set
    # cannot establish the projection dependency chain.
    path = "/main/api/v1/rule-sets/%d" % fx.rs
    try:
        resp = call(fx, "GET", path, timeout=15)
    except Exception as exc:
        raise FixtureError("seeded rule-set probe failed: %s" % type(exc).__name__)
    if resp.status_code != 200:
        raise FixtureError("seeded rule set unavailable: HTTP_%d" % resp.status_code)
    if not list_entries(fx):
        raise FixtureError("seeded rule set has no anchor entry")
    if matching_entries(fx):
        # A leftover entry from a prior failed run cannot be attributed to this
        # process; refuse instead of silently adopting or racing on it.
        raise FixtureError("pre-existing matching entries in seeded rule set")
    if binding_present(fx):
        raise FixtureError("TOCTOU rule set is already bound; prior ownership is unknown")

    card_id = int(fx.actor["card"])
    bind_path = "/main/api/v1/rule-sets/card/%d/bind" % card_id
    try:
        bind = call(fx, "POST", bind_path,
                    {"ruleSetId": fx.rs, "refType": "BASE"}, timeout=15,
                    request_id=stable_request_id(fx, "bind"))
    except Exception:
        if binding_present(fx):
            return True
        raise FixtureUnknown("bind outcome unknown and binding absent on reconciliation")
    if bind.status_code == 200:
        return True
    if is_retriable_write(bind):
        if binding_present(fx):
            return True
        raise FixtureUnknown("bind outcome unknown (HTTP_%d) and binding absent"
                             % bind.status_code)
    raise FixtureError("fixture bind failed: HTTP_%d" % bind.status_code)


def unbind_fixture(fx):
    if not binding_present(fx):
        return
    card_id = int(fx.actor["card"])
    path = "/main/api/v1/rule-sets/card/%d/unbind/%d" % (card_id, fx.rs)
    try:
        resp = call(fx, "DELETE", path, timeout=15,
                    request_id=stable_request_id(fx, "unbind"))
    except Exception:
        if not binding_present(fx):
            return
        raise FixtureUnknown("unbind outcome unknown and binding remains")
    if resp.status_code != 200 and binding_present(fx):
        raise FixtureError("fixture unbind failed: HTTP_%d" % resp.status_code)


def add_owned_entry(fx, retries=3):
    path = "/main/api/v1/rule-sets/%d/entries" % fx.rs
    body = {"effect": "ALLOW", "resource": fx.resource,
            "action": "read", "priority": 1}

    def adopt_single(items, stage):
        if len(items) == 1:
            return items[0].get("id") or items[0].get("entryId")
        raise FixtureUnknown("%s reconciliation found %d matching entries"
                             % (stage, len(items)))

    for attempt in range(retries):
        existing = matching_entries(fx)
        if existing:
            if attempt > 0 and len(existing) == 1:
                # A retried write may have materialized between reconciliation
                # and the loop head; adopt it instead of failing sticky. Startup
                # (ensure_fixture_bound) guarantees it originated from this run.
                return existing[0].get("id") or existing[0].get("entryId")
            if len(existing) == 1:
                raise FixtureError("owned entry already exists before add")
            raise FixtureUnknown("add pre-check found multiple matching entries")
        try:
            resp = call(fx, "POST", path, body, timeout=15,
                        request_id=stable_request_id(fx, "add"))
        except Exception as exc:
            return adopt_single(matching_entries(fx),
                                "add outcome unknown (%s)" % type(exc).__name__)
        data = response_data(resp) or {}
        entry_id = data.get("id") if isinstance(data, dict) else None
        if resp.status_code == 200 and entry_id:
            return entry_id
        if is_definitive_rejection(resp):
            raise FixtureError("add entry rejected: HTTP_%d" % resp.status_code)
        if is_retriable_write(resp) or resp.status_code != 200:
            # PENDING / 503 / 504 / other unexpected: outcome may have committed.
            after = matching_entries(fx)
            if after:
                return adopt_single(after, "pending add")
            if attempt + 1 < retries:
                time.sleep(0.05 * (attempt + 1))
                continue
        raise FixtureError("add entry failed: HTTP_%d" % resp.status_code)
    raise FixtureError("add entry retry budget exhausted")


def delete_owned_entry(fx, entry_id, retries=3):
    path = "/main/api/v1/rule-sets/%d/entries/%s" % (fx.rs, entry_id)
    for attempt in range(retries):
        try:
            resp = call(fx, "DELETE", path, timeout=15,
                        request_id=stable_request_id(fx, "delete:%s" % entry_id))
        except Exception as exc:
            remaining = matching_entries(fx)
            if not remaining:
                return
            if len(remaining) != 1:
                raise FixtureUnknown("delete reconciliation found %d matching entries"
                                     % len(remaining))
            raise FixtureUnknown("delete outcome unknown (%s): entry remains"
                                 % type(exc).__name__)
        if resp.status_code == 200:
            return
        if is_definitive_rejection(resp):
            remaining = matching_entries(fx)
            if not remaining:
                return
            raise FixtureError("revoke rejected: HTTP_%d" % resp.status_code)
        # PENDING / 503 / 504 / 404 / other: outcome may have committed — reconcile.
        remaining = matching_entries(fx)
        if not remaining:
            return
        if len(remaining) != 1:
            raise FixtureUnknown("delete reconciliation found %d matching entries"
                                 % len(remaining))
        if attempt + 1 < retries:
            time.sleep(0.05 * (attempt + 1))
            continue
        raise FixtureError("revoke retry budget exhausted: HTTP_%d" % resp.status_code)
    raise FixtureError("revoke retry budget exhausted")


def cleanup_fixture(fx):
    errors = []
    for entry_id in sorted(fx.owned_entry_ids):
        try:
            delete_owned_entry(fx, entry_id)
        except Exception as exc:
            errors.append("entry_%s:%s" % (entry_id, type(exc).__name__))
    fx.owned_entry_ids.clear()
    # Sweep: any matching entry still in the seeded set originated from this run
    # (startup guarantees a clean pre-state); remove it so the fixture self-heals.
    try:
        for item in matching_entries(fx):
            leftover = item.get("id") or item.get("entryId")
            if leftover is None:
                errors.append("sweep:matching-entry-without-id")
                continue
            try:
                delete_owned_entry(fx, leftover)
            except Exception as exc:
                errors.append("sweep_%s:%s" % (leftover, type(exc).__name__))
    except Exception as exc:
        errors.append("sweep:%s" % type(exc).__name__)
    try:
        unbind_fixture(fx)
    except Exception as exc:
        errors.append("unbind:%s" % type(exc).__name__)
    if errors:
        raise FixtureUnknown("fixture cleanup incomplete: %s" % ",".join(errors))


def sim_body(fx):
    a = fx.actor
    return {"cardId": int(a["card"]), "resource": fx.sim_resource, "action": "read",
            "userId": int(a["user_id"]), "domainId": int(a["domain"]),
            "tenantId": int(a["tenant"]), "proposedRules": []}


SIM_PATH = "/main/api/v1/simulation/evaluate"


def parse_decision(resp):
    """返回 True/False/None（None=结构不可解析，unknown 不得当 DENY）。"""
    try:
        cur = (resp.json().get("data") or {}).get("currentDecision") or {}
        allowed = cur.get("allowed")
        return allowed if isinstance(allowed, bool) else None
    except Exception:
        return None


def sim_once(fx, session=None):
    """单次决策采样。返回 (t0, t1, allowed, kind)，kind ∈
    decision/pending/http_error/network_error/parse_error。"""
    s = session or requests
    t0 = time.monotonic()
    try:
        resp = s.post(fx.base + SIM_PATH, headers=headers(fx, "POST", SIM_PATH),
                      json=sim_body(fx), timeout=10)
    except Exception as e:
        return t0, time.monotonic(), None, ("network_error", repr(e)[:80])
    t1 = time.monotonic()
    if resp.status_code == 503 or is_pending_response(resp):
        return t0, t1, None, ("pending", "PENDING")
    if resp.status_code != 200:
        return t0, t1, None, ("http_error", "HTTP_%d" % resp.status_code)
    allowed = parse_decision(resp)
    if allowed is None:
        return t0, t1, None, ("parse_error", "unparseable body")
    return t0, t1, allowed, ("decision", "")


# ---------- 原子落盘 ----------

def atomic_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------- 主流程 ----------

def wait_decision_ready(fx, want, timeout_s=10):
    """Wait for an explicit decision; expected PENDING probes are counted separately."""
    deadline = time.monotonic() + timeout_s
    errors = []
    pending_probes = 0
    while time.monotonic() < deadline:
        _, _, allowed, (kind, detail) = sim_once(fx)
        if allowed is want:
            return True, errors, pending_probes
        if kind == "pending":
            pending_probes += 1
        elif kind != "decision":
            errors.append({"kind": kind, "detail": detail})
        time.sleep(0.02)
    return False, errors, pending_probes


def wait_allow_ready(fx, timeout_s=10):
    return wait_decision_ready(fx, True, timeout_s)


def run_cycle(fx, cycle, readers, phase, sessions):
    entry_id = add_owned_entry(fx)
    if not entry_id:
        raise FixtureUnknown("add reconciliation returned no entry id")
    fx.owned_entry_ids.add(str(entry_id))

    errors = {"network": 0, "http": 0, "parse": 0, "pending": 0}
    ok, ready_errors, ready_pending = wait_allow_ready(fx)
    errors["pending"] += ready_pending
    for error in ready_errors:
        if error["kind"] == "network_error":
            errors["network"] += 1
        elif error["kind"] == "http_error":
            errors["http"] += 1
        elif error["kind"] == "parse_error":
            errors["parse"] += 1
    ready_probe_errors = len(ready_errors)
    if not ok:
        raise FixtureError("ALLOW did not converge (infra_errors=%d pending=%d)"
                           % (ready_probe_errors, ready_pending))

    stop = threading.Event()
    samples = []
    lock = threading.Lock()

    def reader(sess):
        while not stop.is_set():
            t0, t1, allowed, (kind, detail) = sim_once(fx, sess)
            with lock:
                if kind == "network_error":
                    errors["network"] += 1
                elif kind == "http_error":
                    errors["http"] += 1
                elif kind == "pending":
                    errors["pending"] += 1
                elif kind == "parse_error":
                    errors["parse"] += 1
                samples.append((t0, t1, allowed, kind,
                                detail if kind != "decision" else ""))

    threads = [threading.Thread(target=reader, args=(s,), daemon=True) for s in sessions]
    for thread in threads:
        thread.start()
    try:
        time.sleep(phase / 2)
        delete_owned_entry(fx, entry_id)
        fx.owned_entry_ids.discard(str(entry_id))
        t_ack = time.monotonic()
        time.sleep(phase / 2)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=15)
    hung_threads = sum(1 for thread in threads if thread.is_alive())

    # 分类（在锁外基于快照统计；t_send > t_ack 且 allowed=True 仍为 hard_stale 唯一定义）
    with lock:
        snap = list(samples)
    total = len(snap)
    allow = sum(1 for s in snap if s[2] is True)
    default_deny = sum(1 for s in snap if s[2] is False)
    unknown = total - allow - default_deny
    in_flight = sum(1 for (t0, t1, a, _k, _d) in snap if a is True and t0 <= t_ack < t1)
    hard_stale = sum(1 for (t0, t1, a, _k, _d) in snap if a is True and t0 > t_ack)
    post_ack = [(t1, a) for (t0, t1, a, _k, _d) in snap if t0 > t_ack]
    first_non_allow = min((t1 for (t1, a) in post_ack if a is not True), default=None)
    first_deny = min((t1 for (t1, a) in post_ack if a is False), default=None)
    fnon_ms = (first_non_allow - t_ack) * 1000 if first_non_allow is not None else None
    fdny_ms = (first_deny - t_ack) * 1000 if first_deny is not None else None
    stale_samples = [{"t_send_ms_after_ack": round((t0 - t_ack) * 1000, 3),
                      "t_recv": t1} for (t0, t1, a, _k, _d) in snap
                     if a is True and t0 > t_ack]
    row = {
        "cycle": cycle,
        "total_samples": total,
        "allow": allow,
        "default_deny": default_deny,
        "unknown_samples": unknown,
        "pending": errors["pending"],
        "network_errors": errors["network"],
        "http_errors": errors["http"],
        "parse_errors": errors["parse"],
        "ready_probe_errors": ready_probe_errors,
        "hung_threads": hung_threads,
        "in_flight": in_flight,
        "hard_stale": hard_stale,
        "first_non_allow_ms": round(fnon_ms, 3) if fnon_ms is not None else None,
        "first_deny_ms": round(fdny_ms, 3) if fdny_ms is not None else None,
        "window_ms": round(fdny_ms, 3) if fdny_ms is not None else None,  # 旧字段别名=first_deny
    }
    if stale_samples:
        row["hard_stale_samples"] = stale_samples[:10]
    # 逐样本默认 dump 到 run-scoped raw artifact（main 剥离到 <out>.samples.json）；
    # --dump-samples 额外内嵌进主结果。
    row["samples"] = [{"t_send": t0, "t_recv": t1, "allowed": a, "kind": k}
                      for (t0, t1, a, k, _d) in snap]
    err_examples = [{"kind": k, "detail": d} for (_t0, _t1, _a, k, d) in snap if d][:5]
    if err_examples:
        row["error_samples"] = err_examples
    return row


def write_fixture_failure(path, prov, error, code):
    atomic_json(path, {"complete": True, "verdict": "FIXTURE_ERROR" if code == 2 else "UNKNOWN",
                       "exit_code": code, "error_type": type(error).__name__,
                       "error": str(error)[:240], "provenance": prov, "results": []})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=None, help="目标 trustgraph 基址（默认 TOCTOU_BASE 或 %s）" % DEFAULT_BASE)
    ap.add_argument("--run-config", default=None,
                    help="rust-s15 run_config.json（提供 base 节点与 hmac_secret_file）")
    ap.add_argument("--node", default="node-b", help="run_config 中使用的节点（默认 node-b）")
    ap.add_argument("--hmac-secret-file", default=None, help="hmac secret 文件（优先于 run_config）")
    ap.add_argument("--gateway-yml", default=None, help="application.yml 路径（从中提取 hmac_secret，兼容旧部署）")
    ap.add_argument("--actor", default=None, help="JSON 覆盖默认 actor（9031/9041/9061/9011/9001）")
    ap.add_argument("--rule-set", type=int, default=9071, help="夹具规则集 id（默认 9071）")
    ap.add_argument("--resource", default="user_profile", help="夹具资源类型")
    ap.add_argument("--cycles", type=int, default=30)
    ap.add_argument("--readers", type=int, default=12)
    ap.add_argument("--phase", type=float, default=3.0, help="每周期读压测时长（一半在撤销前/一半在后）")
    ap.add_argument("--out", default="toctou_result.json")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--binary", default=None, help="被测二进制路径（计算 sha256 入 provenance）")
    ap.add_argument("--binary-sha256", default=None, help="直接提供二进制 sha256")
    ap.add_argument("--source-snapshot-sha256", default=None,
                    help="源码快照身份（默认取 run_config.json 的 source_snapshot_sha256）")
    ap.add_argument("--dump-samples", action="store_true",
                    help="额外把逐样本内嵌进主结果（默认仅写 run-scoped raw artifact）")
    ap.add_argument("--no-sample-dump", action="store_true",
                    help="关闭逐样本 raw artifact 落盘（默认开启：dump 到 <out>.samples.json）")
    args = ap.parse_args()

    fx = build_fixture(args)
    prov = provenance(fx, args)

    # 逐样本 run-scoped raw artifact（默认开启）：主结果保持逐周期聚合，
    # 原始 (t_send, t_recv, allowed, kind) 全量进 <out>.samples.json。
    raw_path = None
    if not args.no_sample_dump:
        raw_path = re.sub(r"\.json$", "", args.out) + ".samples.json"
        if raw_path == args.out:
            raw_path = args.out + ".samples.json"

    sessions = [requests.Session() for _ in range(args.readers)]
    results = []
    samples_log = []
    total_errors = 0
    print("provenance: run_id=%s git=%s binary_sha=%s source_snapshot=%s base=%s"
          % (prov["run_id"], (prov["git"] or {}).get("rev", "unknown"),
             prov["binary_sha256"] or "unknown",
             (fx.source_snapshot_sha256 or "unknown")[:16], fx.base), flush=True)

    def write_raw(complete):
        if raw_path:
            atomic_json(raw_path, {"complete": complete, "provenance": prov,
                                   "cycles_done": len(results), "cycles": samples_log})

    # 自持 fixture：验证种子规则集与 anchor entry 后建立本 run 专属绑定；
    # 结果只在绑定由本进程建立时才可采纳（先前所有权未知即拒绝）。
    pre_failure = None
    try:
        ensure_fixture_bound(fx)
    except FixtureError as exc:
        pre_failure = ("FIXTURE_ERROR", 2, str(exc))
    except FixtureUnknown as exc:
        pre_failure = ("UNKNOWN", 4, str(exc))
    if pre_failure is not None:
        verdict, code, detail = pre_failure
        write_fixture_failure(args.out, prov, RuntimeError(detail), code)
        write_raw(True)
        print("\n=== TOCTOU %s (exit=%d) === %s" % (verdict, code, detail), flush=True)
        sys.exit(code)

    failure = None
    cleanup_error = None
    try:
        for cycle in range(args.cycles):
            try:
                row = run_cycle(fx, cycle, args.readers, args.phase, sessions)
            except FixtureError as exc:
                failure = ("FIXTURE_ERROR", 2, str(exc))
                break
            except FixtureUnknown as exc:
                failure = ("UNKNOWN", 4, str(exc))
                break
            except Exception as exc:  # 未预期缺陷：fail-closed，不留半完成 PASS
                failure = ("FIXTURE_ERROR", 2, "%s: %s" % (type(exc).__name__, exc))
                break
            # 逐样本剥离到 raw artifact（--dump-samples 时保留内嵌副本）
            samples_log.append({"cycle": row["cycle"], "samples": row.get("samples", [])})
            if not args.dump_samples:
                row.pop("samples", None)
            results.append(row)
            total_errors += (row["network_errors"] + row["http_errors"]
                             + row["parse_errors"] + row["ready_probe_errors"])
            print("[cycle %02d] samples=%d allow=%d deny=%d unknown=%d(net=%d http=%d parse=%d "
                  "pend=%d ready_err=%d hung=%d) hard_stale=%d in_flight=%d "
                  "first_non_allow_ms=%s first_deny_ms=%s"
                  % (cycle, row["total_samples"], row["allow"], row["default_deny"],
                     row["unknown_samples"], row["network_errors"], row["http_errors"],
                     row["parse_errors"], row["pending"], row["ready_probe_errors"],
                     row["hung_threads"], row["hard_stale"], row["in_flight"],
                     row["first_non_allow_ms"], row["first_deny_ms"]), flush=True)
            # 原子 checkpoint：每个周期后落盘完整中间状态（主结果 + 逐样本 raw）
            atomic_json(args.out, {"complete": False, "provenance": prov,
                                   "cycles_done": len(results), "results": results})
            write_raw(False)
    finally:
        try:
            cleanup_fixture(fx)
        except Exception as exc:
            cleanup_error = "%s: %s" % (type(exc).__name__, exc)

    if failure is None and cleanup_error is not None:
        # 全部周期已完成：竞态证据保留，但清理未闭合 → UNKNOWN，不冒充 PASS。
        failure = ("UNKNOWN", 4, "cleanup: %s" % cleanup_error)
    elif failure is not None and cleanup_error is not None:
        failure = (failure[0], failure[1],
                   "%s; cleanup: %s" % (failure[2], cleanup_error))
    if failure is not None:
        verdict, code, detail = failure
        atomic_json(args.out, {"complete": len(results) == args.cycles,
                               "verdict": verdict, "exit_code": code,
                               "error": detail[:240], "cycles_done": len(results),
                               "provenance": prov, "results": results})
        write_raw(True)
        print("\n=== TOCTOU %s (exit=%d) === %s" % (verdict, code, detail), flush=True)
        sys.exit(code)

    total_stale = sum(r["hard_stale"] for r in results)
    total_hung = sum(r["hung_threads"] for r in results)
    windows = [r["first_deny_ms"] for r in results if r["first_deny_ms"] is not None]
    non_allows = [r["first_non_allow_ms"] for r in results if r["first_non_allow_ms"] is not None]
    if total_stale > 0:
        verdict, code = "FAIL", 1
    elif total_hung > 0:
        # 撤销后 reader 线程未结束：周期口径可能不完整 → UNKNOWN（需对账），非零退出。
        verdict, code = "UNKNOWN", 4
    elif total_errors > 0:
        verdict, code = "PASS_WITH_ERRORS", 3
    else:
        verdict, code = "PASS", 0
    summary = {
        "complete": True,
        "verdict": verdict,
        "exit_code": code,
        "cycles": args.cycles,
        "readers": args.readers,
        "phase_s": args.phase,
        "total_hard_stale": total_stale,
        "total_samples": sum(r["total_samples"] for r in results),
        "total_network_errors": sum(r["network_errors"] for r in results),
        "total_http_errors": sum(r["http_errors"] for r in results),
        "total_parse_errors": sum(r["parse_errors"] for r in results),
        "total_pending": sum(r["pending"] for r in results),
        "total_ready_probe_errors": sum(r["ready_probe_errors"] for r in results),
        "total_hung_threads": total_hung,
        "total_default_deny": sum(r["default_deny"] for r in results),
        "total_in_flight": sum(r["in_flight"] for r in results),
        "first_non_allow_ms_mean": round(sum(non_allows) / len(non_allows), 3) if non_allows else None,
        "first_non_allow_ms_max": round(max(non_allows), 3) if non_allows else None,
        "first_deny_ms_mean": round(sum(windows) / len(windows), 3) if windows else None,
        "first_deny_ms_max": round(max(windows), 3) if windows else None,
        "samples_artifact": raw_path,
        "provenance": prov,
        "results": results,
    }
    atomic_json(args.out, summary)
    write_raw(True)
    print("\n=== TOCTOU %s (exit=%d) === hard_stale=%d hung=%d errors(net/http/parse/ready)=%d/%d/%d/%d "
          "first_non_allow mean/max=%s/%sms first_deny mean/max=%s/%sms samples=%s"
          % (verdict, code, total_stale, total_hung, summary["total_network_errors"],
             summary["total_http_errors"], summary["total_parse_errors"],
             summary["total_ready_probe_errors"],
             summary["first_non_allow_ms_mean"], summary["first_non_allow_ms_max"],
             summary["first_deny_ms_mean"], summary["first_deny_ms_max"],
             raw_path or "not-dumped"), flush=True)
    if verdict == "PASS_WITH_ERRORS":
        print("WARNING: 存在错误样本（unknown，不计入安全窗口也不冒充 DENY）；"
              "复测前先排除网络/负载噪声", flush=True)
    elif verdict == "UNKNOWN":
        print("WARNING: %d 个 reader 线程在停止信号后未结束——本 run 周期口径不完整，"
              "需对账后重测" % total_hung, flush=True)
    sys.exit(code)


if __name__ == "__main__":
    main()
