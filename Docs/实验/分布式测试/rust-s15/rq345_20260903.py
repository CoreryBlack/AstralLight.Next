#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基准 RQ3–5 三节点补测（2026-09-03，rust3n-dist-20260903，dev@6822d38b）。

按 Docs/实验/基准测试/scripts/README.md §3.1 框架（NativeBenchmark 语义）补齐
三节点口径缺口：
  RQ3 增量编译开销：3.1 正常增量 / 3.2 优胜者删除退化 / 3.3 高频写入（ADD-only
      顺序突发；add+del 交替的撤销重压形态另行定性，见报告）/
      3.4 SCAN-vs-HDEL（Rust 等效：keyed DEL + epoch，无 SCAN 路径——
      以写后失效窗口实测作证）
  RQ4.B 长时高频写入稳定性（60s 三线程 ADD-only 风暴 + 排水 + 完整性）
  RQ5  E4 缓存回填（warm/cold） / E11 旧令牌回放与上下文参数 /
       E3+E5 吞吐 QPS 可扩展性（并发阶梯 × 节点）

口径：api_ms = source mutation 请求返回耗时；publish_ms = 本批 delta 行
SUCCEEDED 的异步发布完成耗时（对 projector 增量编译 + 发布事务的真实三节点
口径）；decision_ms = 三节点决策翻转可见时间。全部经真实账本路径。

测量卡卫生（2026-09-03 实测教训）：RQ3.1/3.2 的规模夹具留在 A 卡（9061）上
会使卡证据膨胀、污染吞吐测量；RQ5 三相使用干净 B 卡（9062，bootstrap gen-1，
tenant 9002）。RQ3.3/RQ4.B 为 ADD-only——add+del 交替会让每次 delete 的撤权
类 delta 把卡作用域钉在 PENDING（v2 门禁 fail-closed 语义），后续写全部 403，
那是"撤销重压最坏情形"而非高频写入成本口径。

错误口径（H-3，2026-09-04）：RQ3.3/RQ4.B 中 403 且 body 含
AUTHORIZATION_PENDING（Rust 仲裁器 fail-closed 出口）是撤销/未决窗口内的
预期拒绝语义，单列 pending_403，如实保留、不要求为 0，不进
non_pending_errors；其余 HTTP 非 200 / 200 缺 eid / 网络异常计入
non_pending_errors（PASS 门禁要求为 0）。api_errors 为独立总数（不取
error_samples 长度——样本最多 3 条另存 error_samples）。

运行位置：node-b，run_config.json 经 RUN_CONFIG_PATH 定位（编排器传入；
手动运行回退 cwd/run_config.json）。
用法：python3 -u rq345_20260903.py --out <file>.json [--phase all|rq34|rq5]
"""

import argparse
import hashlib
import hmac
import json
import os
import statistics
import sys
import threading
import time

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import s15_coordinator as C  # noqa: E402

CARD = 9061
KEY_RES = "learn_subject"
KEY = "learn_subject:*"
NW_RES = "learn_level"          # 非优胜资源（不影响 KEY 决策）

# B 卡（干净测量卡）：seed_f4rust.sql 固定身份，bootstrap v2 已发布 gen-1 证据
# （permission_rule 类型级通配），tenant 9002 与 A 卡隔离。
ACTOR_B = {"user_id": "9032", "icard": "9042", "card": "9062",
           "domain": "9012", "tenant": "9002"}
B_CARD = 9062
B_KEY = "learn_subject:*"

RESULTS = {"rq3": {}, "rq4": {}, "rq5": {}}
HF_RS = {"rs": None, "winner_eid": None}
B_RS = {"rs": None, "winner_eid": None}


def dist(samples):
    if not samples:
        return {"n": 0}
    xs = sorted(samples)
    return {
        "n": len(xs),
        "p50_ms": round(xs[len(xs) // 2], 2),
        "p95_ms": round(xs[min(int(len(xs) * 0.95), len(xs) - 1)], 2),
        "max_ms": round(xs[-1], 2),
        "mean_ms": round(statistics.fmean(xs), 2),
    }


def is_pending_403(resp):
    """H-3：v2 门禁预期 fail-closed 形态——HTTP 403 且 body 含
    AUTHORIZATION_PENDING（Rust 仲裁器 fail-closed 出口）。撤销/未决窗口内
    这是正确拒绝语义：单列 pending_403，不计入 non_pending_errors，
    不要求为 0（如实保留）。"""
    try:
        return (resp is not None and getattr(resp, "status_code", None) == 403
                and "AUTHORIZATION_PENDING" in (getattr(resp, "text", "") or ""))
    except Exception:
        return False


def classify_write_result(resp, eid):
    """H-3 写路径结果分类：ok / pending_403（预期 fail-closed）/ non_pending。
    HTTP 200 但缺 eid（写未产生可追踪 delta）同样按 non_pending 计。"""
    if resp is not None and getattr(resp, "status_code", None) == 200 and eid is not None:
        return "ok"
    if is_pending_403(resp):
        return "pending_403"
    return "non_pending"


def error_sample_of(resp, eid):
    """单条错误样本（带 kind 分类）。样本与总数独立：总数用独立计数器累加，
    绝不取样本列表长度（L8）；样本最多保留 3 条，存 error_samples。"""
    if resp is None:
        return {"kind": "exception", "status": None, "body": "no response object"}
    status = getattr(resp, "status_code", None)
    body = str(getattr(resp, "text", ""))[:160]
    if status == 200 and eid is None:
        body = "http 200 without eid（写未产生可追踪 delta）"
    return {"kind": classify_write_result(resp, eid), "status": status, "body": body}


def checkpoint(path):
    """每阶段后原子落盘部分结果：长跑中断流/超时不丢已采集证据
    （phase 级 checkpoint；最终完整结果在 main 末尾原子覆写）。"""
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def max_delta_id(card=CARD):
    row = C.sql("SELECT COALESCE(MAX(delta_event_id),0) FROM authorization_delta_event "
                "WHERE card_id=%d" % card)
    return int(row[0][0])


def wait_drain(since_id, timeout_s=20, card=CARD):
    t0 = time.perf_counter()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        n = C.sql("SELECT COUNT(*) FROM authorization_delta_event WHERE card_id=%d "
                  "AND delta_event_id > %d AND status <> 'SUCCEEDED'" % (card, since_id))
        if int(n[0][0]) == 0:
            return (time.perf_counter() - t0) * 1000
        time.sleep(0.05)
    return None


def timed(fn, publish_timeout_s=20, card=CARD):
    since = max_delta_id(card)
    t0 = time.perf_counter()
    result = fn()
    api_ms = (time.perf_counter() - t0) * 1000
    publish_ms = wait_drain(since, publish_timeout_s, card)
    return result, round(api_ms, 2), (round(publish_ms, 2) if publish_ms is not None else None)


def sim_on(actor, node, card, resource, action):
    return C.sim(actor, node, card, resource, action, int(actor["user_id"]),
                 int(actor["domain"]), int(actor["tenant"]))


def sim3_on(actor, card, resource, action):
    return {n: sim_on(actor, n, card, resource, action) for n in C.NAMES}


def wait3_on(actor, card, resource, action, want, timeout_s=30):
    deadline = time.time() + timeout_s
    t0 = time.perf_counter()
    while time.time() < deadline:
        cur = sim3_on(actor, card, resource, action)
        if all(cur[n]["allowed"] is want for n in C.NAMES):
            return True, (time.perf_counter() - t0) * 1000
        time.sleep(0.3)
    return False, (time.perf_counter() - t0) * 1000


def entry_id_of(rs, resource):
    rows = C.sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d "
                 "AND resource_type='%s' ORDER BY entry_id DESC LIMIT 1" % (rs, resource))
    return int(rows[0][0]) if rows else None


def deltas_terminal_since(since_id, card=CARD):
    n = C.sql("SELECT COUNT(*) FROM authorization_delta_event WHERE card_id=%d "
              "AND delta_event_id > %d AND status <> 'SUCCEEDED'" % (card, since_id))
    return int(n[0][0]) == 0


# ──────────────────────────── RQ3.1 + RQ3.2（每规模一套夹具，A 卡） ────────────────────────────

def rq3_scale(scale):
    out = {"scale": scale}
    rs = C.fixture_plain("RQ3S%d" % scale)

    _, winner_api, winner_pub = timed(
        lambda: C.add_entry(rs, KEY_RES, "read", node="node-b"))
    out["winner_add"] = {"api_ms": winner_api, "publish_ms": winner_pub}
    r = C.bind_card(rs, CARD, layer="BASE", node="node-b")
    assert r.status_code == 200, "bind failed: %s" % r.text[:120]
    ok, _, _ = C.wait3(C.A, CARD, KEY, "read", int(C.A["user_id"]),
                       int(C.A["domain"]), int(C.A["tenant"]), True, timeout_s=45)
    assert ok, "winner bind not ALLOW"

    t0 = time.time()
    for _ in range(scale):
        C.add_entry(rs, NW_RES, "read", node="node-b")
    out["seed_wall_s"] = round(time.time() - t0, 2)
    ok, _, _ = C.wait3(C.A, CARD, KEY, "read", int(C.A["user_id"]),
                       int(C.A["domain"]), int(C.A["tenant"]), True, timeout_s=60)
    assert ok, "seeded set not ALLOW"

    api_s, pub_s = [], []
    pub_fail = 0
    for _ in range(20):
        _, api, pub = timed(lambda: C.add_entry(rs, NW_RES, "read", node="node-b"))
        api_s.append(api)
        if pub is None:
            pub_fail += 1
        else:
            pub_s.append(pub)
    out["incremental_add"] = {"api": dist(api_s), "publish": dist(pub_s),
                              "publish_timeout": pub_fail}

    nw_eid = entry_id_of(rs, NW_RES)
    assert nw_eid, "no non-winner entry"
    r, api, pub = timed(lambda: C.del_entry(rs, nw_eid, node="node-b"))
    assert r.status_code == 200, "non-winner delete failed"
    cur = C.sim3(C.A, CARD, KEY, "read", int(C.A["user_id"]),
                 int(C.A["domain"]), int(C.A["tenant"]))
    out["delete_non_winner"] = {"api_ms": api, "publish_ms": pub,
                                "decision_unchanged_allow":
                                    all(cur[n]["allowed"] is True for n in C.NAMES)}

    w_eid = entry_id_of(rs, KEY_RES)
    since = max_delta_id()
    t0 = time.perf_counter()
    r = C.del_entry(rs, w_eid, node="node-b")
    api_ms = (time.perf_counter() - t0) * 1000
    assert r.status_code == 200, "winner delete failed"
    ok, decision_ms, _ = C.wait3(C.A, CARD, KEY, "read", int(C.A["user_id"]),
                                 int(C.A["domain"]), int(C.A["tenant"]), False,
                                 timeout_s=30)
    out["delete_winner"] = {"api_ms": round(api_ms, 2), "decision_flip_ms": round(decision_ms, 2),
                            "decision_flipped_deny": ok}

    # 夹具保留绑定（不解绑——解绑的逐条目 REMOVE 扇出会触发同聚合发布指针
    # 竞争 → 败者 900s 退避停摆，见报告 RQ4 发现）。learn_level 授权对
    # learn_subject 决策零影响；KEY 决策已由优胜删除收敛 DENY。
    ok_deny, _, _ = C.wait3(C.A, CARD, KEY, "read", int(C.A["user_id"]),
                            int(C.A["domain"]), int(C.A["tenant"]), False,
                            timeout_s=60)
    out["post_winner_delete_deny_converged"] = ok_deny
    assert ok_deny, "winner deletion did not converge DENY"
    RESULTS["rq3"]["scale_%d" % scale] = out
    print("[RQ3] scale=%d incremental_add publish p50=%s  winner_delete api=%s flip=%sms"
          % (scale, out["incremental_add"]["publish"].get("p50_ms"),
             out["delete_winner"]["api_ms"], out["delete_winner"]["decision_flip_ms"]),
          flush=True)
    return rs


# ──────────────────────────── RQ3.3 高频写入（ADD-only）+ RQ4.B 长时风暴 ────────────────────────────

def hf_setup():
    rs = C.fixture_plain("RQ3HF")
    C.add_entry(rs, KEY_RES, "read", node="node-b")
    HF_RS["rs"] = rs
    r = C.bind_card(rs, CARD, layer="BASE", node="node-b")
    assert r.status_code == 200
    ok, _, _ = C.wait3(C.A, CARD, KEY, "read", int(C.A["user_id"]),
                       int(C.A["domain"]), int(C.A["tenant"]), True, timeout_s=45)
    assert ok, "HF fixture not ALLOW"


def rq3_high_freq(ops=60):
    """ADD-only 顺序突发：每 op 一次增量 add（API + 异步发布两段口径）。
    H-3：403 AUTHORIZATION_PENDING 为预期 fail-closed，单列 pending_403
    （不要求 0）；其余 HTTP/缺 eid 计 non_pending_errors（必须 0）。
    L8：api_errors 为独立总数，样本最多 3 条另存 error_samples。"""
    rs = HF_RS["rs"]
    since = max_delta_id()
    api_s, pub_s = [], []
    n_api_errors = 0      # L8：独立总数（含预期 pending_403），不取样本长度
    n_pending_403 = 0     # H-3：预期 fail-closed，如实保留
    n_non_pending = 0     # H-3：非预期错误，PASS 门禁要求 0
    samples = []
    pub_fail = 0
    for _ in range(ops):
        (rr, eid), api, pub = timed(lambda: C.add_entry(rs, NW_RES, "read", node="node-b"))
        if rr.status_code != 200 or eid is None:
            n_api_errors += 1
            kind = classify_write_result(rr, eid)
            if kind == "pending_403":
                n_pending_403 += 1
            else:
                n_non_pending += 1
            if len(samples) < 3:
                samples.append(error_sample_of(rr, eid))
            continue
        api_s.append(api)
        if pub is None:
            pub_fail += 1
        else:
            pub_s.append(pub)
    drain_ms = wait_drain(since, timeout_s=180)
    RESULTS["rq3"]["high_freq_write"] = {
        "ops_requested": ops, "ops_ok": len(api_s),
        "api_errors": n_api_errors,
        "pending_403": n_pending_403,
        "non_pending_errors": n_non_pending,
        "error_samples": samples,
        "add_api": dist(api_s), "publish": dist(pub_s),
        "publish_timeout": pub_fail,
        "burst_drain_ms": round(drain_ms, 2) if drain_ms is not None else None,
        "drain_complete": drain_ms is not None,
        "deltas_terminal": deltas_terminal_since(since),
        "note": "ADD-only 顺序突发（增量编译成本口径）；403 AUTHORIZATION_PENDING "
                "为 v2 门禁预期 fail-closed（单列 pending_403，不进错误口径）；"
                "add+del 交替的撤销重压形态由 v2 门禁语义另列（见报告）",
    }
    print("[RQ3] high_freq ok=%d api_err=%d (pending_403=%d non_pending=%d) "
          "add_api p50=%s publish p50=%s drain=%sms"
          % (len(api_s), n_api_errors, n_pending_403, n_non_pending,
             RESULTS["rq3"]["high_freq_write"]["add_api"].get("p50_ms"),
             RESULTS["rq3"]["high_freq_write"]["publish"].get("p50_ms"),
             RESULTS["rq3"]["high_freq_write"]["burst_drain_ms"]), flush=True)


def rq4_long_storm(seconds=60, threads=3):
    """RQ4.B 长时高频写入稳定性：ADD-only 三线程风暴（每线程跨节点轮转），
    排水窗口 960s（发布指针竞争败者的 900s 退避自愈纳入实测口径）。
    H-3：403 AUTHORIZATION_PENDING 单列 pending_403（预期 fail-closed，不要求
    0）；其余 HTTP/缺 eid/网络异常计入 non_pending_errors（PASS 门禁 0）。"""
    rs = HF_RS["rs"]
    since = max_delta_id()
    stop = time.time() + seconds
    lock = threading.Lock()
    stats = {"ops": 0, "pending_403": 0, "non_pending": 0, "samples": []}

    def worker(idx):
        local = 0
        local_pending = 0
        local_nonpending = 0
        node = ["node-a", "node-b", "node-c"][idx % 3]
        while time.time() < stop:
            try:
                r, eid = C.call(C.A, node, "POST",
                                "/main/api/v1/rule-sets/%d/entries" % rs,
                                {"resource": NW_RES, "action": "read", "effect": "ALLOW",
                                 "priority": 1})
                kind = classify_write_result(r, eid)
                if kind == "ok":
                    local += 1
                else:
                    if kind == "pending_403":
                        local_pending += 1
                    else:
                        local_nonpending += 1
                    with lock:
                        if len(stats["samples"]) < 3:
                            stats["samples"].append(error_sample_of(r, eid))
            except Exception as e:
                local_nonpending += 1
                with lock:
                    if len(stats["samples"]) < 3:
                        stats["samples"].append({"kind": "exception", "status": None,
                                                 "body": repr(e)[:160]})
        with lock:
            stats["ops"] += local
            stats["pending_403"] += local_pending
            stats["non_pending"] += local_nonpending

    ths = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    t0 = time.time()
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    wall = time.time() - t0

    drain_ms = wait_drain(since, timeout_s=960)
    parked = C.sql("SELECT COUNT(*) FROM authorization_delta_event WHERE card_id=%d "
                   "AND delta_event_id > %d AND status <> 'SUCCEEDED' AND attempts >= 5"
                   % (CARD, since))
    gens = [int(r[0]) for r in C.sql(
        "SELECT source_generation FROM authorization_projection_head "
        "WHERE aggregate_type='CARD' AND aggregate_id=%d" % CARD)]
    ob = C.outbox_summary(rs)
    RESULTS["rq4"]["long_storm_60s"] = {
        "seconds": seconds, "threads": threads, "wall_s": round(wall, 2),
        "ops": stats["ops"],
        "errors": stats["pending_403"] + stats["non_pending"],   # 独立总数（含预期 pending_403）
        "pending_403": stats["pending_403"],
        "non_pending_errors": stats["non_pending"],
        "error_samples": stats["samples"],
        "qps": round(stats["ops"] / wall, 2),
        "drain_ms": round(drain_ms, 2) if drain_ms is not None else None,
        "drain_complete": drain_ms is not None,
        "parked_at_budget_exhaustion_at_snapshot": int(parked[0][0]),
        "deltas_terminal": deltas_terminal_since(since),
        "outbox": {"contiguous": ob["contiguous"], "all_processed": ob["all_processed"],
                   "terminal_once": ob["terminal_once"], "rows": len(ob["gens"])},
        "card_head_generation": gens[0] if gens else None,
        "note": "ADD-only；403 AUTHORIZATION_PENDING 为 v2 门禁预期 fail-closed"
                "（单列 pending_403，不计入 non_pending_errors，不要求 0，"
                "撤销重压 add+del 形态的 100% 403 数据见报告叙述）；"
                "排水窗含同聚合指针竞争败者的 900s 退避自愈",
    }
    print("[RQ4] storm %ds ops=%d pending_403=%d non_pending=%d qps=%s drain_complete=%s"
          % (seconds, stats["ops"], stats["pending_403"], stats["non_pending"],
             RESULTS["rq4"]["long_storm_60s"]["qps"],
             RESULTS["rq4"]["long_storm_60s"]["drain_complete"]), flush=True)


# ──────────────────────────── RQ5（干净 B 卡 9062）：E4 / E11 / E3+E5 ────────────────────────────

def b_fixture():
    """tenant 9002 规则集（SQL 种子）+ B 签名 API 条目/绑定 → 等待三节点 ALLOW。"""
    import uuid
    code = "s15_rs_rq5b_%s" % uuid.uuid4().hex[:8]
    C.sql_exec("INSERT INTO rule_set (name, code, source_type, description, enabled, tenant_id) "
               "VALUES ('S15 rs rq5b', '%s', 'CUSTOM', 'rq5 clean measurement card', 1, %s)"
               % (code, ACTOR_B["tenant"]))
    rs = int(C.sql("SELECT rule_set_id FROM rule_set WHERE code='%s'" % code)[0][0])
    r, _ = C.call(ACTOR_B, "node-b", "POST", "/main/api/v1/rule-sets/%d/entries" % rs,
                  {"resource": KEY_RES, "action": "read", "effect": "ALLOW", "priority": 1})
    assert r.status_code == 200, "B entry failed: %s" % r.text[:160]
    r = C.call(ACTOR_B, "node-b", "POST", "/main/api/v1/rule-sets/card/%d/bind" % B_CARD,
               {"ruleSetId": rs, "refType": "BASE"})[0]
    assert r.status_code == 200, "B bind failed: %s" % r.text[:160]
    ok, _ = wait3_on(ACTOR_B, B_CARD, B_KEY, "read", True, timeout_s=45)
    assert ok, "B fixture not ALLOW"
    B_RS["rs"] = rs
    B_RS["winner_eid"] = entry_id_of(rs, KEY_RES)
    print("[RQ5] B fixture ready rs=%d" % rs, flush=True)


def rq5_e4_cache_repopulation(cycles=30):
    cold, warm = [], []
    for _ in range(cycles):
        # 经 s15_coordinator.redis() 访问：requirepass 部署时经 stdin 注入
        # REDISCLI_AUTH（密码不进 argv，不入结果）。FLUSHALL 失败即断言
        # （认证/可用性错误不静默继续）。
        out = C.redis("FLUSHALL")
        assert out == "OK", "FLUSHALL failed (redis auth/availability?): %r" % out[:80]
        t0 = time.perf_counter()
        cur = sim_on(ACTOR_B, "node-b", B_CARD, B_KEY, "read")
        cold.append((time.perf_counter() - t0) * 1000)
        assert cur["allowed"] is True, "post-flush decision must stay ALLOW: %s" % cur
        for _ in range(9):
            t0 = time.perf_counter()
            sim_on(ACTOR_B, "node-b", B_CARD, B_KEY, "read")
            warm.append((time.perf_counter() - t0) * 1000)
    RESULTS["rq5"]["E4_cache_repopulation"] = {
        "cycles": cycles, "cold": dist(cold), "warm": dist(warm),
        "card": "9062 (clean)",
        "note": "cold=FLUSHALL 后首决策（epoch/L2 全失配 → L3 源回填）；"
                "warm=L1/L2 命中；决策语义全程 ALLOW（缓存不可见翻转）",
    }
    print("[RQ5] E4 cold p50=%s warm p50=%s"
          % (RESULTS["rq5"]["E4_cache_repopulation"]["cold"].get("p50_ms"),
             RESULTS["rq5"]["E4_cache_repopulation"]["warm"].get("p50_ms")), flush=True)


def sign_ts(actor, method, path, ts_ms):
    sp = path.split("?")[0]
    payload = "\n".join([C.PREFIX, method.strip(), sp, actor["user_id"], "PLATFORM_USER",
                         "", actor["icard"], actor["card"], actor["domain"], actor["tenant"],
                         "", "", "", "", str(ts_ms)])
    sig = hmac.new(C.HMAC_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {"x-request-id": "rq345-e11-%s" % ts_ms, "x-user-id": actor["user_id"],
            "x-principal-kind": "PLATFORM_USER", "x-identity-card-id": actor["icard"],
            "x-user-card-id": actor["card"], "x-user-card-domain-id": actor["domain"],
            "x-user-card-tenant-id": actor["tenant"], "x-gateway-ts": str(ts_ms),
            "x-gateway-signature": sig, "x-gateway-auth": "verified",
            "Content-Type": "application/json"}


def rq5_e11_stale_token_replay():
    """E11 三臂（B 卡）：
    (a) 撤销前签名评估请求（ALLOW），撤销后原样重放 ×5——决策必须跟随当前投影；
    (b) 陈旧时间戳（ts=now-1h）签名管理 API——记录网关签名新鲜度行为；
    (c) 上下文参数依赖：以 A 卡 9061（tenant 9001）的 cardId 伪造 B 签名上下文
        ——跨租户必须全节点非 ALLOW。"""
    rs = B_RS["rs"]
    body = {"cardId": B_CARD, "resource": B_KEY, "action": "read",
            "userId": int(ACTOR_B["user_id"]), "domainId": int(ACTOR_B["domain"]),
            "tenantId": int(ACTOR_B["tenant"]), "proposedRules": []}
    path = "/main/api/v1/simulation/evaluate"
    url = C.NODES["node-b"] + path

    cur = sim3_on(ACTOR_B, B_CARD, B_KEY, "read")
    assert all(cur[n]["allowed"] is True for n in C.NAMES), "pre-revoke must be ALLOW"

    captured = C.sign_headers(ACTOR_B, "POST", path)
    r0 = requests.post(url, headers=captured, json=body, timeout=10)
    assert r0.status_code == 200 and r0.json().get("data", {}).get("currentDecision", {}).get(
        "allowed") is True, "captured request must be ALLOW pre-revoke"

    r = C.call(ACTOR_B, "node-b", "DELETE",
               "/main/api/v1/rule-sets/%d/entries/%s" % (rs, B_RS["winner_eid"]))[0]
    assert r.status_code == 200, "revoke delete failed"
    ok, _ = wait3_on(ACTOR_B, B_CARD, B_KEY, "read", False, timeout_s=30)
    assert ok, "post-revoke must converge DENY"

    anomalies = 0
    replay_status = []
    replay_allows = 0
    for _ in range(5):
        rr = requests.post(url, headers=captured, json=body, timeout=10)
        replay_status.append(rr.status_code)
        allowed = rr.status_code == 200 and rr.json().get("data", {}).get(
            "currentDecision", {}).get("allowed") is True
        if allowed:
            anomalies += 1
            replay_allows += 1

    stale_ts = int(time.time() * 1000) - 3600_000
    stale_path = "/main/api/v1/rule-sets?page=1&size=1"
    rs_req = requests.get(C.NODES["node-b"] + stale_path,
                          headers=sign_ts(ACTOR_B, "GET", stale_path, stale_ts), timeout=10)
    stale_rejected = rs_req.status_code in (401, 403)

    iso_status, iso_denied = [], 0
    iso_body = dict(body)
    iso_body["cardId"] = CARD          # A 卡（tenant 9001），B 签名上下文（tenant 9002）
    for node in C.NAMES:
        rr = requests.post(C.NODES[node] + path, headers=C.sign_headers(ACTOR_B, "POST", path),
                           json=iso_body, timeout=10)
        iso_status.append(rr.status_code)
        allowed = rr.status_code == 200 and rr.json().get("data", {}).get(
            "currentDecision", {}).get("allowed") is True
        if allowed:
            anomalies += 1
        else:
            iso_denied += 1

    total = 5 + len(C.NAMES)
    RESULTS["rq5"]["E11_stale_replay_context"] = {
        "captured_replay_status": replay_status,
        "captured_replay_allow_anomalies": replay_allows,
        "stale_timestamp_status": rs_req.status_code,
        "stale_timestamp_rejected": stale_rejected,
        "cross_card_status": iso_status,
        "cross_card_denied": iso_denied,
        "anomalies": anomalies,
        "total_evaluations": total,
        "anomaly_rate": round(anomalies / total, 6),
        "note": "(a) 撤销前签名请求撤销后原样重放——旧 ALLOW 不复活；"
                "(c) 跨租户上下文伪造全节点拒绝",
    }
    print("[RQ5] E11 anomalies=%d/%d stale_ts_status=%s cross_card_denied=%d/3"
          % (anomalies, total, rs_req.status_code, iso_denied), flush=True)
    # 恢复优胜（E3+E5 需要 steady ALLOW）
    C.call(ACTOR_B, "node-b", "POST", "/main/api/v1/rule-sets/%d/entries" % rs,
           {"resource": KEY_RES, "action": "read", "effect": "ALLOW", "priority": 1})
    wait3_on(ACTOR_B, B_CARD, B_KEY, "read", True, timeout_s=30)


def rq5_throughput():
    """E3+E5 吞吐 QPS 可扩展性（干净 B 卡）：并发阶梯 {1,2,4,8} × 10s × 2
    repeats（node-b），node-a/node-c 各 8 线程 1 repeat。"""
    path = "/main/api/v1/simulation/evaluate"
    body = {"cardId": B_CARD, "resource": B_KEY, "action": "read",
            "userId": int(ACTOR_B["user_id"]), "domainId": int(ACTOR_B["domain"]),
            "tenantId": int(ACTOR_B["tenant"]), "proposedRules": []}
    lock = threading.Lock()

    def run_point(node, threads, seconds):
        stop = time.time() + seconds
        lat = [[] for _ in range(threads)]
        errors = [0]

        def worker(i):
            s = requests.Session()
            hdrs = C.sign_headers(ACTOR_B, "POST", path)
            local = lat[i]
            while time.time() < stop:
                t0 = time.perf_counter()
                try:
                    rr = s.post(C.NODES[node] + path, headers=hdrs, json=body, timeout=10)
                    ms = (time.perf_counter() - t0) * 1000
                    if rr.status_code == 200:
                        local.append(ms)
                    else:
                        errors[0] += 1
                except Exception:
                    errors[0] += 1
        ths = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
        t0 = time.time()
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        wall = time.time() - t0
        flat = [ms for sub in lat for ms in sub]
        return {"node": node, "threads": threads, "seconds": round(wall, 2),
                "evals": len(flat), "errors": errors[0], "qps": round(len(flat) / wall, 2),
                "latency": dist(flat)}

    points = []
    repeats = 2
    for threads in (1, 2, 4, 8):
        runs = [run_point("node-b", threads, 10) for _ in range(repeats)]
        qps = [r["qps"] for r in runs]
        agg = dict(runs[-1])
        agg["qps_runs"] = qps
        agg["qps_mean"] = round(statistics.fmean(qps), 2)
        agg["qps_sd"] = round(statistics.pstdev(qps), 2) if len(qps) > 1 else 0.0
        points.append(agg)
        print("[RQ5] E3+E5 node-b threads=%d qps_mean=%s±%s lat_p50=%s"
              % (threads, agg["qps_mean"], agg["qps_sd"], agg["latency"].get("p50_ms")),
              flush=True)
    for node in ("node-a", "node-c"):
        p = run_point(node, 8, 10)
        points.append(p)
        print("[RQ5] E3+E5 %s threads=8 qps=%s" % (node, p["qps"]), flush=True)
    RESULTS["rq5"]["E3E5_throughput"] = {
        "points": points, "card": "9062 (clean)",
        "note": "sim 评估全链路（网关签名 + permission check + 严格证据读）；"
                "重复间的 QPS SD 为运行方差",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="rq345_20260903.json")
    ap.add_argument("--phase", default="all", choices=["all", "rq34", "rq5"])
    ap.add_argument("--skip-scales", action="store_true",
                    help="phase rq34: 跳过 3.1/3.2 规模夹具（数据已从日志抢救时用）")
    a = ap.parse_args()
    t0 = time.time()
    # provenance（零秘钥；run_config/provenance.json 为事实源）随首个 checkpoint
    # 一起落盘，中断的部分结果也带 run_id/binary_sha256/git_rev/快照身份。
    RESULTS["provenance"] = dict(C.provenance())

    if a.phase in ("all", "rq34"):
        print("pre-drain: waiting card 9061 deltas terminal ...", flush=True)
        pd_t0 = time.time()
        while time.time() - pd_t0 < 960:
            n = C.sql("SELECT COUNT(*) FROM authorization_delta_event WHERE card_id=%d "
                      "AND status <> 'SUCCEEDED'" % CARD)
            if int(n[0][0]) == 0:
                break
            time.sleep(20)
        print("pre-drain done (%.0fs)" % (time.time() - pd_t0), flush=True)

        if not a.skip_scales:
            print("== RQ3.1/3.2 incremental & winner deletion (scales 100/500) ==",
                  flush=True)
            for scale in (100, 500):
                rq3_scale(scale)
                checkpoint(a.out)
        else:
            print("== RQ3.1/3.2 skipped (--skip-scales) ==", flush=True)
        print("== RQ3.3 high-frequency write (ADD-only) ==", flush=True)
        hf_setup()
        rq3_high_freq(ops=60)
        checkpoint(a.out)
        print("== RQ4.B long storm 60s (ADD-only) ==", flush=True)
        rq4_long_storm(seconds=60, threads=3)
        checkpoint(a.out)

    if a.phase in ("all", "rq5"):
        print("== RQ5 B-card clean fixture ==", flush=True)
        b_fixture()
        checkpoint(a.out)
        print("== RQ5 E4 cache repopulation ==", flush=True)
        rq5_e4_cache_repopulation(cycles=30)
        checkpoint(a.out)
        print("== RQ5 E11 stale token replay ==", flush=True)
        rq5_e11_stale_token_replay()
        checkpoint(a.out)
        print("== RQ5 E3+E5 throughput ==", flush=True)
        rq5_throughput()
        checkpoint(a.out)
        # 收尾清场（B 卡仅 1-2 条目，解绑扇出极小）
        if B_RS["rs"]:
            C.call(ACTOR_B, "node-b", "DELETE",
                   "/main/api/v1/rule-sets/card/%d/unbind/%d" % (B_CARD, B_RS["rs"]))
            wait3_on(ACTOR_B, B_CARD, B_KEY, "read", False, timeout_s=45)

    RESULTS["elapsed_s"] = round(time.time() - t0, 1)
    # M-B 业务失败判定（原始字段直读，不重分类；H-3 口径）：rq34 要求
    # drain_complete、deltas_terminal 且 non_pending_errors==0；pending_403 为
    # 预期 fail-closed，如实保留、不要求 0，不计入失败。rq5 要求 E11 零越权 +
    # E3/E5 各点 errors==0。失败非零退出。
    bad = []
    if a.phase in ("all", "rq34"):
        hf = RESULTS.get("rq3", {}).get("high_freq_write")
        if not hf or hf.get("drain_complete") is not True \
                or hf.get("deltas_terminal") is not True \
                or hf.get("non_pending_errors") != 0:
            bad.append("rq3.high_freq_write(drain/non_pending_errors)")
        ls = RESULTS.get("rq4", {}).get("long_storm_60s")
        if not ls or ls.get("drain_complete") is not True \
                or ls.get("deltas_terminal") is not True \
                or ls.get("non_pending_errors") != 0:
            bad.append("rq4.long_storm_60s(drain/non_pending_errors)")
    if a.phase in ("all", "rq5"):
        e11 = RESULTS.get("rq5", {}).get("E11_stale_replay_context")
        if not e11 or e11.get("anomalies", 1) != 0 \
                or e11.get("captured_replay_allow_anomalies", 1) != 0 \
                or e11.get("stale_timestamp_rejected") is not True \
                or e11.get("cross_card_denied", 0) != 3:
            bad.append("rq5.E11(anomalies)")
        pts = RESULTS.get("rq5", {}).get("E3E5_throughput", {}).get("points") or []
        if not pts or any(p.get("errors", 1) != 0 for p in pts):
            bad.append("rq5.E3E5(errors)")
    RESULTS["verdict"] = "PASS" if not bad else "FAIL"
    RESULTS["fail_items"] = bad
    C.atomic_json(a.out, RESULTS)
    print("RQ345 DONE phase=%s elapsed=%ss verdict=%s bad=%s"
          % (a.phase, RESULTS["elapsed_s"], RESULTS["verdict"], bad or "none"), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
