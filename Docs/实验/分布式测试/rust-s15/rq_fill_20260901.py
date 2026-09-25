"""RQ 补数脚本 v2：CS_1–CS_8 Rust 等效案例（规则集 entry 路径）+ 基准 RQ2 梯度。

对照 Java 定义：AuthorizationClusterScenarios.java 的 cs1..cs8（每案例独立卡
7020-7027）。Rust 侧仅两张健康卡 → 以**逐案例 unbind 清理 + 等待 DENY**等效
隔离。粒度映射（如实记录）：Java 直连规则 per-target → Rust entry 类型级；
Java superseded 行计数 → 新链逐 delta 顺序发布 + 最终代 ALLOW。

运行位置：node-b，run_config.json 经 RUN_CONFIG_PATH 定位（编排器传入；
手动运行回退 cwd/run_config.json）。
用法：python3 -u rq_fill_20260901.py --out rq_fill_20260901.json
退出码：0 = cs/rq2 各案例无 ok=False（RQ2-D 为显式 N/A）；否则 1。
"""
import argparse
import os
import sys
import time

# 以脚本自身目录定位 s15_coordinator（不再硬编码历史部署绝对路径；
# run_config.json 仍按 cwd 解析——与 s15_coordinator.py 保持一致）。
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import s15_coordinator as C  # noqa: E402

RESULTS = {"cs": {}, "rq2": {}, "rq1": {}, "rq3": {}, "rq4": {}}
RES = "learn_subject"
KEY = RES + ":*"
CARD_DELTA_DRAIN_TIMEOUT_S = 1200
CLEANUP_DECISION_TIMEOUT_S = 45


def sim_all(card_id, resource, action, actor):
    return {n: C.sim(actor, n, card_id, resource, action,
                     int(actor["user_id"]), int(actor["domain"]), int(actor["tenant"]))
            for n in C.NAMES}


def expect200(resp, what):
    """Hard-check writes; distinguish breaker sequencing faults from business PENDING."""
    if resp is None or resp.status_code != 200:
        body = str(getattr(resp, "text", ""))[:300]
        if "CIRCUIT_BREAKER_OPEN" in body:
            raise AssertionError("breaker sequencing fault: %s" % what)
        raise AssertionError("expect200 %s: http=%s body=%s" %
                             (what, getattr(resp, "status_code", None), body))


def wait_state(card_id, resource, action, actor, want_allowed, timeout_s=30):
    deadline = time.time() + timeout_s
    t0 = time.perf_counter()
    pending_seen = False
    while time.time() < deadline:
        cur = sim_all(card_id, resource, action, actor)
        pending_seen = pending_seen or any(
            cur[n].get("reason") == "PENDING" or cur[n].get("http") == 503
            for n in C.NAMES)
        if all(cur[n]["allowed"] is want_allowed for n in C.NAMES):
            return True, (time.perf_counter() - t0) * 1000, pending_seen
        time.sleep(0.3)
    return False, (time.perf_counter() - t0) * 1000, pending_seen


def record(group, name, ok, detail=""):
    RESULTS[group][name] = {"ok": bool(ok), "detail": str(detail)[:300]}
    print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, str(detail)[:170]), flush=True)


def record_na(group, name, reason):
    """显式 N/A：结构性不可表示的维度如实记录（不产出虚假梯度，不计入分母）。"""
    RESULTS[group][name] = {"ok": None, "na": True, "reason": str(reason)[:300]}
    print("[N/A] %s %s" % (name, str(reason)[:170]), flush=True)


def max_card_delta_id(card_id):
    rows = C.sql("SELECT COALESCE(MAX(delta_event_id), 0) "
                 "FROM authorization_delta_event WHERE card_id=%d" % int(card_id))
    return int(rows[0][0]) if rows else 0


def _card_delta_drain_sample(card_id, since_id=None):
    if since_id is None:
        scope = "(card_id=%d OR card_id IS NULL)" % int(card_id)
    else:
        scope = "(card_id=%d OR card_id IS NULL) AND delta_event_id > %d" % (
            int(card_id), int(since_id))
    rows = C.sql(
        "SELECT COUNT(*), COALESCE(MAX(attempts), 0), "
        "COALESCE(MAX(delta_event_id), 0) "
        "FROM authorization_delta_event WHERE %s AND status <> 'SUCCEEDED'" % scope)
    if not rows:
        return {"pending": 0, "max_attempts": 0, "max_delta_event_id": 0}
    return {"pending": int(rows[0][0]), "max_attempts": int(rows[0][1]),
            "max_delta_event_id": int(rows[0][2])}


def wait_card_deltas_settled_detail(card_id, timeout_s=CARD_DELTA_DRAIN_TIMEOUT_S,
                                    since_id=None):
    """Wait for a bounded, scoped delta drain and retain diagnostic evidence.

    A revoke fan-out can legitimately take longer than the decision-plane safety
    window: reads must stay PENDING/deny while it drains, then be checked again
    after the durable SUCCEEDED proof.  ``since_id`` scopes cleanup evidence to
    rows created by that unbind rather than mixing in the card's old history.
    """
    started = time.perf_counter()
    deadline = time.time() + timeout_s
    last = _card_delta_drain_sample(card_id, since_id)
    while time.time() < deadline:
        last = _card_delta_drain_sample(card_id, since_id)
        if last["pending"] == 0:
            return {
                "ok": True,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                "since_id": since_id,
                **last,
            }
        time.sleep(5)
    detail = {
        "ok": False,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "since_id": since_id,
        **last,
    }
    print("[FAIL] card delta drain timeout card=%s since=%s pending=%s max_attempts=%s" %
          (card_id, since_id, detail["pending"], detail["max_attempts"]), flush=True)
    return detail


def wait_card_deltas_settled(card_id, timeout_s=CARD_DELTA_DRAIN_TIMEOUT_S,
                             since_id=None):
    """Compatibility bool wrapper for the pre-RQ2 global drain gate."""
    return wait_card_deltas_settled_detail(card_id, timeout_s, since_id)["ok"]


def wait_no_allow(card_id, actor, timeout_s=CLEANUP_DECISION_TIMEOUT_S):
    """Prove the unsafe direction is closed before waiting for durable drain.

    PENDING/transport-unknown is safe for this phase because only an ALLOW is
    unsafe; the post-drain exact DENY/ALLOW check remains mandatory.
    """
    started = time.perf_counter()
    deadline = time.time() + timeout_s
    last = {}
    while time.time() < deadline:
        cur = sim_all(card_id, KEY, "read", actor)
        last = {n: {k: cur[n].get(k) for k in ("allowed", "reason", "http")}
                for n in C.NAMES}
        if all(cur[n].get("allowed") is not True for n in C.NAMES):
            return True, round((time.perf_counter() - started) * 1000, 2), last
        time.sleep(0.3)
    return False, round((time.perf_counter() - started) * 1000, 2), last


def _record_cleanup_evidence(evidence):
    RESULTS.setdefault("rq2", {}).setdefault("cleanup_drain", []).append(evidence)


def cleanup_unbind(card_id, actor, rs_id, want_allowed=False):
    """Unbind, close the unsafe direction, drain revoke deltas, then verify state.

    The former single 45-second wait conflated a safe PENDING decision with a
    completed revoke fan-out.  The phases below keep the fail-closed check
    strict while allowing the durable projection to use its bounded worker
    budget (up to 1200 seconds for high-fanout cleanup).
    """
    since_id = max_card_delta_id(card_id)
    resp = C.unbind_card(rs_id, card_id, node="node-b")
    if resp is None or resp.status_code != 200:
        raise AssertionError("cleanup unbind failed: rs=%s http=%s body=%s" %
                             (rs_id, getattr(resp, "status_code", None),
                              str(getattr(resp, "text", ""))[:120]))

    if want_allowed:
        no_allow_ok, no_allow_ms, no_allow_state = None, None, None
    else:
        no_allow_ok, no_allow_ms, no_allow_state = wait_no_allow(card_id, actor)
        if not no_allow_ok:
            evidence = {
                "rs": int(rs_id), "want_allowed": bool(want_allowed),
                "since_id": since_id, "no_allow_ok": False,
                "no_allow_ms": no_allow_ms, "no_allow_state": no_allow_state,
                "drain_ok": False, "error": "stale ALLOW persisted during safety window",
            }
            _record_cleanup_evidence(evidence)
            raise AssertionError("cleanup stale ALLOW did not close: rs=%s" % rs_id)

    drain = wait_card_deltas_settled_detail(
        card_id, timeout_s=CARD_DELTA_DRAIN_TIMEOUT_S, since_id=since_id)
    if not drain["ok"]:
        evidence = {
            "rs": int(rs_id), "want_allowed": bool(want_allowed),
            "since_id": since_id, "no_allow_ok": no_allow_ok,
            "no_allow_ms": no_allow_ms, "no_allow_state": no_allow_state,
            "drain_ok": False, "drain": drain,
            "error": "revoke delta drain did not converge",
        }
        _record_cleanup_evidence(evidence)
        raise AssertionError("cleanup delta drain did not converge: rs=%s pending=%s" %
                             (rs_id, drain["pending"]))

    ok, decision_ms, pending_seen = wait_state(
        card_id, KEY, "read", actor, want_allowed,
        timeout_s=CLEANUP_DECISION_TIMEOUT_S)
    evidence = {
        "rs": int(rs_id), "want_allowed": bool(want_allowed),
        "since_id": since_id, "no_allow_ok": no_allow_ok,
        "no_allow_ms": no_allow_ms, "no_allow_state": no_allow_state,
        "drain_ok": True, "drain": drain,
        "decision_ok": bool(ok), "decision_ms": round(decision_ms, 2),
        "pending_seen": bool(pending_seen),
    }
    _record_cleanup_evidence(evidence)
    if not ok:
        raise AssertionError("cleanup state did not converge after drain: rs=%s want_allowed=%s" %
                             (rs_id, want_allowed))
    return True


def lat_of(fn, reps=50):
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1000)
    xs.sort()
    return {"n": len(xs), "p50_ms": round(xs[len(xs) // 2], 2),
            "p95_ms": round(xs[int(len(xs) * 0.95)], 2),
            "mean_ms": round(sum(xs) / len(xs), 2)}


def drain(rs_id, timeout_s=20):
    """有界等待该规则集 outbox 全部终态（修复：原实现把 time.time() 与
    timeout_s 数值比较，循环体永不执行——排水实际从未等待过）。"""
    deadline = time.time() + timeout_s
    ob = C.outbox_summary(rs_id)
    while time.time() < deadline and not (ob["all_processed"] and ob["terminal_once"]):
        time.sleep(1)
        ob = C.outbox_summary(rs_id)
    return ob


# ────────────────────────────── CS_1–CS_8（A 卡 9061，逐案例清理）──────────────────────────────

def clean_slate(card_id, actor):
    """清场：解除该卡全部规则集绑定并完成有界排水/终态证明。

    多授权源残留会让单一 remove 的 DENY 断言不可判定——先解除全部引用，
    再以卡级安全检查、撤销 delta 排水和最终 DENY 三段式完成隔离。"""
    refs = C.sql("SELECT rule_set_id FROM card_rule_set_ref WHERE card_id=%d" % card_id)
    for (rs_id,) in refs:
        resp = C.unbind_card(int(rs_id), int(card_id), node="node-b")
        if resp is None or resp.status_code != 200:
            raise AssertionError("clean slate unbind failed: rs=%s http=%s body=%s" %
                                 (rs_id, getattr(resp, "status_code", None),
                                  str(getattr(resp, "text", ""))[:120]))
    no_allow_ok, _, no_allow_state = wait_no_allow(card_id, actor)
    if not no_allow_ok:
        raise AssertionError("clean slate stale ALLOW persisted: %s" % no_allow_state)
    drain = wait_card_deltas_settled_detail(
        card_id, timeout_s=CARD_DELTA_DRAIN_TIMEOUT_S, since_id=None)
    if not drain["ok"]:
        raise AssertionError("clean slate delta drain did not converge: %s" % drain)
    ok, _, _ = wait_state(card_id, KEY, "read", actor, False,
                          timeout_s=CLEANUP_DECISION_TIMEOUT_S)
    if not ok:
        raise AssertionError("clean slate DENY did not converge")
    return len(refs)


def cs_cases(actor, card):
    # CS_1：revoke fence 阻断 ALLOW——remove 后撤权类未发布窗口内全节点
    # 非 ALLOW（v2 门禁 PENDING），READY 后全节点 DENY。
    rs = C.fixture_plain("CS1")
    r_add, _ = C.add_entry(rs, RES, "read", node="node-b")
    expect200(r_add, "CS1 add entry")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS1 bind")
    ok_a, _, pend_before = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    entries = C.sql("SELECT entry_id FROM rule_set_entry WHERE rule_set_id=%d" % rs)
    for (eid,) in entries:
        expect200(C.del_entry(rs, eid, node="node-c"), "CS1 del entry %s" % eid)
    time.sleep(0.5)
    pend = sim_all(card, KEY, "read", actor)
    pending_no_allow = all(not pend[n]["allowed"] for n in C.NAMES)
    ok_d, _, _ = wait_state(card, KEY, "read", actor, False)
    fence = C.sql("SELECT revoke_fence FROM authorization_projection_head "
                  "WHERE aggregate_type='CARD' AND aggregate_id=%d" % card)
    record("cs", "CS1_revoke_fence_blocks_allow",
           ok_a and pending_no_allow and ok_d and bool(fence) and int(fence[0][0]) > 0,
           "base_allow=%s pending_no_allow=%s ready_deny=%s fence=%s"
           % (ok_a, pending_no_allow, ok_d, fence))
    cleanup_unbind(card, actor, rs)

    # CS_2：源 oracle（构造即意图的静态子集）与三节点投影决策一致。
    rs = C.fixture_plain("CS2")
    r_add, _ = C.add_entry(rs, RES, "read", node="node-b")
    expect200(r_add, "CS2 add entry")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS2 bind")
    ok_a, _, _ = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    record("cs", "CS2_source_oracle_matches_projected", ok_a,
           "oracle=ALLOW(static subset) nodes_agree=%s" % ok_a)
    cleanup_unbind(card, actor, rs)

    # CS_3：新 grant 在 bind（发布链建立）前不可准入，bind 后可见。
    rs = C.fixture_plain("CS3")
    r_add, _ = C.add_entry(rs, RES, "read", node="node-b")
    expect200(r_add, "CS3 add entry")
    early = sim_all(card, KEY, "read", actor)
    early_ok = all(early[n]["allowed"] is not True for n in C.NAMES)
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS3 bind")
    ok_pub, _, _ = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    record("cs", "CS3_new_grant_projection_gate", early_ok and ok_pub,
           "early_not_allow=%s published=%s" % (early_ok, ok_pub))
    cleanup_unbind(card, actor, rs)

    # CS_4：OVERLAY DENY 覆盖 BASE ALLOW —— Rust 等效断言（phase-1 建模边界）。
    # canonical grant 刻意 ALLOW-only：DENY 不得进入正授热态（astral-types
    # GrantEffect 契约 + validate_canonical_grant_effect 拒绝语义）。因此
    # Java 的 OVERLAY DENY 条目在 Rust 侧的正确行为是创建被 fail-closed 拒绝
    # （400），且 BASE ALLOW 不受扰动；拒绝语义由 DEFAULT_DENY/PENDING 表达
    # （CS_1/CS_6 已覆盖）。
    rsb = C.fixture_plain("CS4B")
    r_add, _ = C.add_entry(rsb, RES, "read", node="node-b")
    expect200(r_add, "CS4 base add entry")
    expect200(C.bind_card(rsb, card, layer="BASE", node="node-b"), "CS4 base bind")
    ok_base, _, _ = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    rso = C.fixture_plain("CS4O")
    r_deny, _ = C.add_entry(rso, RES, "read", effect="DENY", node="node-b")
    deny_rejected = r_deny is not None and r_deny.status_code == 400
    ok_allow, _, _ = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    record("cs", "CS4_overlay_deny_precedence",
           ok_base and deny_rejected and ok_allow,
           "base_allow=%s deny_entry_rejected=%s allow_persists=%s "
           "(Rust phase-1: ALLOW-only source, deny=DEFAULT_DENY)"
           % (ok_base, deny_rejected, ok_allow))
    cleanup_unbind(card, actor, rsb)

    # CS_5：交替 add/remove ×3——最终 ALLOW、head 单调、delta 全终态
    # （新链逐 delta 顺序发布；Java 的 superseded 行计数映射为最终代唯一性）。
    rs = C.fixture_plain("CS5")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS5 bind")
    ok5 = True
    gens = []
    for _ in range(3):
        r_add, eid = C.add_entry(rs, RES, "read", node="node-b")
        expect200(r_add, "CS5 add entry")
        ok_a, _, _ = wait_state(card, KEY, "read", actor, True)
        gens.append(C.head_state().get(rs, {}).get("src"))
        expect200(C.del_entry(rs, eid, node="node-c"), "CS5 del entry")
        ok_d, _, _ = wait_state(card, KEY, "read", actor, False)
        ok5 = ok5 and ok_a and ok_d
    dl = C.delta_summary(rs)
    record("cs", "CS5_generation_supersession",
           ok5 and dl["all_ok"] and dl["n"] >= 6,
           "rounds=3 final=ALLOW deltas=%s all_ok=%s" % (dl["n"], dl["all_ok"]))
    cleanup_unbind(card, actor, rs)

    # CS_6：unbind 推进 fence 并全节点 DENY。
    rs = C.fixture_plain("CS6")
    r_add, _ = C.add_entry(rs, RES, "read", node="node-b")
    expect200(r_add, "CS6 add entry")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS6 bind")
    ok_a, _, _ = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    expect200(C.unbind_card(rs, card, node="node-b"), "CS6 unbind")
    ok_d, _, _ = wait_state(card, KEY, "read", actor, False, timeout_s=45)
    fence = C.sql("SELECT revoke_fence FROM authorization_projection_head "
                  "WHERE aggregate_type='CARD' AND aggregate_id=%d" % card)
    record("cs", "CS6_unbind_fence_propagates",
           ok_a and ok_d and bool(fence) and int(fence[0][0]) > 0,
           "base_allow=%s unbind_deny=%s fence=%s" % (ok_a, ok_d, fence))

    # CS_7：资源类型隔离（entry 类型级粒度：类型隔离映射，如实记录）。
    # Rust 契约为 ALLOW-only（CS4 实测 DENY entry 400）：monitor/chat 不建任何
    # 条目，其 DENY 来自 DEFAULT_DENY 语义——这正是无显式 DENY 条目时的正确
    # 拒绝路径，不再试图创建会被 400 拒绝的 DENY entry。
    rs = C.fixture_plain("CS7")
    r_add, _ = C.add_entry(rs, RES, "read", node="node-b")
    expect200(r_add, "CS7 add entry")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS7 bind")
    ok_bound, _, _ = wait_state(card, KEY, "read", actor, True, timeout_s=45)
    ok7 = ok_bound
    for node in C.NAMES:
        a_ls = C.sim(actor, node, card, "learn_subject:*", "read", 9031, 9011, 9001)
        a_mo = C.sim(actor, node, card, "monitor:*", "read", 9031, 9011, 9001)
        a_ch = C.sim(actor, node, card, "chat_subject:*", "read", 9031, 9011, 9001)
        ok7 &= (a_ls["allowed"] is True and a_mo["allowed"] is False
                and a_ch["allowed"] is False)
    record("cs", "CS7_resource_type_isolation", ok7,
           "learn=ALLOW monitor=DEFAULT_DENY chat=DEFAULT_DENY ×3"
           "（无 monitor/chat 条目；类型级粒度映射）")
    cleanup_unbind(card, actor, rs)

    # CS_8：write 动作别名（write → create/update/delete；read 不放行）。
    rs = C.fixture_plain("CS8")
    r_add, _ = C.add_entry(rs, RES, "write", node="node-b")
    expect200(r_add, "CS8 add entry")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "CS8 bind")
    ok_bound, _, _ = wait_state(card, KEY, "create", actor, True, timeout_s=45)
    ok8 = ok_bound
    details = {}
    for act, want in [("create", True), ("update", True), ("delete", True),
                      ("read", False)]:
        cur = C.sim3(actor, card, KEY, act, int(actor["user_id"]),
                     int(actor["domain"]), int(actor["tenant"]))
        got = all(cur[n]["allowed"] is want for n in C.NAMES)
        ok8 = ok8 and got
        details[act] = got
    record("cs", "CS8_write_alias_semantics", ok8, str(details))
    cleanup_unbind(card, actor, rs)


# ────────────────────────────── 基准 RQ2 敏感度梯度（A 卡 9061）──────────────────────────────

def rq2_gradients(actor, card, checkpoint=None):
    # K/规则数梯度：同一 ruleset 逐批加 entry（1/10/50/100/200）。
    # M2（2026-09-04）：禁止先绑定空规则集——必须先添加第一个 entry 再 bind
    # （空规则集绑定使卡证据依赖链无法收敛，见 fixture 契约）；每个梯度点都必须
    # 记录 ALLOW 收敛证据（ok/converge_ms/pending_seen/error），任何未收敛点
    # 使汇总 RQ2K/RQ2I_gradient_convergence ok=False → verdict FAIL/非零退出。
    rs = C.fixture_plain("RQ2K")
    r_first, _ = C.add_entry(rs, RES, "read", node="node-b")
    expect200(r_first, "RQ2K first entry（M2：bind 前必须有 entry，禁止绑定空规则集）")
    expect200(C.bind_card(rs, card, layer="BASE", node="node-b"), "RQ2K bind")
    added = 1
    gradient = []
    RESULTS["rq2"]["K_rule_count_gradient"] = gradient
    unconverged = []

    def measure_point(key, label, tag, sink):
        """单梯度点：等待全节点 ALLOW 并记录收敛证据；未收敛照常记录
        （ok=False + error，并登记进 sink），不静默吞掉。"""
        ok, conv_ms, pend = wait_state(card, KEY, "read", actor, True, timeout_s=60)
        if not ok:
            sink.append(label)
        time.sleep(1.5)
        l = lat_of(lambda: C.sim(actor, "node-b", card, KEY, "read",
                                 int(actor["user_id"]), int(actor["domain"]),
                                 int(actor["tenant"])), 50)
        print("%s %s=%d ok=%s converge_ms=%s p50=%s p95=%s"
              % (tag, key, label, ok, round(conv_ms, 2), l["p50_ms"], l["p95_ms"]),
              flush=True)
        return {key: label, "ok": ok,
                "error": None if ok else "ALLOW 未在 60s 内全节点收敛",
                "converge_ms": round(conv_ms, 2), "pending_seen": bool(pend), **l}

    gradient.append(measure_point("entries", 1, "RQ2-K", unconverged))
    if checkpoint:
        checkpoint()
    for target in (10, 50, 100, 200):
        while added < target:
            r_add, _ = C.add_entry(rs, RES, "read", node="node-b")
            expect200(r_add, "RQ2K add entry %d" % (added + 1))
            added += 1
            if added % 20 == 0:
                time.sleep(1.5)
        gradient.append(measure_point("entries", target, "RQ2-K", unconverged))
        if checkpoint:
            checkpoint()
    RESULTS["rq2"]["K_rule_count_gradient"] = gradient
    record("rq2", "RQ2K_gradient_convergence", not unconverged,
           "points=%d unconverged_entries=%s" % (len(gradient), unconverged or "none"))
    cleanup_unbind(card, actor, rs)

    # I/叠加引用数梯度：1/2/4/8 个规则集逐个 bind（每个规则集先加 entry 再
    # bind；每点同样记录 ALLOW 收敛证据）。
    refs = []
    RESULTS["rq2"]["I_reference_count_gradient"] = refs
    bound = []
    unconverged_i = []
    for n in [1, 2, 4, 8]:
        while len(bound) < n:
            r = C.fixture_plain("RQ2I%d" % (len(bound) + 1))
            r_add, _ = C.add_entry(r, RES, "read", node="node-b")
            expect200(r_add, "RQ2I add entry")
            expect200(C.bind_card(r, card, layer="OVERLAY", node="node-b"),
                      "RQ2I bind rs=%s" % r)
            bound.append(r)
            time.sleep(1.5)
        pt = measure_point("references", n, "RQ2-I", unconverged_i)
        refs.append(pt)
        if checkpoint:
            checkpoint()
    RESULTS["rq2"]["I_reference_count_gradient"] = refs
    record("rq2", "RQ2I_gradient_convergence", not unconverged_i,
           "points=%d unconverged_refs=%s" % (len(refs), unconverged_i or "none"))
    for index, r in enumerate(reversed(bound)):
        # 多个 OVERLAY 引用共同提供 ALLOW：只有移除最后一个引用时才期待
        # DENY；中间清理若强行期待 DENY 会把合法残余授权误判为污染。
        cleanup_unbind(card, actor, r, want_allowed=(index < len(bound) - 1))

    # D/冲突密度梯度：结构性 N/A（2026-09-04 harness 审计修复，移除虚假梯度）。
    # Rust canonical 契约为 ALLOW-only：DENY entry 在创建时即被 fail-closed 拒绝
    # （astral-types GrantEffect 契约 + validate_canonical_grant_effect；CS4 已
    # 实测 HTTP 400），“OVERLAY DENY 条目数”这一自变量在 Rust 侧不可表示；
    # 绑定空规则集又被 fixture 契约禁止（无 delta 的规则集使卡证据依赖链无法
    # 收敛）。历史版本的 0/2/4 梯度实际从未创建任何 DENY（add 返回 400 被静默
    # 忽略），三档测的都是同一 ALLOW 基线——属伪造维度，已删除。冲突语义由
    # DEFAULT_DENY / PENDING 表达（CS1/CS6/CS7 已覆盖）。
    record_na("rq2", "D_conflict_density_gradient",
              "Rust phase-1 ALLOW-only source：DENY entry 被 fail-closed 拒绝（CS4 实测 400），"
              "冲突密度自变量结构性不可表示；DENY 语义由 DEFAULT_DENY/PENDING 覆盖"
              "（CS1/CS6/CS7）。历史 0/2/4 梯度未创建任何 DENY，已删除")

    # 历史轮次遗留的 RQ2D-O% 夹具清场（尽力而为；本版本不再新建该形态夹具）。
    try:
        for r in C.sql("SELECT rule_set_id FROM rule_set WHERE code LIKE 'RQ2D-O%'"):
            cleanup_unbind(card, actor, int(r[0]))
    except Exception as e:
        print("[WARN] legacy RQ2D-O%% cleanup skipped: %r" % e, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="rq_fill_20260901.json")
    parser.add_argument("--skip-cs", action="store_true")
    parser.add_argument("--skip-rq2", action="store_true")
    a = parser.parse_args()

    t0 = time.time()
    phase = "init"
    actor = C.A
    card = 9061
    RESULTS["provenance"] = dict(C.provenance())
    try:
        if not a.skip_cs:
            phase = "cs"
            cleaned = clean_slate(card, actor)
            print("clean slate: %d bindings removed" % cleaned, flush=True)
            cs_cases(actor, card)
            C.atomic_json(a.out, RESULTS)
        if not a.skip_rq2:
            phase = "rq2"
            if not wait_card_deltas_settled(card, timeout_s=CARD_DELTA_DRAIN_TIMEOUT_S):
                raise RuntimeError("card-scoped delta drain incomplete before RQ2")
            rq2_gradients(actor, card, checkpoint=lambda: C.atomic_json(a.out, RESULTS))
            C.atomic_json(a.out, RESULTS)

        phase = "rq1"
        storage = C.sql(
            "SELECT table_name, data_length + index_length "
            "FROM information_schema.tables WHERE table_schema = DATABASE() "
            "AND table_name IN ('authorization_projection_manifest', "
            "'authorization_projection_segment', 'authorization_projection_current', "
            "'authorization_grant_revision', 'authorization_delta_event', "
            "'authorization_impact_plan')")
        gens = C.sql("SELECT COALESCE(MAX(current_generation), 0) "
                     "FROM authorization_projection_current")
        grants = C.sql("SELECT COUNT(*) FROM authorization_grant_revision "
                       "WHERE is_tombstone = 0")
        RESULTS["rq1"]["storage_bytes_by_table"] = {str(t): int(b) for t, b in storage}
        RESULTS["rq1"]["max_published_generation"] = int(gens[0][0]) if gens else 0
        RESULTS["rq1"]["active_grant_revisions"] = int(grants[0][0]) if grants else 0
    except Exception as exc:
        RESULTS["complete"] = False
        RESULTS["exception"] = {"phase": phase, "type": type(exc).__name__,
                                 "message": str(exc)[:300]}
        RESULTS.setdefault("fail_items", []).append("exception:%s:%s" %
                                                      (phase, type(exc).__name__))
        print("RQ_FILL FAIL phase=%s type=%s" % (phase, type(exc).__name__), flush=True)

    bad = [k for g in ("cs", "rq2") for k, v in RESULTS.get(g, {}).items()
           if isinstance(v, dict) and v.get("ok") is False]
    bad.extend(x for x in RESULTS.get("fail_items", []) if x not in bad)
    RESULTS["verdict"] = "PASS" if not bad else "FAIL"
    RESULTS["fail_items"] = bad
    RESULTS["elapsed_s"] = round(time.time() - t0, 1)
    RESULTS.setdefault("complete", not bad)
    C.atomic_json(a.out, RESULTS)
    print("RQ_FILL DONE elapsed=%ss bad=%s" %
          (RESULTS["elapsed_s"], bad or "none"), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
