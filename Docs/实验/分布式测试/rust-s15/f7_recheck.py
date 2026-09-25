"""F7 复测：F5 修复后的健康 worker 链路验证（对标 FIXPLAN 修复 5 的复测要求）。

30 轮交替 add/remove（对标 S6 的 10 轮扩展版），每轮断言：
- add 200 → 三节点 ALLOW；remove 200 → 三节点 DENY；
- 该 RULE_SET 聚合的 delta 全部 SUCCEEDED（无 PENDING/LEASED 残留——
  F5 修复前该场景会因 Redis/监督缺口产生永停 delta）；
- head source_generation 严格单调；outbox 连续 + 全 PROCESSED + terminal_once；
- 记录每轮墙钟延迟分布；
- head 缺失（None，head_state 无该聚合行）时判该轮失败且不参与单调性比较
  （L6：不得 TypeError、不得静默当作通过；仍写最终原子 summary 并非零退出）。

运行位置：node-b，run_config.json 经 RUN_CONFIG_PATH 定位（编排器传入；
手动运行回退 cwd/run_config.json，与 s15_coordinator.py 同）。
用法：python3 -u f7_recheck.py [--rounds 30] [--out f7_result_20260901.json]
退出码：0 = 全轮通过且 head 单调/无残留 delta/outbox 完整；否则 1。
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--out", default="f7_result_20260901.json")
    args = parser.parse_args()

    results = []
    rs = C.fixture_plain("F7")
    rb = C.bind_card(rs, C.A["card"])
    assert rb.status_code == 200, "F7 bind failed: %s" % rb.text[:150]
    wargs = C.learn_args()

    def snapshot(complete):
        heads = [r["head_del"] for r in results]
        return {
            "complete": complete,
            "rounds_done": len(results),
            "summary": {
                "rounds": args.rounds,
                "all_ok": all(r["ok"] for r in results),
                # L6：head 可能为 None（head_state 无该聚合行）——比较前显式判
                # None，不 TypeError；任一轮 head 缺失即 head_monotonic=False。
                "head_monotonic": all(a is not None and b is not None and b > a
                                      for a, b in zip(heads, heads[1:])),
                "head_missing_rounds": [r["round"] for r in results
                                        if not r.get("head_ok")],
                "no_lingering_deltas": all(r["delta_all_succeeded"] for r in results),
                "outbox_integrity": all(r["outbox_contiguous"] and r["outbox_all_processed"]
                                        and r["outbox_terminal_once"] for r in results),
                "latency_max_s": max((r["elapsed_s"] for r in results), default=0),
                "latency_avg_s": round(sum(r["elapsed_s"] for r in results) / len(results), 2) if results else None,
                "total_elapsed_s": round(sum(r["elapsed_s"] for r in results), 1),
            },
            "provenance": C.provenance(),
            "results": results,
        }

    for i in range(args.rounds):
        t0 = time.time()
        try:
            r_add, eid = C.add_entry(rs, "learn_subject", "read", node="node-b")
            ok_allow, _, _ = C.wait3(*wargs, want=True, timeout_s=30)
            head_add = C.head_state().get(rs, {}).get("src")
            r_del = C.del_entry(rs, eid, node="node-c")
            ok_deny, _, _ = C.wait3(*wargs, want=False, timeout_s=30)
            head_del = C.head_state().get(rs, {}).get("src")
            dl = C.delta_summary(rs)
            # 旧链 outbox 的 retired 标记由 legacy worker 5s 轮询排水；有界等待
            # 排水完成后再断言（对标 S6 的 30s 排水等待）。
            deadline = time.time() + 15
            ob = C.outbox_summary(rs)
            while time.time() < deadline and not (ob["all_processed"] and ob["terminal_once"]):
                time.sleep(1)
                ob = C.outbox_summary(rs)
            drain_s = round(time.time() - t0, 2)
            elapsed = round(time.time() - t0, 2)
            # L6：head 缺失（None）明确判该轮失败——head 版本栅栏是单调性
            # 证据的前提，None 不得静默通过，也不得让比较抛 TypeError。
            head_ok = head_add is not None and head_del is not None
            round_ok = (r_add.status_code == 200 and eid
                        and ok_allow and r_del.status_code == 200 and ok_deny
                        and head_ok
                        and dl["all_ok"] and ob["all_processed"] and ob["terminal_once"])
            record = {
                "round": i + 1,
                "ok": round_ok,
                "elapsed_s": elapsed,
                "drain_wait_included_s": drain_s,
                "head_add": head_add,
                "head_del": head_del,
                "head_ok": head_ok,
                "delta_all_succeeded": dl["all_ok"],
                "delta_n": dl["n"],
                "outbox_contiguous": ob["contiguous"],
                "outbox_all_processed": ob["all_processed"],
                "outbox_terminal_once": ob["terminal_once"],
            }
        except Exception as exc:
            # L6：单轮异常（含 head None 引发的比较错误）不得中断整个复测：
            # 记失败轮次并继续，最终仍写完整原子 summary、以非零退出。
            elapsed = round(time.time() - t0, 2)
            record = {
                "round": i + 1, "ok": False, "elapsed_s": elapsed,
                "drain_wait_included_s": elapsed,
                "head_add": None, "head_del": None, "head_ok": False,
                "delta_all_succeeded": False, "delta_n": None,
                "outbox_contiguous": False, "outbox_all_processed": False,
                "outbox_terminal_once": False,
                "error": str(exc)[:200],
            }
        results.append(record)
        print("F7 round %2d: ok=%s elapsed=%5.2fs head=%s deltas=%s all_ok=%s outbox_ok=%s"
              % (i + 1, record["ok"], record["elapsed_s"], record["head_del"],
                 record["delta_n"], record["delta_all_succeeded"],
                 record["outbox_all_processed"] and record["outbox_terminal_once"]),
              flush=True)
        # 每轮 checkpoint（原子落盘）：长跑中断不丢已完成轮次证据。
        C.atomic_json(args.out, snapshot(False))

    summary = snapshot(True)
    C.atomic_json(args.out, summary)
    s = summary["summary"]
    print("F7 SUMMARY: all_ok=%s head_monotonic=%s no_lingering_deltas=%s "
          "latency avg/max=%s/%ss total=%ss"
          % (s["all_ok"], s["head_monotonic"], s["no_lingering_deltas"],
             s["latency_avg_s"], s["latency_max_s"], s["total_elapsed_s"]), flush=True)
    # 业务失败非零退出：any 轮失败 / head 非单调 / delta 残留 / outbox 完整性破缺。
    ok = (s["all_ok"] and s["head_monotonic"] and s["no_lingering_deltas"]
          and s["outbox_integrity"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
